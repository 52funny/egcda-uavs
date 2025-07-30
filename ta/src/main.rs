mod rpc_impl;
use blstrs_plus::{group::prime::PrimeCurveAffine, G2Affine, Scalar};
use dashmap::DashMap;
use futures::{future, StreamExt};
use hex::ToHex;
use lazy_static::lazy_static;
use rand::Rng;
use rpc::TaRpc;
use rpc_impl::TA;
use rug::Integer;
use std::{future::Future, net::SocketAddr};
use tarpc::{server, server::Channel, tokio_serde::formats::Json};
use tracing_subscriber::EnvFilter;

#[derive(Clone)]
pub struct TAConfig {
    pub sk: Scalar,
    pub pk: G2Affine,
}

pub struct GsInfo {
    pub gid: String,
    pub pk: G2Affine,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct UavInfo {
    pub uid: String,
    pub sk: Scalar,
    pub pk: G2Affine,
    pub c: String,
    pub r: String,
    pub p: Integer,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavList(DashMap<String, UavInfo>);

const TAG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:BLAKE2b-512_SSWU_RO_NUL_";
const PUF_INPUT_SIZE: usize = 12;
const T_MAX: usize = 10;

lazy_static! {
    static ref TA_CONFIG: TAConfig = init_ta_keys();
    static ref GS_LIST: DashMap<String, GsInfo> = DashMap::new();
    static ref GS_SSK_LIST: DashMap<String, String> = DashMap::new();
    static ref UAV_LIST: UavList = UavList(DashMap::new());
}

/// Init TA keys
fn init_ta_keys() -> TAConfig {
    let sk_bytes = rand::thread_rng().gen::<[u64; 4]>();
    let sk = Scalar::from_raw_unchecked(sk_bytes);
    let pk = G2Affine::generator() * sk;
    TAConfig { sk, pk: pk.into() }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("ta=info".parse().unwrap()))
        .init();

    tracing::info!("sk_ta: {}", TA_CONFIG.sk.to_be_bytes().encode_hex::<String>());
    tracing::info!("puk_ta: {}", TA_CONFIG.pk.to_compressed().encode_hex::<String>());

    let addr: SocketAddr = ([0, 0, 0, 0], 8090).into();
    let mut listener = tarpc::serde_transport::tcp::listen(&addr, Json::default).await?;
    listener.config_mut().max_frame_length(usize::MAX);
    tracing::info!("Listening on port {}", listener.local_addr().port());

    let server = TA::new(TA_CONFIG.clone());

    listener
        // Ignore accept errors.
        .filter_map(|r| future::ready(r.ok()))
        .map(server::BaseChannel::with_defaults)
        .map(|channel| channel.execute(server.clone().serve()).for_each(spawn))
        .buffer_unordered(usize::MAX)
        .for_each(|_| async {})
        .await;

    Ok(())
}

async fn spawn(fut: impl Future<Output = ()> + Send + 'static) {
    tokio::spawn(fut);
}
