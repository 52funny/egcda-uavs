mod auth;
mod mem;
mod reg;
mod rpc_impl;
use crate::rpc_impl::GS;
use auth::auth;
use blstrs_plus::{group::prime::PrimeCurveAffine, G1Affine, G2Affine, Scalar};
use dashmap::DashMap;
use futures::{future, lock::Mutex, StreamExt};
use rand::{thread_rng, Rng};
use reg::register;
use rpc::{GsRpc, TaRpcClient};
use rug::Integer;
use std::future::Future;
use tarpc::{
    client, context,
    server::{self, Channel},
    tokio_serde::formats::Json,
};
use tracing::info;
use tracing_subscriber::EnvFilter;
use utils::abbreviate_key_default;

#[global_allocator]
static GLOBAL: mem::TrackingAllocator = mem::TrackingAllocator;

#[derive(Debug, Clone)]
pub struct GSConfig {
    pub gid: String,
    pub sk: Scalar,
    pub pk_g1: G1Affine,
    pub pk: G2Affine,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct UavInfo {
    pub uid: String,
    pub pk: G2Affine,
    pub c: String,
    pub z: String,
    pub p: Integer,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavList(DashMap<String, UavInfo>);

const TAG: &[u8] = b"BLS_SIG_BLS12381G1_XMD:BLAKE2b-512_SSWU_RO_NUL_";
const T_MAX: i64 = 10;

lazy_static::lazy_static! {
    pub static ref GS_CONFIG: GSConfig = init_gs_keys();
    pub static ref UAV_LIST: UavList = UavList(DashMap::new());
    pub static ref UAV_SESSION_KEYS: DashMap<String, String> = DashMap::new();
    pub static ref UAV_FAKE_PRIME: Mutex<Vec<Integer>> = Mutex::new(vec![]);
}

/// Init GS keys
fn init_gs_keys() -> GSConfig {
    let gid: [u8; 32] = thread_rng().gen::<[u8; 32]>();
    let sk_bytes = rand::thread_rng().gen::<[u64; 4]>();

    let gid = hex::encode(gid);
    let sk = Scalar::from_raw_unchecked(sk_bytes);
    let pk_g1 = G1Affine::generator() * sk;
    let g = G2Affine::generator();
    let pk = g * sk;

    GSConfig {
        gid,
        sk,
        pk_g1: pk_g1.into(),
        pk: pk.into(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("gs=info".parse().unwrap()))
        .init();
    mem::reset_phase_peak();
    mem::log_checkpoint("startup");

    let ta_addr = "0.0.0.0:8090";
    let bind_addr = "0.0.0.0:8091";

    let mut transport = tarpc::serde_transport::tcp::connect(&ta_addr, Json::default);
    transport.config_mut().max_frame_length(usize::MAX);

    let client = TaRpcClient::new(client::Config::default(), transport.await?).spawn();

    let pk_t1 = client.get_ta_pubkey1(context::current()).await?;
    let pk_t1 = G1Affine::from_compressed_hex(&pk_t1).expect("Invalid trust authority G1 public key");
    info!("TA's G1 public key: {}", abbreviate_key_default(&hex::encode(pk_t1.to_compressed())));

    let pk_t2 = client.get_ta_pubkey2(context::current()).await?;
    let pk_t2 = G2Affine::from_compressed_hex(&pk_t2).expect("Invalid trust authority G2 public key");
    info!("TA's G2 public key: {}", abbreviate_key_default(&hex::encode(pk_t2.to_compressed())));

    // register self to TA
    let register_start = mem::reset_phase_peak();
    register(&client).await?;
    mem::log_phase("register_gs", register_start);

    // auth self to TA
    let auth_start = mem::reset_phase_peak();
    auth(&client, &pk_t1, &pk_t2).await?;
    mem::log_phase("auth_gs", auth_start);
    mem::log_uav_storage_stats("uav_list_loaded");

    // spawn the server
    tokio::spawn(server(bind_addr, pk_t2));

    // wait for exit
    tokio::signal::ctrl_c().await?;

    Ok(())
}

async fn server(bind_addr: &str, pk_t: G2Affine) -> anyhow::Result<()> {
    let mut listener = tarpc::serde_transport::tcp::listen(&bind_addr, Json::default).await?;
    listener.config_mut().max_frame_length(usize::MAX);
    tracing::info!("Listening on port {}", listener.local_addr().port());
    mem::log_checkpoint("server_ready");

    let cfg = GSConfig {
        gid: GS_CONFIG.gid.clone(),
        sk: GS_CONFIG.sk,
        pk_g1: GS_CONFIG.pk_g1,
        pk: GS_CONFIG.pk,
    };

    let server = GS::new(cfg, pk_t);

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
