mod codec;
mod reg_auth;
mod uav_auth_comm;
use crate::reg_auth::{auth, register};
use dashmap::DashMap;
use futures::lock::Mutex;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use rand::{thread_rng, Rng};
use rug::Integer;
use std::fmt::Display;
use std::net::{IpAddr, SocketAddr};
use tokio::net::TcpListener;
use tracing_subscriber::EnvFilter;
use uav_auth_comm::uav_auth_communicate;

pub struct GSConfig {
    pub gid: [u8; 32],
    pub rgid: [u8; 32],
    pub sk_gs: BIG,
    pub puk_gs: ECP,
    pub sk_gs_bytes: Vec<u8>,
    pub puk_gs_bytes: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct UavInfo {
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
    pub c: Vec<u8>,
    pub r: Vec<u8>,
    pub n: Integer,
}
#[derive(Debug, serde::Serialize, serde::Deserialize, Clone)]
pub struct UavAuthInfo {
    pub ip_addr: IpAddr,
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
    pub c: Vec<u8>,
    pub r: Vec<u8>,
    pub n: Integer,
}

impl Display for UavInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("UavInfo")
            .field("uid", &hex::encode(&self.uid))
            .field("ruid", &hex::encode(&self.ruid))
            .field("c", &hex::encode(&self.c))
            .field("r", &hex::encode(&self.r))
            .field("n", &self.n.to_string_radix(16))
            .finish()
    }
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavList(DashMap<String, UavInfo>);

pub type UavAuthListState =
    DashMap<String, futures_channel::mpsc::UnboundedSender<(String, String)>>;

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavAuthList(DashMap<String, UavAuthInfo>);

lazy_static::lazy_static! {
    pub static ref GS_CONFIG: GSConfig = init_gs_keys();
    pub static ref UAV_LIST: UavList = UavList(DashMap::new());
    pub static ref UAV_AUTH_LIST: UavAuthList = UavAuthList(DashMap::new());
    pub static ref UAV_AUTH_LIST_STATE: UavAuthListState = UavAuthListState::new();
    pub static ref UAV_FAKE_PRIME: Mutex<Vec<Integer>> = Mutex::new(vec![]);
}

/// Init GS keys
/// Including GS public key $ PUK_{gs} $ and GS private key sk_{gs}
fn init_gs_keys() -> GSConfig {
    let gid: [u8; 32] = thread_rng().gen::<[u8; 32]>();
    let rgid: [u8; 32] = thread_rng().gen::<[u8; 32]>();
    let gs_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let sk_gs = BIG::frombytes(&gs_bytes);
    let puk_gs = ECP::generator().mul(&sk_gs);
    GSConfig {
        gid,
        rgid,
        sk_gs,
        sk_gs_bytes: gs_bytes.to_vec(),
        puk_gs_bytes: {
            let mut puk_gs_bytes = vec![0u8; 65];
            puk_gs.tobytes(&mut puk_gs_bytes, false);
            puk_gs_bytes
        },
        puk_gs,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();

    let ta_addr = "127.0.0.1:8090";
    // register self to TA
    register(ta_addr).await?;
    // auth self to TA
    auth(ta_addr).await?;

    // spawn a server to listen to UAVs connection
    let bind_addr = "127.0.0.1:8091";
    tcp_server(bind_addr.parse::<SocketAddr>()?).await?;
    Ok(())
}

async fn tcp_server(addr: SocketAddr) -> anyhow::Result<()> {
    let socket = TcpListener::bind(addr).await?;
    loop {
        let (stream, _addr) = socket.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = uav_auth_communicate(stream, addr).await {
                tracing::warn!("{}", e);
            }
        });
    }
}
