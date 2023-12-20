mod codec;
mod reg_auth;
mod uav_auth_comm;
use crate::reg_auth::{auth, register};
use dashmap::DashMap;
use futures::lock::Mutex;
use hex_literal::hex;
use pbc_rust::Pairing;
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
    pub t_u: i64,
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
const TYPE_A: &str = "
type a
q 6269501190990595151250674934240647994559640542560528061719627332415708950243708672053776563123743544851675214786949400131452747984830937087887946632632599
h 8579533584978239287913221933865556817094441585921961055557100258639027708646644638908786275391553267066600
r 730750818665452757176057050065048642452048576511
exp2 159
exp1 110
sign1 1
sign0 -1
";

const GENERATION: [u8; 128] = hex!("221e95f6082142d33b1f78bc467bc3d16b8bfff7f1847a481b36b3581aa546798773b20edf1fac46d4f200c5c6296151bd3e835e1325b5bfb474d1c9257314113b1e1201243c6c8257f34a6a24c351ad4968ec9c9c1b3ec1bf23108f643c1a42ebb7137a5a255c845149f76535585a39ef5f96830a10556478ee066a4db57676");

lazy_static::lazy_static! {
    pub static ref P: Pairing = Pairing::new(TYPE_A);
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

    let sk_gs = P.gr().random();
    let mut puk_gs = P.g1();
    puk_gs.from_bytes(GENERATION);
    puk_gs.mul_element_zn(sk_gs.clone());

    GSConfig {
        gid,
        rgid,
        sk_gs_bytes: sk_gs.as_bytes(),
        puk_gs_bytes: puk_gs.as_bytes(),
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
    let bind_addr = "0.0.0.0:8091";
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
