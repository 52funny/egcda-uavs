mod codec;
mod gs_reg_auth;
mod uav_reg;
use crate::gs_reg_auth::{gs_auth, gs_register};
use crate::uav_reg::uav_register;
use dashmap::DashMap;
use lazy_static::lazy_static;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use rand::Rng;
use rug::Integer;
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tracing_subscriber::EnvFilter;

pub struct TAConfig {
    pub sk_ta: BIG,
    pub puk_ta: ECP,
    pub sk_ta_bytes: Vec<u8>,
    pub puk_ta_bytes: Vec<u8>,
}

pub struct GsInfo {
    pub gid: Vec<u8>,
    pub rgid: Vec<u8>,
    pub ip_addr: IpAddr,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavInfo {
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
    pub c: Vec<u8>,
    pub r: Vec<u8>,
    pub n: Integer,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavList(DashMap<String, UavInfo>);

lazy_static! {
    static ref TA_CONFIG: TAConfig = init_ta_keys();
    static ref GS_LIST: DashMap<String, GsInfo> = DashMap::new();
    static ref UAV_LIST: UavList = UavList(DashMap::new());
}

/// Init TA keys
/// Including TA public key $ PUK_{ta} $ and TA private key sk_{ta}
fn init_ta_keys() -> TAConfig {
    let sk_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let sk_ta = BIG::frombytes(&sk_bytes);
    let puk_ta = ECP::generator().mul(&sk_ta);
    TAConfig {
        sk_ta,
        sk_ta_bytes: sk_bytes.to_vec(),
        puk_ta_bytes: {
            let mut puk_ta_bytes = vec![0u8; 65];
            puk_ta.tobytes(&mut puk_ta_bytes, false);
            puk_ta_bytes
        },
        puk_ta,
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();

    tracing::info!("sk_ta: {}", TA_CONFIG.sk_ta);
    tracing::info!("puk_ta: {}", TA_CONFIG.puk_ta);
    let addr: SocketAddr = ([0, 0, 0, 0], 8090).into();
    let listener = TcpListener::bind(addr).await?;
    loop {
        // accept connections and process them serially
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(async move {
            if let Err(e) = tcp_accept(stream, addr).await {
                tracing::warn!("{}", e);
            }
        });
    }
}

async fn tcp_accept(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    let mut stream = stream;
    tracing::info!("connection from {:?}", addr);
    let types = stream.read_i8().await?;
    // 0b0000_0001 means gs register
    // 0b0000_0010 means uav register
    //
    // 0b0000_0100 means gs authentication
    match types {
        // gs register
        0x01 => gs_register(stream, addr).await?,
        // uav
        0x02 => uav_register(stream, addr).await?,
        // gs authentication
        0x04 => gs_auth(stream, addr).await?,
        // unreadable
        _ => {}
    }
    Ok(())
}
