mod codec;
mod reg_auth;
use crate::reg_auth::{auth, register};
use dashmap::DashMap;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use rand::{thread_rng, Rng};
use rug::Integer;
use tracing_subscriber::EnvFilter;

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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct UavList(DashMap<String, UavInfo>);

lazy_static::lazy_static! {
    pub static ref GS_CONFIG: GSConfig = init_gs_keys();
    pub static ref UAV_LIST: UavList = UavList(DashMap::new());
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

    let addr = "127.0.0.1:8090";
    register(addr).await?;
    auth(addr).await?;
    Ok(())
}
