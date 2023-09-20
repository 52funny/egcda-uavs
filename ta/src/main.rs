mod codec;
mod gs_reg_auth;
mod uav_reg;
use crate::gs_reg_auth::{gs_auth, gs_register};
use crate::uav_reg::uav_register;
use dashmap::DashMap;
use hex::ToHex;
use hex_literal::hex;
use lazy_static::lazy_static;
use pbc_rust::Pairing;
use rug::Integer;
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tracing_subscriber::EnvFilter;

#[derive(Debug)]
pub struct TAConfig {
    // pub sk_ta: Element,
    // pub puk_ta: Element,
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
    static ref P: Pairing = Pairing::new(TYPE_A);
}

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

/// Init TA keys
/// Including TA public key$ PUK_{ta} $ and TA private key sk_{ta}
fn init_ta_keys() -> TAConfig {
    let t = std::time::Instant::now();

    let mut puk_ta = P.g1();
    puk_ta.from_bytes(GENERATION);
    println!("{:?}", t.elapsed());

    let sk_ta = P.gr().random();
    puk_ta.mul_element_zn(sk_ta.clone());
    println!("{:?}", t.elapsed());

    TAConfig {
        sk_ta_bytes: sk_ta.as_bytes(),
        puk_ta_bytes: puk_ta.as_bytes(),
    }
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();

    tracing::info!("sk_ta: {}", TA_CONFIG.sk_ta_bytes.encode_hex::<String>());
    tracing::info!("puk_ta: {}", TA_CONFIG.puk_ta_bytes.encode_hex::<String>());

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
