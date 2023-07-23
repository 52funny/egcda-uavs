mod codec;
use codec::gs_register_codec::GsRegisterCodec;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex::ToHex;
use lazy_static::lazy_static;
use mcore::ed25519::big::BIG;
use mcore::ed25519::ecp::ECP;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

pub struct GsInfo {
    pub gid: Vec<u8>,
    pub rgid: Vec<u8>,
    pub ip_addr: IpAddr,
}

lazy_static! {
    static ref GS_LIST: DashMap<String, GsInfo> = DashMap::new();
}

/// Init TA keys
/// Including TA public key $ PUK_{ta} $ and TA private key sk_{ta}
fn init_ta_keys() -> (BIG, ECP) {
    let sk_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let sk_ta = BIG::frombytes(&sk_bytes);
    let puk_ta = ECP::generator().mul(&sk_ta);
    (sk_ta, puk_ta)
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();
    let (sk_ta, puk_ta) = init_ta_keys();
    tracing::info!("sk_ta: {}", sk_ta);
    tracing::info!("puk_ta: {}", puk_ta);
    let mut puk_ta_bytes = vec![0u8; 65];
    puk_ta.tobytes(&mut puk_ta_bytes, false);
    let addr: SocketAddr = ([0, 0, 0, 0], 8090).into();
    let listener = TcpListener::bind(addr).await?;
    loop {
        // accept connections and process them serially
        let (stream, addr) = listener.accept().await?;
        tokio::spawn(tcp_accept(stream, addr));
    }
}

async fn tcp_accept(stream: TcpStream, addr: SocketAddr) -> anyhow::Result<()> {
    let mut stream = stream;
    let ip_addr = addr.ip();
    tracing::info!("connection from {:?}", addr);
    let types = stream.read_i8().await?;
    // 0b0000_0001 means gs register
    // 0b0000_0010 means uav register
    //
    // 0b0000_0100 means gs authentication
    match types {
        // gs
        1 => {
            let mut framed = Framed::new(stream, GsRegisterCodec);
            while let Some(Ok(item)) = framed.next().await {
                tracing::info!("gs register");
                // if gs not registered, then can register, else reject register
                if GS_LIST.contains_key(&item.gid.encode_hex::<String>()) {
                    tracing::warn!("gs already registered");
                    framed
                        .send(pb::register_ta_gs::GsResponse { status: 1 })
                        .await
                        .unwrap();
                    continue;
                }

                // register success
                let gid = item.gid.to_vec();
                let rgid = item.rgid.to_vec();

                // insert to gs list
                GS_LIST.insert(rgid.encode_hex(), GsInfo { gid, rgid, ip_addr });

                // send response to gs
                framed
                    .send(pb::register_ta_gs::GsResponse { status: 0 })
                    .await
                    .unwrap();
                tracing::debug!("gs addr: {}", ip_addr);
                tracing::debug!("gs rgid: {} ", item.rgid.encode_hex::<String>());
                tracing::info!("gs register success");
            }
        }
        // uav
        2 => {}
        // gs authentication
        0x04 => {}
        // unreadable
        _ => {}
    }
    Ok(())
}
