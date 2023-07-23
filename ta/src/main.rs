mod codec;
use codec::gs_register_codec::GsServerCodec;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex::ToHex;
use lazy_static::lazy_static;
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

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();
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
    match types {
        // gs
        1 => {
            let mut framed = Framed::new(stream, GsServerCodec);
            while let Some(Ok(item)) = framed.next().await {
                tracing::debug!("gs register");
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
                tracing::info!("{} gs register success", item.rgid.encode_hex::<String>());
            }
        }
        // uav
        2 => {}
        // unreadable
        _ => {}
    }
    Ok(())
}
