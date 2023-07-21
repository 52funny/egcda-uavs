mod codec;
use codec::gs_register_codec::GsServerCodec;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex::ToHex;
use lazy_static::lazy_static;
use std::net::{IpAddr, SocketAddr};
use tokio::{io::AsyncReadExt, net::TcpListener};
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
        let (mut socket, addr) = listener.accept().await?;
        let ip_addr = addr.ip();
        tracing::info!("connection from {:?}", addr);

        tokio::spawn(async move {
            let types = socket.read_i8().await;
            if types.is_err() {
                tracing::error!("read types error: {:?}", types);
                return;
            }
            match types.unwrap() {
                // gs
                1 => {
                    let mut framed = Framed::new(socket, GsServerCodec);
                    while let Some(Ok(item)) = framed.next().await {
                        tracing::debug!("got request: {:?}", item);
                        framed
                            .send(pb::register_ta_gs::GsResponse { status: 0 })
                            .await
                            .unwrap();

                        let gid = item.gid.to_vec();
                        let rgid = item.rgid.to_vec();
                        GS_LIST.insert(gid.encode_hex(), GsInfo { gid, rgid, ip_addr });
                        GS_LIST.iter().for_each(|item| {
                            tracing::info!("{:?}", item.key());
                        })
                    }
                }
                // uav
                2 => {}
                // unreadable
                _ => {}
            }
        });
    }
}
