mod codec;
use codec::gs_register_codec::GsRegisterCodec;
use dashmap::DashMap;
use futures::{SinkExt, StreamExt};
use hex::ToHex;
use lazy_static::lazy_static;
use mcore::bn254::ecp::ECP;
use mcore::bn254::fp12::FP12;
use mcore::bn254::pair;
use mcore::bn254::{big::BIG, ecp2::ECP2};
use pb::auth_ta_gs::gs_auth_request;
use pb::auth_ta_gs::GsAuthResponse;
use rand::Rng;
use std::net::{IpAddr, SocketAddr};
use tokio::{
    io::AsyncReadExt,
    net::{TcpListener, TcpStream},
};
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

use crate::codec::gs_auth_codec::GsAuthCodec;

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

lazy_static! {
    static ref GS_LIST: DashMap<String, GsInfo> = DashMap::new();
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

lazy_static! {
    static ref TA_CONFIG: TAConfig = init_ta_keys();
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
        0x01 => {
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
        0x02 => {}
        // gs authentication
        0x04 => {
            let mut framed = Framed::new(stream, GsAuthCodec);
            framed
                .send(GsAuthResponse::new_ta_public_parameter_message(
                    TA_CONFIG.puk_ta_bytes.clone(),
                ))
                .await?;
            if let Some(Ok(res)) = framed.next().await {
                if let Some(gs_auth_request::Request::GsAuthPhase1(param)) = res.request {
                    let t1 = std::time::Instant::now();
                    // check timestamp
                    let now_t = chrono::Utc::now().timestamp();
                    if now_t - param.t > 60 {
                        anyhow::bail!("timestamp expired");
                    }
                    // encode rgid to hex
                    let rgid = hex::encode(param.rgid);

                    // check gs rgid
                    // if not registered, then reject
                    if !GS_LIST.contains_key(&rgid) {
                        anyhow::bail!("gs not registered");
                    }

                    // get gid from dashmap
                    let gid = GS_LIST.get(&rgid).unwrap().gid.clone();

                    // compute hash using sha256
                    let gid_str = gid.encode_hex::<String>();
                    let t_str = param.t.to_string();
                    let hash_str = sha256::digest(gid_str + &t_str);
                    // if hash not equal, then reject
                    if hash_str != param.hash {
                        anyhow::bail!("invalid hash");
                    }

                    let hash_bytes = hex::decode(hash_str).unwrap();
                    let hash_ = BIG::frombytes(&hash_bytes);
                    let q = ECP2::generator().mul(&hash_);
                    let p = ECP::frombytes(&param.puk_gs);

                    let t2 = std::time::Instant::now();
                    // compute ta signature
                    let sig_ = pair::ate(&q, &p);
                    let sig_ = pair::fexp(&sig_);
                    let sig_ = sig_.pow(&TA_CONFIG.sk_ta);

                    // convert bytes to fp12
                    let sig = FP12::frombytes(&param.signature);

                    // check signature is valid
                    let status = if sig_.equals(&sig) {
                        tracing::info!("sig equals");
                        0
                    } else {
                        tracing::warn!("sig not equals");
                        1
                    };
                    tracing::info!("t1 time: {:?}", t1.elapsed());
                    tracing::info!("t2 time: {:?}", t2.elapsed());

                    framed
                        .send(GsAuthResponse::new_gs_auth_phase2_message(status))
                        .await?;
                } else {
                    anyhow::bail!("invalid request");
                }
            }
        }
        // unreadable
        _ => {}
    }
    Ok(())
}
