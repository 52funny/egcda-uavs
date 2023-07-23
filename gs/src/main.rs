mod codec;
use std::mem::MaybeUninit;
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::pair;
use pb::auth_ta_gs::gs_auth_response::Response;
use rand::{thread_rng, Rng};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

pub struct GSConfig {
    pub gid: [u8; 32],
    pub rgid: [u8; 32],
    pub sk_gs: BIG,
    pub puk_gs: ECP,
    pub sk_gs_bytes: Vec<u8>,
    pub puk_gs_bytes: Vec<u8>,
}
lazy_static::lazy_static! {
    static ref GS_CONFIG: GSConfig = init_gs_keys();
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
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("info".parse().unwrap()))
        .init();

    let addr = "127.0.0.1:8090";
    register(addr).await?;
    auth(addr).await?;
    Ok(())
}

// Register self to TA
async fn register(addr: &str) -> anyhow::Result<()> {
    // connect to server
    let mut stream = TcpStream::connect(addr).await?;

    // 1 means gs register
    stream.write_u8(1).await.unwrap();

    let _addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, codec::gs_register_codec::GsRegisterCodec);

    let gid = Bytes::from(GS_CONFIG.gid.to_vec());
    let rgid = Bytes::from(GS_CONFIG.rgid.to_vec());

    let req = pb::register_ta_gs::GsRequest { gid, rgid };

    frame.send(req).await?;
    if let Some(Ok(res)) = frame.next().await {
        tracing::info!(
            "gs register status: {}",
            if res.status == 1 { "failed" } else { "success" }
        );
    }
    Ok(())
}

// Auth self to TA
async fn auth(addr: &str) -> anyhow::Result<()> {
    // connect to server
    let mut stream = TcpStream::connect(addr).await?;

    // 1 means gs auth
    stream.write_u8(4).await.unwrap();

    let _addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, codec::gs_auth_codec::GsAuthCodec);

    // lazy init puk_gs
    let mut puk_ta_bytes = MaybeUninit::<Vec<u8>>::uninit();
    // receive ta public parameter
    if let Some(Ok(res)) = frame.next().await {
        if let Some(Response::TaPublicParameter(paramter)) = res.response {
            tracing::info!("get ta public key: {}", hex::encode(&paramter.puk_gs));
            puk_ta_bytes.write(paramter.puk_gs.to_vec());
        } else {
            anyhow::bail!("get ta public parameter failed");
        }
    };

    // auth phase 1
    let gid = hex::encode(GS_CONFIG.gid);
    let t = chrono::Utc::now().timestamp();
    let hash_str = sha256::digest(gid + &t.to_string());
    // 32 byte
    let hash = hex::decode(&hash_str)?;
    let puk_ta = ECP::frombytes(unsafe { puk_ta_bytes.assume_init_ref() });
    let p = puk_ta.mul(&BIG::frombytes(&hash));
    let q = ECP2::generator();
    let fp = pair::ate(&q, &p);
    let fp = pair::fexp(&fp);
    let mut fp = fp.pow(&GS_CONFIG.sk_gs);
    // let mut fp = pair::fexp(&fp);

    let mut sig = vec![0u8; 32 * 2 * 6];
    fp.tobytes(&mut sig);
    tracing::info!("sig: {}", hex::encode(&sig));
    frame
        .send(pb::auth_ta_gs::GsAuthRequest::new_gs_auth_phase1_message(
            GS_CONFIG.rgid.to_vec(),
            t,
            hash_str,
            sig,
            GS_CONFIG.puk_gs_bytes.clone(), // puk_gs,
        ))
        .await?;

    // receive auth phase 2
    if let Some(Ok(res)) = frame.next().await {
        if let Some(Response::GsAuthPhase2(status)) = res.response {
            tracing::info!(
                "auth: {}",
                if status.status == 0 {
                    "success"
                } else {
                    "failed"
                }
            );
        } else {
            anyhow::bail!("get auth phase 2 failed");
        }
    };
    Ok(())
}
