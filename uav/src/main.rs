mod codec;
mod puf;
use clap::Parser;
use codec::uav_auth_codec::UavAuthCodec;
use futures::{SinkExt, StreamExt};
use lazy_static::lazy_static;
use mcore::bn254;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use pb::auth_gs_uav::{uav_auth_response, UavAuthRequest};
use pb::register_ta_uav::uav_register_response::Response;
use pb::register_ta_uav::UavRegisterRequest;
use puf::Puf;
use rand::Rng;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio::sync::OnceCell;
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

#[derive(Debug, Parser)]
struct CliArgs {
    #[arg(short, long)]
    pub register: bool,
}

#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
pub struct Uav {
    pub uid: Vec<u8>,
    pub ruid: Vec<u8>,
}

lazy_static! {
    static ref PUF: Puf = Puf::new(([127, 0, 0, 1], 12345));
}
static UAV: OnceCell<Uav> = OnceCell::const_new();

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("debug".parse().unwrap()))
        .init();
    let args = CliArgs::parse();
    let ta_addr = "127.0.0.1:8090";
    let gs_addr = "127.0.0.1:8091";

    if args.register {
        let _uav = register(ta_addr).await?;
        tracing::debug!("uav: {:?}", UAV.get());
        let f = std::fs::File::create("uav.json")?;
        serde_json::to_writer(f, &_uav)?;
        return Ok(());
    }
    let f = std::fs::File::open("uav.json").expect("not found uav.json, please register.");
    let uav = serde_json::from_reader::<_, Uav>(f)?;

    // insert uav ruid and uid to local database
    UAV.get_or_init(|| futures::future::ready(uav)).await;
    auth(gs_addr).await?;
    Ok(())
}

async fn register(addr: &str) -> anyhow::Result<Uav> {
    let mut stream = TcpStream::connect(addr).await?;
    // 0x02 means uav register
    stream.write_u8(0x02).await?;
    let mut framed = Framed::new(stream, codec::uav_register_codec::UavRegisterCodec);

    // get challenge from TA
    let c = if let Some(Ok(res)) = framed.next().await {
        if let Some(Response::UavRegisterPhase1(c)) = res.response {
            c.c
        } else {
            anyhow::bail!("get uav register phase1 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav register phase1 message error");
    };

    tracing::debug!("uav c: {}", hex::encode(&c));

    // calculate response using puf
    let r = PUF.calculate(hex::encode(c)).await?;

    tracing::debug!("uav r: {}", r.to_ascii_lowercase());

    // send response to TA
    framed
        .send(UavRegisterRequest::new_uav_register_phase2_message(
            hex::decode(r)?,
        ))
        .await?;

    // get uid and ruid from TA
    // first is ruid
    // second is uid
    let id = if let Some(Ok(res)) = framed.next().await {
        if let Some(Response::UavRegisterPhase3(r)) = res.response {
            (r.ruid, r.uid)
        } else {
            anyhow::bail!("get uav register phase3 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav register phase3 message error");
    };

    // insert uav ruid and uid to local database
    UAV.get_or_init(|| {
        futures::future::ready(Uav {
            uid: id.1.to_vec(),
            ruid: id.0.to_vec(),
        })
    })
    .await;

    tracing::debug!("uav ruid: {}", hex::encode(&id.0));
    tracing::debug!("uav uid : {}", hex::encode(&id.1));
    tracing::info!("uav register success");

    Ok(UAV.get().unwrap().clone())
}

async fn auth(addr: &str) -> anyhow::Result<()> {
    let stream = TcpStream::connect(addr).await?;
    let mut framed = Framed::new(stream, UavAuthCodec);
    let ruid = UAV.get().unwrap().ruid.clone();
    let _uid = UAV.get().unwrap().uid.clone();
    // send hello message to gs
    framed.send(UavAuthRequest::new_hello_message(ruid)).await?;
    // get gs public param
    let param = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_auth_response::Response::GsPublicParam(param)) = res.response {
            param
        } else {
            anyhow::bail!("framed get uav get public param message error");
        }
    } else {
        anyhow::bail!("framed recv at uav get public param message error");
    };
    tracing::info!("gs public param: {:?}", param);

    tracing::info!("t_gs: {}", hex::encode(param.t_gs.to_be_bytes()));

    // start auth phase1
    let t = std::time::Instant::now();

    let t_u = chrono::Utc::now().timestamp();
    let r_u_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let r_i_bytes = hex::decode(PUF.calculate(hex::encode(&param.c)).await?)?;

    let mut hash_content = UAV.get().unwrap().uid.clone();
    hash_content.extend_from_slice(&t_u.to_be_bytes());
    hash_content.extend_from_slice(&r_u_bytes);
    let tuid = hex::decode(sha256::digest(&hash_content))?;

    let mut hash_content = tuid.clone();
    hash_content.extend_from_slice(&param.id_gs);
    hash_content.extend_from_slice(&t_u.to_be_bytes());
    hash_content.extend_from_slice(&r_u_bytes);
    let v_i_bytes = hex::decode(sha256::digest(&hash_content))?;

    let p = bn254::ecp::ECP::generator();
    let mut hash_content = tuid.clone();
    hash_content.extend_from_slice(&t_u.to_be_bytes());
    hash_content.extend_from_slice(&r_u_bytes);
    let tmp_hash1 = hex::decode(sha256::digest(&hash_content))?;
    let gamma_first = p
        .mul(&BIG::frombytes(&tmp_hash1))
        .mul(&BIG::frombytes(&r_i_bytes))
        .mul(&BIG::frombytes(&param.r_gs));

    let mut hash_content = r_i_bytes;
    hash_content.extend_from_slice(&r_u_bytes);
    let tmp_hash2 = hex::decode(sha256::digest(&hash_content))?;

    let gamma_second = p.mul(&BIG::frombytes(&tmp_hash2));

    let gamma_third = ECP::frombytes(&param.q_gs)
        .mul(&BIG::frombytes(&v_i_bytes))
        .mul(&BIG::frombytes(&r_u_bytes));
    let mut gamma = gamma_first;
    gamma.sub(&gamma_second);
    gamma.sub(&gamma_third);
    let mut gamma_i_bytes = vec![0u8; 65];
    gamma.tobytes(&mut gamma_i_bytes, false);

    tracing::debug!("t_u : {}", t_u);
    tracing::debug!("tuid: {}", hex::encode(&tuid));
    tracing::debug!("r_u : {}", hex::encode(r_u_bytes));
    tracing::debug!("v_i : {}", hex::encode(&v_i_bytes));
    tracing::debug!("gamma_i: {}", hex::encode(&gamma_i_bytes));

    framed
        .send(UavAuthRequest::new_uav_auth_phase1_message(
            t_u,
            tuid,
            r_u_bytes.to_vec(),
            v_i_bytes,
            gamma_i_bytes,
        ))
        .await?;
    tracing::info!("uav auth phase1 speed time: {:?}", t.elapsed());

    let status = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_auth_response::Response::UavAuthPhase2(status)) = res.response {
            status.status
        } else {
            anyhow::bail!("framed get uav auth phase2 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav auth phase2 message error");
    };
    tracing::info!(
        "uav auth result: {}",
        if status == 0 { "ok" } else { "fail" }
    );
    Ok(())
}
