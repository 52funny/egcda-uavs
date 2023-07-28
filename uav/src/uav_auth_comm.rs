use crate::codec::uav_auth_codec::UavAuthCodec;
use crate::codec::uav_communicate_codec::UavGsCommunicateCodec;
use crate::{PUF, UAV};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use futures::{SinkExt, StreamExt};
use mcore::bn254;
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use pb::auth_gs_uav::{uav_auth_response, UavAuthRequest};
use pb::communicate_gs_uav::{uav_gs_communicate_response, UavGsCommunicateRequest};
use rand::Rng;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn auth_comm(addr: &str) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    tracing::debug!("---------------------------uav auth---------------------------");
    let status = auth(&mut stream).await?;
    tracing::debug!("---------------------------uav auth---------------------------");

    tracing::info!("uav auth result: {}", if status { "ok" } else { "fail" });

    tracing::debug!("----------------------uav gs communicate----------------------");
    communicate(stream).await?;
    tracing::debug!("----------------------uav gs communicate----------------------");
    Ok(())
}

async fn auth(stream: &mut TcpStream) -> anyhow::Result<bool> {
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

    tracing::debug!("t_gs    : {}", param.t_gs);
    tracing::debug!("id_gs   : {}", hex::encode(&param.id_gs));
    tracing::debug!("r_gs    : {}", hex::encode(&param.r_gs));
    tracing::debug!("q_gs    : {}", hex::encode(&param.q_gs));

    let t = std::time::Instant::now();

    // start auth phase1
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

    tracing::debug!("t_u     : {}", t_u);
    tracing::debug!("tuid    : {}", hex::encode(&tuid));
    tracing::debug!("r_u     : {}", hex::encode(r_u_bytes));
    tracing::debug!("v_i     : {}", hex::encode(&v_i_bytes));
    tracing::debug!("gamma_i : {}", hex::encode(&gamma_i_bytes));

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
    tracing::info!("uav auth phase2 speed time: {:?}", t.elapsed());
    Ok(status == 0)
}

async fn communicate(stream: TcpStream) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, UavGsCommunicateCodec);
    framed.flush().await?;
    framed
        .send(UavGsCommunicateRequest::new_communicate_message(vec![]))
        .await?;
    let param = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_gs_communicate_response::Response::CommunicateParam(param)) = res.response {
            param
        } else {
            anyhow::bail!("framed get uav communicate param message error");
        }
    } else {
        anyhow::bail!("framed recv at uav communicate param message error");
    };
    tracing::debug!("lambda: {}", hex::encode(&param.lambda));
    tracing::debug!("t     : {}", param.t);
    tracing::debug!("c     : {}", hex::encode(&param.c));

    // validate timestamp
    let t_now = chrono::Utc::now().timestamp();
    if t_now - param.t > 5 {
        anyhow::bail!("t_now - param.t > 5");
    }

    // calculate lambda'
    let uid = UAV.get().unwrap().uid.clone();
    let mut hash_content = uid;
    hash_content.extend_from_slice(&param.t.to_be_bytes());
    hash_content.extend_from_slice(&param.c);
    let lambda_ = hex::decode(sha256::digest(&hash_content))?;

    // validate lambda'
    if lambda_ != param.lambda {
        anyhow::bail!("lambda' != param.lambda");
    }
    let r = hex::decode(PUF.calculate(hex::encode(&param.c)).await?)?;

    // calculate key
    let mut key = lambda_;
    for i in 0..key.len() {
        key[i] ^= r[i];
    }

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let aes = aes_gcm::Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&key[..12]);

    tracing::debug!("key: {}", hex::encode(key));

    let input = "hello".as_bytes();
    let output = aes.encrypt(nonce, input).unwrap();
    framed
        .send(UavGsCommunicateRequest::new_communicate_message(output))
        .await?;
    Ok(())
}
