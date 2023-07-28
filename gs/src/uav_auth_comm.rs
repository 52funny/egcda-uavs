use crate::codec::uav_auth_codec::UavAuthCodec;
use crate::codec::uav_communicate_codec::UavGsCommunicateCodec;
use crate::{UavAuthInfo, UavInfo, GS_CONFIG, UAV_AUTH_LIST, UAV_AUTH_LIST_STATE, UAV_LIST};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use dashmap::Map;
use futures::{SinkExt, StreamExt};
use mcore::bn254::big::BIG;
use mcore::bn254::ecp::ECP;
use mcore::bn254::ecp2::ECP2;
use mcore::bn254::pair;
use pb::auth_gs_uav::uav_auth_request::Request;
use pb::auth_gs_uav::UavAuthResponse;
use pb::communicate_gs_uav::{uav_gs_communicate_request, UavGsCommunicateResponse};
use rand::Rng;
use rug::Integer;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn uav_auth_communicate(mut stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    tracing::debug!("---------------------------uav auth---------------------------");
    let (uav_info, status) = uav_auth(&mut stream, _addr).await?;
    tracing::debug!("---------------------------uav auth---------------------------");
    tracing::info!("uav auth result: {}", if status { "ok" } else { "fail" });
    if !status {
        return Ok(());
    }

    let key = hex::encode(&uav_info.ruid);
    let uav_auth_info = crate::UavAuthInfo {
        ip_addr: _addr.ip(),
        uid: uav_info.uid,
        ruid: uav_info.ruid,
        c: uav_info.c,
        r: uav_info.r,
        n: uav_info.n,
    };
    let (tx, rx) = futures_channel::mpsc::unbounded::<String>();
    let tx2 = tx.clone();
    UAV_AUTH_LIST_STATE.insert(key.clone(), tx);

    UAV_AUTH_LIST_STATE
        .iter()
        .filter(|k| *k.key() != key)
        .for_each(|k| {
            // send uav auth ruid to already connected uav
            k.value().unbounded_send(key.clone()).unwrap();
            // send already connected uav ruid to myself
            tx2.unbounded_send(k.key().clone()).unwrap();
        });

    UAV_AUTH_LIST.0._insert(key.clone(), uav_auth_info.clone());

    tracing::debug!("---------------------uav gs communication---------------------");
    uav_commuicate(&mut stream, _addr, rx, uav_auth_info).await?;
    tracing::debug!("---------------------uav gs communication---------------------");

    UAV_AUTH_LIST_STATE.remove(&key);
    Ok(())
}

async fn uav_commuicate(
    stream: &mut TcpStream,
    _addr: SocketAddr,
    rx: futures_channel::mpsc::UnboundedReceiver<String>,
    uav_auth_info: UavAuthInfo,
) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, UavGsCommunicateCodec);
    let _ = framed.next().await;
    let t = chrono::Utc::now().timestamp();
    let mut hash_content = uav_auth_info.uid.clone();
    hash_content.extend_from_slice(&t.to_be_bytes());
    hash_content.extend_from_slice(&uav_auth_info.c);
    let lambda = hex::decode(sha256::digest(&hash_content))?;
    framed
        .send(UavGsCommunicateResponse::new_communicate_param_message(
            lambda.clone(),
            t,
            uav_auth_info.c.clone(),
        ))
        .await?;

    let mut key = lambda;
    for (i, k) in key.iter_mut().enumerate() {
        *k ^= uav_auth_info.r[i];
    }
    let key = Key::<Aes256Gcm>::from_slice(&key);
    let aes = Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&key[..12]);

    tracing::debug!("key: {}", hex::encode(key));

    let (outgoing, incoming) = framed.split();

    let receiver = incoming.for_each(|res| async {
        if let Ok(res) = res {
            match res.request {
                Some(uav_gs_communicate_request::Request::CommunicateMessage(message)) => {
                    let b: &[u8] = &message.encrypted_data;
                    let data = aes.decrypt(nonce, b).unwrap();
                    tracing::info!("gs recv uav data: {:?}", data);
                }
                Some(uav_gs_communicate_request::Request::NeedCommunicateRuidList(list)) => {
                    tracing::info!("gs recv uav param: {:?}", list.ruid);
                }
                _ => {}
            }
        }
    });
    let sender = rx
        .map(|x| UavGsCommunicateResponse::new_already_communicate_ruid_list(vec![x]))
        .map(Ok)
        .forward(outgoing);

    futures::pin_mut!(receiver, sender);

    futures::future::select(receiver, sender).await;

    Ok(())
}

async fn uav_auth(stream: &mut TcpStream, _addr: SocketAddr) -> anyhow::Result<(UavInfo, bool)> {
    let mut framed = Framed::new(stream, UavAuthCodec);
    let ruid = if let Some(Ok(res)) = framed.next().await {
        if let Some(Request::Hello(ruid)) = res.request {
            ruid.ruid
        } else {
            anyhow::bail!("framed get uav auth hello message error");
        }
    } else {
        anyhow::bail!("framed recv at uav auth hello message error")
    };

    // hello message
    tracing::debug!("uav hello message");

    let uav_info = UAV_LIST.0.get(&hex::encode(&ruid));
    if uav_info.is_none() {
        anyhow::bail!("uav not register");
    }
    let uav_info = uav_info.unwrap().clone();

    // get the public param
    let (random_gs, t_gs, id_gs, r_gs, q_gs) = public_param().await?;

    tracing::debug!("t_gs  : {}", t_gs);
    tracing::debug!("id_gs : {}", hex::encode(&id_gs));
    tracing::debug!("r_gs  : {}", hex::encode(&r_gs));
    tracing::debug!("q_gs  : {}", hex::encode(&q_gs));

    // send the public param
    framed
        .send(UavAuthResponse::new_uav_auth_gs_public_param_message(
            t_gs,
            id_gs.clone(),
            r_gs.clone(),
            q_gs,
            uav_info.c.clone(),
        ))
        .await?;

    // auth phase
    let status = uav_auth_phase(&mut framed, &uav_info, id_gs, random_gs, r_gs).await?;
    Ok((uav_info, status))
}

/// 10 second
static DELTA_T: i64 = 10;

/// If t_now - t_gs > DELTA_T, then update t_gs
static mut T_GS: i64 = -1;

// 2^256 - 1
lazy_static::lazy_static! {
    static ref Q: Integer =  Integer::from_digits(
        &[
            0xffu8, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
            0xff, 0xff,
        ],
        rug::integer::Order::MsfLe,
    );
}

/// get the uav auth public param
async fn public_param() -> anyhow::Result<(Vec<u8>, i64, Vec<u8>, Vec<u8>, Vec<u8>)> {
    // current timestamp
    let t_now = chrono::Utc::now().timestamp();
    // get t_gs, if not init, then using t_now init.
    if unsafe { T_GS } == -1 {
        unsafe {
            T_GS = t_now;
        }
    }
    // if t_now - t_gs > DELTA_T, then update t_gs
    if t_now - unsafe { T_GS } > DELTA_T {
        // update it
        unsafe {
            T_GS = t_now;
        }
    }

    // generate random r_gs
    let random_gs = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let random_gs_integer = Integer::from_digits(&random_gs, rug::integer::Order::MsfBe);

    let mut hash_content = GS_CONFIG.gid.to_vec();
    let t_gs_bytes = unsafe { T_GS }.to_be_bytes().to_vec();
    hash_content.extend_from_slice(&t_gs_bytes);
    let id_gs = hex::decode(sha256::digest(&hash_content))?;

    let mut hash_content = GS_CONFIG.sk_gs_bytes.clone();
    hash_content.extend_from_slice(&t_gs_bytes);
    let r_gs_parts1 = hex::decode(sha256::digest(&hash_content))?;
    let r_gs_parts1_integer = Integer::from_digits(&r_gs_parts1, rug::integer::Order::MsfBe);
    let r_gs_integer = (r_gs_parts1_integer * random_gs_integer) & Q.clone();
    let r_gs = r_gs_integer.to_digits::<u8>(rug::integer::Order::MsfBe);

    let mut hash_content = id_gs.clone();
    hash_content.extend_from_slice(&random_gs);
    let q_gs_parts_bytes = hex::decode(sha256::digest(&hash_content))?;
    let p = mcore::bn254::ecp::ECP::generator();
    let q_gs_big = mcore::bn254::big::BIG::frombytes(&q_gs_parts_bytes);
    let p = p.mul(&GS_CONFIG.sk_gs).mul(&q_gs_big);
    let mut q_gs = vec![0u8; 65];
    p.tobytes(&mut q_gs, false);
    Ok((random_gs.to_vec(), unsafe { T_GS }, id_gs, r_gs, q_gs))
}

async fn uav_auth_phase(
    framed: &mut Framed<&mut TcpStream, UavAuthCodec>,
    uav_info: &UavInfo,
    id_gs: Vec<u8>,
    random_gs: Vec<u8>,
    r_gs: Vec<u8>,
) -> anyhow::Result<bool> {
    let phase = if let Some(Ok(res)) = framed.next().await {
        if let Some(Request::UavAuthPhase1(p)) = res.request {
            p
        } else {
            anyhow::bail!("framed get uav auth phase1 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav auth phase1 message error");
    };
    let t = std::time::Instant::now();
    let p = ECP::generator();
    let q = ECP2::generator();

    let mut hash_content = uav_info.r.clone();
    hash_content.extend_from_slice(&phase.r_u);
    let sigma_i = p.mul(&BIG::frombytes(&hex::decode(sha256::digest(
        &hash_content,
    ))?));

    let mut gamma_i = ECP::frombytes(&phase.gamma_i);
    gamma_i.add(&sigma_i);

    let psi_i = pair::ate(&q, &gamma_i);
    let psi_i = pair::fexp(&psi_i);

    let delta_i = pair::ate(
        &q.mul(&BIG::frombytes(&phase.v_i))
            .mul(&BIG::frombytes(&phase.r_u)),
        &p.mul(&GS_CONFIG.sk_gs),
    );
    let delta_i = pair::fexp(&delta_i);

    let mut hash_content = phase.tuid_i.to_vec();
    hash_content.extend_from_slice(&phase.t_u.to_be_bytes());
    hash_content.extend_from_slice(&phase.r_u);

    let tmp_hash = hex::decode(sha256::digest(&hash_content));
    let mu_i = pair::ate(
        &q.mul(&BIG::frombytes(&uav_info.r)),
        &p.mul(&BIG::frombytes(&tmp_hash?)),
    );
    let mu_i = pair::fexp(&mu_i);

    let mut hash_content = id_gs;
    hash_content.extend_from_slice(&random_gs);
    let exponent1 = BIG::frombytes(&hex::decode(sha256::digest(&hash_content))?);
    let exponent2 = BIG::frombytes(&r_gs);

    // verify that the equations are equal
    let mut p1 = psi_i;
    p1.mul(&delta_i.pow(&exponent1));

    let p2 = mu_i;
    let p2 = p2.pow(&exponent2);

    let status = if p1.equals(&p2) { 0 } else { 1 };

    tracing::info!("spend time: {:?}", t.elapsed());
    // send status to uav
    framed
        .send(UavAuthResponse::new_uav_auth_phase2_message(status))
        .await?;
    Ok(status == 0)
}
