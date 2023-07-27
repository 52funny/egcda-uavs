use crate::codec::uav_auth_codec::UavAuthCodec;
use crate::{GS_CONFIG, UAV_LIST};
use futures::{SinkExt, StreamExt};
use pb::auth_gs_uav::uav_auth_request::Request;
use pb::auth_gs_uav::UavAuthResponse;
use rand::Rng;
use rug::Integer;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn uav_auth(stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, UavAuthCodec);
    let ruid = if let Some(Ok(res)) = framed.next().await {
        if let Some(Request::Hello(ruid)) = res.request {
            // hello message
            tracing::info!("Uav auth hello message");
            ruid.ruid
        } else {
            anyhow::bail!("framed get uav auth hello message error");
        }
    } else {
        anyhow::bail!("framed recv at uav auth hello message error")
    };

    let uav_info = UAV_LIST.0.get(&hex::encode(&ruid));
    if uav_info.is_none() {
        tracing::error!("uav not register");
        anyhow::bail!("uav not register");
    }
    let uav_info = uav_info.unwrap();

    // get the public param
    let (t_gs, id_gs, r_gs, q_gs) = public_param().await?;

    // send the public param
    framed
        .send(UavAuthResponse::new_uav_auth_gs_public_param(
            t_gs,
            id_gs,
            r_gs,
            q_gs,
            uav_info.c.clone(),
        ))
        .await?;
    Ok(())
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
async fn public_param() -> anyhow::Result<(i64, Vec<u8>, Vec<u8>, Vec<u8>)> {
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

    tracing::info!("t_gs : {}", unsafe { T_GS });
    tracing::info!("id_gs: {}", hex::encode(&id_gs));
    tracing::info!("r_gs : {}", hex::encode(&r_gs));
    tracing::info!("q_gs : {}", hex::encode(&q_gs));
    Ok((unsafe { T_GS }, id_gs, r_gs, q_gs))
}
