use crate::codec::uav_register_codec::UavRegisterCodec;
use crate::{UavInfo, UAV_LIST};
use futures::{SinkExt, StreamExt};
use rand::Rng;
use rug::Integer;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

/// Uav register function
/// It first send a random C to uav
/// After that, a response R was received through the puf calculation of the drone
/// Then TA generate (uid, ruid) send to uav
/// When all the above steps are completed, the UAV registration is successful
pub async fn uav_register(stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    tracing::info!("uav register");
    let mut framed = Framed::new(stream, UavRegisterCodec);
    // send c to uav
    let c = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    tracing::debug!("uav c: {}", hex::encode(&c));
    framed
        .send(pb::register_ta_uav::UavRegisterResponse::new_uav_register_phase1_message(c.clone()))
        .await?;

    // receive r from uav
    let r = if let Some(Ok(res)) = framed.next().await {
        if let Some(r) = res.uav_register_phase2 {
            r.r
        } else {
            anyhow::bail!("get uav register phase2 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav register phase2 message error");
    };
    let r = r.to_vec();

    tracing::debug!("uav r: {}", hex::encode(&r));

    let n = Integer::from_digits(&r, rug::integer::Order::MsfBe).next_prime();
    tracing::debug!("uav n: {}", n);

    // generate uid and ruid
    let uid = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    let ruid = rand::thread_rng().gen::<[u8; 32]>().to_vec();
    tracing::debug!("uav uid: {}", hex::encode(&uid));
    tracing::debug!("uav ruid: {}", hex::encode(&ruid));
    framed
        .send(
            pb::register_ta_uav::UavRegisterResponse::new_uav_register_phase3_message(
                uid.clone(),
                ruid.clone(),
            ),
        )
        .await?;
    UAV_LIST
        .0
        .insert(hex::encode(&uid), UavInfo { uid, ruid, c, r, n });
    tracing::info!("uav register success");
    Ok(())
}
