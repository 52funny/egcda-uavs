use crate::{codec, Uav, PUF, UAV};
use futures::{SinkExt, StreamExt};
use pb::register_ta_uav::uav_register_response::Response;
use pb::register_ta_uav::UavRegisterRequest;
use tokio::io::AsyncWriteExt;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn register(addr: &str) -> anyhow::Result<Uav> {
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
