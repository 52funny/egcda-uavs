use crate::{uav_cfg::UavConfig, PUF, TAG, UAV_CONFIG};
use blake2::Blake2b512;
use blstrs_plus::{elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, G1Affine, G1Projective, Scalar};
use hex::ToHex;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rpc::*;
use tarpc::context;
use tracing::{info, warn};
use utils::abbreviate_key_default;

pub(crate) async fn auth(client: &GsRpcClient) -> anyhow::Result<()> {
    let uav = UAV_CONFIG.get().cloned().expect("UAV not found");
    let uid = uav.uid;
    let ctx = context::current();

    let resp1 = client.authenticate_uav_phase1(ctx, UavAuthRequest1 { uid: uid.clone() }).await?;
    if resp1.is_none() {
        warn!("UAV not registered or invalid UID");
        return Ok(());
    }
    let resp1 = resp1.unwrap();

    let start = std::time::Instant::now();

    let challenge = resp1.puf_challenge;
    let puf_response = PUF.get().unwrap().calculate(&challenge).await?;
    let r = hex::decode(&puf_response)?;
    let mut r_buf = [0u8; 64];
    r_buf[..r.len()].copy_from_slice(&r);
    let r_scalar = Scalar::from_bytes_wide(&r_buf);

    let x = G1Affine::generator() * r_scalar;
    let t_u = chrono::Utc::now().timestamp();

    let mut buf = Vec::with_capacity(challenge.len() + 48 + uid.len() + 8);
    buf.extend_from_slice(challenge.as_bytes());
    buf.extend_from_slice(x.to_compressed().encode_hex::<String>().as_bytes());
    buf.extend_from_slice(uid.as_bytes());
    buf.extend_from_slice(&t_u.to_be_bytes());

    let h_i = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);
    let sigma = h_i * uav.sk;

    let req2 = UavAuthRequest2 {
        uid: uid.clone(),
        sigma: sigma.to_compressed().encode_hex::<String>(),
        x: x.to_compressed().encode_hex::<String>(),
        t_u,
    };
    let resp2 = client.authenticate_uav_phase2(ctx, req2).await?;

    if resp2.is_none() {
        warn!("UAV batch authentication failed in phase2");
        return Ok(());
    }
    info!("Authentication took: {:?}", start.elapsed());
    info!("UAV authentication successful with uid: {}", abbreviate_key_default(&uid));
    Ok(())
}

pub(crate) async fn batch_auth(client: &GsRpcClient, uavs: Vec<UavConfig>) -> anyhow::Result<()> {
    let ctx = context::current();
    let uids = uavs.par_iter().map(|uav| uav.uid.clone()).collect::<Vec<_>>();
    let cs = client
        .batch_authenticate_uavs_phase1(ctx, uids)
        .await?
        .ok_or(anyhow::anyhow!("No response from GS in phase 1"))?;

    let rs = futures::future::join_all(cs.iter().map(|c| PUF.get().unwrap().calculate(c)))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let xs = rs
        .par_iter()
        .map(|r| {
            let r = hex::decode(r).map_err(anyhow::Error::from)?;
            let mut r_buf = [0u8; 64];
            r_buf[..r.len()].copy_from_slice(&r);
            let r_scalar = Scalar::from_bytes_wide(&r_buf);
            let x = G1Affine::generator() * r_scalar;
            Ok::<_, anyhow::Error>(x)
        })
        .map(|x| x.map(G1Affine::from))
        .collect::<Result<Vec<_>, _>>()?;

    let t_u = chrono::Utc::now().timestamp();

    let sigmas = cs
        .par_iter()
        .zip(xs.par_iter())
        .zip(uavs.par_iter())
        .map(|((c, x), uav)| {
            let mut buf = Vec::with_capacity(c.len() + 48 + uav.uid.len() + 8);
            buf.extend_from_slice(c.as_bytes());
            buf.extend_from_slice(x.to_compressed().encode_hex::<String>().as_bytes());
            buf.extend_from_slice(uav.uid.as_bytes());
            buf.extend_from_slice(&t_u.to_be_bytes());
            let h_i = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);
            h_i * uav.sk
        })
        .map(G1Affine::from)
        .collect::<Vec<_>>();

    let reqs = sigmas
        .par_iter()
        .zip(xs.par_iter())
        .zip(uavs.par_iter())
        .map(|((sigma, x), uav)| UavAuthRequest2 {
            uid: uav.uid.clone(),
            sigma: sigma.to_compressed().encode_hex::<String>(),
            x: x.to_compressed().encode_hex::<String>(),
            t_u: chrono::Utc::now().timestamp(),
        })
        .collect::<Vec<_>>();

    let resp2 = client.batch_authenticate_uavs_phase2(ctx, reqs).await?;

    if resp2.is_none() {
        warn!("Batch authentication failed in phase2");
        return Ok(());
    }

    info!("Batch authentication successful");
    Ok(())
}
