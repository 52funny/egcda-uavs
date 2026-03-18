use crate::{uav_cfg::UavConfig, PUF, TAG, TA_PUBKEY1, UAV_CONFIG};
use blake2::Blake2b512;
use blstrs_plus::{
    elliptic_curve::hash2curve::ExpandMsgXmd,
    group::{prime::PrimeCurveAffine, Group},
    G1Affine, G1Projective, Scalar,
};
use hex::ToHex;
use rayon::iter::{IndexedParallelIterator, IntoParallelRefIterator, ParallelIterator};
use rpc::*;
use tarpc::context;
use tracing::{info, warn};
use utils::{abbreviate_key_default, hash_to_scalar};

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
    if (chrono::Utc::now().timestamp() - resp1.t_g).abs() > 10 {
        anyhow::bail!("Ground station authentication request is too old");
    }

    let puf_response = PUF.get().unwrap().calculate(&challenge).await?;
    let r = hex::decode(&puf_response)?;
    let mut r_buf = [0u8; 64];
    r_buf[..r.len()].copy_from_slice(&r);
    let r_scalar = Scalar::from_bytes_wide(&r_buf);

    let g_r = G1Affine::generator() * r_scalar;
    let x = G1Affine::from_compressed_hex(&resp1.x).expect("Invalid GS nonce point");
    let gs_pk = G1Affine::from_compressed_hex(&resp1.gs_pubkey).expect("Invalid GS public key");
    let z = G1Affine::from(*TA_PUBKEY1.get().expect("TA public key not found") * r_scalar);

    let mut e_buf = Vec::with_capacity(
        challenge.len() + uid.len() + 8 + gs_pk.to_compressed().len() + x.to_compressed().len() + z.to_compressed().len(),
    );
    e_buf.extend_from_slice(challenge.as_bytes());
    e_buf.extend_from_slice(uid.as_bytes());
    e_buf.extend_from_slice(&resp1.t_g.to_be_bytes());
    e_buf.extend_from_slice(&gs_pk.to_compressed());
    e_buf.extend_from_slice(&x.to_compressed());
    e_buf.extend_from_slice(&z.to_compressed());
    let e = hash_to_scalar(&e_buf);

    let sigma_g = Scalar::from_be_hex(&resp1.sigma_g).expect("Invalid GS signature");
    let lhs = G1Projective::generator() * sigma_g;
    let rhs = G1Projective::from(x) + (G1Projective::from(gs_pk) * e);
    if lhs != rhs {
        anyhow::bail!("Ground station signature verification failed");
    }

    let t_u = chrono::Utc::now().timestamp();

    let mut buf = Vec::with_capacity(challenge.len() + g_r.to_compressed().len() + uid.len() + 8);
    buf.extend_from_slice(challenge.as_bytes());
    buf.extend_from_slice(&g_r.to_compressed());
    buf.extend_from_slice(uid.as_bytes());
    buf.extend_from_slice(&t_u.to_be_bytes());

    let h_i = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);
    let sigma = h_i * uav.sk;

    let req2 = UavAuthRequest2 {
        uid: uid.clone(),
        sigma: sigma.to_compressed().encode_hex::<String>(),
        g_r: g_r.to_compressed().encode_hex::<String>(),
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
    let responses = client
        .batch_authenticate_uavs_phase1(ctx, uids)
        .await?
        .ok_or(anyhow::anyhow!("No response from GS in phase 1"))?;

    let phase1 = responses
        .iter()
        .map(|resp| serde_json::from_str::<UavAuthResponse1>(resp).map_err(anyhow::Error::from))
        .collect::<Result<Vec<_>, _>>()?;

    let rs = futures::future::join_all(phase1.iter().map(|resp| PUF.get().unwrap().calculate(&resp.puf_challenge)))
        .await
        .into_iter()
        .collect::<Result<Vec<_>, _>>()?;

    let r_scalars = rs
        .par_iter()
        .map(|r| {
            let r = hex::decode(r).map_err(anyhow::Error::from)?;
            let mut r_buf = [0u8; 64];
            r_buf[..r.len()].copy_from_slice(&r);
            Ok::<_, anyhow::Error>(Scalar::from_bytes_wide(&r_buf))
        })
        .collect::<Result<Vec<_>, _>>()?;

    let g_rs = r_scalars
        .par_iter()
        .map(|r_scalar| G1Affine::from(G1Affine::generator() * r_scalar))
        .collect::<Vec<_>>();

    phase1
        .par_iter()
        .zip(r_scalars.par_iter())
        .zip(uavs.par_iter())
        .try_for_each(|((resp, r_scalar), uav)| -> anyhow::Result<()> {
            if (chrono::Utc::now().timestamp() - resp.t_g).abs() > 10 {
                anyhow::bail!("Ground station authentication request is too old");
            }
            let x = G1Affine::from_compressed_hex(&resp.x).expect("Invalid GS nonce point");
            let gs_pk = G1Affine::from_compressed_hex(&resp.gs_pubkey).expect("Invalid GS public key");
            let z = G1Affine::from(*TA_PUBKEY1.get().expect("TA public key not found") * *r_scalar);
            let mut e_buf = Vec::with_capacity(
                resp.puf_challenge.len()
                    + uav.uid.len()
                    + 8
                    + gs_pk.to_compressed().len()
                    + x.to_compressed().len()
                    + z.to_compressed().len(),
            );
            e_buf.extend_from_slice(resp.puf_challenge.as_bytes());
            e_buf.extend_from_slice(uav.uid.as_bytes());
            e_buf.extend_from_slice(&resp.t_g.to_be_bytes());
            e_buf.extend_from_slice(&gs_pk.to_compressed());
            e_buf.extend_from_slice(&x.to_compressed());
            e_buf.extend_from_slice(&z.to_compressed());
            let e = hash_to_scalar(&e_buf);
            let sigma_g = Scalar::from_be_hex(&resp.sigma_g).expect("Invalid GS signature");
            let lhs = G1Projective::generator() * sigma_g;
            let rhs = G1Projective::from(x) + (G1Projective::from(gs_pk) * e);
            if lhs != rhs {
                anyhow::bail!("Ground station signature verification failed");
            }
            Ok(())
        })?;

    let t_u = chrono::Utc::now().timestamp();

    let sigmas = phase1
        .par_iter()
        .zip(g_rs.par_iter())
        .zip(uavs.par_iter())
        .map(|((resp, g_r), uav)| {
            let mut buf = Vec::with_capacity(resp.puf_challenge.len() + g_r.to_compressed().len() + uav.uid.len() + 8);
            buf.extend_from_slice(resp.puf_challenge.as_bytes());
            buf.extend_from_slice(&g_r.to_compressed());
            buf.extend_from_slice(uav.uid.as_bytes());
            buf.extend_from_slice(&t_u.to_be_bytes());
            let h_i = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);
            h_i * uav.sk
        })
        .map(G1Affine::from)
        .collect::<Vec<_>>();

    let reqs = sigmas
        .par_iter()
        .zip(g_rs.par_iter())
        .zip(uavs.par_iter())
        .map(|((sigma, g_r), uav)| UavAuthRequest2 {
            uid: uav.uid.clone(),
            sigma: sigma.to_compressed().encode_hex::<String>(),
            g_r: g_r.to_compressed().encode_hex::<String>(),
            t_u,
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
