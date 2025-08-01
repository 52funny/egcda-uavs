use crate::{PUF, TAG, UAV_CONFIG};
use blake2::Blake2b512;
use blstrs_plus::{elliptic_curve::hash2curve::ExpandMsgXmd, group::prime::PrimeCurveAffine, G1Affine, G1Projective, Scalar};
use hex::ToHex;
use rpc::*;
use tarpc::context;
use tracing::{info, warn};
use utils::abbreviate_key_default;

pub(crate) async fn auth(client: &GsRpcClient) -> anyhow::Result<()> {
    let uav = UAV_CONFIG.get().cloned().expect("UAV not found");
    let uid = uav.uid;

    let resp1 = client
        .authenticate_uav_phase1(context::current(), UavAuthRequest1 { uid: uid.clone() })
        .await?;
    if resp1.is_none() {
        warn!("UAV not registered or invalid UID");
        return Ok(());
    }
    let resp1 = resp1.unwrap();

    let start = std::time::Instant::now();

    let challenge = resp1.puf_challenge;
    let puf_response = PUF.calculate(&challenge).await?;
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
    let resp2 = client.authenticate_uav_phase2(context::current(), req2).await?;

    if resp2.is_none() {
        warn!("UAV authentication failed: Invalid response from GS");
        return Ok(());
    }
    info!("Authentication took: {:?}", start.elapsed());
    info!("UAV authentication successful with uid: {}", abbreviate_key_default(&uid));
    Ok(())
}
