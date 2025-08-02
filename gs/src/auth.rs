use crate::{UavInfo, GS_CONFIG, TAG, UAV_LIST};
use blake2::{Blake2b512, Digest};
use blstrs_plus::{elliptic_curve::hash2curve::ExpandMsgXmd, G1Projective, G2Affine, Scalar};
use chrono::Utc;
use hex::ToHex;
use rpc::{GsAuthRequest, GsAuthResponseStruct, TaRpcClient};
use tarpc::context;
use tracing::{debug, info};
use utils::{abbreviate_key_default, decrypt_aes128_gcm};

#[allow(clippy::missing_transmute_annotations)]
pub(crate) async fn auth(client: &TaRpcClient, ta_pk: &G2Affine) -> anyhow::Result<()> {
    let start = std::time::Instant::now();
    let (gid, _sk) = (GS_CONFIG.gid.clone(), GS_CONFIG.sk);
    // second since epoch
    let t_g = Utc::now().timestamp();
    let t_g_hex = t_g.to_be_bytes().encode_hex::<String>();

    let mut buf = Vec::with_capacity(gid.len() + 8);
    buf.extend_from_slice(gid.as_bytes());
    buf.extend_from_slice(t_g_hex.as_bytes());
    // H_1(GID, T_g)
    let tau = G1Projective::hash::<ExpandMsgXmd<Blake2b512>>(&buf, TAG);
    let sig = tau * GS_CONFIG.sk;

    let req = GsAuthRequest {
        gid: gid.clone(),
        t_g: t_g_hex,
        sigma: sig.to_compressed().encode_hex::<String>(),
    };

    if client.authenticate_gs(context::current(), req).await?.is_none() {
        anyhow::bail!("Ground station authentication failed");
    }

    info!("GS auth time elapsed: {:?}", std::time::Instant::now() - start);
    info!("Successful authentication with TA: {}", abbreviate_key_default(&gid));

    let mut hasher = Blake2b512::new();
    hasher.update(tau.to_compressed());
    let x = hasher.finalize();
    let x = Scalar::from_bytes_wide(unsafe { &std::mem::transmute::<_, [u8; 64]>(x) });

    let ssk = ta_pk * (x * GS_CONFIG.sk);
    let ssk_bytes = ssk.to_compressed();

    let resp = client.get_uav_list(context::current(), gid.clone()).await?;
    if resp.is_none() {
        anyhow::bail!("Failed to get UAV list from TA");
    }
    let resp = resp.unwrap();

    let data = decrypt_aes128_gcm(ssk_bytes[0..16].try_into().expect("Shared secret key length mismatch"), &resp)
        .map_err(|e| anyhow::anyhow!("AES-GCM decryption failed: {}", e))?;

    let data = serde_json::from_slice::<Vec<GsAuthResponseStruct>>(&data)?;
    debug!("Decrypted UAV data: {:?}", data);
    for uav in data {
        UAV_LIST.0.insert(
            uav.uid.clone(),
            UavInfo {
                uid: uav.uid,
                pk: G2Affine::from_compressed_hex(&uav.pk_u).expect("Invalid UAV public key"),
                c: uav.c,
                z: uav.z,
                p: uav.p,
            },
        );
    }

    info!("Received UAV list size: {}", UAV_LIST.0.len());
    Ok(())
}
