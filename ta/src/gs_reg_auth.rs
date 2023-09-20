use crate::codec::gs_auth_codec::GsAuthCodec;
use crate::codec::gs_register_codec::GsRegisterCodec;
use crate::{GsInfo, GENERATION, P};
use crate::{GS_LIST, TA_CONFIG, UAV_LIST};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use futures::{SinkExt, StreamExt};
use hex::ToHex;
use pb::auth_ta_gs::gs_auth_request;
use pb::auth_ta_gs::GsAuthResponse;
use std::net::SocketAddr;
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

// lazy_static! {
//     static ref PAIRING: Pairing = Pairing::new(TYPE_A);
// }

pub async fn gs_register(stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    let ip_addr = _addr.ip();
    let mut framed = Framed::new(stream, GsRegisterCodec);
    while let Some(Ok(item)) = framed.next().await {
        tracing::info!("gs register");
        // if gs not registered, then can register, else reject register
        if GS_LIST.contains_key(&item.gid.encode_hex::<String>()) {
            tracing::warn!("gs already registered");
            framed
                .send(pb::register_ta_gs::GsResponse { status: 1 })
                .await
                .unwrap();
            continue;
        }

        // register success
        let gid = item.gid.to_vec();
        let rgid = item.rgid.to_vec();

        // insert to gs list
        GS_LIST.insert(rgid.encode_hex(), GsInfo { gid, rgid, ip_addr });

        // send response to gs
        framed
            .send(pb::register_ta_gs::GsResponse { status: 0 })
            .await
            .unwrap();
        tracing::debug!("gs addr: {}", _addr);
        tracing::debug!("gs rgid: {} ", item.rgid.encode_hex::<String>());
        tracing::info!("gs register success");
    }
    Ok(())
}

pub async fn gs_auth(stream: TcpStream, _addr: SocketAddr) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, GsAuthCodec);
    framed
        .send(GsAuthResponse::new_ta_public_parameter_message(
            TA_CONFIG.puk_ta_bytes.clone(),
        ))
        .await?;
    // auth phase
    let (status, puk_gs, hash_) = if let Some(Ok(res)) = framed.next().await {
        if let Some(gs_auth_request::Request::GsAuthPhase1(param)) = res.request {
            let t1 = std::time::Instant::now();
            // check timestamp
            let now_t = chrono::Utc::now().timestamp();
            if now_t - param.t > 60 {
                anyhow::bail!("timestamp expired");
            }
            // encode rgid to hex
            let rgid = hex::encode(param.rgid);

            // check gs rgid
            // if not registered, then reject
            if !GS_LIST.contains_key(&rgid) {
                anyhow::bail!("gs not registered");
            }

            // get gid from dashmap
            let gid = GS_LIST.get(&rgid).unwrap().gid.clone();

            // compute hash using sha256
            let gid_str = gid.encode_hex::<String>();
            let t_str = param.t.to_string();
            let hash_str = sha256::digest(gid_str + &t_str);
            // if hash not equal, then reject
            if hash_str != param.hash {
                anyhow::bail!("invalid hash");
            }

            let hash_bytes = hex::decode(hash_str).unwrap();

            let mut hash_ = P.gr();
            hash_.from_bytes(&hash_bytes);

            tracing::debug!("tau: {:?}", hash_);
            let mut q = P.g2();
            q.from_bytes(GENERATION);
            q.mul_element_zn(hash_.clone());

            // let q = P.g2() * hash_.clone();

            let mut puk_gs = P.g1();
            puk_gs.from_bytes(&param.puk_gs);

            let t2 = std::time::Instant::now();
            // compute ta signature
            //
            let mut sig_ = P.pairing(&puk_gs, &q);

            let mut sk_ta = P.gr();
            sk_ta.from_bytes(&TA_CONFIG.sk_ta_bytes);
            sig_.pow_zn(&sk_ta);

            let mut sig = P.gt();
            sig.from_bytes(&param.signature);

            tracing::debug!("sig: {:?}", sig);
            tracing::debug!("sig_: {:?}", sig_);
            // check signature is valid
            let status = if sig_ == sig {
                tracing::info!("sig equals");
                0
            } else {
                tracing::warn!("sig not equals");
                1
            };
            tracing::info!("t1 time: {:?}", t1.elapsed());
            tracing::info!("t2 time: {:?}", t2.elapsed());
            framed
                .send(GsAuthResponse::new_gs_auth_phase2_message(status))
                .await?;
            (status, puk_gs, hash_)
        } else {
            anyhow::bail!("invalid request");
        }
    } else {
        anyhow::bail!("invalid framed");
    };

    // means gs auth success, then send encryped uav list
    if status == 0 {
        let mut sk_ta = P.gr();
        sk_ta.from_bytes(&TA_CONFIG.sk_ta_bytes);
        let mut ssk_tags = puk_gs;
        ssk_tags.mul_element_zn(sk_ta);
        ssk_tags.mul_element_zn(hash_);

        let ssk_tags_bytes = ssk_tags.as_bytes();
        let ssk_tags_bytes_sha2 = hex::decode(sha256::digest(&ssk_tags_bytes))?;

        tracing::debug!("ssk_tags: {:?}", hex::encode(ssk_tags_bytes));

        let key = Key::<Aes256Gcm>::from_slice(&ssk_tags_bytes_sha2);
        let nonce = Nonce::from_slice(&ssk_tags_bytes_sha2[..12]);
        let aes_gcm = aes_gcm::Aes256Gcm::new(key);

        tracing::debug!("aes key: {}", hex::encode(&ssk_tags_bytes_sha2));
        tracing::debug!("aes nonce: {}", hex::encode(nonce));

        let input_str = serde_json::to_string(&UAV_LIST.0)?;
        let input = input_str.as_bytes();

        let output = aes_gcm.encrypt(nonce, input).unwrap();

        framed
            .send(GsAuthResponse::new_uav_list_message(output))
            .await?;
    }
    Ok(())
}
