use crate::{codec, UavList, GENERATION, GS_CONFIG, P, UAV_FAKE_PRIME, UAV_LIST};
use aes_gcm::{aead::Aead, Aes256Gcm, Key, KeyInit, Nonce};
use bytes::Bytes;
use futures::{SinkExt, StreamExt};
use pb::auth_ta_gs::gs_auth_response::Response;
use rand::Rng;
use rug::Integer;
use std::mem::MaybeUninit;
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::codec::Framed;

// Register self to TA
pub async fn register(addr: &str) -> anyhow::Result<()> {
    // connect to server
    let mut stream = TcpStream::connect(addr).await?;

    // 1 means gs register
    stream.write_u8(1).await.unwrap();

    let _addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, codec::gs_register_codec::GsRegisterCodec);

    let gid = Bytes::from(GS_CONFIG.gid.to_vec());
    let rgid = Bytes::from(GS_CONFIG.rgid.to_vec());

    let req = pb::register_ta_gs::GsRequest { gid, rgid };

    frame.send(req).await?;
    if let Some(Ok(res)) = frame.next().await {
        tracing::info!(
            "gs register status: {}",
            if res.status == 1 { "failed" } else { "success" }
        );
    }
    Ok(())
}

// Auth self to TA
pub async fn auth(addr: &str) -> anyhow::Result<()> {
    // connect to server
    let mut stream = TcpStream::connect(addr).await?;

    // 1 means gs auth
    stream.write_u8(4).await.unwrap();

    let _addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, codec::gs_auth_codec::GsAuthCodec);

    // lazy init puk_gs
    let mut puk_ta_bytes = MaybeUninit::<Vec<u8>>::uninit();
    // receive ta public parameter
    if let Some(Ok(res)) = frame.next().await {
        if let Some(Response::TaPublicParameter(paramter)) = res.response {
            tracing::debug!("get ta public key: {}", hex::encode(&paramter.puk_gs));
            puk_ta_bytes.write(paramter.puk_gs.to_vec());
        } else {
            anyhow::bail!("get ta public parameter failed");
        }
    };

    // auth phase 1
    let gid = hex::encode(GS_CONFIG.gid);
    let t = chrono::Utc::now().timestamp();
    let hash_str = sha256::digest(gid + &t.to_string());
    // 32 byte
    let hash_bytes = hex::decode(&hash_str)?;
    let mut hash = P.gr();
    hash.from_bytes(hash_bytes);
    tracing::debug!("tau: {:?}", hash);

    let mut puk_ta = P.g1();
    puk_ta.from_bytes(unsafe { puk_ta_bytes.assume_init_ref() });

    let mut puk_ta_clone = puk_ta.clone();
    puk_ta_clone.mul_element_zn(hash.clone());

    let mut q = P.g1();
    q.from_bytes(GENERATION);

    let mut fp = P.pairing(&puk_ta_clone, &q);

    let mut sk_gs = P.gr();
    sk_gs.from_bytes(&GS_CONFIG.sk_gs_bytes);
    fp.pow_zn(&sk_gs);

    let sig = fp.as_bytes();
    tracing::debug!("sig: {}", hex::encode(&sig));
    frame
        .send(pb::auth_ta_gs::GsAuthRequest::new_gs_auth_phase1_message(
            GS_CONFIG.rgid.to_vec(),
            t,
            hash_str,
            sig,
            GS_CONFIG.puk_gs_bytes.clone(), // puk_gs,
        ))
        .await?;

    // receive auth phase 2
    let status = if let Some(Ok(res)) = frame.next().await {
        if let Some(Response::GsAuthPhase2(status)) = res.response {
            status.status
        } else {
            anyhow::bail!("get auth phase2 failed");
        }
    } else {
        anyhow::bail!("get gs auth phase2 response failed");
    };
    tracing::info!("auth: {}", if status == 0 { "success" } else { "failed" });
    // means auth success
    if status == 0 {
        // receive uav list
        if let Some(Ok(res)) = frame.next().await {
            if let Some(Response::UavList(uav_list)) = res.response {
                let uav_list_enc = uav_list.uav_list_enc.to_vec();

                let mut ssk_tags = puk_ta.clone();
                ssk_tags.mul_element_zn(sk_gs);
                ssk_tags.mul_element_zn(hash);

                // let mut ssk_tags_bytes = vec![0u8; 65];
                // ssk_tags.tobytes(&mut ssk_tags_bytes, false);
                let ssk_tags_bytes = ssk_tags.as_bytes();
                let ssk_tags_bytes_sha2 = hex::decode(sha256::digest(&ssk_tags_bytes))?;

                tracing::info!("ssk_tags: {}", hex::encode(ssk_tags_bytes));

                let key = Key::<Aes256Gcm>::from_slice(&ssk_tags_bytes_sha2);
                let nonce = Nonce::from_slice(&ssk_tags_bytes_sha2[..12]);
                let aes_gcm = aes_gcm::Aes256Gcm::new(key);
                tracing::debug!("aes key: {}", hex::encode(key));
                tracing::debug!("aes nonce: {}", hex::encode(nonce));

                // decrypt
                let uav_list = aes_gcm.decrypt(nonce, uav_list_enc.as_ref()).unwrap();

                let uav_list: UavList = serde_json::from_slice(&uav_list)?;

                // construct n unrelated prime numbers
                let n = uav_list.0.len();
                let mut i = 0;
                while i < n {
                    let prime: Integer = Integer::from_digits(
                        &rand::thread_rng().gen::<[u8; 32]>(),
                        rug::integer::Order::MsfBe,
                    )
                    .next_prime();
                    for uav in &uav_list.0 {
                        if uav.value().n != prime {
                            UAV_FAKE_PRIME.lock().await.push(prime);
                            i += 1;
                            break;
                        }
                    }
                }

                uav_list.0.iter().for_each(|k| {
                    UAV_LIST.0.insert(k.key().clone(), k.value().clone());
                });

                for (idx, item) in UAV_LIST.0.iter().enumerate() {
                    tracing::debug!("uav{}: {}", idx + 1, item.value());
                }
            } else {
                anyhow::bail!("get uav list failed");
            }
        } else {
            anyhow::bail!("get uav list response failed");
        }
    }
    Ok(())
}
