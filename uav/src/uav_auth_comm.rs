use crate::codec::uav_auth_codec::UavAuthCodec;
use crate::codec::uav_communicate_codec::UavGsCommunicateCodec;
use crate::{GENERATION, P, PUF, UAV, UAV_RUID_LIST};
use aes_gcm::aead::Aead;
use aes_gcm::{Aes256Gcm, Key, KeyInit, Nonce};
use futures::channel::mpsc::{UnboundedReceiver, UnboundedSender};
use futures::{SinkExt, StreamExt};
use pb::auth_gs_uav::{uav_auth_response, UavAuthRequest};
use pb::communicate_gs_uav::{uav_gs_communicate_response, UavGsCommunicateRequest};
use tokio::net::TcpStream;
use tokio_util::codec::Framed;

pub async fn auth_comm(
    addr: &str,
    anonym_rx: UnboundedReceiver<Vec<String>>,
    param_tx: UnboundedSender<(Vec<u8>, Vec<String>)>,
) -> anyhow::Result<()> {
    let mut stream = TcpStream::connect(addr).await?;
    tracing::debug!("---------------------------uav auth---------------------------");
    let (status, pho_i) = auth(&mut stream).await?;
    tracing::debug!("---------------------------uav auth---------------------------");

    tracing::info!("uav auth result: {}", if status { "ok" } else { "fail" });

    tracing::debug!("----------------------uav gs communicate----------------------");
    communicate(stream, anonym_rx, param_tx, pho_i).await?;
    tracing::debug!("----------------------uav gs communicate----------------------");
    Ok(())
}

async fn auth(stream: &mut TcpStream) -> anyhow::Result<(bool, Vec<u8>)> {
    let t = std::time::Instant::now();
    let mut framed = Framed::new(stream, UavAuthCodec);
    let ruid = UAV.get().unwrap().ruid.clone();
    let _uid = UAV.get().unwrap().uid.clone();
    // send hello message to gs
    framed.send(UavAuthRequest::new_hello_message(ruid)).await?;

    // get gs public param
    let param = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_auth_response::Response::GsPublicParam(param)) = res.response {
            param
        } else {
            anyhow::bail!("framed get uav get public param message error");
        }
    } else {
        anyhow::bail!("framed recv at uav get public param message error");
    };

    tracing::debug!("t_gs    : {}", param.t_gs);
    tracing::debug!("id_gs   : {}", hex::encode(&param.id_gs));
    tracing::debug!("r_gs    : {}", hex::encode(&param.r_gs));
    tracing::debug!("q_gs    : {}", hex::encode(&param.q_gs));

    // start auth phase1
    let t_u = chrono::Utc::now().timestamp();
    // let r_u_bytes = rand::thread_rng().gen::<[u8; 32]>();
    let r_i_bytes = hex::decode(PUF.calculate(hex::encode(&param.c)).await?)?;

    // TUID_i
    let mut hash_content = UAV.get().unwrap().uid.clone();
    hash_content.extend_from_slice(&t_u.to_be_bytes());
    hash_content.extend_from_slice(&r_i_bytes);
    let tuid = hex::decode(sha256::digest(&hash_content))?;

    // pho_i
    let mut hash_content = t_u.to_be_bytes().to_vec();
    hash_content.extend_from_slice(&r_i_bytes);
    let pho_i = hex::decode(sha256::digest(&hash_content))?;

    // v_i
    let mut hash_content = vec![];
    hash_content.extend_from_slice(&t_u.to_be_bytes());
    hash_content.extend_from_slice(&tuid);
    hash_content.extend_from_slice(&param.id_gs);
    hash_content.extend_from_slice(&pho_i);
    let v_i_bytes = hex::decode(sha256::digest(&hash_content))?;

    // gamma_i
    let mut p = P.g1();
    p.from_bytes(GENERATION);

    // first part
    let mut gamma_first = p.clone();
    let mut gamma_ri = P.gr();
    gamma_ri.from_bytes(&r_i_bytes);
    let mut gamma_rgs = P.gr();
    gamma_rgs.from_bytes(&param.r_gs);
    gamma_first.mul_element_zn(gamma_ri);
    gamma_first.mul_element_zn(gamma_rgs);

    // second part
    let mut gamma_second = p;
    let mut gamma_pho_i = P.gr();
    gamma_pho_i.from_bytes(&pho_i);
    gamma_second.mul_element_zn(gamma_pho_i);

    // third part
    let mut gamma_third = P.g1();
    gamma_third.from_bytes(&param.q_gs);
    let mut gamma_nu_i = P.gr();
    let mut gamma_nu_ri = P.gr();
    gamma_nu_i.from_bytes(&v_i_bytes);
    gamma_nu_ri.from_bytes(&r_i_bytes);

    gamma_third.mul_element_zn(gamma_nu_i);
    gamma_third.mul_element_zn(gamma_nu_ri);

    let mut gamma = gamma_first;
    gamma.sub_element(gamma_second);
    gamma.sub_element(gamma_third);
    let gamma_i_bytes = gamma.as_bytes();

    tracing::debug!("t_u     : {}", t_u);
    tracing::debug!("tuid    : {}", hex::encode(&tuid));
    tracing::debug!("v_i     : {}", hex::encode(&v_i_bytes));
    tracing::debug!("gamma_i : {}", hex::encode(&gamma_i_bytes));
    println!("uav calculate params: {:?}", t.elapsed());

    framed
        .send(UavAuthRequest::new_uav_auth_phase1_message(
            t_u,
            tuid,
            v_i_bytes,
            gamma_i_bytes,
        ))
        .await?;

    tracing::info!("uav auth phase1 speed time: {:?}", t.elapsed());

    let status = if let Some(Ok(res)) = framed.next().await {
        if let Some(uav_auth_response::Response::UavAuthPhase2(status)) = res.response {
            status.status
        } else {
            anyhow::bail!("framed get uav auth phase2 message error");
        }
    } else {
        anyhow::bail!("framed recv at uav auth phase2 message error");
    };
    tracing::info!("uav auth phase2 speed time: {:?}", t.elapsed());
    Ok((status == 0, pho_i))
}

async fn communicate(
    stream: TcpStream,
    mut anonym_rx: UnboundedReceiver<Vec<String>>,
    param_tx: UnboundedSender<(Vec<u8>, Vec<String>)>,
    pho_i: Vec<u8>,
) -> anyhow::Result<()> {
    let mut framed = Framed::new(stream, UavGsCommunicateCodec);
    framed
        .send(UavGsCommunicateRequest::new_communicate_message(vec![]))
        .await?;
    // let param = if let Some(Ok(res)) = framed.next().await {
    //     if let Some(uav_gs_communicate_response::Response::CommunicateParam(param)) = res.response {
    //         param
    //     } else {
    //         anyhow::bail!("framed get uav communicate param message error");
    //     }
    // } else {
    //     anyhow::bail!("framed recv at uav communicate param message error");
    // };
    // tracing::debug!("lambda: {}", hex::encode(&param.lambda));
    // tracing::debug!("t     : {}", param.t);
    // tracing::debug!("c     : {}", hex::encode(&param.c));

    // validate timestamp
    // let t_now = chrono::Utc::now().timestamp();
    // if t_now - param.t > 5 {
    //     anyhow::bail!("t_now - param.t > 5");
    // }

    // calculate lambda'
    let uid = UAV.get().unwrap().uid.clone();
    // let mut hash_content = uid;
    // hash_content.extend_from_slice(&param.t.to_be_bytes());
    // hash_content.extend_from_slice(&param.c);
    // let lambda_ = hex::decode(sha256::digest(&hash_content))?;

    // validate lambda'
    // if lambda_ != param.lambda {
    //     anyhow::bail!("lambda' != param.lambda");
    // }
    // let r = hex::decode(PUF.calculate(hex::encode(&param.c)).await?)?;

    // calculate key
    let mut key = uid;
    for i in 0..key.len() {
        key[i] ^= pho_i[i];
    }

    let key = Key::<Aes256Gcm>::from_slice(&key);
    let aes = aes_gcm::Aes256Gcm::new(key);
    let nonce = Nonce::from_slice(&key[..12]);

    tracing::debug!("key   : {}", hex::encode(key));

    let (mut outgoing, incoming) = framed.split();

    let sender = async {
        loop {
            let msg = tokio::select! {
                Some(ruid) = anonym_rx.next() => {
                    UavGsCommunicateRequest::new_need_communicate_ruid_list(ruid)
                }
            };
            let _ = outgoing.send(msg).await;
        }
    };
    let receiver = incoming.for_each(|res| async {
        if let Ok(res) = res {
            match res.response {
                Some(uav_gs_communicate_response::Response::CommunicateMessage(message)) => {
                    let b: &[u8] = &message.encrypted_data;
                    let output = aes.decrypt(nonce, b).unwrap();
                    tracing::debug!("message: {}", String::from_utf8_lossy(&output));
                }
                Some(uav_gs_communicate_response::Response::AlreadyAuthenticatedRuidList(list)) => {
                    tracing::debug!("{:?}", list);

                    // insert into uav ruid list
                    UAV_RUID_LIST.insert(
                        list.ruid.clone(),
                        crate::UavRuid {
                            ruid: list.ruid,
                            ip_addr: list.ip_addr,
                        },
                    );
                }
                Some(uav_gs_communicate_response::Response::UavCommunicateParam(param)) => {
                    let _ = param_tx.unbounded_send((param.ssk.to_vec(), param.c));
                }
                _ => {}
            }
        }
    });
    futures::pin_mut!(sender, receiver);
    futures::future::select(sender, receiver).await;
    Ok(())
}
