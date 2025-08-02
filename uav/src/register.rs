use crate::{UavConfig, PUF};
use blstrs_plus::{G2Affine, Scalar};
use rpc::{TaRpcClient, UavRegisterRequest1};
use tarpc::context;
use tracing::{debug, info};
use utils::abbreviate_key_default;

pub(crate) async fn register(client: &TaRpcClient) -> anyhow::Result<UavConfig> {
    let ctx = context::current();

    let resp1 = client
        .register_uav_phase1(ctx, UavRegisterRequest1 {})
        .await?
        .ok_or_else(|| anyhow::anyhow!("UAV registration phase 1 failed"))?;
    debug!("UAV registration phase 1 completed: {:?}", resp1);

    let puf_response = PUF
        .get()
        .unwrap()
        .calculate(resp1.puf_challenge)
        .await
        .map_err(|e| anyhow::anyhow!("PUF calculation failed of {}", e))?;

    let sk = Scalar::from_be_hex(&resp1.uav_sk).expect("Invalid UAV secret key format");
    let pk = G2Affine::from_compressed_hex(&resp1.uav_pubkey).expect("Invalid UAV public key format");

    let cfg = UavConfig::new(resp1.uid.clone(), sk, pk);

    let req2 = rpc::UavRegisterRequest2 {
        uid: resp1.uid.clone(),
        puf_response,
    };
    client
        .register_uav_phase2(ctx, req2)
        .await?
        .ok_or_else(|| anyhow::anyhow!("UAV registration phase 2 failed"))?;
    info!("UAV registered with uid: {}", abbreviate_key_default(&resp1.uid));
    Ok(cfg)
}
