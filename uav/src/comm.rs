use crate::{PUF, UAV_AUTH_LIST, UAV_CONFIG};
use rpc::*;
use rug::Integer;
use tarpc::context;
use tracing::info;
use utils::{abbreviate_key_default, hash_to_prime};

pub async fn comm_with_uavs(client: &GsRpcClient) -> anyhow::Result<()> {
    let uid_k = UAV_AUTH_LIST.lock().unwrap().clone();
    let resp = client
        .communicate_uavs(context::current(), UavCommRequest { uid_k })
        .await?
        .ok_or(anyhow::anyhow!("No response from GS"))?;

    let mu = Integer::from_str_radix(&resp.mu, 16)?;
    let c_1 = resp.c_m.first().ok_or(anyhow::anyhow!("Empty c_m"))?.clone();

    let puf_response = PUF.calculate(c_1).await?;

    let p = hash_to_prime(puf_response + &UAV_CONFIG.get().unwrap().uid);

    let k_d = mu.clone().modulo(&p);

    info!("Group key: {}", abbreviate_key_default(&k_d.to_string_radix(16)));

    Ok(())
}
