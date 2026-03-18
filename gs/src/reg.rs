use hex::ToHex;
use rpc::TaRpcClient;
use tarpc::context;
use tracing::info;
use utils::abbreviate_key_default;

use crate::GS_CONFIG;

pub(crate) async fn register(client: &TaRpcClient) -> anyhow::Result<()> {
    let gid = GS_CONFIG.gid.clone();
    let pk1 = GS_CONFIG.pk_g1.to_compressed().encode_hex::<String>();
    let pk2 = GS_CONFIG.pk.to_compressed().encode_hex::<String>();

    let req = rpc::GsRegisterRequest {
        gid: gid.clone(),
        gs_pubkey1: pk1,
        gs_pubkey2: pk2,
    };

    client.register_gs(context::current(), req).await?;
    info!("GS registered successfully: {}", abbreviate_key_default(&gid));
    Ok(())
}
