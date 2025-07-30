use hex::ToHex;
use rpc::TaRpcClient;
use tarpc::context;
use tracing::info;

use crate::GS_CONFIG;

pub(crate) async fn register(client: &TaRpcClient) -> anyhow::Result<()> {
    let (gid, pk) = (GS_CONFIG.gid.clone(), GS_CONFIG.pk);
    let pk = pk.to_compressed().encode_hex::<String>();

    let req = rpc::GsRegisterRequest {
        gid: gid.clone(),
        gs_pubkey: pk,
    };

    client.register_gs(context::current(), req).await?;
    info!("Register ground station with gid: {}", gid);
    Ok(())
}
