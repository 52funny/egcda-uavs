use rug::Integer;

#[tarpc::service]
pub trait TaRpc {
    async fn get_ta_pubkey() -> String;
    async fn register_gs(req: GsRegisterRequest) -> ();
    async fn authenticate_gs(req: GsAuthRequest) -> Option<GsAuthResponse>;
    async fn get_uav_list(gid: String) -> Option<Vec<u8>>;
    async fn register_uav_phase1(req: UavRegisterRequest1) -> Option<UavRegisterResponse1>;
    async fn register_uav_phase2(req: UavRegisterRequest2) -> Option<UavRegisterResponse2>;
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct GsRegisterRequest {
    pub gid: String,
    pub gs_pubkey: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavRegisterRequest1 {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavRegisterResponse1 {
    pub uid: String,
    pub puf_challenge: String,
    pub uav_sk: String,
    pub uav_pubkey: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavRegisterRequest2 {
    pub uid: String,
    pub puf_response: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavRegisterResponse2 {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct GsAuthRequest {
    pub gid: String,
    pub t_g: String,
    pub sigma: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct GsAuthResponse {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct GsAuthResponseStruct {
    pub uid: String,
    pub pk_u: String,
    pub c: String,
    pub z: String,
    pub p: Integer,
}
