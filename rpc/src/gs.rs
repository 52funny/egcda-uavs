#[tarpc::service]
pub trait GsRpc {
    async fn get_gs_pubkey() -> String;
    async fn authenticate_uav_phase1(req: UavAuthRequest1) -> Option<UavAuthResponse1>;
    async fn authenticate_uav_phase2(req: UavAuthRequest2) -> Option<UavAuthResponse2>;
    async fn get_all_uav_id(id: String) -> Vec<String>;
    async fn communicate_uavs(req: UavCommRequest) -> Option<UavCommResponse>;
    async fn batch_authenticate_uavs_phase1(reqs: Vec<String>) -> Option<Vec<String>>;
    async fn batch_authenticate_uavs_phase2(reqs: Vec<UavAuthRequest2>) -> Option<UavAuthResponse2>;
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavAuthRequest1 {
    pub uid: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavAuthResponse1 {
    pub puf_challenge: String,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavAuthRequest2 {
    pub uid: String,
    pub sigma: String,
    pub x: String,
    pub t_u: i64,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavAuthResponse2 {}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavCommRequest {
    pub uid_k: Vec<String>,
}

#[derive(serde::Serialize, serde::Deserialize, Debug, Clone)]
pub struct UavCommResponse {
    pub mu: String,
    pub c_m: Vec<String>,
}
