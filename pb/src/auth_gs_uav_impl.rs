use crate::auth_gs_uav::{
    uav_auth_request::Request, uav_auth_response::Response, UavAuthGsPublicParamMessage,
    UavAuthHelloMessage, UavAuthRequest, UavAuthResponse,
};

impl UavAuthRequest {
    pub fn new_hello(ruid: Vec<u8>) -> Self {
        UavAuthRequest {
            request: Some(Request::Hello(UavAuthHelloMessage { ruid: ruid.into() })),
        }
    }
}

impl UavAuthResponse {
    pub fn new_uav_auth_gs_public_param(
        t_gs: i64,
        id_gs: Vec<u8>,
        r_gs: Vec<u8>,
        q_gs: Vec<u8>,
        c: Vec<u8>,
    ) -> Self {
        UavAuthResponse {
            response: Some(Response::GsPublicParam(UavAuthGsPublicParamMessage {
                t_gs,
                id_gs: id_gs.into(),
                r_gs: r_gs.into(),
                q_gs: q_gs.into(),
                c: c.into(),
            })),
        }
    }
}
