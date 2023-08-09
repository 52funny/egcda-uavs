use crate::auth_gs_uav::{
    uav_auth_request::Request, uav_auth_response::Response, UavAuthGsPublicParamMessage,
    UavAuthHelloMessage, UavAuthPhase1Message, UavAuthPhase2Message, UavAuthRequest,
    UavAuthResponse,
};

impl UavAuthRequest {
    pub fn new_hello_message(ruid: Vec<u8>) -> Self {
        UavAuthRequest {
            request: Some(Request::Hello(UavAuthHelloMessage { ruid: ruid.into() })),
        }
    }
    pub fn new_uav_auth_phase1_message(
        t_u: i64,
        tuid_i: Vec<u8>,
        v_i: Vec<u8>,
        gamma_i: Vec<u8>,
    ) -> Self {
        UavAuthRequest {
            request: Some(Request::UavAuthPhase1(UavAuthPhase1Message {
                t_u,
                tuid_i: tuid_i.into(),
                v_i: v_i.into(),
                gamma_i: gamma_i.into(),
            })),
        }
    }
}

impl UavAuthResponse {
    pub fn new_uav_auth_gs_public_param_message(
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
    pub fn new_uav_auth_phase2_message(status: i32) -> Self {
        UavAuthResponse {
            response: Some(Response::UavAuthPhase2(UavAuthPhase2Message { status })),
        }
    }
}
