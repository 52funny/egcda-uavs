use prost::bytes::Bytes;

use crate::auth_ta_gs;

impl auth_ta_gs::GsAuthResponse {
    pub fn new_ta_public_parameter_message(puk_gs: Vec<u8>) -> Self {
        Self {
            response: Some(auth_ta_gs::gs_auth_response::Response::TaPublicParameter(
                auth_ta_gs::TaPublicParameterMessage {
                    puk_gs: Bytes::from(puk_gs),
                },
            )),
        }
    }
    pub fn new_gs_auth_phase2_message(status: i32) -> Self {
        Self {
            response: Some(auth_ta_gs::gs_auth_response::Response::GsAuthPhase2(
                auth_ta_gs::GsAuthPhase2Message { status },
            )),
        }
    }
}

impl auth_ta_gs::GsAuthRequest {
    pub fn new_gs_auth_hello_message() -> Self {
        Self {
            request: Some(auth_ta_gs::gs_auth_request::Request::GsAuthHello(
                auth_ta_gs::GsAuthHelloMessage {},
            )),
        }
    }
    pub fn new_gs_auth_phase1_message(
        rgid: Vec<u8>,
        t: i64,
        hash: String,
        signature: Vec<u8>,
        puk_gs: Vec<u8>,
    ) -> Self {
        Self {
            request: Some(auth_ta_gs::gs_auth_request::Request::GsAuthPhase1(
                auth_ta_gs::GsAuthPhase1Message {
                    rgid: rgid.into(),
                    t,
                    hash,
                    signature: signature.into(),
                    puk_gs: puk_gs.into(),
                },
            )),
        }
    }
}
