use crate::communicate_uav_uav::{
    uav_uav_communicate_request::Request, uav_uav_communicate_response::Response,
    UavUavCommunicateMessage, UavUavCommunicatePrevMessage, UavUavCommunicateRequest,
    UavUavCommunicateResponse,
};

impl UavUavCommunicateRequest {
    pub fn new_uav_uav_communicate_message(encrypt_data: Vec<u8>) -> Self {
        Self {
            request: Some(Request::UavUavCommunicateMessage(
                UavUavCommunicateMessage {
                    encrypted_data: encrypt_data.into(),
                },
            )),
        }
    }

    pub fn new_uav_uav_communicate_prev_message(
        encrypt_data: Vec<u8>,
        c: String,
        ssk: Vec<u8>,
    ) -> Self {
        Self {
            request: Some(Request::UavUavCommunicatePrevMessage(
                UavUavCommunicatePrevMessage {
                    encrypted_data: encrypt_data.into(),
                    c,
                    ssk: ssk.into(),
                },
            )),
        }
    }
}

impl UavUavCommunicateResponse {
    pub fn new_uav_uav_communicate_message(encrypt_data: Vec<u8>) -> Self {
        Self {
            response: Some(Response::UavUavCommunicateMessage(
                UavUavCommunicateMessage {
                    encrypted_data: encrypt_data.into(),
                },
            )),
        }
    }
}
