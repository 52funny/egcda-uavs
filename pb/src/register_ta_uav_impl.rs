use crate::register_ta_uav::{
    uav_register_response::Response, UavRegisterPhase1Message, UavRegisterPhase2Message,
    UavRegisterPhase3Message, UavRegisterRequest, UavRegisterResponse,
};
use prost::bytes::Bytes;

impl UavRegisterRequest {
    pub fn new_uav_register_phase2_message(r: Vec<u8>) -> Self {
        Self {
            uav_register_phase2: Some(UavRegisterPhase2Message { r: Bytes::from(r) }),
        }
    }
}

impl UavRegisterResponse {
    pub fn new_uav_register_phase1_message(c: Vec<u8>) -> Self {
        Self {
            response: Some(Response::UavRegisterPhase1(UavRegisterPhase1Message {
                c: Bytes::from(c),
            })),
        }
    }
    pub fn new_uav_register_phase3_message(uid: Vec<u8>, ruid: Vec<u8>) -> Self {
        Self {
            response: Some(Response::UavRegisterPhase3(UavRegisterPhase3Message {
                uid: Bytes::from(uid),
                ruid: Bytes::from(ruid),
            })),
        }
    }
    pub fn new_uav_register_status(status: i32) -> Self {
        Self {
            response: Some(Response::Status(status)),
        }
    }
}
