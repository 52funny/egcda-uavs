use crate::communicate_gs_uav::{
    uav_gs_communicate_request::Request, uav_gs_communicate_response::Response, CommunicateMessage,
    NeedCommunicateRuidListMessage, UavCommunicateParamMessage, UavGsCommunicateRequest,
    UavGsCommunicateResponse, UavRuidListMessage,
};

impl UavGsCommunicateRequest {
    pub fn new_communicate_message(communicate_message: Vec<u8>) -> Self {
        Self {
            request: Some(Request::CommunicateMessage(CommunicateMessage {
                encrypted_data: communicate_message.into(),
            })),
        }
    }
    pub fn new_need_communicate_ruid_list(ruid: Vec<String>) -> Self {
        Self {
            request: Some(Request::NeedCommunicateRuidList(
                NeedCommunicateRuidListMessage { ruid },
            )),
        }
    }
}

impl UavGsCommunicateResponse {
    // pub fn new_communicate_param_message(lambda: Vec<u8>, t: i64, c: Vec<u8>) -> Self {
    //     Self {
    //         response: Some(Response::CommunicateParam(CommunicateParamMessage {
    //             lambda: lambda.into(),
    //             t,
    //             c: c.into(),
    //         })),
    //     }
    // }
    pub fn new_communicate_message(message: Vec<u8>) -> Self {
        Self {
            response: Some(Response::CommunicateMessage(CommunicateMessage {
                encrypted_data: message.into(),
            })),
        }
    }
    pub fn new_already_communicate_ruid_list(ruid: String, ip_addr: String) -> Self {
        Self {
            response: Some(Response::AlreadyAuthenticatedRuidList(UavRuidListMessage {
                ruid,
                ip_addr,
            })),
        }
    }
    pub fn new_uav_communicate_param(ssk: Vec<u8>, c: Vec<String>) -> Self {
        Self {
            response: Some(Response::UavCommunicateParam(UavCommunicateParamMessage {
                ssk: ssk.into(),
                c,
            })),
        }
    }
}
