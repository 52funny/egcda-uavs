use crate::communicate_gs_uav::{
    uav_gs_communicate_response::Response, CommunicateMessage, CommunicateParamMessage,
    UavGsCommunicateRequest, UavGsCommunicateResponse,
};

impl UavGsCommunicateRequest {
    pub fn new_communicate_message(communicate_message: Vec<u8>) -> Self {
        Self {
            communicate_message: Some(CommunicateMessage {
                encrypted_data: communicate_message.into(),
            }),
        }
    }
}

impl UavGsCommunicateResponse {
    pub fn new_communicate_param_message(lambda: Vec<u8>, t: i64, c: Vec<u8>) -> Self {
        Self {
            response: Some(Response::CommunicateParam(CommunicateParamMessage {
                lambda: lambda.into(),
                t,
                c: c.into(),
            })),
        }
    }
    pub fn new_communicate_message(message: Vec<u8>) -> Self {
        Self {
            response: Some(Response::CommunicateMessage(CommunicateMessage {
                encrypted_data: message.into(),
            })),
        }
    }
}
