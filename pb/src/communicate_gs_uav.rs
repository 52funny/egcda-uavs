/// Communication structure used between uav and gs
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommunicateMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_data: ::prost::bytes::Bytes,
}
/// Some parameters of the construction key, which used to encrypt the communication message
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct CommunicateParamMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub lambda: ::prost::bytes::Bytes,
    #[prost(int64, tag = "2")]
    pub t: i64,
    #[prost(bytes = "bytes", tag = "3")]
    pub c: ::prost::bytes::Bytes,
}
/// The request message used to communicate uav to gs
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavGsCommunicateRequest {
    #[prost(message, optional, tag = "1")]
    pub communicate_message: ::core::option::Option<CommunicateMessage>,
}
/// The response message used to communicate gs to uav
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavGsCommunicateResponse {
    #[prost(oneof = "uav_gs_communicate_response::Response", tags = "1, 2")]
    pub response: ::core::option::Option<uav_gs_communicate_response::Response>,
}
/// Nested message and enum types in `UavGsCommunicateResponse`.
pub mod uav_gs_communicate_response {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        CommunicateParam(super::CommunicateParamMessage),
        #[prost(message, tag = "2")]
        CommunicateMessage(super::CommunicateMessage),
    }
}
