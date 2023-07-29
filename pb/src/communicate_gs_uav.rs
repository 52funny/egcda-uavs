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
/// Message including the ruid list
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct NeedCommunicateRuidListMessage {
    #[prost(string, repeated, tag = "1")]
    pub ruid: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavRuidListMessage {
    #[prost(string, tag = "1")]
    pub ruid: ::prost::alloc::string::String,
    #[prost(string, tag = "2")]
    pub ip_addr: ::prost::alloc::string::String,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavCommunicateParamMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub ssk: ::prost::bytes::Bytes,
    #[prost(string, repeated, tag = "2")]
    pub c: ::prost::alloc::vec::Vec<::prost::alloc::string::String>,
}
/// The request message used to communicate uav to gs
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavGsCommunicateRequest {
    #[prost(oneof = "uav_gs_communicate_request::Request", tags = "1, 2")]
    pub request: ::core::option::Option<uav_gs_communicate_request::Request>,
}
/// Nested message and enum types in `UavGsCommunicateRequest`.
pub mod uav_gs_communicate_request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        CommunicateMessage(super::CommunicateMessage),
        #[prost(message, tag = "2")]
        NeedCommunicateRuidList(super::NeedCommunicateRuidListMessage),
    }
}
/// The response message used to communicate gs to uav
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavGsCommunicateResponse {
    #[prost(oneof = "uav_gs_communicate_response::Response", tags = "1, 2, 3, 4")]
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
        #[prost(message, tag = "3")]
        AlreadyAuthenticatedRuidList(super::UavRuidListMessage),
        #[prost(message, tag = "4")]
        UavCommunicateParam(super::UavCommunicateParamMessage),
    }
}
