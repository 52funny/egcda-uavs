/// Message for the first GS connect to the TA server.
/// It will send message like Hello
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsAuthHelloMessage {}
/// Message for the TA server to send the public parameter to the GS
/// Including the TA's public key
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct TaPublicParameterMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub puk_gs: ::prost::bytes::Bytes,
}
/// Message for the first phase of the authentication protocol
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsAuthPhase1Message {
    #[prost(bytes = "bytes", tag = "1")]
    pub rgid: ::prost::bytes::Bytes,
    #[prost(int64, tag = "2")]
    pub t: i64,
    #[prost(string, tag = "3")]
    pub hash: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "4")]
    pub signature: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "5")]
    pub puk_gs: ::prost::bytes::Bytes,
}
/// Message for the second phase of the authentication protocol
/// status = 0: success
/// status = 1: fail
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsAuthPhase2Message {
    #[prost(int32, tag = "1")]
    pub status: i32,
}
/// When auth completed, the TA server will send the UAV list to the GS
/// Use the AES-GCM to encrypt the UAV list
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavListMessage {
    /// bytes uav_list_mac = 2;
    #[prost(bytes = "bytes", tag = "1")]
    pub uav_list_enc: ::prost::bytes::Bytes,
}
/// Request message
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsAuthRequest {
    #[prost(oneof = "gs_auth_request::Request", tags = "1, 2")]
    pub request: ::core::option::Option<gs_auth_request::Request>,
}
/// Nested message and enum types in `GsAuthRequest`.
pub mod gs_auth_request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        GsAuthHello(super::GsAuthHelloMessage),
        #[prost(message, tag = "2")]
        GsAuthPhase1(super::GsAuthPhase1Message),
    }
}
/// Response message
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsAuthResponse {
    #[prost(oneof = "gs_auth_response::Response", tags = "1, 2, 3")]
    pub response: ::core::option::Option<gs_auth_response::Response>,
}
/// Nested message and enum types in `GsAuthResponse`.
pub mod gs_auth_response {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        TaPublicParameter(super::TaPublicParameterMessage),
        #[prost(message, tag = "2")]
        GsAuthPhase2(super::GsAuthPhase2Message),
        #[prost(message, tag = "3")]
        UavList(super::UavListMessage),
    }
}
