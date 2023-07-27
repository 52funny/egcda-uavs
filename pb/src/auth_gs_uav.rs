/// It is a message that is sent by the UAV to the GS at the first time.
/// It include uav's ruid
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavAuthHelloMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub ruid: ::prost::bytes::Bytes,
}
/// When the GS receives the Uav hello message
/// It will send the UavAuthGsPublicParam message to the UAV.
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavAuthGsPublicParamMessage {
    #[prost(int64, tag = "1")]
    pub t_gs: i64,
    #[prost(bytes = "bytes", tag = "2")]
    pub id_gs: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "3")]
    pub r_gs: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "4")]
    pub q_gs: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "5")]
    pub c: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavAuthRequest {
    #[prost(oneof = "uav_auth_request::Request", tags = "1")]
    pub request: ::core::option::Option<uav_auth_request::Request>,
}
/// Nested message and enum types in `UavAuthRequest`.
pub mod uav_auth_request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        Hello(super::UavAuthHelloMessage),
    }
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavAuthResponse {
    #[prost(oneof = "uav_auth_response::Response", tags = "1")]
    pub response: ::core::option::Option<uav_auth_response::Response>,
}
/// Nested message and enum types in `UavAuthResponse`.
pub mod uav_auth_response {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        GsPublicParam(super::UavAuthGsPublicParamMessage),
    }
}
