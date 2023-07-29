#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavUavCommunicatePrevMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_data: ::prost::bytes::Bytes,
    #[prost(string, tag = "2")]
    pub c: ::prost::alloc::string::String,
    #[prost(bytes = "bytes", tag = "3")]
    pub ssk: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavUavCommunicateMessage {
    #[prost(bytes = "bytes", tag = "1")]
    pub encrypted_data: ::prost::bytes::Bytes,
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavUavCommunicateRequest {
    #[prost(oneof = "uav_uav_communicate_request::Request", tags = "1, 2")]
    pub request: ::core::option::Option<uav_uav_communicate_request::Request>,
}
/// Nested message and enum types in `UavUavCommunicateRequest`.
pub mod uav_uav_communicate_request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        #[prost(message, tag = "1")]
        UavUavCommunicateMessage(super::UavUavCommunicateMessage),
        #[prost(message, tag = "2")]
        UavUavCommunicatePrevMessage(super::UavUavCommunicatePrevMessage),
    }
}
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavUavCommunicateResponse {
    #[prost(oneof = "uav_uav_communicate_response::Response", tags = "1")]
    pub response: ::core::option::Option<uav_uav_communicate_response::Response>,
}
/// Nested message and enum types in `UavUavCommunicateResponse`.
pub mod uav_uav_communicate_response {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Response {
        #[prost(message, tag = "1")]
        UavUavCommunicateMessage(super::UavUavCommunicateMessage),
    }
}
