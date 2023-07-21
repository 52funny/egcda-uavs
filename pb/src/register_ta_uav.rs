/// From TA to UAV
/// maybe this not needed,
/// when the drone first connects to TA, it can send a TCP message instead of using protobuf.
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavRegisterPhase1Message {
    #[prost(bytes = "bytes", tag = "1")]
    pub c: ::prost::bytes::Bytes,
}
/// From UAV to TA
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavRegisterPhase2Message {
    #[prost(bytes = "bytes", tag = "1")]
    pub r: ::prost::bytes::Bytes,
}
/// From TA to UAV
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavRegisterPhase3Message {
    #[prost(bytes = "bytes", tag = "1")]
    pub uid: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub ruid: ::prost::bytes::Bytes,
}
/// uav request message
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavRequest {
    #[prost(oneof = "uav_request::Request", tags = "1, 2")]
    pub request: ::core::option::Option<uav_request::Request>,
}
/// Nested message and enum types in `UavRequest`.
pub mod uav_request {
    #[derive(PartialOrd)]
    #[allow(clippy::derive_partial_eq_without_eq)]
    #[derive(Clone, PartialEq, ::prost::Oneof)]
    pub enum Request {
        /// it's including the UAV's response `r` from PUF
        #[prost(message, tag = "1")]
        UavRegisterPhase2(super::UavRegisterPhase2Message),
        /// it's including the UAV's uid and ruid
        #[prost(message, tag = "2")]
        UavRegisterPhase3(super::UavRegisterPhase3Message),
    }
}
/// ta returns information to the UAV
/// use the status to indicate the result
/// if status == 0, it means success
/// if status == 1, it means fail
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct UavResponse {
    #[prost(int32, tag = "1")]
    pub status: i32,
}
