/// gs request message
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsRequest {
    /// it's including the GS's GID and RGID
    #[prost(bytes = "bytes", tag = "1")]
    pub gid: ::prost::bytes::Bytes,
    #[prost(bytes = "bytes", tag = "2")]
    pub rgid: ::prost::bytes::Bytes,
}
/// ta returns information to the gs
/// use the status to indicate the result
/// if status == 0, it means success
/// if status == 1, it means fail
#[derive(PartialOrd)]
#[allow(clippy::derive_partial_eq_without_eq)]
#[derive(Clone, PartialEq, ::prost::Message)]
pub struct GsResponse {
    #[prost(int32, tag = "1")]
    pub status: i32,
}
