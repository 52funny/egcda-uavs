use bytes::{Buf, BufMut};
use pb::register_ta_gs::{GsRequest, GsResponse};
use prost::Message;
use tokio_util::codec;

pub struct GsRegisterCodec;

impl GsRegisterCodec {
    const MAX_SIZE: usize = 1024 * 1024 * 1024 * 8;
}

impl codec::Encoder<GsResponse> for GsRegisterCodec {
    type Error = std::io::Error;
    fn encode(&mut self, item: GsResponse, dst: &mut bytes::BytesMut) -> Result<(), Self::Error> {
        let data = item.encode_to_vec();
        let data_len = data.len();
        if data_len > Self::MAX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "data too large",
            ));
        }
        dst.reserve(4 + data_len);
        dst.put_u32(data_len as u32);
        dst.extend_from_slice(&data);
        Ok(())
    }
}

impl codec::Decoder for GsRegisterCodec {
    type Item = GsRequest;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buf_len = src.len();
        if buf_len < 4 {
            return Ok(None);
        }
        let data_len = src.get_u32() as usize;
        if data_len > Self::MAX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "data too large",
            ));
        }

        if buf_len < data_len {
            src.reserve(data_len - buf_len);
            return Ok(None);
        }

        let data = src.split_to(data_len);
        let item = GsRequest::decode(data)?;
        Ok(Some(item))
    }
}
