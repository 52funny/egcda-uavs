use bytes::BufMut;
use pb::communicate_gs_uav::{UavGsCommunicateRequest, UavGsCommunicateResponse};
use prost::Message;
use tokio_util::codec;

pub struct UavGsCommunicateCodec;

impl UavGsCommunicateCodec {
    const MAX_SIZE: usize = 1024 * 1024 * 1024 * 8;
}

impl codec::Encoder<UavGsCommunicateResponse> for UavGsCommunicateCodec {
    type Error = std::io::Error;
    fn encode(
        &mut self,
        item: UavGsCommunicateResponse,
        dst: &mut bytes::BytesMut,
    ) -> Result<(), Self::Error> {
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

impl codec::Decoder for UavGsCommunicateCodec {
    type Item = UavGsCommunicateRequest;
    type Error = std::io::Error;
    fn decode(&mut self, src: &mut bytes::BytesMut) -> Result<Option<Self::Item>, Self::Error> {
        let buf_len = src.len();
        if buf_len < 4 {
            return Ok(None);
        }

        let mut length_bytes = [0u8; 4];
        length_bytes.copy_from_slice(&src[..4]);
        let data_len = u32::from_be_bytes(length_bytes) as usize;

        if data_len > Self::MAX_SIZE {
            return Err(std::io::Error::new(
                std::io::ErrorKind::Other,
                "data too large",
            ));
        }

        let frame_len = 4 + data_len;
        if buf_len < frame_len {
            src.reserve(frame_len - buf_len);
            return Ok(None);
        }

        let data = src.split_to(frame_len);
        let item = UavGsCommunicateRequest::decode(&data[4..])?;
        Ok(Some(item))
    }
}
