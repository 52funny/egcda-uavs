mod codec;
use bytes::Bytes;
use futures::SinkExt;
use rand::{thread_rng, Rng};
use tokio::{io::AsyncWriteExt, net::TcpStream};
use tokio_util::codec::Framed;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // tracing logger
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or("info".parse().unwrap()))
        .init();

    let addr = "127.0.0.1:8090";

    // connect to server
    let mut stream = TcpStream::connect(addr).await?;

    // 1 means gs
    stream.write_u8(1).await.unwrap();

    let _addr = stream.peer_addr()?.ip();

    // use custom frame
    let mut frame = Framed::new(stream, codec::gs_register_codec::GsRegisterCodec);

    let gid: Bytes = thread_rng().gen::<[u8; 32]>().to_vec().into();
    let rgid: Bytes = thread_rng().gen::<[u8; 32]>().to_vec().into();

    let req = pb::register_ta_gs::GsRequest { gid, rgid };

    frame.send(req).await?;
    frame.get_mut().write_u8(1).await?;

    Ok(())
}
