use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

/// This puf is simulated by python pypuf library.
/// Using internal TCP communication.
/// without any external communication.
pub struct Puf {
    addr: SocketAddr,
}

impl Puf {
    pub fn new(addr: impl Into<SocketAddr>) -> Self {
        Self { addr: addr.into() }
    }
    pub async fn calculate(&self, c: String) -> anyhow::Result<String> {
        let mut stream = TcpStream::connect(self.addr).await?;
        stream.write_all(c.as_bytes()).await?;
        let mut v = Vec::new();
        stream.read_to_end(&mut v).await?;
        Ok(unsafe { String::from_utf8_unchecked(v) })
    }
}
