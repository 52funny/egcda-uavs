use anyhow::{bail, Context};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::Mutex,
};

/// Puf client that reuses a single TCP connection and exchanges fixed-size (24-byte) messages.
pub struct Puf {
    writer: Arc<Mutex<tokio::net::tcp::OwnedWriteHalf>>,
    reader: Arc<Mutex<BufReader<tokio::net::tcp::OwnedReadHalf>>>,
}

impl Puf {
    /// Create a new client and immediately establish the TCP connection.
    pub async fn new(addr: impl Into<SocketAddr>) -> anyhow::Result<Self> {
        let stream = TcpStream::connect(addr.into()).await.context("failed to connect to PUF server")?;
        let (read_half, write_half) = stream.into_split();
        let reader = BufReader::new(read_half);
        Ok(Self {
            writer: Arc::new(Mutex::new(write_half)),
            reader: Arc::new(Mutex::new(reader)),
        })
    }

    /// Send a 24-byte hex style challenge and read a 24-byte hex style response over the existing connection.
    pub async fn calculate(&self, c: impl AsRef<[u8]>) -> anyhow::Result<String> {
        let payload = c.as_ref();
        if payload.len() != 24 {
            bail!("challenge must be exactly 24 bytes, got {}", payload.len());
        }

        // Send the 24-byte challenge.
        {
            let mut writer = self.writer.lock().await;
            writer.write_all(payload).await?;
            writer.flush().await?;
        }

        // Read exactly 24 bytes of response.
        let mut resp_buf = [0u8; 24];
        {
            let mut reader = self.reader.lock().await;
            reader.read_exact(&mut resp_buf).await?;
        }

        // Convert response to String.
        let s = String::from_utf8(resp_buf.to_vec())?;
        Ok(s)
    }
}
