use anyhow::{bail, Context};
use std::{collections::VecDeque, net::SocketAddr, sync::Arc};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, BufReader},
    net::TcpStream,
    sync::{Mutex, Notify},
};

struct PooledConnection {
    writer: tokio::net::tcp::OwnedWriteHalf,
    reader: BufReader<tokio::net::tcp::OwnedReadHalf>,
}

/// Puf client backed by a TCP connection pool for concurrent 24-byte request/response exchanges.
pub struct Puf {
    connections: Arc<Mutex<VecDeque<PooledConnection>>>,
    notify: Arc<Notify>,
}

impl Puf {
    const DEFAULT_POOL_SIZE: usize = 8;

    #[allow(dead_code)]
    /// Create a new client and immediately establish the default-size connection pool.
    pub async fn new(addr: impl Into<SocketAddr>) -> anyhow::Result<Self> {
        Self::new_with_pool_size(addr, Self::DEFAULT_POOL_SIZE).await
    }

    /// Create a new client and immediately establish a fixed-size connection pool.
    pub async fn new_with_pool_size(addr: impl Into<SocketAddr>, pool_size: usize) -> anyhow::Result<Self> {
        if pool_size == 0 {
            bail!("pool size must be greater than 0");
        }

        let addr = addr.into();
        let mut connections = VecDeque::with_capacity(pool_size);
        for _ in 0..pool_size {
            let stream = TcpStream::connect(addr).await.context("failed to connect to PUF server")?;
            let (read_half, write_half) = stream.into_split();
            connections.push_back(PooledConnection {
                writer: write_half,
                reader: BufReader::new(read_half),
            });
        }

        Ok(Self {
            connections: Arc::new(Mutex::new(connections)),
            notify: Arc::new(Notify::new()),
        })
    }

    async fn acquire_connection(&self) -> PooledConnection {
        loop {
            let notified = self.notify.notified();
            if let Some(conn) = self.connections.lock().await.pop_front() {
                return conn;
            }
            notified.await;
        }
    }

    async fn release_connection(&self, conn: PooledConnection) {
        self.connections.lock().await.push_back(conn);
        self.notify.notify_one();
    }

    /// Send a 24-byte hex style challenge and read a 24-byte hex style response using a pooled connection.
    pub async fn calculate(&self, c: impl AsRef<[u8]>) -> anyhow::Result<String> {
        let payload = c.as_ref();
        if payload.len() != 24 {
            bail!("challenge must be exactly 24 bytes, got {}", payload.len());
        }

        let mut conn = self.acquire_connection().await;
        let result = async {
            conn.writer.write_all(payload).await?;
            conn.writer.flush().await?;

            let mut resp_buf = [0u8; 24];
            conn.reader.read_exact(&mut resp_buf).await?;

            let s = String::from_utf8(resp_buf.to_vec())?;
            Ok::<_, anyhow::Error>(s)
        }
        .await;

        self.release_connection(conn).await;
        result
    }
}
