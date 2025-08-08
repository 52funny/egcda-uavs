use anyhow::{bail, Context, Result};
use std::sync::Arc;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::Mutex,
};
use tokio_serial::{SerialPortBuilderExt, SerialStream};

#[allow(dead_code)]
const MSG_LEN: usize = 12; // Fixed-size message length (bytes)

/// PUF client that communicates over a serial port.
/// Each request sends exactly 12 bytes and receives exactly 12 bytes back.
pub(crate) struct PufSerial {
    /// Shared serial port stream, protected by a mutex to serialize request/response cycles.
    port: Arc<Mutex<SerialStream>>,
}

#[allow(dead_code)]
impl PufSerial {
    /// Create a new PUF client using a serial port.
    ///
    /// # Arguments
    /// * `port_name` - Serial port device path (e.g., "/dev/ttyUSB0" or "COM3")
    /// * `baud_rate` - Communication speed in bits per second
    pub(crate) async fn new(port_name: &str, baud_rate: u32) -> Result<Self> {
        // Open serial port in async mode
        let serial = tokio_serial::new(port_name, baud_rate)
            .open_native_async()
            .context("failed to open serial port")?;

        Ok(Self {
            port: Arc::new(Mutex::new(serial)),
        })
    }

    /// Send a 12-byte challenge and read the 12-byte response.
    ///
    /// # Arguments
    /// * `c` - The challenge bytes to send (must be exactly 12 bytes)
    ///
    /// # Returns
    /// * `String` - Response converted from UTF-8 (fails if not valid UTF-8)
    pub(crate) async fn calculate(&self, c: impl AsRef<[u8]>) -> Result<String> {
        let payload = c.as_ref();
        if payload.len() != MSG_LEN {
            bail!("challenge must be exactly {} bytes, got {}", MSG_LEN, payload.len());
        }

        let mut buf = [0u8; MSG_LEN];

        // Lock the port so that request/response cycles are not interleaved across tasks.
        let mut port = self.port.lock().await;

        // Write the 12-byte challenge.
        port.write_all(payload).await?;
        port.flush().await?;

        // Read exactly 12 bytes of response.
        port.read_exact(&mut buf).await?;

        // Convert to String (only safe if response is valid UTF-8 / ASCII)
        let resp = String::from_utf8(buf.to_vec())?;
        Ok(resp)
    }
}
