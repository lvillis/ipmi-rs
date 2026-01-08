use std::net::SocketAddr;
use std::time::Duration;

use tokio::net::UdpSocket;

use crate::error::{Error, Result};
use crate::transport::AsyncTransport;

/// Maximum UDP payload we accept.
///
/// IPMI packets are small; 4 KiB is a conservative upper bound.
const DEFAULT_MAX_PACKET_SIZE: usize = 4096;

/// Tokio UDP transport for RMCP+/IPMI.
pub struct UdpTransport {
    socket: UdpSocket,
    max_packet_size: usize,
    max_attempts: u32,
    timeout: Duration,
}

impl UdpTransport {
    /// Connect a UDP socket to an RMCP+ target.
    pub async fn connect(target: SocketAddr, timeout: Duration, retries: u32) -> Result<Self> {
        let bind_addr = match target {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr).await?;
        socket.connect(target).await?;

        Ok(Self {
            socket,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            max_attempts: retries.max(1),
            timeout,
        })
    }

    async fn send_recv_impl(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.max_packet_size];

        for attempt in 0..self.max_attempts {
            self.socket.send(request).await?;

            match tokio::time::timeout(self.timeout, self.socket.recv(&mut buf)).await {
                Ok(Ok(n)) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Ok(Err(e)) => return Err(Error::Io(e)),
                Err(_elapsed) => {
                    if attempt + 1 == self.max_attempts {
                        return Err(Error::Timeout);
                    }
                }
            }
        }

        Err(Error::Timeout)
    }
}

impl AsyncTransport for UdpTransport {
    fn send_recv<'a>(
        &'a self,
        request: &'a [u8],
    ) -> core::pin::Pin<Box<dyn core::future::Future<Output = Result<Vec<u8>>> + Send + 'a>> {
        Box::pin(async move { self.send_recv_impl(request).await })
    }
}
