use std::io;
use std::net::{SocketAddr, UdpSocket};
use std::time::Duration;

use crate::error::{Error, Result};
use crate::transport::Transport;

/// Maximum UDP payload we accept.
///
/// IPMI packets are small; 4 KiB is a conservative upper bound.
const DEFAULT_MAX_PACKET_SIZE: usize = 4096;

/// Blocking UDP transport for RMCP+/IPMI.
pub struct UdpTransport {
    socket: UdpSocket,
    max_packet_size: usize,
    max_attempts: u32,
}

impl UdpTransport {
    /// Connect a UDP socket to an RMCP+ target.
    pub fn connect(target: SocketAddr, timeout: Duration, retries: u32) -> Result<Self> {
        let bind_addr = match target {
            SocketAddr::V4(_) => "0.0.0.0:0",
            SocketAddr::V6(_) => "[::]:0",
        };

        let socket = UdpSocket::bind(bind_addr)?;
        socket.connect(target)?;
        socket.set_read_timeout(Some(timeout))?;

        Ok(Self {
            socket,
            max_packet_size: DEFAULT_MAX_PACKET_SIZE,
            max_attempts: retries.max(1),
        })
    }

    fn send_recv_impl(&self, request: &[u8]) -> Result<Vec<u8>> {
        let mut buf = vec![0u8; self.max_packet_size];

        for attempt in 0..self.max_attempts {
            self.socket.send(request)?;

            match self.socket.recv(&mut buf) {
                Ok(n) => {
                    buf.truncate(n);
                    return Ok(buf);
                }
                Err(e) if is_timeout(&e) => {
                    // Retry.
                    if attempt + 1 == self.max_attempts {
                        return Err(Error::Timeout);
                    }
                    continue;
                }
                Err(e) => return Err(Error::Io(e)),
            }
        }

        Err(Error::Timeout)
    }
}

impl Transport for UdpTransport {
    fn send_recv(&self, request: &[u8]) -> Result<Vec<u8>> {
        self.send_recv_impl(request)
    }
}

fn is_timeout(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::TimedOut | io::ErrorKind::WouldBlock
    )
}
