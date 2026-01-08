use std::io;

use thiserror::Error;

/// Result type used across this crate.
pub type Result<T> = std::result::Result<T, Error>;

/// Errors returned by this crate.
#[derive(Debug, Error)]
pub enum Error {
    /// I/O error (socket, OS, etc.).
    #[error("io error: {0}")]
    Io(#[from] io::Error),

    /// Operation timed out.
    #[error("timeout waiting for response")]
    Timeout,

    /// Peer responded with an unexpected or invalid packet.
    #[error("protocol error: {0}")]
    Protocol(&'static str),

    /// Peer responded with an unexpected or invalid packet.
    #[error("protocol error: {0}")]
    ProtocolOwned(String),

    /// Authentication or integrity verification failed.
    #[error("authentication failed: {0}")]
    AuthenticationFailed(&'static str),

    /// Cryptographic failure (invalid key sizes, decrypt failure, etc.).
    #[error("crypto error: {0}")]
    Crypto(&'static str),

    /// Unsupported configuration or protocol feature.
    #[error("unsupported: {0}")]
    Unsupported(&'static str),

    /// Invalid caller-supplied argument.
    #[error("invalid argument: {0}")]
    InvalidArgument(&'static str),

    /// An IPMI command completed with a non-zero completion code.
    #[error("ipmi completion code: {completion_code:#04x}")]
    CompletionCode {
        /// Raw completion code returned by the BMC.
        completion_code: u8,
    },
}

impl Error {
    #[allow(dead_code)]
    pub(crate) fn protocol_owned(msg: impl Into<String>) -> Self {
        Self::ProtocolOwned(msg.into())
    }
}
