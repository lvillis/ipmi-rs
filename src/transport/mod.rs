#[cfg(feature = "blocking")]
use crate::error::Result;

/// A synchronous transport for exchanging RMCP+/IPMI datagrams.
#[cfg(feature = "blocking")]
pub trait Transport {
    /// Send a request datagram and wait for the corresponding response datagram.
    fn send_recv(&self, request: &[u8]) -> Result<Vec<u8>>;
}

#[cfg(feature = "async")]
mod async_support {
    use core::future::Future;
    use core::pin::Pin;

    use crate::error::Result;

    /// An asynchronous transport for exchanging RMCP+/IPMI datagrams.
    pub trait AsyncTransport {
        /// Send a request datagram and wait for the corresponding response datagram.
        fn send_recv<'a>(
            &'a self,
            request: &'a [u8],
        ) -> Pin<Box<dyn Future<Output = Result<Vec<u8>>> + Send + 'a>>;
    }
}

#[cfg(feature = "async")]
pub use async_support::AsyncTransport;

#[cfg(feature = "blocking")]
pub(crate) mod blocking;

#[cfg(feature = "async")]
pub(crate) mod tokio;
