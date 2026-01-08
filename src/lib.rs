#![deny(unsafe_code)]
#![warn(missing_docs)]

//! A production-oriented IPMI v2.0 RMCP+ client library (async-first + optional blocking).
//!
//! The crate implements:
//! - RMCP+ Open Session handshake
//! - RAKP 1-4 key exchange
//! - Integrity (HMAC-SHA1-96)
//! - Confidentiality (AES-CBC-128)
//!
//! By default (feature `async`) it exposes [`Client`] / [`ClientBuilder`] (tokio-based async).
//! With feature `blocking` it also exposes `BlockingClient` / `BlockingClientBuilder`.
//!
//! Protocol and transport details are kept internal.

mod client;
/// Typed IPMI commands and helpers.
///
/// This module defines the `commands::Command` trait and a set of common standard commands that
/// can be executed via `Client::execute` or `BlockingClient::execute`.
pub mod commands;
mod crypto;
mod debug;
mod error;
mod observe;
mod protocol;
mod session;
mod transport;
mod types;

/// Tokio-based asynchronous client API.
///
/// This is the default mode (feature `async`).
#[cfg(feature = "async")]
pub use crate::client::tokio::{Client, ClientBuilder};

/// Blocking (synchronous) client API.
#[cfg(feature = "blocking")]
pub use crate::client::blocking::{
    Client as BlockingClient, ClientBuilder as BlockingClientBuilder,
};

/// Backwards-compatible module-style exports for the blocking client.
#[cfg(feature = "blocking")]
pub mod blocking {
    pub use crate::client::blocking::{Client, ClientBuilder};
}

/// Backwards-compatible module-style exports for the tokio client.
#[cfg(feature = "async")]
pub mod tokio {
    pub use crate::client::tokio::{Client, ClientBuilder};
}

pub use crate::error::{Error, Result};
pub use crate::types::{
    ChannelAuthCapabilities, ChassisControl, ChassisStatus, DeviceId, FrontPanelControls,
    LastPowerEvent, PowerRestorePolicy, PrivilegeLevel, RawResponse, SelfTestDeviceError,
    SelfTestResult, SystemGuid,
};
