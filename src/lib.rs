#![deny(unsafe_code)]
#![warn(missing_docs)]

//! A production-oriented, blocking IPMI v2.0 RMCP+ client library.
//!
//! The crate implements:
//! - RMCP+ Open Session handshake
//! - RAKP 1-4 key exchange
//! - Integrity (HMAC-SHA1-96)
//! - Confidentiality (AES-CBC-128)
//!
//! It exposes a small public API (`Client`, `ClientBuilder`, and a few types)
//! while keeping protocol and transport details internal.

mod client;
mod crypto;
mod error;
mod protocol;
mod transport;
mod types;

pub use crate::client::{Client, ClientBuilder};
pub use crate::error::{Error, Result};
pub use crate::types::{
    ChannelAuthCapabilities, ChassisControl, ChassisStatus, DeviceId, FrontPanelControls,
    LastPowerEvent, PowerRestorePolicy, PrivilegeLevel, RawResponse, SelfTestDeviceError,
    SelfTestResult, SystemGuid,
};
