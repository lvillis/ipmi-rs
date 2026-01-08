# ipmi

<a href="https://crates.io/crates/ipmi">
  <img src="https://img.shields.io/crates/v/ipmi.svg" alt="crates.io version">
</a>

A production-oriented **IPMI v2.0 RMCP+** client library (async-first + optional blocking).

This crate focuses on:

- **IPMI v2.0 RMCP+ session establishment** (Open Session + RAKP 1-4)
- **Integrity**: HMAC-SHA1-96
- **Confidentiality**: AES-CBC-128
- **Async API** (tokio, default)
- **Blocking API** (feature `blocking`)

> Note: IPMI is a large specification. This crate implements a secure and commonly supported baseline (mandatory-to-implement algorithms) and provides a solid foundation for adding more commands and cipher suites.

## Install

Async API (default):

```toml
[dependencies]
ipmi = "0.1"
```

Blocking API without pulling tokio:

```toml
[dependencies]
ipmi = { version = "0.1", default-features = false, features = ["blocking"] }
```

Observability (optional):

```toml
[dependencies]
ipmi = { version = "0.1", features = ["tracing", "metrics"] }
```

## Quick start (async)

```rust
use ipmi::{Client, PrivilegeLevel};

// You need a tokio runtime in your application to use the async client.
#[tokio::main]
async fn main() -> ipmi::Result<()> {
    let target = "192.0.2.10:623".parse()?;

    let client = Client::builder(target)
        .username("ADMIN")
        .password("secret")
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(std::time::Duration::from_secs(2))
        .retries(3)
        .build()
        .await?;

    let device_id = client.get_device_id().await?;
    println!("BMC: {:?}", device_id);

    // Optional: explicitly close the session when you're done.
    let _ = client.close_session().await;

    Ok(())
}
```

## Quick start (blocking)

```rust
use ipmi::{BlockingClient, PrivilegeLevel};

fn main() -> ipmi::Result<()> {
    let target = "192.0.2.10:623".parse()?;

    let client = BlockingClient::builder(target)
        .username("ADMIN")
        .password("secret")
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(std::time::Duration::from_secs(2))
        .retries(3)
        .build()?;

    let device_id = client.get_device_id()?;
    println!("BMC: {:?}", device_id);

    // Optional: explicitly close the session when you're done.
    let _ = client.close_session();

    Ok(())
}
```

## Typed commands

The crate exposes a typed command interface in `ipmi::commands`. You can execute built-in commands
directly, or implement `commands::Command` for custom commands:

```rust
use ipmi::commands::GetDeviceId;

let device_id = client.execute(GetDeviceId).await?;
let device_id = blocking_client.execute(GetDeviceId)?;
```

## Security notes

- Password / KG are stored in memory only for the duration of session establishment and are zeroized on drop.
- Session keys are zeroized when the client is dropped.
- The client verifies integrity checks (HMAC) before decrypting payloads.
- The library avoids `unwrap()`/`expect()` in production code.

## Feature support

- Transport: UDP/623 (LAN)
- Session: RMCP+ / RAKP (IPMI v2.0)
- Commands:
  - `Get Device ID` (netfn `0x06`, cmd `0x01`)
  - `Get Self Test Results` (netfn `0x06`, cmd `0x04`)
  - `Get System GUID` (netfn `0x06`, cmd `0x37`)
  - `Get Chassis Status` (netfn `0x00`, cmd `0x01`)
  - `Chassis Control` (netfn `0x00`, cmd `0x02`)
  - `Get Channel Authentication Capabilities` (netfn `0x06`, cmd `0x38`)
  - `Close Session` (netfn `0x06`, cmd `0x3C`)
  - `send_raw()` for arbitrary commands
