# ipmi

<a href="https://crates.io/crates/ipmi">
  <img src="https://img.shields.io/crates/v/ipmi.svg" alt="crates.io version">
</a>

A production-oriented, blocking **IPMI v2.0 RMCP+** client library.

This crate focuses on:

- **IPMI v2.0 RMCP+ session establishment** (Open Session + RAKP 1-4)
- **Integrity**: HMAC-SHA1-96
- **Confidentiality**: AES-CBC-128
- **Blocking API** (no async runtime required)

> Note: IPMI is a large specification. This crate implements a secure and commonly supported baseline (mandatory-to-implement algorithms) and provides a solid foundation for adding more commands and cipher suites.

## Install

```toml
[dependencies]
ipmi = "0.1"
```

## Quick start

```rust
use ipmi::{Client, PrivilegeLevel};

fn main() -> ipmi::Result<()> {
    let target = "192.0.2.10:623".parse()?;

    let mut client = Client::builder(target)
        .username("ADMIN")
        .password("secret")
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(std::time::Duration::from_secs(2))
        .retries(3)
        .build()?;

    let device_id = client.get_device_id()?;
    println!("BMC: {:?}", device_id);

    Ok(())
}
```

## Security notes

- Password / KG are stored in memory only for the duration of session establishment and are zeroized on drop.
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
  - `send_raw()` for arbitrary commands
