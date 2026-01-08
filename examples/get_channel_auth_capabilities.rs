use std::time::Duration;

use ipmi::{Client, PrivilegeLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example:
    //   cargo run --example get_channel_auth_capabilities -- 192.168.1.10:623 admin password 1 admin
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("missing <host:port>")?.parse()?;
    let username = args.next().ok_or("missing <username>")?;
    let password = args.next().ok_or("missing <password>")?;
    let channel_str = args.next().ok_or("missing <channel>")?;
    let privilege_str = args.next().unwrap_or_else(|| "admin".to_string());

    let channel = parse_u8(&channel_str)?;
    let privilege = parse_privilege(&privilege_str)?;

    let mut client = Client::builder(target)
        .username(username)
        .password(password)
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(Duration::from_secs(2))
        .retries(3)
        .build()?;

    let caps = client.get_channel_auth_capabilities(channel, privilege)?;
    println!("Channel Auth Capabilities: {caps:?}");

    Ok(())
}

fn parse_u8(s: &str) -> Result<u8, Box<dyn std::error::Error>> {
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        Ok(u8::from_str_radix(hex, 16)?)
    } else {
        Ok(s.parse::<u8>()?)
    }
}

fn parse_privilege(s: &str) -> Result<PrivilegeLevel, Box<dyn std::error::Error>> {
    let value = s.to_ascii_lowercase();
    match value.as_str() {
        "admin" | "administrator" => Ok(PrivilegeLevel::Administrator),
        "operator" | "oper" => Ok(PrivilegeLevel::Operator),
        "user" => Ok(PrivilegeLevel::User),
        "callback" => Ok(PrivilegeLevel::Callback),
        "oem" => Ok(PrivilegeLevel::Oem),
        _ => Err("invalid privilege (admin|operator|user|callback|oem)".into()),
    }
}
