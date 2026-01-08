use std::time::Duration;

use ipmi::{Client, PrivilegeLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example:
    //   cargo run --example get_chassis_status -- 192.168.1.10:623 admin password
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("missing <host:port>")?.parse()?;
    let username = args.next().ok_or("missing <username>")?;
    let password = args.next().ok_or("missing <password>")?;

    let mut client = Client::builder(target)
        .username(username)
        .password(password)
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(Duration::from_secs(2))
        .retries(3)
        .build()?;

    let status = client.get_chassis_status()?;
    println!("Chassis Status: {status:?}");

    Ok(())
}
