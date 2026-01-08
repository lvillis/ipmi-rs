use std::time::Duration;

use ipmi::{ChassisControl, Client, PrivilegeLevel};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Example:
    //   cargo run --example chassis_control -- 192.168.1.10:623 admin password on
    let mut args = std::env::args().skip(1);
    let target = args.next().ok_or("missing <host:port>")?.parse()?;
    let username = args.next().ok_or("missing <username>")?;
    let password = args.next().ok_or("missing <password>")?;
    let action = args.next().ok_or("missing <action>")?;

    let control = match action.to_ascii_lowercase().as_str() {
        "on" | "up" => ChassisControl::PowerUp,
        "off" | "down" => ChassisControl::PowerDown,
        "cycle" => ChassisControl::PowerCycle,
        "reset" => ChassisControl::HardReset,
        "diag" => ChassisControl::PulseDiagnostic,
        "soft" | "acpi" => ChassisControl::AcpiSoft,
        _ => return Err("invalid action (on|off|cycle|reset|diag|soft)".into()),
    };

    let mut client = Client::builder(target)
        .username(username)
        .password(password)
        .privilege_level(PrivilegeLevel::Administrator)
        .timeout(Duration::from_secs(2))
        .retries(3)
        .build()?;

    client.chassis_control(control)?;
    println!("Chassis control command sent: {action}");

    Ok(())
}
