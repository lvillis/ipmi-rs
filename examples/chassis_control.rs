#[cfg(feature = "blocking")]
mod enabled {
    use std::time::Duration;

    use ipmi::{BlockingClient, ChassisControl, PrivilegeLevel};

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Example:
        //   cargo run --no-default-features --features blocking --example chassis_control -- 192.168.1.10:623 admin password on
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

        let client = BlockingClient::builder(target)
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
}

#[cfg(feature = "blocking")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    enabled::main()
}

#[cfg(not(feature = "blocking"))]
fn main() {
    eprintln!("This example requires feature `blocking`.");
}
