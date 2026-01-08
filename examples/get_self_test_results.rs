#[cfg(feature = "blocking")]
mod enabled {
    use std::time::Duration;

    use ipmi::{BlockingClient, PrivilegeLevel};

    pub fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Example:
        //   cargo run --no-default-features --features blocking --example get_self_test_results -- 192.168.1.10:623 admin password
        let mut args = std::env::args().skip(1);
        let target = args.next().ok_or("missing <host:port>")?.parse()?;
        let username = args.next().ok_or("missing <username>")?;
        let password = args.next().ok_or("missing <password>")?;

        let client = BlockingClient::builder(target)
            .username(username)
            .password(password)
            .privilege_level(PrivilegeLevel::Administrator)
            .timeout(Duration::from_secs(2))
            .retries(3)
            .build()?;

        let result = client.get_self_test_results()?;
        println!("Self Test Results: {result:?}");

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
