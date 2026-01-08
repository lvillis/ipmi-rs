#[cfg(feature = "async")]
mod enabled {
    use std::time::Duration;

    use ipmi::{Client, PrivilegeLevel};

    #[tokio::main(flavor = "current_thread")]
    pub async fn main() -> Result<(), Box<dyn std::error::Error>> {
        // Example:
        //   cargo run --example tokio_get_device_id -- 192.168.1.10:623 admin password
        let mut args = std::env::args().skip(1);
        let target = args.next().ok_or("missing <host:port>")?.parse()?;
        let username = args.next().ok_or("missing <username>")?;
        let password = args.next().ok_or("missing <password>")?;

        let client = Client::builder(target)
            .username(username)
            .password(password)
            .privilege_level(PrivilegeLevel::Administrator)
            .timeout(Duration::from_secs(2))
            .retries(3)
            .build()
            .await?;

        let device_id = client.get_device_id().await?;
        println!("Device: {device_id:?}");

        Ok(())
    }
}

#[cfg(feature = "async")]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    enabled::main()
}

#[cfg(not(feature = "async"))]
fn main() {
    eprintln!("This example requires feature `async` (or `tokio`).");
}
