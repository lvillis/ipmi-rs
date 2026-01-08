# Examples

All examples use the same argument order:

```
cargo run --example <name> -- <host:port> <username> <password> [extra...]
```

Examples:

```
# Async (default)
cargo run --example tokio_get_device_id -- 192.168.1.10:623 admin password

# Blocking (feature `blocking`)
cargo run --no-default-features --features blocking --example get_device_id -- 192.168.1.10:623 admin password
cargo run --no-default-features --features blocking --example get_self_test_results -- 192.168.1.10:623 admin password
cargo run --no-default-features --features blocking --example get_system_guid -- 192.168.1.10:623 admin password
cargo run --no-default-features --features blocking --example get_chassis_status -- 192.168.1.10:623 admin password
cargo run --no-default-features --features blocking --example chassis_control -- 192.168.1.10:623 admin password on
cargo run --no-default-features --features blocking --example get_channel_auth_capabilities -- 192.168.1.10:623 admin password 1 admin
```
