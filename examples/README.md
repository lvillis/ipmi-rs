# Examples

All examples use the same argument order:

```
cargo run --example <name> -- <host:port> <username> <password> [extra...]
```

Examples:

```
cargo run --example get_device_id -- 192.168.1.10:623 admin password
cargo run --example get_self_test_results -- 192.168.1.10:623 admin password
cargo run --example get_system_guid -- 192.168.1.10:623 admin password
cargo run --example get_chassis_status -- 192.168.1.10:623 admin password
cargo run --example chassis_control -- 192.168.1.10:623 admin password on
cargo run --example get_channel_auth_capabilities -- 192.168.1.10:623 admin password 1 admin
```
