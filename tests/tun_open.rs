//! test that opens a real interface, so it needs root. ignored by default.
//! run with `sudo cargo test --test tun_open -- --ignored`.

use weave::tun::{TunConfig, TunDevice};

#[test]
#[ignore = "requires root and creates a utun interface"]
fn opens_and_splits_a_tun_interface() {
    let config = TunConfig {
        name: None,
        address: "10.77.0.1".parse().unwrap(),
        destination: "10.77.0.2".parse().unwrap(),
        netmask: "255.255.255.255".parse().unwrap(),
        mtu: 1420,
        enable_routing: false,
    };

    let device = TunDevice::open(&config).expect("open tun (needs root)");
    let (_reader, _writer) = device.split().expect("split tun");
}
