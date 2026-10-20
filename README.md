# weave

[![ci](https://github.com/Yashbhu/weave/actions/workflows/ci.yml/badge.svg)](https://github.com/Yashbhu/weave/actions/workflows/ci.yml)
[![license](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

Weave is a peer-to-peer Layer-3 overlay network written in Rust. Peers build a
virtual network on top of the physical one and exchange IP packets without a
direct link between them.

It ships the UDP transport, a two-node TUN overlay, multi-hop routing with
static routes, topology-driven routing with automatic failover, authenticated
endpoint migration with relay fallback, and a hardening pass (correctness and
security fixes, fault injection, lifecycle probing, rate limiting, fuzzing,
benchmarks). Peers exchange link state, calculate routes with Dijkstra, switch
to an alternate path when a link fails, authenticate each other with a Noise IK
handshake, encrypt control messages, migrate a peer's UDP endpoint when an
authenticated message says it moved, and fall back to a relay when a direct
path is dead.

## Performance

Measured on an Apple M-class laptop, macOS 15.5, `rustc` 1.91.1, `cargo bench
--bench baseline` (loopback; see [BENCHMARKING.md](BENCHMARKING.md) for
methodology and real-network runs).

### Hot paths (ns/op)

| Path                         | 64 B  | 512 B | 1400 B |
| ---------------------------- | ----- | ----- | ------ |
| wire encode                  | 21.2  | 48.5  | 37.0   |
| wire decode                  | 1.9   | 2.2   | 2.2    |
| packet validate              | 2.2   | 3.7   | 2.2    |
| hop-limit decrement          | 30.6  | 82.1  | 40.2   |

Single-node topology (1000 routes): route lookup 649.9 ns. Noise record layer
(1400 B): seal 1537.8 ns, open 726.5 ns. Topology recomputation (128 nodes):
27.5 µs.

### End-to-end loopback (µs, pps, Mbps)

Direct path:

| Payload | RTT median | RTT p95 | pkt/s   | Mbps   |
| ------- | ---------- | ------- | ------- | ------ |
| 64 B    | 19.6 µs    | 47.2 µs | 288,101 | 147.5  |
| 512 B   | 19.1 µs    | 33.5 µs | 253,736 | 1039.3 |
| 1400 B  | 19.1 µs    | 39.6 µs | 247,157 | 2768.2 |

Two-hop path (one relay node):

| Payload | RTT median | RTT p95 | pkt/s  | Mbps  |
| ------- | ---------- | ------- | ------ | ----- |
| 64 B    | 28.0 µs    | 46.5 µs | 51,390 | 26.3  |
| 512 B   | 29.7 µs    | 79.8 µs | 52,876 | 216.6 |
| 1400 B  | 33.6 µs    | 82.0 µs | 52,980 | 593.4 |

## Quick start

```sh
cargo build --release
```

Two nodes on loopback (message mode):

```sh
# terminal 1
cargo run --release -- --bind 127.0.0.1:4000 --peer 127.0.0.1:4001

# terminal 2
cargo run --release -- --bind 127.0.0.1:4001 --peer 127.0.0.1:4000
```

Two nodes with a TUN overlay (root required for the TUN device):

```sh
# terminal 1
sudo ./target/release/weave \
  --bind 0.0.0.0:4000 \
  --tun --address 10.77.0.1 --peer-address 10.77.0.2

# terminal 2
sudo ./target/release/weave \
  --bind 0.0.0.0:4001 \
  --tun --address 10.77.0.2 --peer-address 10.77.0.1

# then, from either side
ping 10.77.0.1
```

### Authenticated, encrypted control sessions

Generate a keypair per node, then pass each node its own private key
(`--identity`) and every neighbour's public key (`--peer-key`):

```sh
cargo run --release --bin weave -- --tun ... --identity <HEX>
cargo run --release --bin weave -- --tun ... --peer-key 10.77.0.1=<HEX>
```

With `--identity` set, every neighbour must have a `--peer-key` entry. Control
messages are encrypted with Noise IK; session keys are rotated. Data-plane
packets are not yet encrypted.

### Multi-hop and failover

Static routes:

```sh
--route 10.77.0.3=203.0.113.7:4000
```

Dynamic topology (link-state, Dijkstra, automatic failover):

```sh
--neighbor 10.77.0.2=203.0.113.9:4000
```

Relay fallback (run any reachable node as a relay with `--serve-relay`, and
point unreachable neighbours at it with `--relay <ADDR:PORT>`).

## Benchmarks

### Loopback micro-benchmarks

```sh
cargo bench --bench baseline
```

### weave-netbench (application-level, real or emulated networks)

An echo benchmark that measures RTT, throughput, and loss end-to-end. When run
through the overlay it traverses the TUN data plane, so it reflects what a real
application sees:

```sh
# echo server on its overlay address (root)
sudo ./target/release/weave --bind 0.0.0.0:4000 \
  --tun --address 10.77.0.1 --peer-address 10.77.0.2

# probe (root not required)
./target/release/weave-netbench probe \
  --target 10.77.0.1:4000 \
  --sizes 64,512,1200,1400 \
  --runs 5 --warmup 1 --csv results.csv
```

```text
payload   rtt_median     rtt_p95  rtt_loss    thr_pkt/s   thr_mbps  thr_loss
   64B      40.0us      77.6us     0.00%     105776.7      54.16     0.00%
  512B      33.8us     157.3us     0.00%      92560.0     379.13     0.00%
 1400B      31.6us      97.5us     0.00%      92476.7    1035.74     0.00%
```

See [BENCHMARKING.md](BENCHMARKING.md) for the full methodology: baselines
(iperf3, ping), multi-hop and relay scenarios, `tc netem` impairment tests
(1%/5% loss, 50/100 ms delay, partition-and-heal), and the reproducibility
checklist.

## CLI

```text
--bind <ADDR:PORT>      local UDP address to bind (required)
--peer <ADDR:PORT>      peer endpoint, repeatable (message mode)
--tun                   run the TUN overlay instead of message mode
--address <IP>          this node's overlay address (with --tun)
--peer-address <IP>     the peer's overlay address (with --tun)
--route <P=ADDR:PORT>   static route, repeatable (with --tun)
--neighbor <IP=ADDR:PORT> topology neighbour, repeatable; enables dynamic
                        routing and automatic failover (with --tun)
--heartbeat-ms <N>      control-plane heartbeat interval (with --tun)
--link-timeout-ms <N>   how long a silent neighbour is trusted (with --tun)
--identity <HEX>        this node's long-term private key; enables
                        authenticated, encrypted control sessions (with --tun)
--peer-key <IP=HEX>     a neighbour's static public key, repeatable; required
                        for every neighbour when --identity is set (with --tun)
--relay <ADDR:PORT>     relay to fall back to when a neighbour is unreachable
                        (with --tun)
--serve-relay           forward relay envelopes; run as a relay (with --tun)
--control-rate-limit <N> control messages per second accepted from one source
                        (default 32; 0 disables; with --tun)
--mtu <N>               overlay MTU (default 1420; with --tun)
--queue-depth <N>       packets buffered per direction (default 1024; with --tun)
-h, --help              print help
-V, --version           print version
```

## Wire format

Each datagram is a small frame: a 3-byte header (version + 16-bit big-endian
payload length) followed by the payload. Largest datagram: 1500 bytes
(`MAX_DATAGRAM_SIZE`); largest payload: 1497 bytes. On receive, anything that
isn't a valid frame is dropped, not fatal.

## Development

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo bench --bench baseline
```

Tests live beside the modules in `src/` and in `tests/` (`transport.rs`,
`routing.rs`, `topology.rs`, `connectivity.rs`, `fuzz.rs`, and the root-only
`tun_open.rs`). They use random free ports, a fake TUN, and short timeouts.
`topology.rs` includes deterministic no-sleep simulations of failover and of a
full partition-and-heal; `fuzz.rs` is a deterministic mutational fuzzer over
every wire-facing decoder.

## Not done yet

- data-plane packets are not encrypted; only control-plane traffic is
- authentication is per-peer Noise IK, but a compromised long-term key is not
  detected (no rotation or revocation)
- no delivery, ordering, or duplicate protection
- peer addresses are set by hand, no discovery
- convergence is eventual, not instantaneous or strongly consistent
- NAT traversal is heuristic (advertised endpoint candidates plus relay
  fallback), not a full ICE-style negotiation

## License

Licensed under the Apache License, Version 2.0. See [LICENSE](LICENSE).
