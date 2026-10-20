# weave

Weave is a peer-to-peer Layer-3 overlay network written in Rust. The idea is a
virtual network on top of the physical one, so peers can exchange IP packets
without a direct link between them.

This repo has the UDP transport (M1), the two-node TUN overlay (M2), multi-hop
routing with static routes (M4), topology-driven routing with automatic failover
(M5), authenticated endpoint migration with relay fallback (M6), and the M7
hardening pass. Peers exchange link state, calculate routes with Dijkstra,
switch to an alternate path when a link fails, authenticate each other with a
Noise IK handshake, encrypt control messages, migrate a peer's UDP endpoint when
an authenticated message says it moved, and fall back to a relay when a direct
path is dead. M7 audited the implementation, fixed several correctness and
security defects, and added fault-injection, lifecycle, rate-limiting, fuzzing
and benchmark coverage.

See [`docs/08-m4-routing.md`](./docs/08-m4-routing.md) for static multi-hop
routing, [`docs/09-m5-topology.md`](./docs/09-m5-topology.md) for topology
exchange, failure detection and recovery,
[`docs/10-m6-migration-relay.md`](./docs/10-m6-migration-relay.md) for endpoint
migration, relay fallback and control authentication, and
[`docs/11-m7-hardening.md`](./docs/11-m7-hardening.md) for the M7 audit,
security review, fault injection and benchmarks.

## The transport

A small UDP transport that lets two processes exchange framed messages. Each
process can:

- bind to a UDP address (`--bind`),
- send one message to a peer at startup (`--peer`),
- receive datagrams and see who sent them,
- drop malformed or oversized datagrams instead of crashing,
- shut down on Ctrl+C.

This is a local development transport, not the real wire protocol. It doesn't
encrypt anything, doesn't guarantee delivery or ordering, and shouldn't be used
outside local testing.

## Frame layout

Frames are a fixed 3-byte header followed by the payload:

```text
 0        1                 2                2 + N
+--------+--------+--------+------------------+
| version|  payload length |     payload      |
| 1 byte | 2 bytes big-end |   0..=N bytes    |
+--------+--------+--------+------------------+
```

| Field            | Size    | Notes                                |
| ---------------- | ------- | ------------------------------------ |
| `version`        | 1 byte  | protocol version, `1` for now        |
| `payload length` | 2 bytes | big-endian byte count of the payload |
| `payload`        | 0–N     | message body                         |

Size limits:

- biggest datagram: **1500 bytes** (`MAX_DATAGRAM_SIZE`) — keeps us under a
  typical Ethernet MTU so we don't rely on IP fragmentation on a LAN
- biggest payload: **1497 bytes** (`MAX_PAYLOAD_LEN` = 1500 − 3)

On receive we drop anything that isn't a valid frame: too short, too big, wrong
version, or a length that doesn't match the payload.

## Running two peers

Build once:

```sh
cargo build
```

Then, in terminal 1, start the first node (listen on 4000, message peer on 4001):

```sh
cargo run -- --bind 127.0.0.1:4000 --peer 127.0.0.1:4001
```

In terminal 2, start the second node (listen on 4001, message peer on 4000):

```sh
cargo run -- --bind 127.0.0.1:4001 --peer 127.0.0.1:4000
```

Each node sends one message at startup and logs a `received message` line when it
gets a datagram. Ctrl+C stops a node and the receive task exits.

CLI options:

```text
--bind <ADDR:PORT>   local UDP address to bind (required)
--peer <ADDR:PORT>   peer endpoint, repeatable (message mode sends to the first)
--tun                 run the TUN overlay instead of message mode
--address <IP>        this node's overlay address (with --tun)
--peer-address <IP>   the peer's overlay address (with --tun)
--route <P=ADDR:PORT> static route, repeatable (with --tun)
--neighbor <IP=ADDR:PORT> topology neighbour, repeatable; enables dynamic
                      routing and automatic failover (with --tun)
--heartbeat-ms <N>    control-plane heartbeat interval (with --tun)
--link-timeout-ms <N> how long a silent neighbour is trusted (with --tun)
--identity <HEX>      this node's long-term private key; enables authenticated,
                      encrypted control sessions (with --tun)
--peer-key <IP=HEX>   a neighbour's static public key, repeatable; required for
                      every neighbour when --identity is set (with --tun)
--relay <ADDR:PORT>   relay to fall back to when a neighbour is unreachable
                      (with --tun)
--serve-relay         forward relay envelopes for neighbours; run this node as a
                      relay (with --tun)
--control-rate-limit <N> control messages per second accepted from one source
                      (default 32; 0 disables; with --tun)
--mtu <N>             overlay MTU (default 1420; with --tun)
--queue-depth <N>     packets buffered per direction (default 1024; with --tun)
-h, --help            print help
-V, --version         print version
```

## Development

Format, lint, test, and benchmark:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
cargo bench --bench baseline
```

Tests live beside the modules in `src/` (`wire`, `packet`, `route`, `forward`,
`peer`, `noise`, `rate`, `lifecycle`, `endpoints`, `relay`, `overlay`,
`topology`, `control`, `router`) and in `tests/` (`transport.rs`, `routing.rs`,
`topology.rs`, `connectivity.rs`, `fuzz.rs`, and the root-only `tun_open.rs`).
They use random free ports, a fake TUN, and short timeouts. `topology.rs`
includes a deterministic no-sleep simulation of failover and of a full
partition-and-heal; `fuzz.rs` is a deterministic mutational fuzzer over every
wire-facing decoder. `benches/baseline.rs` measures the pure hot paths, the
Noise record layer, and loopback end-to-end paths (direct and two-hop).

## Not done yet

- data-plane packets are not encrypted; only control-plane traffic is
- authentication is per-peer Noise IK, but a compromised long-term key is not
  detected (no rotation or revocation)
- no delivery, ordering, or duplicate protection
- peer addresses are set by hand, no discovery
- convergence is eventual, not instantaneous or strongly consistent
- NAT traversal is heuristic (advertised endpoint candidates plus relay fallback),
  not a full ICE-style negotiation
- the frame format is a placeholder and will change

## License

MIT OR Apache-2.0.
