# weave

Weave is a peer-to-peer Layer-3 overlay network written in Rust. The idea is a
virtual network on top of the physical one, so peers can exchange IP packets
without a direct link between them.

This repo only has the UDP transport so far. TUN devices, packet forwarding,
encryption, peer discovery, routing, and failure detection aren't built yet.

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
--peer <ADDR:PORT>   peer to send one message to at startup (optional)
-h, --help           print help
-V, --version        print version
```

## Development

Format, lint, and test:

```sh
cargo fmt --all
cargo clippy --all-targets --all-features -- -D warnings
cargo test
```

Tests are in `src/wire.rs` (encoding) and `tests/transport.rs` (sockets, message
exchange, sender id, bad input, shutdown). They use random free ports and short
timeouts.

## Not done yet

- no encryption or authentication
- no delivery, ordering, or duplicate protection
- peer addresses are set by hand, no discovery
- no routing or multi-hop
- no failover
- no TUN device or packet forwarding
- the frame format is a placeholder and will change

## License

MIT OR Apache-2.0.
