//! weave - a peer-to-peer layer 3 overlay network.
//!
//! right now it's just the udp transport: two processes can swap framed
//! messages over a socket. wire.rs has the frame layout, transport.rs has the
//! socket side.
//!
//! not here yet: tun, packet forwarding, crypto, discovery, routing, failover.
//! this is for local development, not the real wire protocol.

pub mod transport;
pub mod wire;
