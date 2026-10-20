//! weave - a peer-to-peer layer 3 overlay network.
//!
//! two modes: a udp transport that swaps framed messages, and a tun overlay
//! that moves ip packets between interfaces. wire.rs has the frame format,
//! transport.rs the socket, packet.rs validation, tun.rs the interface,
//! route.rs the routing table, forward.rs the forwarding decision, peer.rs
//! peer availability and overlay.rs the packet pipeline.
//!
//! topology.rs models the network as a graph and calculates routes with
//! dijkstra; control.rs encodes the link-state messages peers exchange;
//! router.rs is the control plane that floods updates, detects failed links and
//! republishes the routing table. noise.rs authenticates and encrypts control
//! sessions between peers; routing is static unless a topology is configured.

pub mod connectivity;
pub mod control;
pub mod endpoints;
pub mod forward;
pub mod lifecycle;
pub mod noise;
pub mod overlay;
pub mod packet;
pub mod peer;
pub mod rate;
pub mod relay;
pub mod route;
pub mod router;
pub mod topology;
pub mod transport;
pub mod tun;
pub mod wire;
