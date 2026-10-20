//! relay envelope and forwarding policy.
//!
//! when a peer cannot be reached directly, traffic is wrapped in a relay
//! envelope and sent to a relay that both sides can reach. the envelope keeps
//! the *inner* ip packet untouched - only addressing metadata is added - so the
//! overlay destination and the peer's logical identity never depend on the
//! relay endpoint.
//!
//!   relay body: [ src id 4 ][ dst id 4 ][ ttl 1 ][ inner packet ]
//!
//! `src` and `dst` are overlay identities (`NodeId`), not udp endpoints. the
//! relay resolves `dst` to an endpoint using its own endpoint registry, which is
//! what keeps forwarding independent of any single physical address.
//!
//! # limits and loop safety
//!
//! - `ttl` starts at `MAX_RELAY_TTL` and is decremented on every relay hop; a
//!   hop that would reach zero is dropped, so a misconfigured relay cannot loop
//!   a packet forever.
//! - a relay only forwards for clients it was configured to serve
//!   (`Action::Drop(RelayDrop::NotAllowed)`), so an unauthenticated stranger
//!   cannot turn it into an open forwarder.
//! - the envelope is capped at `MAX_RELAY_BYTES`, so a relay buffers at most one
//!   bounded packet per forward.
//!
//! this module is pure: it does no i/o and makes no decisions about *which*
//! relay to use (that is `connectivity.rs`).

use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};

use crate::topology::NodeId;
use crate::wire::MAX_PAYLOAD_LEN;

/// bytes of relay header before the inner packet.
pub const HEADER_LEN: usize = 9;

/// highest ttl a relay envelope may carry.
pub const MAX_RELAY_TTL: u8 = 8;

/// largest relay body we will accept or emit.
pub const MAX_RELAY_BYTES: usize = MAX_PAYLOAD_LEN;

/// a relay envelope: where a packet is from, where it is going, and the packet.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Envelope {
    /// logical identity of the node that originated the inner packet.
    pub src: NodeId,
    /// logical identity the inner packet is ultimately for.
    pub dst: NodeId,
    /// remaining relay hops.
    pub ttl: u8,
    /// the untouched inner ip packet.
    pub inner: Vec<u8>,
}

/// what can go wrong encoding or decoding an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayError {
    /// fewer bytes than the header needs.
    TooShort {
        /// bytes we got.
        len: usize,
    },
    /// the envelope is larger than `MAX_RELAY_BYTES`.
    TooLarge {
        /// bytes we got.
        len: usize,
    },
    /// the inner packet is empty, which is not a packet.
    EmptyInner,
    /// the ttl is above `MAX_RELAY_TTL`.
    TtlTooLarge(u8),
    /// the envelope names the unspecified address as source or destination.
    UnspecifiedNode,
}

impl fmt::Display for RelayError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "relay envelope too short: {len} bytes"),
            Self::TooLarge { len } => {
                write!(
                    f,
                    "relay envelope too large: {len} bytes (maximum {MAX_RELAY_BYTES})"
                )
            }
            Self::EmptyInner => f.write_str("relay envelope carries no inner packet"),
            Self::TtlTooLarge(ttl) => {
                write!(f, "relay ttl {ttl} is above the maximum {MAX_RELAY_TTL}")
            }
            Self::UnspecifiedNode => f.write_str("relay envelope names the unspecified address"),
        }
    }
}

impl Error for RelayError {}

/// encode an envelope body (without the wire version byte).
pub fn encode(src: NodeId, dst: NodeId, ttl: u8, inner: &[u8]) -> Result<Vec<u8>, RelayError> {
    if ttl > MAX_RELAY_TTL {
        return Err(RelayError::TtlTooLarge(ttl));
    }
    if inner.is_empty() {
        return Err(RelayError::EmptyInner);
    }
    if src.0.is_unspecified() || dst.0.is_unspecified() {
        return Err(RelayError::UnspecifiedNode);
    }
    let total = HEADER_LEN + inner.len();
    if total > MAX_RELAY_BYTES {
        return Err(RelayError::TooLarge { len: total });
    }
    let mut body = Vec::with_capacity(total);
    body.extend_from_slice(&src.0.octets());
    body.extend_from_slice(&dst.0.octets());
    body.push(ttl);
    body.extend_from_slice(inner);
    Ok(body)
}

/// decode and validate an envelope body.
pub fn decode(body: &[u8]) -> Result<Envelope, RelayError> {
    if body.len() > MAX_RELAY_BYTES {
        return Err(RelayError::TooLarge { len: body.len() });
    }
    if body.len() < HEADER_LEN {
        return Err(RelayError::TooShort { len: body.len() });
    }
    let src = NodeId(Ipv4Addr::new(body[0], body[1], body[2], body[3]));
    let dst = NodeId(Ipv4Addr::new(body[4], body[5], body[6], body[7]));
    let ttl = body[8];
    if ttl > MAX_RELAY_TTL {
        return Err(RelayError::TtlTooLarge(ttl));
    }
    let inner = body[HEADER_LEN..].to_vec();
    if inner.is_empty() {
        return Err(RelayError::EmptyInner);
    }
    if src.0.is_unspecified() || dst.0.is_unspecified() {
        return Err(RelayError::UnspecifiedNode);
    }
    Ok(Envelope {
        src,
        dst,
        ttl,
        inner,
    })
}

/// why a relay dropped an envelope.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RelayDrop {
    /// the envelope ran out of relay hops.
    TtlExpired,
    /// the sender is not a configured relay client.
    NotAllowed,
    /// the relay does not know how to reach the destination.
    UnknownDestination,
}

impl RelayDrop {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RelayDrop::TtlExpired => "relay ttl expired",
            RelayDrop::NotAllowed => "sender is not an allowed relay client",
            RelayDrop::UnknownDestination => "relay does not know the destination endpoint",
        }
    }
}

/// what a relay should do with an envelope.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Action {
    /// the destination is us: hand the inner packet to the local stack.
    Deliver(Vec<u8>),
    /// forward the (decremented) envelope to this endpoint.
    Forward {
        /// the next hop's udp endpoint.
        to: SocketAddr,
        /// the re-encoded body, ready for a relay frame.
        body: Vec<u8>,
    },
    /// give up.
    Drop(RelayDrop),
}

/// decide what to do with a received envelope.
///
/// - `local` is this node's identity; an envelope addressed to it is delivered.
/// - `allowed` is whether `envelope.src` is an authorized relay client. the
///   caller decides this (e.g. the source is a configured, authenticated peer);
///   an unauthorized source is refused before any forwarding.
/// - `dst_endpoint` is the endpoint the relay would forward to, looked up from
///   its own endpoint registry.
pub fn decide(
    envelope: &Envelope,
    local: NodeId,
    allowed: bool,
    dst_endpoint: Option<SocketAddr>,
) -> Action {
    if envelope.dst == local {
        return Action::Deliver(envelope.inner.clone());
    }
    if !allowed {
        return Action::Drop(RelayDrop::NotAllowed);
    }
    if envelope.ttl == 0 {
        return Action::Drop(RelayDrop::TtlExpired);
    }
    let Some(to) = dst_endpoint else {
        return Action::Drop(RelayDrop::UnknownDestination);
    };
    match encode(
        envelope.src,
        envelope.dst,
        envelope.ttl - 1,
        &envelope.inner,
    ) {
        Ok(body) => Action::Forward { to, body },
        Err(_) => Action::Drop(RelayDrop::TtlExpired),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn packet(payload: &[u8]) -> Vec<u8> {
        let mut p = vec![0u8; 20 + payload.len()];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&((20 + payload.len()) as u16).to_be_bytes());
        p[8] = 64;
        p[20..].copy_from_slice(payload);
        p
    }

    #[test]
    fn round_trips_an_envelope() {
        let inner = packet(b"hello");
        let body = encode(node("10.0.0.1"), node("10.0.0.4"), 4, &inner).unwrap();
        assert_eq!(body.len(), HEADER_LEN + inner.len());
        let env = decode(&body).unwrap();
        assert_eq!(env.src, node("10.0.0.1"));
        assert_eq!(env.dst, node("10.0.0.4"));
        assert_eq!(env.ttl, 4);
        assert_eq!(env.inner, inner, "the inner packet must be untouched");
    }

    #[test]
    fn delivers_when_the_destination_is_local() {
        let inner = packet(b"payload");
        let env = Envelope {
            src: node("10.0.0.1"),
            dst: node("10.0.0.4"),
            ttl: 3,
            inner: inner.clone(),
        };
        assert_eq!(
            decide(&env, node("10.0.0.4"), true, Some(addr(1))),
            Action::Deliver(inner)
        );
    }

    #[test]
    fn forwards_and_decrements_the_ttl_preserving_the_inner_packet() {
        let inner = packet(b"payload");
        let env = Envelope {
            src: node("10.0.0.1"),
            dst: node("10.0.0.4"),
            ttl: 3,
            inner: inner.clone(),
        };
        match decide(&env, node("10.0.0.9"), true, Some(addr(4004))) {
            Action::Forward { to, body } => {
                assert_eq!(to, addr(4004));
                let fwd = decode(&body).unwrap();
                assert_eq!(fwd.ttl, 2);
                assert_eq!(fwd.src, node("10.0.0.1"));
                assert_eq!(fwd.dst, node("10.0.0.4"));
                assert_eq!(fwd.inner, inner, "inner packet changed in transit");
            }
            other => panic!("expected a forward, got {other:?}"),
        }
    }

    #[test]
    fn drops_when_the_ttl_is_spent() {
        let env = Envelope {
            src: node("10.0.0.1"),
            dst: node("10.0.0.4"),
            ttl: 0,
            inner: packet(b"x"),
        };
        assert_eq!(
            decide(&env, node("10.0.0.9"), true, Some(addr(4004))),
            Action::Drop(RelayDrop::TtlExpired)
        );
    }

    #[test]
    fn refuses_unconfigured_clients() {
        let env = Envelope {
            src: node("10.0.0.1"),
            dst: node("10.0.0.4"),
            ttl: 3,
            inner: packet(b"x"),
        };
        assert_eq!(
            decide(&env, node("10.0.0.9"), false, Some(addr(4004))),
            Action::Drop(RelayDrop::NotAllowed),
            "an unauthenticated sender must not be relayed"
        );
    }

    #[test]
    fn drops_unknown_destinations() {
        let env = Envelope {
            src: node("10.0.0.1"),
            dst: node("10.0.0.4"),
            ttl: 3,
            inner: packet(b"x"),
        };
        assert_eq!(
            decide(&env, node("10.0.0.9"), true, None),
            Action::Drop(RelayDrop::UnknownDestination)
        );
    }

    #[test]
    fn rejects_bad_bodies() {
        assert_eq!(decode(&[]), Err(RelayError::TooShort { len: 0 }));
        assert_eq!(decode(&[0u8; HEADER_LEN]), Err(RelayError::EmptyInner));

        let too_big = vec![0u8; MAX_RELAY_BYTES + 1];
        assert_eq!(
            decode(&too_big),
            Err(RelayError::TooLarge {
                len: MAX_RELAY_BYTES + 1
            })
        );

        assert_eq!(
            encode(node("10.0.0.1"), node("10.0.0.4"), MAX_RELAY_TTL + 1, b"x"),
            Err(RelayError::TtlTooLarge(MAX_RELAY_TTL + 1))
        );
    }

    #[test]
    fn rejects_the_unspecified_address() {
        assert_eq!(
            encode(node("0.0.0.0"), node("10.0.0.4"), 4, b"x"),
            Err(RelayError::UnspecifiedNode)
        );
        assert_eq!(
            encode(node("10.0.0.1"), node("0.0.0.0"), 4, b"x"),
            Err(RelayError::UnspecifiedNode)
        );

        // a hand-built body with an unspecified destination is refused.
        let mut body = vec![10, 0, 0, 1, 0, 0, 0, 0, 4];
        body.extend_from_slice(&packet(b"x"));
        assert_eq!(decode(&body), Err(RelayError::UnspecifiedNode));
    }
}
