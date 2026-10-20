//! encoding and decoding for topology control messages.
//!
//! these are the bodies carried in a `wire::CONTROL_VERSION` frame. the format
//! is a one byte kind followed by a fixed layout per kind. every decode is
//! length-checked and bounded, so a malformed or oversized message is rejected
//! before it reaches the topology.
//!
//! endpoints are carried as IPv4 address plus port. the overlay addresses are
//! IPv4, so this is enough for now; an IPv6 endpoint is rejected at encode time.

use std::error::Error;
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use crate::topology::{LinkAdvert, LinkState, NodeId};

/// a link-state advertisement: one directed link.
pub const KIND_LINK_ADVERT: u8 = 1;

/// a request for the sender's peer to reply with everything it knows.
pub const KIND_LINK_REQUEST: u8 = 2;

/// an endpoint update: the sender's physical endpoints have changed.
pub const KIND_ENDPOINT_UPDATE: u8 = 3;

/// a hole-punch probe, sent directly to a candidate endpoint to open a nat.
pub const KIND_PUNCH: u8 = 4;

/// hard cap on a single control message body.
pub const MAX_CONTROL_BYTES: usize = 256;

/// most candidate endpoints an update may carry.
pub const MAX_CANDIDATE_ENDPOINTS: u8 = 4;

const ADVERT_LEN: usize = 33;
const REQUEST_LEN: usize = 11;
const ENDPOINT_UPDATE_HEADER: usize = 14;
const ENDPOINT_ADDR_LEN: usize = 6;
const PUNCH_LEN: usize = 13;

/// a topology control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Message {
    /// a single directed link advertisement.
    LinkAdvert(LinkAdvert),
    /// "send me everything you know"; used to converge a fresh node.
    LinkRequest {
        /// the requester's identity.
        origin: NodeId,
        /// the requester's udp endpoint.
        origin_addr: SocketAddr,
    },
    /// the sender's physical endpoints have changed. `epoch` orders updates so a
    /// delayed one cannot roll an endpoint back.
    EndpointUpdate {
        /// the sender's identity.
        origin: NodeId,
        /// monotonically increasing revision of this update.
        epoch: u64,
        /// candidate endpoints the sender believes it is reachable at.
        addrs: Vec<SocketAddr>,
    },
    /// a hole-punch probe. receiving one proves the sender can reach us from the
    /// udp address it arrived on, which is what validates an endpoint.
    Punch {
        /// the sender's identity.
        origin: NodeId,
        /// opaque token echoed back to correlate the probe.
        token: u64,
    },
}

/// what can go wrong encoding or decoding a control message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ControlError {
    /// fewer bytes than the kind's layout needs.
    TooShort {
        /// bytes we got.
        len: usize,
    },
    /// more bytes than the kind's layout allows.
    BadLength {
        /// bytes we got.
        len: usize,
    },
    /// a kind byte we do not understand.
    UnknownKind(u8),
    /// a message body over `MAX_CONTROL_BYTES`.
    Oversized {
        /// bytes we got.
        len: usize,
    },
    /// an endpoint that was not IPv4.
    UnsupportedAddress,
    /// a state byte that was neither up nor down.
    BadState(u8),
    /// an endpoint update carried too many candidate endpoints.
    TooManyEndpoints(u8),
}

impl fmt::Display for ControlError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooShort { len } => write!(f, "control message too short: {len} bytes"),
            Self::BadLength { len } => {
                write!(f, "control message has the wrong length: {len} bytes")
            }
            Self::UnknownKind(kind) => write!(f, "unknown control message kind: {kind}"),
            Self::Oversized { len } => write!(
                f,
                "control message too large: {len} bytes (maximum {MAX_CONTROL_BYTES})"
            ),
            Self::UnsupportedAddress => write!(f, "control message carries a non-IPv4 endpoint"),
            Self::BadState(state) => write!(f, "unknown link state: {state}"),
            Self::TooManyEndpoints(count) => write!(
                f,
                "endpoint update carries {count} endpoints (maximum {MAX_CANDIDATE_ENDPOINTS})"
            ),
        }
    }
}

impl Error for ControlError {}

/// encode a control message body.
pub fn encode(message: &Message) -> Result<Vec<u8>, ControlError> {
    match message {
        Message::LinkAdvert(advert) => {
            let mut bytes = Vec::with_capacity(ADVERT_LEN);
            bytes.push(KIND_LINK_ADVERT);
            bytes.extend_from_slice(&advert.origin.0.octets());
            put_addr(&mut bytes, advert.origin_addr)?;
            bytes.extend_from_slice(&advert.from.0.octets());
            bytes.extend_from_slice(&advert.to.0.octets());
            bytes.extend_from_slice(&advert.metric.to_be_bytes());
            bytes.push(match advert.state {
                LinkState::Up => 1,
                LinkState::Down => 0,
            });
            bytes.extend_from_slice(&advert.seq.to_be_bytes());
            bytes.push(advert.ttl);
            debug_assert_eq!(bytes.len(), ADVERT_LEN);
            Ok(bytes)
        }
        Message::LinkRequest {
            origin,
            origin_addr,
        } => {
            let mut bytes = Vec::with_capacity(REQUEST_LEN);
            bytes.push(KIND_LINK_REQUEST);
            bytes.extend_from_slice(&origin.0.octets());
            put_addr(&mut bytes, *origin_addr)?;
            debug_assert_eq!(bytes.len(), REQUEST_LEN);
            Ok(bytes)
        }
        Message::EndpointUpdate {
            origin,
            epoch,
            addrs,
        } => {
            let count = u8::try_from(addrs.len())
                .map_err(|_| ControlError::TooManyEndpoints(MAX_CANDIDATE_ENDPOINTS))?;
            if count > MAX_CANDIDATE_ENDPOINTS {
                return Err(ControlError::TooManyEndpoints(count));
            }
            let mut bytes =
                Vec::with_capacity(ENDPOINT_UPDATE_HEADER + addrs.len() * ENDPOINT_ADDR_LEN);
            bytes.push(KIND_ENDPOINT_UPDATE);
            bytes.extend_from_slice(&origin.0.octets());
            bytes.extend_from_slice(&epoch.to_be_bytes());
            bytes.push(count);
            for addr in addrs {
                put_addr(&mut bytes, *addr)?;
            }
            Ok(bytes)
        }
        Message::Punch { origin, token } => {
            let mut bytes = Vec::with_capacity(PUNCH_LEN);
            bytes.push(KIND_PUNCH);
            bytes.extend_from_slice(&origin.0.octets());
            bytes.extend_from_slice(&token.to_be_bytes());
            debug_assert_eq!(bytes.len(), PUNCH_LEN);
            Ok(bytes)
        }
    }
}

/// decode and validate a control message body.
pub fn decode(bytes: &[u8]) -> Result<Message, ControlError> {
    let Some(&kind) = bytes.first() else {
        return Err(ControlError::TooShort { len: 0 });
    };
    if bytes.len() > MAX_CONTROL_BYTES {
        return Err(ControlError::Oversized { len: bytes.len() });
    }

    match kind {
        KIND_LINK_ADVERT => {
            if bytes.len() < ADVERT_LEN {
                return Err(ControlError::TooShort { len: bytes.len() });
            }
            if bytes.len() > ADVERT_LEN {
                return Err(ControlError::BadLength { len: bytes.len() });
            }
            let origin = node(&bytes[1..5]);
            let origin_addr = read_addr(&bytes[5..11]);
            let from = node(&bytes[11..15]);
            let to = node(&bytes[15..19]);
            let metric = u32::from_be_bytes([bytes[19], bytes[20], bytes[21], bytes[22]]);
            let state = match bytes[23] {
                1 => LinkState::Up,
                0 => LinkState::Down,
                other => return Err(ControlError::BadState(other)),
            };
            let mut seq_bytes = [0u8; 8];
            seq_bytes.copy_from_slice(&bytes[24..32]);
            let seq = u64::from_be_bytes(seq_bytes);
            let ttl = bytes[32];
            Ok(Message::LinkAdvert(LinkAdvert {
                origin,
                origin_addr,
                seq,
                from,
                to,
                metric,
                state,
                ttl,
            }))
        }
        KIND_LINK_REQUEST => {
            if bytes.len() < REQUEST_LEN {
                return Err(ControlError::TooShort { len: bytes.len() });
            }
            if bytes.len() > REQUEST_LEN {
                return Err(ControlError::BadLength { len: bytes.len() });
            }
            let origin = node(&bytes[1..5]);
            let origin_addr = read_addr(&bytes[5..11]);
            Ok(Message::LinkRequest {
                origin,
                origin_addr,
            })
        }
        KIND_ENDPOINT_UPDATE => {
            if bytes.len() < ENDPOINT_UPDATE_HEADER {
                return Err(ControlError::TooShort { len: bytes.len() });
            }
            let origin = node(&bytes[1..5]);
            let mut epoch_bytes = [0u8; 8];
            epoch_bytes.copy_from_slice(&bytes[5..13]);
            let epoch = u64::from_be_bytes(epoch_bytes);
            let count = bytes[13];
            if count > MAX_CANDIDATE_ENDPOINTS {
                return Err(ControlError::TooManyEndpoints(count));
            }
            let expected = ENDPOINT_UPDATE_HEADER + usize::from(count) * ENDPOINT_ADDR_LEN;
            if bytes.len() != expected {
                return Err(ControlError::BadLength { len: bytes.len() });
            }
            let mut addrs = Vec::with_capacity(usize::from(count));
            for i in 0..usize::from(count) {
                let start = ENDPOINT_UPDATE_HEADER + i * ENDPOINT_ADDR_LEN;
                addrs.push(read_addr(&bytes[start..start + ENDPOINT_ADDR_LEN]));
            }
            Ok(Message::EndpointUpdate {
                origin,
                epoch,
                addrs,
            })
        }
        KIND_PUNCH => {
            if bytes.len() < PUNCH_LEN {
                return Err(ControlError::TooShort { len: bytes.len() });
            }
            if bytes.len() > PUNCH_LEN {
                return Err(ControlError::BadLength { len: bytes.len() });
            }
            let origin = node(&bytes[1..5]);
            let mut token_bytes = [0u8; 8];
            token_bytes.copy_from_slice(&bytes[5..13]);
            let token = u64::from_be_bytes(token_bytes);
            Ok(Message::Punch { origin, token })
        }
        other => Err(ControlError::UnknownKind(other)),
    }
}

fn node(bytes: &[u8]) -> NodeId {
    NodeId(Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]))
}

fn put_addr(buf: &mut Vec<u8>, addr: SocketAddr) -> Result<(), ControlError> {
    match addr {
        SocketAddr::V4(v4) => {
            buf.extend_from_slice(&v4.ip().octets());
            buf.extend_from_slice(&v4.port().to_be_bytes());
            Ok(())
        }
        SocketAddr::V6(_) => Err(ControlError::UnsupportedAddress),
    }
}

fn read_addr(bytes: &[u8]) -> SocketAddr {
    let ip = Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]);
    let port = u16::from_be_bytes([bytes[4], bytes[5]]);
    SocketAddr::V4(SocketAddrV4::new(ip, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn node(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn sample_advert() -> LinkAdvert {
        LinkAdvert {
            origin: node("10.0.0.2"),
            origin_addr: addr(4002),
            seq: 42,
            from: node("10.0.0.2"),
            to: node("10.0.0.3"),
            metric: 7,
            state: LinkState::Up,
            ttl: 4,
        }
    }

    #[test]
    fn round_trips_an_advertisement() {
        let message = Message::LinkAdvert(sample_advert());
        let bytes = encode(&message).expect("encode");
        assert_eq!(bytes.len(), ADVERT_LEN);
        assert_eq!(decode(&bytes).expect("decode"), message);
    }

    #[test]
    fn round_trips_a_request() {
        let message = Message::LinkRequest {
            origin: node("10.0.0.5"),
            origin_addr: addr(5005),
        };
        let bytes = encode(&message).expect("encode");
        assert_eq!(bytes.len(), REQUEST_LEN);
        assert_eq!(decode(&bytes).expect("decode"), message);
    }

    #[test]
    fn rejects_short_and_oversized_messages() {
        assert_eq!(decode(&[]), Err(ControlError::TooShort { len: 0 }));
        assert_eq!(
            decode(&[KIND_LINK_ADVERT, 0, 0]),
            Err(ControlError::TooShort { len: 3 })
        );
        let oversized = vec![KIND_LINK_ADVERT; MAX_CONTROL_BYTES + 1];
        assert_eq!(
            decode(&oversized),
            Err(ControlError::Oversized {
                len: MAX_CONTROL_BYTES + 1
            })
        );
    }

    #[test]
    fn rejects_unknown_kind_and_bad_length() {
        assert_eq!(decode(&[99, 0]), Err(ControlError::UnknownKind(99)));

        let mut bytes = encode(&Message::LinkAdvert(sample_advert())).unwrap();
        bytes.push(0);
        assert_eq!(
            decode(&bytes),
            Err(ControlError::BadLength {
                len: ADVERT_LEN + 1
            })
        );
    }

    #[test]
    fn rejects_bad_state_byte() {
        let mut bytes = encode(&Message::LinkAdvert(sample_advert())).unwrap();
        bytes[23] = 9;
        assert_eq!(decode(&bytes), Err(ControlError::BadState(9)));
    }

    #[test]
    fn round_trips_an_endpoint_update() {
        let message = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 7,
            addrs: vec![addr(4102), addr(4103)],
        };
        let bytes = encode(&message).expect("encode");
        assert_eq!(bytes.len(), ENDPOINT_UPDATE_HEADER + 2 * ENDPOINT_ADDR_LEN);
        assert_eq!(decode(&bytes).expect("decode"), message);
    }

    #[test]
    fn round_trips_a_punch() {
        let message = Message::Punch {
            origin: node("10.0.0.2"),
            token: 0xdead_beef,
        };
        let bytes = encode(&message).expect("encode");
        assert_eq!(bytes.len(), PUNCH_LEN);
        assert_eq!(decode(&bytes).expect("decode"), message);
    }

    #[test]
    fn rejects_too_many_endpoints() {
        let addrs = vec![addr(1); usize::from(MAX_CANDIDATE_ENDPOINTS) + 1];
        let message = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs,
        };
        assert_eq!(
            encode(&message),
            Err(ControlError::TooManyEndpoints(MAX_CANDIDATE_ENDPOINTS + 1))
        );

        // a hand-built body claiming too many endpoints is refused on decode.
        let mut bytes = vec![KIND_ENDPOINT_UPDATE];
        bytes.extend_from_slice(&[10, 0, 0, 2]);
        bytes.extend_from_slice(&1u64.to_be_bytes());
        bytes.push(MAX_CANDIDATE_ENDPOINTS + 1);
        assert_eq!(
            decode(&bytes),
            Err(ControlError::TooManyEndpoints(MAX_CANDIDATE_ENDPOINTS + 1))
        );
    }

    #[test]
    fn rejects_a_miscounted_endpoint_update() {
        let message = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs: vec![addr(1)],
        };
        let mut bytes = encode(&message).unwrap();
        bytes.push(0);
        assert_eq!(
            decode(&bytes),
            Err(ControlError::BadLength {
                len: ENDPOINT_UPDATE_HEADER + ENDPOINT_ADDR_LEN + 1
            })
        );
    }

    #[test]
    fn rejects_ipv6_endpoints_on_encode() {
        let message = Message::LinkRequest {
            origin: node("10.0.0.5"),
            origin_addr: "[::1]:4000".parse().unwrap(),
        };
        assert_eq!(encode(&message), Err(ControlError::UnsupportedAddress));
    }
}
