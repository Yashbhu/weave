//! the forwarding decision for one ip packet.
//!
//! this is the pure part of the forwarding path: given a validated packet, the
//! node's own addresses, the routing table and the peer set, decide whether to
//! deliver it, forward it, or drop it. it does no i/o and no route calculation,
//! which keeps the policy small and easy to test.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};

use crate::packet;
use crate::peer::PeerSet;
use crate::route::RoutingTable;
use crate::topology::NodeId;

/// what to do with a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Decision {
    /// the destination is one of ours; write it to the tun interface.
    Deliver,
    /// send it to this peer.
    Forward {
        /// the next hop's udp endpoint as the routing table knew it.
        next_hop: SocketAddr,
        /// the next hop's logical identity, when the route carries one. the data
        /// plane uses this to resolve the current endpoint and any relay
        /// fallback; `None` means send straight to `next_hop`.
        next_hop_id: Option<NodeId>,
    },
    /// give up on it.
    Drop(DropReason),
}

/// why a packet was dropped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DropReason {
    /// the destination isn't ours and no route matches it.
    NoRoute,
    /// the ttl or hop limit ran out on the way here.
    HopLimitExpired,
    /// the next hop isn't a configured, usable peer.
    NextHopUnavailable,
    /// the next hop is the peer we got it from, which would loop straight back.
    WouldLoop,
    /// not an ipv4 or ipv6 packet we can route.
    NotRoutable,
}

impl DropReason {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            DropReason::NoRoute => "no route",
            DropReason::HopLimitExpired => "hop limit expired",
            DropReason::NextHopUnavailable => "next hop unavailable",
            DropReason::WouldLoop => "would route back to sender",
            DropReason::NotRoutable => "not routable",
        }
    }
}

/// decide what to do with `packet`.
///
/// `incoming_from` is the peer the packet arrived from, or `None` when it came
/// from the local tun interface. locally originated packets skip the hop-limit
/// and loop checks: a host may send with any ttl, and there is no sender to
/// loop back to.
pub fn decide(
    packet: &[u8],
    local: &[Ipv4Addr],
    routes: &RoutingTable,
    peers: &PeerSet,
    incoming_from: Option<SocketAddr>,
) -> Decision {
    let Some(IpAddr::V4(dest)) = packet::destination(packet) else {
        return Decision::Drop(DropReason::NotRoutable);
    };

    if local.contains(&dest) {
        return Decision::Deliver;
    }

    let Some(route) = routes.lookup(dest) else {
        return Decision::Drop(DropReason::NoRoute);
    };

    if let Some(from) = incoming_from {
        match packet::hop_limit(packet) {
            Some(limit) if limit > 1 => {}
            _ => return Decision::Drop(DropReason::HopLimitExpired),
        }
        if route.next_hop == from {
            return Decision::Drop(DropReason::WouldLoop);
        }
    }

    if !peers.is_available(route.next_hop) {
        return Decision::Drop(DropReason::NextHopUnavailable);
    }

    Decision::Forward {
        next_hop: route.next_hop,
        next_hop_id: route.next_hop_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::route::Route;

    fn hop(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    // a valid ipv4 packet with the given destination and ttl.
    fn packet(dst: &str, ttl: u8) -> Vec<u8> {
        let mut bytes = vec![0u8; 20];
        bytes[0] = 0x45;
        bytes[2..4].copy_from_slice(&20u16.to_be_bytes());
        bytes[8] = ttl;
        bytes[16..20].copy_from_slice(&ip(dst).octets());
        bytes
    }

    fn table(routes: Vec<Route>) -> RoutingTable {
        RoutingTable::new(routes)
    }

    #[test]
    fn delivers_packets_for_a_local_address() {
        let local = [ip("10.0.0.1")];
        let routes = table(vec![Route::host(ip("10.0.0.1"), hop(2))]);
        let peers = PeerSet::new([hop(2)]);
        assert_eq!(
            decide(&packet("10.0.0.1", 64), &local, &routes, &peers, None),
            Decision::Deliver
        );
    }

    #[test]
    fn forwards_to_the_next_hop_for_a_remote_address() {
        let routes = table(vec![Route::host(ip("10.0.0.3"), hop(3))]);
        let peers = PeerSet::new([hop(3)]);
        assert_eq!(
            decide(&packet("10.0.0.3", 64), &[], &routes, &peers, Some(hop(2))),
            Decision::Forward {
                next_hop: hop(3),
                next_hop_id: None
            }
        );
    }

    #[test]
    fn drops_when_no_route_matches() {
        let peers = PeerSet::new([hop(3)]);
        assert_eq!(
            decide(&packet("10.0.0.9", 64), &[], &table(vec![]), &peers, None),
            Decision::Drop(DropReason::NoRoute)
        );
    }

    #[test]
    fn drops_when_the_next_hop_is_unavailable() {
        let routes = table(vec![Route::host(ip("10.0.0.3"), hop(3))]);
        let peers = PeerSet::new([hop(3)]);
        peers.set_available(hop(3), false);
        assert_eq!(
            decide(&packet("10.0.0.3", 64), &[], &routes, &peers, None),
            Decision::Drop(DropReason::NextHopUnavailable)
        );
    }

    #[test]
    fn drops_transit_packets_with_an_expired_hop_limit() {
        let routes = table(vec![Route::host(ip("10.0.0.3"), hop(3))]);
        let peers = PeerSet::new([hop(3)]);
        assert_eq!(
            decide(&packet("10.0.0.3", 1), &[], &routes, &peers, Some(hop(2))),
            Decision::Drop(DropReason::HopLimitExpired)
        );
    }

    #[test]
    fn drops_a_packet_that_would_loop_back_to_the_sender() {
        // the route for 10.0.0.3 points back at the peer that just sent it.
        let routes = table(vec![Route::host(ip("10.0.0.3"), hop(2))]);
        let peers = PeerSet::new([hop(2)]);
        assert_eq!(
            decide(&packet("10.0.0.3", 64), &[], &routes, &peers, Some(hop(2))),
            Decision::Drop(DropReason::WouldLoop)
        );
    }

    #[test]
    fn ignores_the_loop_check_for_local_origin() {
        let routes = table(vec![Route::host(ip("10.0.0.3"), hop(2))]);
        let peers = PeerSet::new([hop(2)]);
        assert_eq!(
            decide(&packet("10.0.0.3", 1), &[], &routes, &peers, None),
            Decision::Forward {
                next_hop: hop(2),
                next_hop_id: None
            },
            "a local packet with ttl 1 can still be sent"
        );
    }

    #[test]
    fn drops_packets_that_are_not_ipv4() {
        let peers = PeerSet::new([]);
        assert_eq!(
            decide(&[0x60, 0, 0, 0], &[], &table(vec![]), &peers, None),
            Decision::Drop(DropReason::NotRoutable)
        );
    }
}
