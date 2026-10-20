//! choosing between a direct path and a relay for each peer.
//!
//! this sits above `endpoints.rs`: endpoints.rs says *which* address a peer is
//! reachable at, connectivity says *how* we send to it right now - straight to
//! the peer, or wrapped through a relay because the direct path is not working.
//!
//! the selection is deliberately conservative. switching on a single lost
//! packet would flap, so a direct path has to prove itself a few times before we
//! trust it, and it takes several consecutive direct failures before we give up
//! and use the relay. that keeps transient packet loss from moving traffic.
//!
//! this is kept separate from route calculation: the routing table still points
//! at a next-hop identity, and this module resolves that identity to a concrete
//! `Link` at send time.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, RwLock};
use std::time::Instant;

use crate::topology::NodeId;

/// how many times a path must succeed or fail before we switch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConnectivityConfig {
    /// consecutive direct successes needed to move from relay to direct.
    pub switch_to_direct_after: u32,
    /// consecutive direct failures needed to give up on direct.
    pub switch_to_relay_after: u32,
}

impl Default for ConnectivityConfig {
    fn default() -> Self {
        Self {
            switch_to_direct_after: 2,
            switch_to_relay_after: 3,
        }
    }
}

/// the path currently in use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Mode {
    /// sending straight to the peer's proven endpoint.
    Direct,
    /// sending through a relay on the peer's behalf.
    Relay,
    /// no path works right now.
    Unavailable,
}

impl Mode {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Direct => "direct",
            Mode::Relay => "relay",
            Mode::Unavailable => "unavailable",
        }
    }
}

/// where to actually send a packet for a peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Link {
    /// send straight to this endpoint.
    Direct(SocketAddr),
    /// wrap in a relay envelope and send to this relay endpoint.
    Relay(SocketAddr),
}

impl Link {
    /// the udp endpoint the datagram goes to.
    pub fn addr(self) -> SocketAddr {
        match self {
            Link::Direct(addr) | Link::Relay(addr) => addr,
        }
    }

    /// the mode this link corresponds to.
    pub fn mode(self) -> Mode {
        match self {
            Link::Direct(_) => Mode::Direct,
            Link::Relay(_) => Mode::Relay,
        }
    }
}

#[derive(Debug)]
struct PeerConnectivity {
    mode: Mode,
    direct: Option<SocketAddr>,
    relay: Option<SocketAddr>,
    direct_ok: u32,
    direct_fail: u32,
    updated_at: Instant,
}

/// per-peer path selection.
#[derive(Debug)]
pub struct Connectivity {
    peers: HashMap<NodeId, PeerConnectivity>,
    config: ConnectivityConfig,
}

impl Connectivity {
    /// a new, empty selection table.
    pub fn new(config: ConnectivityConfig) -> Self {
        Self {
            peers: HashMap::new(),
            config,
        }
    }

    /// register a peer, optionally with a configured relay. without a relay the
    /// peer is `Unavailable` until a direct path is proven.
    pub fn register(&mut self, id: NodeId, relay: Option<SocketAddr>, now: Instant) {
        self.peers.insert(
            id,
            PeerConnectivity {
                mode: if relay.is_some() {
                    Mode::Relay
                } else {
                    Mode::Unavailable
                },
                direct: None,
                relay,
                direct_ok: 0,
                direct_fail: 0,
                updated_at: now,
            },
        );
    }

    /// set or clear a peer's relay without touching its direct state.
    pub fn set_relay(&mut self, id: NodeId, relay: Option<SocketAddr>, now: Instant) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.relay = relay;
        peer.updated_at = now;
        if relay.is_none() && peer.mode == Mode::Relay {
            // losing the relay drops us to whatever direct path we have.
            peer.mode = if peer.direct.is_some() {
                Mode::Direct
            } else {
                Mode::Unavailable
            };
        }
    }

    /// record a successful direct exchange with `addr`.
    pub fn on_direct_success(&mut self, id: NodeId, addr: SocketAddr, now: Instant) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.direct = Some(addr);
        peer.direct_fail = 0;
        peer.updated_at = now;
        match peer.mode {
            Mode::Direct => {}
            Mode::Relay | Mode::Unavailable => {
                peer.direct_ok += 1;
                // without a relay there is nothing to fall back to, so a single
                // success is enough to use the direct path.
                let needed = if peer.relay.is_some() {
                    self.config.switch_to_direct_after
                } else {
                    1
                };
                if peer.direct_ok >= needed {
                    peer.mode = Mode::Direct;
                    peer.direct_ok = 0;
                }
            }
        }
    }

    /// record a failed direct exchange.
    pub fn on_direct_failure(&mut self, id: NodeId, now: Instant) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.direct_ok = 0;
        peer.updated_at = now;
        if peer.mode != Mode::Direct {
            return;
        }
        peer.direct_fail += 1;
        if peer.direct_fail >= self.config.switch_to_relay_after {
            peer.direct = None;
            peer.direct_fail = 0;
            peer.mode = if peer.relay.is_some() {
                Mode::Relay
            } else {
                Mode::Unavailable
            };
        }
    }

    /// the endpoint we believed in changed. the old direct path is invalid, so
    /// it must be proven again before we trust it.
    pub fn on_endpoint_change(&mut self, id: NodeId, now: Instant) {
        let Some(peer) = self.peers.get_mut(&id) else {
            return;
        };
        peer.direct = None;
        peer.direct_ok = 0;
        peer.direct_fail = 0;
        peer.updated_at = now;
        peer.mode = if peer.relay.is_some() {
            Mode::Relay
        } else {
            Mode::Unavailable
        };
    }

    /// where to send for `id` right now, if anywhere.
    pub fn current(&self, id: NodeId) -> Option<Link> {
        let peer = self.peers.get(&id)?;
        match peer.mode {
            Mode::Direct => peer.direct.map(Link::Direct),
            Mode::Relay => peer.relay.map(Link::Relay),
            Mode::Unavailable => None,
        }
    }

    /// the current mode for `id`.
    pub fn mode(&self, id: NodeId) -> Option<Mode> {
        self.peers.get(&id).map(|peer| peer.mode)
    }

    /// number of peers tracked.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// true when no peers are tracked.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }
}

/// a peer identity mapped to where traffic for it should go.
pub type LinkMap = HashMap<NodeId, Link>;

/// a shared, swappable view of the current link table.
///
/// this mirrors `RouteSnapshot`: the control plane publishes a whole new
/// immutable map in one swap and the data plane reads a consistent snapshot, so
/// endpoint migration can never be observed half-applied.
#[derive(Debug, Clone, Default)]
pub struct LinkSnapshot {
    inner: Arc<RwLock<Arc<LinkMap>>>,
}

impl LinkSnapshot {
    /// an empty link table.
    pub fn new() -> Self {
        Self {
            inner: Arc::new(RwLock::new(Arc::new(LinkMap::new()))),
        }
    }

    /// the current map, as an immutable snapshot.
    pub fn current(&self) -> Arc<LinkMap> {
        self.inner
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    /// where to send for `id` right now, if anywhere.
    pub fn get(&self, id: NodeId) -> Option<Link> {
        self.current().get(&id).copied()
    }

    /// replace the current map.
    pub fn publish(&self, map: LinkMap) {
        let mut guard = self
            .inner
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *guard = Arc::new(map);
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

    #[test]
    fn prefers_a_validated_direct_path() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, Some(addr(9999)), now);
        assert_eq!(c.current(id), Some(Link::Relay(addr(9999))));

        // two direct successes are needed before we trust direct.
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.current(id), Some(Link::Relay(addr(9999))));
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(4002))));
    }

    #[test]
    fn falls_back_to_the_relay_after_repeated_failures() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, Some(addr(9999)), now);
        c.on_direct_success(id, addr(4002), now);
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(4002))));

        // one or two failures are not enough to move.
        c.on_direct_failure(id, now);
        c.on_direct_failure(id, now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(4002))));

        // the third consecutive failure falls back to the relay.
        c.on_direct_failure(id, now);
        assert_eq!(c.current(id), Some(Link::Relay(addr(9999))));
        assert_eq!(c.mode(id), Some(Mode::Relay));
    }

    #[test]
    fn without_a_relay_failure_means_unavailable() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, None, now);
        assert_eq!(c.current(id), None);

        // a single success suffices when there is no relay to prefer.
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(4002))));

        for _ in 0..3 {
            c.on_direct_failure(id, now);
        }
        assert_eq!(c.current(id), None);
        assert_eq!(c.mode(id), Some(Mode::Unavailable));
    }

    #[test]
    fn transient_loss_and_a_single_recovery_do_not_flap() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, Some(addr(9999)), now);
        c.on_direct_success(id, addr(4002), now);
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.mode(id), Some(Mode::Direct));

        // drop to relay.
        for _ in 0..3 {
            c.on_direct_failure(id, now);
        }
        assert_eq!(c.mode(id), Some(Mode::Relay));

        // a single success does not immediately pull us back.
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.mode(id), Some(Mode::Relay), "single success flapped back");
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.mode(id), Some(Mode::Direct));
    }

    #[test]
    fn an_endpoint_change_revalidates_direct() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, Some(addr(9999)), now);
        c.on_direct_success(id, addr(4002), now);
        c.on_direct_success(id, addr(4002), now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(4002))));

        // the peer moved: the proven direct path is void until replotted.
        c.on_endpoint_change(id, now);
        assert_eq!(
            c.current(id),
            Some(Link::Relay(addr(9999))),
            "old direct endpoint must not be used after a move"
        );

        c.on_direct_success(id, addr(5002), now);
        assert_eq!(c.current(id), Some(Link::Relay(addr(9999))));
        c.on_direct_success(id, addr(5002), now);
        assert_eq!(c.current(id), Some(Link::Direct(addr(5002))));
    }

    #[test]
    fn losing_the_relay_with_no_proven_direct_is_unavailable() {
        let now = Instant::now();
        let id = node("10.0.0.2");
        let mut c = Connectivity::new(ConnectivityConfig::default());
        c.register(id, Some(addr(9999)), now);
        c.on_direct_success(id, addr(4002), now);
        c.on_direct_success(id, addr(4002), now);

        // force relay, then clear it.
        for _ in 0..3 {
            c.on_direct_failure(id, now);
        }
        assert_eq!(c.mode(id), Some(Mode::Relay));
        c.set_relay(id, None, now);
        assert_eq!(c.mode(id), Some(Mode::Unavailable), "no direct path proven");
    }

    #[test]
    fn link_snapshot_swaps_atomically() {
        let snapshot = LinkSnapshot::new();
        assert_eq!(snapshot.get(node("10.0.0.2")), None);

        let mut map = LinkMap::new();
        map.insert(node("10.0.0.2"), Link::Direct(addr(4002)));
        snapshot.publish(map);
        assert_eq!(
            snapshot.get(node("10.0.0.2")),
            Some(Link::Direct(addr(4002)))
        );

        let mut map = LinkMap::new();
        map.insert(node("10.0.0.2"), Link::Relay(addr(9999)));
        snapshot.publish(map);
        assert_eq!(
            snapshot.get(node("10.0.0.2")),
            Some(Link::Relay(addr(9999)))
        );
    }
}
