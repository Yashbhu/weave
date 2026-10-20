//! the mapping from a peer's stable identity to its current udp endpoint.
//!
//! m1-m5 keyed almost everything by `SocketAddr`: `PeerSet`, `Route.next_hop`
//! and the `Topology` endpoint map all used the udp address as if it were the
//! peer. that is fine while endpoints never move, but m6 is about endpoints that
//! *do* move, so identity and endpoint are split apart here.
//!
//! a peer is a `NodeId` (its overlay ipv4 address) and keeps:
//!
//! - an `epoch`: the newest endpoint-update revision the peer announced. an
//!   update with an epoch we have already seen is stale and ignored, so a
//!   delayed packet cannot roll an endpoint back.
//! - `candidates`: endpoints the peer announced but we have not proven yet.
//! - `active`: the one endpoint we have actually received an authenticated
//!   message from. only this is used for sending.
//!
//! announcing a candidate does **not** make it active. it has to survive a
//! round trip first (`confirm`), which is how hole punching proves reachability.
//! the caller is responsible for authenticating the message before calling any
//! of this; see `noise.rs` and `router.rs`.
//!
//! time is passed in, so the whole registry is deterministic and sleep-free.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::{Duration, Instant};

use crate::topology::NodeId;

/// hard caps so a peer cannot make us store unbounded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EndpointLimits {
    /// most peers whose endpoints we will track.
    pub max_peers: usize,
    /// most candidate endpoints we keep per peer.
    pub max_candidates: usize,
}

impl Default for EndpointLimits {
    fn default() -> Self {
        Self {
            max_peers: 1024,
            max_candidates: 4,
        }
    }
}

/// what happened when an endpoint update was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointApply {
    /// the update was newer and the candidates were replaced.
    Updated,
    /// the update was older than or equal to what we have; ignored.
    Stale,
    /// the update was rejected.
    Rejected(EndpointReject),
}

/// why an endpoint update was rejected.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EndpointReject {
    /// the update named no endpoints.
    NoCandidates,
    /// we are already tracking the maximum number of peers.
    LimitReached,
}

impl EndpointReject {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            EndpointReject::NoCandidates => "no candidate endpoints",
            EndpointReject::LimitReached => "endpoint peer limit reached",
        }
    }
}

/// a snapshot of one peer's endpoint state.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointView {
    /// the epoch of the newest announcement we applied.
    pub epoch: u64,
    /// the proven endpoint, if any.
    pub active: Option<SocketAddr>,
    /// announced, unproven endpoints.
    pub candidates: Vec<SocketAddr>,
}

#[derive(Debug, Clone)]
struct PeerEndpoints {
    epoch: u64,
    active: Option<SocketAddr>,
    active_at: Instant,
    candidates: Vec<SocketAddr>,
    seen_at: Instant,
}

/// the endpoints of every peer we currently know.
#[derive(Debug)]
pub struct EndpointRegistry {
    peers: HashMap<NodeId, PeerEndpoints>,
    limits: EndpointLimits,
}

impl Default for EndpointRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl EndpointRegistry {
    /// an empty registry with default limits.
    pub fn new() -> Self {
        Self::with_limits(EndpointLimits::default())
    }

    /// an empty registry with explicit limits.
    pub fn with_limits(limits: EndpointLimits) -> Self {
        Self {
            peers: HashMap::new(),
            limits,
        }
    }

    /// apply an announced endpoint update from `id`.
    ///
    /// the caller must already have authenticated the message that carried it.
    /// a newer epoch replaces the candidate set; announcing candidates never
    /// changes the active endpoint, so a peer cannot redirect traffic to an
    /// address it has not proven it can reach.
    pub fn declare(
        &mut self,
        id: NodeId,
        epoch: u64,
        addrs: &[SocketAddr],
        now: Instant,
    ) -> EndpointApply {
        if addrs.is_empty() {
            return EndpointApply::Rejected(EndpointReject::NoCandidates);
        }
        // the unspecified address is not a real endpoint to punch or send to, so
        // it is filtered out; if nothing usable is left the update is refused.
        let candidates = bounded_candidates(addrs, self.limits.max_candidates);
        if candidates.is_empty() {
            return EndpointApply::Rejected(EndpointReject::NoCandidates);
        }

        if let Some(peer) = self.peers.get_mut(&id) {
            if epoch <= peer.epoch {
                return EndpointApply::Stale;
            }
            peer.epoch = epoch;
            peer.candidates = candidates;
            // if the proven endpoint is no longer announced, it must be
            // re-proven before we keep sending there.
            if let Some(active) = peer.active {
                if !peer.candidates.contains(&active) {
                    peer.active = None;
                }
            }
            peer.seen_at = now;
            return EndpointApply::Updated;
        }

        if self.peers.len() >= self.limits.max_peers {
            return EndpointApply::Rejected(EndpointReject::LimitReached);
        }

        self.peers.insert(
            id,
            PeerEndpoints {
                epoch,
                active: None,
                active_at: now,
                candidates,
                seen_at: now,
            },
        );
        EndpointApply::Updated
    }

    /// record an authenticated message received from `addr`. this is the only
    /// way an endpoint becomes active, so it has to be an address we really got
    /// traffic from. returns whether the active endpoint changed.
    pub fn confirm(&mut self, id: NodeId, addr: SocketAddr, now: Instant) -> bool {
        let Some(peer) = self.peers.get_mut(&id) else {
            return false;
        };
        peer.seen_at = now;
        if peer.active == Some(addr) {
            peer.active_at = now;
            return false;
        }
        peer.active = Some(addr);
        peer.active_at = now;
        true
    }

    /// note that we heard from `id` without changing its endpoint.
    pub fn touch(&mut self, id: NodeId, now: Instant) {
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.seen_at = now;
        }
    }

    /// the proven endpoint for `id`, if there is one.
    pub fn endpoint_of(&self, id: NodeId) -> Option<SocketAddr> {
        self.peers.get(&id).and_then(|peer| peer.active)
    }

    /// the announced, unproven endpoints for `id`.
    pub fn candidates(&self, id: NodeId) -> &[SocketAddr] {
        self.peers
            .get(&id)
            .map(|peer| peer.candidates.as_slice())
            .unwrap_or(&[])
    }

    /// a snapshot of `id`'s endpoint state.
    pub fn view(&self, id: NodeId) -> Option<EndpointView> {
        self.peers.get(&id).map(|peer| EndpointView {
            epoch: peer.epoch,
            active: peer.active,
            candidates: peer.candidates.clone(),
        })
    }

    /// drop endpoints and peers we have not heard from within `ttl`.
    ///
    /// a proven endpoint older than `ttl` is cleared but the peer (and its
    /// epoch) is kept until the peer itself ages out, so its sequence number
    /// still blocks older updates. returns the number of peers changed.
    pub fn expire(&mut self, now: Instant, ttl: Duration) -> usize {
        let mut changed = 0;
        self.peers.retain(|_, peer| {
            if now.saturating_duration_since(peer.seen_at) >= ttl {
                changed += 1;
                return false;
            }
            if peer.active.is_some() && now.saturating_duration_since(peer.active_at) >= ttl {
                peer.active = None;
                changed += 1;
            }
            true
        });
        changed
    }

    /// number of peers tracked.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// true when no peers are tracked.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// every peer we track.
    pub fn peers(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.peers.keys().copied()
    }
}

/// deduplicate and cap a candidate list, preserving announcement order.
/// the unspecified address is skipped: it is never a usable endpoint.
fn bounded_candidates(addrs: &[SocketAddr], max: usize) -> Vec<SocketAddr> {
    let mut out: Vec<SocketAddr> = Vec::with_capacity(addrs.len().min(max));
    for addr in addrs {
        if out.len() >= max {
            break;
        }
        if addr.ip().is_unspecified() {
            continue;
        }
        if !out.contains(addr) {
            out.push(*addr);
        }
    }
    out
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
    fn identity_is_stable_when_the_endpoint_changes() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");

        reg.declare(id, 1, &[addr(4002)], now);
        assert!(reg.confirm(id, addr(4002), now));
        assert_eq!(reg.endpoint_of(id), Some(addr(4002)));

        // the peer moved to a new address and announced it.
        reg.declare(id, 2, &[addr(5002)], now);
        assert!(reg.confirm(id, addr(5002), now));

        assert_eq!(reg.endpoint_of(id), Some(addr(5002)), "endpoint moved");
        assert_eq!(reg.len(), 1, "still one peer, same identity");
        assert_eq!(reg.view(id).unwrap().epoch, 2);
    }

    #[test]
    fn declaring_candidates_does_not_change_the_active_endpoint() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");

        reg.declare(id, 1, &[addr(4002)], now);
        reg.confirm(id, addr(4002), now);
        // a new announcement must not redirect traffic until it is proven.
        reg.declare(id, 2, &[addr(6002)], now);
        assert_eq!(
            reg.endpoint_of(id),
            None,
            "an unproven endpoint must not become active"
        );
        assert_eq!(reg.candidates(id), &[addr(6002)]);

        assert!(reg.confirm(id, addr(6002), now));
        assert_eq!(reg.endpoint_of(id), Some(addr(6002)));
    }

    #[test]
    fn stale_updates_are_rejected() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");

        reg.declare(id, 5, &[addr(5002)], now);
        reg.confirm(id, addr(5002), now);

        // a delayed duplicate of an older epoch must not roll it back.
        assert_eq!(reg.declare(id, 4, &[addr(4002)], now), EndpointApply::Stale);
        assert_eq!(reg.declare(id, 5, &[addr(4002)], now), EndpointApply::Stale);
        assert_eq!(reg.endpoint_of(id), Some(addr(5002)));
        assert_eq!(reg.candidates(id), &[addr(5002)]);
    }

    #[test]
    fn endpoints_expire() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");
        let ttl = Duration::from_secs(3);

        reg.declare(id, 1, &[addr(4002)], now);
        reg.confirm(id, addr(4002), now);
        assert_eq!(reg.endpoint_of(id), Some(addr(4002)));

        // keep hearing from the peer, but never again from its endpoint.
        let half = now + ttl / 2;
        reg.touch(id, half);

        // after ttl with no traffic the proven endpoint is cleared...
        let later = now + ttl;
        assert_eq!(reg.expire(later, ttl), 1);
        assert_eq!(reg.endpoint_of(id), None);
        // ...but the peer and its epoch survive until it ages out entirely.
        assert_eq!(reg.len(), 1);
        assert_eq!(reg.view(id).unwrap().epoch, 1);

        // eventually the peer itself is dropped, freeing the slot.
        let much_later = half + ttl;
        assert_eq!(reg.expire(much_later, ttl), 1);
        assert!(reg.is_empty());
    }

    #[test]
    fn stale_epoch_still_blocks_after_expiry() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");
        let ttl = Duration::from_secs(3);

        reg.declare(id, 9, &[addr(4002)], now);
        // the peer stays alive, but its endpoint was never proven.
        reg.touch(id, now + ttl / 2);
        reg.expire(now + ttl, ttl);
        assert_eq!(reg.endpoint_of(id), None);
        // the newer epoch is still remembered, so an old one cannot return.
        assert_eq!(reg.declare(id, 3, &[addr(1002)], now), EndpointApply::Stale);
    }

    #[test]
    fn repeated_updates_do_not_grow_state() {
        let mut reg = EndpointRegistry::with_limits(EndpointLimits {
            max_peers: 4,
            max_candidates: 2,
        });
        let now = Instant::now();
        let id = node("10.0.0.2");

        for epoch in 1..=100 {
            let addrs = [
                addr(1000 + epoch as u16),
                addr(2000 + epoch as u16),
                addr(3000),
            ];
            assert_eq!(reg.declare(id, epoch, &addrs, now), EndpointApply::Updated);
            reg.confirm(id, addr(1000 + epoch as u16), now);
        }

        assert_eq!(reg.len(), 1, "one peer");
        assert!(
            reg.candidates(id).len() <= 2,
            "candidate list must stay bounded"
        );
    }

    #[test]
    fn unknown_peers_are_bounded() {
        let mut reg = EndpointRegistry::with_limits(EndpointLimits {
            max_peers: 2,
            max_candidates: 1,
        });
        let now = Instant::now();
        assert_eq!(
            reg.declare(node("10.0.0.1"), 1, &[addr(1)], now),
            EndpointApply::Updated
        );
        assert_eq!(
            reg.declare(node("10.0.0.2"), 1, &[addr(2)], now),
            EndpointApply::Updated
        );
        assert_eq!(
            reg.declare(node("10.0.0.3"), 1, &[addr(3)], now),
            EndpointApply::Rejected(EndpointReject::LimitReached)
        );
        // confirming an unknown peer is a no-op, so it cannot create state.
        assert!(!reg.confirm(node("10.0.0.9"), addr(9), now));
        assert_eq!(reg.len(), 2);
    }

    #[test]
    fn empty_updates_are_rejected() {
        let mut reg = EndpointRegistry::new();
        assert_eq!(
            reg.declare(node("10.0.0.2"), 1, &[], Instant::now()),
            EndpointApply::Rejected(EndpointReject::NoCandidates)
        );
        assert!(reg.is_empty());
    }

    #[test]
    fn deduplicates_candidates() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let id = node("10.0.0.2");
        reg.declare(id, 1, &[addr(1), addr(1), addr(2)], now);
        assert_eq!(reg.candidates(id), &[addr(1), addr(2)]);
    }

    #[test]
    fn unspecified_candidates_are_filtered_and_rejected() {
        let mut reg = EndpointRegistry::new();
        let now = Instant::now();
        let unspecified: SocketAddr = "0.0.0.0:9".parse().unwrap();

        // nothing usable is left, so the update is refused and creates no state.
        assert_eq!(
            reg.declare(node("10.0.0.2"), 1, &[unspecified], now),
            EndpointApply::Rejected(EndpointReject::NoCandidates)
        );
        assert!(reg.is_empty());

        // a usable endpoint alongside the unspecified one is kept.
        reg.declare(node("10.0.0.2"), 2, &[unspecified, addr(4002)], now);
        assert_eq!(reg.candidates(node("10.0.0.2")), &[addr(4002)]);
    }
}
