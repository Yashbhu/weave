//! the overlay topology: a directed graph of nodes and links.
//!
//! topology is kept separate from the forwarding table. this module only
//! describes the network and can derive routes from it; `route.rs` holds the
//! resulting forwarding table and `forward.rs` uses that. nothing here does i/o
//! and time is always passed in, so the whole model is deterministic and easy to
//! test.
//!
//! a node's stable identity is its overlay IPv4 address (`NodeId`). each node
//! originates a directed link advertisement for every link leaving it. only the
//! tail node of a link may originate it, which stops an unrelated node from
//! claiming arbitrary links, but there is no cryptographic authentication: see
//! the module docs in `router.rs` for what that does and does not buy us.

use std::collections::{BinaryHeap, HashMap, HashSet};
use std::fmt;
use std::net::{Ipv4Addr, SocketAddr};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use crate::route::Route;

/// a node's stable identity: its overlay IPv4 address.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId(pub Ipv4Addr);

impl fmt::Display for NodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// whether a link can currently carry traffic.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LinkState {
    /// the link is usable.
    Up,
    /// the link is down (failed or expired) and must not be used.
    Down,
}

impl LinkState {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            LinkState::Up => "up",
            LinkState::Down => "down",
        }
    }

    /// is the link usable?
    pub fn is_up(self) -> bool {
        matches!(self, LinkState::Up)
    }
}

/// one directed link, originated by the node at its tail (`from`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinkAdvert {
    /// the node that originated this advertisement.
    pub origin: NodeId,
    /// the origin's udp endpoint, so every node can learn how to reach it.
    pub origin_addr: SocketAddr,
    /// the origin's sequence number for this link; higher is newer.
    pub seq: u64,
    /// tail of the link (equals `origin`).
    pub from: NodeId,
    /// head of the link.
    pub to: NodeId,
    /// path cost of the link; lower is better.
    pub metric: u32,
    /// current state.
    pub state: LinkState,
    /// remaining flood hops. 0 means do not re-flood.
    pub ttl: u8,
}

impl LinkAdvert {
    /// a re-flooded copy with one fewer hop, or `None` when the ttl is spent.
    pub fn decremented(&self) -> Option<LinkAdvert> {
        if self.ttl == 0 {
            return None;
        }
        let mut next = self.clone();
        next.ttl -= 1;
        Some(next)
    }
}

/// a learned link plus when we last heard it.
#[derive(Debug, Clone)]
struct Link {
    advert: LinkAdvert,
    received_at: Instant,
    fresh: bool,
}

/// the sequence decision for an advertisement against existing state.
enum LinkApply {
    Stale,
    Refreshed,
    New,
}

/// what happened when an advertisement was applied.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Applied {
    /// accepted as new information; the caller should re-flood it.
    New,
    /// already seen at this sequence number; the freshness timer was bumped but
    /// nothing changed, so it must not be re-flooded.
    Refreshed,
    /// older than what we already have; rejected so it cannot overwrite newer
    /// state.
    Stale,
    /// not a valid advertisement; rejected.
    Invalid(RejectReason),
}

impl Applied {
    /// whether the usable graph may have changed and routes should be recomputed.
    pub fn is_change(self) -> bool {
        matches!(self, Applied::New)
    }
}

/// why an advertisement was rejected outright.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectReason {
    /// the advertisement names our own node as origin (a flood loop).
    SelfOriginated,
    /// `origin` is not the tail of the link, so it is not allowed to describe it.
    OriginMismatch,
    /// the metric is zero, which would create a free loop.
    ZeroMetric,
    /// a node identity that is not a valid overlay address.
    UnspecifiedNode,
    /// the topology is already at its node or link limit.
    LimitReached,
}

impl RejectReason {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            RejectReason::SelfOriginated => "self-originated",
            RejectReason::OriginMismatch => "origin does not own the link",
            RejectReason::ZeroMetric => "zero metric",
            RejectReason::UnspecifiedNode => "unspecified node",
            RejectReason::LimitReached => "topology limit reached",
        }
    }
}

/// a snapshot of one link for observability.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct LinkView {
    /// tail node.
    pub from: NodeId,
    /// head node.
    pub to: NodeId,
    /// link cost.
    pub metric: u32,
    /// the state the origin most recently advertised.
    pub advertised: LinkState,
    /// the state to use for routing, after freshness is applied.
    pub effective: LinkState,
    /// whether the link has been refreshed within its max age.
    pub fresh: bool,
    /// the origin's sequence number.
    pub seq: u64,
}

/// hard caps so a peer cannot make us store unbounded state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
    /// most nodes we will track, including ourselves.
    pub max_nodes: usize,
    /// most links we will track, including our own.
    pub max_links: usize,
}

impl Default for Limits {
    fn default() -> Self {
        Self {
            max_nodes: 1024,
            max_links: 8192,
        }
    }
}

/// a local (self-originated) link.
#[derive(Debug, Clone)]
struct LocalLink {
    metric: u32,
    state: LinkState,
    seq: u64,
}

/// the topology a node believes in.
#[derive(Debug)]
pub struct Topology {
    local: NodeId,
    local_addr: SocketAddr,
    nodes: HashSet<NodeId>,
    endpoints: HashMap<NodeId, SocketAddr>,
    local_links: HashMap<NodeId, LocalLink>,
    remote_links: HashMap<(NodeId, NodeId), Link>,
    limits: Limits,
    version: u64,
    seq: u64,
}

impl Topology {
    /// a fresh topology containing only ourselves.
    pub fn new(local: NodeId, local_addr: SocketAddr) -> Self {
        let mut nodes = HashSet::new();
        nodes.insert(local);
        let mut endpoints = HashMap::new();
        endpoints.insert(local, local_addr);
        Self {
            local,
            local_addr,
            nodes,
            endpoints,
            local_links: HashMap::new(),
            remote_links: HashMap::new(),
            limits: Limits::default(),
            version: 0,
            // base the sequence on wall-clock milliseconds so a restarted node
            // originates numbers above the ones its peers last saw.
            seq: unix_millis(),
        }
    }

    /// the same topology with custom resource limits.
    pub fn with_limits(mut self, limits: Limits) -> Self {
        self.limits = limits;
        self
    }

    /// this node's identity.
    pub fn local(&self) -> NodeId {
        self.local
    }

    /// this node's udp endpoint.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// a counter bumped whenever the usable graph changes.
    pub fn version(&self) -> u64 {
        self.version
    }

    /// number of nodes we know about.
    pub fn node_count(&self) -> usize {
        self.nodes.len()
    }

    /// number of links (local + learned).
    pub fn link_count(&self) -> usize {
        self.local_links.len() + self.remote_links.len()
    }

    /// the udp endpoint we have for a node, if any.
    pub fn endpoint_of(&self, node: NodeId) -> Option<SocketAddr> {
        self.endpoints.get(&node).copied()
    }

    /// register a direct neighbour and its endpoint as an up link.
    pub fn add_neighbor(&mut self, to: NodeId, addr: SocketAddr, metric: u32) {
        let metric = metric.max(1);
        self.nodes.insert(to);
        self.endpoints.insert(to, addr);
        if let Some(existing) = self.local_links.get_mut(&to) {
            if existing.metric != metric {
                existing.metric = metric;
                self.seq += 1;
                existing.seq = self.seq;
                self.bump_version();
            }
            return;
        }
        self.seq += 1;
        self.local_links.insert(
            to,
            LocalLink {
                metric,
                state: LinkState::Up,
                seq: self.seq,
            },
        );
        self.bump_version();
    }

    /// update a local link's state, bumping its sequence when it changes.
    pub fn set_local_state(&mut self, to: NodeId, state: LinkState) -> bool {
        let Some(link) = self.local_links.get_mut(&to) else {
            return false;
        };
        if link.state == state {
            return false;
        }
        link.state = state;
        self.seq += 1;
        link.seq = self.seq;
        self.bump_version();
        true
    }

    /// the current state of a local link, if it exists.
    pub fn local_state(&self, to: NodeId) -> Option<LinkState> {
        self.local_links.get(&to).map(|link| link.state)
    }

    /// every local neighbour identity.
    pub fn local_neighbors(&self) -> impl Iterator<Item = NodeId> + '_ {
        self.local_links.keys().copied()
    }

    /// originate a fresh advertisement for one local link, bumping its sequence.
    ///
    /// every originated advertisement gets a new sequence number, so a receiver
    /// can tell a live heartbeat apart from a delayed duplicate: only a strictly
    /// newer sequence refreshes a link.
    pub fn local_advert(&mut self, to: NodeId, ttl: u8) -> Option<LinkAdvert> {
        self.seq += 1;
        let seq = self.seq;
        let local = self.local;
        let local_addr = self.local_addr;
        let link = self.local_links.get_mut(&to)?;
        link.seq = seq;
        Some(LinkAdvert {
            origin: local,
            origin_addr: local_addr,
            seq,
            from: local,
            to,
            metric: link.metric,
            state: link.state,
            ttl,
        })
    }

    /// originate fresh advertisements for every local link, bumping sequences.
    pub fn local_adverts(&mut self, ttl: u8) -> Vec<LinkAdvert> {
        let targets: Vec<NodeId> = self.local_links.keys().copied().collect();
        targets
            .into_iter()
            .filter_map(|to| self.local_advert(to, ttl))
            .collect()
    }

    /// apply a received advertisement.
    ///
    /// validation happens here: the origin must own the link's tail, metrics and
    /// identities must be sane, and stale sequence numbers are rejected so a
    /// delayed message cannot overwrite newer state.
    pub fn apply(&mut self, advert: &LinkAdvert, now: Instant) -> Applied {
        if advert.origin == self.local {
            return Applied::Invalid(RejectReason::SelfOriginated);
        }
        if advert.origin != advert.from {
            return Applied::Invalid(RejectReason::OriginMismatch);
        }
        if advert.metric == 0 {
            return Applied::Invalid(RejectReason::ZeroMetric);
        }
        if advert.origin.0.is_unspecified() || advert.to.0.is_unspecified() {
            return Applied::Invalid(RejectReason::UnspecifiedNode);
        }

        let key = (advert.from, advert.to);
        // sequence handshake for an existing link:
        // - lower sequence: delayed, reject.
        // - equal sequence: a duplicate. if it conflicts with the stored state,
        //   reject; if it matches and the link had expired, a returning peer
        //   restores it; while already fresh it does not extend freshness.
        // - higher sequence: real news. refresh, and report whether the usable
        //   graph changed.
        let decision = self.remote_links.get_mut(&key).map(|existing| {
            use LinkApply::*;
            if advert.seq < existing.advert.seq {
                return Stale;
            }
            if advert.seq == existing.advert.seq {
                if existing.advert.state != advert.state {
                    return Stale;
                }
                if existing.fresh {
                    return Refreshed;
                }
                existing.received_at = now;
                existing.fresh = true;
                return New;
            }
            let content_changed = !existing.fresh
                || existing.advert.state != advert.state
                || existing.advert.metric != advert.metric;
            existing.advert = advert.clone();
            existing.received_at = now;
            existing.fresh = true;
            if content_changed {
                New
            } else {
                Refreshed
            }
        });
        match decision {
            Some(LinkApply::Stale) => return Applied::Stale,
            Some(LinkApply::Refreshed) => return Applied::Refreshed,
            Some(LinkApply::New) => {
                self.learn_node(advert.origin, Some(advert.origin_addr));
                self.bump_version();
                return Applied::New;
            }
            None => {}
        }

        // a brand new link: check resource limits before storing. both the tail
        // and the head may be new nodes, and a peer must not be able to slip an
        // extra node past the cap by adding links whose head it has not seen.
        let adds_origin = !self.nodes.contains(&advert.origin);
        let adds_head = advert.to != self.local && !self.nodes.contains(&advert.to);
        let new_nodes = usize::from(adds_origin) + usize::from(adds_head);
        if new_nodes > 0 && self.nodes.len() + new_nodes > self.limits.max_nodes {
            return Applied::Invalid(RejectReason::LimitReached);
        }
        if self.link_count() >= self.limits.max_links {
            return Applied::Invalid(RejectReason::LimitReached);
        }

        self.learn_node(advert.origin, Some(advert.origin_addr));
        self.learn_node(advert.to, None);
        self.remote_links.insert(
            key,
            Link {
                advert: advert.clone(),
                received_at: now,
                fresh: true,
            },
        );
        self.bump_version();
        Applied::New
    }

    /// invalidate remote links not refreshed within `max_age`.
    ///
    /// the link is kept (so its sequence number still blocks delayed stale
    /// updates) but it stops being usable. returns true when the usable graph
    /// changed and routes should be recomputed.
    pub fn expire(&mut self, now: Instant, max_age: Duration) -> bool {
        let mut changed = false;
        for link in self.remote_links.values_mut() {
            let fresh = now.saturating_duration_since(link.received_at) < max_age;
            if !fresh && link.fresh {
                link.fresh = false;
                if link.advert.state.is_up() {
                    changed = true;
                }
            }
        }
        if changed {
            self.bump_version();
        }
        changed
    }

    /// the effective state of a remote link: up only when advertised up and not
    /// expired.
    fn remote_effective(&self, link: &Link) -> LinkState {
        if link.fresh && link.advert.state.is_up() {
            LinkState::Up
        } else {
            LinkState::Down
        }
    }

    /// every link we know, for observability.
    pub fn link_views(&self) -> Vec<LinkView> {
        let mut views: Vec<LinkView> = self
            .local_links
            .iter()
            .map(|(to, link)| LinkView {
                from: self.local,
                to: *to,
                metric: link.metric,
                advertised: link.state,
                effective: link.state,
                fresh: true,
                seq: link.seq,
            })
            .collect();
        views.extend(self.remote_links.values().map(|link| LinkView {
            from: link.advert.from,
            to: link.advert.to,
            metric: link.advert.metric,
            advertised: link.advert.state,
            effective: self.remote_effective(link),
            fresh: link.fresh,
            seq: link.advert.seq,
        }));
        views.sort_by_key(|view| (view.from, view.to));
        views
    }

    /// derive a dynamic host route to every reachable node using dijkstra.
    ///
    /// each route maps a destination's overlay address to the udp endpoint of
    /// the neighbour on the shortest path. unreachable destinations have no
    /// route, so callers see `None` from `RoutingTable::lookup`.
    pub fn routes(&self) -> Vec<Route> {
        let adjacency = self.adjacency();
        let mut dist: HashMap<NodeId, u64> = HashMap::new();
        let mut first_hop: HashMap<NodeId, NodeId> = HashMap::new();
        let mut heap: BinaryHeap<(std::cmp::Reverse<u64>, NodeId)> = BinaryHeap::new();

        dist.insert(self.local, 0);
        heap.push((std::cmp::Reverse(0), self.local));

        while let Some((std::cmp::Reverse(cost), node)) = heap.pop() {
            if cost > *dist.get(&node).unwrap_or(&u64::MAX) {
                continue;
            }
            let Some(edges) = adjacency.get(&node) else {
                continue;
            };
            for &(next, weight) in edges {
                let candidate = cost.saturating_add(u64::from(weight));
                let hop = if node == self.local {
                    next
                } else {
                    *first_hop.get(&node).unwrap_or(&node)
                };
                let current = *dist.get(&next).unwrap_or(&u64::MAX);
                if candidate < current {
                    dist.insert(next, candidate);
                    first_hop.insert(next, hop);
                    heap.push((std::cmp::Reverse(candidate), next));
                } else if candidate == current {
                    // equal cost: break the tie on the lower next-hop id so the
                    // choice does not depend on heap pop order.
                    if let Some(existing) = first_hop.get(&next) {
                        if hop < *existing {
                            first_hop.insert(next, hop);
                            heap.push((std::cmp::Reverse(candidate), next));
                        }
                    }
                }
            }
        }

        let mut routes = Vec::new();
        for (node, cost) in dist {
            if node == self.local {
                continue;
            }
            let Some(&hop) = first_hop.get(&node) else {
                continue;
            };
            let Some(addr) = self.endpoint_of(hop) else {
                continue;
            };
            let metric = cost.min(u64::from(u32::MAX)) as u32;
            routes.push(Route::dynamic(node.0, hop, addr, metric));
        }
        routes.sort_by_key(|route| route.dest.addr());
        routes
    }

    /// directed adjacency over usable links.
    fn adjacency(&self) -> HashMap<NodeId, Vec<(NodeId, u32)>> {
        let mut adjacency: HashMap<NodeId, Vec<(NodeId, u32)>> = HashMap::new();
        for (to, link) in &self.local_links {
            if link.state.is_up() {
                adjacency
                    .entry(self.local)
                    .or_default()
                    .push((*to, link.metric));
            }
        }
        for link in self.remote_links.values() {
            if self.remote_effective(link).is_up() {
                adjacency
                    .entry(link.advert.from)
                    .or_default()
                    .push((link.advert.to, link.advert.metric));
            }
        }
        adjacency
    }

    /// advertisements for every link we know, with ttl 0 (unicast a snapshot).
    /// sequences are not bumped: a snapshot reports what we already have.
    pub fn snapshot_adverts(&self) -> Vec<LinkAdvert> {
        let mut adverts: Vec<LinkAdvert> = self
            .local_links
            .iter()
            .map(|(to, link)| LinkAdvert {
                origin: self.local,
                origin_addr: self.local_addr,
                seq: link.seq,
                from: self.local,
                to: *to,
                metric: link.metric,
                state: link.state,
                ttl: 0,
            })
            .collect();
        adverts.extend(self.remote_links.values().map(|link| {
            let mut advert = link.advert.clone();
            advert.ttl = 0;
            advert
        }));
        adverts
    }

    fn learn_node(&mut self, node: NodeId, addr: Option<SocketAddr>) {
        if node == self.local {
            return;
        }
        self.nodes.insert(node);
        if let Some(addr) = addr {
            self.endpoints.insert(node, addr);
        }
    }

    fn bump_version(&mut self) {
        self.version = self.version.wrapping_add(1);
    }
}

/// milliseconds since the unix epoch, used as a restart-safe sequence base.
fn unix_millis() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn ip(s: &str) -> Ipv4Addr {
        s.parse().unwrap()
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn has_route_to(topo: &Topology, dest: &str) -> bool {
        let dest = ip(dest);
        topo.routes().iter().any(|route| route.dest.addr() == dest)
    }

    fn advert(
        origin: &str,
        seq: u64,
        from: &str,
        to: &str,
        metric: u32,
        state: LinkState,
    ) -> LinkAdvert {
        LinkAdvert {
            origin: node(origin),
            origin_addr: addr(4000 + u16::from(origin.as_bytes()[7] - b'0')),
            seq,
            from: node(from),
            to: node(to),
            metric,
            state,
            ttl: 8,
        }
    }

    #[test]
    fn topology_updates_produce_the_expected_graph() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            Instant::now(),
        );
        topo.apply(
            &advert("10.0.0.3", 1, "10.0.0.3", "10.0.0.4", 1, LinkState::Up),
            Instant::now(),
        );

        assert_eq!(topo.link_count(), 3);
        assert_eq!(topo.node_count(), 4);
        let views = topo.link_views();
        assert_eq!(views.len(), 3);
        assert!(views
            .iter()
            .any(|v| v.from == node("10.0.0.2") && v.to == node("10.0.0.4")));
    }

    #[test]
    fn route_calculation_selects_the_expected_next_hop() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        topo.add_neighbor(node("10.0.0.3"), addr(4003), 1);
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            Instant::now(),
        );
        topo.apply(
            &advert("10.0.0.3", 1, "10.0.0.3", "10.0.0.4", 5, LinkState::Up),
            Instant::now(),
        );

        let routes = topo.routes();
        let to_d = routes
            .iter()
            .find(|route| route.dest.addr() == ip("10.0.0.4"))
            .expect("route to d");
        assert_eq!(to_d.next_hop, addr(4002));
        assert_eq!(to_d.metric, 2);
    }

    #[test]
    fn unreachable_destination_has_no_route() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        assert!(topo
            .routes()
            .iter()
            .all(|route| route.dest.addr() != ip("10.0.0.9")));
    }

    #[test]
    fn stale_updates_are_rejected() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        let now = Instant::now();
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 5, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                now
            ),
            Applied::New
        );
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 3, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                now
            ),
            Applied::Stale
        );
        // a repeated sequence number with the same state is a duplicate, not
        // fresh information, so it does not change the graph.
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 5, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                now
            ),
            Applied::Refreshed
        );
    }

    #[test]
    fn same_sequence_cannot_flip_state() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let now = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            now,
        );
        // same seq, different state: rejected, state unchanged.
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Down),
                now
            ),
            Applied::Stale
        );
        assert!(
            has_route_to(&topo, "10.0.0.4"),
            "state was flipped without a new seq"
        );
    }

    #[test]
    fn a_heartbeat_refreshes_without_changing_the_graph() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let start = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        // same content, newer sequence: a heartbeat. freshness is bumped but the
        // graph is unchanged, so the caller need not recompute or re-flood.
        let version = topo.version();
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 2, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                start + Duration::from_secs(1)
            ),
            Applied::Refreshed
        );
        assert_eq!(
            topo.version(),
            version,
            "heartbeat should not change the graph"
        );
        assert!(!topo.expire(start + Duration::from_secs(2), Duration::from_secs(5)));
    }

    #[test]
    fn delayed_update_cannot_restore_a_stale_route() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let now = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            now,
        );
        assert!(has_route_to(&topo, "10.0.0.4"));
        topo.apply(
            &advert("10.0.0.2", 2, "10.0.0.2", "10.0.0.4", 1, LinkState::Down),
            now,
        );
        assert!(!has_route_to(&topo, "10.0.0.4"));
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                now
            ),
            Applied::Stale
        );
        assert!(!has_route_to(&topo, "10.0.0.4"), "stale route was restored");
    }

    #[test]
    fn expired_links_become_unusable() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let start = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        assert!(has_route_to(&topo, "10.0.0.4"));

        let later = start + Duration::from_secs(10);
        assert!(topo.expire(later, Duration::from_secs(5)));
        assert!(
            !has_route_to(&topo, "10.0.0.4"),
            "expired link still routed"
        );

        // a newer "down" keeps it down, and a delayed older "up" cannot undo it.
        topo.apply(
            &advert("10.0.0.2", 2, "10.0.0.2", "10.0.0.4", 1, LinkState::Down),
            later,
        );
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                later
            ),
            Applied::Stale
        );
        assert!(!has_route_to(&topo, "10.0.0.4"));
    }

    #[test]
    fn recovered_link_becomes_usable_again() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let start = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        topo.expire(start + Duration::from_secs(10), Duration::from_secs(5));
        assert!(!has_route_to(&topo, "10.0.0.4"));

        let recovered = start + Duration::from_secs(11);
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 2, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                recovered
            ),
            Applied::New
        );
        assert!(has_route_to(&topo, "10.0.0.4"));
    }

    #[test]
    fn a_returning_peer_refreshes_its_expired_link() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        let start = Instant::now();
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        topo.expire(start + Duration::from_secs(10), Duration::from_secs(5));
        assert!(!has_route_to(&topo, "10.0.0.4"));

        // the peer comes back with the same link revision it had before; since
        // our copy had expired, this restores it.
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                start + Duration::from_secs(11)
            ),
            Applied::New
        );
        assert!(has_route_to(&topo, "10.0.0.4"));
    }

    #[test]
    fn rejects_malformed_advertisements() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        let now = Instant::now();
        assert_eq!(
            topo.apply(
                &advert("10.0.0.9", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
                now
            ),
            Applied::Invalid(RejectReason::OriginMismatch)
        );
        assert_eq!(
            topo.apply(
                &advert("10.0.0.1", 1, "10.0.0.1", "10.0.0.2", 1, LinkState::Up),
                now
            ),
            Applied::Invalid(RejectReason::SelfOriginated)
        );
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 0, LinkState::Up),
                now
            ),
            Applied::Invalid(RejectReason::ZeroMetric)
        );
    }

    #[test]
    fn advertisements_are_bounded_by_limits() {
        let limits = Limits {
            max_nodes: 2,
            max_links: 4,
        };
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001)).with_limits(limits);
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        assert_eq!(
            topo.apply(
                &advert("10.0.0.3", 1, "10.0.0.3", "10.0.0.4", 1, LinkState::Up),
                Instant::now()
            ),
            Applied::Invalid(RejectReason::LimitReached)
        );
    }

    #[test]
    fn head_nodes_count_against_the_node_limit() {
        // regression: only the advertisement's *origin* used to be checked
        // against `max_nodes`, so a peer could keep introducing new head nodes
        // by describing links to them and exceed the cap while staying under
        // `max_links`.
        let limits = Limits {
            max_nodes: 2,
            max_links: 8,
        };
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001)).with_limits(limits);
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);

        // the origin (b) is known, but the head (c) is new: that would be a
        // third node, over the cap of two (self + b).
        assert_eq!(
            topo.apply(
                &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.3", 1, LinkState::Up),
                Instant::now()
            ),
            Applied::Invalid(RejectReason::LimitReached)
        );
        assert_eq!(
            topo.node_count(),
            2,
            "the extra head node was stored anyway"
        );
    }

    #[test]
    fn flood_ttl_is_bounded() {
        let adv = advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up);
        let once = adv.decremented().expect("one hop left");
        assert_eq!(once.ttl, adv.ttl - 1);
        let spent = LinkAdvert { ttl: 0, ..adv };
        assert!(spent.decremented().is_none());
    }

    #[test]
    fn two_paths_prefer_the_cheaper_one_and_recover() {
        let start = Instant::now();
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        topo.add_neighbor(node("10.0.0.3"), addr(4003), 1);
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        topo.apply(
            &advert("10.0.0.3", 1, "10.0.0.3", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        let next = |topo: &Topology| {
            topo.routes()
                .iter()
                .find(|r| r.dest.addr() == ip("10.0.0.4"))
                .map(|r| r.next_hop)
        };
        // both paths cost 2; the lower next-hop id (b) wins deterministically.
        assert_eq!(next(&topo), Some(addr(4002)));

        topo.apply(
            &advert("10.0.0.2", 2, "10.0.0.2", "10.0.0.4", 1, LinkState::Down),
            start,
        );
        assert_eq!(next(&topo), Some(addr(4003)));

        topo.apply(
            &advert("10.0.0.2", 3, "10.0.0.2", "10.0.0.4", 1, LinkState::Up),
            start,
        );
        assert_eq!(next(&topo), Some(addr(4002)));
    }

    #[test]
    fn dijkstra_takes_a_transit_path_through_two_learned_links() {
        let mut topo = Topology::new(node("10.0.0.1"), addr(4001));
        topo.add_neighbor(node("10.0.0.2"), addr(4002), 1);
        topo.apply(
            &advert("10.0.0.2", 1, "10.0.0.2", "10.0.0.3", 1, LinkState::Up),
            Instant::now(),
        );
        topo.apply(
            &advert("10.0.0.3", 1, "10.0.0.3", "10.0.0.4", 1, LinkState::Up),
            Instant::now(),
        );
        let routes = topo.routes();
        let to_d = routes
            .iter()
            .find(|r| r.dest.addr() == ip("10.0.0.4"))
            .expect("route to d");
        assert_eq!(to_d.next_hop, addr(4002));
        assert_eq!(to_d.metric, 3);
    }
}
