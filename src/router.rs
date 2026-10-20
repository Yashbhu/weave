//! the topology control plane: exchange link state, detect failures, and
//! publish routes.
//!
//! this ties the pieces together. it owns a `Topology`, floods advertisements
//! over the same udp transport the data plane uses, tracks which direct
//! neighbours are still alive, and republishes the `RouteSnapshot` whenever the
//! usable graph changes.
//!
//! # what is and is not trusted
//!
//! control messages arrive over udp. `Topology::apply` requires that the origin
//! of a link owns its tail, so an unrelated peer cannot describe a link it does
//! not own. when a long-term identity is configured (`RouterConfig::identity`),
//! every neighbour is additionally authenticated with a noise ik handshake and
//! control bodies travel as encrypted records, so a peer must prove possession
//! of its static key before it can affect the topology - and a spoofed udp
//! source address buys nothing. without an identity the plane is unauthenticated
//! and only configured endpoints are accepted.
//!
//! time is passed into every method, so the core is deterministic and testable
//! without sleeping. `run` is the only async part and just drives the core.

use std::collections::{HashMap, HashSet};
use std::io;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::net::UdpSocket;
use tokio::sync::{mpsc, watch};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use crate::connectivity::{Connectivity, ConnectivityConfig, Link, LinkMap, LinkSnapshot};
use crate::control::{self, Message};
use crate::endpoints::{EndpointApply, EndpointLimits, EndpointRegistry};
use crate::lifecycle::{Action as LifecycleAction, Lifecycle, PeerState, ProbeConfig};
use crate::noise::{Handshake, Identity, PublicKey, Session};
use crate::peer::PeerSet;
use crate::rate::{RateLimitConfig, RateLimiter};
use crate::route::{Route, RouteSnapshot, RoutingTable};
use crate::topology::{Applied, LinkState, NodeId, Topology};
use crate::transport;

/// one direct neighbour: a stable identity and its current udp endpoint.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Neighbor {
    /// the neighbour's overlay identity.
    pub id: NodeId,
    /// the neighbour's udp endpoint.
    pub addr: SocketAddr,
}

/// settings for the topology control plane.
#[derive(Debug, Clone)]
pub struct RouterConfig {
    /// this node's identity.
    pub local: NodeId,
    /// this node's udp endpoint.
    pub local_addr: SocketAddr,
    /// configured direct neighbours.
    pub neighbors: Vec<Neighbor>,
    /// metric applied to every local link.
    pub link_metric: u32,
    /// how often to re-send local advertisements as heartbeats.
    pub heartbeat: Duration,
    /// how long without a control message before a neighbour is considered down.
    pub link_timeout: Duration,
    /// how many hops an originated advertisement may flood.
    pub max_flood_ttl: u8,
    /// static routes kept in every published table.
    pub base_routes: Vec<Route>,
    /// this node's long-term key. `Some` enables authenticated, encrypted
    /// control sessions (m7); `None` keeps the unauthenticated behaviour.
    pub identity: Option<Identity>,
    /// the static public key of each peer we will talk to.
    pub peer_keys: HashMap<NodeId, PublicKey>,
    /// a relay to fall back to when a neighbour cannot be reached directly.
    pub relay: Option<SocketAddr>,
    /// whether this node forwards relay envelopes for its neighbours.
    pub serve_relay: bool,
    /// caps on the endpoint registry.
    pub endpoint_limits: EndpointLimits,
    /// thresholds for switching between direct and relayed paths.
    pub connectivity: ConnectivityConfig,
    /// per-source and global control-message rate limits.
    pub rate_limit: RateLimitConfig,
}

impl RouterConfig {
    /// defaults for the timers, keeping the identity and neighbours.
    pub fn new(local: NodeId, local_addr: SocketAddr, neighbors: Vec<Neighbor>) -> Self {
        Self {
            local,
            local_addr,
            neighbors,
            link_metric: 1,
            heartbeat: Duration::from_secs(1),
            link_timeout: Duration::from_secs(3),
            max_flood_ttl: 4,
            base_routes: Vec::new(),
            identity: None,
            peer_keys: HashMap::new(),
            relay: None,
            serve_relay: false,
            endpoint_limits: EndpointLimits::default(),
            connectivity: ConnectivityConfig::default(),
            rate_limit: RateLimitConfig::default(),
        }
    }
}

/// a message the core wants sent to a neighbour.
pub type Outbound = (SocketAddr, Message);

/// counters for observability.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct RouterStats {
    /// advertisements accepted as new information.
    pub applied: u64,
    /// advertisements rejected as stale.
    pub stale: u64,
    /// advertisements rejected as invalid.
    pub invalid: u64,
    /// routing table recalculations.
    pub recalculations: u64,
    /// advertisements re-flooded to other peers.
    pub floods: u64,
    /// control messages rejected for a bad or missing mac.
    pub unauthorized: u64,
    /// endpoint migrations accepted (a peer's active endpoint changed).
    pub migrations: u64,
    /// control messages dropped by the rate limiter before any crypto.
    pub rate_limited: u64,
    /// authenticated sessions established.
    pub sessions: u64,
}

/// an established control session with a peer.
struct PeerSession {
    session: Session,
    addr: SocketAddr,
}

/// a handshake we started and are waiting to finish.
struct PendingInit {
    handshake: Handshake,
    since: Instant,
}

/// a raw control-plane datagram, tagged by which frame it arrived in.
#[derive(Debug, Clone)]
pub enum Inbound {
    /// an encrypted control body (a session record).
    Control(Vec<u8>),
    /// a noise handshake message.
    Handshake(Vec<u8>),
}

/// the deterministic core of the control plane.
pub struct Router {
    config: RouterConfig,
    topology: Topology,
    peers: Arc<PeerSet>,
    routes: RouteSnapshot,
    links: LinkSnapshot,
    endpoints: EndpointRegistry,
    connectivity: Connectivity,
    limiter: RateLimiter,
    lifecycle: Lifecycle,
    /// established sessions, by peer identity.
    sessions: HashMap<NodeId, PeerSession>,
    /// handshakes we initiated, by the address we dialled.
    pending_init: HashMap<SocketAddr, PendingInit>,
    /// udp address -> peer identity, learned from sessions (handles migration).
    bindings: HashMap<SocketAddr, NodeId>,
    /// punch tokens we originated toward a peer and have not yet seen echoed.
    our_punches: HashSet<(NodeId, u64)>,
    /// punch tokens we have already echoed to a peer. a token is echoed at most
    /// once per peer, so two configured neighbours cannot bounce one punch
    /// forever.
    echoed_punches: HashSet<(NodeId, u64)>,
    punch_token: u64,
    dirty: bool,
    stats: RouterStats,
}

impl Router {
    /// build a router with local links to every configured neighbour.
    pub fn new(
        config: RouterConfig,
        peers: Arc<PeerSet>,
        routes: RouteSnapshot,
        links: LinkSnapshot,
    ) -> Self {
        let mut topology = Topology::new(config.local, config.local_addr);
        for neighbor in &config.neighbors {
            topology.add_neighbor(neighbor.id, neighbor.addr, config.link_metric);
        }
        let mut endpoints = EndpointRegistry::with_limits(config.endpoint_limits);
        let mut connectivity = Connectivity::new(config.connectivity);
        let rate_limit = config.rate_limit;
        let probe = ProbeConfig::from_timeouts(config.heartbeat, config.link_timeout);
        let now = Instant::now();
        for neighbor in &config.neighbors {
            // seed the registry so a neighbour's first confirmed message can
            // mark its endpoint active. epoch 0 is below any advertised epoch.
            endpoints.declare(neighbor.id, 0, &[neighbor.addr], now);
            connectivity.register(neighbor.id, config.relay, now);
        }
        let mut lifecycle = Lifecycle::new(probe);
        for neighbor in &config.neighbors {
            lifecycle.track(neighbor.id, now);
        }
        let bindings = config
            .neighbors
            .iter()
            .map(|neighbor| (neighbor.addr, neighbor.id))
            .collect();
        let mut router = Self {
            config,
            topology,
            peers,
            routes,
            links,
            endpoints,
            connectivity,
            limiter: RateLimiter::new(rate_limit, now),
            lifecycle,
            sessions: HashMap::new(),
            pending_init: HashMap::new(),
            bindings,
            our_punches: HashSet::new(),
            echoed_punches: HashSet::new(),
            punch_token: 0,
            // the initial neighbour graph is a usable routing table; publish it
            // now so locally originated traffic is routable before any control
            // message arrives.
            dirty: true,
            stats: RouterStats::default(),
        };
        router.publish_if_dirty();
        router.publish_links();
        router
    }

    /// the shared link table the data plane reads.
    pub fn links(&self) -> LinkSnapshot {
        self.links.clone()
    }

    /// the proven endpoint for a peer identity, if any.
    pub fn endpoint_of(&self, id: NodeId) -> Option<SocketAddr> {
        self.endpoints.endpoint_of(id)
    }

    /// the topology this router currently believes in.
    pub fn topology(&self) -> &Topology {
        &self.topology
    }

    /// counters.
    pub fn stats(&self) -> RouterStats {
        self.stats
    }

    /// the routing table this router last published.
    pub fn routes(&self) -> std::sync::Arc<RoutingTable> {
        self.routes.current()
    }

    /// the endpoint for a neighbour identity as configured.
    fn neighbor_addr(&self, id: NodeId) -> Option<SocketAddr> {
        self.config
            .neighbors
            .iter()
            .find(|neighbor| neighbor.id == id)
            .map(|neighbor| neighbor.addr)
    }

    /// the neighbour identity for a udp endpoint.
    fn neighbor_of(&self, addr: SocketAddr) -> Option<NodeId> {
        self.config
            .neighbors
            .iter()
            .find(|neighbor| neighbor.addr == addr)
            .map(|neighbor| neighbor.id)
    }

    /// is `id` one of our configured neighbours?
    fn is_neighbor(&self, id: NodeId) -> bool {
        self.config
            .neighbors
            .iter()
            .any(|neighbor| neighbor.id == id)
    }

    /// where to send to a neighbour right now: its live endpoint if we have one,
    /// otherwise the configured one.
    fn direct_addr(&self, id: NodeId) -> Option<SocketAddr> {
        self.endpoints
            .endpoint_of(id)
            .or_else(|| self.neighbor_addr(id))
    }

    /// the identity a control message claims as its origin.
    fn origin_of(message: &Message) -> NodeId {
        match message {
            Message::LinkAdvert(advert) => advert.origin,
            Message::LinkRequest { origin, .. }
            | Message::EndpointUpdate { origin, .. }
            | Message::Punch { origin, .. } => *origin,
        }
    }

    /// prime liveness and ask every neighbour for a full update. advertise our
    /// own links so they learn us too.
    pub fn start(&mut self, now: Instant) -> Vec<Outbound> {
        for neighbor in &self.config.neighbors {
            self.lifecycle.on_message(neighbor.id, now);
        }
        let mut outbound = Vec::new();
        for neighbor in &self.config.neighbors {
            let Some(addr) = self.direct_addr(neighbor.id) else {
                continue;
            };
            outbound.push((
                addr,
                Message::LinkRequest {
                    origin: self.config.local,
                    origin_addr: self.config.local_addr,
                },
            ));
        }
        self.advertise_all(&mut outbound);
        self.publish_if_dirty();
        self.publish_links();
        outbound
    }

    /// authenticate, decode and handle a raw control body from `from`.
    ///
    /// this is the entry point the data plane uses. when a session exists the
    /// body must be an encrypted record that decrypts under it, or it is dropped
    /// before anything sees it. without a configured identity we fall back to
    /// the unauthenticated behaviour.
    pub fn handle_body(&mut self, from: SocketAddr, body: &[u8], now: Instant) -> Vec<Outbound> {
        // cheapest possible first gate: drop a flood before it costs any crypto.
        if !self.limiter.check(from, now) {
            self.stats.rate_limited += 1;
            debug!(%from, "dropped control message: rate limited");
            return Vec::new();
        }
        let payload = if self.crypto_enabled() {
            let Some((peer, payload)) = self.open_record(from, body) else {
                self.stats.unauthorized += 1;
                debug!(%from, "rejected control record");
                return Vec::new();
            };
            let outbound = match control::decode(&payload) {
                Ok(message) => self.handle(from, message, now),
                Err(err) => {
                    self.stats.invalid += 1;
                    warn!(%from, error = %err, "dropped malformed control message");
                    return Vec::new();
                }
            };
            // the record's aead tag proves this peer sent it, so a new source
            // address is a migration, not an impostor.
            self.rebind(peer, from);
            return outbound;
        } else {
            body.to_vec()
        };
        match control::decode(&payload) {
            Ok(message) => self.handle(from, message, now),
            Err(err) => {
                self.stats.invalid += 1;
                warn!(%from, error = %err, "dropped malformed control message");
                Vec::new()
            }
        }
    }

    /// is authenticated, encrypted control enabled?
    fn crypto_enabled(&self) -> bool {
        self.config.identity.is_some()
    }

    /// our own static public key, if control is authenticated.
    pub fn local_public(&self) -> Option<PublicKey> {
        self.config.identity.as_ref().map(Identity::public)
    }

    /// the peer identity that owns a udp address, from config or a learned
    /// session binding.
    fn peer_for_addr(&self, addr: SocketAddr) -> Option<NodeId> {
        self.neighbor_of(addr)
            .or_else(|| self.bindings.get(&addr).copied())
    }

    /// which configured peer owns a static public key, if any.
    fn peer_for_static(&self, key: &PublicKey) -> Option<NodeId> {
        self.config
            .peer_keys
            .iter()
            .find(|(_, configured)| *configured == key)
            .map(|(id, _)| *id)
    }

    /// decrypt a control record, identifying the peer by its session. a record
    /// from an address we have not bound (a migrating peer) is tried against
    /// every session: the aead tag is what proves who sent it.
    fn open_record(&self, from: SocketAddr, body: &[u8]) -> Option<(NodeId, Vec<u8>)> {
        if let Some(peer) = self.peer_for_addr(from) {
            if let Some(payload) = self
                .sessions
                .get(&peer)
                .and_then(|session| session.session.open(body).ok())
            {
                return Some((peer, payload));
            }
        }
        for (peer, session) in &self.sessions {
            if let Ok(payload) = session.session.open(body) {
                return Some((*peer, payload));
            }
        }
        None
    }

    /// move a peer's address binding after it proves newer liveness from it.
    fn rebind(&mut self, peer: NodeId, from: SocketAddr) {
        let Some(session) = self.sessions.get_mut(&peer) else {
            return;
        };
        if session.addr == from {
            return;
        }
        let old = session.addr;
        session.addr = from;
        self.bindings.remove(&old);
        self.bindings.insert(from, peer);
        self.peers.remove(old);
        self.peers.add(from);
    }

    /// begin (or retry) a handshake with every neighbour we should be dialling
    /// and do not yet have a session with. the node with the lower identity is
    /// the initiator, so exactly one side dials.
    pub fn ensure_handshakes(&mut self, now: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        if !self.crypto_enabled() {
            return Vec::new();
        }
        let Some(identity) = self.config.identity.clone() else {
            return Vec::new();
        };
        let mut outbound = Vec::new();
        for neighbor in &self.config.neighbors {
            let id = neighbor.id;
            if self.sessions.contains_key(&id) {
                continue;
            }
            if self.config.local.0 >= id.0 {
                continue;
            }
            let Some(remote) = self.config.peer_keys.get(&id).copied() else {
                continue;
            };
            let addr = self.direct_addr(id).unwrap_or(neighbor.addr);
            if let Some(pending) = self.pending_init.get(&addr) {
                if now.saturating_duration_since(pending.since) < self.config.heartbeat {
                    continue;
                }
            }
            match Handshake::initiate(&identity, &remote) {
                Ok(mut handshake) => match handshake.write() {
                    Ok(message) => {
                        self.pending_init.insert(
                            addr,
                            PendingInit {
                                handshake,
                                since: now,
                            },
                        );
                        outbound.push((addr, message));
                    }
                    Err(err) => warn!(%id, error = %err, "failed to start handshake"),
                },
                Err(err) => warn!(%id, error = %err, "failed to start handshake"),
            }
        }
        outbound
    }

    /// handle a noise handshake message from `from`. returns queued control
    /// messages plus any handshake message to send back.
    pub fn handle_handshake(
        &mut self,
        from: SocketAddr,
        body: &[u8],
        now: Instant,
    ) -> (Vec<Outbound>, Vec<(SocketAddr, Vec<u8>)>) {
        let mut control = Vec::new();
        let mut handshake_out = Vec::new();
        if !self.crypto_enabled() {
            return (control, handshake_out);
        }
        if !self.limiter.check(from, now) {
            self.stats.rate_limited += 1;
            return (control, handshake_out);
        }
        let Some(identity) = self.config.identity.clone() else {
            return (control, handshake_out);
        };

        if let Some(pending) = self.pending_init.remove(&from) {
            // completion of a handshake we initiated: message 2.
            let mut handshake = pending.handshake;
            if handshake.read(body).is_err() || !handshake.is_finished() {
                self.stats.unauthorized += 1;
                debug!(%from, "bad handshake response");
                return (control, handshake_out);
            }
            let session = match handshake.finish() {
                Ok(session) => session,
                Err(err) => {
                    self.stats.unauthorized += 1;
                    debug!(%from, error = %err, "handshake failed");
                    return (control, handshake_out);
                }
            };
            let remote = session.remote_static();
            match self.peer_for_static(&remote) {
                Some(id) => self.install_session(id, from, session, now, &mut control),
                None => {
                    self.stats.unauthorized += 1;
                    warn!(%from, "handshake with an unrecognised static key");
                }
            }
            return (control, handshake_out);
        }

        // a handshake a peer initiated: we are the responder.
        let mut handshake = match Handshake::respond(&identity) {
            Ok(handshake) => handshake,
            Err(err) => {
                warn!(%from, error = %err, "failed to start responder handshake");
                return (control, handshake_out);
            }
        };
        if handshake.read(body).is_err() {
            self.stats.unauthorized += 1;
            debug!(%from, "bad handshake message");
            return (control, handshake_out);
        }
        let Some(remote) = handshake.remote_static() else {
            self.stats.unauthorized += 1;
            return (control, handshake_out);
        };
        let Some(id) = self.peer_for_static(&remote) else {
            self.stats.unauthorized += 1;
            warn!(%from, "handshake from an unrecognised static key");
            return (control, handshake_out);
        };
        let response = match handshake.write() {
            Ok(response) => response,
            Err(err) => {
                self.stats.unauthorized += 1;
                debug!(%from, error = %err, "failed to finish responder handshake");
                return (control, handshake_out);
            }
        };
        match handshake.finish() {
            Ok(session) => {
                self.install_session(id, from, session, now, &mut control);
                handshake_out.push((from, response));
            }
            Err(err) => {
                self.stats.unauthorized += 1;
                debug!(%from, error = %err, "handshake failed");
            }
        }
        (control, handshake_out)
    }

    /// record a completed session, bind its address, and treat it as liveness.
    fn install_session(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        session: Session,
        now: Instant,
        control: &mut Vec<Outbound>,
    ) {
        if let Some(previous) = self.sessions.get(&id) {
            if previous.addr != addr {
                self.bindings.remove(&previous.addr);
                self.peers.remove(previous.addr);
            }
        }
        self.bindings.insert(addr, id);
        self.peers.add(addr);
        self.sessions.insert(id, PeerSession { session, addr });
        self.stats.sessions += 1;
        info!(peer = %id, %addr, "control session established");
        self.mark_live(id, addr, now, control);
        // converge quickly: ask the peer for everything it knows.
        control.push((
            addr,
            Message::LinkRequest {
                origin: self.config.local,
                origin_addr: self.config.local_addr,
            },
        ));
    }

    /// handle a decoded control message from `from`.
    pub fn handle(&mut self, from: SocketAddr, message: Message, now: Instant) -> Vec<Outbound> {
        // normally the source is a configured endpoint. after a migration the
        // message arrives from the peer's *new* address, so fall back to the
        // origin it claims - but only when messages are authenticated, so an
        // unauthenticated stranger cannot impersonate a neighbour.
        let peer_id = match self.neighbor_of(from) {
            Some(id) => id,
            None => {
                let origin = Self::origin_of(&message);
                if self.crypto_enabled() && self.is_neighbor(origin) {
                    origin
                } else {
                    debug!(%from, "ignored control message from a non-neighbour");
                    return Vec::new();
                }
            }
        };

        let mut outbound = Vec::new();
        // for an advertisement, first decide whether it carries information that
        // is *current*: a delayed or replayed message (for instance a stale
        // advertisement held up in the network) must not be taken as proof that
        // the neighbour is alive, or it could resurrect a link we already marked
        // down during the outage. every other message is inherently a current
        // action, so it counts as liveness straight away.
        match message {
            Message::LinkAdvert(advert) => {
                if self.handle_advert(peer_id, from, advert, now, &mut outbound) {
                    self.mark_live(peer_id, from, now, &mut outbound);
                }
            }
            Message::LinkRequest {
                origin,
                origin_addr,
            } => {
                self.mark_live(peer_id, from, now, &mut outbound);
                debug!(%from, %origin, %origin_addr, "replying to a link request");
                self.reply_snapshot(from, &mut outbound);
            }
            Message::EndpointUpdate {
                origin,
                epoch,
                addrs,
            } => {
                // observe first: migration bookkeeping needs to see the previous
                // endpoint before the update is applied.
                self.mark_live(peer_id, from, now, &mut outbound);
                if origin != peer_id {
                    warn!(%from, %origin, "endpoint update origin does not match sender");
                } else {
                    self.handle_endpoint_update(peer_id, epoch, &addrs, now, &mut outbound);
                }
            }
            Message::Punch { origin, token } => {
                self.mark_live(peer_id, from, now, &mut outbound);
                // an echo of a punch we originated proves the peer's endpoint,
                // so consume it and stop. otherwise echo the peer's punch once
                // (so it can prove ours) and never again, so two configured
                // neighbours cannot bounce one punch forever.
                let ours = self.our_punches.remove(&(peer_id, token));
                if origin == peer_id && !ours && self.echoed_punches.insert((peer_id, token)) {
                    outbound.push((
                        from,
                        Message::Punch {
                            origin: self.config.local,
                            token,
                        },
                    ));
                }
            }
        }

        self.publish_if_dirty();
        self.publish_links();
        outbound
    }

    /// record that `id` is alive at `addr` right now: bump its liveness, apply
    /// any endpoint migration, and restore a link we had marked down.
    fn mark_live(
        &mut self,
        id: NodeId,
        addr: SocketAddr,
        now: Instant,
        outbound: &mut Vec<Outbound>,
    ) {
        self.lifecycle.on_message(id, now);
        // a current, authenticated message from a neighbour proves the direct
        // path and validates its endpoint. this is where migration takes effect.
        self.observe_endpoint(id, addr, now);
        // it also proves the link is alive: restore it if we had marked it down,
        // and let everyone know.
        if self.topology.local_state(id) == Some(LinkState::Down)
            && self.set_link_state(id, LinkState::Up)
        {
            info!(neighbor = %id, "neighbour link recovered");
            self.advertise_all(outbound);
        }
    }

    /// periodic work: expire stale links, detect failed neighbours, and
    /// heartbeat our own advertisements.
    pub fn tick(&mut self, now: Instant) -> Vec<Outbound> {
        if self.topology.expire(now, self.config.link_timeout) {
            self.dirty = true;
        }
        self.endpoints.expire(now, self.config.link_timeout);
        self.limiter.prune(now);

        let mut changed = false;
        let mut outbound = Vec::new();
        for action in self.lifecycle.tick(now) {
            match action {
                LifecycleAction::Probe(id) => {
                    // count a miss only once the peer is fully disconnected; the
                    // suspect window is the half-open phase where we are still
                    // trying to confirm it.
                    if self.lifecycle.state(id) == Some(PeerState::Disconnected) {
                        self.connectivity.on_direct_failure(id, now);
                    }
                    if let Some(addr) = self.direct_addr(id) {
                        outbound.push((
                            addr,
                            Message::LinkRequest {
                                origin: self.config.local,
                                origin_addr: self.config.local_addr,
                            },
                        ));
                    }
                }
                LifecycleAction::WentDown(id) => {
                    self.connectivity.on_direct_failure(id, now);
                    if self.topology.local_state(id) == Some(LinkState::Up)
                        && self.set_link_state(id, LinkState::Down)
                    {
                        warn!(neighbor = %id, "neighbour link timed out");
                        changed = true;
                    }
                }
                LifecycleAction::WentSuspect(id) => {
                    debug!(neighbor = %id, "neighbour went quiet; probing");
                }
                LifecycleAction::CameUp(id) => {
                    debug!(neighbor = %id, "neighbour came back");
                }
            }
        }
        if changed {
            self.dirty = true;
        }

        self.publish_if_dirty();
        self.publish_links();

        self.advertise_all(&mut outbound);
        outbound
    }

    /// record an authenticated message from a neighbour: it proves the direct
    /// path and its endpoint. this is where an endpoint migration is applied.
    fn observe_endpoint(&mut self, id: NodeId, addr: SocketAddr, now: Instant) {
        let previous = self.endpoints.endpoint_of(id);
        self.endpoints.touch(id, now);
        if self.endpoints.confirm(id, addr, now) {
            if let Some(old) = previous {
                if old != addr {
                    // the peer moved: stop accepting its old address.
                    self.peers.remove(old);
                    self.stats.migrations += 1;
                    info!(peer = %id, old = %old, new = %addr, "peer endpoint migrated");
                }
            }
            self.peers.add(addr);
            // the old direct path is void; it must be re-proven.
            self.connectivity.on_endpoint_change(id, now);
        }
        self.connectivity.on_direct_success(id, addr, now);
    }

    /// apply an announced endpoint update and punch the new candidates.
    fn handle_endpoint_update(
        &mut self,
        id: NodeId,
        epoch: u64,
        addrs: &[SocketAddr],
        now: Instant,
        outbound: &mut Vec<Outbound>,
    ) {
        match self.endpoints.declare(id, epoch, addrs, now) {
            EndpointApply::Updated => {
                let token = self.next_punch_token(id);
                for addr in addrs {
                    outbound.push((
                        *addr,
                        Message::Punch {
                            origin: self.config.local,
                            token,
                        },
                    ));
                }
            }
            EndpointApply::Stale => {
                debug!(%id, epoch, "ignored stale endpoint update");
            }
            EndpointApply::Rejected(reason) => {
                warn!(%id, reason = reason.as_str(), "rejected endpoint update");
            }
        }
    }

    fn next_punch_token(&mut self, peer: NodeId) -> u64 {
        self.punch_token = self.punch_token.wrapping_add(1);
        // bound the outstanding set: old tokens are forgotten once enough newer
        // punches exist.
        if self.our_punches.len() >= 1024 {
            self.our_punches.clear();
        }
        if self.echoed_punches.len() >= 4096 {
            self.echoed_punches.clear();
        }
        self.our_punches.insert((peer, self.punch_token));
        self.punch_token
    }

    /// rebuild and publish the link table from the current endpoint and
    /// connectivity state.
    fn publish_links(&mut self) {
        let mut map = LinkMap::new();
        for neighbor in &self.config.neighbors {
            match self.connectivity.current(neighbor.id) {
                Some(link) => {
                    map.insert(neighbor.id, link);
                }
                None => {
                    // no proven direct path; if we still have a proven endpoint,
                    // expose it as direct so relay lookups on other nodes can
                    // reach us, but keep the peer unavailable otherwise.
                    if let Some(addr) = self.endpoints.endpoint_of(neighbor.id) {
                        map.insert(neighbor.id, Link::Direct(addr));
                    }
                }
            }
        }
        self.links.publish(map);
    }

    fn handle_advert(
        &mut self,
        sender: NodeId,
        from: SocketAddr,
        advert: crate::topology::LinkAdvert,
        now: Instant,
        outbound: &mut Vec<Outbound>,
    ) -> bool {
        // a *self-originated* advert for one of our direct neighbours must come
        // from that neighbour. otherwise a member could forge another peer's
        // local links and poison everyone's view of who is directly reachable.
        // (transit adverts about non-neighbours are only as trustworthy as the
        // authenticated peer that forwarded them - a documented limitation.)
        if advert.from == advert.origin
            && self.is_neighbor(advert.origin)
            && advert.origin != sender
        {
            self.stats.invalid += 1;
            warn!(
                %from,
                claimed = %advert.origin,
                sender = %sender,
                "rejected advertisement claiming another neighbour's identity"
            );
            return false;
        }
        match self.topology.apply(&advert, now) {
            Applied::New => {
                self.stats.applied += 1;
                self.dirty = true;
                if let Some(forwarded) = advert.decremented() {
                    let message = Message::LinkAdvert(forwarded);
                    let mut sent = 0;
                    for neighbor in &self.config.neighbors {
                        if neighbor.id == advert.origin {
                            continue;
                        }
                        let Some(addr) = self.direct_addr(neighbor.id) else {
                            continue;
                        };
                        if addr == from {
                            continue;
                        }
                        outbound.push((addr, message.clone()));
                        sent += 1;
                    }
                    self.stats.floods += u64::from(sent > 0);
                }
                true
            }
            // a heartbeat (newer sequence, same content) or a duplicate while
            // the link is still fresh: current enough to prove liveness, but it
            // changes no routing state.
            Applied::Refreshed => true,
            Applied::Stale => {
                self.stats.stale += 1;
                debug!(%from, origin = %advert.origin, seq = advert.seq, "rejected stale advertisement");
                false
            }
            Applied::Invalid(reason) => {
                self.stats.invalid += 1;
                warn!(%from, reason = reason.as_str(), "rejected invalid advertisement");
                false
            }
        }
    }

    fn reply_snapshot(&self, to: SocketAddr, outbound: &mut Vec<Outbound>) {
        for advert in self.topology.snapshot_adverts() {
            outbound.push((to, Message::LinkAdvert(advert)));
        }
    }

    fn advertise_all(&mut self, outbound: &mut Vec<Outbound>) {
        let ttl = self.config.max_flood_ttl;
        let adverts = self.topology.local_adverts(ttl);
        let messages: Vec<Message> = adverts.into_iter().map(Message::LinkAdvert).collect();
        for neighbor in &self.config.neighbors {
            let Some(addr) = self.direct_addr(neighbor.id) else {
                continue;
            };
            for message in &messages {
                outbound.push((addr, message.clone()));
            }
        }
    }

    fn set_link_state(&mut self, id: NodeId, state: LinkState) -> bool {
        if !self.topology.set_local_state(id, state) {
            return false;
        }
        self.dirty = true;
        if let Some(addr) = self.direct_addr(id) {
            self.peers.set_available(addr, state.is_up());
        }
        true
    }

    /// recompute and publish routes if the usable graph changed.
    fn publish_if_dirty(&mut self) {
        if !self.dirty {
            return;
        }
        let mut routes = self.config.base_routes.clone();
        routes.extend(self.topology.routes());
        let count = routes.len();
        self.routes.publish(RoutingTable::new(routes));
        self.dirty = false;
        self.stats.recalculations += 1;
        info!(
            routes = count,
            version = self.topology.version(),
            recalculations = self.stats.recalculations,
            "published routing table"
        );
    }
}

/// run the control plane until shutdown.
///
/// `inbound` carries raw control-plane datagrams from the overlay's udp
/// receiver, tagged with the udp source address and the frame kind.
pub async fn run(
    mut router: Router,
    socket: Arc<UdpSocket>,
    mut inbound: mpsc::Receiver<(SocketAddr, Inbound)>,
    mut stop: watch::Receiver<bool>,
) -> io::Result<()> {
    let now = Instant::now();
    let started = router.start(now);
    let handshakes = router.ensure_handshakes(now);
    router.send_control(&socket, started).await;
    send_handshakes(&socket, handshakes).await;

    let mut ticker = tokio::time::interval(router.config.heartbeat);
    ticker.set_missed_tick_behavior(MissedTickBehavior::Delay);

    loop {
        tokio::select! {
            _ = stop.changed() => {
                debug!("control plane stopping");
                return Ok(());
            }
            _ = ticker.tick() => {
                let now = Instant::now();
                let outbound = router.tick(now);
                let handshakes = router.ensure_handshakes(now);
                router.send_control(&socket, outbound).await;
                send_handshakes(&socket, handshakes).await;
            }
            item = inbound.recv() => {
                let Some((from, inbound)) = item else {
                    return Ok(());
                };
                let now = Instant::now();
                match inbound {
                    Inbound::Control(body) => {
                        let outbound = router.handle_body(from, &body, now);
                        router.send_control(&socket, outbound).await;
                    }
                    Inbound::Handshake(body) => {
                        let (outbound, handshakes) = router.handle_handshake(from, &body, now);
                        // the peer cannot read sealed control until it has
                        // processed our handshake response, so send that first.
                        send_handshakes(&socket, handshakes).await;
                        router.send_control(&socket, outbound).await;
                    }
                }
            }
        }
    }
}

impl Router {
    /// encode and send queued control messages. when sessions are enabled a
    /// message with no session for its destination is dropped: sending it in the
    /// clear would defeat the point.
    async fn send_control(&self, socket: &UdpSocket, outbound: Vec<Outbound>) {
        for (addr, message) in outbound {
            let body = match control::encode(&message) {
                Ok(body) => body,
                Err(err) => {
                    warn!(error = %err, "failed to encode control message");
                    continue;
                }
            };
            let record = if self.crypto_enabled() {
                let Some(peer) = self.peer_for_addr(addr) else {
                    debug!(%addr, "no peer for control destination; dropping");
                    continue;
                };
                let Some(session) = self.sessions.get(&peer) else {
                    debug!(%addr, %peer, "no session yet; dropping control message");
                    continue;
                };
                match session.session.seal(&body) {
                    Ok(record) => record,
                    Err(err) => {
                        warn!(%addr, error = %err, "failed to seal control message");
                        continue;
                    }
                }
            } else {
                body
            };
            if let Err(err) = transport::send_control(socket, addr, &record).await {
                debug!(%addr, error = %err, "failed to send control message");
            }
        }
    }
}

async fn send_handshakes(socket: &UdpSocket, outbound: Vec<(SocketAddr, Vec<u8>)>) {
    for (addr, message) in outbound {
        if let Err(err) = transport::send_handshake(socket, addr, &message).await {
            debug!(%addr, error = %err, "failed to send handshake message");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::topology::LinkAdvert;

    fn node(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn ip(s: &str) -> std::net::Ipv4Addr {
        s.parse().unwrap()
    }

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    fn far_advert(origin: &str, seq: u64, to: &str, state: LinkState) -> LinkAdvert {
        LinkAdvert {
            origin: node(origin),
            origin_addr: addr(4000 + u16::from(origin.as_bytes()[7] - b'0')),
            seq,
            from: node(origin),
            to: node(to),
            metric: 1,
            state,
            ttl: 4,
        }
    }

    fn router(local: &str, local_port: u16, neighbors: &[(&str, u16)]) -> Router {
        let neighbors: Vec<Neighbor> = neighbors
            .iter()
            .map(|(id, port)| Neighbor {
                id: node(id),
                addr: addr(*port),
            })
            .collect();
        let addrs = neighbors.iter().map(|n| n.addr);
        let peers = Arc::new(PeerSet::new(addrs));
        Router::new(
            RouterConfig::new(node(local), addr(local_port), neighbors),
            peers,
            RouteSnapshot::new(RoutingTable::default()),
            LinkSnapshot::new(),
        )
    }

    #[test]
    fn a_new_advert_is_flooded_to_other_peers() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002), ("10.0.0.3", 4003)]);
        let now = Instant::now();
        r.start(now);

        // b tells a about b -> d
        let out = r.handle(
            addr(4002),
            Message::LinkAdvert(far_advert("10.0.0.2", 1, "10.0.0.4", LinkState::Up)),
            now,
        );
        assert!(
            out.iter().any(|(to, msg)| *to == addr(4003)
                && matches!(msg, Message::LinkAdvert(a) if a.origin == node("10.0.0.2"))),
            "the new advert should be flooded to the third peer"
        );
        assert_eq!(r.stats().applied, 1);
        assert!(
            r.stats().recalculations >= 1,
            "routes should have been recalculated"
        );
    }

    #[test]
    fn a_stale_advert_is_not_flooded() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002), ("10.0.0.3", 4003)]);
        let now = Instant::now();
        r.start(now);
        r.handle(
            addr(4002),
            Message::LinkAdvert(far_advert("10.0.0.2", 5, "10.0.0.4", LinkState::Up)),
            now,
        );
        let out = r.handle(
            addr(4002),
            Message::LinkAdvert(far_advert("10.0.0.2", 2, "10.0.0.4", LinkState::Up)),
            now,
        );
        assert!(out.is_empty(), "stale advert was re-flooded");
        assert_eq!(r.stats().stale, 1);
    }

    #[test]
    fn a_peer_timeout_marks_the_link_down_and_recomputes() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let start = Instant::now();
        r.start(start);
        r.handle(
            addr(4002),
            Message::LinkAdvert(far_advert("10.0.0.2", 1, "10.0.0.4", LinkState::Up)),
            start,
        );
        assert!(r
            .topology()
            .routes()
            .iter()
            .any(|route| route.dest.addr() == ip("10.0.0.4")));

        // no control messages for longer than link_timeout.
        let later = start + r.config.link_timeout + Duration::from_millis(1);
        r.tick(later);
        assert_eq!(
            r.topology().local_state(node("10.0.0.2")),
            Some(LinkState::Down)
        );
        assert!(
            r.topology().routes().is_empty(),
            "routes through the failed peer remain"
        );
        assert!(
            !r.peers.is_available(addr(4002)),
            "failed peer still marked available"
        );
    }

    #[test]
    fn a_recovered_peer_link_comes_back() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let start = Instant::now();
        r.start(start);
        let later = start + r.config.link_timeout + Duration::from_secs(1);
        r.tick(later);
        assert_eq!(
            r.topology().local_state(node("10.0.0.2")),
            Some(LinkState::Down)
        );

        // a fresh control message arrives from the peer.
        r.handle(
            addr(4002),
            Message::LinkRequest {
                origin: node("10.0.0.2"),
                origin_addr: addr(4002),
            },
            later,
        );
        assert_eq!(
            r.topology().local_state(node("10.0.0.2")),
            Some(LinkState::Up)
        );
        assert!(r.peers.is_available(addr(4002)));
    }

    #[test]
    fn a_stale_advert_does_not_resurrect_a_failed_link() {
        // regression: a delayed/replayed advertisement used to be treated as
        // liveness as soon as it arrived, restoring a link we had marked down
        // and flooding a recovery. a stale advert must not do that.
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let start = Instant::now();
        r.start(start);
        // b first tells a about b -> d at seq 5.
        r.handle(
            addr(4002),
            Message::LinkAdvert(far_advert("10.0.0.2", 5, "10.0.0.4", LinkState::Up)),
            start,
        );
        // then b goes silent long enough to be declared down.
        let later = start + r.config.link_timeout + Duration::from_secs(1);
        r.tick(later);
        assert_eq!(
            r.topology().local_state(node("10.0.0.2")),
            Some(LinkState::Down)
        );

        // a delayed, older copy of b's advert arrives.
        let stale = far_advert("10.0.0.2", 3, "10.0.0.4", LinkState::Up);
        let out = r.handle(addr(4002), Message::LinkAdvert(stale), later);
        assert!(out.is_empty(), "a stale advert was re-flooded");
        assert_eq!(
            r.topology().local_state(node("10.0.0.2")),
            Some(LinkState::Down),
            "a stale advert resurrected the failed link"
        );
        assert_eq!(r.stats().stale, 1);
    }

    #[test]
    fn an_exhausted_advert_is_not_flooded() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002), ("10.0.0.3", 4003)]);
        let now = Instant::now();
        r.start(now);
        let mut advert = far_advert("10.0.0.2", 1, "10.0.0.4", LinkState::Up);
        advert.ttl = 0;
        let out = r.handle(addr(4002), Message::LinkAdvert(advert), now);
        assert!(
            out.iter()
                .all(|(_, msg)| !matches!(msg, Message::LinkAdvert(_))),
            "an advert with no ttl left must not be re-flooded"
        );
        assert_eq!(r.stats().applied, 1, "it is still applied locally");
    }

    #[test]
    fn control_messages_from_non_neighbours_are_ignored() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let now = Instant::now();
        r.start(now);
        let out = r.handle(
            addr(9999),
            Message::LinkAdvert(far_advert("10.0.0.2", 1, "10.0.0.4", LinkState::Up)),
            now,
        );
        assert!(out.is_empty());
        assert_eq!(
            r.stats().applied,
            0,
            "a stranger must not change the topology"
        );
    }

    #[test]
    fn a_link_request_gets_a_snapshot_reply() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let now = Instant::now();
        r.start(now);
        let out = r.handle(
            addr(4002),
            Message::LinkRequest {
                origin: node("10.0.0.2"),
                origin_addr: addr(4002),
            },
            now,
        );
        assert!(
            out.iter().all(|(to, _)| *to == addr(4002)),
            "snapshot replies must be unicast to the requester"
        );
        assert!(
            out.iter().any(
                |(_, msg)| matches!(msg, Message::LinkAdvert(a) if a.origin == node("10.0.0.1"))
            ),
            "the snapshot should include our own links"
        );
    }

    fn test_identity(seed: u8) -> Identity {
        let mut private = [0u8; 32];
        private[0] = seed;
        private[31] = 0x77;
        Identity::from_private(private)
    }

    /// run a full ik handshake locally between two identities.
    fn establish(initiator: &Identity, responder: &Identity) -> (Session, Session) {
        let mut init = Handshake::initiate(initiator, &responder.public()).unwrap();
        let m1 = init.write().unwrap();
        let mut resp = Handshake::respond(responder).unwrap();
        resp.read(&m1).unwrap();
        let m2 = resp.write().unwrap();
        init.read(&m2).unwrap();
        (init.finish().unwrap(), resp.finish().unwrap())
    }

    /// a peer-side session that can seal messages our router will accept.
    struct TestPeer {
        id: NodeId,
        session: Session,
    }

    impl TestPeer {
        fn seal(&self, message: &Message) -> Vec<u8> {
            self.session
                .seal(&control::encode(message).unwrap())
                .unwrap()
        }
    }

    /// a router with an authenticated session to each peer, plus the matching
    /// peer-side sessions so tests can seal accepted messages.
    fn linked_router(specs: &[(&str, u16, u8)]) -> (Router, Vec<TestPeer>) {
        let local_key = test_identity(1);
        let neighbors: Vec<Neighbor> = specs
            .iter()
            .map(|(id, port, _)| Neighbor {
                id: node(id),
                addr: addr(*port),
            })
            .collect();
        let addrs = neighbors.iter().map(|n| n.addr);
        let peers = Arc::new(PeerSet::new(addrs));
        let mut config = RouterConfig::new(node("10.0.0.1"), addr(4001), neighbors);
        config.identity = Some(local_key.clone());
        for (id, _, seed) in specs {
            config
                .peer_keys
                .insert(node(id), test_identity(*seed).public());
        }
        let mut r = Router::new(
            config,
            peers,
            RouteSnapshot::new(RoutingTable::default()),
            LinkSnapshot::new(),
        );
        let now = Instant::now();
        let mut test_peers = Vec::new();
        for (id, port, seed) in specs {
            let peer_key = test_identity(*seed);
            let (ours, theirs) = establish(&local_key, &peer_key);
            let id = node(id);
            let addr = addr(*port);
            let mut ignore = Vec::new();
            r.install_session(id, addr, ours, now, &mut ignore);
            test_peers.push(TestPeer {
                id,
                session: theirs,
            });
        }
        (r, test_peers)
    }

    #[test]
    fn a_remote_static_key_identifies_the_peer() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let start = Instant::now();
        r.start(start);
        assert_eq!(r.stats().sessions, 1);
        assert_eq!(
            r.peer_for_static(&test_identity(2).public()),
            Some(peers[0].id)
        );
    }

    /// a router with an authenticated session enabled toward one neighbour.
    fn authed_router(
        local: &str,
        local_port: u16,
        local_seed: u8,
        neighbor: &str,
        neighbor_port: u16,
        neighbor_seed: u8,
    ) -> Router {
        let mut config = RouterConfig::new(
            node(local),
            addr(local_port),
            vec![Neighbor {
                id: node(neighbor),
                addr: addr(neighbor_port),
            }],
        );
        config.identity = Some(test_identity(local_seed));
        config
            .peer_keys
            .insert(node(neighbor), test_identity(neighbor_seed).public());
        let peers = Arc::new(PeerSet::new([addr(neighbor_port)]));
        Router::new(
            config,
            peers,
            RouteSnapshot::new(RoutingTable::default()),
            LinkSnapshot::new(),
        )
    }

    #[test]
    fn two_routers_complete_a_handshake_and_exchange_control() {
        let now = Instant::now();
        let mut a = authed_router("10.0.0.1", 4001, 1, "10.0.0.2", 4002, 2);
        let mut b = authed_router("10.0.0.2", 4002, 2, "10.0.0.1", 4001, 1);
        let a_id = node("10.0.0.1");
        let b_id = node("10.0.0.2");

        // only the lower identity dials, so exactly one handshake starts.
        assert!(b.ensure_handshakes(now).is_empty());
        let m1 = a.ensure_handshakes(now);
        assert_eq!(m1.len(), 1);
        assert_eq!(m1[0].0, addr(4002));

        // the responder answers and now has a session.
        let (b_out, b_hs) = b.handle_handshake(addr(4001), &m1[0].1, now);
        assert_eq!(b.stats().sessions, 1);
        assert_eq!(b_hs.len(), 1);
        assert!(b_out
            .iter()
            .any(|(_, m)| matches!(m, Message::LinkRequest { .. })));

        // the initiator consumes the response and now has a session too.
        let (a_out, a_hs) = a.handle_handshake(addr(4002), &b_hs[0].1, now);
        assert_eq!(a.stats().sessions, 1);
        assert!(a_hs.is_empty());
        assert!(a_out
            .iter()
            .any(|(_, m)| matches!(m, Message::LinkRequest { .. })));

        // a record sealed by b is accepted by a.
        let punch = control::encode(&Message::Punch {
            origin: b_id,
            token: 7,
        })
        .unwrap();
        let record = b.sessions.get(&a_id).unwrap().session.seal(&punch).unwrap();
        let out = a.handle_body(addr(4002), &record, now);
        assert_eq!(a.endpoint_of(b_id), Some(addr(4002)));
        assert!(out.iter().any(|(to, _)| *to == addr(4002)));
    }

    #[test]
    fn a_handshake_from_an_unknown_key_is_rejected() {
        let now = Instant::now();
        let mut a = authed_router("10.0.0.1", 4001, 1, "10.0.0.2", 4002, 2);

        // an impostor that a has no key for tries to talk to it.
        let impostor = test_identity(9);
        let mut init = Handshake::initiate(&impostor, &a.local_public().unwrap()).unwrap();
        let m1 = init.write().unwrap();

        let (out, hs) = a.handle_handshake(addr(4001), &m1, now);
        assert!(out.is_empty());
        assert!(hs.is_empty());
        assert_eq!(a.stats().sessions, 0);
        assert!(a.stats().unauthorized >= 1);
    }

    #[test]
    fn an_authenticated_endpoint_update_migrates_the_peer() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        // the update arrives from the peer's *new* address, which is not a
        // configured endpoint, but decrypts under its session.
        let update = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs: vec![addr(5002)],
        };
        let out = r.handle_body(addr(5002), &peer.seal(&update), start);
        assert!(
            out.iter()
                .any(|(to, msg)| *to == addr(5002) && matches!(msg, Message::Punch { .. })),
            "a new candidate should be punched"
        );
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(5002)));
        assert!(r.peers.is_known(addr(5002)));
        assert_eq!(
            r.links().get(node("10.0.0.2")),
            Some(Link::Direct(addr(5002)))
        );

        // it moves again; the old address must stop being accepted.
        let update = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 2,
            addrs: vec![addr(6002)],
        };
        r.handle_body(addr(6002), &peer.seal(&update), start);
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(6002)));
        assert!(r.peers.is_known(addr(6002)));
        assert!(
            !r.peers.is_known(addr(5002)),
            "the migrated-away endpoint was not removed"
        );
        assert_eq!(r.stats().migrations, 2);
    }

    #[test]
    fn an_unauthenticated_control_message_is_rejected() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        let update = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs: vec![addr(5002)],
        };
        let raw = control::encode(&update).unwrap();

        // a plaintext body is not a record.
        assert!(r.handle_body(addr(5002), &raw, start).is_empty());
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(4002)));

        // a valid record, then tampered.
        let mut body = peer.seal(&update);
        let last = body.len() - 1;
        body[last] ^= 0x01;
        assert!(r.handle_body(addr(5002), &body, start).is_empty());
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(4002)));

        assert_eq!(r.stats().unauthorized, 2);
    }

    #[test]
    fn a_stale_endpoint_update_is_ignored() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        let update = |epoch: u64, addr: SocketAddr| Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch,
            addrs: vec![addr],
        };
        r.handle_body(addr(5002), &peer.seal(&update(5, addr(5002))), start);
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(5002)));

        // a delayed, older revision must not roll the endpoint back.
        r.handle_body(addr(5002), &peer.seal(&update(3, addr(4002))), start);
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(5002)));
    }

    #[test]
    fn repeated_endpoint_churn_keeps_state_bounded() {
        // resource: a peer that keeps migrating must not grow our accept list or
        // endpoint registry without bound. the migrated-away endpoint is dropped
        // each time, leaving only the configured endpoint and the current one.
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        for i in 0..200u16 {
            let from = addr(7000 + i);
            let punch = Message::Punch {
                origin: node("10.0.0.2"),
                token: u64::from(i),
            };
            r.handle_body(from, &peer.seal(&punch), start);
            assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(from));
        }

        assert!(
            r.peers.len() <= 2,
            "accept list grew to {} entries",
            r.peers.len()
        );
    }

    #[test]
    fn a_control_flood_is_rate_limited() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        let body = peer.seal(&Message::Punch {
            origin: node("10.0.0.2"),
            token: 1,
        });
        // the default burst is small, so a burst of 500 is throttled.
        for _ in 0..500 {
            r.handle_body(addr(5002), &body, start);
        }
        assert!(
            r.stats().rate_limited > 0,
            "a control flood should be rate limited"
        );
    }

    #[test]
    fn the_prober_restores_a_link_that_timed_out() {
        let mut config = RouterConfig::new(
            node("10.0.0.1"),
            addr(4001),
            vec![Neighbor {
                id: node("10.0.0.2"),
                addr: addr(4002),
            }],
        );
        config.heartbeat = Duration::from_millis(100);
        config.link_timeout = Duration::from_millis(300);
        let peers = Arc::new(PeerSet::new([addr(4002)]));
        let mut r = Router::new(
            config,
            peers,
            RouteSnapshot::new(RoutingTable::default()),
            LinkSnapshot::new(),
        );
        let id = node("10.0.0.2");
        let t0 = Instant::now();
        r.start(t0);

        // a quiet neighbour becomes suspect, then gets probed.
        r.tick(t0 + Duration::from_millis(160));
        assert_eq!(r.topology().local_state(id), Some(LinkState::Up));
        let out = r.tick(t0 + Duration::from_millis(200));
        assert!(
            out.iter()
                .any(|(_, m)| matches!(m, Message::LinkRequest { .. })),
            "a suspect neighbour should be probed"
        );

        // past the full timeout the link is down.
        r.tick(t0 + Duration::from_millis(300));
        assert_eq!(r.topology().local_state(id), Some(LinkState::Down));

        // the peer answers the probe and the link comes back up.
        let body = control::encode(&Message::Punch {
            origin: id,
            token: 1,
        })
        .unwrap();
        r.handle_body(addr(4002), &body, t0 + Duration::from_millis(320));
        assert_eq!(r.topology().local_state(id), Some(LinkState::Up));
    }

    #[test]
    fn a_punch_confirms_a_peer_endpoint() {
        let (mut r, peers) = linked_router(&[("10.0.0.2", 4002, 2)]);
        let peer = &peers[0];
        let start = Instant::now();
        r.start(start);

        let punch = Message::Punch {
            origin: node("10.0.0.2"),
            token: 9,
        };
        let out = r.handle_body(addr(5002), &peer.seal(&punch), start);
        assert_eq!(r.endpoint_of(node("10.0.0.2")), Some(addr(5002)));
        assert!(r.peers.is_known(addr(5002)));
        assert!(
            out.iter().any(|(to, _)| *to == addr(5002)),
            "the punch should be echoed back"
        );
    }

    #[test]
    fn a_punch_is_not_echoed_twice() {
        // regression: two configured neighbours could bounce one punch forever
        // because each side satisfied `origin == peer_id` and re-echoed it.
        let now = Instant::now();
        let a_key = test_identity(1);
        let b_key = test_identity(2);
        let mut a = authed_router("10.0.0.1", 4001, 1, "10.0.0.2", 4002, 2);
        let mut b = authed_router("10.0.0.2", 4002, 2, "10.0.0.1", 4001, 1);
        let (a_session, b_session) = establish(&a_key, &b_key);
        let mut ignore = Vec::new();
        a.install_session(node("10.0.0.2"), addr(4002), a_session, now, &mut ignore);
        b.install_session(node("10.0.0.1"), addr(4001), b_session, now, &mut ignore);

        // b announces a new endpoint; a punches it and records the token.
        let update = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs: vec![addr(5002)],
        };
        let b_to_a = b.sessions[&node("10.0.0.1")]
            .session
            .seal(&control::encode(&update).unwrap())
            .unwrap();
        let a_out = a.handle_body(addr(4002), &b_to_a, now);
        let (punch_to, punch_token) = a_out
            .iter()
            .find_map(|(to, m)| match m {
                Message::Punch { token, .. } => Some((*to, *token)),
                _ => None,
            })
            .expect("a should punch b's new endpoint");
        assert!(
            !a.our_punches.is_empty(),
            "a should record the punch token it originated"
        );

        // b receives a's punch and echoes it back.
        let a_punch = Message::Punch {
            origin: node("10.0.0.1"),
            token: punch_token,
        };
        let a_to_b = a.sessions[&node("10.0.0.2")]
            .session
            .seal(&control::encode(&a_punch).unwrap())
            .unwrap();
        let b_out = b.handle_body(punch_to, &a_to_b, now);
        assert_eq!(b_out.len(), 1, "the first punch should be echoed");

        // a receives that echo; it must not send it back again.
        let echo = Message::Punch {
            origin: node("10.0.0.2"),
            token: punch_token,
        };
        let b_to_a = b.sessions[&node("10.0.0.1")]
            .session
            .seal(&control::encode(&echo).unwrap())
            .unwrap();
        let second = a.handle_body(addr(4002), &b_to_a, now);
        assert!(
            second
                .iter()
                .all(|(_, m)| !matches!(m, Message::Punch { .. })),
            "an echoed punch was bounced back, which would loop forever"
        );

        // and a duplicate of the original is not echoed again either.
        let third = b.handle_body(punch_to, &a_to_b, now);
        assert!(third
            .iter()
            .all(|(_, m)| !matches!(m, Message::Punch { .. })));
    }

    #[test]
    fn without_authentication_unknown_sources_are_ignored() {
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let start = Instant::now();
        r.start(start);

        let update = Message::EndpointUpdate {
            origin: node("10.0.0.2"),
            epoch: 1,
            addrs: vec![addr(5002)],
        };
        assert!(r.handle(addr(5002), update, start).is_empty());
        assert_eq!(
            r.endpoint_of(node("10.0.0.2")),
            None,
            "an unauthenticated origin must not migrate an endpoint"
        );
    }

    #[test]
    fn start_publishes_the_initial_route_table() {
        // regression: a node whose only controls are its static neighbours used
        // to publish an empty route table, so locally originated traffic was
        // dropped with NoRoute until the first control message arrived.
        let r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002)]);
        let routes = r.routes();
        assert!(
            routes.lookup(ip("10.0.0.2")).is_some(),
            "the direct neighbour must be routable from startup"
        );
    }

    #[test]
    fn a_neighbour_cannot_forge_another_neighbours_identity() {
        // A peers with B and C. B must not be able to originate a local-link
        // advert *for C* (origin == C), which would let it poison A's view of
        // who is directly reachable.
        let mut r = router("10.0.0.1", 4001, &[("10.0.0.2", 4002), ("10.0.0.3", 4003)]);
        let now = Instant::now();
        r.start(now);

        let forged = far_advert("10.0.0.3", 100, "10.0.0.4", LinkState::Up);
        let out = r.handle(addr(4002), Message::LinkAdvert(forged), now);
        assert!(out.is_empty(), "a forged advert must not be flooded");
        assert_eq!(r.stats().invalid, 1);

        // C's own advert is still accepted.
        let honest = far_advert("10.0.0.3", 1, "10.0.0.4", LinkState::Up);
        r.handle(addr(4003), Message::LinkAdvert(honest), now);
        assert_eq!(r.stats().applied, 1);
    }
}
