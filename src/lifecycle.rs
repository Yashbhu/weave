//! m3: per-peer lifecycle and probing.
//!
//! m5 only knew whether a neighbour had sent us anything within a timeout. this
//! module turns that into a real per-peer lifecycle with explicit states and
//! active probing:
//!
//! ```text
//!            message                silence >= suspect_after
//!   Connected --------> (stays) ----------------------------> Suspect
//!       ^                                                        |
//!       |  message                            silence >= disconnect_after
//!       |                                                        v
//!       +------------------------------------------------ Disconnected
//!                                    (probe with exponential backoff)
//! ```
//!
//! - **Connected**: we have heard from the peer within `suspect_after`.
//! - **Suspect**: the peer has gone quiet. we send a probe every
//!   `probe_interval` to try to confirm it is still there.
//! - **Disconnected**: the peer missed the whole `disconnect_after` window. we
//!   keep probing, but with exponential backoff so a long-dead peer costs less.
//!
//! any inbound message (including a reply to our probe) returns the peer to
//! `connected` and records a round-trip estimate.
//!
//! time is passed into every method, so the state machine is deterministic and
//! testable without sleeping.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use crate::topology::NodeId;

/// the lifecycle state of one peer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PeerState {
    /// heard from recently.
    Connected,
    /// gone quiet; probing.
    Suspect,
    /// missed the full window; probing with backoff.
    Disconnected,
}

impl PeerState {
    /// short label for logs.
    pub fn as_str(self) -> &'static str {
        match self {
            PeerState::Connected => "connected",
            PeerState::Suspect => "suspect",
            PeerState::Disconnected => "disconnected",
        }
    }

    /// is traffic usable in this state?
    pub fn is_live(self) -> bool {
        !matches!(self, PeerState::Disconnected)
    }
}

/// timers for the lifecycle.
#[derive(Debug, Clone, Copy)]
pub struct ProbeConfig {
    /// silence before a peer becomes `suspect`.
    pub suspect_after: Duration,
    /// silence before a peer becomes `disconnected`.
    pub disconnect_after: Duration,
    /// how often to probe a peer that is not `connected`.
    pub probe_interval: Duration,
    /// first backoff when `disconnected`; doubles each failure.
    pub backoff_base: Duration,
    /// cap on the exponential backoff.
    pub backoff_max: Duration,
}

impl ProbeConfig {
    /// derive timers from the control-plane heartbeat and link timeout.
    ///
    /// `disconnect_after` stays exactly the link timeout, so the state machine
    /// agrees with the rest of the control plane about when a neighbour is down.
    pub fn from_timeouts(heartbeat: Duration, link_timeout: Duration) -> Self {
        let heartbeat = heartbeat.max(Duration::from_millis(1));
        let link_timeout = link_timeout.max(Duration::from_millis(1));
        Self {
            suspect_after: (link_timeout / 2).max(heartbeat),
            disconnect_after: link_timeout,
            probe_interval: heartbeat,
            backoff_base: heartbeat,
            backoff_max: link_timeout.max(heartbeat),
        }
    }

    fn backoff(&self, failures: u32) -> Duration {
        let shift = failures.saturating_sub(1).min(16);
        let scaled = self.backoff_base.saturating_mul(1u32 << shift);
        scaled.min(self.backoff_max)
    }
}

/// a snapshot of one peer's lifecycle, for observability and tests.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerStatus {
    /// current state.
    pub state: PeerState,
    /// when the state last changed.
    pub since: Instant,
    /// when we last heard from the peer.
    pub last_heard: Instant,
    /// probes sent since the peer was last connected.
    pub probes: u64,
    /// consecutive failures while not connected.
    pub failures: u32,
    /// most recent round-trip estimate, if a probe was answered.
    pub rtt: Option<Duration>,
}

/// something the control plane should do in response to a transition.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Action {
    /// send a probe to this peer; the reply is what proves it alive.
    Probe(NodeId),
    /// the peer went quiet: mark it suspect.
    WentSuspect(NodeId),
    /// the peer missed the full window.
    WentDown(NodeId),
    /// the peer came back after being suspect or disconnected.
    CameUp(NodeId),
}

#[derive(Debug, Clone, Copy)]
struct Entry {
    state: PeerState,
    since: Instant,
    last_heard: Instant,
    probes: u64,
    failures: u32,
    /// when the next probe is due, while not connected.
    next_probe: Option<Instant>,
    /// when the outstanding probe was sent, to estimate rtt.
    probe_sent: Option<Instant>,
    /// most recent round-trip estimate.
    rtt: Option<Duration>,
}

/// per-peer lifecycle and probing.
#[derive(Debug)]
pub struct Lifecycle {
    config: ProbeConfig,
    peers: HashMap<NodeId, Entry>,
}

impl Lifecycle {
    /// a new lifecycle tracker.
    pub fn new(config: ProbeConfig) -> Self {
        Self {
            config,
            peers: HashMap::new(),
        }
    }

    /// the configuration in use.
    pub fn config(&self) -> ProbeConfig {
        self.config
    }

    /// start tracking a peer, optimistically `connected` as of `now`.
    pub fn track(&mut self, id: NodeId, now: Instant) {
        self.peers.entry(id).or_insert(Entry {
            state: PeerState::Connected,
            since: now,
            last_heard: now,
            probes: 0,
            failures: 0,
            next_probe: None,
            probe_sent: None,
            rtt: None,
        });
    }

    /// record an inbound message from `id`. returns true if this brought the
    /// peer back from suspect/disconnected.
    pub fn on_message(&mut self, id: NodeId, now: Instant) -> bool {
        let Some(entry) = self.peers.get_mut(&id) else {
            // a message from an untracked peer (e.g. a migrating endpoint we
            // have not registered): adopt it as connected.
            self.track(id, now);
            return true;
        };
        let rtt = entry.probe_sent.take().map(|sent| now - sent);
        let was_down = entry.state != PeerState::Connected;
        entry.last_heard = now;
        entry.failures = 0;
        entry.next_probe = None;
        if let Some(rtt) = rtt {
            entry.rtt = Some(rtt);
        }
        if was_down {
            entry.state = PeerState::Connected;
            entry.since = now;
        }
        was_down
    }

    /// the current state of a peer, if tracked.
    pub fn state(&self, id: NodeId) -> Option<PeerState> {
        self.peers.get(&id).map(|entry| entry.state)
    }

    /// a full status snapshot of a peer, if tracked.
    pub fn status(&self, id: NodeId) -> Option<PeerStatus> {
        self.peers.get(&id).map(|entry| PeerStatus {
            state: entry.state,
            since: entry.since,
            last_heard: entry.last_heard,
            probes: entry.probes,
            failures: entry.failures,
            rtt: entry.rtt,
        })
    }

    /// number of peers tracked.
    pub fn len(&self) -> usize {
        self.peers.len()
    }

    /// true when no peers are tracked.
    pub fn is_empty(&self) -> bool {
        self.peers.is_empty()
    }

    /// advance time: transition states and decide which peers to probe.
    pub fn tick(&mut self, now: Instant) -> Vec<Action> {
        let config = self.config;
        let mut actions = Vec::new();
        for (&id, entry) in self.peers.iter_mut() {
            let silent = now.saturating_duration_since(entry.last_heard);
            match entry.state {
                PeerState::Connected => {
                    if silent >= config.disconnect_after {
                        entry.state = PeerState::Disconnected;
                        entry.since = now;
                        entry.failures = 1;
                        entry.next_probe = Some(now + config.backoff(1));
                        actions.push(Action::WentDown(id));
                    } else if silent >= config.suspect_after {
                        entry.state = PeerState::Suspect;
                        entry.since = now;
                        entry.next_probe = Some(now);
                        actions.push(Action::WentSuspect(id));
                    }
                }
                PeerState::Suspect => {
                    if silent >= config.disconnect_after {
                        entry.state = PeerState::Disconnected;
                        entry.since = now;
                        entry.failures = 1;
                        entry.next_probe = Some(now + config.backoff(1));
                        actions.push(Action::WentDown(id));
                    } else if next_due(entry.next_probe, now) {
                        entry.probes += 1;
                        entry.probe_sent = Some(now);
                        entry.next_probe = Some(now + config.probe_interval);
                        actions.push(Action::Probe(id));
                    }
                }
                PeerState::Disconnected => {
                    if next_due(entry.next_probe, now) {
                        entry.probes += 1;
                        entry.failures = entry.failures.saturating_add(1);
                        entry.probe_sent = Some(now);
                        entry.next_probe = Some(now + config.backoff(entry.failures));
                        actions.push(Action::Probe(id));
                    }
                }
            }
        }
        actions
    }
}

fn next_due(next: Option<Instant>, now: Instant) -> bool {
    match next {
        Some(at) => now >= at,
        None => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn node(s: &str) -> NodeId {
        NodeId(s.parse().unwrap())
    }

    fn config() -> ProbeConfig {
        ProbeConfig {
            suspect_after: Duration::from_millis(100),
            disconnect_after: Duration::from_millis(300),
            probe_interval: Duration::from_millis(50),
            backoff_base: Duration::from_millis(50),
            backoff_max: Duration::from_millis(400),
        }
    }

    #[test]
    fn a_tracked_peer_starts_connected() {
        let now = Instant::now();
        let mut l = Lifecycle::new(config());
        l.track(node("10.0.0.2"), now);
        assert_eq!(l.state(node("10.0.0.2")), Some(PeerState::Connected));
        assert!(l.tick(now).is_empty(), "no transitions while connected");
    }

    #[test]
    fn silence_moves_connected_to_suspect_to_disconnected() {
        let now = Instant::now();
        let mut l = Lifecycle::new(config());
        let id = node("10.0.0.2");
        l.track(id, now);

        let suspect = l.tick(now + Duration::from_millis(100));
        assert_eq!(l.state(id), Some(PeerState::Suspect));
        assert_eq!(suspect, vec![Action::WentSuspect(id)]);

        let down = l.tick(now + Duration::from_millis(300));
        assert_eq!(l.state(id), Some(PeerState::Disconnected));
        assert_eq!(down, vec![Action::WentDown(id)]);
    }

    #[test]
    fn a_suspect_peer_is_probed() {
        let now = Instant::now();
        let mut l = Lifecycle::new(config());
        let id = node("10.0.0.2");
        l.track(id, now);

        // go suspect.
        l.tick(now + Duration::from_millis(100));
        // the suspect transition schedules a probe at once.
        let actions = l.tick(now + Duration::from_millis(100));
        assert!(
            actions.contains(&Action::Probe(id)),
            "suspect peer should be probed: {actions:?}"
        );
    }

    #[test]
    fn a_message_brings_a_peer_back_and_records_rtt() {
        let now = Instant::now();
        let mut l = Lifecycle::new(config());
        let id = node("10.0.0.2");
        l.track(id, now);

        l.tick(now + Duration::from_millis(100)); // suspect
        l.tick(now + Duration::from_millis(100)); // probe sent
        let heard = l.on_message(id, now + Duration::from_millis(120));
        assert!(heard, "message should mark recovery");
        assert_eq!(l.state(id), Some(PeerState::Connected));
        assert_eq!(l.status(id).unwrap().rtt, Some(Duration::from_millis(20)));
    }

    #[test]
    fn disconnected_probes_back_off() {
        let now = Instant::now();
        let mut l = Lifecycle::new(config());
        let id = node("10.0.0.2");
        l.track(id, now);
        l.tick(now + Duration::from_millis(300)); // disconnected

        // first probe after backoff(1) = 50ms.
        let first = l.tick(now + Duration::from_millis(350));
        assert!(first.contains(&Action::Probe(id)));

        // the next probe is further away (backoff(2) = 100ms), so an immediate
        // tick finds nothing.
        assert!(l.tick(now + Duration::from_millis(360)).is_empty());
        let second = l.tick(now + Duration::from_millis(470));
        assert!(second.contains(&Action::Probe(id)));
    }

    #[test]
    fn backoff_is_capped() {
        let config = config();
        assert_eq!(config.backoff(1), Duration::from_millis(50));
        assert_eq!(config.backoff(2), Duration::from_millis(100));
        assert_eq!(config.backoff(10), Duration::from_millis(400), "capped");
    }

    #[test]
    fn from_timeouts_keeps_the_link_timeout() {
        let config = ProbeConfig::from_timeouts(Duration::from_secs(1), Duration::from_secs(3));
        assert_eq!(config.disconnect_after, Duration::from_secs(3));
        assert_eq!(config.suspect_after, Duration::from_millis(1500));
    }
}
