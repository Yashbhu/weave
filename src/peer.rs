//! the set of peers we accept traffic from, and whether each is usable.
//!
//! the m3 lifecycle monitor (probing, suspect/connected/disconnected) is still
//! not implemented as its own service. routing only needs to know which peers
//! are configured and whether each is currently usable, so that is what this
//! does.
//!
//! m6 made this mutable at runtime: when a peer migrates to a new endpoint the
//! control plane adds the new address and removes the old one, so the accept
//! list tracks migration without ever changing the peer's identity. the map is
//! behind a lock because it is read on the data path and written by the control
//! plane.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::RwLock;

/// the peers a node knows about, keyed by their current udp endpoint.
#[derive(Debug, Default)]
pub struct PeerSet {
    peers: RwLock<HashMap<SocketAddr, bool>>,
}

impl PeerSet {
    /// build a set from peer addresses, all marked available.
    pub fn new(addrs: impl IntoIterator<Item = SocketAddr>) -> Self {
        let peers = addrs.into_iter().map(|addr| (addr, true)).collect();
        Self {
            peers: RwLock::new(peers),
        }
    }

    fn read(&self) -> std::sync::RwLockReadGuard<'_, HashMap<SocketAddr, bool>> {
        self.peers
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// is this a configured peer? unknown addresses are ignored on receive.
    pub fn is_known(&self, addr: SocketAddr) -> bool {
        self.read().contains_key(&addr)
    }

    /// can this peer be used as a next hop right now? unknown peers are not.
    pub fn is_available(&self, addr: SocketAddr) -> bool {
        self.read().get(&addr).copied().unwrap_or(false)
    }

    /// mark a peer usable or not. returns false if it wasn't known.
    pub fn set_available(&self, addr: SocketAddr, available: bool) -> bool {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        match peers.get_mut(&addr) {
            Some(state) => {
                *state = available;
                true
            }
            None => false,
        }
    }

    /// add a peer endpoint (e.g. after a validated migration). returns whether
    /// it was newly added. the new endpoint starts available.
    pub fn add(&self, addr: SocketAddr) -> bool {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.insert(addr, true).is_none()
    }

    /// remove a peer endpoint (e.g. the old address a peer migrated away from).
    /// returns whether it was present.
    pub fn remove(&self, addr: SocketAddr) -> bool {
        let mut peers = self
            .peers
            .write()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        peers.remove(&addr).is_some()
    }

    /// number of configured peers.
    pub fn len(&self) -> usize {
        self.read().len()
    }

    /// true when no peers are configured.
    pub fn is_empty(&self) -> bool {
        self.read().is_empty()
    }

    /// every configured peer address.
    pub fn addrs(&self) -> Vec<SocketAddr> {
        self.read().keys().copied().collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn addr(port: u16) -> SocketAddr {
        format!("127.0.0.1:{port}").parse().unwrap()
    }

    #[test]
    fn tracks_known_and_available_peers() {
        let peers = PeerSet::new([addr(1), addr(2)]);
        assert_eq!(peers.len(), 2);
        assert!(peers.is_known(addr(1)));
        assert!(!peers.is_known(addr(3)));
        assert!(peers.is_available(addr(1)));
        assert!(
            !peers.is_available(addr(3)),
            "unknown peers are unavailable"
        );
    }

    #[test]
    fn availability_can_be_flipped() {
        let peers = PeerSet::new([addr(1)]);
        assert!(peers.set_available(addr(1), false));
        assert!(!peers.is_available(addr(1)));
        assert!(peers.set_available(addr(1), true));
        assert!(peers.is_available(addr(1)));
        assert!(!peers.set_available(addr(9), false), "unknown peer");
    }

    #[test]
    fn endpoints_can_be_added_and_removed() {
        let peers = PeerSet::new([addr(1)]);
        assert!(peers.add(addr(2)), "new endpoint added");
        assert!(!peers.add(addr(2)), "adding twice is not new");
        assert!(peers.is_known(addr(2)));

        assert!(peers.remove(addr(1)), "old endpoint removed");
        assert!(!peers.is_known(addr(1)));
        assert!(!peers.remove(addr(1)), "removing twice is a no-op");
        assert_eq!(peers.len(), 1);
    }
}
