//! Server-owned two-phase session replacement. Authorization only supplies identity.
use crate::{
    authorization::{AccessGrant, AccessLease, LeaseState},
    error::{Error, Result},
};
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::sync::watch;

#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct PeerId(String);
impl PeerId {
    pub fn new(value: impl Into<String>) -> Result<Self> {
        let value = value.into();
        if value.is_empty() || value.len() > 256 || value.chars().any(char::is_control) {
            return Err(Error::InvalidConfig("invalid peer identity".into()));
        }
        Ok(Self(value))
    }
}
struct Active {
    generation: u64,
    revoke: watch::Sender<LeaseState>,
}
#[derive(Default)]
struct State {
    next: u64,
    peers: HashMap<PeerId, Active>,
}
#[derive(Clone, Default)]
pub(crate) struct Registry(Arc<Mutex<State>>);
pub(crate) struct Prepared {
    registry: Registry,
    peer: PeerId,
    expected: Option<u64>,
}
pub(crate) struct Owner {
    registry: Registry,
    peer: PeerId,
    generation: u64,
    pub lease: AccessLease,
}
impl Registry {
    pub fn prepare(&self, peer: PeerId) -> Prepared {
        let expected = self
            .0
            .lock()
            .unwrap()
            .peers
            .get(&peer)
            .map(|a| a.generation);
        Prepared {
            registry: self.clone(),
            peer,
            expected,
        }
    }
}
impl Prepared {
    /// Call only after syntax, policy and packet-device preparation succeeded.
    /// No await occurs between validation and replacing the active generation.
    pub fn commit(self, grant: &AccessGrant) -> Result<Owner> {
        let mut state = self.registry.0.lock().unwrap();
        if !grant.valid() {
            return Err(Error::Rejected(403));
        }
        if state.peers.get(&self.peer).map(|a| a.generation) != self.expected {
            return Err(Error::Rejected(409));
        }
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| Error::InvalidConfig("session generation exhausted".into()))?;
        let generation = state.next;
        let (revoke, lease) = AccessLease::new(None);
        if let Some(old) = state
            .peers
            .insert(self.peer.clone(), Active { generation, revoke })
        {
            old.revoke.send_replace(LeaseState::Revoked);
        }
        drop(state);
        Ok(Owner {
            registry: self.registry,
            peer: self.peer,
            generation,
            lease,
        })
    }
}
impl Drop for Owner {
    fn drop(&mut self) {
        let mut state = self.registry.0.lock().unwrap();
        if state
            .peers
            .get(&self.peer)
            .is_some_and(|a| a.generation == self.generation)
        {
            state.peers.remove(&self.peer);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn aborted_and_stale_preparations_preserve_the_current_owner() {
        let registry = Registry::default();
        let peer = PeerId::new("device").unwrap();
        let (_keepalive, lease) = AccessLease::new(None);
        let grant = AccessGrant {
            proxy: false,
            allow_private: false,
            vpn: None,
            vpn_slots: Arc::new(tokio::sync::Semaphore::new(1)),
            lease,
            session: None,
            peer: Some(peer.clone()),
        };
        let first = registry.prepare(peer.clone()).commit(&grant).unwrap();
        drop(registry.prepare(peer.clone()));
        assert!(first.lease.valid());
        let losing = registry.prepare(peer.clone());
        let successor = registry.prepare(peer.clone()).commit(&grant).unwrap();
        assert!(!first.lease.valid());
        assert!(losing.commit(&grant).is_err());
        drop(first);
        assert!(successor.lease.valid());
        let prepared = registry.prepare(peer.clone());
        let (revoke, lease) = AccessLease::new(None);
        revoke.send_replace(LeaseState::Revoked);
        let revoked = AccessGrant { lease, ..grant };
        assert!(prepared.commit(&revoked).is_err());
        assert!(successor.lease.valid());
    }
}
