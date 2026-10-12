//! Payload counters exclude TLS/H2 framing and control capsules.
use std::time::Duration;
#[derive(Clone, Debug)]
pub enum SessionState {
    AwaitingConfiguration,
    Running,
    Closed,
    Failed { detail: String },
}
#[derive(Clone, Debug)]
pub struct TrafficStats {
    pub tx_bytes: u64,
    pub rx_bytes: u64,
    pub uptime: Duration,
    /// Age of nonempty payload in either direction.
    pub since_last_payload: Option<Duration>,
    /// Inbound payload age, for peer reachability evidence.
    pub since_last_rx_payload: Option<Duration>,
}
#[cfg(any(feature = "client", feature = "server"))]
use std::{
    sync::{
        Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};
#[cfg(any(feature = "client", feature = "server"))]
pub(crate) struct Counters {
    tx: AtomicU64,
    rx: AtomicU64,
    started: Instant,
    last_payload: Mutex<Option<Instant>>,
    last_rx: Mutex<Option<Instant>>,
}
#[cfg(any(feature = "client", feature = "server"))]
impl Default for Counters {
    fn default() -> Self {
        Self {
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            started: Instant::now(),
            last_payload: Mutex::new(None),
            last_rx: Mutex::new(None),
        }
    }
}
#[cfg(any(feature = "client", feature = "server"))]
impl Counters {
    pub(crate) fn tx(&self, n: usize) {
        self.tx.fetch_add(n as u64, Ordering::Relaxed);
        self.activity(n);
    }
    pub(crate) fn rx(&self, n: usize) {
        self.rx.fetch_add(n as u64, Ordering::Relaxed);
        if n != 0 {
            *self.last_rx.lock().unwrap() = Some(Instant::now());
        }
        self.activity(n);
    }
    fn activity(&self, n: usize) {
        if n != 0 {
            *self.last_payload.lock().unwrap() = Some(Instant::now());
        }
    }
    pub(crate) fn snapshot(&self) -> TrafficStats {
        TrafficStats {
            tx_bytes: self.tx.load(Ordering::Relaxed),
            rx_bytes: self.rx.load(Ordering::Relaxed),
            uptime: self.started.elapsed(),
            since_last_payload: self.last_payload.lock().unwrap().map(|t| t.elapsed()),
            since_last_rx_payload: self.last_rx.lock().unwrap().map(|t| t.elapsed()),
        }
    }
}
#[cfg(all(test, any(feature = "client", feature = "server")))]
mod tests {
    use super::*;
    #[test]
    fn upload_updates_activity_but_does_not_invent_inbound_evidence() {
        let counters = Counters::default();
        counters.tx(0);
        assert!(counters.snapshot().since_last_payload.is_none());
        counters.tx(12);
        assert!(counters.snapshot().since_last_payload.is_some());
        assert!(counters.snapshot().since_last_rx_payload.is_none());
        counters.rx(3);
        assert!(counters.snapshot().since_last_rx_payload.is_some());
    }
}
