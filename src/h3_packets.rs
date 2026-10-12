//! One HTTP datagram reader per carrier, with bounded per-request delivery.
use crate::{
    error::{Error, Result},
    h3_transport::Datagrams,
};
use bytes::Bytes;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::{
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
    task::JoinHandle,
};
const QUEUE_BYTES: usize = 1024 * 1024;
const MAX_AGE: Duration = Duration::from_millis(100);
#[derive(Debug)]
struct Packet {
    bytes: Bytes,
    queued: Instant,
    _permit: OwnedSemaphorePermit,
}
struct Route {
    send: mpsc::Sender<Packet>,
    budget: Arc<Semaphore>,
}
struct Shared {
    routes: Mutex<HashMap<u64, Route>>,
    drops: AtomicU64,
    closed: std::sync::atomic::AtomicBool,
}
impl Shared {
    fn deliver(&self, id: u64, bytes: Bytes) {
        let routes = self.routes.lock().unwrap();
        let Some(route) = routes.get(&id) else {
            return;
        };
        if bytes.is_empty() || bytes.len() > crate::vpn::MTU {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        }
        let Ok(permit) = route
            .budget
            .clone()
            .try_acquire_many_owned(bytes.len() as u32)
        else {
            self.drops.fetch_add(1, Ordering::Relaxed);
            return;
        };
        if route
            .send
            .try_send(Packet {
                bytes,
                queued: Instant::now(),
                _permit: permit,
            })
            .is_err()
        {
            self.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}

#[cfg(any(feature = "client", feature = "server"))]
pub(crate) struct Capsules {
    shared: Arc<Shared>,
    id: u64,
}
#[cfg(any(feature = "client", feature = "server"))]
impl Capsules {
    pub(crate) fn send(&self, bytes: Bytes) {
        self.shared.deliver(self.id, bytes);
    }
}
pub struct Hub {
    shared: Arc<Shared>,
    datagrams: Datagrams,
    task: Option<JoinHandle<()>>,
}
impl Hub {
    pub fn new(mut datagrams: Datagrams) -> Self {
        let shared = Arc::new(Shared {
            routes: Mutex::new(HashMap::new()),
            drops: AtomicU64::new(0),
            closed: false.into(),
        });
        let read = shared.clone();
        let send = datagrams.clone();
        let task = tokio::spawn(async move {
            while let Ok((id, bytes)) = datagrams.recv().await {
                read.deliver(id, bytes);
            }
            read.closed.store(true, Ordering::Release);
            read.routes.lock().unwrap().clear();
        });
        Self {
            shared,
            datagrams: send,
            task: Some(task),
        }
    }
    pub fn subscribe(&self, id: u64) -> Result<(Sender, Receiver)> {
        let mut routes = self.shared.routes.lock().unwrap();
        if self.shared.closed.load(Ordering::Acquire) {
            return Err(Error::Closed);
        }
        if routes.contains_key(&id) {
            return Err(Error::InvalidConfig(
                "datagram stream already registered".into(),
            ));
        }
        let (send, recv) = mpsc::channel(1024);
        routes.insert(
            id,
            Route {
                send,
                budget: Arc::new(Semaphore::new(QUEUE_BYTES)),
            },
        );
        Ok((
            Sender {
                datagrams: self.datagrams.clone(),
                id,
            },
            Receiver {
                recv,
                shared: self.shared.clone(),
                id,
            },
        ))
    }
    pub fn dropped(&self) -> u64 {
        self.shared.drops.load(Ordering::Relaxed)
    }
    pub async fn stop(&mut self) {
        if let Some(task) = self.task.as_mut() {
            task.abort();
            let _ = task.await;
        }
        self.task.take();
        self.shared.closed.store(true, Ordering::Release);
        self.shared.routes.lock().unwrap().clear();
    }
}
impl Drop for Hub {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        self.shared.closed.store(true, Ordering::Release);
        self.shared.routes.lock().unwrap().clear();
    }
}
#[derive(Clone)]
pub struct Sender {
    datagrams: Datagrams,
    id: u64,
}
impl Sender {
    pub async fn require_vpn_mtu(&self) -> Result<()> {
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match self.datagrams.require_mtu(self.id, 1280) {
                Ok(()) => return Ok(()),
                Err(Error::PathMtu { .. }) if Instant::now() < deadline => {
                    tokio::time::sleep(Duration::from_millis(10)).await
                }
                Err(error) => return Err(error),
            }
        }
    }
    pub fn send(&self, packet: Bytes) -> Result<()> {
        self.datagrams.send(self.id, packet)
    }
}
pub struct Receiver {
    recv: mpsc::Receiver<Packet>,
    shared: Arc<Shared>,
    id: u64,
}
impl Receiver {
    #[cfg(any(feature = "client", feature = "server"))]
    pub(crate) fn capsules(&self) -> Capsules {
        Capsules {
            shared: self.shared.clone(),
            id: self.id,
        }
    }
    pub async fn recv(&mut self) -> Result<Bytes> {
        loop {
            let packet = self.recv.recv().await.ok_or(Error::Closed)?;
            if packet.queued.elapsed() <= MAX_AGE {
                return Ok(packet.bytes);
            }
            self.shared.drops.fetch_add(1, Ordering::Relaxed);
        }
    }
}
impl Drop for Receiver {
    fn drop(&mut self) {
        self.shared.routes.lock().unwrap().remove(&self.id);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn datagram_queue_enforces_bytes_age_and_releases_budget() {
        let (send, recv) = mpsc::channel(1024);
        let budget = Arc::new(Semaphore::new(QUEUE_BYTES));
        let shared = Arc::new(Shared {
            routes: Mutex::new(HashMap::from([(
                0,
                Route {
                    send: send.clone(),
                    budget: budget.clone(),
                },
            )])),
            drops: AtomicU64::new(0),
            closed: false.into(),
        });
        let mut receiver = Receiver {
            recv,
            shared: shared.clone(),
            id: 0,
        };
        // No clock sleeps: the oldest packet is already past the delivery deadline.
        send.try_send(Packet {
            bytes: Bytes::from_static(b"old"),
            queued: Instant::now() - Duration::from_secs(1),
            _permit: budget.clone().try_acquire_many_owned(3).unwrap(),
        })
        .unwrap();
        shared.deliver(0, Bytes::from_static(b"new"));
        assert_eq!(receiver.recv().await.unwrap(), Bytes::from_static(b"new"));
        assert_eq!(shared.drops.load(Ordering::Relaxed), 1);
        assert_eq!(budget.available_permits(), QUEUE_BYTES);
        for _ in 0..1024 {
            shared.deliver(0, Bytes::from(vec![1; 1280]));
        }
        assert_eq!(budget.available_permits(), QUEUE_BYTES % 1280);
        assert_eq!(
            shared.drops.load(Ordering::Relaxed),
            1 + 1024 - (QUEUE_BYTES / 1280) as u64
        );
        drop(receiver);
        assert_eq!(budget.available_permits(), QUEUE_BYTES);
        assert!(shared.routes.lock().unwrap().is_empty());
    }
}
