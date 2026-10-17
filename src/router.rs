//! One packet-device owner for multiple authenticated peers. The host configures
//! the TUN, forwarding and egress; this router only dispatches complete IP packets.
use crate::{
    admission::PeerId,
    packet::{PacketDevice, PacketDeviceFactory, PacketRecv, PacketSend},
    vpn,
};
use bytes::Bytes;
use ipnet::IpNet;
use std::{
    collections::{HashMap, VecDeque},
    future::poll_fn,
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll, Waker},
};
use tokio::{sync::watch, task::JoinHandle};

/// Payload limits for router queues, excluding transport buffers and one packet
/// being written to the device. Limits do not reserve memory or promise fairness.
#[derive(Clone, Copy, Debug)]
pub struct RouterConfig {
    /// Payload capacity of each peer queue, separately for each direction.
    pub per_peer_queue_bytes: usize,
    /// Shared payload capacity across both directions and all peer queues.
    pub total_queue_bytes: usize,
}
impl Default for RouterConfig {
    fn default() -> Self {
        Self {
            per_peer_queue_bytes: 1024 * 1024,
            total_queue_bytes: 64 * 1024 * 1024,
        }
    }
}
#[derive(Default)]
struct Queue {
    packets: VecDeque<Bytes>,
    bytes: usize,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
impl Queue {
    fn push(&mut self, packet: Bytes) {
        self.bytes += packet.len();
        self.packets.push_back(packet);
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
    }
    fn pop(&mut self) -> Option<Bytes> {
        let packet = self.packets.pop_front()?;
        self.bytes -= packet.len();
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
        Some(packet)
    }
    fn wake(&mut self) {
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        if let Some(waker) = self.writer.take() {
            waker.wake();
        }
    }
}
struct Peer {
    identity: PeerId,
    config: vpn::Config,
    prefixes: Vec<IpNet>,
    outbound: Queue,
    inbound: Queue,
}
#[derive(Default)]
struct State {
    config: RouterConfig,
    budget_waiters: HashMap<u64, Waker>,
    next: u64,
    peers: HashMap<u64, Peer>,
    active: HashMap<PeerId, u64>,
    round_robin: VecDeque<u64>,
    input_waker: Option<Waker>,
    output_waker: Option<Waker>,
    closed: bool,
    stats: RouterStats,
}
#[derive(Clone, Copy, Debug, Default)]
pub struct RouterStats {
    pub unroutable_packets: u64,
    pub full_queue_drops: u64,
    pub rejected_packets: u64,
    /// Current queued payload, both directions and all registrations.
    pub queued_bytes: usize,
    pub peak_queued_bytes: usize,
    /// Outbound drops caused by the shared budget (also in full_queue_drops).
    pub global_budget_drops: u64,
}
impl State {
    fn reserve(&mut self, bytes: usize) {
        self.stats.queued_bytes += bytes;
        self.stats.peak_queued_bytes = self.stats.peak_queued_bytes.max(self.stats.queued_bytes);
    }
    fn release(&mut self, bytes: usize) {
        self.stats.queued_bytes -= bytes;
        if bytes != 0 {
            for (_, waker) in self.budget_waiters.drain() {
                waker.wake();
            }
        }
    }
    fn clear_peer(&mut self, id: u64) {
        if let Some(peer) = self.peers.get_mut(&id) {
            peer.inbound.wake();
            peer.outbound.wake();
            let bytes = peer.inbound.bytes + peer.outbound.bytes;
            peer.inbound = Queue::default();
            peer.outbound = Queue::default();
            self.release(bytes);
        }
        if let Some(waker) = self.budget_waiters.remove(&id) {
            waker.wake();
        }
    }
}
type Shared = Arc<Mutex<State>>;

pub struct Router {
    shared: Shared,
    task: Option<JoinHandle<io::Result<()>>>,
    terminated: watch::Receiver<bool>,
}
// Also close peer queues if a host packet adapter panics or the runner is aborted.
struct RunnerGuard(Shared, watch::Sender<bool>);
impl Drop for RunnerGuard {
    fn drop(&mut self) {
        close(&self.0);
        self.1.send_replace(true);
    }
}
impl Router {
    pub fn start(device: PacketDevice) -> Self {
        Self::start_with_config(device, RouterConfig::default())
            .expect("valid default router limits")
    }
    /// Each limit must fit a complete engine packet. A full inbound queue applies
    /// backpressure; a full outbound queue drops without stalling other peers.
    pub fn start_with_config(device: PacketDevice, config: RouterConfig) -> io::Result<Self> {
        if config.per_peer_queue_bytes < vpn::MTU || config.total_queue_bytes < vpn::MTU {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "router limits must fit the VPN MTU",
            ));
        }
        let shared = Arc::new(Mutex::new(State {
            config,
            ..State::default()
        }));
        let owner = shared.clone();
        let (finished, terminated) = watch::channel(false);
        let guard = RunnerGuard(owner.clone(), finished);
        let task = tokio::spawn(async move {
            let _guard = guard;
            run(device, owner).await
        });
        Ok(Self {
            shared,
            task: Some(task),
            terminated,
        })
    }
    /// Supervise packet IO alongside listeners and control-plane synchronization.
    /// Cancellation-safe; call `stop` afterwards to join and retrieve the failure.
    pub async fn closed(&self) {
        let mut terminated = self.terminated.clone();
        let _ = terminated.wait_for(|finished| *finished).await;
    }
    /// Creates an inert factory. `open` reserves prefixes and prepares queues;
    /// routes activate on the first packet poll, after server admission commits.
    pub fn peer(
        &self,
        identity: PeerId,
        config: vpn::Config,
    ) -> crate::error::Result<Arc<dyn PacketDeviceFactory>> {
        config.validate()?;
        Ok(Arc::new(Factory {
            shared: self.shared.clone(),
            identity,
            config,
        }))
    }
    pub fn stats(&self) -> RouterStats {
        self.shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stats
    }
    pub async fn stop(&mut self) -> io::Result<()> {
        let result = if let Some(task) = self.task.as_mut() {
            task.abort();
            match task.await {
                Ok(result) => result,
                Err(e) if e.is_cancelled() => Ok(()),
                Err(e) => Err(io::Error::other(e)),
            }
        } else {
            Ok(())
        };
        self.task.take();
        close(&self.shared);
        result
    }
}
impl Drop for Router {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
        close(&self.shared);
    }
}
fn closed() -> io::Error {
    io::Error::new(
        io::ErrorKind::BrokenPipe,
        "packet router closed or peer replaced",
    )
}
fn close(shared: &Shared) {
    // The host's poll_send implementation may have panicked while holding this
    // lock. Teardown must still wake waiters rather than panic during unwinding.
    let mut state = shared.lock().unwrap_or_else(|poison| poison.into_inner());
    state.closed = true;
    for id in state.peers.keys().copied().collect::<Vec<_>>() {
        state.clear_peer(id);
    }
    if let Some(waker) = state.input_waker.take() {
        waker.wake();
    }
    if let Some(waker) = state.output_waker.take() {
        waker.wake();
    }
}
struct Factory {
    shared: Shared,
    identity: PeerId,
    config: vpn::Config,
}
impl PacketDeviceFactory for Factory {
    fn open(&self) -> io::Result<PacketDevice> {
        let prefixes: Vec<_> = self
            .config
            .peer
            .iter()
            .copied()
            .map(IpNet::from)
            .chain(self.config.peer_routes.iter().copied())
            .collect();
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(closed());
        }
        if state.peers.values().any(|other| {
            other.identity != self.identity
                && other.prefixes.iter().any(|a| {
                    prefixes
                        .iter()
                        .any(|b| a.contains(&b.network()) || b.contains(&a.network()))
                })
        }) {
            return Err(io::Error::new(
                io::ErrorKind::AddrInUse,
                "peer prefixes overlap another peer",
            ));
        }
        state.next = state
            .next
            .checked_add(1)
            .ok_or_else(|| io::Error::other("router generation exhausted"))?;
        let id = state.next;
        state.peers.insert(
            id,
            Peer {
                identity: self.identity.clone(),
                config: self.config.clone(),
                prefixes,
                outbound: Queue::default(),
                inbound: Queue::default(),
            },
        );
        let registration = Arc::new(Registration {
            shared: self.shared.clone(),
            id,
            activated: Mutex::new(false),
        });
        Ok(PacketDevice::new(
            Reader(registration.clone()),
            Writer(registration),
        ))
    }
}
struct Registration {
    shared: Shared,
    id: u64,
    activated: Mutex<bool>,
}
impl Registration {
    fn activate(&self) -> io::Result<()> {
        let mut activated = self
            .activated
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed {
            return Err(closed());
        }
        let identity = state
            .peers
            .get(&self.id)
            .ok_or_else(closed)?
            .identity
            .clone();
        if !*activated {
            if let Some(old) = state.active.insert(identity.clone(), self.id) {
                state.round_robin.retain(|id| *id != old);
                state.clear_peer(old);
            }
            state.round_robin.push_back(self.id);
            if let Some(waker) = state.output_waker.take() {
                waker.wake();
            }
            *activated = true;
            if let Some(waker) = state.input_waker.take() {
                waker.wake();
            }
        }
        if state.active.get(&identity) != Some(&self.id) {
            return Err(closed());
        }
        Ok(())
    }
}
impl Drop for Registration {
    fn drop(&mut self) {
        let mut state = self
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.clear_peer(self.id);
        if let Some(peer) = state.peers.remove(&self.id)
            && state.active.get(&peer.identity) == Some(&self.id)
        {
            state.active.remove(&peer.identity);
        }
        state.round_robin.retain(|id| *id != self.id);
        if let Some(waker) = state.output_waker.take() {
            waker.wake();
        }
    }
}
struct Reader(Arc<Registration>);
impl PacketRecv for Reader {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        self.0.activate()?;
        let mut state = self
            .0
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed
            || !state
                .peers
                .get(&self.0.id)
                .is_some_and(|p| state.active.get(&p.identity) == Some(&self.0.id))
        {
            return Poll::Ready(Err(closed()));
        }
        let queue = &mut state.peers.get_mut(&self.0.id).ok_or_else(closed)?.outbound;
        if let Some(packet) = queue.packets.front() {
            if packet.len() > buffer.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet receive buffer too small",
                )));
            }
            let packet = queue.pop().unwrap();
            buffer[..packet.len()].copy_from_slice(&packet);
            state.release(packet.len());
            Poll::Ready(Ok(packet.len()))
        } else {
            queue.reader = Some(cx.waker().clone());
            Poll::Pending
        }
    }
}
struct Writer(Arc<Registration>);
impl PacketSend for Writer {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        self.0.activate()?;
        let mut state = self
            .0
            .shared
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.closed
            || !state
                .peers
                .get(&self.0.id)
                .is_some_and(|p| state.active.get(&p.identity) == Some(&self.0.id))
        {
            return Poll::Ready(Err(closed()));
        }
        let limit = state.config.per_peer_queue_bytes;
        let peer = state.peers.get_mut(&self.0.id).ok_or_else(closed)?;
        if !vpn::addresses(packet).is_some_and(|(src, dst)| peer.config.incoming(src, dst)) {
            state.stats.rejected_packets += 1;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet violates peer policy",
            )));
        }
        if packet.len() > limit {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds queue limit",
            )));
        }
        if peer.inbound.bytes > limit - packet.len() {
            peer.inbound.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        if packet.len() > state.config.total_queue_bytes {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "packet exceeds router budget",
            )));
        }
        if state.stats.queued_bytes > state.config.total_queue_bytes - packet.len() {
            state.budget_waiters.insert(self.0.id, cx.waker().clone());
            return Poll::Pending;
        }
        state.budget_waiters.remove(&self.0.id);
        state
            .peers
            .get_mut(&self.0.id)
            .unwrap()
            .inbound
            .push(Bytes::copy_from_slice(packet));
        state.reserve(packet.len());
        if let Some(waker) = state.input_waker.take() {
            waker.wake();
        }
        Poll::Ready(Ok(()))
    }
}
async fn run(mut device: PacketDevice, shared: Shared) -> io::Result<()> {
    let outbound = async {
        let mut buffer = vec![0; 65536];
        let mut work = 0;
        loop {
            let length = poll_fn(|cx| device.recv.poll_recv(cx, &mut buffer)).await?;
            if length == 0 {
                return Err(closed());
            }
            {
                let mut state = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                let selected = vpn::addresses(&buffer[..length]).and_then(|(src, dst)| {
                    state
                        .active
                        .values()
                        .copied()
                        .find(|id| state.peers[id].config.incoming(dst, src))
                });
                if let Some(id) = selected {
                    let global_full = length
                        > state
                            .config
                            .total_queue_bytes
                            .saturating_sub(state.stats.queued_bytes);
                    let peer_full = length
                        > state
                            .config
                            .per_peer_queue_bytes
                            .saturating_sub(state.peers[&id].outbound.bytes);
                    if global_full || peer_full {
                        state.stats.full_queue_drops += 1;
                        state.stats.global_budget_drops += u64::from(global_full);
                    } else {
                        state
                            .peers
                            .get_mut(&id)
                            .unwrap()
                            .outbound
                            .push(Bytes::copy_from_slice(&buffer[..length]));
                        state.reserve(length);
                    }
                } else {
                    state.stats.unroutable_packets += 1;
                }
            }
            work += 1;
            if work == 32 {
                work = 0;
                tokio::task::yield_now().await;
            }
        }
    };
    let inbound = async {
        loop {
            let (id, packet) = poll_fn(|cx| {
                let mut state = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.closed {
                    return Poll::Ready(Err(closed()));
                }
                for _ in 0..state.round_robin.len() {
                    let id = state.round_robin.pop_front().unwrap();
                    state.round_robin.push_back(id);
                    if let Some(packet) = state.peers.get_mut(&id).unwrap().inbound.pop() {
                        state.release(packet.len());
                        return Poll::Ready(Ok((id, packet)));
                    }
                }
                state.input_waker = Some(cx.waker().clone());
                Poll::Pending
            })
            .await?;
            poll_fn(|cx| {
                // Serialize a pending write with replacement/revocation. An old
                // generation cannot resume writing after a successor activates.
                let mut state = shared
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if !state
                    .peers
                    .get(&id)
                    .is_some_and(|p| state.active.get(&p.identity) == Some(&id))
                {
                    return Poll::Ready(Ok(()));
                }
                let result = device.send.poll_send(cx, &packet);
                state.output_waker = result.is_pending().then(|| cx.waker().clone());
                result
            })
            .await?;
            tokio::task::yield_now().await;
        }
        #[allow(unreachable_code)]
        Ok::<(), io::Error>(())
    };
    tokio::select! { result = outbound => result, result = inbound => result }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        sync::atomic::{AtomicUsize, Ordering},
        task::Wake,
    };
    struct Count(AtomicUsize);
    impl Wake for Count {
        fn wake(self: Arc<Self>) {
            self.0.fetch_add(1, Ordering::SeqCst);
        }
    }
    fn factory(shared: &Shared, name: &str, suffix: u8) -> Factory {
        Factory {
            shared: shared.clone(),
            identity: PeerId::new(name).unwrap(),
            config: vpn::Config {
                local: vec!["198.18.0.10".parse().unwrap()],
                peer: vec![format!("198.18.0.{suffix}").parse().unwrap()],
                local_routes: vec![],
                peer_routes: vec![],
            },
        }
    }
    fn packet(suffix: u8) -> Vec<u8> {
        let mut p = vec![0; 1500];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1500_u16.to_be_bytes());
        p[12..16].copy_from_slice(&[198, 18, 0, suffix]);
        p[16..20].copy_from_slice(&[198, 18, 0, 10]);
        p
    }
    #[test]
    fn shared_budget_wakes_other_peer_after_drop_and_replacement() {
        let shared = Arc::new(Mutex::new(State {
            config: RouterConfig {
                per_peer_queue_bytes: 3000,
                total_queue_bytes: 1500,
            },
            ..State::default()
        }));
        let first = factory(&shared, "first", 1);
        let mut one = first.open().unwrap();
        let mut two = factory(&shared, "second", 2).open().unwrap();
        let count = Arc::new(Count(AtomicUsize::new(0)));
        let waker = Waker::from(count.clone());
        let mut cx = Context::from_waker(&waker);
        assert!(matches!(
            one.send.poll_send(&mut cx, &packet(1)),
            Poll::Ready(Ok(()))
        ));
        assert!(two.send.poll_send(&mut cx, &packet(2)).is_pending());
        // Replacement must release old queued bytes even if old handles survive.
        let mut replacement = first.open().unwrap();
        assert!(
            replacement
                .recv
                .poll_recv(&mut cx, &mut [0; 1500])
                .is_pending()
        );
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert_eq!(shared.lock().unwrap().stats.queued_bytes, 0);
        assert!(matches!(
            two.send.poll_send(&mut cx, &packet(2)),
            Poll::Ready(Ok(()))
        ));
        assert!(replacement.send.poll_send(&mut cx, &packet(1)).is_pending());
        count.0.store(0, Ordering::SeqCst);
        drop(two);
        assert!(count.0.load(Ordering::SeqCst) > 0);
        assert!(matches!(
            replacement.send.poll_send(&mut cx, &packet(1)),
            Poll::Ready(Ok(()))
        ));
        drop(one);
        assert_eq!(shared.lock().unwrap().stats.queued_bytes, 1500);
        drop(replacement);
        assert_eq!(shared.lock().unwrap().stats.queued_bytes, 0);
    }
}
