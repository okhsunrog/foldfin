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

const QUEUE_BYTES: usize = 1024 * 1024;
#[derive(Default)]
struct Queue {
    packets: VecDeque<Bytes>,
    bytes: usize,
    reader: Option<Waker>,
    writer: Option<Waker>,
}
impl Queue {
    fn push(&mut self, packet: Bytes) -> bool {
        if self.bytes + packet.len() > QUEUE_BYTES {
            return false;
        }
        self.bytes += packet.len();
        self.packets.push_back(packet);
        if let Some(waker) = self.reader.take() {
            waker.wake();
        }
        true
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
        let shared = Shared::default();
        let owner = shared.clone();
        let (finished, terminated) = watch::channel(false);
        let guard = RunnerGuard(owner.clone(), finished);
        let task = tokio::spawn(async move {
            let _guard = guard;
            run(device, owner).await
        });
        Self {
            shared,
            task: Some(task),
            terminated,
        }
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
    for peer in state.peers.values_mut() {
        peer.inbound.wake();
        peer.outbound.wake();
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
                if let Some(peer) = state.peers.get_mut(&old) {
                    peer.inbound.wake();
                    peer.outbound.wake();
                }
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
        if let Some(packet) = queue.pop() {
            if packet.len() > buffer.len() {
                return Poll::Ready(Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "packet receive buffer too small",
                )));
            }
            buffer[..packet.len()].copy_from_slice(&packet);
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
        let peer = state.peers.get_mut(&self.0.id).ok_or_else(closed)?;
        if !vpn::addresses(packet).is_some_and(|(src, dst)| peer.config.incoming(src, dst)) {
            state.stats.rejected_packets += 1;
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                "packet violates peer policy",
            )));
        }
        if peer.inbound.bytes + packet.len() > QUEUE_BYTES {
            peer.inbound.writer = Some(cx.waker().clone());
            return Poll::Pending;
        }
        peer.inbound.push(Bytes::copy_from_slice(packet));
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
                    if !state
                        .peers
                        .get_mut(&id)
                        .unwrap()
                        .outbound
                        .push(Bytes::copy_from_slice(&buffer[..length]))
                    {
                        state.stats.full_queue_drops += 1;
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
