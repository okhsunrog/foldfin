//! A VPN session owns its packet device across carrier loss and explicit recovery.
//! The host supplies each connected carrier and decides when/how to retry.
use crate::{
    client::{Client as H2Client, VpnTunnel},
    error::{Error, Result},
    packet::{PacketDevice, PacketRecv, PacketSend},
    stats::{SessionState, TrafficStats},
    vpn,
};
use std::{
    io,
    sync::{Arc, Mutex},
    task::{Context, Poll},
    time::Instant,
};
use tokio::{sync::watch, task::JoinHandle};

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Event {
    Preparing,
    Running,
    CarrierLost { detail: String },
    Recovering,
    Closed,
}

/// A prepared carrier supplied by the host's transport/underlay policy.
#[derive(Clone)]
pub enum Carrier {
    H2(H2Client),
    #[cfg(feature = "h3")]
    H3(crate::h3_client::Client),
}
impl From<H2Client> for Carrier {
    fn from(client: H2Client) -> Self {
        Self::H2(client)
    }
}
#[cfg(feature = "h3")]
impl From<crate::h3_client::Client> for Carrier {
    fn from(client: crate::h3_client::Client) -> Self {
        Self::H3(client)
    }
}
pub(crate) enum Prepared {
    H2(crate::client::PreparedVpn),
    #[cfg(feature = "h3")]
    H3(Box<crate::h3_client::PreparedVpn>),
}
impl Prepared {
    pub(crate) fn start(self, device: PacketDevice) -> VpnTunnel {
        match self {
            Self::H2(p) => p.start(device),
            #[cfg(feature = "h3")]
            Self::H3(p) => p.start(device),
        }
    }
}
/// Transport-neutral TCP flow used by host proxy adapters.
pub trait TcpStream: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send {}
impl<T: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send> TcpStream for T {}
impl Carrier {
    pub async fn open_tcp(&self, target: &str) -> Result<Box<dyn TcpStream>> {
        match self {
            Self::H2(client) => Ok(Box::new(client.open_tcp(target).await?)),
            #[cfg(feature = "h3")]
            Self::H3(client) => Ok(Box::new(client.open_tcp(target).await?)),
        }
    }
    pub async fn closed(&self) {
        match self {
            Self::H2(client) => {
                let mut state = client.subscribe();
                while matches!(*state.borrow_and_update(), SessionState::Running) {
                    if state.changed().await.is_err() {
                        break;
                    }
                }
            }
            #[cfg(feature = "h3")]
            Self::H3(client) => client.closed().await,
        }
    }
    pub(crate) async fn prepare_vpn(&self, config: vpn::Config) -> Result<Prepared> {
        match self {
            Self::H2(c) => c.prepare_vpn(config).await.map(Prepared::H2),
            #[cfg(feature = "h3")]
            Self::H3(c) => c
                .prepare_vpn(config)
                .await
                .map(|p| Prepared::H3(Box::new(p))),
        }
    }
    pub async fn stop(&self) -> Result<()> {
        match self {
            Self::H2(c) => c.clone().stop().await,
            #[cfg(feature = "h3")]
            Self::H3(c) => c.stop().await,
        }
    }
    async fn probe(&self) -> Result<()> {
        match self {
            Self::H2(c) => c.probe().await,
            #[cfg(feature = "h3")]
            Self::H3(c) => c.probe().await,
        }
    }
}

/// One owner serializes recovery. Dropping a recovery future retains the device
/// and candidate carrier so a later recovery/stop can finish their teardown.
pub struct Session {
    device: Option<Arc<Mutex<PacketDevice>>>,
    config: vpn::Config,
    client: Option<Carrier>,
    tunnel: Option<VpnTunnel>,
    monitor: Option<JoinHandle<()>>,
    events: watch::Sender<Event>,
    started: Instant,
    completed_tx: u64,
    completed_rx: u64,
}
impl Session {
    pub fn new(config: vpn::Config, device: PacketDevice) -> Result<Self> {
        config.validate().map_err(Error::from)?;
        let (events, _) = watch::channel(Event::Preparing);
        Ok(Self {
            device: Some(Arc::new(Mutex::new(device))),
            config,
            client: None,
            tunnel: None,
            monitor: None,
            events,
            started: Instant::now(),
            completed_tx: 0,
            completed_rx: 0,
        })
    }
    pub fn subscribe(&self) -> watch::Receiver<Event> {
        self.events.subscribe()
    }
    pub fn snapshot(&self) -> Event {
        self.events.borrow().clone()
    }
    pub fn stats(&self) -> TrafficStats {
        let current = self.tunnel.as_ref().map(VpnTunnel::stats);
        TrafficStats {
            tx_bytes: self.completed_tx + current.as_ref().map_or(0, |s| s.tx_bytes),
            rx_bytes: self.completed_rx + current.as_ref().map_or(0, |s| s.rx_bytes),
            uptime: self.started.elapsed(),
            since_last_payload: current.as_ref().and_then(|s| s.since_last_payload),
            since_last_rx_payload: current.as_ref().and_then(|s| s.since_last_rx_payload),
        }
    }
    /// One attempt using an already connected carrier; never silently redials or
    /// changes a healthy connection. Initial attachment uses this same method.
    pub async fn recover(&mut self, client: impl Into<Carrier>) -> Result<()> {
        if self.device.is_none() {
            return Err(Error::Closed);
        }
        if self.tunnel.as_ref().is_some_and(|t| {
            matches!(
                t.snapshot(),
                SessionState::Running | SessionState::AwaitingConfiguration
            )
        }) {
            return Err(Error::InvalidConfig(
                "session still has an active carrier".into(),
            ));
        }
        self.stop_carrier().await;
        self.events.send_replace(Event::Recovering);
        self.client = Some(client.into());
        let result = self
            .client
            .as_ref()
            .unwrap()
            .prepare_vpn(self.config.clone())
            .await;
        let prepared = match result {
            Ok(prepared) => prepared,
            Err(error) => {
                self.stop_carrier().await;
                self.events.send_replace(Event::CarrierLost {
                    detail: error.to_string(),
                });
                return Err(error);
            }
        };
        let device = self.device.as_ref().unwrap().clone();
        let tunnel = prepared.start(PacketDevice::new(Reader(device.clone()), Writer(device)));
        let mut state = tunnel.subscribe();
        let events = self.events.clone();
        self.monitor = Some(tokio::spawn(async move {
            loop {
                let snapshot = state.borrow_and_update().clone();
                match snapshot {
                    SessionState::Running => {
                        events.send_replace(Event::Running);
                    }
                    SessionState::AwaitingConfiguration => (),
                    SessionState::Failed { detail } => {
                        events.send_replace(Event::CarrierLost { detail });
                        break;
                    }
                    SessionState::Closed => {
                        events.send_replace(Event::CarrierLost {
                            detail: "carrier closed".into(),
                        });
                        break;
                    }
                }
                if state.changed().await.is_err() {
                    break;
                }
            }
        }));
        self.tunnel = Some(tunnel);
        Ok(())
    }
    /// Carrier evidence only. The host separately checks IP forwarding and DNS.
    pub async fn probe_carrier(&self) -> Result<()> {
        self.client.as_ref().ok_or(Error::Closed)?.probe().await
    }
    /// Host-confirmed underlay change invalidates the old carrier while retaining
    /// packet ownership. No connection is made until the host calls recover.
    pub async fn underlay_changed(&mut self) {
        self.stop_carrier().await;
        if self.device.is_some() {
            self.events.send_replace(Event::CarrierLost {
                detail: "underlay changed".into(),
            });
        }
    }
    async fn stop_carrier(&mut self) {
        // Retain handles while awaiting them: cancellation never detaches cleanup.
        if let Some(monitor) = self.monitor.as_mut() {
            monitor.abort();
            let _ = monitor.await;
        }
        self.monitor.take();
        if let Some(tunnel) = self.tunnel.as_mut() {
            let _ = tunnel.stop_mut().await;
        }
        if let Some(tunnel) = self.tunnel.take() {
            let stats = tunnel.stats();
            self.completed_tx += stats.tx_bytes;
            self.completed_rx += stats.rx_bytes;
        }
        if let Some(client) = &self.client {
            let _ = client.stop().await;
        }
        self.client.take();
    }
    /// Joins carrier tasks before releasing the packet device. May be retried if
    /// the caller cancels this future; no packet device is released prematurely.
    pub async fn stop(&mut self) -> Result<()> {
        self.stop_carrier().await;
        self.device.take();
        self.events.send_replace(Event::Closed);
        Ok(())
    }
}
impl Drop for Session {
    fn drop(&mut self) {
        if let Some(monitor) = &self.monitor {
            monitor.abort();
        }
    }
}
struct Reader(Arc<Mutex<PacketDevice>>);
impl PacketRecv for Reader {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        self.0.lock().unwrap().recv.poll_recv(cx, buffer)
    }
    fn try_recv(&mut self, buffer: &mut [u8]) -> io::Result<Option<usize>> {
        self.0.lock().unwrap().recv.try_recv(buffer)
    }
}
struct Writer(Arc<Mutex<PacketDevice>>);
impl PacketSend for Writer {
    fn poll_send(&mut self, cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        self.0.lock().unwrap().send.poll_send(cx, packet)
    }
}
