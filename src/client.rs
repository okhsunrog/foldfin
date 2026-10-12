//! Embeddable TLS/H2 client. Uses the caller's Tokio runtime; never reads files,
//! environment variables or signals, and never configures the operating system.
use crate::{
    credential::Credential,
    error::{Error, Result},
    packet::PacketDevice,
    stats::{Counters, SessionState, TrafficStats},
    vpn,
};
use bytes::Bytes;
use std::{
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
    sync::watch,
    task::JoinHandle,
    time::timeout,
};
use tokio_rustls::{TlsConnector, rustls};

#[derive(Clone, Debug)]
pub struct ClientConfig {
    /// HTTP authority used by CONNECT-IP, independent of the dialled IP.
    pub authority: String,
    /// TLS verification name/SNI; never replaced by the resolved endpoint IP.
    pub server_name: String,
    pub credential: Credential,
    pub additional_ca_pem: Option<Vec<u8>>,
}

struct Inner {
    sender: h2::client::SendRequest<Bytes>,
    config: ClientConfig,
    state: watch::Receiver<SessionState>,
    publish: watch::Sender<SessionState>,
    driver: tokio::sync::Mutex<Option<JoinHandle<()>>>,
    ping: tokio::sync::Mutex<h2::PingPong>,
    counters: Arc<Counters>,
}

impl Drop for Inner {
    fn drop(&mut self) {
        if let Some(driver) = self.driver.get_mut().take() {
            driver.abort();
        }
    }
}

/// Clones share one carrier. `stop()` closes it for every clone; dropping the last
/// clone aborts its driver. TCP flows fail when that carrier is lost.
#[derive(Clone)]
pub struct Client(Arc<Inner>);

impl Client {
    /// TCP must already be connected. Android protect/network binding and Linux
    /// socket marks must be applied by the caller before connecting it.
    pub async fn connect_over(config: ClientConfig, tcp: TcpStream) -> Result<Self> {
        let authority: http::uri::Authority = config
            .authority
            .parse()
            .map_err(|_| Error::InvalidConfig("invalid server authority".into()))?;
        if authority.port_u16().is_none_or(|port| port == 0) {
            return Err(Error::InvalidConfig(
                "server authority needs a nonzero port".into(),
            ));
        }
        tcp.set_nodelay(true)?;
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = &config.additional_ca_pem {
            for cert in rustls_pemfile::certs(&mut &pem[..]) {
                roots.add(cert?).map_err(|e| Error::Tls(e.into()))?;
            }
        }
        let mut tls_config = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .map_err(|e| Error::Tls(e.into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls_config.alpn_protocols = vec![b"h2".to_vec()];
        let name = rustls::pki_types::ServerName::try_from(config.server_name.clone())
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        let tls = timeout(
            crate::DEADLINE,
            TlsConnector::from(Arc::new(tls_config)).connect(name, tcp),
        )
        .await
        .map_err(|_| Error::Timeout("TLS handshake"))?
        .map_err(|e| Error::Tls(e.into()))?;
        if tls.get_ref().1.alpn_protocol() != Some(b"h2".as_slice()) {
            return Err(Error::Unsupported("server did not negotiate h2"));
        }
        let mut builder = h2::client::Builder::new();
        builder
            .initial_window_size(crate::h2_window::RECEIVE_WINDOW)
            .initial_connection_window_size(crate::h2_window::RECEIVE_WINDOW);
        let (sender, mut connection) = timeout(crate::DEADLINE, builder.handshake(tls))
            .await
            .map_err(|_| Error::Timeout("H2 handshake"))??;
        let ping = connection.ping_pong().expect("first ping handle");
        let (publish, state) = watch::channel(SessionState::Running);
        let status = publish.clone();
        let driver = tokio::spawn(async move {
            let state = match connection.await {
                Ok(()) => SessionState::Closed,
                Err(e) => SessionState::Failed {
                    detail: e.to_string(),
                },
            };
            status.send_replace(state);
        });
        Ok(Self(Arc::new(Inner {
            sender,
            config,
            state,
            publish,
            driver: tokio::sync::Mutex::new(Some(driver)),
            ping: tokio::sync::Mutex::new(ping),
            counters: Arc::new(Counters::default()),
        })))
    }

    pub fn snapshot(&self) -> SessionState {
        self.0.state.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<SessionState> {
        self.0.state.clone()
    }
    pub fn stats(&self) -> TrafficStats {
        self.0.counters.snapshot()
    }

    /// Carrier liveness only. Does not prove IP forwarding or destination reachability.
    pub async fn probe(&self) -> Result<()> {
        timeout(crate::DEADLINE, async {
            self.0.ping.lock().await.ping(h2::Ping::opaque()).await
        })
        .await
        .map_err(|_| Error::Timeout("carrier probe"))??;
        Ok(())
    }

    pub async fn stop(self) -> Result<()> {
        stop_driver(&self.0.driver).await;
        self.0.publish.send_replace(SessionState::Closed);
        Ok(())
    }

    async fn request(
        &self,
        request: http::Request<()>,
    ) -> Result<(h2::RecvStream, h2::SendStream<Bytes>)> {
        if !matches!(self.snapshot(), SessionState::Running) {
            return Err(Error::Closed);
        }
        timeout(crate::DEADLINE, async {
            let mut sender = self.0.sender.clone().ready().await?;
            let (response, output) = sender.send_request(request, false)?;
            let response = response.await?;
            if response.status() != 200 || response.headers().contains_key("content-type") {
                return Err(Error::Rejected(response.status().as_u16()));
            }
            Ok((response.into_body(), output))
        })
        .await
        .map_err(|_| Error::Timeout("CONNECT setup"))?
    }

    pub async fn open_tcp(&self, target: &str) -> Result<TcpFlow> {
        let authority: http::uri::Authority = target
            .parse()
            .map_err(|_| Error::InvalidConfig("invalid TCP target".into()))?;
        if authority.port_u16().is_none_or(|p| p == 0) {
            return Err(Error::InvalidConfig(
                "TCP target needs a nonzero port".into(),
            ));
        }
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(target)
            .header("authorization", self.0.config.credential.header())
            .body(())
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        let (input, output) = self.request(request).await?;
        Ok(TcpFlow {
            input,
            output,
            buffered: Bytes::new(),
            eof: false,
            shutdown: false,
            counters: self.0.counters.clone(),
            _client: self.clone(),
        })
    }

    /// Negotiates CONNECT-IP using out-of-band static addresses/prefixes.
    /// It does not install OS configuration or dynamically allocate an address.
    pub async fn prepare_vpn(&self, config: vpn::Config) -> Result<PreparedVpn> {
        config
            .validate()
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        let sender = self.0.sender.clone().ready().await?;
        timeout(crate::DEADLINE, async {
            while !sender.is_extended_connect_protocol_enabled() {
                if !matches!(self.snapshot(), SessionState::Running) {
                    return Err(Error::Closed);
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            }
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout("Extended CONNECT negotiation"))??;
        let request = http::Request::builder()
            .method("CONNECT")
            .uri(format!("https://{}{}", self.0.config.authority, vpn::PATH))
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .header("authorization", self.0.config.credential.header())
            .header("capsule-protocol", "?1")
            .body(())
            .map_err(|e| Error::InvalidConfig(e.to_string()))?;
        // Validate capsule negotiation before exposing the prepared stream.
        let (input, output) = timeout(crate::DEADLINE, async {
            let mut sender = sender.ready().await?;
            let (response, output) = sender.send_request(request, false)?;
            let response = response.await?;
            if response.status() != 200 {
                return Err(Error::Rejected(response.status().as_u16()));
            }
            if response
                .headers()
                .get("capsule-protocol")
                .and_then(|v| v.to_str().ok())
                != Some("?1")
                || response.headers().contains_key("content-type")
            {
                return Err(Error::Unsupported("invalid capsule negotiation"));
            }
            Ok((response.into_body(), output))
        })
        .await
        .map_err(|_| Error::Timeout("CONNECT-IP setup"))??;
        Ok(PreparedVpn {
            client: self.clone(),
            config,
            input,
            output,
        })
    }
}

/// Complete TCP byte stream with independent read EOF and write shutdown.
/// Dropping an unfinished flow sends RST_STREAM/CANCEL.
pub struct TcpFlow {
    input: h2::RecvStream,
    output: h2::SendStream<Bytes>,
    buffered: Bytes,
    eof: bool,
    shutdown: bool,
    counters: Arc<Counters>,
    _client: Client,
}

impl AsyncRead for TcpFlow {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        loop {
            if !self.buffered.is_empty() {
                let n = buf.remaining().min(self.buffered.len());
                buf.put_slice(&self.buffered.split_to(n));
                self.input
                    .flow_control()
                    .release_capacity(n)
                    .map_err(io::Error::other)?;
                self.counters.rx(n);
                return Poll::Ready(Ok(()));
            }
            if self.eof {
                return Poll::Ready(Ok(()));
            }
            match std::task::ready!(self.input.poll_data(cx)) {
                Some(Ok(bytes)) => self.buffered = bytes,
                Some(Err(e)) => return Poll::Ready(Err(io::Error::other(e))),
                None => self.eof = true,
            }
        }
    }
}

impl AsyncWrite for TcpFlow {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.shutdown {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::BrokenPipe,
                "TCP flow write side closed",
            )));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let wanted = bytes.len().min(crate::CHUNK);
        let n = std::task::ready!(crate::h2_io::poll_capacity(&mut self.output, cx, wanted))?;
        self.output
            .send_data(Bytes::copy_from_slice(&bytes[..n]), false)
            .map_err(io::Error::other)?;
        self.counters.tx(n);
        Poll::Ready(Ok(n))
    }

    fn poll_flush(self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Poll::Ready(Ok(()))
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, _cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if !self.shutdown {
            self.output
                .send_data(Bytes::new(), true)
                .map_err(io::Error::other)?;
            self.shutdown = true;
        }
        Poll::Ready(Ok(()))
    }
}

impl Drop for TcpFlow {
    fn drop(&mut self) {
        if !(self.eof && self.shutdown) {
            self.output.send_reset(h2::Reason::CANCEL);
        }
    }
}

pub struct PreparedVpn {
    client: Client,
    config: vpn::Config,
    input: h2::RecvStream,
    output: h2::SendStream<Bytes>,
}

impl PreparedVpn {
    /// Static plan supplied by provisioning. DNS and host route policy stay outside Foldfin.
    pub fn network_plan(&self) -> &vpn::Config {
        &self.config
    }

    pub fn start(self, device: PacketDevice) -> VpnTunnel {
        let counters = Arc::new(Counters::default());
        let (publish, state) = watch::channel(SessionState::AwaitingConfiguration);
        let publisher = publish.clone();
        let stats = counters.clone();
        let task = tokio::spawn(async move {
            let mut carrier = self.client.subscribe();
            let bridge = vpn::bridge(
                device,
                &self.config,
                self.input,
                self.output,
                stats,
                Some(publish.clone()),
            );
            let result = tokio::select! {
                result = bridge => result.map_err(Error::from),
                _ = async { while matches!(*carrier.borrow_and_update(), SessionState::Running) { if carrier.changed().await.is_err() { break; } } } => Err(Error::Closed),
            };
            publish.send_replace(match &result {
                Ok(()) => SessionState::Closed,
                Err(e) => SessionState::Failed {
                    detail: e.to_string(),
                },
            });
            result
        });
        VpnTunnel {
            task: Some(task),
            publish: publisher,
            state,
            counters,
        }
    }
}

pub struct VpnTunnel {
    pub(crate) publish: watch::Sender<SessionState>,
    pub(crate) task: Option<JoinHandle<Result<()>>>,
    pub(crate) state: watch::Receiver<SessionState>,
    pub(crate) counters: Arc<Counters>,
}

impl VpnTunnel {
    pub fn snapshot(&self) -> SessionState {
        self.state.borrow().clone()
    }
    pub fn subscribe(&self) -> watch::Receiver<SessionState> {
        self.state.clone()
    }
    pub fn stats(&self) -> TrafficStats {
        self.counters.snapshot()
    }
    /// Waits for failure/closure without consuming or detaching the task.
    pub async fn closed(&self) {
        let mut state = self.subscribe();
        while matches!(
            *state.borrow_and_update(),
            SessionState::Running | SessionState::AwaitingConfiguration
        ) {
            if state.changed().await.is_err() {
                break;
            }
        }
    }
    /// Releases packet endpoints and the stream before returning. Existing failures propagate.
    pub async fn stop(mut self) -> Result<()> {
        self.stop_mut().await
    }

    pub(crate) async fn stop_mut(&mut self) -> Result<()> {
        let Some(task) = self.task.as_mut() else {
            return Ok(());
        };
        if !task.is_finished() {
            task.abort();
        }
        let result = match task.await {
            Ok(result) => result,
            Err(e) if e.is_cancelled() => Ok(()),
            Err(e) => Err(Error::Protocol(e.into())),
        };
        self.task.take();
        if result.is_ok() {
            self.publish.send_replace(SessionState::Closed);
        }
        result
    }
}

impl Drop for VpnTunnel {
    fn drop(&mut self) {
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}

async fn stop_driver(driver: &tokio::sync::Mutex<Option<JoinHandle<()>>>) {
    // Keep the handle in shared storage while joining. Concurrent callers wait
    // for the same teardown; cancellation of a caller leaves the aborted handle
    // available for the next caller to join.
    let mut driver = driver.lock().await;
    if let Some(task) = driver.as_mut() {
        task.abort();
        let _ = task.await;
    }
    driver.take();
}

#[cfg(test)]
mod lifecycle_tests {
    use super::*;
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_and_cancelled_stop_wait_for_driver_teardown() {
        struct Held(std::sync::mpsc::Sender<()>, std::sync::mpsc::Receiver<()>);
        impl Drop for Held {
            fn drop(&mut self) {
                self.0.send(()).unwrap();
                self.1.recv().unwrap();
            }
        }
        let (entered, entering) = std::sync::mpsc::channel();
        let (release, released) = std::sync::mpsc::channel();
        let (ready, readiness) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            let _held = Held(entered, released);
            ready.send(()).unwrap();
            std::future::pending::<()>().await;
        });
        readiness.await.unwrap();
        let driver = Arc::new(tokio::sync::Mutex::new(Some(task)));
        let first = {
            let driver = driver.clone();
            tokio::spawn(async move { stop_driver(&driver).await })
        };
        tokio::task::spawn_blocking(move || entering.recv().unwrap())
            .await
            .unwrap();
        let mut second = {
            let driver = driver.clone();
            tokio::spawn(async move { stop_driver(&driver).await })
        };
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut second)
                .await
                .is_err()
        );
        first.abort();
        let _ = first.await;
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(30), &mut second)
                .await
                .is_err()
        );
        release.send(()).unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(2), second)
            .await
            .unwrap()
            .unwrap();
        assert!(driver.lock().await.is_none());
    }
}
