//! Embeddable single-static-peer server. The application owns TLS material,
//! listeners, device setup and shutdown. No runtime, environment or signals are owned here.
use crate::authorization::{
    AccessGrant, AccessLease, AccessRequest, Authorizer, RequestedMode, StaticAuthorizer,
};
use crate::{
    credential::Credential,
    packet::PacketDeviceFactory,
    stats::{Counters, TrafficStats},
};
use anyhow::Result;
use bytes::Bytes;
use http::{Request, Response, StatusCode};
use std::sync::Arc;
use tokio::{
    net::{TcpListener, TcpStream},
    sync::{Semaphore, watch},
    task::JoinSet,
    time::timeout,
};
use tokio_rustls::{TlsAcceptor, rustls};
/// TLS configuration type accepted by the server host.
pub type TlsConfig = rustls::ServerConfig;

#[derive(Clone)]
pub struct VpnConfig {
    pub policy: crate::vpn::Config,
    pub device: Arc<dyn PacketDeviceFactory>,
}

#[derive(Clone)]
pub struct ServerConfig {
    pub tls: Arc<rustls::ServerConfig>,
    pub credential: Credential,
    pub allow_private: bool,
    pub vpn: Option<VpnConfig>,
}

struct Inner {
    authorizer: Arc<dyn Authorizer>,
    acceptor: TlsAcceptor,
    connections: Arc<Semaphore>,
    flows: Arc<Semaphore>,
    counters: Arc<Counters>,
    receive_budget: crate::h2_window::ReceiveBudget,
}

#[derive(Clone)]
pub struct Server(Arc<Inner>);

impl Server {
    pub fn new(config: ServerConfig) -> crate::error::Result<Self> {
        if let Some(vpn) = &config.vpn {
            vpn.policy
                .validate()
                .map_err(|e| crate::error::Error::InvalidConfig(e.to_string()))?;
        }
        if !config.tls.alpn_protocols.iter().any(|p| p == b"h2") {
            return Err(crate::error::Error::InvalidConfig(
                "server TLS must advertise h2".into(),
            ));
        }
        let (keepalive, lease) = AccessLease::new(None);
        let authorizer = StaticAuthorizer {
            credential: config.credential,
            grant: AccessGrant {
                proxy: true,
                allow_private: config.allow_private,
                vpn: config.vpn,
                vpn_slots: Arc::new(Semaphore::new(1)),
                lease,
                session: None,
            },
            _keepalive: keepalive,
        };
        Self::with_authorizer(config.tls, Arc::new(authorizer))
    }

    /// Embed a host's device/subscription authorizer. Every CONNECT is checked independently.
    pub fn with_authorizer(
        tls: Arc<rustls::ServerConfig>,
        authorizer: Arc<dyn Authorizer>,
    ) -> crate::error::Result<Self> {
        if !tls.alpn_protocols.iter().any(|p| p == b"h2") {
            return Err(crate::error::Error::InvalidConfig(
                "server TLS must advertise h2".into(),
            ));
        }
        Ok(Self(Arc::new(Inner {
            acceptor: TlsAcceptor::from(tls),
            authorizer,
            connections: Arc::new(Semaphore::new(128)),
            flows: Arc::new(Semaphore::new(256)),
            counters: Arc::new(Counters::default()),
            receive_budget: crate::h2_window::ReceiveBudget::new(),
        })))
    }

    /// IP payload stats aggregated over VPN sessions. Proxy traffic is not included yet.
    pub fn vpn_stats(&self) -> TrafficStats {
        self.0.counters.snapshot()
    }

    /// Returns only after all connection tasks and their upstream flows are gone.
    /// Dropping this future also cancels tasks via JoinSet; await it for complete teardown.
    pub async fn serve(
        &self,
        listener: TcpListener,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> crate::error::Result<()> {
        let mut tasks = JoinSet::new();
        let (cancel, cancellation) = watch::channel(false);
        tokio::pin!(shutdown);
        tracing::info!("listening on {}", listener.local_addr()?);
        let result = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                result = tasks.join_next(), if !tasks.is_empty() => {
                    if let Some(Err(e)) = result { tracing::warn!(%e, "server connection task failed"); }
                }
                accepted = listener.accept() => {
                    let (tcp, _) = match accepted { Ok(tcp) => tcp, Err(e) => break Err(e.into()) };
                    let Ok(permit) = self.0.connections.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    let cancellation = cancellation.clone();
                    tasks.spawn(async move { let _permit = permit;
                        if let Err(e) = server.serve_connection(tcp, cancellation).await { tracing::debug!(%e, "connection failed"); }
                    });
                }
            }
        };
        cancel.send_replace(true);
        while tasks.join_next().await.is_some() {}
        result
    }

    async fn serve_connection(
        &self,
        tcp: TcpStream,
        mut cancellation: watch::Receiver<bool>,
    ) -> Result<()> {
        tcp.set_nodelay(true)?;
        if *cancellation.borrow() {
            return Ok(());
        }
        let setup = async {
            let tls = timeout(crate::DEADLINE, self.0.acceptor.accept(tcp)).await??;
            let credit = self.0.receive_budget.reserve();
            let mut builder = h2::server::Builder::new();
            builder
                .initial_window_size(crate::h2_window::RECEIVE_WINDOW)
                .initial_connection_window_size(credit.window)
                .max_concurrent_streams(64)
                .max_header_list_size(8192)
                .enable_connect_protocol();
            Ok::<_, anyhow::Error>((
                timeout(crate::DEADLINE, builder.handshake::<_, Bytes>(tls)).await??,
                credit,
            ))
        };
        // Keep the shared credit reserved through stream cancellation/join and
        // until the H2 connection itself has released its receive buffers.
        let (connection, receive_credit) = tokio::select! {
            result = setup => result?,
            _ = cancellation.changed() => return Ok(()),
        };
        let _receive_credit = receive_credit;
        let mut connection = connection;
        let mut tasks = JoinSet::new();
        let result = loop {
            let request = tokio::select! {
                _ = cancellation.changed() => break Ok(()),
                request = connection.accept() => request,
                _ = tasks.join_next(), if !tasks.is_empty() => continue,
            };
            let Some(request) = request else {
                break Ok(());
            };
            let (request, mut response) = match request {
                Ok(request) => request,
                Err(e) => break Err(e.into()),
            };
            let Ok(permit) = self.0.flows.clone().try_acquire_owned() else {
                if let Err(e) =
                    response.send_response(Response::builder().status(503).body(())?, true)
                {
                    break Err(e.into());
                }
                continue;
            };
            let inner = self.0.clone();
            tasks.spawn(async move {
                let _permit = permit;
                if let Err(error) = serve_authorized(
                    request,
                    response,
                    inner.authorizer.clone(),
                    inner.counters.clone(),
                )
                .await
                {
                    tracing::debug!(%error, "stream failed");
                }
            });
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        result
    }
}

async fn serve_authorized(
    req: Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    authorizer: Arc<dyn Authorizer>,
    counters: Arc<crate::stats::Counters>,
) -> Result<()> {
    let mode = if req.extensions().get::<h2::ext::Protocol>().is_some() {
        RequestedMode::Ip
    } else {
        RequestedMode::Tcp {
            target: req
                .uri()
                .authority()
                .map(ToString::to_string)
                .unwrap_or_default(),
        }
    };
    let grant = if req.method() == http::Method::CONNECT {
        if let Some(header) = req.headers().get("authorization") {
            timeout(
                crate::DEADLINE,
                authorizer.authorize(AccessRequest::new(mode, header.clone())),
            )
            .await??
        } else {
            None
        }
    } else {
        None
    };
    let Some(mut grant) = grant.filter(AccessGrant::valid) else {
        let body = Bytes::from_static(b"<!doctype html><title>Welcome</title><h1>Welcome</h1>");
        let mut stream = reply.send_response(
            Response::builder()
                .status(StatusCode::OK)
                .header("content-type", "text/html; charset=utf-8")
                .body(())?,
            false,
        )?;
        stream.send_data(body, true)?;
        return Ok(());
    };
    if let Some(vpn) = &grant.vpn {
        vpn.policy.validate()?;
    }
    let private = grant.allow_private;
    let vpn = grant.vpn.clone();
    let vpn_slots = grant.vpn_slots.clone();
    let proxy = grant.proxy;
    tokio::select! {
        biased;
        _ = grant.cancelled() => Ok(()),
        result = serve_granted(req, reply, private, proxy, vpn, counters, vpn_slots) => result,
    }
}

async fn serve_granted(
    req: Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    private: bool,
    proxy: bool,
    vpn: Option<VpnConfig>,
    counters: Arc<crate::stats::Counters>,
    vpn_slot: Arc<Semaphore>,
) -> Result<()> {
    if let Some(protocol) = req.extensions().get::<h2::ext::Protocol>() {
        if protocol.as_str() != "connect-ip"
            || req.uri().path() != crate::vpn::PATH
            || req.uri().scheme_str() != Some("https")
            || req
                .headers()
                .get("capsule-protocol")
                .and_then(|h| h.to_str().ok())
                != Some("?1")
            || ["content-length", "content-type", "transfer-encoding"]
                .iter()
                .any(|h| req.headers().contains_key(*h))
        {
            reply.send_response(Response::builder().status(400).body(())?, true)?;
            return Ok(());
        }
        let Some(config) = vpn else {
            reply.send_response(Response::builder().status(501).body(())?, true)?;
            return Ok(());
        };
        let Ok(_slot) = vpn_slot.try_acquire_owned() else {
            reply.send_response(Response::builder().status(409).body(())?, true)?;
            return Ok(());
        };
        let tun = match config.device.open() {
            Ok(tun) => tun,
            Err(error) => {
                reply.send_response(Response::builder().status(503).body(())?, true)?;
                return Err(error.into());
            }
        };
        let output = reply.send_response(
            Response::builder()
                .status(200)
                .header("capsule-protocol", "?1")
                .body(())?,
            false,
        )?;
        return crate::vpn::bridge(tun, &config.policy, req.into_body(), output, counters, None)
            .await;
    }
    if !proxy {
        reply.send_response(Response::builder().status(403).body(())?, true)?;
        return Ok(());
    }
    let Some(authority) = req.uri().authority() else {
        reply.send_response(Response::builder().status(400).body(())?, true)?;
        return Ok(());
    };
    let tcp = match crate::connect_target(authority.as_str(), private).await {
        Ok(tcp) => tcp,
        Err(_) => {
            reply.send_response(Response::builder().status(502).body(())?, true)?;
            return Ok(());
        }
    };
    let output = reply.send_response(Response::builder().status(200).body(())?, false)?;
    crate::bridge(tcp, req.into_body(), output).await
}
