//! Embeddable single-static-peer server. The application owns TLS material,
//! listeners, device setup and shutdown. No runtime, environment or signals are owned here.
use crate::authorization::{AccessGrant, AccessLease, AccessRequest, Authorizer, StaticAuthorizer};
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
    sessions: crate::admission::Registry,
    #[cfg(feature = "h3")]
    tls: Arc<rustls::ServerConfig>,
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
                peer: None,
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
            acceptor: TlsAcceptor::from(tls.clone()),
            #[cfg(feature = "h3")]
            tls,
            authorizer,
            connections: Arc::new(Semaphore::new(128)),
            flows: Arc::new(Semaphore::new(256)),
            counters: Arc::new(Counters::default()),
            receive_budget: crate::h2_window::ReceiveBudget::new(),
            sessions: crate::admission::Registry::default(),
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
                    inner.sessions.clone(),
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
    sessions: crate::admission::Registry,
) -> Result<()> {
    let protocol = req
        .extensions()
        .get::<h2::ext::Protocol>()
        .map(|p| p.as_str());
    let mode = crate::request::validate(&req, protocol);
    if req.method() == http::Method::CONNECT && mode.is_none() {
        reply.send_response(Response::builder().status(400).body(())?, true)?;
        return Ok(());
    }
    let grant = if req.method() == http::Method::CONNECT {
        if let Some(header) = req.headers().get("authorization") {
            timeout(
                crate::DEADLINE,
                authorizer.authorize(AccessRequest::new(
                    mode.expect("CONNECT validated above"),
                    header.clone(),
                )),
            )
            .await??
        } else {
            None
        }
    } else {
        None
    };
    let Some(grant) = grant.filter(AccessGrant::valid) else {
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
    // A disconnected request cannot replace the live session during authorization.
    if std::future::poll_fn(|cx| std::task::Poll::Ready(reply.poll_reset(cx).is_ready())).await {
        return Ok(());
    }
    serve_granted(req, reply, grant, counters, sessions).await
}

async fn serve_granted(
    req: Request<h2::RecvStream>,
    mut reply: h2::server::SendResponse<Bytes>,
    mut grant: AccessGrant,
    counters: Arc<crate::stats::Counters>,
    sessions: crate::admission::Registry,
) -> Result<()> {
    if req.extensions().get::<h2::ext::Protocol>().is_some() {
        let Some(config) = grant.vpn.clone() else {
            reply.send_response(Response::builder().status(501).body(())?, true)?;
            return Ok(());
        };
        let admission = grant.peer.clone().map(|peer| sessions.prepare(peer));
        // Anonymous/static peers cannot replace an existing owner.
        let mut slot = if admission.is_none() {
            match grant.vpn_slots.clone().try_acquire_owned() {
                Ok(slot) => Some(slot),
                Err(_) => {
                    reply.send_response(Response::builder().status(409).body(())?, true)?;
                    return Ok(());
                }
            }
        } else {
            None
        };
        let tun = match config.device.open() {
            Ok(tun) => tun,
            Err(error) => {
                reply.send_response(Response::builder().status(503).body(())?, true)?;
                return Err(error.into());
            }
        };
        if !grant.valid()
            || std::future::poll_fn(|cx| std::task::Poll::Ready(reply.poll_reset(cx).is_ready()))
                .await
        {
            return Ok(());
        }
        let owner = if let Some(admission) = admission {
            match admission.commit(&grant) {
                Ok(owner) => {
                    grant.session = Some(owner.lease.clone());
                    Some(owner)
                }
                Err(error) => {
                    reply.send_response(Response::builder().status(409).body(())?, true)?;
                    return Err(error.into());
                }
            }
        } else {
            None
        };
        if slot.is_none() {
            let slots = grant.vpn_slots.clone();
            slot = Some(tokio::select! {
                biased;
                _ = grant.cancelled() => return Ok(()),
                slot = timeout(crate::DEADLINE, slots.acquire_owned()) => slot??,
            });
        }
        let (_slot, _owner) = (slot, owner);
        let output = reply.send_response(
            Response::builder()
                .status(200)
                .header("capsule-protocol", "?1")
                .body(())?,
            false,
        )?;
        return tokio::select! {
            biased;
            _ = grant.cancelled() => Ok(()),
            result = crate::vpn::bridge(tun, &config.policy, req.into_body(), output, counters, None) => result,
        };
    }
    if !grant.proxy {
        reply.send_response(Response::builder().status(403).body(())?, true)?;
        return Ok(());
    }
    let Some(authority) = req.uri().authority() else {
        reply.send_response(Response::builder().status(400).body(())?, true)?;
        return Ok(());
    };
    let private = grant.allow_private;
    let connected = tokio::select! {
        biased;
        _ = grant.cancelled() => return Ok(()),
        result = crate::connect_target(authority.as_str(), private) => result,
    };
    let tcp = match connected {
        Ok(tcp) => tcp,
        Err(_) => {
            reply.send_response(Response::builder().status(502).body(())?, true)?;
            return Ok(());
        }
    };
    let output = reply.send_response(Response::builder().status(200).body(())?, false)?;
    tokio::select! {
        biased;
        _ = grant.cancelled() => Ok(()),
        result = crate::bridge(tcp, req.into_body(), output) => result,
    }
}

#[cfg(feature = "h3")]
impl Server {
    /// Serve HTTP/3 on a host-prepared UDP socket, sharing authorization, session
    /// generations and global connection/flow limits with this server's H2 listener.
    pub async fn serve_h3(
        &self,
        socket: std::net::UdpSocket,
        shutdown: impl std::future::Future<Output = ()>,
    ) -> crate::error::Result<()> {
        let listener = crate::h3_transport::Listener::new(socket, (*self.0.tls).clone())?;
        let (cancel, stopped) = watch::channel(false);
        let mut peers = JoinSet::new();
        tokio::pin!(shutdown);
        let result = loop {
            tokio::select! {
                _ = &mut shutdown => break Ok(()),
                _ = peers.join_next(), if !peers.is_empty() => (),
                incoming = listener.accept() => {
                    let incoming = match incoming { Ok(Some(incoming)) => incoming, Ok(None) => break Ok(()), Err(error) => break Err(error) };
                    let Ok(permit) = self.0.connections.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    let stopped = stopped.clone();
                    peers.spawn(async move { let _permit = permit; server.serve_h3_peer(incoming, stopped).await });
                }
            }
        };
        cancel.send_replace(true);
        while peers.join_next().await.is_some() {}
        listener.stop().await;
        result
    }
    async fn serve_h3_peer(
        &self,
        incoming: crate::h3_transport::Incoming,
        mut stopped: watch::Receiver<bool>,
    ) -> crate::error::Result<()> {
        let mut connection = tokio::select! {
            _ = stopped.changed() => return Ok(()),
            connection = incoming.handshake() => connection?,
        };
        let packets = Arc::new(tokio::sync::Mutex::new(crate::h3_packets::Hub::new(
            connection.datagrams(),
        )));
        let mut tasks = JoinSet::new();
        let result = loop {
            tokio::select! {
                _ = stopped.changed() => break Ok(()),
                _ = tasks.join_next(), if !tasks.is_empty() => (),
                request = connection.accept() => {
                    let request = match request { Ok(Some(request)) => request, Ok(None) => break Ok(()), Err(error) => break Err(error) };
                    let Ok(permit) = self.0.flows.clone().try_acquire_owned() else { continue; };
                    let server = self.clone();
                    let packets = packets.clone();
                    tasks.spawn(async move {
                        let _permit = permit;
                        if let Err(error) = server.serve_h3_request(request, packets).await { tracing::debug!(%error, "H3 stream failed"); }
                    });
                }
            }
        };
        tasks.abort_all();
        while tasks.join_next().await.is_some() {}
        packets.lock().await.stop().await;
        result
    }
    async fn serve_h3_request(
        &self,
        pending: crate::h3_transport::PendingRequest,
        packets: Arc<tokio::sync::Mutex<crate::h3_packets::Hub>>,
    ) -> Result<()> {
        use crate::h3_transport::ConnectProtocol;
        let (request, extension, mut stream) = pending.resolve().await?;
        let protocol = extension.map(|p| match p {
            ConnectProtocol::Ip => "connect-ip",
            ConnectProtocol::Udp => "connect-udp",
        });
        let Some(mode) = crate::request::validate(&request, protocol) else {
            stream
                .respond(
                    Response::builder()
                        .status(if request.method() == http::Method::CONNECT {
                            400
                        } else {
                            404
                        })
                        .body(())?,
                )
                .await?;
            stream.finish().await?;
            return Ok(());
        };
        let grant = if let Some(header) = request.headers().get("authorization") {
            timeout(
                crate::DEADLINE,
                self.0
                    .authorizer
                    .authorize(AccessRequest::new(mode, header.clone())),
            )
            .await??
        } else {
            None
        };
        let Some(mut grant) = grant.filter(AccessGrant::valid) else {
            stream
                .respond(Response::builder().status(403).body(())?)
                .await?;
            stream.finish().await?;
            return Ok(());
        };
        if extension == Some(ConnectProtocol::Ip) {
            let Some(config) = grant.vpn.clone() else {
                stream
                    .respond(Response::builder().status(501).body(())?)
                    .await?;
                stream.finish().await?;
                return Ok(());
            };
            config.policy.validate()?;
            let channel = packets.lock().await.subscribe(stream.id())?;
            // Path capability failure precedes admission, so H2 fallback cannot
            // accidentally tear down a working VPN session.
            if channel.0.require_vpn_mtu().await.is_err() {
                stream
                    .respond(Response::builder().status(501).body(())?)
                    .await?;
                stream.finish().await?;
                return Ok(());
            }
            let prepared = grant.peer.clone().map(|peer| self.0.sessions.prepare(peer));
            let mut slot = if prepared.is_none() {
                match grant.vpn_slots.clone().try_acquire_owned() {
                    Ok(slot) => Some(slot),
                    Err(_) => {
                        stream
                            .respond(Response::builder().status(409).body(())?)
                            .await?;
                        stream.finish().await?;
                        return Ok(());
                    }
                }
            } else {
                None
            };
            let device = match config.device.open() {
                Ok(device) => device,
                Err(error) => {
                    stream
                        .respond(Response::builder().status(503).body(())?)
                        .await?;
                    stream.finish().await?;
                    return Err(error.into());
                }
            };
            stream.check_open().await?;
            let owner = match prepared {
                Some(prepared) => {
                    let owner = prepared.commit(&grant)?;
                    grant.session = Some(owner.lease.clone());
                    Some(owner)
                }
                None => None,
            };
            if slot.is_none() {
                let slots = grant.vpn_slots.clone();
                slot = Some(tokio::select! {
                    biased;
                    _ = grant.cancelled() => return Ok(()),
                    slot = timeout(crate::DEADLINE, slots.acquire_owned()) => slot??,
                });
            }
            let (_slot, _owner) = (slot, owner);
            stream
                .respond(
                    Response::builder()
                        .status(200)
                        .header("capsule-protocol", "?1")
                        .body(())?,
                )
                .await?;
            return tokio::select! {
                biased;
                _ = grant.cancelled() => Ok(()),
                result = crate::vpn::bridge_h3(device, &config.policy, stream, channel, self.0.counters.clone(), None) => result,
            };
        }
        if !grant.proxy {
            stream
                .respond(Response::builder().status(403).body(())?)
                .await?;
            stream.finish().await?;
            return Ok(());
        }
        let private = grant.allow_private;
        let target = request.uri().authority().unwrap().as_str();
        let tcp = tokio::select! {
            biased;
            _ = grant.cancelled() => return Ok(()),
            tcp = crate::connect_target(target, private) => match tcp {
                Ok(tcp) => tcp,
                Err(_) => { stream.respond(Response::builder().status(502).body(())?).await?; stream.finish().await?; return Ok(()); }
            },
        };
        stream
            .respond(Response::builder().status(200).body(())?)
            .await?;
        let (mut send, mut recv) = stream.split();
        let (mut read, mut write) = tcp.into_split();
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let upload = async {
            let mut buffer = vec![0; crate::CHUNK];
            loop {
                let n = read.read(&mut buffer).await?;
                if n == 0 {
                    send.finish().await?;
                    return Ok::<(), anyhow::Error>(());
                }
                send.send(Bytes::copy_from_slice(&buffer[..n])).await?;
            }
        };
        let download = async {
            while let Some(data) = recv.recv().await? {
                write.write_all(&data).await?;
            }
            write.shutdown().await?;
            Ok::<(), anyhow::Error>(())
        };
        tokio::select! {
            biased;
            _ = grant.cancelled() => Ok(()),
            result = async { tokio::try_join!(upload, download)?; Ok(()) } => result,
        }
    }
}

#[cfg(test)]
mod admission_tests {
    use super::*;
    use std::{
        future::Future,
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
    };
    struct Count(AtomicUsize);
    impl Authorizer for Count {
        fn authorize(
            &self,
            _: AccessRequest,
        ) -> Pin<Box<dyn Future<Output = crate::error::Result<Option<AccessGrant>>> + Send + '_>>
        {
            self.0.fetch_add(1, Ordering::SeqCst);
            Box::pin(async { Ok(None) })
        }
    }
    #[tokio::test]
    async fn malformed_connect_never_calls_authorizer() {
        let authorizer = Arc::new(Count(AtomicUsize::new(0)));
        let (client, server) = tokio::io::duplex(65536);
        let access = authorizer.clone();
        let server = tokio::spawn(async move {
            let mut builder = h2::server::Builder::new();
            builder.enable_connect_protocol();
            let mut conn = builder.handshake(server).await.unwrap();
            let (request, response) = conn.accept().await.unwrap().unwrap();
            let serve = serve_authorized(
                request,
                response,
                access,
                Arc::new(Counters::default()),
                crate::admission::Registry::default(),
            );
            tokio::pin!(serve);
            tokio::select! {
                result = &mut serve => result.unwrap(),
                _ = conn.accept() => panic!("unexpected connection termination"),
            }
            // Flush the response until the client closes.
            let _ = conn.accept().await;
        });
        let (sender, connection) = h2::client::handshake(client).await.unwrap();
        let driver = tokio::spawn(connection);
        let mut sender = sender.ready().await.unwrap();
        while !sender.is_extended_connect_protocol_enabled() {
            tokio::task::yield_now().await;
        }
        let request = Request::builder()
            .method("CONNECT")
            .uri("https://localhost/wrong")
            .extension(h2::ext::Protocol::from_static("connect-ip"))
            .header("authorization", "Bearer 0123456789abcdef0123456789abcdef")
            .header("capsule-protocol", "?1")
            .body(())
            .unwrap();
        let (response, _) = sender.send_request(request, true).unwrap();
        assert_eq!(response.await.unwrap().status(), 400);
        assert_eq!(authorizer.0.load(Ordering::SeqCst), 0);
        drop(sender);
        driver.abort();
        let _ = driver.await;
        server.await.unwrap();
    }
}
