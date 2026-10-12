//! HTTP/3 carrier. All sockets are prepared by the host before ownership transfers.
//! The experimental h3/Quinn types stay private to this module.
use crate::error::{Error, Result};
use bytes::{Buf, Bytes};
use h3::ConnectionState;
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};
use tokio::task::JoinHandle;

const QUEUE_BYTES: usize = 1024 * 1024;

fn protocol(error: impl std::error::Error + Send + Sync + 'static) -> Error {
    Error::Protocol(anyhow::Error::new(error))
}

fn transport() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config.datagram_receive_buffer_size(Some(QUEUE_BYTES));
    config.datagram_send_buffer_size(QUEUE_BYTES);
    config.max_concurrent_bidi_streams(64_u32.into());
    config.keep_alive_interval(Some(std::time::Duration::from_secs(15)));
    config.max_idle_timeout(Some(std::time::Duration::from_secs(45).try_into().unwrap()));
    Arc::new(config)
}

/// Listener lifetime belongs to the embedding server. No filesystem or OS setup.
pub struct Listener {
    endpoint: quinn::Endpoint,
}
impl Listener {
    pub fn new(socket: UdpSocket, mut tls: rustls::ServerConfig) -> Result<Self> {
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.max_early_data_size = 0;
        let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls).map_err(protocol)?;
        let mut config = quinn::ServerConfig::with_crypto(Arc::new(crypto));
        config.transport_config(transport());
        let endpoint = quinn::Endpoint::new(
            Default::default(),
            Some(config),
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        Ok(Self { endpoint })
    }
    pub fn local_addr(&self) -> Result<SocketAddr> {
        Ok(self.endpoint.local_addr()?)
    }
    pub async fn accept(&self) -> Result<Option<Incoming>> {
        Ok(self.endpoint.accept().await.map(Incoming))
    }
    pub async fn stop(&self) {
        self.endpoint.close(0x100_u32.into(), b"shutdown");
        self.endpoint.wait_idle().await;
    }
}
impl Drop for Listener {
    fn drop(&mut self) {
        self.endpoint.close(0x100_u32.into(), b"shutdown");
    }
}

/// Handshakes are separate from accept, so slow clients cannot serialize admission.
pub struct Incoming(quinn::Incoming);
impl Incoming {
    pub async fn handshake(self) -> Result<ServerConnection> {
        tokio::time::timeout(crate::DEADLINE, async {
            let connection = self.0.await.map_err(protocol)?;
            let http = h3::server::builder()
                .enable_datagram(true)
                .enable_extended_connect(true)
                .max_field_section_size(8192)
                .build(h3_quinn::Connection::new(connection.clone()))
                .await
                .map_err(protocol)?;
            Ok(ServerConnection {
                http,
                datagrams: Datagrams(connection),
            })
        })
        .await
        .map_err(|_| Error::Timeout("H3 handshake"))?
    }
}

pub struct ServerConnection {
    http: h3::server::Connection<h3_quinn::Connection, Bytes>,
    datagrams: Datagrams,
}
impl ServerConnection {
    /// Poll continuously; this also drives SETTINGS and connection control.
    pub async fn accept(&mut self) -> Result<Option<PendingRequest>> {
        match self.http.accept().await {
            Ok(request) => Ok(request.map(PendingRequest)),
            Err(error) if error.is_h3_no_error() => Ok(None),
            Err(error) => Err(protocol(error)),
        }
    }
    pub fn datagrams(&self) -> Datagrams {
        self.datagrams.clone()
    }
}
impl Drop for ServerConnection {
    fn drop(&mut self) {
        self.datagrams.0.close(0x100_u32.into(), b"shutdown");
    }
}

pub struct PendingRequest(h3::server::RequestResolver<h3_quinn::Connection, Bytes>);
impl PendingRequest {
    pub async fn resolve(self) -> Result<(http::Request<()>, Option<ConnectProtocol>, Stream)> {
        let (mut request, stream) = tokio::time::timeout(crate::DEADLINE, self.0.resolve_request())
            .await
            .map_err(|_| Error::Timeout("H3 request headers"))?
            .map_err(protocol)?;
        let extension = request.extensions_mut().remove::<h3::ext::Protocol>();
        let extension = match extension {
            None => None,
            Some(p) if p == h3::ext::Protocol::CONNECT_IP => Some(ConnectProtocol::Ip),
            Some(p) if p == h3::ext::Protocol::CONNECT_UDP => Some(ConnectProtocol::Udp),
            Some(_) => return Err(Error::Unsupported("extended CONNECT protocol")),
        };
        Ok((
            request,
            extension,
            Stream(StreamInner::Server(stream), None),
        ))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConnectProtocol {
    Ip,
    Udp,
}

pub struct Client {
    endpoint: quinn::Endpoint,
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    datagrams: Datagrams,
    driver: Option<JoinHandle<()>>,
}
impl Client {
    /// `socket` must be bound/protected/marked by the host. SNI is independent of remote IP.
    pub async fn connect(
        socket: UdpSocket,
        remote: SocketAddr,
        server_name: &str,
        additional_ca_pem: Option<&[u8]>,
    ) -> Result<Self> {
        let mut roots = rustls::RootCertStore::empty();
        roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        if let Some(pem) = additional_ca_pem {
            for certificate in rustls_pemfile::certs(&mut &pem[..]) {
                roots.add(certificate?).map_err(|e| Error::Tls(e.into()))?;
            }
        }
        let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_protocol_versions(&[&rustls::version::TLS13])
        .map_err(|e| Error::Tls(e.into()))?
        .with_root_certificates(roots)
        .with_no_client_auth();
        tls.alpn_protocols = vec![b"h3".to_vec()];
        tls.enable_early_data = false;
        let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls).map_err(protocol)?;
        let mut config = quinn::ClientConfig::new(Arc::new(crypto));
        config.transport_config(transport());
        let mut endpoint = quinn::Endpoint::new(
            Default::default(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        endpoint.set_default_client_config(config);
        let connection = tokio::time::timeout(
            crate::DEADLINE,
            endpoint.connect(remote, server_name).map_err(protocol)?,
        )
        .await
        .map_err(|_| Error::Timeout("QUIC handshake"))?
        .map_err(|error| match error {
            quinn::ConnectionError::TransportError(ref e)
                if u64::from(e.code) >= 0x100 && u64::from(e.code) < 0x200 =>
            {
                Error::Tls(error.into())
            }
            quinn::ConnectionError::TimedOut => Error::Timeout("QUIC handshake"),
            quinn::ConnectionError::Reset => Error::Io(std::io::ErrorKind::ConnectionReset.into()),
            _ => protocol(error),
        })?;
        let (mut driver, sender) = h3::client::builder()
            .enable_datagram(true)
            .enable_extended_connect(true)
            .max_field_section_size(8192)
            .build(h3_quinn::Connection::new(connection.clone()))
            .await
            .map_err(protocol)?;
        let driver = tokio::spawn(async move {
            driver.wait_idle().await;
        });
        Ok(Self {
            endpoint,
            sender,
            datagrams: Datagrams(connection),
            driver: Some(driver),
        })
    }
    pub fn datagrams(&self) -> Datagrams {
        self.datagrams.clone()
    }
    pub async fn request(
        &mut self,
        mut request: http::Request<()>,
        extension: Option<ConnectProtocol>,
    ) -> Result<Stream> {
        if let Some(extension) = extension {
            // SETTINGS must be received before an extended CONNECT is sent.
            tokio::time::timeout(crate::DEADLINE, async {
                loop {
                    let settings = self.sender.settings();
                    if settings.enable_extended_connect() && settings.enable_datagram() {
                        break Ok(());
                    }
                    if self.datagrams.0.close_reason().is_some() {
                        break Err(Error::Closed);
                    }
                    tokio::time::sleep(std::time::Duration::from_millis(5)).await;
                }
            })
            .await
            .map_err(|_| Error::Timeout("H3 SETTINGS"))??;
            request.extensions_mut().insert(match extension {
                ConnectProtocol::Ip => h3::ext::Protocol::CONNECT_IP,
                ConnectProtocol::Udp => h3::ext::Protocol::CONNECT_UDP,
            });
        }
        let stream = self.sender.send_request(request).await.map_err(protocol)?;
        Ok(Stream(StreamInner::Client(stream), None))
    }
    pub async fn stop(mut self) {
        self.stop_mut().await;
    }
    pub(crate) async fn stop_mut(&mut self) {
        self.endpoint.close(0x100_u32.into(), b"shutdown");
        if let Some(driver) = self.driver.as_mut() {
            let _ = driver.await;
        }
        self.driver.take();
        self.endpoint.wait_idle().await;
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.endpoint.close(0x100_u32.into(), b"shutdown");
        if let Some(driver) = self.driver.take() {
            driver.abort();
        }
    }
}

/// One receive owner per connection; dispatch by stream ID before delivering to sessions.
#[derive(Clone)]
pub struct Datagrams(quinn::Connection);
impl Datagrams {
    pub fn max_payload(&self, stream: u64) -> Result<usize> {
        let quarter = stream / 4;
        let width = match quarter {
            0..=63 => 1,
            64..=16383 => 2,
            16384..=1073741823 => 4,
            _ => 8,
        };
        self.0
            .max_datagram_size()
            .map(|n| n.saturating_sub(width + 1))
            .ok_or(Error::Unsupported("QUIC datagrams"))
    }
    /// Checks the current path capacity, including HTTP quarter-stream and context ID overhead.
    pub fn require_mtu(&self, stream: u64, mtu: usize) -> Result<()> {
        let maximum = self.max_payload(stream)?;
        if maximum < mtu {
            return Err(Error::PathMtu {
                required: mtu,
                available: maximum,
            });
        }
        Ok(())
    }
    pub fn send(&self, stream: u64, payload: Bytes) -> Result<()> {
        if !stream.is_multiple_of(4) {
            return Err(Error::InvalidConfig("not a client request stream".into()));
        }
        self.require_mtu(stream, payload.len())?;
        let id = h3::quic::StreamId::try_from(stream)
            .map_err(|_| Error::InvalidConfig("invalid stream ID".into()))?;
        let mut data =
            h3_datagram::datagram::Datagram::new(id, Bytes::from_static(&[0]).chain(payload))
                .encode();
        self.0
            .send_datagram(data.copy_to_bytes(data.remaining()))
            .map_err(protocol)
    }
    pub async fn recv(&mut self) -> Result<(u64, Bytes)> {
        loop {
            let data = self.0.read_datagram().await.map_err(protocol)?;
            let datagram = h3_datagram::datagram::Datagram::decode(data)
                .map_err(|_| Error::Protocol(anyhow::anyhow!("invalid HTTP datagram")))?;
            let stream = datagram.stream_id().into_inner();
            let mut payload = datagram.into_payload();
            // Context zero is encoded as a QUIC varint, not necessarily one byte.
            if payload.is_empty() {
                continue;
            }
            let width = 1 << (payload[0] >> 6);
            if payload.len() < width {
                continue;
            }
            let zero = payload[0] & 0x3f == 0 && payload[1..width].iter().all(|b| *b == 0);
            if !zero {
                continue;
            }
            payload.advance(width);
            return Ok((stream, payload));
        }
    }
}

pub struct Stream(StreamInner, Option<Bytes>);
enum StreamInner {
    Client(h3::client::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>),
    Server(h3::server::RequestStream<h3_quinn::BidiStream<Bytes>, Bytes>),
}
impl Stream {
    /// Inspect already received cancellation before committing admission. Preserve
    /// any early control data for the bridge; this never waits for peer input.
    #[cfg(feature = "server")]
    pub(crate) async fn check_open(&mut self) -> Result<()> {
        if self.1.is_some() {
            return Ok(());
        }
        let next = std::future::poll_fn(|cx| {
            use std::task::Poll;
            match &mut self.0 {
                StreamInner::Server(s) => Poll::Ready(match s.poll_recv_data(cx) {
                    Poll::Pending => Ok(None),
                    Poll::Ready(Ok(Some(mut data))) => {
                        Ok(Some(data.copy_to_bytes(data.remaining())))
                    }
                    Poll::Ready(Ok(None)) => Err(Error::Closed),
                    Poll::Ready(Err(error)) => Err(protocol(error)),
                }),
                _ => Poll::Ready(Err(Error::Unsupported("server admission on client stream"))),
            }
        })
        .await?;
        self.1 = next;
        Ok(())
    }
    pub fn id(&self) -> u64 {
        match &self.0 {
            StreamInner::Client(s) => s.id().into_inner(),
            StreamInner::Server(s) => s.id().into_inner(),
        }
    }
    pub async fn response(&mut self) -> Result<http::Response<()>> {
        match &mut self.0 {
            StreamInner::Client(s) => s.recv_response().await.map_err(protocol),
            _ => Err(Error::Unsupported("client response on server stream")),
        }
    }
    pub async fn respond(&mut self, response: http::Response<()>) -> Result<()> {
        match &mut self.0 {
            StreamInner::Server(s) => s.send_response(response).await.map_err(protocol),
            _ => Err(Error::Unsupported("server response on client stream")),
        }
    }
    pub async fn send(&mut self, bytes: Bytes) -> Result<()> {
        match &mut self.0 {
            StreamInner::Client(s) => s.send_data(bytes).await.map_err(protocol),
            StreamInner::Server(s) => s.send_data(bytes).await.map_err(protocol),
        }
    }
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        if let Some(data) = self.1.take() {
            return Ok(Some(data));
        }
        match &mut self.0 {
            StreamInner::Client(s) => Ok(s
                .recv_data()
                .await
                .map_err(protocol)?
                .map(|mut b| b.copy_to_bytes(b.remaining()))),
            StreamInner::Server(s) => Ok(s
                .recv_data()
                .await
                .map_err(protocol)?
                .map(|mut b| b.copy_to_bytes(b.remaining()))),
        }
    }
    pub async fn finish(&mut self) -> Result<()> {
        match &mut self.0 {
            StreamInner::Client(s) => s.finish().await.map_err(protocol),
            StreamInner::Server(s) => s.finish().await.map_err(protocol),
        }
    }
}

pub struct SendStream(SendInner);
enum SendInner {
    Client(h3::client::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
    Server(h3::server::RequestStream<h3_quinn::SendStream<Bytes>, Bytes>),
}
pub struct RecvStream(RecvInner, Option<Bytes>);
enum RecvInner {
    Client(h3::client::RequestStream<h3_quinn::RecvStream, Bytes>),
    Server(h3::server::RequestStream<h3_quinn::RecvStream, Bytes>),
}
impl Stream {
    pub fn split(self) -> (SendStream, RecvStream) {
        match self.0 {
            StreamInner::Client(s) => {
                let (tx, rx) = s.split();
                (
                    SendStream(SendInner::Client(tx)),
                    RecvStream(RecvInner::Client(rx), self.1),
                )
            }
            StreamInner::Server(s) => {
                let (tx, rx) = s.split();
                (
                    SendStream(SendInner::Server(tx)),
                    RecvStream(RecvInner::Server(rx), self.1),
                )
            }
        }
    }
}
impl SendStream {
    pub async fn send(&mut self, data: Bytes) -> Result<()> {
        match &mut self.0 {
            SendInner::Client(s) => s.send_data(data).await.map_err(protocol),
            SendInner::Server(s) => s.send_data(data).await.map_err(protocol),
        }
    }
    pub async fn finish(&mut self) -> Result<()> {
        match &mut self.0 {
            SendInner::Client(s) => s.finish().await.map_err(protocol),
            SendInner::Server(s) => s.finish().await.map_err(protocol),
        }
    }
}
impl RecvStream {
    pub async fn recv(&mut self) -> Result<Option<Bytes>> {
        if let Some(data) = self.1.take() {
            return Ok(Some(data));
        }
        match &mut self.0 {
            RecvInner::Client(s) => Ok(s
                .recv_data()
                .await
                .map_err(protocol)?
                .map(|mut b| b.copy_to_bytes(b.remaining()))),
            RecvInner::Server(s) => Ok(s
                .recv_data()
                .await
                .map_err(protocol)?
                .map(|mut b| b.copy_to_bytes(b.remaining()))),
        }
    }
}
