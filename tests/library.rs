//! Embedding acceptance: no CLI, environment credentials, named TUN or OS changes.
#![cfg(all(feature = "client", feature = "server"))]
use foldfin::{
    client::{Client, ClientConfig},
    credential::Credential,
    packet::{PacketDevice, PacketDeviceFactory, PacketRecv, PacketSend},
    server::{Server, ServerConfig, VpnConfig},
    stats::SessionState,
};
use std::{
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{mpsc, oneshot},
    time::timeout,
};
use tokio_rustls::rustls;

const TOKEN: &str = "0123456789abcdef0123456789abcdef";

struct Fixture {
    address: SocketAddr,
    certificate: Vec<u8>,
    stop: oneshot::Sender<()>,
    task: tokio::task::JoinHandle<foldfin::error::Result<()>>,
}

impl Fixture {
    async fn new(vpn: Option<VpnConfig>) -> Self {
        Self::new_with_transport(vpn, false).await
    }

    async fn new_with_transport(vpn: Option<VpnConfig>, h3: bool) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let key = dir.path().join("key.pem");
        let cert = dir.path().join("cert.pem");
        assert!(
            std::process::Command::new("openssl")
                .args([
                    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1", "-keyout",
                ])
                .arg(&key)
                .arg("-out")
                .arg(&cert)
                .args([
                    "-subj",
                    "/CN=localhost",
                    "-addext",
                    "subjectAltName=DNS:localhost",
                    "-addext",
                    "basicConstraints=critical,CA:FALSE",
                    "-addext",
                    "extendedKeyUsage=serverAuth",
                ])
                .output()
                .unwrap()
                .status
                .success()
        );
        let certificate = std::fs::read(cert).unwrap();
        let certs = rustls_pemfile::certs(&mut &certificate[..])
            .collect::<io::Result<Vec<_>>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut &std::fs::read(key).unwrap()[..])
            .unwrap()
            .unwrap();
        let mut tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        tls.alpn_protocols = vec![b"h2".to_vec()];
        let server = Server::new(ServerConfig {
            tls: Arc::new(tls),
            credential: Credential::bearer(TOKEN).unwrap(),
            allow_private: true,
            vpn,
        })
        .unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let (stop, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            #[cfg(feature = "h3")]
            if h3 {
                let socket = std::net::UdpSocket::bind(address).unwrap();
                return server
                    .serve_h3(socket, async {
                        let _ = stopped.await;
                    })
                    .await;
            }
            assert!(!h3);
            server
                .serve(listener, async {
                    let _ = stopped.await;
                })
                .await
        });
        Self {
            address,
            certificate,
            stop,
            task,
        }
    }

    async fn client(&self) -> Client {
        Client::connect_over(
            ClientConfig {
                authority: "localhost:8443".into(),
                server_name: "localhost".into(),
                credential: Credential::bearer(TOKEN).unwrap(),
                additional_ca_pem: Some(self.certificate.clone()),
            },
            TcpStream::connect(self.address).await.unwrap(),
        )
        .await
        .unwrap()
    }

    async fn stop(self) {
        self.stop.send(()).unwrap();
        timeout(Duration::from_secs(3), self.task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
}

async fn tcp_acceptance() {
    let fixture = Fixture::new(None).await;
    let client = fixture.client().await;
    client.probe().await.unwrap();
    let endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = endpoint.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = endpoint.accept().await.unwrap();
        let mut payload = Vec::new();
        stream.read_to_end(&mut payload).await.unwrap();
        stream.write_all(&payload).await.unwrap();
    });
    let mut flow = client.open_tcp(&address.to_string()).await.unwrap();
    let payload = vec![42; 512 * 1024];
    timeout(Duration::from_secs(5), async {
        flow.write_all(&payload).await.unwrap();
        flow.shutdown().await.unwrap();
        let mut response = Vec::new();
        flow.read_to_end(&mut response).await.unwrap();
        assert_eq!(response, payload);
        echo.await.unwrap();
    })
    .await
    .unwrap();
    assert_eq!(client.stats().tx_bytes, payload.len() as u64);
    assert_eq!(client.stats().rx_bytes, payload.len() as u64);
    assert!(client.stats().since_last_payload.is_some());
    drop(flow);

    // Cancelling an unfinished flow must close its upstream socket.
    let endpoint = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let flow = client
        .open_tcp(&endpoint.local_addr().unwrap().to_string())
        .await
        .unwrap();
    let (mut upstream, _) = endpoint.accept().await.unwrap();
    drop(flow);
    assert_eq!(
        timeout(Duration::from_secs(3), upstream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );

    // Awaited server shutdown also tears down an active upstream flow.
    let flow = client
        .open_tcp(&endpoint.local_addr().unwrap().to_string())
        .await
        .unwrap();
    let (mut upstream, _) = endpoint.accept().await.unwrap();
    fixture.stop().await;
    assert_eq!(
        timeout(Duration::from_secs(3), upstream.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    let mut states = client.subscribe();
    timeout(Duration::from_secs(3), async {
        while matches!(*states.borrow_and_update(), SessionState::Running) {
            states.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    assert!(client.open_tcp(&address.to_string()).await.is_err());
    drop(flow);
    client.stop().await.unwrap();
}

struct Reader(mpsc::UnboundedReceiver<Vec<u8>>, Arc<AtomicUsize>);
struct Writer(mpsc::UnboundedSender<Vec<u8>>, Arc<AtomicUsize>);
impl Drop for Reader {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
impl Drop for Writer {
    fn drop(&mut self) {
        self.1.fetch_add(1, Ordering::SeqCst);
    }
}
impl PacketRecv for Reader {
    fn poll_recv(&mut self, cx: &mut Context<'_>, buffer: &mut [u8]) -> Poll<io::Result<usize>> {
        match std::task::ready!(self.0.poll_recv(cx)) {
            Some(packet) if packet.len() <= buffer.len() => {
                buffer[..packet.len()].copy_from_slice(&packet);
                Poll::Ready(Ok(packet.len()))
            }
            Some(_) => Poll::Ready(Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "packet too large",
            ))),
            None => Poll::Ready(Ok(0)),
        }
    }
}
impl PacketSend for Writer {
    fn poll_send(&mut self, _cx: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
        Poll::Ready(self.0.send(packet.to_vec()).map_err(io::Error::other))
    }
}
type DeviceChannels = (
    PacketDevice,
    mpsc::UnboundedSender<Vec<u8>>,
    mpsc::UnboundedReceiver<Vec<u8>>,
);
fn device(drops: Arc<AtomicUsize>) -> DeviceChannels {
    let (inject, recv) = mpsc::unbounded_channel();
    let (send, delivered) = mpsc::unbounded_channel();
    (
        PacketDevice::new(Reader(recv, drops.clone()), Writer(send, drops)),
        inject,
        delivered,
    )
}
struct Factory(Mutex<Option<PacketDevice>>);
impl PacketDeviceFactory for Factory {
    fn open(&self) -> io::Result<PacketDevice> {
        self.0
            .lock()
            .unwrap()
            .take()
            .ok_or_else(|| io::Error::other("device already opened"))
    }
}
fn config(local: &str, peer: &str) -> foldfin::vpn::Config {
    foldfin::vpn::Config {
        local: vec![local.parse().unwrap()],
        peer: vec![peer.parse().unwrap()],
        local_routes: vec![],
        peer_routes: vec![],
    }
}
fn packet(source: [u8; 4], destination: [u8; 4]) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&28_u16.to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&source);
    packet[16..20].copy_from_slice(&destination);
    packet
}

async fn vpn_acceptance() {
    let server_drops = Arc::new(AtomicUsize::new(0));
    let client_drops = Arc::new(AtomicUsize::new(0));
    let (server_device, server_tx, mut server_rx) = device(server_drops.clone());
    let fixture = Fixture::new(Some(VpnConfig {
        policy: config("198.18.0.2", "198.18.0.1"),
        device: Arc::new(Factory(Mutex::new(Some(server_device)))),
    }))
    .await;
    let client = fixture.client().await;
    let prepared = client
        .prepare_vpn(config("198.18.0.1", "198.18.0.2"))
        .await
        .unwrap();
    assert_eq!(prepared.network_plan().local[0].to_string(), "198.18.0.1");
    let (client_device, client_tx, mut client_rx) = device(client_drops.clone());
    let tunnel = prepared.start(client_device);
    let mut states = tunnel.subscribe();
    timeout(Duration::from_secs(3), async {
        while !matches!(*states.borrow_and_update(), SessionState::Running) {
            states.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let request = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    client_tx.send(request.clone()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), server_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        request
    );
    let response = packet([198, 18, 0, 2], [198, 18, 0, 1]);
    server_tx.send(response.clone()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), client_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        response
    );
    assert_eq!(tunnel.stats().tx_bytes, 28);
    assert_eq!(tunnel.stats().rx_bytes, 28);
    tunnel.stop().await.unwrap();
    assert_eq!(client_drops.load(Ordering::SeqCst), 2);
    assert!(matches!(*states.borrow(), SessionState::Closed));
    fixture.stop().await;
    assert_eq!(server_drops.load(Ordering::SeqCst), 2);
    client.stop().await.unwrap();
}

#[test]
fn credentials_are_redacted_and_validation_does_not_read_environment() {
    assert_eq!(
        format!("{:?}", Credential::bearer(TOKEN).unwrap()),
        "Credential([REDACTED])"
    );
    assert!(Credential::bearer("too-short").is_err());
}

#[tokio::test]
async fn embedded_tcp_half_close_stats_probe_and_cancellation() {
    tcp_acceptance().await;
}

async fn slow_reader_backpressure(h3: bool) {
    // More payload than either receive window and the local socket buffers.
    // Keep only one chunk in the producer; holding a reader must stall its
    // writer, and resuming it must preserve all bytes and independent FINs.
    const CHUNK: usize = 64 * 1024;
    const CHUNKS: usize = 2048;
    let fixture = Fixture::new_with_transport(None, h3).await;
    #[cfg(feature = "h3")]
    let client: foldfin::session::Carrier = if h3 {
        foldfin::h3_client::Client::connect_over(
            ClientConfig {
                authority: "localhost:8443".into(),
                server_name: "localhost".into(),
                credential: Credential::bearer(TOKEN).unwrap(),
                additional_ca_pem: Some(fixture.certificate.clone()),
            },
            std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
            fixture.address,
        )
        .await
        .unwrap()
        .into()
    } else {
        fixture.client().await.into()
    };
    #[cfg(not(feature = "h3"))]
    let client: foldfin::session::Carrier = fixture.client().await.into();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut flow = client
        .open_tcp(&listener.local_addr().unwrap().to_string())
        .await
        .unwrap();
    let (mut upstream, _) = listener.accept().await.unwrap();
    let mut producer = tokio::spawn(async move {
        let payload = [42; CHUNK];
        for _ in 0..CHUNKS {
            flow.write_all(&payload).await.unwrap();
        }
        flow.shutdown().await.unwrap();
        flow
    });
    assert!(
        timeout(Duration::from_millis(150), &mut producer)
            .await
            .is_err()
    );
    let mut responder = tokio::spawn(async move {
        let mut count = 0;
        let mut chunk = [0; CHUNK];
        loop {
            let n = upstream.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(chunk[..n].iter().all(|&b| b == 42));
            count += n;
        }
        assert_eq!(count, CHUNKS * CHUNK);
        for _ in 0..CHUNKS {
            upstream.write_all(&[17; CHUNK]).await.unwrap();
        }
        upstream.shutdown().await.unwrap();
    });
    // Completion is a correctness bound, not a throughput benchmark. Debug QUIC
    // on a loaded builder can take tens of seconds for 128 MiB in each direction.
    let mut flow = timeout(Duration::from_secs(60), producer)
        .await
        .unwrap()
        .unwrap();
    assert!(
        timeout(Duration::from_millis(150), &mut responder)
            .await
            .is_err()
    );
    timeout(Duration::from_secs(60), async {
        let mut count = 0;
        let mut chunk = [0; CHUNK];
        loop {
            let n = flow.read(&mut chunk).await.unwrap();
            if n == 0 {
                break;
            }
            assert!(chunk[..n].iter().all(|&b| b == 17));
            count += n;
        }
        assert_eq!(count, CHUNKS * CHUNK);
        responder.await.unwrap();
    })
    .await
    .unwrap();
    drop(flow);
    client.stop().await.unwrap();
    fixture.stop().await;
}

#[tokio::test]
async fn rustls_slow_readers_preserve_bidirectional_backpressure() {
    slow_reader_backpressure(false).await;
}

#[tokio::test]
async fn embedded_vpn_uses_packet_io_and_releases_owned_endpoints() {
    vpn_acceptance().await;
}

#[tokio::test]
async fn session_retains_packet_device_across_loss_failed_recovery_and_new_carrier() {
    use foldfin::session::{Event, Session};
    let drops = Arc::new(AtomicUsize::new(0));
    let (packet_device, tx, _rx) = device(drops.clone());
    let mut session = Session::new(config("198.18.0.1", "198.18.0.2"), packet_device).unwrap();
    let mut events = session.subscribe();
    for attempt in 0..3 {
        let (packet_device, _tx, mut received) = device(Arc::new(AtomicUsize::new(0)));
        let fixture = Fixture::new_with_transport(
            Some(VpnConfig {
                policy: config("198.18.0.2", "198.18.0.1"),
                device: Arc::new(Factory(Mutex::new(Some(packet_device)))),
            }),
            cfg!(feature = "h3") && attempt == 1,
        )
        .await;
        #[cfg(feature = "h3")]
        let client: foldfin::session::Carrier = if attempt == 1 {
            foldfin::h3_client::Client::connect_over(
                ClientConfig {
                    authority: "localhost:8443".into(),
                    server_name: "localhost".into(),
                    credential: Credential::bearer(TOKEN).unwrap(),
                    additional_ca_pem: Some(fixture.certificate.clone()),
                },
                std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
                fixture.address,
            )
            .await
            .unwrap()
            .into()
        } else {
            fixture.client().await.into()
        };
        #[cfg(not(feature = "h3"))]
        let client: foldfin::session::Carrier = fixture.client().await.into();
        session.recover(client.clone()).await.unwrap();
        timeout(Duration::from_secs(3), async {
            while !matches!(*events.borrow_and_update(), Event::Running) {
                events.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        let packet = packet([198, 18, 0, 1], [198, 18, 0, 2]);
        tx.send(packet.clone()).unwrap();
        assert_eq!(
            timeout(Duration::from_secs(3), received.recv())
                .await
                .unwrap()
                .unwrap(),
            packet
        );
        client.stop().await.unwrap();
        timeout(Duration::from_secs(3), async {
            while !matches!(*events.borrow_and_update(), Event::CarrierLost { .. }) {
                events.changed().await.unwrap();
            }
        })
        .await
        .unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        fixture.stop().await;
        // A server without VPN capability rejects negotiation; the device remains owned.
        let rejected = Fixture::new(None).await;
        assert!(session.recover(rejected.client().await).await.is_err());
        assert_eq!(drops.load(Ordering::SeqCst), 0);
        assert!(matches!(session.snapshot(), Event::CarrierLost { .. }));
        rejected.stop().await;
    }
    assert_eq!(session.stats().tx_bytes, 84);
    session.stop().await.unwrap();
    session.stop().await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert_eq!(session.snapshot(), Event::Closed);
}

#[tokio::test]
async fn router_failure_is_observable_and_releases_the_device() {
    use foldfin::{admission::PeerId, router::Router};
    let drops = Arc::new(AtomicUsize::new(0));
    let (device, inject, _received) = device(drops.clone());
    let mut router = Router::start(device);
    let factory = router
        .peer(
            PeerId::new("one").unwrap(),
            config("198.18.0.2", "198.18.0.1"),
        )
        .unwrap();
    let mut peer = factory.open().unwrap();
    // Cancelling supervision does not detach the runner or consume its result.
    assert!(
        timeout(Duration::from_millis(10), router.closed())
            .await
            .is_err()
    );
    drop(inject);
    timeout(Duration::from_secs(2), router.closed())
        .await
        .unwrap();
    assert!(factory.open().is_err());
    assert!(
        std::future::poll_fn(|cx| peer.recv.poll_recv(cx, &mut [0; 1500]))
            .await
            .is_err()
    );
    assert!(router.stop().await.is_err());
    assert_eq!(drops.load(Ordering::SeqCst), 2);
}

#[tokio::test]
async fn router_adapter_panic_closes_peers_and_is_reported_on_join() {
    use foldfin::{admission::PeerId, router::Router};
    struct PanickingWriter;
    impl PacketSend for PanickingWriter {
        fn poll_send(&mut self, _: &mut Context<'_>, _: &[u8]) -> Poll<io::Result<()>> {
            panic!("injected packet adapter failure");
        }
    }
    let (device, _inject, _) = device(Arc::new(AtomicUsize::new(0)));
    let mut router = Router::start(PacketDevice {
        recv: device.recv,
        send: Box::new(PanickingWriter),
    });
    let factory = router
        .peer(
            PeerId::new("one").unwrap(),
            config("198.18.0.2", "198.18.0.1"),
        )
        .unwrap();
    let mut peer = factory.open().unwrap();
    let packet = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    std::future::poll_fn(|cx| peer.send.poll_send(cx, &packet))
        .await
        .unwrap();
    timeout(Duration::from_secs(2), router.closed())
        .await
        .unwrap();
    assert!(factory.open().is_err());
    assert!(
        std::future::poll_fn(|cx| peer.recv.poll_recv(cx, &mut [0; 1500]))
            .await
            .is_err()
    );
    assert!(router.stop().await.is_err());
    drop(peer);
}

#[tokio::test]
async fn replacing_peer_wakes_a_stale_pending_kernel_write() {
    use foldfin::{admission::PeerId, router::Router};
    use std::future::poll_fn;
    struct BlockOld {
        polled: mpsc::UnboundedSender<()>,
        delivered: mpsc::UnboundedSender<Vec<u8>>,
    }
    impl PacketSend for BlockOld {
        fn poll_send(&mut self, _: &mut Context<'_>, packet: &[u8]) -> Poll<io::Result<()>> {
            if packet[1] == 0 {
                self.polled.send(()).unwrap();
                // The old packet never becomes writable. Replacement must cancel it.
                Poll::Pending
            } else {
                Poll::Ready(
                    self.delivered
                        .send(packet.to_vec())
                        .map_err(io::Error::other),
                )
            }
        }
    }
    let drops = Arc::new(AtomicUsize::new(0));
    let (device, _inject, _) = device(drops);
    let (polled, mut waiting) = mpsc::unbounded_channel();
    let (delivered, mut received) = mpsc::unbounded_channel();
    let mut router = Router::start(PacketDevice {
        recv: device.recv,
        send: Box::new(BlockOld { polled, delivered }),
    });
    let factory = router
        .peer(
            PeerId::new("one").unwrap(),
            config("198.18.0.2", "198.18.0.1"),
        )
        .unwrap();
    let mut old = factory.open().unwrap();
    let packet = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    poll_fn(|cx| old.send.poll_send(cx, &packet)).await.unwrap();
    timeout(Duration::from_secs(2), waiting.recv())
        .await
        .unwrap()
        .unwrap();
    let mut next = factory.open().unwrap();
    let mut new_packet = packet;
    new_packet[1] = 1;
    poll_fn(|cx| next.send.poll_send(cx, &new_packet))
        .await
        .unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), received.recv())
            .await
            .unwrap()
            .unwrap(),
        new_packet
    );
    router.stop().await.unwrap();
}

#[tokio::test]
async fn shared_router_isolates_peers_and_keeps_one_device_owner() {
    use foldfin::{admission::PeerId, router::Router};
    use std::future::poll_fn;
    let drops = Arc::new(AtomicUsize::new(0));
    let (device, kernel_tx, mut kernel_rx) = device(drops.clone());
    let mut router = Router::start(device);
    let first_factory = router
        .peer(
            PeerId::new("first").unwrap(),
            config("198.18.0.2", "198.18.0.1"),
        )
        .unwrap();
    let mut first = first_factory.open().unwrap();
    let second_factory = router
        .peer(
            PeerId::new("second").unwrap(),
            config("198.18.0.2", "198.18.0.3"),
        )
        .unwrap();
    let mut second = second_factory.open().unwrap();
    let one = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    let two = packet([198, 18, 0, 3], [198, 18, 0, 2]);
    poll_fn(|cx| first.send.poll_send(cx, &one)).await.unwrap();
    poll_fn(|cx| second.send.poll_send(cx, &two)).await.unwrap();
    let mut seen = Vec::new();
    for _ in 0..2 {
        seen.push(
            timeout(Duration::from_secs(2), kernel_rx.recv())
                .await
                .unwrap()
                .unwrap(),
        );
    }
    assert!(seen.contains(&one) && seen.contains(&two));
    assert!(poll_fn(|cx| first.send.poll_send(cx, &two)).await.is_err());
    assert_eq!(router.stats().rejected_packets, 1);
    assert!(
        router
            .peer(
                PeerId::new("overlap").unwrap(),
                config("198.18.0.2", "198.18.0.1")
            )
            .unwrap()
            .open()
            .is_err()
    );
    // Preparing and discarding a candidate does not alter active routes.
    drop(first_factory.open().unwrap());
    let reply_one = packet([198, 18, 0, 2], [198, 18, 0, 1]);
    let reply_two = packet([198, 18, 0, 2], [198, 18, 0, 3]);
    kernel_tx.send(reply_one.clone()).unwrap();
    kernel_tx.send(reply_two.clone()).unwrap();
    for (device, expected) in [(&mut first, &reply_one), (&mut second, &reply_two)] {
        let mut buffer = [0; 1500];
        let n = timeout(
            Duration::from_secs(2),
            poll_fn(|cx| device.recv.poll_recv(cx, &mut buffer)),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(&buffer[..n], expected);
    }
    let mut replacement = first_factory.open().unwrap();
    poll_fn(|cx| replacement.send.poll_send(cx, &one))
        .await
        .unwrap();
    assert!(poll_fn(|cx| first.send.poll_send(cx, &one)).await.is_err());
    drop(first);
    assert_eq!(drops.load(Ordering::SeqCst), 0);
    router.stop().await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    assert!(
        poll_fn(|cx| replacement.send.poll_send(cx, &one))
            .await
            .is_err()
    );
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_vpn_carries_full_mtu_datagrams_and_reliable_configuration() {
    let server_drops = Arc::new(AtomicUsize::new(0));
    let (server_device, server_tx, mut server_rx) = device(server_drops.clone());
    let fixture = Fixture::new_with_transport(
        Some(VpnConfig {
            policy: config("198.18.0.2", "198.18.0.1"),
            device: Arc::new(Factory(Mutex::new(Some(server_device)))),
        }),
        true,
    )
    .await;
    let client = foldfin::h3_client::Client::connect_over(
        ClientConfig {
            authority: "localhost:8443".into(),
            server_name: "localhost".into(),
            credential: Credential::bearer(TOKEN).unwrap(),
            additional_ca_pem: Some(fixture.certificate.clone()),
        },
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        fixture.address,
    )
    .await
    .unwrap();
    client.probe().await.unwrap();
    let prepared = client
        .prepare_vpn(config("198.18.0.1", "198.18.0.2"))
        .await
        .unwrap();
    let drops = Arc::new(AtomicUsize::new(0));
    let (device, tx, mut rx) = device(drops.clone());
    let tunnel = prepared.start(device);
    let mut state = tunnel.subscribe();
    timeout(Duration::from_secs(3), async {
        while !matches!(*state.borrow_and_update(), SessionState::Running) {
            state.changed().await.unwrap();
        }
    })
    .await
    .unwrap();
    let mut request = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    request.resize(1280, 0x5a);
    request[2..4].copy_from_slice(&1280_u16.to_be_bytes());
    tx.send(request.clone()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), server_rx.recv())
            .await
            .unwrap()
            .unwrap(),
        request
    );
    let response = packet([198, 18, 0, 2], [198, 18, 0, 1]);
    server_tx.send(response.clone()).unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), rx.recv())
            .await
            .unwrap()
            .unwrap(),
        response
    );
    tunnel.stop().await.unwrap();
    assert_eq!(drops.load(Ordering::SeqCst), 2);
    client.stop().await.unwrap();
    fixture.stop().await;
    assert_eq!(server_drops.load(Ordering::SeqCst), 2);
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_accepts_early_datagram_capsules_without_losing_buffered_data() {
    use bytes::Bytes;
    let (packet_device, _tx, mut received) = device(Arc::new(AtomicUsize::new(0)));
    let fixture = Fixture::new_with_transport(
        Some(VpnConfig {
            policy: config("198.18.0.2", "198.18.0.1"),
            device: Arc::new(Factory(Mutex::new(Some(packet_device)))),
        }),
        true,
    )
    .await;
    let mut client = foldfin::h3_transport::Client::connect(
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        fixture.address,
        "localhost",
        Some(&fixture.certificate),
    )
    .await
    .unwrap();
    let mut stream = client
        .request(
            http::Request::builder()
                .method("CONNECT")
                .uri(format!("https://localhost{}", foldfin::vpn::PATH))
                .header("authorization", format!("Bearer {TOKEN}"))
                .header("capsule-protocol", "?1")
                .body(())
                .unwrap(),
            Some(foldfin::h3_transport::ConnectProtocol::Ip),
        )
        .await
        .unwrap();
    let packet = packet([198, 18, 0, 1], [198, 18, 0, 2]);
    let mut capsule = vec![0, (packet.len() + 1) as u8, 0];
    capsule.extend_from_slice(&packet);
    stream.send(Bytes::from(capsule)).await.unwrap();
    assert_eq!(stream.response().await.unwrap().status(), 200);
    assert_eq!(
        timeout(Duration::from_secs(3), received.recv())
            .await
            .unwrap()
            .unwrap(),
        packet
    );
    drop(stream);
    client.stop().await;
    fixture.stop().await;
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_proxy_preserves_half_close_and_cancels_upstream_on_drop() {
    let fixture = Fixture::new_with_transport(None, true).await;
    let client = foldfin::h3_client::Client::connect_over(
        ClientConfig {
            authority: "localhost:8443".into(),
            server_name: "localhost".into(),
            credential: Credential::bearer(TOKEN).unwrap(),
            additional_ca_pem: Some(fixture.certificate.clone()),
        },
        std::net::UdpSocket::bind("127.0.0.1:0").unwrap(),
        fixture.address,
    )
    .await
    .unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = listener.local_addr().unwrap().to_string();
    let mut flow = client.open_tcp(&target).await.unwrap();
    let (mut upstream, _) = listener.accept().await.unwrap();
    let echo = tokio::spawn(async move {
        let mut data = Vec::new();
        upstream.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, vec![42; 256 * 1024]);
        upstream.write_all(&data).await.unwrap();
        upstream.shutdown().await.unwrap();
    });
    timeout(Duration::from_secs(5), async {
        flow.write_all(&vec![42; 256 * 1024]).await.unwrap();
        flow.shutdown().await.unwrap();
        let mut reply = Vec::new();
        flow.read_to_end(&mut reply).await.unwrap();
        assert_eq!(reply, vec![42; 256 * 1024]);
        echo.await.unwrap();
    })
    .await
    .unwrap();
    let mut cancelled = client.open_tcp(&target).await.unwrap();
    let (mut upstream, _) = listener.accept().await.unwrap();
    // Cancellation must also work after the QUIC reader has returned Pending.
    // h3-quinn 0.0.10 previously moved its stream out and panicked on this drop.
    assert!(
        timeout(Duration::from_millis(20), cancelled.read_u8())
            .await
            .is_err()
    );
    drop(cancelled);
    let read = timeout(Duration::from_secs(3), upstream.read(&mut [0; 1]))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "unfinished CONNECT must close upstream"
    );
    client.stop().await.unwrap();
    fixture.stop().await;
}

#[cfg(feature = "h3")]
#[tokio::test]
async fn h3_slow_readers_preserve_bidirectional_backpressure() {
    slow_reader_backpressure(true).await;
}
