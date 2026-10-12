#![cfg(feature = "h3")]
use bytes::Bytes;
use foldfin::h3_transport::{Client, ConnectProtocol, Listener};
use std::{net::UdpSocket, time::Duration};

fn certificate() -> (Vec<u8>, rustls::ServerConfig) {
    let dir = tempfile::tempdir().unwrap();
    let cert = dir.path().join("cert.pem");
    let key = dir.path().join("key.pem");
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
    let pem = std::fs::read(cert).unwrap();
    let certs = rustls_pemfile::certs(&mut &pem[..])
        .collect::<std::io::Result<Vec<_>>>()
        .unwrap();
    let key = rustls_pemfile::private_key(&mut &std::fs::read(key).unwrap()[..])
        .unwrap()
        .unwrap();
    let tls = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(certs, key)
    .unwrap();
    (pem, tls)
}

#[tokio::test]
async fn independent_streams_datagrams_and_tls_validation() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let (pem, tls) = certificate();
        let listener = Listener::new(UdpSocket::bind("127.0.0.1:0").unwrap(), tls).unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            // Two rejected TLS handshakes followed by the authenticated one.
            for _ in 0..2 { assert!(listener.accept().await.unwrap().unwrap().handshake().await.is_err()); }
            let mut connection = listener.accept().await.unwrap().unwrap().handshake().await.unwrap();
            let mut datagrams = connection.datagrams();
            let dgram = tokio::spawn(async move {
                for _ in 0..3 {
                    let (id, data) = datagrams.recv().await.unwrap();
                    assert_ne!(id, 0);
                    datagrams.send(id, data).unwrap();
                }
            });
            let mut tasks = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    request = connection.accept() => {
                        let Some(request) = request.unwrap() else { break };
                        tasks.spawn(async move {
                            let (request, extension, mut stream) = request.resolve().await.unwrap();
                            assert_eq!(request.method(), "CONNECT");
                            assert_eq!(extension, Some(ConnectProtocol::Ip));
                            stream.respond(http::Response::builder().status(200).header("capsule-protocol", "?1").body(()).unwrap()).await.unwrap();
                            let mut received = Vec::new();
                            while let Some(data) = stream.recv().await.unwrap() { received.extend_from_slice(&data); }
                            stream.send(Bytes::from(received)).await.unwrap();
                            stream.finish().await.unwrap();
                        });
                    }
                    result = tasks.join_next(), if !tasks.is_empty() => { result.unwrap().unwrap(); }
                }
            }
            while let Some(result) = tasks.join_next().await { result.unwrap(); }
            dgram.await.unwrap();
            listener.stop().await;
        });
        for (name, ca) in [("localhost", None), ("wrong.invalid", Some(pem.as_slice()))] {
            let result = Client::connect(UdpSocket::bind("127.0.0.1:0").unwrap(), address, name, ca).await;
            assert!(matches!(result, Err(foldfin::error::Error::Tls(_))));
        }
        let mut client = Client::connect(UdpSocket::bind("127.0.0.1:0").unwrap(), address, "localhost", Some(&pem)).await.unwrap();
        let mut datagrams = client.datagrams();
        let mut streams = Vec::new();
        for n in 0..4 {
            let request = http::Request::builder().method("CONNECT").uri("https://localhost/.well-known/masque/ip/*/*/")
                .header("capsule-protocol", "?1").body(()).unwrap();
            let mut stream = client.request(request, Some(ConnectProtocol::Ip)).await.unwrap();
            assert_eq!(stream.response().await.unwrap().status(), 200);
            if n != 0 {
                let payload = Bytes::from(vec![n; 512]);
                datagrams.send(stream.id(), payload.clone()).unwrap();
                let (id, data) = datagrams.recv().await.unwrap();
                assert_eq!(id, stream.id());
                assert_eq!(data, payload);
            }
            streams.push(stream);
        }
        // Finish later streams before the first; independent half-close and progress.
        for mut stream in streams.into_iter().rev() {
            let payload = vec![0x5a; 96 * 1024];
            stream.send(Bytes::from(payload.clone())).await.unwrap();
            stream.finish().await.unwrap();
            let mut received = Vec::new();
            while let Some(data) = stream.recv().await.unwrap() { received.extend_from_slice(&data); }
            assert_eq!(received, payload);
        }
        assert!(matches!(datagrams.require_mtu(4, usize::MAX), Err(foldfin::error::Error::PathMtu { .. })));
        client.stop().await;
        server.await.unwrap();
    }).await.unwrap();
}

#[test]
fn datagram_quarter_stream_encoding() {
    use bytes::Buf;
    for id in [0, 4, 252, 256, 65536, 1 << 32] {
        let id = h3::quic::StreamId::try_from(id).unwrap();
        let mut wire =
            h3_datagram::datagram::Datagram::new(id, Bytes::from_static(b"packet")).encode();
        let wire = wire.copy_to_bytes(wire.remaining());
        let decoded = h3_datagram::datagram::Datagram::decode(wire).unwrap();
        assert_eq!(decoded.stream_id(), id);
        assert_eq!(decoded.into_payload(), "packet");
    }
}
