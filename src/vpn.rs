//! Platform-independent, statically configured, single-peer CONNECT-IP prototype.
//! Network setup is external; this module never changes routes or DNS.
#[cfg(any(feature = "client", feature = "server"))]
use anyhow::{Context, bail};
use anyhow::{Result, ensure};
#[cfg(any(feature = "client", feature = "server", test))]
use bytes::Bytes;
#[cfg(any(feature = "client", feature = "server"))]
use h2::{RecvStream, SendStream};
use ipnet::IpNet;
pub mod control;
#[cfg(any(feature = "client", feature = "server"))]
use std::future::poll_fn;
use std::net::IpAddr;

pub const PATH: &str = "/.well-known/masque/ip/*/*/";
pub const MTU: usize = 1500;

#[derive(Clone, Debug)]
pub struct Config {
    pub local: Vec<IpAddr>,
    pub peer: Vec<IpAddr>,
    pub local_routes: Vec<IpNet>,
    pub peer_routes: Vec<IpNet>,
}

impl Config {
    pub fn validate(&self) -> Result<()> {
        for prefixes in [&self.local_routes, &self.peer_routes] {
            ensure!(prefixes.len() <= 60, "too many configured VPN prefixes");
            ensure!(
                prefixes.iter().all(|p| p.addr() == p.network()),
                "VPN prefixes must be canonical"
            );
        }
        ensure!(
            !self.local.is_empty() && !self.peer.is_empty(),
            "VPN needs local and peer addresses"
        );
        for addresses in [&self.local, &self.peer] {
            for (index, ip) in addresses.iter().enumerate() {
                ensure!(
                    !ip.is_unspecified() && !ip.is_multicast() && !ip.is_loopback(),
                    "invalid tunnel address"
                );
                ensure!(
                    !addresses[..index]
                        .iter()
                        .any(|other| other.is_ipv4() == ip.is_ipv4()),
                    "prototype allows one address per IP version"
                );
            }
        }
        ensure!(
            self.local.iter().all(|ip| self
                .peer
                .iter()
                .any(|p| p.is_ipv4() == ip.is_ipv4() && p != ip))
                && self.peer.iter().all(|ip| self
                    .local
                    .iter()
                    .any(|p| p.is_ipv4() == ip.is_ipv4() && p != ip)),
            "local and peer IP versions must match and addresses must differ"
        );
        Ok(())
    }

    #[cfg(any(feature = "client", feature = "server", test))]
    pub(crate) fn incoming(&self, source: IpAddr, dest: IpAddr) -> bool {
        allowed_ip(source)
            && allowed_ip(dest)
            && (self.peer.contains(&source) || self.peer_routes.iter().any(|p| p.contains(&source)))
            && (self.local.contains(&dest) || self.local_routes.iter().any(|p| p.contains(&dest)))
    }
}

#[cfg(any(feature = "client", feature = "server", test))]
fn allowed_ip(ip: IpAddr) -> bool {
    !ip.is_unspecified()
        && !ip.is_multicast()
        && !ip.is_loopback()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && ip.octets()[0] != 0 && ip.octets()[0] < 224,
            IpAddr::V6(ip) => !ip.is_unicast_link_local() && ip.to_ipv4_mapped().is_none(),
        }
}

fn varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let size = 1 << (bytes.first()? >> 6);
    if bytes.len() < size {
        return None;
    }
    let mut value = (bytes[0] & 0x3f) as u64;
    for byte in &bytes[1..size] {
        value = (value << 8) | *byte as u64;
    }
    Some((value, size))
}

fn encode_varint(value: usize, out: &mut Vec<u8>) {
    if value < 64 {
        out.push(value as u8);
    } else if value < 16384 {
        out.extend_from_slice(&((value as u16) | 0x4000).to_be_bytes());
    } else {
        out.extend_from_slice(&((value as u32) | 0x80000000).to_be_bytes());
    }
}

#[cfg(test)]
fn datagram(packet: &[u8]) -> Bytes {
    let mut out = Vec::with_capacity(packet.len() + 6);
    append_datagram(&mut out, packet);
    Bytes::from(out)
}

#[cfg(any(feature = "client", feature = "server", test))]
fn append_datagram(out: &mut Vec<u8>, packet: &[u8]) {
    out.push(0); // DATAGRAM capsule
    encode_varint(packet.len() + 1, out);
    out.push(0); // CONNECT-IP context ID
    out.extend_from_slice(packet);
}

/// Incremental capsule decoder. Unknown capsules are skipped without allocation,
/// even when their declared length is enormous. DATA frame boundaries are ignored.
#[derive(Default)]
pub struct Decoder {
    header: Vec<u8>,
    remaining: Option<u64>,
    datagram: bool,
    kind: u64,
    body: Vec<u8>,
}

impl Decoder {
    pub fn feed(
        &mut self,
        input: &[u8],
        mut packet: impl FnMut(&[u8]) -> Result<()>,
    ) -> Result<()> {
        self.feed_events(input, |event| match event {
            control::Event::Packet(data) => packet(data),
            _ => Ok(()),
        })
    }

    pub fn feed_events(
        &mut self,
        mut input: &[u8],
        mut event: impl FnMut(control::Event<'_>) -> Result<()>,
    ) -> Result<()> {
        while !input.is_empty() {
            if let Some(remaining) = self.remaining {
                let take = remaining.min(input.len() as u64) as usize;
                if self.kind <= 3 {
                    self.body.extend_from_slice(&input[..take]);
                }
                input = &input[take..];
                self.remaining = Some(remaining - take as u64);
                if self.remaining == Some(0) {
                    self.complete(&mut event)?;
                }
                continue;
            }
            self.header.push(input[0]);
            input = &input[1..];
            if let Some((kind, type_len)) = varint(&self.header)
                && let Some((length, _)) = varint(&self.header[type_len..])
            {
                self.datagram = kind == 0;
                self.kind = kind;
                ensure!(
                    !self.datagram || length <= (MTU + 8) as u64,
                    "oversized DATAGRAM capsule"
                );
                ensure!(
                    kind == 0 || kind > 3 || length <= 4096,
                    "oversized configuration capsule"
                );
                self.remaining = Some(length);
                self.header.clear();
                if length == 0 {
                    self.complete(&mut event)?;
                }
            }
        }
        Ok(())
    }

    fn complete(&mut self, event: &mut impl FnMut(control::Event<'_>) -> Result<()>) -> Result<()> {
        if self.kind <= 3 {
            control::decode(self.kind, &self.body, event)?;
        }
        self.body.clear();
        self.remaining = None;
        Ok(())
    }

    pub fn finish(&self) -> Result<()> {
        ensure!(
            self.header.is_empty() && self.remaining.is_none(),
            "truncated capsule at END_STREAM"
        );
        Ok(())
    }
}

/// Validate full IP lengths and extract source/destination. No userspace TCP stack.
#[cfg(any(feature = "client", feature = "server", test))]
pub(crate) fn addresses(packet: &[u8]) -> Option<(IpAddr, IpAddr)> {
    if packet.len() > MTU {
        return None;
    }
    match packet.first()? >> 4 {
        4 if packet.len() >= 20 => {
            let header = ((packet[0] & 15) as usize) * 4;
            if header < 20
                || header > packet.len()
                || u16::from_be_bytes([packet[2], packet[3]]) as usize != packet.len()
            {
                return None;
            }
            Some((
                IpAddr::from(<[u8; 4]>::try_from(&packet[12..16]).ok()?),
                IpAddr::from(<[u8; 4]>::try_from(&packet[16..20]).ok()?),
            ))
        }
        6 if packet.len() >= 40 => {
            if u16::from_be_bytes([packet[4], packet[5]]) as usize + 40 != packet.len() {
                return None;
            }
            Some((
                IpAddr::from(<[u8; 16]>::try_from(&packet[8..24]).ok()?),
                IpAddr::from(<[u8; 16]>::try_from(&packet[24..40]).ok()?),
            ))
        }
        _ => None,
    }
}

#[cfg(any(feature = "client", feature = "server"))]
pub(crate) async fn bridge(
    mut device: crate::packet::PacketDevice,
    config: &Config,
    mut input: RecvStream,
    mut output: SendStream<Bytes>,
    counters: std::sync::Arc<crate::stats::Counters>,
    status: Option<tokio::sync::watch::Sender<crate::stats::SessionState>>,
) -> Result<()> {
    let assignments: Vec<_> = config
        .peer
        .iter()
        .map(|ip| control::Assignment {
            id: 0,
            prefix: IpNet::from(*ip),
        })
        .collect();
    crate::h2_io::send(&mut output, control::assign(&assignments)).await?;
    crate::h2_io::send(&mut output, control::advertise(config)).await?;
    let state = std::sync::Mutex::new(control::State::new());
    let (replies, responses) = tokio::sync::mpsc::channel::<Bytes>(16);
    tokio::select! {
        result = send_packets(&mut *device.recv, config, &mut output, &state, responses, &counters) => result,
        result = receive_packets(&mut *device.send, config, &mut input, &state, replies, status.as_ref(), &counters) => result,
    }
}

#[cfg(any(feature = "client", feature = "server"))]
async fn send_packets(
    recv: &mut dyn crate::packet::PacketRecv,
    config: &Config,
    output: &mut SendStream<Bytes>,
    state: &std::sync::Mutex<control::State>,
    mut responses: tokio::sync::mpsc::Receiver<Bytes>,
    counters: &crate::stats::Counters,
) -> Result<()> {
    // Drain short device bursts independently of H2 send capacity. A blocked
    // carrier still applies backpressure after this fixed queue fills. These
    // are borrowed futures, not detached tasks; session teardown drops both.
    let (queued, mut batches) = tokio::sync::mpsc::channel(OUTBOUND_BATCHES);
    let collect = collect_packets(recv, config, queued);
    let forward = async {
        loop {
            let batch = tokio::select! {
                biased;
                Some(reply) = responses.recv() => {
                    crate::h2_io::send(output, reply).await?;
                    continue;
                }
                batch = batches.recv() => batch.context("packet reader closed")?,
            };
            // Advertisements may have changed while the batch was queued.
            // Apply the current route/assignment state immediately before send.
            let data = encode_packets(batch, config, state, counters);
            if !data.is_empty() {
                crate::h2_io::send(output, data).await?;
            }
        }
        #[allow(unreachable_code)]
        Ok::<_, anyhow::Error>(())
    };
    tokio::select! {
        result = collect => result,
        result = forward => result,
    }
}

#[cfg(any(feature = "client", feature = "server"))]
const OUTBOUND_BATCHES: usize = 64;

#[cfg(any(feature = "client", feature = "server"))]
async fn collect_packets(
    recv: &mut dyn crate::packet::PacketRecv,
    config: &Config,
    queued: tokio::sync::mpsc::Sender<Vec<Bytes>>,
) -> Result<()> {
    let mut buf = vec![0; 65536]; // large enough to detect an oversized TUN packet
    let mut work = 0;
    loop {
        let mut n = poll_fn(|cx| recv.poll_recv(cx, &mut buf)).await?;
        let mut batch = Vec::with_capacity(32);
        let mut bytes = 0;
        // Coalesce only packets already queued on TUN, without a timer.
        // Each remains a separate capsule. A DATA frame per tiny TCP ACK
        // can exhaust h2's small-frame budget before the reader is polled.
        for index in 0..32 {
            ensure!(n != 0, "TUN closed");
            work += 1;
            if work == 32 {
                tokio::task::yield_now().await;
                work = 0;
            }
            if let Some((source, destination)) = addresses(&buf[..n])
                && config.incoming(destination, source)
            {
                batch.push(Bytes::copy_from_slice(&buf[..n]));
                bytes += n + 8;
            }
            if bytes >= crate::CHUNK || index == 31 {
                break;
            }
            match recv.try_recv(&mut buf)? {
                Some(next) => n = next,
                None => break,
            }
        }
        if !batch.is_empty() {
            queued.send(batch).await.context("packet sender closed")?;
        }
    }
    #[allow(unreachable_code)]
    Ok::<_, anyhow::Error>(())
}

#[cfg(any(feature = "client", feature = "server"))]
fn encode_packets(
    packets: Vec<Bytes>,
    config: &Config,
    state: &std::sync::Mutex<control::State>,
    counters: &crate::stats::Counters,
) -> Bytes {
    let mut data = Vec::with_capacity(crate::CHUNK + MTU + 8);
    let state = state.lock().unwrap();
    for packet in packets {
        if let Some((source, destination)) = addresses(&packet)
            && state.outbound(config, source, destination)
        {
            append_datagram(&mut data, &packet);
            counters.tx(packet.len());
        }
    }
    Bytes::from(data)
}

#[cfg(any(feature = "client", feature = "server"))]
async fn receive_packets(
    send: &mut dyn crate::packet::PacketSend,
    config: &Config,
    input: &mut RecvStream,
    state: &std::sync::Mutex<control::State>,
    replies: tokio::sync::mpsc::Sender<Bytes>,
    status: Option<&tokio::sync::watch::Sender<crate::stats::SessionState>>,
    counters: &crate::stats::Counters,
) -> Result<()> {
    let mut decoder = Decoder::default();
    let mut confirmed = false;
    let mut frames = 0;
    let mut written = 0;
    while let Some(data) = input.data().await {
        let data = data?;
        let mut packets = Vec::new();
        decoder.feed_events(&data, |event| {
            if let control::Event::Packet(packet) = event {
                if let Some((source, destination)) = addresses(packet)
                    && config.incoming(source, destination)
                {
                    packets.push(packet.to_vec());
                }
            } else {
                let mut state = state.lock().unwrap();
                if let Some(reply) = state.apply(event, config)? {
                    replies
                        .try_send(reply)
                        .context("configuration response queue full")?;
                }
                if !confirmed && state.confirmed() {
                    confirmed = true;
                    if let Some(status) = &status {
                        status.send_replace(crate::stats::SessionState::Running);
                    }
                    tracing::info!(
                        addresses = state.assigned().len(),
                        routes = state.routes().len(),
                        "CONNECT-IP configuration confirmed"
                    );
                }
            }
            Ok(())
        })?;
        for packet in packets {
            poll_fn(|cx| send.poll_send(cx, &packet)).await?;
            counters.rx(packet.len());
            written += 1;
            if written == 32 {
                // Inbound TCP ACKs can immediately release an outbound burst.
                // Give the device reader a turn while that burst is still small.
                tokio::task::yield_now().await;
                written = 0;
            }
        }
        input.flow_control().release_capacity(data.len())?;
        frames += 1;
        if frames == 4 {
            // PacketSend and RecvStream may both stay ready for a large burst.
            // Let the other direction drain device ACK/data packets before the
            // kernel's small TUN ring overflows. No timer or detached task.
            tokio::task::yield_now().await;
            frames = 0;
        }
    }
    decoder.finish()?;
    bail!("VPN stream closed");
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn segmented_capsules_and_unknown() {
        let mut bytes = vec![42, 3, 1, 2, 3];
        bytes.extend_from_slice(&datagram(b"first"));
        bytes.extend_from_slice(&datagram(b"second"));
        for chunk in 1..=bytes.len() {
            let mut decoder = Decoder::default();
            let mut packets = Vec::new();
            for part in bytes.chunks(chunk) {
                decoder
                    .feed(part, |p| {
                        packets.push(p.to_vec());
                        Ok(())
                    })
                    .unwrap();
            }
            decoder.finish().unwrap();
            assert_eq!(packets, [b"first".to_vec(), b"second".to_vec()]);
        }
    }
    #[test]
    fn truncation_and_bounds() {
        for bytes in [&[0][..], &[0, 5, 0, 1][..], &[0, 1, 0x40][..]] {
            let mut decoder = Decoder::default();
            let result = decoder.feed(bytes, |_| Ok(()));
            assert!(result.is_err() || decoder.finish().is_err());
        }
        let mut decoder = Decoder::default();
        assert!(decoder.feed(&[0, 0x7f, 0xff], |_| Ok(())).is_err());
        let mut decoder = Decoder::default();
        // Unknown type, maximal eight-byte length: skip instead of allocate.
        decoder
            .feed(
                &[42, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 1],
                |_| Ok(()),
            )
            .unwrap();
        assert!(decoder.body.is_empty());
        assert!(decoder.finish().is_err());
    }
    #[test]
    fn nonminimal_context_and_unknown_context() {
        let mut decoder = Decoder::default();
        let mut count = 0;
        decoder
            .feed(&[0, 3, 0x40, 0, 7, 0, 2, 1, 8], |p| {
                assert_eq!(p, &[7]);
                count += 1;
                Ok(())
            })
            .unwrap();
        decoder.finish().unwrap();
        assert_eq!(count, 1);
    }
    #[test]
    fn packet_lengths() {
        let mut packet = vec![0; 20];
        packet[0] = 0x45;
        packet[3] = 20;
        assert!(addresses(&packet).is_some());
        packet[3] = 21;
        assert!(addresses(&packet).is_none());
        let mut packet = vec![0; 40];
        packet[0] = 0x60;
        assert!(addresses(&packet).is_some());
        packet[5] = 1;
        assert!(addresses(&packet).is_none());
    }
}

#[cfg(all(test, any(feature = "client", feature = "server")))]
mod queue_tests {
    use super::*;
    use std::{
        future::Future,
        sync::{
            Arc,
            atomic::{AtomicUsize, Ordering},
        },
        task::{Context, Poll},
    };

    fn config() -> Config {
        Config {
            local: vec!["198.18.0.1".parse().unwrap()],
            peer: vec!["198.18.0.2".parse().unwrap()],
            local_routes: Vec::new(),
            peer_routes: Vec::new(),
        }
    }

    fn packet(marker: u8) -> Bytes {
        let mut p = vec![0; 1280];
        p[0] = 0x45;
        p[2..4].copy_from_slice(&1280u16.to_be_bytes());
        p[12..16].copy_from_slice(&[198, 18, 0, 1]);
        p[16..20].copy_from_slice(&[198, 18, 0, 2]);
        p[20] = marker;
        Bytes::from(p)
    }

    struct Source(Arc<AtomicUsize>);

    #[tokio::test]
    async fn rejected_packets_yield_to_cancellation() {
        struct Rejected(usize);
        impl crate::packet::PacketRecv for Rejected {
            fn poll_recv(
                &mut self,
                _: &mut Context<'_>,
                buffer: &mut [u8],
            ) -> Poll<std::io::Result<usize>> {
                self.0 += 1;
                assert!(self.0 <= 32, "collector did not yield");
                buffer[..20].fill(0);
                buffer[0] = 0x45;
                buffer[3] = 20;
                Poll::Ready(Ok(20))
            }
        }
        let mut source = Rejected(0);
        let (queued, _receiver) = tokio::sync::mpsc::channel(1);
        let config = config();
        let mut task = Box::pin(collect_packets(&mut source, &config, queued));
        poll_fn(|cx| {
            assert!(task.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(task);
        assert_eq!(source.0, 32);
    }
    impl crate::packet::PacketRecv for Source {
        fn poll_recv(
            &mut self,
            _: &mut Context<'_>,
            buffer: &mut [u8],
        ) -> Poll<std::io::Result<usize>> {
            let n = self.0.fetch_add(1, Ordering::SeqCst);
            let p = packet(n as u8);
            buffer[..p.len()].copy_from_slice(&p);
            Poll::Ready(Ok(p.len()))
        }
    }

    #[tokio::test]
    async fn device_bursts_are_bounded_and_resume_in_order() {
        let reads = Arc::new(AtomicUsize::new(0));
        let mut source = Source(reads.clone());
        let (queued, mut batches) = tokio::sync::mpsc::channel(OUTBOUND_BATCHES);
        let observe = queued.clone();
        let config = config();
        let mut producer = Box::pin(collect_packets(&mut source, &config, queued));
        tokio::time::timeout(
            std::time::Duration::from_secs(1),
            poll_fn(|cx| {
                assert!(producer.as_mut().poll(cx).is_pending());
                if observe.capacity() == 0 {
                    Poll::Ready(())
                } else {
                    cx.waker().wake_by_ref();
                    Poll::Pending
                }
            }),
        )
        .await
        .unwrap();
        assert_eq!(reads.load(Ordering::SeqCst), OUTBOUND_BATCHES + 1);
        assert_eq!(batches.recv().await.unwrap()[0][20], 0);
        poll_fn(|cx| {
            assert!(producer.as_mut().poll(cx).is_pending());
            if observe.capacity() == 0 {
                Poll::Ready(())
            } else {
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        })
        .await;
        assert_eq!(reads.load(Ordering::SeqCst), OUTBOUND_BATCHES + 2);
        assert_eq!(batches.recv().await.unwrap()[0][20], 1);
        drop(producer);
        let frozen = reads.load(Ordering::SeqCst);
        tokio::task::yield_now().await;
        assert_eq!(reads.load(Ordering::SeqCst), frozen);
    }

    #[test]
    fn queued_packets_follow_current_route_withdrawal() {
        let config = config();
        let mut state = control::State::new();
        state
            .apply(
                control::Event::Assign(vec![control::Assignment {
                    id: 0,
                    prefix: IpNet::from(config.local[0]),
                }]),
                &config,
            )
            .unwrap();
        let route = control::Route {
            start: config.peer[0],
            end: config.peer[0],
            protocol: 0,
        };
        state
            .apply(control::Event::Routes(vec![route.clone()]), &config)
            .unwrap();
        // This batch was read under the previous route, then withdrawn.
        let pending = vec![packet(42)];
        state
            .apply(control::Event::Routes(Vec::new()), &config)
            .unwrap();
        let state = std::sync::Mutex::new(state);
        let counters = crate::stats::Counters::default();
        assert!(encode_packets(pending, &config, &state, &counters).is_empty());
        assert_eq!(counters.snapshot().tx_bytes, 0);
        state
            .lock()
            .unwrap()
            .apply(control::Event::Routes(vec![route]), &config)
            .unwrap();
        let p = packet(43);
        let data = encode_packets(vec![p.clone()], &config, &state, &counters);
        assert_eq!(data, datagram(&p));
        assert_eq!(counters.snapshot().tx_bytes, p.len() as u64);
    }
}

/// H3 carries control capsules reliably and IP packets in HTTP datagrams.
#[cfg(all(feature = "h3", any(feature = "client", feature = "server")))]
pub(crate) async fn bridge_h3(
    mut device: crate::packet::PacketDevice,
    config: &Config,
    stream: crate::h3_transport::Stream,
    packets: (crate::h3_packets::Sender, crate::h3_packets::Receiver),
    counters: std::sync::Arc<crate::stats::Counters>,
    status: Option<tokio::sync::watch::Sender<crate::stats::SessionState>>,
) -> Result<()> {
    let (mut output, mut input) = stream.split();
    let (sender, mut receiver) = packets;
    sender.require_vpn_mtu().await?;
    let assignments: Vec<_> = config
        .peer
        .iter()
        .map(|ip| control::Assignment {
            id: 0,
            prefix: IpNet::from(*ip),
        })
        .collect();
    output.send(control::assign(&assignments)).await?;
    output.send(control::advertise(config)).await?;
    let state = std::sync::Mutex::new(control::State::new());
    let capsules = receiver.capsules();
    let control = async {
        let mut decoder = Decoder::default();
        while let Some(data) = input.recv().await? {
            let mut replies = Vec::new();
            decoder.feed_events(&data, |event| {
                // RFC 9297 gives capsules and QUIC datagrams identical receive
                // semantics. Both enter the same bounded, age-limited queue.
                if let control::Event::Packet(packet) = event {
                    capsules.send(Bytes::copy_from_slice(packet));
                } else {
                    let mut state = state.lock().unwrap();
                    if let Some(reply) = state.apply(event, config)? {
                        ensure!(replies.len() < 16, "too many pending control replies");
                        replies.push(reply);
                    }
                    if state.confirmed()
                        && let Some(status) = &status
                    {
                        status.send_replace(crate::stats::SessionState::Running);
                    }
                }
                Ok(())
            })?;
            for reply in replies {
                output.send(reply).await?;
            }
            tokio::task::yield_now().await;
        }
        decoder.finish()?;
        Err::<(), _>(anyhow::anyhow!("CONNECT-IP control stream closed"))
    };
    let upload = async {
        let mut buffer = vec![0; 65536];
        loop {
            let length = poll_fn(|cx| device.recv.poll_recv(cx, &mut buffer)).await?;
            ensure!(length != 0, "packet device closed");
            if length <= 1280
                && let Some((source, destination)) = addresses(&buffer[..length])
                && config.incoming(destination, source)
                && state.lock().unwrap().outbound(config, source, destination)
            {
                sender.send(Bytes::copy_from_slice(&buffer[..length]))?;
                counters.tx(length);
            }
            tokio::task::yield_now().await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    let download = async {
        loop {
            let packet = receiver.recv().await?;
            if packet.len() <= 1280
                && let Some((source, destination)) = addresses(&packet)
                && config.incoming(source, destination)
            {
                poll_fn(|cx| device.send.poll_send(cx, &packet)).await?;
                counters.rx(packet.len());
            }
            tokio::task::yield_now().await;
        }
        #[allow(unreachable_code)]
        Ok::<(), anyhow::Error>(())
    };
    tokio::select! { result = control => result, result = upload => result, result = download => result }
}
