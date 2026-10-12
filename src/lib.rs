//! Foldfin: an embeddable TCP proxy and CONNECT-IP engine on the caller's Tokio runtime.
//! Client and server roles share the protocol core; OS/network setup stays in adapters.
#![doc = include_str!("../docs/LIBRARY.md")]
#[cfg(feature = "server")]
use anyhow::{Result, anyhow, bail};
#[cfg(feature = "server")]
use bytes::Bytes;
#[cfg(feature = "server")]
use h2::{RecvStream, SendStream};
pub mod adapters;
#[cfg(feature = "server")]
pub mod authorization;
#[cfg(feature = "chrome-tls")]
pub mod chrome_tls;
#[cfg(feature = "cli")]
pub mod cli;
#[cfg(feature = "client")]
pub mod client;
#[cfg(any(feature = "client", feature = "server"))]
pub mod credential;
pub mod error;
#[cfg(any(feature = "client", feature = "server"))]
mod h2_io;
#[cfg(any(feature = "client", feature = "server"))]
mod h2_window;
#[cfg(feature = "h3")]
pub mod h3_transport;
pub mod packet;
#[cfg(feature = "server")]
mod request;
#[cfg(feature = "server")]
pub mod server;
pub mod stats;
pub mod vpn;
#[cfg(any(feature = "server", test))]
use std::net::IpAddr;
#[cfg(feature = "server")]
use std::net::SocketAddr;
use std::time::Duration;
#[cfg(feature = "server")]
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, lookup_host},
    time::timeout,
};

pub const DEADLINE: Duration = Duration::from_secs(15);
pub const CHUNK: usize = 16 * 1024;

#[cfg(feature = "server")]
pub(crate) async fn upload<R: AsyncRead + Unpin>(
    mut input: R,
    mut output: SendStream<Bytes>,
) -> Result<()> {
    let mut buf = vec![0; CHUNK];
    loop {
        let n = input.read(&mut buf).await?;
        if n == 0 {
            output.send_data(Bytes::new(), true)?;
            return Ok(());
        }
        h2_io::send(&mut output, Bytes::copy_from_slice(&buf[..n])).await?;
    }
}

#[cfg(feature = "server")]
pub(crate) async fn download<W: AsyncWrite + Unpin>(
    mut input: RecvStream,
    mut output: W,
) -> Result<()> {
    while let Some(data) = input.data().await {
        let data = data?;
        output.write_all(&data).await?;
        input.flow_control().release_capacity(data.len())?;
    }
    output.shutdown().await?;
    Ok(())
}

#[cfg(feature = "server")]
pub(crate) async fn bridge(
    tcp: TcpStream,
    incoming: RecvStream,
    outgoing: SendStream<Bytes>,
) -> Result<()> {
    let (read, write) = tcp.into_split();
    tokio::try_join!(upload(read, outgoing), download(incoming, write))?;
    Ok(())
}

#[cfg(any(feature = "server", test))]
pub(crate) fn public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v) => {
            let [a, b, _, _] = v.octets();
            !(v.is_private()
                || v.is_loopback()
                || v.is_link_local()
                || v.is_multicast()
                || a == 0
                || a >= 240
                || (a == 100 && (64..128).contains(&b))
                || (a == 192 && b == 0)
                || (a == 198 && (b == 18 || b == 19))
                || v.is_documentation())
        }
        IpAddr::V6(v) => {
            if let Some(v4) = v.to_ipv4_mapped() {
                return public_ip(IpAddr::V4(v4));
            }
            let s = v.segments();
            // Conservative: only global unicast, excluding documentation.
            s[0] & 0xe000 == 0x2000 && !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
    }
}

#[cfg(feature = "server")]
pub(crate) async fn connect_target(authority: &str, allow_private: bool) -> Result<TcpStream> {
    let authority: http::uri::Authority = authority.parse()?;
    let port = authority
        .port_u16()
        .ok_or_else(|| anyhow!("port required"))?;
    if port == 0 {
        bail!("invalid port");
    }
    let host = authority
        .host()
        .trim_start_matches('[')
        .trim_end_matches(']');
    let addresses: Vec<SocketAddr> = timeout(DEADLINE, lookup_host((host, port)))
        .await??
        .collect();
    if addresses.is_empty() || (!allow_private && addresses.iter().any(|a| !public_ip(a.ip()))) {
        bail!("destination denied");
    }
    // Connect to the already validated addresses, preventing a second DNS lookup.
    timeout(DEADLINE, async {
        for address in addresses.iter().take(16) {
            if let Ok(Ok(stream)) =
                timeout(Duration::from_secs(3), TcpStream::connect(address)).await
            {
                return Ok(stream);
            }
        }
        Err(anyhow!("destination unavailable"))
    })
    .await?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn addresses() {
        for s in [
            "127.0.0.1",
            "10.0.0.1",
            "100.64.0.1",
            "169.254.169.254",
            "::1",
            "::ffff:127.0.0.1",
            "fd00::1",
        ] {
            assert!(!public_ip(s.parse().unwrap()), "{s}");
        }
        assert!(public_ip("1.1.1.1".parse().unwrap()));
    }
}
