//! Loopback SOCKS5 TCP adapter over the public Client API.
use crate::session::Carrier;
use anyhow::{Result, bail};
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Semaphore,
    task::JoinSet,
    time::timeout,
};

/// Runs until shutdown/carrier failure, cancelling and joining all accepted flows.
pub async fn serve(
    listener: TcpListener,
    client: impl Into<Carrier>,
    shutdown: impl std::future::Future<Output = ()>,
) -> Result<()> {
    if !listener.local_addr()?.ip().is_loopback() {
        bail!("SOCKS listener must be loopback");
    }
    let limit = Arc::new(Semaphore::new(64));
    let mut tasks = JoinSet::new();
    let client = client.into();
    let closing = client.clone();
    let closed = closing.closed();
    tokio::pin!(closed);
    tokio::pin!(shutdown);
    tracing::info!("SOCKS5 listening on {}", listener.local_addr()?);
    let result = loop {
        tokio::select! {
            _ = &mut shutdown => break Ok(()),
            _ = &mut closed => break Err(anyhow::anyhow!("carrier closed")),
            _ = tasks.join_next(), if !tasks.is_empty() => {},
            accepted = listener.accept() => {
                let (tcp, _) = match accepted { Ok(tcp) => tcp, Err(e) => break Err(e.into()) };
                let Ok(permit) = limit.clone().try_acquire_owned() else { continue; };
                let client = client.clone();
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Err(error) = serve_flow(tcp, client).await { tracing::debug!(%error, "SOCKS stream failed"); }
                });
            }
        }
    };
    tasks.abort_all();
    while tasks.join_next().await.is_some() {}
    result
}

async fn serve_flow(mut tcp: TcpStream, client: Carrier) -> Result<()> {
    let target = timeout(crate::DEADLINE, negotiate(&mut tcp)).await??;
    match client.open_tcp(&target).await {
        Ok(mut stream) => {
            reply(&mut tcp, 0).await?;
            tokio::io::copy_bidirectional(&mut tcp, &mut stream).await?;
            Ok(())
        }
        Err(error) => {
            reply(&mut tcp, 1).await?;
            Err(error.into())
        }
    }
}

async fn reply(tcp: &mut TcpStream, status: u8) -> Result<()> {
    tcp.write_all(&[5, status, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    Ok(())
}

async fn negotiate(tcp: &mut TcpStream) -> Result<String> {
    let version = tcp.read_u8().await?;
    let n = tcp.read_u8().await? as usize;
    if version != 5 || n == 0 {
        bail!("invalid SOCKS greeting");
    }
    let mut methods = vec![0; n];
    tcp.read_exact(&mut methods).await?;
    if !methods.contains(&0) {
        tcp.write_all(&[5, 255]).await?;
        bail!("no supported auth method");
    }
    tcp.write_all(&[5, 0]).await?;
    let mut header = [0; 4];
    tcp.read_exact(&mut header).await?;
    if header[0] != 5 || header[2] != 0 {
        bail!("invalid SOCKS request");
    }
    if header[1] != 1 {
        reply(tcp, 7).await?;
        bail!("only TCP CONNECT supported");
    }
    let host = match header[3] {
        1 => {
            let mut octets = [0; 4];
            tcp.read_exact(&mut octets).await?;
            IpAddr::V4(Ipv4Addr::from(octets)).to_string()
        }
        4 => {
            let mut octets = [0; 16];
            tcp.read_exact(&mut octets).await?;
            format!("[{}]", Ipv6Addr::from(octets))
        }
        3 => {
            let n = tcp.read_u8().await? as usize;
            let mut bytes = vec![0; n];
            tcp.read_exact(&mut bytes).await?;
            let host = String::from_utf8(bytes)?;
            if host.is_empty()
                || !host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'.' || b == b'-')
            {
                bail!("invalid hostname");
            }
            host
        }
        _ => {
            reply(tcp, 8).await?;
            bail!("unsupported address type");
        }
    };
    let port = tcp.read_u16().await?;
    Ok(format!("{host}:{port}"))
}
