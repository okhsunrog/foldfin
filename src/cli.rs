//! Process adapters for the CLI and legacy client/server launchers.
use crate::{
    client::{Client, ClientConfig},
    credential::Credential,
    server::{Server, ServerConfig},
};
use anyhow::{Context, Result, ensure};
use clap::{Parser, Subcommand};
use std::{
    net::{IpAddr, SocketAddr},
    path::PathBuf,
    sync::Arc,
};
use tokio::{
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::rustls;

#[derive(Parser)]
#[command(
    name = "foldfin",
    version,
    about = "TLS/H2 TCP proxy and CONNECT-IP VPN"
)]
pub struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    Client(ClientArgs),
    Server(ServerArgs),
}

fn init_logging() {
    let filter =
        tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into());
    let _ = tracing_subscriber::fmt()
        .with_env_filter(filter)
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .try_init();
}

fn credential() -> Result<Credential> {
    let token = std::env::var("FOLDFIN_TOKEN")?;
    Ok(Credential::bearer(token)?)
}

async fn shutdown() {
    let _ = tokio::signal::ctrl_c().await;
}

fn vpn_config(
    local: Vec<IpAddr>,
    peer: Vec<IpAddr>,
    local_routes: Vec<ipnet::IpNet>,
    peer_routes: Vec<ipnet::IpNet>,
) -> Result<crate::vpn::Config> {
    let config = crate::vpn::Config {
        local,
        peer,
        local_routes,
        peer_routes,
    };
    config.validate()?;
    Ok(config)
}

pub async fn run() -> Result<()> {
    init_logging();
    match Cli::parse().command {
        Command::Client(args) => run_client(args).await,
        Command::Server(args) => run_server(args).await,
    }
}

pub async fn client() -> Result<()> {
    init_logging();
    run_client(ClientArgs::parse()).await
}
pub async fn server() -> Result<()> {
    init_logging();
    run_server(ServerArgs::parse()).await
}

#[derive(Parser)]
pub struct ClientArgs {
    #[arg(long, default_value = "127.0.0.1:1080")]
    listen: SocketAddr,
    /// TCP address, e.g. vpn.example.com:443; TLS name is set separately.
    #[arg(long)]
    server: String,
    #[arg(long)]
    server_name: String,
    /// Additional trusted PEM CA certificate. Never disables verification.
    #[arg(long)]
    ca: Option<PathBuf>,
    /// Use VPN instead of SOCKS, attaching to an already prepared Linux TUN.
    #[arg(long)]
    tun: Option<String>,
    #[arg(long, value_delimiter = ',')]
    vpn_local: Vec<IpAddr>,
    #[arg(long, value_delimiter = ',')]
    vpn_peer: Vec<IpAddr>,
    /// Networks reachable locally and advertised to the peer.
    #[arg(long, value_delimiter = ',')]
    vpn_local_routes: Vec<ipnet::IpNet>,
    /// Administrative allowlist for networks advertised by the peer.
    #[arg(long, value_delimiter = ',')]
    vpn_peer_routes: Vec<ipnet::IpNet>,
}

#[derive(Parser)]
pub struct ServerArgs {
    #[arg(long, default_value = "127.0.0.1:8443")]
    listen: SocketAddr,
    #[arg(long)]
    cert: PathBuf,
    #[arg(long)]
    key: PathBuf,
    /// Permit LAN/loopback targets. Only for trusted local experiments.
    #[arg(long)]
    allow_private: bool,
    /// Enable the single-peer Linux VPN prototype on an already prepared TUN.
    #[arg(long)]
    tun: Option<String>,
    #[arg(long, value_delimiter = ',')]
    vpn_local: Vec<std::net::IpAddr>,
    #[arg(long, value_delimiter = ',')]
    vpn_peer: Vec<std::net::IpAddr>,
    /// Networks reachable locally and advertised to the peer.
    #[arg(long, value_delimiter = ',')]
    vpn_local_routes: Vec<ipnet::IpNet>,
    /// Administrative allowlist for networks advertised by the peer.
    #[arg(long, value_delimiter = ',')]
    vpn_peer_routes: Vec<ipnet::IpNet>,
}

async fn run_client(args: ClientArgs) -> Result<()> {
    ensure!(
        args.listen.ip().is_loopback(),
        "SOCKS listener must be loopback"
    );
    let policy = if args.tun.is_some() {
        Some(vpn_config(
            args.vpn_local,
            args.vpn_peer,
            args.vpn_local_routes,
            args.vpn_peer_routes,
        )?)
    } else {
        ensure!(
            args.vpn_local.is_empty()
                && args.vpn_peer.is_empty()
                && args.vpn_local_routes.is_empty()
                && args.vpn_peer_routes.is_empty(),
            "VPN addresses require --tun"
        );
        None
    };
    let config = ClientConfig {
        authority: args.server.clone(),
        server_name: args.server_name,
        credential: credential()?,
        additional_ca_pem: args.ca.map(std::fs::read).transpose()?,
    };
    let tcp = timeout(crate::DEADLINE, TcpStream::connect(&args.server)).await??;
    let client = Client::connect_over(config, tcp).await?;
    let result: Result<()> = if let Some(policy) = policy {
        #[cfg(target_os = "linux")]
        {
            let name = args.tun.unwrap();
            let prepared = client
                .prepare_vpn(policy)
                .await
                .context("IP tunnel rejected")?;
            let device = crate::adapters::tun::Tun::open(&name)?.into_device();
            let tunnel = prepared.start(device);
            tracing::info!(
                "CONNECT-IP ready on {} (static peer, MTU {})",
                name,
                crate::vpn::MTU
            );
            tokio::select! { _ = shutdown() => {}, _ = tunnel.closed() => {} }
            tunnel.stop().await.map_err(Into::into)
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = policy;
            anyhow::bail!("named TUN CLI requires Linux; embed packet IO on other platforms");
        }
    } else {
        crate::adapters::socks::serve(
            TcpListener::bind(args.listen).await?,
            client.clone(),
            shutdown(),
        )
        .await
    };
    client.stop().await?;
    result
}

async fn run_server(args: ServerArgs) -> Result<()> {
    let vpn = if let Some(name) = args.tun {
        let policy = vpn_config(
            args.vpn_local,
            args.vpn_peer,
            args.vpn_local_routes,
            args.vpn_peer_routes,
        )?;
        #[cfg(target_os = "linux")]
        {
            Some(crate::server::VpnConfig {
                policy,
                device: Arc::new(crate::adapters::tun::NamedTun(name)),
            })
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (name, policy);
            anyhow::bail!("named TUN CLI requires Linux");
        }
    } else {
        ensure!(
            args.vpn_local.is_empty()
                && args.vpn_peer.is_empty()
                && args.vpn_local_routes.is_empty()
                && args.vpn_peer_routes.is_empty(),
            "VPN addresses require --tun"
        );
        None
    };
    let certs = rustls_pemfile::certs(&mut std::io::BufReader::new(std::fs::File::open(
        args.cert,
    )?))
    .collect::<std::io::Result<Vec<_>>>()?;
    let key =
        rustls_pemfile::private_key(&mut std::io::BufReader::new(std::fs::File::open(args.key)?))?
            .ok_or_else(|| anyhow::anyhow!("PEM private key missing"))?;
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let server = Server::new(ServerConfig {
        tls: Arc::new(tls),
        credential: credential()?,
        allow_private: args.allow_private,
        vpn,
    })?;
    server
        .serve(TcpListener::bind(args.listen).await?, shutdown())
        .await?;
    Ok(())
}
