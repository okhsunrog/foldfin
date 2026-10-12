//! HTTP/3 client role over host-prepared UDP sockets.
use crate::{
    client::{ClientConfig, VpnTunnel},
    error::{Error, Result},
    h3_packets::Hub,
    h3_transport,
    packet::PacketDevice,
    stats::{Counters, SessionState},
    vpn,
};
use std::{
    net::{SocketAddr, UdpSocket},
    sync::Arc,
};
use tokio::{
    sync::{Mutex, watch},
    time::timeout,
};
struct Inner {
    config: ClientConfig,
    transport: Mutex<h3_transport::Client>,
    packets: Mutex<Hub>,
}
#[derive(Clone)]
pub struct Client(Arc<Inner>);
impl Client {
    pub async fn connect_over(
        config: ClientConfig,
        socket: UdpSocket,
        remote: SocketAddr,
    ) -> Result<Self> {
        let transport = h3_transport::Client::connect(
            socket,
            remote,
            &config.server_name,
            config.additional_ca_pem.as_deref(),
        )
        .await?;
        let packets = Hub::new(transport.datagrams());
        Ok(Self(Arc::new(Inner {
            config,
            transport: Mutex::new(transport),
            packets: Mutex::new(packets),
        })))
    }
    pub async fn closed(&self) {
        let connection = self.0.transport.lock().await.datagrams();
        connection.closed().await;
    }
    pub async fn stop(&self) -> Result<()> {
        self.0.transport.lock().await.stop_mut().await;
        self.0.packets.lock().await.stop().await;
        Ok(())
    }
    pub async fn probe(&self) -> Result<()> {
        timeout(crate::DEADLINE, async {
            let request = http::Request::builder()
                .method("HEAD")
                .uri(format!("https://{}/", self.0.config.authority))
                .body(())
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            let mut stream = self.0.transport.lock().await.request(request, None).await?;
            stream.finish().await?;
            stream.response().await?;
            Ok(())
        })
        .await
        .map_err(|_| Error::Timeout("H3 carrier probe"))?
    }
    pub async fn open_tcp(&self, target: &str) -> Result<crate::h3_tcp::TcpFlow> {
        let authority: http::uri::Authority = target
            .parse()
            .map_err(|_| Error::InvalidConfig("invalid TCP target".into()))?;
        if authority.port_u16().is_none_or(|p| p == 0) {
            return Err(Error::InvalidConfig(
                "TCP target needs a nonzero port".into(),
            ));
        }
        timeout(crate::DEADLINE, async {
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(target)
                .header("authorization", self.0.config.credential.header())
                .body(())
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            let mut stream = self.0.transport.lock().await.request(request, None).await?;
            let response = stream.response().await?;
            if response.status() != 200 {
                return Err(Error::Rejected(response.status().as_u16()));
            }
            Ok(crate::h3_tcp::TcpFlow::new(stream, self.clone()))
        })
        .await
        .map_err(|_| Error::Timeout("H3 CONNECT"))?
    }
    pub async fn prepare_vpn(&self, config: vpn::Config) -> Result<PreparedVpn> {
        config.validate()?;
        timeout(crate::DEADLINE, async {
            let request = http::Request::builder()
                .method("CONNECT")
                .uri(format!("https://{}{}", self.0.config.authority, vpn::PATH))
                .header("authorization", self.0.config.credential.header())
                .header("capsule-protocol", "?1")
                .body(())
                .map_err(|e| Error::InvalidConfig(e.to_string()))?;
            let mut stream = self
                .0
                .transport
                .lock()
                .await
                .request(request, Some(h3_transport::ConnectProtocol::Ip))
                .await?;
            let packets = self.0.packets.lock().await.subscribe(stream.id())?;
            let response = stream.response().await?;
            if response.status() != 200 {
                return Err(Error::Rejected(response.status().as_u16()));
            }
            if response
                .headers()
                .get("capsule-protocol")
                .is_none_or(|h| h != "?1")
                || response.headers().contains_key("content-type")
            {
                return Err(Error::Unsupported("invalid capsule negotiation"));
            }
            packets.0.require_vpn_mtu().await?;
            Ok(PreparedVpn {
                client: self.clone(),
                config,
                stream,
                packets,
            })
        })
        .await
        .map_err(|_| Error::Timeout("H3 CONNECT-IP"))?
    }
}
pub struct PreparedVpn {
    client: Client,
    config: vpn::Config,
    stream: h3_transport::Stream,
    packets: (crate::h3_packets::Sender, crate::h3_packets::Receiver),
}
impl PreparedVpn {
    pub fn start(self, device: PacketDevice) -> VpnTunnel {
        let counters = Arc::new(Counters::default());
        let stats = counters.clone();
        let (publish, state) = watch::channel(SessionState::AwaitingConfiguration);
        let status = publish.clone();
        let task = tokio::spawn(async move {
            let _client = self.client;
            let result = vpn::bridge_h3(
                device,
                &self.config,
                self.stream,
                self.packets,
                stats,
                Some(status.clone()),
            )
            .await
            .map_err(Error::from);
            status.send_replace(match &result {
                Ok(()) => SessionState::Closed,
                Err(error) => SessionState::Failed {
                    detail: error.to_string(),
                },
            });
            result
        });
        VpnTunnel {
            publish,
            task: Some(task),
            state,
            counters,
        }
    }
}
