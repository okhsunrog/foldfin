# Foldfin library

One Rust 2024 crate implements both roles. The CLI uses the same engine.

```toml
foldfin = { path = "../foldfin", default-features = false, features = ["client"] }
# Server host: features = ["server"]. Either host may enable both roles.
```

`client` and `server` enable rustls TLS. Optional `h3` enables the experimental
HTTP/3 carrier and CONNECT/CONNECT-IP roles. `h3_client::Client::connect_over`
accepts a host-prepared UDP socket and resolved endpoint; `open_tcp` returns an
AsyncRead/AsyncWrite flow with independent half-close and bounded writes.
`session::Carrier` accepts either client and lets the SOCKS adapter share both.
`Server::serve_h3` accepts a host-prepared UDP socket; H2 and H3 listeners on one
Server share authorization, admission and limits. Chrome/BoringSSL support has
been removed.
`cli` adds argument parsing, file/env handling, logging initialization and
process signals. Defaults include both roles and CLI for standalone development.
Library consumers should disable defaults. The crate doesn't install a runtime
or tracing subscriber, and credentials are never read from the environment.

## Client

```rust,no_run
# #[cfg(feature = "client")]
# async fn example() -> foldfin::error::Result<()> {
use foldfin::{client::{Client, ClientConfig}, credential::Credential};
use tokio::net::TcpStream;

let config = ClientConfig {
    authority: "vpn.example.org:443".into(),
    server_name: "vpn.example.org".into(),
    credential: Credential::bearer("0123456789abcdef0123456789abcdef")?,
    additional_ca_pem: None,
};
// The host resolves, creates, protects/marks/binds and connects the TCP socket.
let tcp = TcpStream::connect("vpn.example.org:443").await?;
let client = Client::connect_over(config, tcp).await?;
let flow = client.open_tcp("example.org:443").await?;
// flow implements AsyncRead + AsyncWrite, with independent half-close.
drop(flow); // cancels an unfinished CONNECT and closes its upstream
client.probe().await?; // H2 carrier round trip, not proof of IP forwarding
client.stop().await?;
# Ok(())
# }
```

TCP dial address, HTTP authority and TLS verification name are distinct. Floppa
can use its already resolved endpoint without replacing SNI with an IP.
Android must call `VpnService.protect()` before TCP connect; the application may
also bind the socket to its chosen underlying Network. Protection failure must
abort the dial. No process-global socket protection callback exists in Foldfin.

`Client` clones share a carrier. `subscribe()` publishes its running/closed/failed
state and `stats()` counts TCP payload only. `stop()` closes the carrier for all
clones and joins its driver. Concurrent calls all wait for teardown; cancelling
one call leaves the driver available for another call to join. Dropping the last clone aborts the driver;
await `stop()` when completed cleanup matters. Existing flows are not reconnected.

For VPN, call `prepare_vpn(vpn::Config)`, inspect `network_plan()`, perform host
setup, then call `start(PacketDevice)`. The plan is the static provisioning
configuration; it is not a server-selected DHCP lease. DNS and full/split host
route policy remain outside the library. `start()` begins in
`AwaitingConfiguration`; validated ADDRESS_ASSIGN and ROUTE_ADVERTISEMENT move
it to `Running`. This means packet-session configuration, not host VPN acceptance.

`VpnTunnel::subscribe()` retains terminal failure state even if no subscriber
was watching. `closed()` waits without detaching the runner. `stop().await`
cancels and joins it, drops both packet endpoints and returns a failure if the
runner had already failed. Dropping the tunnel aborts it as a fallback.
VPN counters count accepted IP packets, excluding control capsules and framing.
The prototype still has a fixed maximum packet size/MTU of 1500.

## Packet IO and FD ownership

`PacketRecv` and `PacketSend` are object-safe poll interfaces for complete raw IP
packets. They do not require Linux, gotatun or a userspace TCP stack. The engine
passes a 65536-byte receive buffer so it can detect oversize packets; adapters
must not silently truncate. Packet-info headers must be removed by the adapter.
No packet queue is sized from a peer-supplied capsule length. An optional
nonblocking `try_recv` lets the engine retain its existing queued-packet batching.

`adapters::tun::Tun::open(name)` on Linux attaches to an existing persistent
device; it never creates it or changes routes/DNS. `from_owned_fd(OwnedFd)` on
Linux/Android consumes an already established nonblocking raw-IP descriptor.
If Kotlin or another host retains ownership, duplicate its descriptor and give
Foldfin the duplicate. The library closes only its descriptor after both split
packet endpoints are dropped. The caller must stop the engine before replacing
the device. An FD adapter cannot validate the whole platform configuration.

## Server

`Server::new(ServerConfig)` accepts an application-created rustls server config,
a `Credential`, the existing proxy destination policy, and an optional
`VpnConfig { policy, device }`. `device` implements `PacketDeviceFactory` and
returns owned packet endpoints for an exclusive static-peer session.

`Server::serve(TcpListener, shutdown_future)` accepts connections and tracks their
tasks. Awaited shutdown cancels handshakes and streams, joins their tasks, and
releases upstream sockets and packet devices. Dropping the serve future aborts
its tasks as a fallback, but does not synchronously join them. TLS material,
listener binding, certificates, OS networking and subscription policy belong to
the host. `adapters::tun::NamedTun` provides the current Linux deployment adapter.

`Server::with_authorizer(tls, Arc<dyn Authorizer>)` accepts application access
checks. Each CONNECT supplies a redacted `AccessRequest` with the requested mode
and secret authorization header. A successful `AccessGrant` carries proxy rights,
IP policy/device factory, a shared VPN semaphore, a shared `AccessLease` with a monotonic expiry deadline and revocation state.
The host keeps its `LeaseState` sender alive and renews an active lease without
interrupting streams. Revocation, expiry or loss of the lease sender
cancels active streams and packet IO; later requests are checked again even on an
existing carrier. Authorizer errors/timeouts fail closed. The host must not log
credentials or echo them into denial errors. Keep lease senders alive while
grants are valid; their lifetime is intentionally part of the fail-closed contract.

An optional per-session lease can cancel one VPN session while retaining the device
credential and its proxy flows. Floppa uses this for authenticated carrier replacement:
revoke the previous VPN lease, await its shared device slot, then admit the successor.
The shared slot still guards packet-device ownership across credential changes.

The CLI retains one configured bearer token and one static VPN session. A multi-peer
host starts one `router::Router` with its prepared packet device and obtains isolated
factories with `Router::peer(PeerId, vpn::Config)`. The router reserves disjoint
source prefixes, activates admitted generations on packet polling, and bounds each
peer's queues. Do not attach competing readers to one named TUN by increasing the
semaphore. Public source IP is never an identity or a grant key.

Supervise `Router::closed()` alongside listeners and control-plane synchronization.
It is cancellation-safe and wakes on IO failure, panic or stop. `Router::stop()`
joins the runner and returns its failure before host platform teardown. Prefix
validation does not replace destination/client isolation when grants contain default
routes; the host must explicitly enforce those permissions.

TLS renewal need not replace the `Server`. Floppa's host-side `TlsIdentity` supplies
a shared rustls certificate resolver: a validated certificate/key pair is atomically
published to future H2/H3 handshakes while established flows remain alive. Issuance,
validity/name checks and file watching are host/deployment responsibilities. A pinned
self-signed certificate is not transparently renewable without updating client trust.

## Floppa integration

`floppa-vpn-core` now imports a versioned Foldfin JSON document, persists it with
other protocol configs and runs it through `TunnelManager` and the existing actor.
Linux opens the prepared TUN and configures MTU through the privileged helper.
Android protects outer TCP before connect and passes an owned duplicate of the
Kotlin TUN descriptor. The dial literal remains separate from authority and SNI.
Windows/macOS Foldfin device adapters are not implemented.

`floppa-foldfin::DeviceRegistry` adapts committed device grants to `Authorizer`,
stores credential digests, supports replacement/revocation and bounded grant
lifetimes. PostgreSQL issuance, subscription/region synchronization, node process
orchestration and automatic Foldfin provisioning are not wired yet. See Floppa's
`docs/FOLDFIN.md` for the proposed control-plane design and exact current scope.

## Control state and statistics

`control::State` fields are private. Read `assigned()`, `routes()` and `confirmed()`.
`request()` registers outgoing ADDRESS_REQUEST IDs and encodes the capsule; replies
must match an outstanding ID and address family/range. Unknown/replayed/duplicate
IDs fail. A refusal consumes its ID without installing the unspecified address.
Prepared host addresses remain authoritative; the VPN runner does not initiate
requests or allocate addresses dynamically.

`since_last_payload` counts activity in either direction. `since_last_rx_payload`
reports inbound payload only. Neither includes H2 PING or control capsules, and
neither by itself proves forwarding. Floppa separately records a successful carrier
probe as reachability evidence after capsule configuration is confirmed.

## Receive credit and long-RTT performance

The normal client advertises 32 MiB stream and connection receive windows per
carrier. Capacity release follows consumption: a blocked
TCP or packet-device writer does not release the corresponding receive credit.

The server advertises a 32 MiB stream window. Connection receive credit starts
with the standard 65,535 bytes plus up to 32 MiB reserved from a shared 128 MiB
extra-credit pool. All clones of a Server share that pool; separate Server
instances have separate pools. The existing 128-connection limit bounds total
connection DATA credit below 136 MiB per instance. This is not a whole-process
RSS limit: frame/header overhead, TLS, socket buffers and application memory are
separate. No receive allocation is sized from a peer-supplied capsule length.

Reservations are held through connection and stream teardown. An exhausted
pool falls back to the base window without rejecting a connection. Reservations
are made after TLS and before HTTP authorization, remain with idle carriers,
and are not redistributed to existing carriers when others close. This is a
bounded prototype policy, not per-user fairness or protection from slot abuse.
Authorization, connection counts and deadlines retain their existing behavior.

Window tuning does not remove outer TCP head-of-line blocking, TCP-over-TCP
effects, socket-buffer limits or CPU costs. See [the performance plan](PERFORMANCE-PLAN.md)
and [measurements](BENCHMARK-2026-10-12.md).

## Packet bursts and outbound buffering

CONNECT-IP owns a bounded queue of 64 packet batches per session. Each batch
has at most 32 packets and less than `CHUNK + MTU + 8` bytes including conservative
framing allowance: roughly 1.1 MiB maximum queued payload, excluding metadata,
scratch buffers and H2/TLS/socket memory. A full queue stops device reads.
This does not guarantee kernel TUN backpressure or prevent driver drops.

Device collection and H2 forwarding are borrowed futures inside the bridge;
there is no detached pump task. Cancellation drops both and retains the existing
packet-endpoint teardown. Collection validates static address/prefix policy;
serialization checks current negotiated assignments/routes again, so a queued
packet can be discarded after route withdrawal. Control responses take priority
over the next batch; an in-progress H2 send is not preempted.

Inbound delivery yields cooperatively after 32 packets or four DATA frames,
allowing outbound ACK/data reads during a continuously ready receive burst.
No batching timer, new capsule format or platform configuration is introduced.
TUN queue length and TCP socket-buffer policy remain the adapter/platform owner's
responsibility. See [the local TCP diagnosis](BENCHMARK-TCP-2026-10-12.md);
its tuned namespace settings are not production defaults.

`scripts/network_policy.py` is an external Linux platform adapter for temporary
namespace policy. It raises the TCP send-autotune maximum without disabling
autotuning or setting socket-wide fixed buffers, and adjusts an existing TUN's
queue. It refuses the host namespace and validates the named namespace identity.
On failure/exit it restores values it changed; external changes or a replaced
namespace/device cause an explicit rollback error instead of overwriting them.
Its command wrapper stops its child process group before restoring on termination.
No routes, resolver configuration, library runtime or public Rust API are added.

## Deployment

The primary command is `foldfin client ...` / `foldfin server ...`. CLI credentials
use `FOLDFIN_TOKEN`. The `client`/`server` binary wrappers remain available.
Cloud-forge uses the `foldfin` role, service user, systemd units, vault keys and
`generated_configs/foldfin/` exports. The owned static TUN is `ffvpn0`.
Renaming deployment preserves credentials, pinned certificates and service UID/GID.
