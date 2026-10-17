# Foldfin

Experimental Rust TCP proxy and IP VPN engine, embedded by Floppa VPN.
One library provides client and server roles; the standalone CLI uses the same
engine. Foldfin does not promise browser equivalence or proven censorship resistance.

## Current implementation

- TLS with rustls; HTTP/2 CONNECT and CONNECT-IP.
- Optional HTTP/3 with Quinn: TCP streams and CONNECT-IP datagrams.
- SOCKS5 TCP adapter and Linux/Android packet-device adapters.
- IPv4/IPv6 packets, explicit routed prefixes and validated control capsules.
- Caller-owned credentials, authorization leases, revocation and session admission.
- One shared packet router for multiple peers, with bounded per-peer queues.
- Client packet-device ownership retained across host-driven carrier recovery.

Chromium/BoringSSL support has been removed. Historical benchmark and fingerprint
reports describe older versions; their commands and conclusions are not current
feature documentation. CONNECT-UDP proxying is not implemented. UDP inside the IP
VPN is supported.

The Floppa branch already integrates configuration import, protected/marked outer
sockets and actor recovery. Full account-to-node provisioning and multi-user
production deployment remain incomplete. See [server review](docs/SERVER-REVIEW.md)
and [implementation status](docs/IMPLEMENTATION.md) for the remaining work.

## Ownership

The library owns protocol connections, stream/session admission, packet framing
and task cleanup. Its host owns the Tokio runtime, logging, credentials and
certificate lifecycle, TUN setup, routes, firewall, DNS and recovery policy.
Account/subscription management belongs to Floppa, not the protocol library.

The standalone server currently accepts one bearer credential and an optional
static VPN peer. A multi-user host uses `Authorizer`, `router::Router` and one
shared `Server` for both listeners. A default route alone is not client isolation
or an internet-exit deployment.

## Build and local verification

```sh
cargo build
cargo test
cargo test --features h3
cargo clippy --all-targets --features h3 -- -D warnings
uv run --no-project tests/smoke.py
uv run --no-project tests/smoke.py --h3
uv run --no-project tests/vpn_netns.py --routed
uv run --no-project tests/vpn_netns.py --routed --h3
```

Namespace tests require the tools and privileges described in
[local VPN testing](docs/LOCAL-VPN-TESTING.md). They use disposable interfaces and
routes. DNS queries in these tests do not prove integration with the OS resolver.
Set `TMPDIR` to a disk-backed diagnostic directory for temporary test material.

`foldfin client --help` and `foldfin server --help` describe CLI options.
Credentials use `FOLDFIN_TOKEN`; do not put real tokens in command arguments or
logs. Certificate verification remains enabled. The CLI opens an externally
prepared TUN and does not configure host routes or DNS.

The optional H3 dependencies currently require the isolated fixes documented in
[vendor/README.md](vendor/README.md). Embedding workspace roots must apply all
three Cargo patches; dependency-level patch tables are ignored by Cargo.

## Documentation and acceptance

- [Library API and lifecycle](docs/LIBRARY.md)
- [Architecture](docs/ARCHITECTURE.md) and [product goals](docs/GOALS.md)
- [Implementation history and open gates](docs/IMPLEMENTATION.md)
- [Server review and completion architecture](docs/SERVER-REVIEW.md)
- [Validation history](docs/VALIDATION.md)
- [Measured Singapore H2 performance](docs/BENCHMARK-SINGAPORE-2026-10-12.md)

Only Singapore is in the current remote test cycle. Direct-WAN acceptance uses a
physical interface in an isolated namespace, with outer route, source and packet
capture evidence. There is no automatic fallback through an existing VPN.
H2/H3 actor recovery passed that path, but full internet tunnel, OS DNS lifecycle,
physical IPv6 WAN, physical Android and API/database/node acceptance remain open.
