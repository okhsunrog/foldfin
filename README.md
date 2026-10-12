# Foldfin — general-purpose VPN project

The product goal is one client with two modes: a per-application TCP proxy and a device-level IP VPN. The proxy works; a Linux TUN / CONNECT-IP prototype now carries IP between one statically configured pair of peers. Explicit routed subnets are supported; automatic full-tunnel internet setup is not implemented yet. Mode and carrier are independent: both use TLS/H2, with H3 datagrams as a later option. See [the product goals](docs/GOALS.md) and [the VPN design](docs/VPN-DESIGN.md).

```
Application → SOCKS5 (localhost) → TLS / HTTP2 CONNECT → server → destination TCP
```

One persistent TLS/H2 connection multiplexes independent TCP streams. DNS names supplied through SOCKS are resolved on the server. TLS certificates and names are always validated. Flow control bounds application-side buffering; FIN maps to H2 END_STREAM independently in each direction. Shared outer TCP still causes connection-level head-of-line blocking.

The crate, command and deployed service are named `foldfin`. The checkout is
`~/code/rust/foldfin`. CLI credentials use `FOLDFIN_TOKEN`; cloud-forge owns the
`foldfin` role, units, vault keys and `generated_configs/foldfin/` exports.
The `client`/`server` command wrappers remain available. Capture metadata and
filenames use the same project name; raw captured packet bytes are preserved.

## Library

One crate provides `foldfin::client` and `foldfin::server`. To embed it, disable
default features and select `client`, `server`, or both. CLI dependencies are
optional; `chrome-tls` enables the measured Chrome 154 Linux profile.

See [LIBRARY.md](docs/LIBRARY.md) for ownership, lifecycle and integration examples.
The CLI uses these same APIs. The IP core is platform independent; Linux and
Android have an owned nonblocking FD adapter. Android runtime behavior and
Chrome Android fingerprints are not established by host acceptance.

## Build

Install stable Rust, then:

```sh
cargo build --release
cargo test
uv run tests/smoke.py
```

Dependencies need access to crates.io. Cargo.lock records the validated dependency versions. Local compilation and smoke tests have been run; see docs/VALIDATION.md for the scope and remaining checks.

## Direct VPS connectivity

See [LOCAL-VPN-TESTING.md](docs/LOCAL-VPN-TESTING.md). Run
`./scripts/test-physical.sh` to test both TLS
profiles through a physical namespace/veth/NAT path, with local and VPS packet
metadata. This never falls back to the host VPN. TCP failure is reported before
TLS tests. Both wrappers currently target Singapore only; Frankfurt is temporarily
excluded because its IP is unreachable on the physical path. Moscow is outside
the regular test scope. `scripts/test.sh` uses this physical path too.

## Singapore development loop

The default remote target is Singapore only. From any working directory:

```sh
~/code/rust/foldfin/scripts/deploy-test.sh   # incremental build, quick update, acceptance
~/code/rust/foldfin/scripts/deploy.sh        # build and quick update only
~/code/rust/foldfin/scripts/test.sh          # current client build and remote acceptance only
~/code/rust/foldfin/scripts/deploy.sh --setup # full Foldfin configuration on Singapore
```

Quick updates use the `~/code/cloud-forge` checkout and update only the server
binary, restarting the service only when it changed. `--setup` applies tokens,
certificates, the unit and firewall through the full Foldfin role. Set
`FOLDFIN_INFRA_DIR` if cloud-forge lives elsewhere. `--no-build` explicitly reuses
an existing release. Both deploy paths are restricted to `singapore`; tests check
parallel HTTPS, egress IP, authentication and private destination rejection.

## Experimental Chrome TLS profile

The optional `chrome-tls` feature provides a BoringSSL client backend derived
from the installed Linux Chrome 154.0.8037.92. Select it with `--chrome-tls`;
the default client continues using rustls. Authorization and server policy are
unchanged. Peer certificate and hostname verification remain enabled.
For this profile, HTTP/2 client SETTINGS and the connection receive window also
match the local Chrome capture.

```sh
cargo build --locked --features chrome-tls --bin foldfin
./target/debug/foldfin client --chrome-tls --server sg.okhsunrog.dev:8445 \
  --server-name sg.okhsunrog.dev --ca ../../cloud-forge/generated_configs/foldfin/singapore.pem
# Supply FOLDFIN_TOKEN from the protected singapore.env as for the normal client.
./scripts/test.sh --chrome-tls  # local profile build, Singapore acceptance only
```

The native build needs CMake, a C++ compiler and libclang. The bindings revision
and BoringSSL submodule are pinned in Cargo.lock; the first build downloads them.
Profile provenance is in [profiles/README.md](profiles/README.md).

Capture and compare fresh handshakes on a loopback collector (dumpcap must have
capture permission). Use a new directory for every run:

```sh
uv run scripts/fingerprint.py --output captures/new-baseline
uv run scripts/fingerprint.py --chrome-tls --samples 5 --output captures/new-chrome
uv run scripts/compare-fingerprints.py captures/new-chrome --require-match
```

Captures stop the connection after ClientHello, before TLS authentication or
application traffic. Comparison normalizes GREASE values, cryptographic random
bytes and the order of permuted extensions; it reports ECH GREASE payload length
and TLS record length separately. This checks ClientHello properties, not full
browser equivalence. Capture and inspect HTTP/2 SETTINGS and request frames with
a local TLS peer:

```sh
uv run python tests/http2_capture.py
```

This uses a dummy token, redacts credential fields from its report and removes
the temporary TLS key log after decoding. Chrome's SETTINGS and connection
WINDOW_UPDATE are reproduced. Chrome sends browser GET requests; Foldfin sends
CONNECT with authorization and keeps the stream open for tunneled TCP. Request
headers and HEADERS priority flags therefore remain different. Resumption, ECH
with a real DNS configuration, server behavior and traffic statistics need
separate measurement. ECH GREASE does not encrypt or conceal the real SNI.

## Local experiment

Generate a localhost certificate (OpenSSL required):

```sh
mkdir -p certs
openssl req -x509 -newkey rsa:2048 -nodes -days 7 \
  -keyout certs/local.key -out certs/local.pem \
  -subj /CN=localhost -addext subjectAltName=DNS:localhost \
  -addext basicConstraints=critical,CA:FALSE -addext extendedKeyUsage=serverAuth
export FOLDFIN_TOKEN="$(openssl rand -hex 32)"
./target/release/foldfin server --cert certs/local.pem --key certs/local.key --allow-private
```

In another terminal, use the same token:

```sh
export FOLDFIN_TOKEN='<same token>'
./target/release/foldfin client --server 127.0.0.1:8443 --server-name localhost --ca certs/local.pem
curl --socks5-hostname 127.0.0.1:1080 https://example.com/
```

For a remote experiment, install your own domain's certificate on the server, listen on `0.0.0.0:443`, omit `--allow-private`, and connect using that domain as `--server-name`. Protect the token and private key. Only the server host needs public inbound access. The example HTML response is a placeholder, not a realistic site.

## Linux VPN prototype

`--tun NAME` selects VPN instead of SOCKS on the client and enables VPN alongside
TCP CONNECT on the server. Both require `--vpn-local IP[,IP]` and
`--vpn-peer IP[,IP]`, with one address per enabled IP version. The server allows
one active IP tunnel because the prototype attaches one exclusive TUN queue.
This is unrelated to the peer's public source IP. Existing bearer authentication
and TLS verification also apply to CONNECT-IP; the Chrome backend is available.

The interface must already exist as a persistent TUN accessible to the process,
with MTU 1500, addresses and explicit routes configured externally. The binaries
do not change system routes or DNS. `--vpn-local-routes CIDR[,CIDR]` advertises reachable networks;
`--vpn-peer-routes CIDR[,CIDR]` sets the allowlist for peer advertisements.
ADDRESS_ASSIGN, ADDRESS_REQUEST and ROUTE_ADVERTISEMENT capsules are supported.
Assignments must match the prepared addresses; advertisements cannot widen the
configured peer allowlist. Route updates replace the previous list, including
withdrawal. Kernel forwarding and return routes provide LAN access without NAT.
Network/DNS setup and multi-peer routing remain future work. Protocol-scoped
advertisements are currently unsupported; this is not a complete MASQUE stack.

Run actual dual-stack TUN acceptance in disposable network namespaces:

```sh
uv run tests/vpn_netns.py
uv run tests/vpn_netns.py --chrome-tls
uv run tests/vpn_netns.py --routed --chrome-tls
./scripts/test-vpn.sh --chrome-tls       # Singapore through the physical NIC
./scripts/deploy-vpn-test.sh --chrome-tls # configure, deploy, proxy + VPN tests
```

The script requires passwordless sudo for namespace setup, iproute2 (`ip`, `tc`),
`setpriv`, `ping` and OpenSSL. Client/server and socket probes run as the invoking
user. It checks bidirectional TCP/UDP/DNS/ICMP, concurrent TCP with half-close,
inner packet sizes up to MTU, wrong token, duplicate session rejection,
outer-carrier loss/delay and server session release after client exit.
Namespaces, processes and their interfaces are removed on exit; host routes
and DNS are untouched. DNS is tested against a temporary responder, not by
changing the system resolver. This is functional acceptance, not a performance
benchmark. `--routed` adds a third namespace, tests kernel forwarding and reverse
connections, then reduces its link MTU to verify IPv4/IPv6 ICMP MTU errors.
The Singapore test creates a temporary routed responder on the VPS and a local
client namespace with scoped physical routing/NAT. TLS goes directly to the
public endpoint. TCP/UDP responders check original source addresses, including
reverse connections. Temporary remote responder units expire after 20 minutes;
normal cleanup runs immediately after acceptance. Managed remote VPN is IPv4;
local acceptance continues checking IPv4 and IPv6.

For release throughput of the real Floppa/TUN integration, use
`uv run --no-project tests/bench_vps.py --seconds 12 --repeats 2`.
It compares direct TCP with Rustls and Chrome CONNECT-IP and records CPU usage.
See [the benchmark method](docs/BENCHMARKS.md) and
[the October 2 measurements](docs/BENCHMARK-2026-10-02.md); the reported Frankfurt
run explicitly uses an existing WireGuard underlay because the physical path
could not establish a connection.

That Frankfurt/Floppa remote command is currently disabled. Current Singapore
CLI/TUN throughput uses `uv run --no-project tests/vpn_physical.py --telemetry
--output /tmp/foldfin-singapore --seconds 12 --repeats 2`. Direct TCP and TUN use
one endpoint through the physical NIC. The namespace-only
[network policy helper](scripts/network_policy.py) temporarily increases TUN
queue length and TCP send autotuning, then restores both on exit or failure.
It refuses the host network namespace. The deployed server TUN queue is 10000;
global TCP sysctls are unchanged on both machines.
See [the Singapore measurements](docs/BENCHMARK-SINGAPORE-2026-10-12.md) for
actual WAN rates, acceptance and cleanup.

For controlled local CLI/TUN measurements at a specified outer RTT, use
`uv run --no-project tests/bench_local.py --output /tmp/foldfin-bench --rtt-ms 200`.
It requires an already-built release CLI with `chrome-tls`, iperf3 and namespace
privileges. It changes only disposable namespaces. The normal client now uses
larger H2 receive windows; the server shares a bounded extra-credit pool across
connections. Chrome client SETTINGS stay unchanged. See the
[performance plan](docs/PERFORMANCE-PLAN.md) and
[October 12 window results](docs/BENCHMARK-2026-10-12.md) and
[TCP/TUN diagnosis](docs/BENCHMARK-TCP-2026-10-12.md). The latter identifies local
TUN-driver drops and TCP send-buffer limits, compares proxy with TUN, and reaches
about 700 Mbps at simulated 200 ms RTT with tuned namespace settings. These are
local results, not a new Singapore throughput measurement.

## Implemented proxy

- SOCKS5 no-auth, TCP CONNECT only, IPv4/IPv6/domain targets; loopback listener enforced.
- Actual TLS with H2 ALPN, standard HTTP/2 CONNECT and bearer authentication.
- One H2 stream per TCP flow, concurrent upload/download, half-close and backpressure.
- Bounded concurrent sessions/streams; setup and DNS/connect timeouts.
- Conservative public-address policy; DNS validated once, same addresses used for connect.
- Unauthenticated requests receive an HTML response.

## Current limits and next work

The proxy mode carries TCP only; the Linux VPN prototype carries full IP packets between static endpoints and configured routed networks. Foldfin is not yet the planned general-purpose VPN. The Chrome profile covers measured ClientHello fields and HTTP/2 connection settings, while CONNECT and CONNECT-IP still differ from browser GETs. TLS terminates directly at this server. There is no ordinary browser H1 fallback, full browser impersonation, QUIC, Noise, padding, automatic reconnect, stream migration, or traffic shaping. Calling it undetectable would be incorrect.

An authenticated user can proxy arbitrary permitted public TCP targets. This is a trusted-user prototype, not a multi-tenant service. Idle connections have no inactivity timeout; semaphore limits bound their count but do not prevent slot exhaustion. Keep it private during experiments. IPv6 policy is conservative and not a complete IANA special-purpose range database.

Next, add client network setup/rollback, full/split tunnel routing and DNS lifecycle on the validated routed IP core. The current Frankfurt rollout is deliberately configured with test prefixes and no internet NAT. Full/split routing, DNS lifecycle, reconnect, LAN gateways, Android and H3 follow as separate stages; see [docs/VPN-DESIGN.md](docs/VPN-DESIGN.md). Authorization and protective policy changes are deferred.
