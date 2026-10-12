# Validation

## Routed CONNECT-IP and Frankfurt rollout — 2026-10-02

The current core supports IPv4/IPv6 routed prefixes and ADDRESS_ASSIGN,
ADDRESS_REQUEST and ROUTE_ADVERTISEMENT capsules. Addresses remain prepared
out-of-band; wire assignments are checked against them. Peer advertisements
are bounded by configured prefixes, replace earlier routes and support
withdrawal. Empty assignments stop originating traffic from withdrawn local
addresses. Protocol-scoped routes and complete MASQUE interoperability are
not supported. TTL/Hop Limit currently follows normal kernel TUN forwarding;
the exact RFC encapsulation/decapsulation accounting still needs an audit.

`uv run tests/vpn_netns.py --routed` and its `--chrome-tls` variant passed with
a third node behind the server: bidirectional IPv4/IPv6 TCP/UDP/DNS/ICMP without
NAT. Reducing the server-to-LAN link to MTU 1280 returned IPv4 fragmentation-needed
and IPv6 packet-too-big errors to the client; subsequent TCP/UDP/DNS traffic
passed. Capsule tests include a fixed RFC-format IPv4 example, 62-bit request-ID
encoding, duplicate request-ID rejection, malformed fields, noncanonical
prefixes, unordered/overlapping ranges, route allowlists and withdrawals.
Default/Chrome compilation, eight unit tests, clippy and existing proxy smokes
passed. The musl build uses libc's target-specific TUNSETIFF ioctl constant.

`scripts/deploy.sh --setup` applied the opt-in VPN configuration only on
`europe`. It keeps the existing TCP/8445 endpoint, token, pinned certificate
and proxy destination policy. A root oneshot prepares a persistent TUN owned
by `foldfin`; the data-plane service runs as UID 997, with `CapEff=0`, access to
`/dev/net/tun` and a 256 MiB memory limit. Dedicated CF-FOLDFIN-VPN forwarding
and input chains allow the configured test topology. There is no VPN NAT or
new public listener. Remote systemd unit verification passed.
Reapplying the role with the same binary finished `ok=35 changed=0 failed=0`.
The deployed server SHA-256 matches the local musl artifact:
`4c79025b8da638dc20419555f91609a3cde0fdee37bee4f4fc9496eccb4df0fc`.

Frankfurt configuration: server TUN `198.18.77.1`, client `198.18.77.2`, routed
test prefix `198.19.77.0/30`. `scripts/test-vpn.sh` and `--chrome-tls` passed
through the public endpoint, including TCP/UDP/DNS/ICMP to a temporary LAN
node and reverse TCP/UDP/DNS connections to the client. The Chrome run also
asserted original TCP/UDP source addresses at both responders. A transparent
TCP/Unix byte relay gives the isolated local client access to the host's
internet connection; TLS still terminates only at the Foldfin endpoints.
The managed remote VPN rollout is IPv4; IPv6 forwarding acceptance is local.

Temporary remote responders run in a 300-second systemd unit with namespace
cleanup on exit; normal cleanup removes them immediately. The configured
server TUN/service remain available. Tests do not alter local host default
routes or DNS. `scripts/test.sh` with default and Chrome profiles passed after
deployment: four parallel HTTPS requests, DNS, wrong-token/private-target
rejection and Frankfurt egress `68.183.74.207`. Moscow/Singapore were untouched.

Next: client route/address/DNS lifecycle and rollback, full/split tunnel setup,
then reconnect/multi-peer handling. Current tests do not prove full-tunnel
internet egress, roaming, Android behavior, performance or browser equivalence.

## Linux static-peer CONNECT-IP — 2026-10-02

Implemented opt-in `--tun`, static local/peer IPv4/IPv6 addresses, Extended
CONNECT dispatch and incremental DATAGRAM capsule parsing. TUN devices, MTU
1500, addresses and routes are prepared externally. The initial scope is
endpoint-to-endpoint IP, not internet egress, LAN routing or multi-peer VPN.
Address/route control capsules and complete MASQUE interoperability are not
implemented. No remote VPN deployment was performed in this step.

`uv run tests/vpn_netns.py` and `uv run tests/vpn_netns.py --chrome-tls`
exercise real kernel TUN devices in two disposable namespaces, with client,
server and socket probes running as the invoking user. Each backend passed:

- IPv4/IPv6 ICMP echo in both directions, IPv4 1500-byte and IPv6 1280-byte
  inner packets.
- Four concurrent 512 KiB TCP round trips per address/direction, with response
  after FIN; UDP payloads of 1, 100 and 1200 bytes and a synthetic DNS query.
- Wrong bearer token and second active static-peer session rejection.
- TCP/UDP/DNS transfer with outer-carrier `netem delay 10ms loss 1%`.
- Client exit, server TUN-session release, new client setup and successful ping.

The script removes namespace processes/interfaces on success and failure;
it does not change host routes/DNS. These are functional tests, not measured
throughput/memory bounds, real network roaming, PMTU discovery or forwarding
acceptance. Client recreation was explicit; automatic reconnect is absent.

The first Chrome-profile bulk transfer failed: one H2 DATA frame per small TCP
ACK exhausted h2's framing-overhead budget and caused `ENHANCE_YOUR_CALM`.
The packet sender now combines already queued capsules into bounded DATA
batches, without a batching timer or changing h2's protection. Packets retain
their own capsule boundaries. Subsequent dual-stack and impaired-carrier
acceptance passed. Enabling TCP_NODELAY on both carriers removed the observed
roughly 40 ms delayed small-packet round trips in the local test; this is not
a general latency benchmark.

Capsule unit tests cover every chunk size across combined/segmented capsules,
unknown capsules with huge lengths without payload allocation, truncated
headers/payload/context, oversized DATAGRAMs, nonminimal varints and unknown
contexts. IP tests cover inconsistent IPv4/IPv6 lengths. Existing proxy smoke
passed with both rustls and Chrome backends, including auth/TLS policy,
half-close, concurrency and upstream cancellation.

`cargo fmt --check`, `cargo check --all-targets`, `cargo test` and
`cargo clippy --all-targets -- -D warnings` were run with default and
`chrome-tls` configurations. Linux namespace acceptance does not establish
Android support, Chrome equivalence for VPN traffic or censorship resistance.

## Proxy baseline — 2026-10-01

Validated on Linux with rustc 1.98.1, edition 2024 and the supplied Cargo.lock:

- `cargo fmt --check`
- `cargo check --all-targets`
- `cargo test` (address policy unit test)
- `uv run tests/smoke.py`
- `cargo clippy --all-targets -- -D warnings`
- `cargo build --release --target x86_64-unknown-linux-musl --bins`

Smoke covers eight concurrent 512 KiB round trips with replies after client FIN,
wrong token, untrusted TLS certificate, wrong TLS name, default rejection of a
loopback destination, and upstream socket EOF after forcibly killing the carrier
client. It exercises flow control but is not a measured memory-bound test.

Fixed the H2 handshake API call and the test certificate's CA flag. Server flow
tasks now belong to the connection's JoinSet: carrier EOF/error cancels remaining
upstream handlers and releases their permits. Missing PEM keys report an error.

Remote experiments are reproducible with:

```sh
uv run tests/remote.py --ssh root@sg.okhsunrog.dev --host sg.okhsunrog.dev --port 443
```

The port must be unused and reachable. The script uploads static binaries and a
temporary certificate/token, runs a transient unit with a 120-second maximum
lifetime, tests HTTPS through SOCKS and reports the egress IP, then stops the
unit and removes its temporary directory. It does not change the firewall.

The Singapore SSH connection and remote process launch succeeded. The remote
server listened on TCP/443, but the direct client connection hit its 15-second
deadline; no remote HTTPS round trip was established. Temporary files and the
unit were removed. Inspection found an IPv4 INPUT default-drop firewall allowing
SSH and WireGuard, with no public TCP/443 allowance. The firewall was unchanged;
a direct experiment requires a scoped temporary allowance or a private route.

## Managed three-VPS deployment

The subsequent `cloud-forge` Foldfin role provides a persistent systemd service,
per-host Vault tokens, pinned TLS certificates and dedicated firewall chains on
TCP/8445. See `../cloud-forge/docs/FOLDFIN.md`. Frankfurt is the primary exit;
Moscow's Foldfin UID uses the existing WireGuard tunnel to Frankfurt, with a
fallback unreachable rule. Singapore is a secondary exit.

The initial `uv run tests/vps.py --hosts europe moscow singapore` acceptance
passed on all three public endpoints:

| Entry | Endpoint | Observed egress |
| --- | --- | --- |
| Frankfurt (primary) | eu.okhsunrog.dev:8445 | 68.183.74.207 |
| Moscow → Frankfurt | msk.okhsunrog.ru:8445 | 68.183.74.207 |
| Singapore | sg.okhsunrog.dev:8445 | 66.179.31.173 |

Each instance passed four concurrent HTTPS requests through the direct TLS/H2
carrier, server-side DNS, private destination rejection and wrong-token
rejection. Server binaries matched the local static build SHA-256:
`41e71f63090681edcd25d92ddf38a8e4de84fe46c47dc22f32cad6f3903e5b5a`.
All three services were active and enabled. Existing 443 frontends were not
reconfigured. These are host/network-specific acceptance results, not evidence
of censorship resistance or Chrome fingerprint matching.

Subsequent development is restricted to Frankfurt. `scripts/deploy-test.sh`
passed from outside the checkout in 42 seconds with cached builds: quick
Ansible update `ok=8 changed=0 failed=0`, matching server SHA-256, and Frankfurt
acceptance including four parallel HTTPS flows, private destination rejection,
wrong-token rejection and egress `68.183.74.207`. The test script now defaults
to Frankfurt; repeat the other endpoints only on explicit request.

## Chrome 154 TLS profile

Captured the installed Google Chrome 154.0.8037.92 and the optional BoringSSL
client on a loopback TLS collector. `captures/baseline` records the original
rustls mismatch; `captures/chrome-154` contains the final pcapng, raw ClientHello
records and comparison report. No application authentication or payload was
sent to the collector.

`uv run scripts/compare-fingerprints.py captures/chrome-154 --require-match`
passed: all 30 Chrome handshakes from five fresh launches and five Foldfin
handshakes matched the compared normalized fields. These include ordered
ciphers, groups, signature algorithms, ALPN, key-share groups and sizes,
extension sets and parsed contents, GREASE extension positions, trust-anchor
identifiers, ALPS, certificate compression and ECH GREASE framing. Random
cryptographic values, GREASE IDs and shuffled extension order are normalized.
Chrome showed four record lengths (1912–2008); five Foldfin samples showed three
within that set (1944–2008). This sample does not prove identical distributions.
The same comparator rejects the original baseline with exit code 1.

With the pinned bindings revision, `cargo fmt --check`,
`cargo test --features chrome-tls`,
`cargo clippy --all-targets --features chrome-tls -- -D warnings`,
`uv run tests/smoke.py --chrome-tls` and the default
`cargo check --all-targets` passed. The profile retains rejection of an untrusted
certificate and wrong hostname, and passes the same eight-flow smoke workload.

`./scripts/test.sh --chrome-tls` passed against Frankfurt only:
`eu.okhsunrog.dev:8445`, four parallel HTTPS flows, server-side DNS, private
destination and wrong-token rejection, egress `68.183.74.207`. The native
release client was built locally; no server deployment was needed. The default
rustls smoke test also passed after the profile changes.

## HTTP/2 Chrome comparison

`uv run python tests/http2_capture.py` captures Chrome and the profile client
against a local TLS peer, then decodes the pcap with tshark. Output is in
`captures/http2-chrome-154`; it contains encrypted packet captures and parsed
frame summaries. The temporary TLS key log is removed after decoding, and the
Foldfin run uses only an all-zero dummy token.

The initial SETTINGS frame matches exactly: header table size 65,536; push
disabled; initial stream window 6,291,456; max header list 262,144. The initial
connection WINDOW_UPDATE is also 15,663,105 in both captures. The `chrome-tls`
client applies those values through `h2::client::Builder`; the rustls default
profile is unchanged.

Request frames still show the tunnel protocol: Chrome sends GET for `/` and
`/favicon.ico`, with ordinary browser headers and HEADERS priority metadata.
Foldfin sends CONNECT for `example.com:443` with Authorization and no priority
metadata, then keeps the stream open. Credential header values are redacted in
parsed output. The separate Frankfurt acceptance passed through the deployed
server after this client change; deployed-server frame captures, HPACK encoding,
resumption, real ECH, frame timing and full browser equivalence remain
unmeasured.

Next for mimicry: measure HTTP/2 request header encoding, priority and frame
timing against more Chrome requests, then measure under your own ISP/mobile
network. Resumption, real ECH, traffic statistics and full browser equivalence
are unverified.
Authorization, IP limits and protective timeout changes are deferred by request.
Existing TCP flows cannot be transparently restored after carrier loss.
No censorship resistance has been established.

## Foldfin library refactor — 2026-10-02

The checkout moved to `~/code/rust/foldfin`; deployment scripts and direct VPS
test defaults now locate `~/code/cloud-forge`. The crate and primary CLI are
`foldfin`, with legacy client/server binaries and deployment names retained.

Default and Chrome builds passed all eight unit tests and three library
integration tests. Library tests exercise preconnected TCP, certificate/name
validation, TCP half-close, unfinished-flow cancellation, carrier shutdown,
payload counters, redacted credentials, in-memory packet IO, capsule confirmation
and awaited packet-device release. The documentation example compiles from the
new path. Formatting and clippy with warnings denied passed for default,
Chrome, role-free, client-only and server-only library builds.

Both TLS profiles passed smoke tests and routed Linux namespace acceptance:
dual-stack TCP/UDP/DNS/ICMP, reverse routed LAN access, MTU errors, loss/delay and
carrier cleanup. Android arm64 client-only compilation passed with cargo-ndk;
Android runtime and Chrome-on-Android validation remain pending.

New captures are in `captures/foldfin-library-chrome-154` and
`captures/foldfin-library-http2-chrome-154`. Against installed Chrome
154.0.8037.92, the normalized TLS comparison passed without differences
(18 browser samples, three Foldfin samples). Initial HTTP/2 SETTINGS and
connection WINDOW_UPDATE match. CONNECT headers, priority metadata and frame
ordering still differ; this does not establish full browser equivalence.

The refactored server was incrementally deployed only to Frankfurt. Its binary
SHA-256 was `8510d1533aca513318ce03da5819f3e720307aceced406c85ca2cf1cb487f47b`.
Default and Chrome proxy acceptance passed: four parallel HTTPS flows, server DNS,
private-destination and wrong-token rejection, egress `68.183.74.207`.
Both default and Chrome VPN clients passed through the public Frankfurt carrier:
routed TCP/UDP/DNS/ICMP and reverse TCP/UDP/DNS, preserving addresses without NAT.

The server still provisions one static peer and one bearer token. Full-tunnel
host setup, multi-peer routing, dynamic provisioning and Floppa runtime
integration remain separate work. Authorization changes remain deferred.

## Review fixes and Floppa adapter — 2026-10-02

Concurrent and cancelled Client::stop calls now share the driver join. A controlled
teardown test proves a second caller cannot return while the driver is still
releasing its resources. Feature-gated doctests pass without roles and with
server-only features. ADDRESS_REQUEST tests cover a complete request/reply cycle,
refusal, unknown/replayed IDs and static-address policy. Control fields are private.
H2 DATA capacity logic is shared; VPN send/receive loops are separate functions.
Activity stats count both directions and also expose inbound-only payload age.

Eleven unit tests and five library integration tests pass with chrome-tls. The
integration suite now runs shared TCP and VPN acceptance against both rustls and
Chrome backends. Formatting, clippy with warnings denied for each role/core and
Chrome, default/server-only/core doctests, Chrome smoke and routed dual-stack
namespace acceptance passed.

Floppa's new integration suite verifies config import/persistence/redaction,
TunnelManager packet IO, active grant revocation, token rotation, mode withdrawal,
renewal without disconnecting flows, and expiry of an existing stream. The same
suite passes with Chrome TLS enabled and selected by the imported client config.
Authenticated VPN carrier replacement releases the old endpoints before the new
session forwards packets. A separate
registry test keeps the per-device VPN slot across revoke/replacement until old
packet ownership is released. Existing Floppa suites passed (233 VPN core,
17 provision, five CLI tests); TypeScript protocol-order tests and Vue typecheck
passed. The actual Floppa CLI/actor also passed isolated real-TUN acceptance:
MTU 1280, routed TCP/FIN/UDP/DNS/ICMP and awaited route/address rollback. Android
arm64 compilation passed; Android device runtime is pending.

The current static server was redeployed only to Frankfurt. SHA-256:
`606c1ec3c1c9694cddabfb412060cf1adfa32f84bc4e9e53d1a34ab39e30a7d5`.
Default and Chrome clients passed public proxy and VPN acceptance, including
reverse routed traffic. Credentials and deployed network policy were preserved.
The DeviceRegistry is exercised locally; automatic Floppa API issuance, database
grant synchronization and shared multi-peer TUN routing are not deployed.

## Name migration and physical paths — 2026-10-02

The service and infrastructure name migration is complete on all three VPS.
Role/vars/vault/export paths, users/groups, unit files, helper scripts, firewall
chains and comments now use Foldfin. Existing numeric UID/GID, credentials and
pinned certificate/key bytes were verified unchanged. The static TUN is ffvpn0.
The same server artifact is deployed on all three:
`39f71575051d5959e9a9842e10305c4116d5337011d10ba737334c613324e731`.
Capture filenames and metadata labels have been normalized to Foldfin; original
packet bytes are preserved. Historical sections above did not record a physical
underlay and must not be interpreted as successful provider-path/DPI acceptance.

`docs/LOCAL-VPN-TESTING.md` was copied from Floppa and adapted to Foldfin.
`tests/physical_vps.py` / `scripts/test-physical.sh` add source-specific physical
routing, namespace/veth/NAT isolation, local and VPS SYN/RST metadata, port
controls and explicit TLS-profile acceptance. `scripts/test.sh` now uses this
path, so Frankfurt's connection failure is an actual failed check, not a reason
to retry through the host VPN. Administration SSH is kept on its existing path.

Confirmed physical Ethernet interface: enp0s13f0u1u5, gateway 10.77.77.1.
Local capture shows test SYNs on Ethernet, with original namespace traffic on
its veth; Moscow/Singapore see source 128.0.128.51 on their public interfaces.
Both hosts passed the proxy acceptance suite with Rustls and Chrome profiles:
four parallel HTTPS flows, remote DNS, expected egress, private destinations
and wrong credentials denied. Moscow exits Frankfurt; Singapore exits itself.
This establishes current connectivity on this network, not undetectability.

Frankfurt's IPv4 68.183.74.207 timed out on TCP/22, 443 and 8445 repeatedly.
SYN retransmissions leave Ethernet but matching SYNs are absent in the scoped
VPS capture. ICMP also times out. TCP traceroute sees the namespace gateway,
10.77.77.1 and 192.168.1.1, then unanswered hops. The server listener is active,
its dedicated input chain accepts connections and its return route to the public
source uses eth0. Loss lies before the captured VPS interface; the exact point
and responsible party remain unknown. These results do not establish protocol-
specific DPI blocking, since TLS never starts. No firewall or service change was
made to try to conceal this failure. Singapore's 443 control has no listener,
so its timeout is not a failed Foldfin test.

Raw route/probe/packet evidence: `captures/physical-20261002-first/`,
`captures/physical-20261002-europe-diagnosis/` and subsequent wrapper runs.
All owned namespaces, routing rules/tables, NAT/forward rules and transient
capture units were removed. Host default routes and DNS stayed unchanged.

The [follow-up Frankfurt investigation](FRANKFURT-REACHABILITY-2026-10-02.md)
confirms that bound/marked host sockets reproduce the namespace failure.
Frankfurt TCP/22, /443, /8445 and /80, UDP/58886 and ICMP leave the OpenWrt WAN;
the source-independent, immediate-mode Frankfurt eth0 capture sees none of these
probes. Public TCP/22, /443 and /8445 connect from both other VPSs. Host AmneziaWG
uses Moscow as its endpoint, explaining working administration through the VPN.
The remaining unverified segment includes the Innbox uplink, provider/transit
and the VPS cloud perimeter; no protocol-specific attribution follows.

After the rename, default/Chrome library tests, formatting, all-target checks,
clippy with warnings denied, Chrome smoke, routed dual-stack namespace acceptance
and both existing normalized TLS fingerprint comparisons passed. Floppa's three
Foldfin integration tests with Chrome and affected-crate clippy also passed.

## Singapore-only physical acceptance — 2026-10-03

Per the user's revised scope, ordinary deploy/test wrappers and proxy/physical
test defaults now select Singapore. Frankfurt is temporarily excluded; Moscow
is outside routine tests. Historical Frankfurt remote CONNECT-IP acceptance,
its deployment wrapper and the remote TUN benchmark are paused before any remote
operation until CONNECT-IP is configured on Singapore. Local VPN tests remain
available; this change does not deploy VPN mode to Singapore.

Physical namespace acceptance on Singapore passed with both Rustls and Chrome:
`captures/physical-20261003-024307/`. TCP/8445 connects in approximately 203 ms.
The unrelated TCP/443 control times out as before; no HTTPS listener is deployed.

Ordinary kernel WireGuard to `66.179.31.173:58886` also passed a short physical
check using `tests/wireguard_physical.py`. A new temporary peer completed a real
handshake, verified independently at both endpoints. Three inner ICMP requests
received three replies, with approximately 200 ms steady RTT. The Ethernet and
VPS captures show the 148-byte initiation, 92-byte response and encrypted data
in both directions; the VPS sees the home public source `128.0.128.51`.
The host WireGuard UDP socket was marked to use the physical main-table route,
while its interface and inner route lived in a disposable namespace. Neither
the existing host VPN nor a Moscow relay carried this test.

Evidence: `captures/wireguard-physical-20261003-024152/summary.json` and the local
and server UDP metadata logs. The temporary peer, client namespace/device,
private-key file and transient capture unit were removed. The existing Moscow
peer and persistent WireGuard configuration were retained. This establishes
current handshake and short data-path availability, not sustained throughput or
the absence of filtering after longer use.

## H2 receive-credit tuning — 2026-10-12

Normal-client receive windows are now 32 MiB. The server reserves extra
connection credit from a shared 128 MiB pool; existing admission limits,
authorization and deadlines are unchanged. Chrome initial H2 SETTINGS and
connection WINDOW_UPDATE remain matched to the measured profile.

Default and chrome-tls fmt/check/test/clippy all-targets passed, along with
core/client/server feature checks and doctests. The suite has 13 unit tests,
four default / seven Chrome library tests. New tests exercise concurrent budget
reservations, exhaustion/return and slow-reader backpressure in both directions
with 128 MiB payloads. Default and Chrome SOCKS smoke and routed dual-stack
namespace acceptance passed, including reverse traffic, PMTU, loss/delay and
carrier/device cleanup.

The routed test now changes both ends of the LAN veth to MTU 1280: the former
asymmetric setup dropped return packets before IP forwarding, causing sporadic
TCP timeouts under faster delivery. Optional output retains packet metadata and
failure snapshots, and `--binary` tests one frozen release CLI. TLS private keys
remain temporary.

Physical Singapore proxy acceptance passed for both profiles with the new client
and unchanged deployed server: Ethernet `enp0s13f0u1u5`, source seen on VPS
`128.0.128.51`, captures at both ends and verified cleanup. Remote CONNECT-IP
remains unconfigured; this is not a WAN throughput test of the new server.
Sequential H2 capture matches installed Chrome 155.0.8059.39 initial SETTINGS;
the existing TLS Chrome 154 profile was not revalidated against Chrome 155.

Local final CLI/TUN measurement reached 2.9–3.1 Gbps without added delay. At
200 ms, a final short run measured Rustls 33.2/64.1 and Chrome 51.9/62.7 Mbps
upload/download, versus about 165 Mbps direct TCP in this model. High loss
still substantially reduces throughput. See [the full report](BENCHMARK-2026-10-12.md)
and [plan](PERFORMANCE-PLAN.md). No censorship-resistance conclusion follows.

## TCP/TUN burst diagnosis — 2026-10-12

Added a bounded 64-batch outbound packet collector/forwarder and cooperative
inbound delivery. Unit coverage now includes queue saturation, FIFO, resumption,
collector cancellation and current-route revalidation of queued packets.
Default/chrome all-target fmt/check/test/clippy passed, as did core/client/server
feature checks. The suite has 15 unit tests and four default / seven Chrome
library tests. Both profiles passed SOCKS smoke and routed dual-stack acceptance
including PMTU, reverse traffic, carrier loss/delay and packet-device cleanup.
Logs are in `benchmarks/2026-10-12-tcp/*-final-*.log`.

`captures/http2-tcp-final-20261012/summary.json` confirms initial Chrome H2
SETTINGS and connection WINDOW_UPDATE still match the local browser capture.
TLS ClientHello against the newer browser was not revalidated here.

Telemetry distinguishes local TUN driver drops from qdisc drops. Tuned test
namespaces (TUN queue 10000, TCP send-autotune maximum 32 MiB) reach Rustls TUN
696/700 Mbps at simulated 200 ms in the common verified stream workload;
Chrome TUN is 666/174 Mbps with its preserved receive profile. No-delay final
CLI/TUN reaches about 3.6 Gbps. Original code also benefits substantially from
the network settings; code-only gains and repeats are documented separately.
Host network settings and production deployment are unchanged in this stage.
A 200 ms / 1% ingress-loss throughput run did not complete: native measured
1.55/2.01 Mbps, then TUN upload failed receiving iperf results. Evidence and
successful cleanup are retained in `benchmarks/2026-10-12-tcp/loss-final/`.
This does not count as successful high-RTT loss acceptance or a measured TUN rate.
See [the detailed TCP/TUN report](BENCHMARK-TCP-2026-10-12.md).

## Namespace policy and Singapore CONNECT-IP — 2026-10-12

The external namespace policy helper passes five runtime tests: work failure
rollback, partial setup rollback, preserving external changes, host-namespace
refusal, and SIGTERM child cleanup/rollback. Managed TUN setup passes isolated
up/reentry/down and foreign-interface refusal. Rust source/API is unchanged;
musl server and native Chrome CLI release builds completed.

Singapore now has opt-in static-peer IPv4 CONNECT-IP, separate `198.18.78.1`/
`198.18.78.2` addresses and routed test prefix `198.19.78.0/30` without NAT.
TUN queue is 10000; the data-plane service retains its unprivileged user.
Both profiles passed physical routed IPv4 TCP/FIN, UDP/DNS/ICMP and reverse
connections with source preservation. Both public proxy profiles passed on the
updated server. Remote IPv6 is not configured; local dual-stack evidence remains
separate.

Final physical path: Ethernet `enp0s13f0u1u5`, gateway `10.77.77.1`, source on VPS
`128.0.128.51`, direct TLS/H2 to Singapore TCP/8445. Twelve workload transfers
passed SHA-256/count verification. Download: direct 108–109, Rustls/TUN 98–99,
Chrome/TUN 102–104 Mbps. Upload varies substantially, including direct TCP.
Client namespace TCP autotune max is temporarily 32 MiB; server global TCP
maximum remains 4 MiB. This is not the fully tuned local benchmark.

Raw: `captures/vpn-physical-20261012-wan2/`, `captures/proxy-deployed-20261012/`;
full conditions and preparation failures:
[BENCHMARK-SINGAPORE-2026-10-12.md](BENCHMARK-SINGAPORE-2026-10-12.md).
Cleanup removed temporary rules/routes/units/listeners/namespaces/scripts and
restored the client policy; host default routes and both global TCP policies
match before/after. Foldfin remains active, deployed SHA-256
`2d8610bc00cab6fac76a7dce9e964e3dafbcefe3e46c35c5dc3a6049bb92621e`.
Quick-update now targets Singapore instead of its stale Frankfurt host/guard;
runtime verification passed with `changed=0`. Historical Frankfurt tests remain
disabled.
