# Foldfin session and transport implementation

Accepted architecture: one Rust library; H2/rustls and H3/Quinn; CONNECT,
CONNECT-UDP and CONNECT-IP. Remove Chrome/BoringSSL. Session and packet-device
ownership outlive carriers. Floppa owns recovery policy and platform networking;
Android owns its system lockdown policy. No protocol-owned kill switch.

Current delivery state: [STATUS.md](STATUS.md). The increments below are historical.

## Delivery sequence

- [x] Record original source (364a0c5) and release binary baseline.
- [x] Fix packet collector fairness and capsule request/response bounds.
- [x] H3 vertical slice with caller-owned UDP sockets and TLS validation.
- [x] Transport-independent sessions, bounded queues, recovery and multi-peer router.
- [x] Remove Chrome backend; update CLI and regression harnesses.
- [x] Floppa config v2, dual-stack NetworkPlan, Underlay, Recovering and typed health.
- [x] Floppa node binary, provisioning, versioned grant synchronization and metrics.
- [x] Local dual-stack, multi-peer and lifecycle acceptance.
- [ ] Full load and latency/loss matrix; adversarial resource-exhaustion acceptance.
- [ ] Physical Android and isolated Singapore API/database/node acceptance.

## Invariants

No runtime/signals/env/database ownership in the library. Validate requests before
access decisions. Preparing a replacement never revokes a working session.
Session admission commits one active generation per peer. No own crypto, mux,
FEC or fragmentation. H3 VPN requires space for a 1280-byte inner packet.
Auto may fall back on network/capability errors, never on certificate/auth errors.
Stop joins owned tasks; cancelled attempts release all acquired resources.

Existing Floppa users, services and database stay unchanged. Singapore is the only
remote test node, reached via physical namespace/veth/NAT with route/source/capture
evidence. Tests do not change host default routes, DNS or global TCP settings.
Node authorization leases default to one hour, bounded by subscription expiry.
Unavailable device/WAN acceptance must remain explicitly incomplete.

## Validated increments

- Collector cancellation fairness and ADDRESS_REQUEST/ADDRESS_ASSIGN bounds fixed.
- Optional `h3` carrier implements prepared UDP socket ownership, TLS 1.3/SNI,
  extended CONNECT, reliable streams, HTTP datagrams, path payload checks and
  joined shutdown. Local tests cover four independent streams, half-close,
  nonzero quarter-stream IDs and negative certificate/name validation.
  CONNECT-IP now uses this carrier with reliable configuration and HTTP datagrams,
  requiring capacity for a 1280-byte inner IP packet. Incoming capsules and QUIC
  datagrams share byte-bounded, age-limited delivery; reliable control responses
  are bounded. The server shares authorization, admission and global limits with H2.
- CONNECT syntax is validated before application authorization, with an H2
  regression proving invalid requests never call the authorizer.
- Published h3 0.0.8 lacks CONNECT-IP and h3-datagram 0.0.2 discards the encoded
  stream ID. Minimal vendored patches are documented in vendor/README.md.
  They must also be applied at embedding workspace roots.
- Chrome/BoringSSL backend, profile selector, native dependencies and build/test
  switches removed. Floppa's importing adapter updated to the rustls-only client
  API. Existing measurements remain historical. H2 proxy and Floppa's three
  integration tests pass after the removal.
- `session::Session` retains the packet device across carrier failure,
  failed negotiation and explicit recovery. Recovery is host-driven and one
  attempt at a time; stop joins tasks before releasing the device. Integration
  tests verify packet transfer over two carriers and no premature device drop.
- Floppa network-change handling now replaces the carrier through that session;
  a manager-level test verifies device ownership remains stable and forwarding
  resumes. Socket preparation is now session-scoped in Floppa; actor-wide retry states
  and underlay DNS/candidate resolution remain open.
- Floppa config v2 has a cached dual-stack NetworkPlan and explicit route exclusions.
  Android uses its provisioned routes; desktop rolls back every configured address.
  v1 imports explicitly require reissuance. 236 Floppa core unit tests and four
  integration tests passed at that increment. H3-only and conservative Auto
  selection were connected in the following H3 increment below.
- Server-owned generation admission replaces authorizer-side revocation. Packet
  device preparation and request cancellation checks precede commit. Aborted,
  revoked and stale candidates preserve the active generation; failed factory
  preparation is covered by a Floppa forwarding regression.
- Physical Android acceptance is pending. On 2026-10-15, a Pixel 8 Pro is
  reachable over ADB but has an active Floppa VPN; it has not been interrupted.
- Shared `router::Router` owns one packet device. Peer factories reserve disjoint
  source prefixes before admission and activate routes only when the admitted
  bridge starts polling. Per-peer queues are byte-bounded (1 MiB/direction),
  incoming scheduling is round-robin, and full outbound queues drop independently.
  Tests cover peer isolation, spoof rejection, overlap rejection, inert candidates,
  replacement and joined release of the shared device.

- Local regressions cover H2 -> H3 -> H2 with one packet device, full-MTU H3
  packet transfer, early DATAGRAM capsules, queue byte/age limits and budget release.
  Floppa manager regressions cover H3 recovery/replacement/revocation and Auto
  fallback with bound but unresponsive UDP. H3 is still optional; CONNECT-UDP is not yet implemented. The 100 ms age policy covers
  the application receive queue; expiry inside Quinn's outbound queue is still open.

- HTTP/3 TCP flows implement bounded AsyncRead/AsyncWrite without per-flow tasks.
  Half-close preserves response reads and cancellation closes upstream TCP.
  CLI/SOCKS transport selection now supports H3; a server can listen on both TCP
  and UDP using one admission registry. A third isolated h3 vendor correction
  omits :scheme/:path in classic CONNECT as required by RFC 9114 section 4.4.

- H3 CLI acceptance passed: eight concurrent 512 KiB SOCKS flows, independent FIN,
  token/certificate/name/private-target rejection, and upstream cleanup after
  abrupt process death. The existing 45-second QUIC idle timeout bounds the latter.
- Routed H3 namespace acceptance passed for IPv4/IPv6 TCP/UDP/DNS/ICMP, reverse
  connections, full 1280-byte packets, MTU rejection, 10 ms delay/1% outer loss,
  SIGTERM/reconnect and namespace cleanup. SIGTERM now closes the carrier gracefully.
  Test harnesses snapshot their binaries so concurrent Cargo builds cannot change
  transport support midway through recovery checks. No host routes were changed.
- H3 TCP backpressure passed with 128 MiB in each direction and deliberately held
  readers. Both directions stall and resume while preserving payload and FIN.
  Full latency/loss matrix, physical Android and isolated Singapore remain pending.

- Floppa Underlay now owns TCP/UDP socket preparation for one session. Linux
  applies SO_MARK; Android captures the exact VpnService instance/generation,
  protects sockets and binds them to the underlying Network before transmission.
  A retired service cannot borrow the successor's protector. Late network-change
  events are checked against the current Foldfin generation under the tunnel lock.
  Foldfin no longer uses the global Android socket callback. Existing resolver
  and endpoint selection are unchanged; network-generation snapshots and scoped
  DNS/candidate selection remain pending.
- Host validation: 238 unit tests and eight Floppa integration tests, including
  zero TCP/UDP transmission on preparation refusal, retained preparation across
  H2/H3 recovery, service retirement and stale notification rejection. Android
  Rust/JNI checks and core/application Clippy passed; device acceptance is separate.

- Floppa arm64 debug APK now builds through Rust/JNI and Kotlin. Debug signing
  configuration was fixed to work without release credentials. Extra Android lint
  reports the existing core-ktx 1.19.0 -> 1.19.1 GradleDependency finding only.
  APK and logs: /home/okhsunrog/tmp_zfs/codex_tmp/foldfin-underlay/.
  Installation on the currently active Pixel VPN awaits the user's answer.

- The Pixel's installed signing certificate differs from the debug build. No
  uninstall/replacement was attempted. A separate `.foldfinlab` package was built
  and its application ID verified. Artifact: foldfin-underlay/artifacts/
  floppa-foldfin-lab-arm64-debug.apk under the temporary root above. Installing it
  preserves the existing application; activating its VPN still interrupts the
  current VPN and awaits the user's reply.

- Floppa was rebased onto main 60bc70b and now uses its mandatory Linux SO_MARK,
  shared route subtraction, endpoint resolver/cache and persistent retry settings.
  Linux route events do not trigger endpoint-route rewrites or unconditional
  tunnel replacement. Initial Foldfin attempts walk all configured endpoints,
  preserving TLS identity and applying rollback before retrying a failed address.
  Network/capability failures permit fallback; typed TLS/auth/policy rejection
  terminates the actor cycle, including on Android. Carrier-only recovery still
  needs fresh resolution and actor-owned retained-TUN retry states.
- Per the revised validation order, finish implementation/integration first;
  device/WAN acceptance is deferred. No phone installation or VPN interruption
  is currently requested. Local code/regression checks continue on the laptop.

- Floppa now retains TUN/platform state during actor-owned carrier recovery
  (`bace384`): bounded retries, offline parking, cancellation joined before
  rollback, and stale-observation rejection. Public UI uses its existing Retrying
  phase; carrier probes no longer count as received payload.
- Recovery discovery now uses session-prepared DoH sockets and the shared endpoint
  cache, then walks provisioned endpoints and resolved addresses. Linux applies
  SO_MARK; Android uses the captured service instance. TLS identity and provisioned
  network state remain unchanged. Private DNS names need cached candidates or a
  host-supplied Underlay resolver; initial connection discovery is unchanged.
- Latest laptop validation: 14 resolver/relay tests, 284 core tests and 13 Foldfin
  integration tests pass; host check/Clippy and Android all-target Clippy pass.
  Logs: /home/okhsunrog/tmp_zfs/codex_tmp/foldfin-discovery/.
  Public resolver reachability and physical roaming remain untested.

- Linux scoped discovery physically validated on 2026-10-17 in an isolated
  namespace/veth/NAT path through Ethernet, with unmarked external sockets
  blackholed. Fresh DoH returned Singapore; an owned TCP marker was correlated by
  source port with the source seen by Singapore and captures at both ends.
  Temporary firewalld veth membership and namespace-only rp_filter adjustment
  account for the current host/test fixture. Cleanup preserved host routes,
  policy rules, DNS and global sysctls. Evidence:
  /home/okhsunrog/tmp_zfs/codex_tmp/foldfin-physical-discovery/run-5/.
  This is scoped DNS/outer connectivity acceptance only; remote Foldfin recovery,
  IPv6 WAN forwarding and Android roaming are still pending.

- Real Floppa actor recovery passed against a disposable current Foldfin server on
  Singapore through the physical Ethernet namespace path. H2 TCP socket destruction
  and H3 lab-server restart both recover without changing TUN ifindex, addresses,
  MTU, routes/rules or connected_at. TCP/FIN, UDP, DNS packets and ICMP pass before
  and after each fault; explicit Down completes rollback. Client mount isolation
  keeps the host ownership lock and privileged rollback journal separate.
- Evidence: /home/okhsunrog/tmp_zfs/codex_tmp/foldfin-recovery-wan/run-2/.
  Actual carrier captures and server-observed physical source are recorded.
  Local/remote cleanup pass; the production service retains its MainPID. The lab
  uses its own temporary binary, token, TUN, peer subnet and source-limited port.
  IPv4 routed acceptance does not cover full tunnel, OS DNS application, existing
  flow continuity, prolonged outages, physical IPv6 or Android roaming.
