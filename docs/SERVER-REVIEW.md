# Server integration review — 2026-10-17

Delivery update (2026-10-18): see [STATUS.md](STATUS.md). Findings below describe
the review-start state; source publication and client provisioning have since advanced.

Scope: Foldfin server, authorization/admission, shared packet router and its
Floppa host. This is a source review, not a completed multi-user deployment audit.
The existing Singapore transport acceptance used a temporary static credential;
it did not exercise provisioning, database synchronization or certificate renewal.

## Findings at review start

1. **Release blocker: there is no production grant delivery path.**
   Floppa's `DeviceRegistry` is used by integration tests, not by a database-backed
   node process. The API does not issue Foldfin configurations. A tested access
   adapter is not user management. Finish issuance, revocation, address ownership,
   subscription/region policy and node synchronization as one vertical slice.
2. **Release blocker: internet routing does not imply client isolation.**
   `vpn::Config::incoming` enforces assigned source prefixes and destination route
   allowlists. A default destination route includes private addresses and other
   clients. A deployed node needs an explicit isolation policy before accepting
   full-tunnel grants. Reuse Floppa's entitlement semantics; do not assume the
   WireGuard-only firewall automatically covers a new TUN.
3. **Correctness: replacing a peer does not wake a pending device write.**
   `router::run` waits on the underlying writer's waker. A new generation can
   invalidate the selected packet without waking that wait, stalling subsequent
   peers. Replacement and registration removal must wake this wait; the resumed
   poll must discard the old generation before writing.
4. **Lifecycle: the host cannot supervise router termination.**
   Router IO failure closes queues but is only returned by `stop`. Add an awaitable
   termination signal and keep the task result until joined. A node must stop both
   listeners if the shared packet device fails, and release the device after joins.
5. **Certificate lifecycle is incomplete.**
   The CLI reads one PEM pair at startup. The current infrastructure regenerates a
   pinned self-signed experiment certificate when absent/expiring; this changes
   client trust and is not transparent production renewal. Use an infrastructure
   ACME/internal-CA issuer and an atomic shared rustls certificate resolver in the
   host. A failed reload must retain the working pair; both carriers must see the
   same resolver without replacing their admission registry or live sessions.
6. **Policy versions and lease horizon have no executable contract yet.**
   Floppa's design mentions five minutes; IMPLEMENTATION specifies one hour.
   The node needs one configured horizon bounded by subscription expiry, monotonic
   deadlines, serialized reconciliation, version checks, and unchanged-grant
   renewal without disconnecting sessions. Failed/incomplete reads must never
   renew access. A fresh authorized snapshot may install a new lease after an old
   lease expires; it must not revive the old lease's streams.
7. **Documentation and delivery drift.**
   README/ARCHITECTURE/GOALS contain pre-H3 and removed Chrome backend descriptions.
   LIBRARY still describes the shared router as future work. Current implementation
   history is in IMPLEMENTATION. The Floppa path dependency and vendor patches also
   require a reproducible packaging decision before distribution.
8. **Correctness: H3 cancellation can panic in the transport dependency.**
   Published h3-quinn 0.0.10 temporarily moves its receive stream into a pending
   future; `stop_sending` unwraps the now-empty slot. A cancelled pending read
   reproduces the panic. Keep the stream owned inline and poll Quinn's cancel-safe
   borrowed read future. This also keeps stream ID access valid during a read.
9. **Integration gap: plan limits and operational accounting.**
   Global connection/flow bounds are not per-device speed limits. A node must map
   Floppa plan policy to both IP and proxy traffic and expose readiness, failed
   synchronization, lease expiry and traffic/drop metrics before claiming full
   subscription integration. Do not silently treat a limited plan as unlimited.

## Changes from this review

- Fixed pending router-write wakeup on replacement/removal. Added observable
  router termination and teardown after an adapter panic, preserving joined stop.
- Added host-side atomic TLS identity replacement with H2/H3 integration coverage;
  no certificate issuer, file watcher or production service rollout is implied.
- Added the isolated h3-quinn receive cancellation fix; embedding workspace patch
  tables must include it alongside h3 and h3-datagram.
- Updated README, architecture and goals to the implemented transport stack and
  corrected shared-router API documentation.
- Reproduced the old H3 backpressure test timeout on unmodified revision 26402a2.
  With only its completion timeout raised, the baseline passed in 41.75 seconds.
  Keep the 128 MiB bidirectional data/backpressure assertions and allow 60 seconds
  per transfer; this test does not specify a minimum debug-build throughput.

The accompanying Floppa implementation adds the API/database/node path: digest-only
per-device issuance, quota serialization shared with WG/AWG, stable regional address
allocation, logout/region revocation, subscription-bounded leases and complete snapshot
reconciliation. Policy changes publish configuration revisions. A shared H2/H3 node
applies per-device bandwidth and private/client isolation, and supervises the packet
router. Deployment includes a systemd service, network template generation, a restricted
DB role, a certificate deploy hook and a dedicated musl build/package target.

Local PostgreSQL/API and real H2/H3 tests cover this path, including two peers, IPv4/IPv6,
related ICMP errors, renewal, rotation, subscription expiry, failed snapshots, DB-pool
outage, recovery and shutdown on packet-device failure. The static musl node also passed real TUN/nftables acceptance, running unprivileged
in a local three-namespace topology: IPv4/IPv6 TCP, UDP and ICMP over H2/H3, followed
by process and namespace cleanup. This is not a deployed Singapore multi-user service. ACME issuance and installation of the supplied deployment files
remain infrastructure rollout work. Per-region DB RLS and per-account traffic accounting
are not implemented. The current plan bandwidth limit is enforced per device/direction.
See the Floppa checkout's `docs/FOLDFIN-SERVER.md` for the executable/operator contract.

## Ownership and target architecture

- `foldfin`: CONNECT semantics, transport, admission, packet IO/router, cancellation
  and bounded buffering. No account database, certificate issuer, environment,
  process signals, interface creation or firewall management.
- `floppa-core` / `floppa-server`: authenticated provisioning transaction, device
  quota shared with existing protocols, region/subscription entitlement, stable
  address allocation, token digest and version persistence, configuration issuance
  and explicit credential rotation. A configuration response is not node readiness.
- `floppa-foldfin`: host access adapter and node executable. One shared router and
  registry serve both H2 and H3. A serialized reconciliation owner renews unchanged
  grants and revokes removed/changed grants. LISTEN/NOTIFY accelerates a periodic
  authoritative snapshot; notifications are not the source of truth.
- Deployment: unprivileged node with one prepared TUN; explicit forwarding, return
  routes/NAT and client isolation; certificate issuance/renewal outside the packet
  process. The node applies certificate updates and exposes health/metrics.

No per-packet PostgreSQL queries, no client certificates required, no account JWT
used as a VPN credential, and no second users database in the protocol crate.
Use separate high-entropy credentials per installation/region. Credentials are
returned once and persisted as digests; lost client credentials require rotation.

## Acceptance gates

1. Regression tests for pending-write cancellation, router IO failure and joined
   shutdown, including host adapter panic and cancellation of the supervision wait.
2. H2/H3 certificate replacement: new handshakes receive the new certificate;
   existing flows survive; malformed/mismatched reload keeps the previous identity.
3. Database/API/node: ownership/quota races, stable addresses, token rotation,
   subscription expiry, deletion/logout, region changes, stale snapshots, reconnect
   after missed notifications and bounded access during database outage.
4. Real multi-peer IPv4/IPv6 TUN acceptance: private/client isolation, internet and
   granted private routes, TCP/UDP/ICMP, backpressure and process restart/cleanup.
5. Isolated Singapore acceptance through the physical interface with packet/source
   evidence. Keep existing services and host networking unchanged during tests.

Full/split client routes, OS DNS application and physical Android acceptance remain
separate release gates even after the server path passes.

Floppa implementation: commit `4683ed6` in `floppa-vpn-foldfin`. Server acceptance:
177 Rust tests, workspace offline check and Clippy, generated API/cache checks,
frontend build, static musl build and isolated real-TUN acceptance passed.

## Architectural conclusion

Keep the protocol crate and its H2/H3 wire architecture. The missing work was primarily
in host policy, control-plane delivery and lifecycle supervision, with two concrete
transport/router defects fixed above. Accounts, plans, certificates and kernel network
setup belong to Floppa/deployment; adding those to the protocol would create a second
source of truth. No Chromium stack, custom mux or second account database is required.

Release remains gated on deploying the multi-user node through the isolated physical
Singapore path, exercising the real TUN/firewall/NAT with production-issued profiles. Protocol publication and Git pinning are complete; client
API-driven provisioning is implemented in Floppa PR #58. Full/split DNS lifecycle
and Android runtime acceptance remain separate from the completed server implementation.
