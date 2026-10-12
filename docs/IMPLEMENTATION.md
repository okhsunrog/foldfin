# Foldfin session and transport implementation

Accepted architecture: one Rust library; H2/rustls and H3/Quinn; CONNECT,
CONNECT-UDP and CONNECT-IP. Remove Chrome/BoringSSL. Session and packet-device
ownership outlive carriers. Floppa owns recovery policy and platform networking;
Android owns its system lockdown policy. No protocol-owned kill switch.

## Delivery sequence

- [x] Record original source (364a0c5) and release binary baseline.
- [x] Fix packet collector fairness and capsule request/response bounds.
- [ ] H3 vertical slice with caller-owned UDP sockets and TLS validation.
- [ ] Transport-independent sessions, bounded queues, recovery and multi-peer router.
- [x] Remove Chrome backend; update CLI and regression harnesses.
- [ ] Floppa config v2, dual-stack NetworkPlan, Underlay, Recovering and typed health.
- [ ] Floppa node binary, provisioning, versioned grant synchronization and metrics.
- [ ] Local dual-stack, loss/latency, multi-peer and lifecycle acceptance.
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
  This is a carrier API, not yet the integrated CONNECT-IP VPN bridge.
- CONNECT syntax is validated before application authorization, with an H2
  regression proving invalid requests never call the authorizer.
- Published h3 0.0.8 lacks CONNECT-IP and h3-datagram 0.0.2 discards the encoded
  stream ID. Minimal vendored patches are documented in vendor/README.md.
  They must also be applied at embedding workspace roots.
- Chrome/BoringSSL backend, profile selector, native dependencies and build/test
  switches removed. Floppa's importing adapter updated to the rustls-only client
  API. Existing measurements remain historical. H2 proxy and Floppa's three
  integration tests pass after the removal.
- H2 `session::Session` retains the packet device across carrier failure,
  failed negotiation and explicit recovery. Recovery is host-driven and one
  attempt at a time; stop joins tasks before releasing the device. Integration
  tests verify packet transfer over two carriers and no premature device drop.
- Floppa network-change handling now replaces the carrier through that session;
  a manager-level test verifies device ownership remains stable and forwarding
  resumes. Actor-wide retry states and session-scoped Android Underlay remain open.
- Floppa config v2 has a cached dual-stack NetworkPlan and explicit route exclusions.
  Android uses its provisioned routes; desktop rolls back every configured address.
  v1 imports explicitly require reissuance. 236 Floppa core unit tests and four
  integration tests pass. H3-only currently reports unavailable; Auto uses H2
  until the H3 VPN bridge and candidate selection are connected.
- Server-owned generation admission replaces authorizer-side revocation. Packet
  device preparation and request cancellation checks precede commit. Aborted,
  revoked and stale candidates preserve the active generation; failed factory
  preparation is covered by a Floppa forwarding regression.
- No Android ADB device is currently connected; physical acceptance is pending.
