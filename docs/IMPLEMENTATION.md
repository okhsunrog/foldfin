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
- [ ] Remove Chrome backend; update CLI and regression harnesses.
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
