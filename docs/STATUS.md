# Current status — 2026-10-18

This is a delivery snapshot. IMPLEMENTATION and benchmark reports retain historical
results; they do not describe the deployed service or the current TLS fingerprint.

| Area | Implemented | Acceptance / delivery |
| --- | --- | --- |
| Foldfin engine | H2/H3 proxy and CONNECT-IP, admission, leases, multi-peer router, retained-device recovery | Local Rust and namespace coverage; earlier isolated Singapore actor recovery passed |
| Floppa server | API issuance/revocation, PostgreSQL grants, node synchronization, isolation, TLS reload and deployment artifacts | Merged via Floppa PR #57; local database and real-TUN acceptance recorded in SERVER-REVIEW |
| Normal client flow | Automatic API provisioning/refresh, actor-owned credentials and repair | Floppa PR #58 (`7623ef0`), locally checked; full deployed flow pending |
| Limited rollout | `plans.foldfin_enabled`, initially admin plan only; checked at issuance and node synchronization | Floppa PR #58 (`9e71357`); production migration not applied by this work |
| Source distribution | Public MIT OR Apache-2.0 repository and pinned Git dependencies | Published; Floppa must bump its pin to consume subsequent engine changes |
| Production node | Deployment templates and operator contract available | Multi-user Singapore rollout, certificate issuance and live provisioning acceptance pending |
| Platform behavior | Host-owned route/DNS setup, Linux SO_MARK and Android protect/bind | Full/split OS DNS acceptance, physical IPv6 WAN and Android roaming remain open |

## Review follow-up

The router now supports `Router::start_with_config` with a shared queued-payload
budget. Defaults are 64 MiB total and 1 MiB per peer per direction. Limits must fit
at least the VPN MTU. Admission does not preallocate these bytes. Queue statistics
expose current/peak payload and global-budget drops. This is not a bound on process
RSS: queue metadata, transport queues, socket buffers and an in-flight device write
are separate. A shared budget does not guarantee fair allocation among peers.

Inbound saturation applies backpressure; outbound saturation drops the arriving
packet. Dequeue, peer removal, replacement and shutdown release the budget and wake
blocked senders. Replaced peers cannot retain queued payload indefinitely. A small
receive buffer returns InvalidInput while preserving the queued packet for retry.

`Session::stop` completes cleanup and releases its packet device before returning
the first task failure. That failure may have occurred during forwarding; it does
not imply incomplete cleanup. Cancellation retains task handles and an already
observed error for a later stop. Recovery and underlay changes log a preceding
carrier failure at debug level and continue; they do not fail solely because the
old carrier failed. A repeated completed stop succeeds.

Route indexing and moving packet writes outside the generation lock remain deferred
until profiling justifies them. The generation fence and source/destination policy
must survive any optimization. H3 vendor patches remain necessary for this pinned
source; their rationale is in vendor/README.md.

## Next acceptance gates

1. Broader throughput/contention and adversarial load tests before claiming capacity.
   The regression suite includes budget saturation/release, replacement wakeups,
   undersized reads and 128 bursts across 16 slow plus 16 fast peers.
2. Normal Floppa account-to-client flow on the laptop: admin entitlement, issuance,
   connection, refresh/revocation, recovery, full/split routes and OS DNS rollback.
3. Deploy and exercise the multi-user Singapore node through the physical interface
   in an isolated namespace, retaining route/source/capture evidence.
4. Build/install the matching Android application and exercise lifecycle and roaming.

The earlier static-peer WAN tests do not satisfy the production provisioning gate.

Validation of this follow-up: formatting, all-target check/Clippy and Rust tests
passed with the default features and with H3. Proxy smoke tests and routed local
namespace acceptance passed for H2 and H3, including dual-stack TCP/UDP/ICMP,
reverse traffic, loss/delay and cleanup. These checks do not establish multi-user
WAN capacity or complete the Floppa production/Android gates above.
