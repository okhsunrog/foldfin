# TLS/H2 performance plan — 2026-10-12

Goal: remove the measured long-RTT H2 flow-control bottleneck, keep TCP proxy
and CONNECT-IP behavior, and report measured throughput separately from estimates.
No claim of censorship resistance follows from these changes.

## Work and acceptance

1. Preserve the original source and release artifact; run a controlled baseline
   at 200 ms outer RTT using real TUN and the current CLI.
2. Increase receive windows for the normal client and server. Keep the measured
   Chrome client SETTINGS and connection window unchanged. Server receive credit
   must have a shared budget across connections, with credit returned at teardown.
   Do not change authorization, connection/stream counts or protective deadlines.
3. Verify formatting, all-target checks/tests/clippy, feature-only builds and
   Chrome builds. Check budget exhaustion/recovery, slow-reader backpressure,
   TCP half-close, TLS validation and cancellation. Run existing smoke and routed
   dual-stack TUN acceptance, including UDP/ICMP, MTU and carrier loss.
4. Repeat the same release benchmark at 200 ms RTT, then under controlled loss.
   Record binary hashes, raw iperf JSON and namespace cleanup. These CLI tests
   do not reproduce the earlier Floppa actor CPU benchmark.
5. Run available Singapore proxy acceptance only through a physical namespace,
   veth/NAT, source routing and captures at both ends. Remote CONNECT-IP remains
   paused until its server configuration exists. Do not add Frankfurt or Moscow.
6. Save results and remaining bottlenecks. Do not extrapolate UDP throughput to
   the H2 TCP carrier, or several direct TCP connections to one VPN connection.

## Implemented policy

Normal client: fixed 32 MiB stream and connection receive credit per carrier.
Chrome client: existing 6 MiB stream / 15 MiB connection profile.
Server: up to 32 MiB extra credit per connection, reserved from a shared 128 MiB extra-credit
pool per Server instance, plus the standard 65,535-byte base window per connection.
If the pool is exhausted, use the base window without rejecting the connection.
The unchanged 128-connection limit bounds total advertised connection credit
to less than 136 MiB. This is a DATA-credit budget, not a cap on whole-process RSS;
TLS, socket buffers, headers and application buffering have separate costs.

Allocation is intentionally conservative: reservations stay with their carrier
until teardown, and existing small-window carriers are not dynamically enlarged
when another carrier exits. Authentication and per-IP fairness are separate work.

## Progress

- Repository instructions, code and existing measurement reports inspected.
- Original source saved under `benchmarks/2026-10-12-h2/original-src/`.
- Added `tests/bench_local.py` for reproducible local CLI/TUN measurements.
- Completed before/after release measurements at 200 ms, under loss and without
  netem; final idle-host local TUN result 2.9–3.1 Gbps.
- Implemented normal-client windows and the server shared receive-credit pool.
- Passed default/Chrome checks, tests, clippy, feature checks, smoke, routed
  dual-stack TUN and Chrome initial H2 settings comparison.
- Fixed the routed test's asymmetric LAN-veth MTU; retained optional diagnostics
  and support for one frozen release CLI, with no retained TLS private key.
- Passed both proxy profiles on Singapore through physical Ethernet, with
  bidirectional packet evidence and cleanup. Production server unchanged;
  remote TUN still outside scope until Singapore CONNECT-IP configuration exists.
- Results and limits: [BENCHMARK-2026-10-12.md](BENCHMARK-2026-10-12.md).

## Second pass completed: local TCP/TUN diagnosis

- Added opt-in TCP sampling and packet metadata capture to the local benchmark.
- Added one SHA-256-verified framed TCP workload shared by direct, SOCKS proxy
  and TUN cases; it has no extra forwarding relay. Endpoint TCP_NODELAY is set
  consistently. Its Python/checksum costs preclude treating it as a CPU ceiling.
- Compare TUN driver drops with qdisc drops and inner/outer TCP retransmissions.
  Queue-length experiments change disposable test interfaces only.
- Confirmed thousands of TUN driver drops with the small default queue, despite
  zero qdisc drops. A larger test queue improves throughput even on original code.
- Confirmed the inherited 4 MiB TCP send-autotune maximum limits direct TCP to
  about 165 Mbps at 200 ms. A 32 MiB maximum inside test namespaces raises it
  to about 1 Gbps. Host sysctls, routes and DNS are untouched.
- Added a bounded 64-batch outbound packet pump and cooperative receive polling.
  Cancellation owns both borrowed futures; queued packets follow current policy.
  A 512-batch experiment did not show a stable advantage and was not retained.
- Final shared workload reaches Rustls TUN 696/700 Mbps at 200 ms with tuned
  test queues/buffers. Chrome TUN is 666/174 Mbps; its measured receive profile
  stays unchanged. No-delay final CLI/TUN measures about 3.6 Gbps.
- Original code also reaches 551/705 Mbps in the tuned network. Do not attribute
  the entire gain to code or report any one run as a guaranteed ceiling.
- Default/Chrome validation, routed acceptance and initial H2 comparison pass.
- A final 200 ms / 1% ingress-loss benchmark gives native only 1.55/2.01 Mbps;
  TUN upload fails receiving iperf results. Retained as a failed measurement,
  not a validated TUN rate. High-RTT loss robustness remains unresolved.
- Detailed evidence: [BENCHMARK-TCP-2026-10-12.md](BENCHMARK-TCP-2026-10-12.md).

## Following stage

Integrate explicit platform queue/buffer policy with network setup/rollback,
then full/split routes and DNS lifecycle. Do not silently apply benchmark sysctls
to the host or change the packet library into an OS configuration owner.
Remote TUN configuration and a new-server WAN throughput result require
Singapore CONNECT-IP setup and the physical-interface method. They remain
separate from these completed local measurements. H2 HOL and loss sensitivity
still need consideration; a carrier redesign is not justified by the former
33–64 Mbps result alone.

## Namespace policy and WAN stage completed

- External helper applies/restores TUN queue and TCP autotune settings only in
  an explicit isolated namespace, with host refusal and five runtime tests.
- Enabled static-peer CONNECT-IP on Singapore; production server TUN queue is
  10000. Global TCP policy is unchanged on both hosts.
- Fixed quick-update selection and restored physical VPN wrappers. Historical
  Frankfurt/relay/Floppa remote helpers remain disabled.
- Both proxy profiles and both routed IPv4 VPN profiles passed through Ethernet,
  with VPS-observed source and captures at both ends.
- WAN download: native 108–109, Rustls 98–99, Chrome 102–104 Mbps; upload is
  variable. TUN driver drops are zero. This does not reproduce the two-sided
  32 MiB TCP tuning of the local 700 Mbps experiment.
- Report: [BENCHMARK-SINGAPORE-2026-10-12.md](BENCHMARK-SINGAPORE-2026-10-12.md).

The H2 optimization stage is closed. Next prioritize full/split route and DNS
lifecycle, setup/rollback and carrier-loss behavior. Separate server buffer policy
and upload stability diagnosis require their own evidence; more H2 window tuning
is not justified by this run. Remote IPv6, Android and censorship-resistance
acceptance remain unestablished.
