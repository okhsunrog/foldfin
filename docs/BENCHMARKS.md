# Throughput benchmarks

## Current Singapore CLI/TUN workflow — 2026-10-12

Singapore now has opt-in static-peer CONNECT-IP. Use the current physical-only
helper for release CLI/TUN throughput:

```bash
cargo build --locked --release --features chrome-tls --bins
uv run --no-project tests/vpn_physical.py --output /tmp/foldfin-singapore \
  --seconds 12 --repeats 2 --telemetry
```

The direct baseline and Rustls/Chrome TUN carry the same SHA-256-verified framed
TCP workload, 64 KiB blocks, two-second warmup and consistent TCP_NODELAY.
Client TUN MTU is 1280. Physical NIC/source routing, namespace/veth/NAT and
captures at both ends are mandatory; no existing-VPN fallback is available.
The client namespace temporarily uses TUN queue 10000 and TCP send-autotune
maximum 32 MiB, with guarded rollback. Production server TCP globals are not
changed; its managed TUN queue is 10000. Modes/repeats run sequentially.
Optional telemetry samples client/server TCP state every two seconds via local
namespace inspection and administrative SSH; two seconds are waited after each
completed sample, and the commands add time/load.

Remote routed IPv4 acceptance checks TCP/FIN, UDP/DNS/ICMP and reverse traffic
with source addresses preserved. Remote IPv6, WAN packet-loss experiments and
Floppa runtime throughput are separate checks. The proxy destination firewall
correctly denies the server's own public IP, so it is not used for this throughput
endpoint; public proxy HTTPS acceptance is checked separately.
Current results: [Singapore report](BENCHMARK-SINGAPORE-2026-10-12.md).
Raw generated-workload results, errors, binary hashes, route/source/capture
evidence and rollback status are retained. The helper does not install internet
NAT for the VPN or modify host default routes/DNS.

## Historical Frankfurt/Floppa workflow (disabled)

As of 2026-10-03 the Frankfurt remote TUN benchmark is paused before any remote
operation. The current test target is Singapore, whose CONNECT-IP mode is not
configured at that point. The remote recipe below remains disabled even after
Singapore setup; use the new CLI/TUN workflow above. Local benchmarks remain available.

`uv run --no-project tests/bench_vps.py --seconds 12 --repeats 2` builds the
Floppa CLI in release mode with `foldfin-chrome`, then benchmarks its Foldfin TUN
integration against the current Frankfurt server. `--no-build` reuses that binary.
The script requires passwordless sudo, SSH root access to Frankfurt, iperf3 on
both hosts, iptables/iproute2, curl, and already-enabled host forwarding.

A disposable namespace reaches the physical default gateway through veth/NAT,
with a source-specific policy rule to bypass existing host VPNs. Host default
routes, resolver configuration, server credentials and subscriptions are untouched.
Temporary tagged firewall rules permit the iperf TCP port only from the measured
observed outer client IP and the configured inner peer. The temporary server unit has a
20-minute runtime cap. Normal cleanup stops it and removes all test rules, policy
routes, links, namespace and private client configuration. Abrupt SIGKILL or power
loss can bypass finally; inspect tagged `foldfin-bench-*` rules if interrupted that
way. The script does not flush shared firewall chains or routing tables. The outer
source restriction uses a held TCP connection and the peer seen by the VPS,
rather than an IP-echo service whose routing can differ from the tested path.

Each profile runs two repetitions of TCP upload/download, with one and four
parallel streams. The first two seconds are omitted from iperf measurements.
Direct TCP uses the same namespace, physical route, server and iperf listener.
Foldfin uses a validated TLS/H2 carrier and real Floppa actor/TUN at MTU 1280;
there is no Python socket relay. Rustls and Chrome TLS are measured separately.
The static deployment's VPN policy needs no internet NAT because the workload
terminates on the server's configured inner address.

The output directory contains raw per-run iperf JSON and a summary with client
and server binary hashes, CPU models, receiver throughput, retransmissions and
process CPU usage. CPU percentage uses 100% per occupied core. Server CPU is
systemd service CPU time; client CPU is the Floppa process's user/system CPU time.
Both cover the whole run including iperf warmup and control overhead. The server
process is shared with its normal listener, so unrelated activity can contribute.
Credentials are removed at cleanup; logs are not intended as public artifacts.

These are throughput measurements for this client/network/VPS combination, not
an intrinsic protocol maximum. WAN congestion, RTT, loss, provider shaping and
one-vCPU scheduling can dominate. Modes run in blocks rather than interleaved;
repeat at another time if small differences matter. Download means VPS to client;
upload means client to VPS. Mbps is decimal megabits per second. The iperf workload
covers TCP over CONNECT-IP; it does not measure SOCKS mode, UDP capacity, roaming
performance or Android device performance. Local no-WAN and controlled-loss runs
are separate experiments needed to establish CPU ceilings and TCP-over-TCP/HOL
behavior.

## Existing VPN underlay and local CPU test

If the physical path cannot reach Frankfurt, an explicit alternate underlay is
available: `--underlay-interface sirius_nova`. This measures Foldfin over an
existing WireGuard tunnel; the direct baseline uses that same tunnel. The script
records the selected underlay and the source address actually observed on the
server. It never silently substitutes the host VPN for a physical-path result.

For a no-WAN release test, run from `~/code/floppa-vpn`:

```bash
uv run --no-project tests/integration/test_foldfin.py --benchmark --seconds 10
uv run --no-project tests/integration/test_foldfin.py --benchmark --chrome-tls --seconds 10 --output /tmp/floppa-foldfin-local-chrome
```

This uses two network namespaces on the local machine, real Floppa actor/TUN,
and direct veth versus CONNECT-IP traffic. It also runs acceptance and awaited
rollback. Both processes compete for resources on the same machine, so the
result is not the throughput ceiling of Frankfurt's one-vCPU instance.

## Controlled CLI/TUN benchmark

`tests/bench_local.py` uses two disposable namespaces, a veth carrier, real TUN
at MTU 1280 and iperf3 TCP. It uses the Foldfin CLI directly, without Floppa's
actor. There is no host-facing veth, host route/DNS change or remote access.
An explicit frozen `--binary` permits reproducible before/after comparisons.

```bash
cargo build --locked --release --bins --features chrome-tls
uv run --no-project tests/bench_local.py --output /tmp/foldfin-200ms --rtt-ms 200 --seconds 8 --repeats 2
uv run --no-project tests/bench_local.py --output /tmp/foldfin-loss --rtt-ms 200 --loss-percent 1 --seconds 8 --repeats 1
```

Each direction of the outer path receives half the requested RTT. The direct
TCP baseline uses that same carrier; tunnel cases use one CONNECT-IP stream
and one outer TCP connection. The netem queue is enlarged to avoid its usual
1000-packet queue becoming an accidental bandwidth limit. Loss applies to
queued veth packets with their normal offloads, not necessarily individual
wire-sized Ethernet frames. This is not a precise physical-loss model.

Results include binary hashes, receiver goodput, retransmissions, raw iperf JSON
and verified namespace cleanup. A failed run has no comparable goodput result;
retain its error rather than interpreting it as zero throughput. Short runs,
TCP startup, host load and offloads can affect rates. Run longer repetitions
without competing builds before claiming a CPU ceiling or small improvement.
See [the October 12 report](BENCHMARK-2026-10-12.md).

For TCP diagnosis use `--netem-placement ingress`, which redirects receive
traffic to a namespace-owned IFB. This avoids sender TCP Small Queues artifacts
described by [tc-netem](https://man7.org/linux/man-pages/man8/tc-netem.8.html).
The historical default remains `egress` to reproduce previous reports.
`--telemetry` samples `ss -tinm` and retains TCP metadata plus link, qdisc and
`nstat` snapshots. TUN driver drops must be checked separately from qdisc drops.
Counters are cumulative within a namespace; compare successive snapshots.

`--tun-queue` changes only the test TUN txqueuelen (default 500).
`--tcp-wmem-max` sets the TCP send-autotune maximum inside each test namespace,
with minimum/default values 4096/16384; it does not change host sysctls or set
SO_SNDBUF on the production client. A larger buffer is a network-setting
experiment, not evidence of an equivalent code-only speedup.

```bash
uv run --no-project tests/bench_local.py --output /tmp/foldfin-tcp \
  --rtt-ms 200 --seconds 20 --repeats 2 --telemetry \
  --netem-placement ingress --tun-queue 10000 --tcp-wmem-max 33554432
uv run --no-project tests/bench_local.py --output /tmp/foldfin-modes \
  --rtt-ms 200 --seconds 12 --repeats 1 --workload stream --modes proxy tun \
  --telemetry --netem-placement ingress --tun-queue 10000 --tcp-wmem-max 33554432
```

`--workload stream` selects one framed TCP endpoint for direct, SOCKS proxy and
TUN, with SHA-256/count verification, independent half-close and consistent
endpoint TCP_NODELAY. No extra relay is used. Its Python/checksum overhead is
shared, so it is useful for long-RTT mode comparisons rather than CPU ceilings.
`--modes proxy` requires this workload; iperf remains the default TUN test.
See [the TCP/TUN follow-up](BENCHMARK-TCP-2026-10-12.md) for results and caveats.

For retained routed acceptance diagnostics, use
`uv run --no-project tests/vpn_netns.py --routed --output /tmp/foldfin-routed`.
`--binary /absolute/path/to/foldfin` bypasses building and selects one frozen CLI
for both roles. Output contains test packet metadata, logs and failure snapshots;
temporary TLS private keys are not retained. The reduced-MTU routed test sets
both ends of its LAN veth to 1280, preserving a symmetric simulated link.
