# Foldfin throughput — 2026-10-02

Measured the actual release Floppa CLI, using its actor/TunnelManager and real
Linux TUN, against the deployed static Foldfin server in Frankfurt. iperf3 TCP,
MTU 1280, one/four parallel streams, upload/download, 12 measured seconds after
2 omitted warmup seconds, two repetitions per case. No speed-limit or protocol
settings were changed during the measurements.

The physical-gateway path could not establish a TCP connection to Frankfurt's
8445 listener within 10 seconds. A short capture on the VPS saw no matching
packets; this does not identify the cause. The successful measurements explicitly
use the existing `sirius_nova` WireGuard underlay (outer peer `10.65.65.3`).
The baseline uses the same namespace/NAT/underlay to the same VPS, without Foldfin.
Thus these are nested VPN results, not direct physical internet-path results.
Modes ran in blocks; the baseline showed substantial TCP retransmissions and
variation. Small differences between modes should not be overinterpreted.

| Mode | Streams | Upload, Mbps | Download, Mbps |
|---|---:|---:|---:|
| TCP baseline over existing WG | 1 | 262.9 (244.8–281.1) | 374.5 (372.9–376.2) |
| TCP baseline over existing WG | 4 | 276.8 (250.5–303.2) | 490.0 (466.8–513.2) |
| Foldfin / Rustls | 1 | 9.9 | 7.7 |
| Foldfin / Rustls | 4 | 10.0 | 7.8 |
| Foldfin / Chrome profile | 1 | 9.8 | 292.1 (286.1–298.1) |
| Foldfin / Chrome profile | 4 | 9.9 | 278.1 (271.0–285.2) |

Values are means of two runs; ranges are included for the variable higher-rate
cases. Download is VPS → client; upload is client → VPS. Receiver goodput is
reported, in decimal megabits per second. Four inner TCP flows still share one
CONNECT-IP stream and one outer TCP connection.

The client is an Intel Core Ultra 5 125H; Frankfurt exposes one `DO-Regular` vCPU.
The server Foldfin process used about 4.6–5.3% of one CPU during the low-speed
cases, and 43.8–48.0% during Chrome downloads. Floppa used about 1–2% during
low-speed cases and 18–20% during Chrome downloads. These figures exclude the
iperf server/client and WireGuard processing, and include warmup/control overhead.

The source strongly points to H2 flow control as the low-speed bottleneck:
`server::serve_connection` does not override the default initial stream/connection
windows. The Rustls client also leaves them at their defaults. h2 0.4.19 defines
the initial window as 65,535 bytes. The observed outer RTT is around 47–53 ms;
64 KiB per RTT is roughly 10–11 Mbps. The Chrome client instead advertises a
6 MiB stream window and a 15 MiB connection window, and only its download becomes
fast. The server receive window stays small, so both profiles retain slow upload.
This is a source-supported diagnosis, not an A/B confirmation with modified
server windows. No performance fix was deployed during this benchmark.

The next performance experiment should increase the server receive windows with
a bounded aggregate memory budget, expose suitable H2 settings for the normal
client profile, then repeat the same benchmark. Keep the measured Chrome client
profile intact. Follow with controlled RTT/loss and bidirectional traffic tests
before claiming a protocol or CPU ceiling.

Raw Frankfurt measurements and full binary hashes are retained locally in
`benchmarks/2026-10-02/frankfurt/summary.json` and the adjacent per-run JSON files.
Client SHA-256: `c0ccf9e0ab42681f` (prefix; full value in summary).
Server SHA-256: `606c1ec3c1c9694cddabfb412060cf1adfa32f84bc4e9e53d1a34ab39e30a7d5`.
See [BENCHMARKS.md](BENCHMARKS.md) for reproducible commands and cleanup behavior.

## Local release test without WAN

Both processes ran on the local Core Ultra 5 125H, in separate network namespaces
connected by veth. Floppa actor, real TUN and TLS/H2 remained in the packet path.
One short run per case: five measured seconds plus two omitted warmup seconds.
These are initial CPU/path measurements, not a sustained stress test. They do
not measure the maximum of the Frankfurt VPS, whose CPU is different.

| Profile | Streams | Upload, Mbps | Download, Mbps |
|---|---:|---:|---:|
| Rustls | 1 | 1887.0 | 2023.1 |
| Rustls | 4 | 1792.9 | 1794.8 |
| Chrome | 1 | 1732.5 | 2230.8 |
| Chrome | 4 | 1738.2 | 2168.9 |

The direct veth baseline was about 55–61 Gbps with one stream and 88–94 Gbps
with four, well above the tunnel results. Foldfin transmit-side server CPU was
about 66–91% during downloads; its receive-side CPU reached 92–96% during
uploads. Floppa reached about 94–109% during downloads and 67–69% during uploads.
Local performance therefore shows a processing ceiling near one occupied core
for these workloads, while the slow WAN cases barely occupy the CPU. The
results support an RTT-sensitive flow-control bottleneck in the WAN runs.
They do not isolate the individual costs of encryption, packet parsing, TUN
syscalls or scheduler wakeups. Profile differences need longer repeated runs.

Both local runs also passed routed TCP/FIN/UDP/DNS/ICMP acceptance and awaited
address/route rollback. All temporary local namespaces and tagged local/remote
firewall rules were confirmed removed after the measurements. No server service
restart, subscription modification or host default-route/DNS modification was
performed. Raw results are in `benchmarks/2026-10-02/local-rustls/` and
`benchmarks/2026-10-02/local-chrome/`.
