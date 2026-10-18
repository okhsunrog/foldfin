# H2 CONNECT-IP versus TCP CONNECT — 2026-10-18

This is a local controlled comparison of existing Foldfin paths, not a new TCP
split implementation. Engine revision: `71f6af9`. No remote VPS, host routing,
firewall, DNS or global sysctl changes are involved.

## Method

Two isolated namespaces are joined by veth; this matrix uses IPv4. Receiver-side IFB/netem applies half
the requested RTT and the specified independent random loss in each direction.
Each direction is limited to 50 Mbit/s. Veth GRO/GSO/TSO are disabled so loss is
applied to individual packets rather than large offloaded buffers. TCP uses the
host kernel's CUBIC implementation, confirmed by saved `ss -tinm` samples.

The same server/workload is accessed by direct TCP, real TUN over H2 CONNECT-IP,
and SOCKS5 over H2 TCP CONNECT. CONNECT flows share one carrier. The TUN MTU is
1280; outer/direct MTU is 1500. The TUN queue length is 10000, and namespace TCP
buffer defaults are preserved. Netem's generous queue limit allows bufferbloat;
this is deliberately saturated traffic, not a latency-controlled access link.

Each run receives for a fixed 8-second measurement window after 2 seconds of
warmup. Every complete 64 KiB frame is compared byte-for-byte with the generated
payload; an incomplete final frame is counted separately and excluded from
goodput. The receiver then closes the stream without waiting for queued data to
drain. This avoids interpreting sender-buffer drain time as a measurement window.
Concurrent sequential probes open a new application TCP connection and request a
1 KiB response, then pause 200 ms. Latency includes TCP/SOCKS CONNECT and response;
samples starting within the first 2 seconds are omitted. Probe failures are
retained. A socket timeout applies per operation, not as one total request deadline.
Multiple-bulk-flow results sum per-flow goodput over equal-duration windows whose
starts can differ slightly due to connection setup.

There are two samples per mode, each with a fresh carrier. These short exploratory
trials are not confidence estimates. Netem random loss is not replayed identically
between modes. Direct runs precede tunneled runs; the zero-loss case runs TUN first,
the impaired cases run CONNECT first. A larger randomized matrix is needed before
attributing small differences to the protocol. Low successful-probe counts make
p95 particularly unstable; report failed probes alongside successful latency.

The initial drain-to-completion experiment is retained under `rtt*` artifact
folders. At 100 ms / 1% loss its CONNECT workload exceeded the 43-second process
deadline. These preliminary results are excluded from the bounded-window tables.
Their failure motivated the receiver-bounded measurement above, not a protocol fix.

Outgoing outer0 packet metadata is captured at both endpoints, before receiver-side
loss. The analysis separates zero-payload outer TCP packets from TCP packets with
payload. Payload lengths include retransmissions and are not TLS-record lengths.
Capture kernel-drop counters must be zero. The workload windows exclude initial
carrier setup, so these summaries do not assess TLS/HTTP handshake fingerprints.

The application workload is synthetic framing, not HTTPS browsing. There is no
benign HTTPS reference set or classifier. A changed traffic profile therefore
cannot establish censorship resistance or a false-positive rate. This experiment
also excludes the CPU/memory/compatibility cost of a userspace TUN TCP stack.

## Reproduction

Build a release Foldfin CLI and freeze it outside the build directory. Set TMPDIR
to a directory under `/home/okhsunrog/tmp_zfs/codex_tmp/`. For example:

```sh
uv run --no-project tests/bench_local.py \
  --binary "$TMPDIR/foldfin" --output "$TMPDIR/rtt100-loss1" \
  --workload mixed --modes proxy tun --seconds 8 --repeats 2 \
  --directions download --flows 1 --rtt-ms 100 --loss-percent 1 \
  --rate-mbps 50 --disable-offloads --netem-placement ingress \
  --tun-queue 10000 --telemetry
uv run --no-project tests/analyze_mixed.py "$TMPDIR/rtt100-loss1"
```

Artifacts for this investigation are under
`/home/okhsunrog/tmp_zfs/codex_tmp/foldfin-split-comparison/`: binary/hash,
per-trial workload results, TCP/qdisc telemetry, packet metadata, and cleanup status.

## Results

All 36 bounded trials completed; payload checks passed, capture kernel drops were
zero, and all six scenarios reported namespace cleanup. Values below are ranges
across two trials, in Mbit/s. Loss is per outer direction.

| RTT / loss / bulk flows | Direct TCP | H2 CONNECT-IP | H2 CONNECT |
| --- | ---: | ---: | ---: |
| 100 ms / 0% / 1 | 47.78–47.78 | 45.09–45.15 | 47.64–47.64 |
| 100 ms / 0.1% / 1 | 5.77–9.83 | 10.09–14.22 | 5.96–7.41 |
| 100 ms / 1% / 1 | 1.38–1.64 | 1.18–1.38 | 1.44–1.44 |
| 100 ms / 1% / 4 | 4.85–5.96 | 1.18–1.18 | 1.38–1.44 |
| 100 ms / 2% / 1 | 0.85–0.92 | 0.85–1.11 | 0.85–0.85 |
| 200 ms / 1% / 1 | 0.79–0.92 | 0.66–1.11 | 0.72–0.92 |

Successful short-request latency below is the median pooled across both trials,
in milliseconds. Counts include requests started after the 2-second warmup;
failures are filtered to that same start window. These are completion counts,
not rates: slower sequential requests produce fewer samples. A successful
request can finish after the bulk window. With few completions, p95 is not a
useful summary; raw per-trial samples and timeouts remain in the artifacts.

| RTT / loss / flows | TUN median ms | TUN successes / errors | CONNECT median ms | CONNECT successes / errors |
| --- | ---: | ---: | ---: | ---: |
| 100 ms / 0% / 1 | 712 | 19 / 0 | 993 | 14 / 0 |
| 100 ms / 0.1% / 1 | 3442 | 5 / 0 | 5638 | 1 / 2 |
| 100 ms / 1% / 1 | 2679 | 8 / 0 | 4912 | 4 / 0 |
| 100 ms / 1% / 4 | 4466 | 3 / 0 | 2590 | 3 / 2 |
| 100 ms / 2% / 1 | 3418 | 6 / 0 | 4167 | 2 / 1 |
| 200 ms / 1% / 1 | 4092 | 3 / 1 | 5508 | 3 / 1 |

### Outer traffic observations

| Scenario | Mode | Client-to-server TCP packets carrying payload, per trial |
| --- | --- | ---: |
| rtt100-loss0-flows1 | tun | 5272–11296 |
| rtt100-loss0-flows1 | proxy | 43–44 |
| rtt100-loss1-flows1 | tun | 346–406 |
| rtt100-loss1-flows1 | proxy | 20–20 |

## Interpretation

The expected general throughput/latency advantage of TCP CONNECT did not emerge
in this short matrix. CONNECT saves encapsulation overhead without loss, and is
slightly faster in the four-flow lossy case, but the ranges overlap in several
other cases and CONNECT-IP is faster in the 0.1% case. The small number of random,
short trials does not establish a general ranking. At low throughput, counting
complete 64 KiB frames also quantizes results by about 0.066 Mbit/s per flow.

Short requests often wait seconds in both tunneled modes. CONNECT has fewer
successful probes and/or timeouts in multiple cases; the four-flow median must
not hide its two failed probes. For example, sampled server outer TCP Send-Q in
the 0.1% case reaches about 2.1–4.2 MB for CONNECT and at least 2.1 MB for TUN.
This supports investigating queued bytes and shared-carrier HOL before expecting
TCP split alone to improve responsiveness. It does not isolate their respective
causal contributions or prove a particular scheduling defect.

Four direct bulk connections get independent TCP congestion controllers; four
CONNECT streams still share one outer TCP controller, as do the TUN flows. The
direct four-flow result is a useful reference but not an equal-congestion-control
comparison. Additional carriers would change this property and fairness.

The external profile changes substantially: during a download, CONNECT-IP carries
inner TCP acknowledgements as encrypted upstream payload, while TCP CONNECT ends
those TCP sessions locally. The thousands-versus-dozens contrast in payload-bearing
upstream packets is consistent with that mechanism. It supports testing TCP split
as a traffic-profile change, but does not establish that one mode is harder to
classify against real HTTPS. No DPI classifier, realistic TLS application workload,
active interference detection, or benign-web false-positive measurement was run.

Keep CONNECT-IP as the device-level VPN baseline. Before adding a userspace TCP
stack, investigate carrier write-ahead/queue residence under mixed load and repeat
with longer, randomized trials. Assess stealth separately with equivalent HTTPS
application traffic and a benign HTTPS/H2 reference set. This experiment adds only
benchmark tools; it does not change production transport, admission or routing.
