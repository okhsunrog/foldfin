# Foldfin: local isolation and direct VPS testing

Copied and adapted from Floppa's `docs/LOCAL-VPN-TESTING.md`. The namespace/veth/NAT
scheme is unchanged; commands, configurations and acceptance below are Foldfin's.

## Traffic path

```
[isolated namespace]           [host]                    [VPS]
 Foldfin client → outer0 ─── veth + scoped NAT ── physical NIC → TCP/8445
       │                                                    TLS/H2
 SOCKS5 or TUN                                          Foldfin server
```

The host can keep its existing WireGuard tunnels. A source-specific routing rule
for the disposable namespace uses the physical gateway before host VPN rules.
The physical interface is selected from the lowest-metric main-table default:
currently Ethernet `enp0s13f0u1u5`, gateway `10.77.77.1`. Do not assume these
values on another machine. Do not replace the host default route or DNS.

The prior remote scripts used the host's ordinary outer socket route, including
its active WireGuard tunnel. A public destination IP, correct egress IP and a
namespace alone do not prove a physical-path test. Record the namespace route,
host forwarding route, transmitted packets on the physical NIC and the outer
source seen by the VPS. Never silently fall back to a VPN underlay.

## Deployed instances

| Inventory host | Endpoint | SSH administration | Modes |
|---|---|---|---|
| moscow | msk.okhsunrog.ru:8445 | ubuntu@msk.okhsunrog.ru | TCP proxy; upstream exits Frankfurt |
| europe | eu.okhsunrog.dev:8445 | root@eu.okhsunrog.dev | TCP proxy and static-peer CONNECT-IP |
| singapore | sg.okhsunrog.dev:8445 | root@sg.okhsunrog.dev | TCP proxy and static-peer CONNECT-IP |

Administration SSH may use the host's existing VPN. Test client traffic must stay
inside the namespace on the physical path. Keep these two paths distinct.

The role, service user, units, directories, environment and vault keys now use
`foldfin`: `/opt/foldfin`, `/etc/foldfin`, `foldfin.service`, `FOLDFIN_TOKEN`,
`vault_foldfin_tokens`, `generated_configs/foldfin/`. The Frankfurt owned TUN is
`ffvpn0`. Certificates and credentials remain unchanged during the name migration.
Generated env files contain secrets and must stay private.

## Direct connection acceptance

Current remote scope (2026-10-03): Singapore only, through the physical interface.
Frankfurt is excluded while its IP is unreachable; Moscow is outside routine
tests. Historical endpoint descriptions below do not expand that scope.
Singapore CONNECT-IP was configured on 2026-10-12, with static test addresses
`198.18.78.1`/`198.18.78.2` and routed test LAN `198.19.78.0/30`, without internet
NAT or full tunnel. `scripts/test-vpn.sh` now uses `tests/vpn_physical.py`.
It verifies the configured service before creating any test network state.

A short ordinary WireGuard check against Singapore can be run with
`uv run --no-project tests/wireguard_physical.py`. It adds a temporary in-memory
server peer, creates a disposable client namespace, and uses the host physical
underlay with a WireGuard socket fwmark. It records real handshakes, inner ping
and both outer UDP captures, then removes the peer, device and private key.
This is short-session reachability, not a throughput or long-session test.

Run from `~/code/rust/foldfin`:

```bash
cargo build --locked --release --features chrome-tls --bin client
uv run --no-project tests/physical_vps.py
```

The script requires passwordless sudo, iproute2, iptables, tcpdump, curl, SSH and
already-enabled IPv4 forwarding. It sets up an isolated namespace, veth/NAT and
an owned policy table, then tests TCP/22, TCP/443 and Foldfin TCP/8445 for each VPS.
It captures SYN/RST metadata locally and on each server. A reachable Foldfin
listener is tested with both Rustls and Chrome TLS using the existing proxy
acceptance suite: concurrent HTTPS, remote DNS, expected egress, wrong credential
and private destination rejection. Local SOCKS listens only on namespace loopback.

A TCP timeout is recorded as a failed connection, not a TLS/fingerprint result.
A TLS failure after an established TCP connection is a separate stage. Working
SSH or HTTPS on another port does not prove the Foldfin listener is reachable.
Do not attribute failure to DPI without locating the packet loss/reset and
comparing controls. For diagnosis, capture at both ends before changing settings.

The [October 2 Frankfurt investigation](FRANKFURT-REACHABILITY-2026-10-02.md)
adds simultaneous OpenWrt WAN captures, direct UDP/ICMP controls and public
Moscow/Singapore-to-Frankfurt probes. The acceptance helper uses tcpdump
`--immediate-mode` to deliver packet lines before transient captures stop.

Normal cleanup terminates owned client/capture processes and removes the exact
rules, route, namespace and veth it created. No firewall chains are flushed;
server policies and listeners are not changed. Abrupt power loss/SIGKILL can bypass
cleanup, so inspect tagged `foldfin-physical-*` rules after such an interruption.

## VPN and performance

The Frankfurt static peer uses `198.18.77.1`/`198.18.77.2` and the advertised test
LAN `198.19.77.0/30`. Full IP routing differs from SOCKS TCP proxying. Moscow and
Singapore now has its own explicitly configured peer and prefix listed above.

`tests/vpn_vps.py` is historical functional acceptance with a transparent host
relay. Its success must not be used as evidence of direct physical reachability.
The Floppa integration's local real-TUN acceptance is:

```bash
cd ~/code/floppa-vpn
uv run --no-project tests/integration/test_foldfin.py
```

For throughput, `tests/bench_vps.py` in Foldfin uses namespace/veth/NAT with the
physical gateway by default. Any explicit `--underlay-interface` substitution
must be labelled. See [BENCHMARKS.md](BENCHMARKS.md) and
[the October 2 report](BENCHMARK-2026-10-02.md). Local packet/TLS fingerprint
matches and nested-VPN benchmarks do not establish resistance to network filters.

Current Singapore routed acceptance and CLI throughput:

```bash
./scripts/test-vpn.sh
./scripts/test-vpn.sh --chrome-tls
uv run --no-project tests/vpn_physical.py --output /tmp/foldfin-singapore \
  --interface enp0s13f0u1u5 --seconds 12 --repeats 2 --telemetry
```

The helper checks TCP/UDP/DNS/ICMP and source-preserving reverse connections
through a temporary VPS LAN namespace. Managed remote policy is IPv4; local
routed acceptance remains dual stack. Namespace and forwarding routes, the
VPS-observed source and captures on the physical NIC and VPS are retained.
A held marker socket is matched by its source port; ambiguous/NAT-rebased
identification fails instead of guessing. SSH administration uses its existing
route and is not the test carrier.

TUN queue 10000 and TCP send-autotune maximum 32 MiB are applied only inside the
disposable client namespace by `scripts/network_policy.py`. Its previous values
are restored before namespace deletion. Existing host/server global TCP settings
remain untouched. The managed server TUN also uses queue 10000. Server TCP
buffers retain their current global policy, so this does not reproduce the fully
tuned two-namespace local benchmark.

The temporary public benchmark listener is allowed only from the observed source;
the inner listener has a separate exact peer/interface rule. No global allow-private
or proxy destination-policy exception is installed. Proxy access to the VPS's own
public IP is denied by its LOCAL destination guard, so the throughput comparison
uses direct TCP and TUN. External proxy acceptance remains a separate check.
Cleanup removes exact tagged rules, capture/responder units, LAN/client namespaces,
veths, route/rule entries and temporary remote scripts; it verifies host default
routes, TCP sysctls and the running Foldfin service.
