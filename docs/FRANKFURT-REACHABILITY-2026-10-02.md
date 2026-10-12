# Frankfurt direct-path investigation — 2026-10-02

Direct connections from the home Internet connection to `68.183.74.207` fail
before TLS. The deployed Foldfin server is reachable from Moscow and Singapore.
The evidence localizes the failure beyond the OpenWrt WAN interface, but does
not identify the device or network dropping packets.

## Verified paths

The laptop's active `sirius_nova` AmneziaWG endpoint is Moscow
`212.233.78.60:58888`, not Frankfurt. Frankfurt's WireGuard peer is also Moscow.
Consequently, successful SSH administration through the host VPN does not
demonstrate home-to-Frankfurt physical reachability.

The direct tests used two independent routing arrangements:

- The existing disposable namespace, with a source-specific policy route and
  NAT through the physical Ethernet interface.
- Host sockets bound to `enp0s13f0u1u5`, with `SO_MARK=0xca6c` to bypass the host
  VPN policy. This mark selects the main-table route via `10.77.77.1`.

Both arrangements fail to establish TCP to Frankfurt. The second test also
captured packets on the home OpenWrt router's WAN interface:

```text
laptop 10.77.77.230 / physical Ethernet
  -> OpenWrt 10.77.77.1, WAN 192.168.1.2
  -> Innbox G84 192.168.1.1
  -> upstream network
  -> Frankfurt 68.183.74.207
```

Moscow and Singapore observe source `128.0.128.51` for the direct probes.
OpenWrt has only local/main/default policy rules, forwards LAN to WAN, and
masquerades WAN traffic. Its WAN capture contains Frankfurt SYN retransmissions,
UDP probes and ICMP echo requests. Thus these packets leave OpenWrt; the capture
does not establish whether they leave the Innbox's external interface.

## Results

| Source/path | Destination | Result |
| --- | --- | --- |
| Home, physical Ethernet | Frankfurt TCP/22, /443, /8445, /80 | All time out after 5 s |
| Home, physical Ethernet | Frankfurt UDP/58886 | Sent; not observed at VPS |
| Home, physical Ethernet | Frankfurt ICMP | Two echo requests, no replies; requests not observed at VPS |
| Home, physical Ethernet | Moscow TCP/22, /443, /8445 | Connected in approximately 5–6 ms |
| Home, physical Ethernet | Singapore TCP/22, /8445 | Connected in approximately 200 ms |
| Home, physical Ethernet | Moscow and Singapore UDP/58886 | Observed at both VPSs |
| Moscow, public ens3 route | Frankfurt TCP/22, /443, /8445 | All connect |
| Singapore, public eth0 route | Frankfurt TCP/22, /443, /8445 | All connect |

UDP probes contain a short diagnostic marker, not valid WireGuard handshakes.
They test arrival at the remote NIC, not UDP session establishment. Singapore
TCP/443 also times out, but it has no HTTPS listener and is not a Foldfin control.
Frankfurt TCP/80 is an additional arrival probe; no listener is required to see
an incoming SYN in tcpdump.

The final Frankfurt capture used `--immediate-mode` on `eth0`, without a home
source-IP restriction. It observed other traffic but none of the diagnostic
flows. This rules out the assumed source IP being the reason for missing probe
lines. Earlier captures without immediate mode reported nonzero kernel receive
counters with zero delivered packet lines; those counters alone are not evidence
that the diagnostic flows arrived.

Frankfurt has listeners on TCP/22, TCP/443 and Foldfin TCP/8445. INPUT rules
permit these ports and ICMP; its return route to the home public IP uses eth0.
No XDP attachment or ingress/egress tc filters were shown on eth0. The successful
public TCP probes from the other VPSs independently establish listener
availability. Cloud-provider firewall configuration was not verified through
the provider API.

UDP traceroute from OpenWrt receives a reply from Innbox at hop 1 and then only
timeouts through hop 10. The earlier TCP traceroute also stops receiving replies
beyond Innbox. Routers may suppress TTL-expired replies, so this does not locate
the packet drop at the next hop. Reverse ping from Frankfurt to the home public
IP also receives no replies and is inconclusive without knowing CPE ICMP policy.

## Interpretation and remaining checks

This failure precedes Foldfin authentication, HTTP/2 and TLS fingerprinting.
Ordinary SSH and HTTPS TCP handshakes fail along the same direct path. These
results do not support attributing the failure to recognition of Foldfin's
ClientHello. An IP-based filter, a routing fault, Innbox policy or a cloud-edge
filter remains possible; TSPU involvement has not been established.

To distinguish them, the useful next checks are:

1. Repeat direct Frankfurt probes from an independent connection, such as mobile
   data. No Android device was attached during this investigation.
2. Inspect the DigitalOcean firewall attached to this VPS. Local iptables
   acceptance does not establish cloud-edge acceptance.

The user provided the Logseq `my net` note. A subsequent read-only web login to
Innbox confirmed its current WAN address is `128.0.128.51`, with default route
via `128.0.128.1` on `nas1` and no destination-specific Frankfurt route in the
displayed IPv4 table. There is no evidence implicating the home router, and
further router investigation was stopped. The HTTP tunnel and temporary session
files were removed. SSH host-key checking was retained and `known_hosts` was
not modified.

No VPN, router or firewall configuration was changed. Transient tcpdump services
and the router capture were stopped after testing. The acceptance helper now
uses tcpdump immediate mode locally and remotely to avoid ambiguous buffered
capture shutdowns.

## Artifacts

Final simultaneous captures and structured probe results:

`captures/frankfurt-path-20261002-162517/`

- `summary.json`: bound/marked host socket results and ICMP output.
- `local-packets.txt`: physical Ethernet traffic.
- `router-wan-packets.txt`: traffic after OpenWrt NAT.
- `europe-packets.txt`: source-independent Frankfurt eth0 capture, handshake
  metadata only; also includes unrelated VPS traffic metadata.
- `moscow-packets.txt`, `singapore-packets.txt`: direct-source controls.
- `diagnostic.py`: the exact one-off diagnostic runner; hard-coded addresses and
  interfaces are a record of this experiment, not a general deployment tool.

The preceding narrow-source run is in
`captures/frankfurt-path-20261002-162400/`. Earlier physical namespace acceptance
is recorded separately in `docs/VALIDATION.md`. Capture directories are private
(`0700`); no Foldfin tokens or TLS payloads were captured by this diagnostic.
