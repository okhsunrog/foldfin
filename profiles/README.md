# Chrome 154 Linux profile provenance

`chrome-154-trust-anchors.bin` is the public, 8-bit length-prefixed trust-anchor
identifier vector from a fresh local ClientHello of Google Chrome
154.0.8037.92, captured on 2026-10-01. It contains no certificates, keys or
tokens. `captures/baseline/report.json` and the accompanying pcap record the
original extension 51764, including its outer 16-bit vector length.

This advertisement is a version-specific snapshot. BoringSSL still verifies
the actual certificate chain against its default system roots and any explicit
`--ca` file, and verifies the requested TLS hostname. Sending these IDs does not
turn the system root store into the Chrome Root Store and does not implement
Chrome's trust-anchor retry flow. Refresh the profile when Chrome changes.

Bindings are pinned to `0x676e67/btls` revision
`0f5416d1f61eb4f64a9f2f4d8b867495305d61c1`, whose BoringSSL includes TLS
ML-DSA signature verification and GREASE signature algorithms. The published
0.5.6 crate lacked these TLS APIs, leaving extension 13 different from Chrome.
No peer verification relaxation feature is enabled.
