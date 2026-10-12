# HTTP/3 patches

Sources: crates.io h3 0.0.8 and h3-datagram 0.0.2 (MIT licensed).

- h3: add RFC 9484 CONNECT_IP, matching upstream Protocol support.
- h3: omit :scheme/:path for classic CONNECT as required by RFC 9114 section 4.4;
  keep both for extended CONNECT. The release otherwise emits an invalid request.
  Covered by the Foldfin H3 proxy half-close/cancellation integration test.
- h3-datagram: retain the encoded quarter stream ID instead of replacing it
  with zeroes. Required for datagrams on every request after stream zero.

Keep these changes isolated. Remove patches once published releases contain them.
Embedding workspaces must apply these same Cargo patches at their workspace root;
Cargo ignores dependency-level patch tables.
