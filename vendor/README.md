# HTTP/3 patches

Sources: crates.io h3 0.0.8, h3-datagram 0.0.2 and h3-quinn 0.0.10 (MIT licensed).

- h3: add RFC 9484 CONNECT_IP, matching upstream Protocol support.
- h3: omit :scheme/:path for classic CONNECT as required by RFC 9114 section 4.4;
  keep both for extended CONNECT. The release otherwise emits an invalid request.
  Covered by the Foldfin H3 proxy half-close/cancellation integration test.
- h3-datagram: retain the encoded quarter stream ID instead of replacing it
  with zeroes. Required for datagrams on every request after stream zero.
- h3-quinn: retain receive-stream ownership while polling Quinn's cancel-safe
  `read_chunk` future. Upstream 0.0.10 moves it into a stored future, so cancelling
  an outstanding read panics in `stop_sending`; querying its stream ID also panics.
  Poll a temporary borrowed future instead, preserving zero-copy reads and immediate
  STOP_SENDING. The H3 proxy cancellation test polls an idle read before dropping it.
  Related upstream discussion: https://github.com/hyperium/h3/issues/361 (a deferred
  stop is insufficient when the peer never produces more data).

Keep these changes isolated. Remove patches once published releases contain them.
Embedding workspaces must apply these same Cargo patches at their workspace root;
Cargo ignores dependency-level patch tables.
