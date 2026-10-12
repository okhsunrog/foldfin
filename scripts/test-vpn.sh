#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
cd "$FOLDFIN_ROOT"
if [[ $# -gt 1 ]]; then
    printf '%s\n' 'Usage: scripts/test-vpn.sh [--chrome-tls]' >&2
    exit 2
fi
profile=rustls
case "${1:-}" in
    '') ;;
    --chrome-tls) profile=chrome ;;
    --help|-h) printf '%s\n' 'Usage: scripts/test-vpn.sh [--chrome-tls]' 'Singapore routed IPv4 acceptance through the physical NIC only.'; exit 0 ;;
    *) printf '%s\n' 'Usage: scripts/test-vpn.sh [--chrome-tls]' >&2; exit 2 ;;
esac
cargo build --locked --release --features chrome-tls --bin foldfin
uv run --no-project tests/vpn_physical.py --accept-only --profiles "$profile" \
    --output "captures/vpn-physical-$(date +%Y%m%d-%H%M%S)"
