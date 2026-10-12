#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
cd "$FOLDFIN_ROOT"
if [[ $# -gt 0 ]]; then
    printf '%s\n' 'Usage: scripts/test-vpn.sh' 'Singapore routed IPv4 acceptance through the physical NIC only.'
    [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]] && exit 0
    exit 2
fi
cargo build --locked --release --bin foldfin
uv run --no-project tests/vpn_physical.py --accept-only --profiles rustls \
    --output "captures/vpn-physical-$(date +%Y%m%d-%H%M%S)"
