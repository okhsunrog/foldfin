#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
if [[ $# -gt 0 ]]; then
    printf '%s\n' 'Usage: scripts/test.sh' 'Build and test only Singapore through the physical interface.'
    [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]] && exit 0
    exit 2
fi
cd "$FOLDFIN_ROOT"
cargo build --locked --release --target "$FOLDFIN_TARGET" --bin client
binary_dir=$(foldfin_binary_dir)
uv run --no-project tests/physical_vps.py --configs "$FOLDFIN_INFRA_DIR/generated_configs/foldfin" --hosts singapore --client "$binary_dir/client" --profiles rustls
