#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
cd "$FOLDFIN_ROOT"
cargo build --locked --release --features chrome-tls --bin client
uv run --no-project tests/physical_vps.py --configs "$FOLDFIN_INFRA_DIR/generated_configs/foldfin" "$@"
