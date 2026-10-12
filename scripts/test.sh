#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

chrome_tls=false
if [[ $# -gt 0 ]]; then
    if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
        printf '%s\n' 'Usage: scripts/test.sh [--chrome-tls]' \
            'Build the current client and test only the deployed Singapore endpoint.'
        exit 0
    fi
    if [[ $# -eq 1 && $1 == --chrome-tls ]]; then
        chrome_tls=true
    else
        printf '%s\n' 'Usage: scripts/test.sh [--chrome-tls]' >&2
        exit 2
    fi
fi
cd "$FOLDFIN_ROOT"
if "$chrome_tls"; then
    # BoringSSL/C++ stays local; the server and deployed musl artifact are unchanged.
    cargo build --locked --release --features chrome-tls --bin client
    binary_dir=$(cargo metadata --locked --no-deps --format-version 1 |
        uv run python -c 'import json,pathlib,sys; print(pathlib.Path(json.load(sys.stdin)["target_directory"]) / "release")')
    uv run --no-project tests/physical_vps.py --configs "$FOLDFIN_INFRA_DIR/generated_configs/foldfin" --hosts singapore --client "$binary_dir/client" --profiles chrome
else
    cargo build --locked --release --target "$FOLDFIN_TARGET" --bin client
    binary_dir=$(foldfin_binary_dir)
    uv run --no-project tests/physical_vps.py --configs "$FOLDFIN_INFRA_DIR/generated_configs/foldfin" --hosts singapore --client "$binary_dir/client" --profiles rustls
fi
