#!/usr/bin/env bash
# Sourced by the entrypoints; paths do not depend on the caller's directory.
FOLDFIN_ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
FOLDFIN_INFRA_DIR=${FOLDFIN_INFRA_DIR:-"$FOLDFIN_ROOT/../../cloud-forge"}
FOLDFIN_TARGET=x86_64-unknown-linux-musl

foldfin_binary_dir() {
    cargo metadata --locked --no-deps --format-version 1 |
        uv run python -c 'import json, pathlib, sys; print(pathlib.Path(json.load(sys.stdin)["target_directory"]) / sys.argv[1] / "release")' "$FOLDFIN_TARGET"
}
