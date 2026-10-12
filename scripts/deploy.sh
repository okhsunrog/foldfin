#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"

playbook=site-foldfin-update.yml
build=true
for argument in "$@"; do
    case "$argument" in
        --setup) playbook=site-foldfin.yml ;;
        --no-build) build=false ;;
        --help|-h)
            printf '%s\n' 'Usage: scripts/deploy.sh [--setup] [--no-build]' \
                'Default: incremental static build, update only Singapore Foldfin.' \
                '--setup: apply the Foldfin deployment role on Singapore (config, TLS, firewall).' \
                '--no-build: explicitly reuse existing release binaries.'
            exit 0 ;;
        *) printf 'Unknown argument: %s\n' "$argument" >&2; exit 2 ;;
    esac
done

cd "$FOLDFIN_ROOT"
if "$build"; then
    cargo build --locked --release --target "$FOLDFIN_TARGET" --bins
fi
binary_dir=$(foldfin_binary_dir)
test -x "$binary_dir/server" || { printf 'Missing server binary: %s\n' "$binary_dir/server" >&2; exit 1; }
extra_vars=$(uv run python -c 'import json, sys; print(json.dumps({"foldfin_binary": sys.argv[1]}))' "$binary_dir/server")
cd "$FOLDFIN_INFRA_DIR"
ansible-playbook "$playbook" --limit singapore --extra-vars "$extra_vars"
