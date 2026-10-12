#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
    printf '%s\n' 'Usage: scripts/deploy-test.sh [--setup] [--no-build]' \
        'Deploy Singapore, then run acceptance; stop immediately on failure.'
    exit 0
fi
"$script_dir/deploy.sh" "$@"
"$script_dir/test.sh"
