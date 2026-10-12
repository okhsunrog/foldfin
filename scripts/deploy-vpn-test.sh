#!/usr/bin/env bash
set -euo pipefail
script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
if [[ $# -eq 1 && ( $1 == --help || $1 == -h ) ]]; then
    printf '%s\n' 'Usage: scripts/deploy-vpn-test.sh' 'Configure Singapore, deploy, then physical proxy and routed VPN acceptance.'
    exit 0
fi
if [[ $# -ne 0 ]]; then
    printf '%s\n' 'Usage: scripts/deploy-vpn-test.sh' >&2
    exit 2
fi
"$script_dir/deploy.sh" --setup
"$script_dir/test-physical.sh"
"$script_dir/test-vpn.sh" "$@"
