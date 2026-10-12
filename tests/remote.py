#!/usr/bin/env python3
"""Temporary TLS/H2 experiment on an SSH-accessible Linux VPS.

Uses a transient systemd unit with a two-minute lifetime; cleans up on exit.
No firewall changes. Requires an unused, reachable TCP port (default 8443).
"""
import argparse
import json
import os
import pathlib
import secrets
import subprocess
import tempfile

from smoke import free_port, wait_port

ROOT = pathlib.Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--ssh', required=True)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=8443)
    args = parser.parse_args()
    if not 1 <= args.port <= 65535:
        parser.error('invalid TCP port')
    ssh = ['ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', args.ssh]
    run_id = secrets.token_hex(6)
    remote = f'/tmp/foldfin-{run_id}'
    unit = f'foldfin-test-{run_id}'
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    binary_dir = pathlib.Path(metadata['target_directory']) / 'x86_64-unknown-linux-musl' / 'release'
    client = None
    try:
        with tempfile.TemporaryDirectory() as directory:
            directory = pathlib.Path(directory)
            token = secrets.token_hex(32)
            env_file = directory / 'token.env'
            env_file.write_text(f'FOLDFIN_TOKEN={token}\n')
            env_file.chmod(0o600)
            cert, key = directory / 'cert.pem', directory / 'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-subj', f'/CN={args.host}',
                            '-addext', f'subjectAltName=DNS:{args.host}',
                            '-addext', 'basicConstraints=critical,CA:FALSE',
                            '-addext', 'extendedKeyUsage=serverAuth'], check=True, capture_output=True)
            subprocess.run(ssh + [f'mkdir -m 700 {remote}'], check=True, timeout=20)
            subprocess.run(['scp', '-q', '-o', 'BatchMode=yes', str(binary_dir / 'server'), str(cert), str(key), str(env_file),
                            f'{args.ssh}:{remote}/'], check=True, timeout=60)
            subprocess.run(ssh + [f'systemd-run --quiet --collect --unit={unit} --property=RuntimeMaxSec=120 '
                                    f'--property=EnvironmentFile={remote}/token.env '
                                    f'{remote}/server --listen 0.0.0.0:{args.port} --cert {remote}/cert.pem --key {remote}/key.pem'],
                           check=True, timeout=20)
            socks = free_port()
            client = subprocess.Popen([str(binary_dir / 'client'), '--server', f'{args.host}:{args.port}',
                                       '--server-name', args.host, '--ca', str(cert), '--listen', f'127.0.0.1:{socks}'],
                                      env=dict(os.environ, FOLDFIN_TOKEN=token))
            wait_port(socks, client, seconds=35)
            curl = ['curl', '--fail', '--silent', '--show-error', '--max-time', '30', '--socks5-hostname', f'127.0.0.1:{socks}']
            page = subprocess.check_output(curl + ['https://example.com/'], timeout=35)
            assert b'Example Domain' in page
            address = subprocess.check_output(curl + ['https://api.ipify.org/'], timeout=35).decode().strip()
            print(f'PASS: TLS/H2 endpoint to {args.host}:{args.port}, HTTPS through SOCKS, server DNS; egress {address}')
    finally:
        if client is not None:
            client.terminate()
            try:
                client.wait(timeout=5)
            except subprocess.TimeoutExpired:
                client.kill(); client.wait()
        subprocess.run(ssh + [f'systemctl stop {unit}.service; rm -rf {remote}'], check=True, timeout=20)


if __name__ == '__main__':
    main()
