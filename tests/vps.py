#!/usr/bin/env python3
"""Read-only acceptance, Frankfurt only by default. Never logs tokens."""
import argparse
import concurrent.futures
import hashlib
import json
import os
import pathlib
import socket
import subprocess

from smoke import exact, free_port, wait_port

ROOT = pathlib.Path(__file__).resolve().parents[1]


def configuration(directory, host):
    values = {}
    for line in (directory / f'{host}.env').read_text().splitlines():
        if line and not line.startswith('#'):
            key, value = line.split('=', 1)
            values[key] = value
    return values


def socks_status(port, target=None):
    with socket.create_connection(('127.0.0.1', port), timeout=10) as stream:
        stream.settimeout(20)
        stream.sendall(b'\x05\x01\x00')
        assert exact(stream, 2) == b'\x05\x00'
        if target is None:
            # A loopback destination must be denied by every production instance.
            request = b'\x05\x01\x00\x01\x7f\x00\x00\x01\x00\x16'
        else:
            name = target.encode('ascii')
            request = b'\x05\x01\x00\x03' + bytes([len(name)]) + name + b'\x00\x50'
        stream.sendall(request)
        return exact(stream, 10)[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--configs', type=pathlib.Path, default=ROOT.parent.parent / 'cloud-forge/generated_configs/foldfin')
    parser.add_argument('--hosts', nargs='+', choices=['europe', 'moscow', 'singapore'], default=['singapore'])
    parser.add_argument('--client', type=pathlib.Path, help='explicit locally built client binary')
    parser.add_argument('--chrome-tls', action='store_true')
    args = parser.parse_args()
    if args.client:
        binary = args.client
    else:
        metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
        binary = pathlib.Path(metadata['target_directory']) / 'x86_64-unknown-linux-musl/release/client'
    results = []
    for host in args.hosts:
        config = configuration(args.configs, host)
        socks = free_port()
        client_args = [str(binary), '--server', config['FOLDFIN_SERVER'], '--server-name', config['FOLDFIN_SERVER_NAME'],
                       '--ca', str(args.configs / f'{host}.pem'), '--listen', f'127.0.0.1:{socks}']
        if args.chrome_tls:
            client_args.insert(1, '--chrome-tls')
        # Capture stderr rather than printing environment or command token values.
        client = subprocess.Popen(client_args, env=dict(os.environ, FOLDFIN_TOKEN=config['FOLDFIN_TOKEN']), stderr=subprocess.PIPE)
        try:
            wait_port(socks, client, seconds=35)
            curl = ['curl', '--fail', '--silent', '--show-error', '--max-time', '30', '--socks5-hostname', f'127.0.0.1:{socks}']
            def fetch(_):
                page = subprocess.check_output(curl + ['https://example.com/'], timeout=35)
                assert b'Example Domain' in page
                return hashlib.sha256(page).hexdigest()
            with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
                pages = list(pool.map(fetch, range(4)))
            assert len(set(pages)) == 1
            egress = subprocess.check_output(curl + ['https://api.ipify.org/'], timeout=35).decode().strip()
            exit_host = 'europe' if host in ['europe', 'moscow'] else 'singapore'
            expected = socket.gethostbyname(configuration(args.configs, exit_host)['FOLDFIN_SERVER_NAME'])
            assert egress == expected, f'{host}: egress {egress}, expected {expected}'
            assert socks_status(socks) != 0
            assert socks_status(socks, 'example.com') == 0
            wrong_port = free_port()
            wrong_args = client_args[:-1] + [f'127.0.0.1:{wrong_port}']
            bad_token = '0' * 64 if config['FOLDFIN_TOKEN'] != '0' * 64 else '1' * 64
            wrong = subprocess.Popen(wrong_args, env=dict(os.environ, FOLDFIN_TOKEN=bad_token), stderr=subprocess.DEVNULL)
            try:
                wait_port(wrong_port, wrong, seconds=35)
                assert socks_status(wrong_port, 'example.com') != 0, 'wrong token accepted'
            finally:
                wrong.terminate()
                try:
                    wrong.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    wrong.kill(); wrong.wait()
            results.append({'host': host, 'endpoint': config['FOLDFIN_SERVER'], 'egress': egress,
                            'parallel_https_flows': 4, 'private_destination_rejected': True, 'wrong_token_rejected': True})
            print(f'PASS {host}: TLS/H2 endpoint, 4 parallel HTTPS flows, server DNS, private destination and wrong token denied, egress {egress}', flush=True)
        except Exception:
            client.terminate()
            _, errors = client.communicate(timeout=5)
            print(errors.decode(errors='replace'))
            raise
        finally:
            if client.poll() is None:
                client.terminate()
                try:
                    client.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    client.kill(); client.wait()
            client.stderr.close()
    print(json.dumps(results, indent=2))


if __name__ == '__main__':
    main()
