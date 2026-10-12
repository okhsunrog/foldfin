#!/usr/bin/env python3
"""Local end-to-end regression: TLS, SOCKS, multiplexing, flow control, FIN, auth."""
import concurrent.futures, os, pathlib, secrets, socket, subprocess, tempfile, threading, time

ROOT = pathlib.Path(__file__).resolve().parents[1]

def free_port():
    with socket.socket() as s:
        s.bind(('127.0.0.1', 0))
        return s.getsockname()[1]

def exact(s, n):
    data = b''
    while len(data) < n:
        chunk = s.recv(n - len(data))
        if not chunk: raise AssertionError('premature EOF')
        data += chunk
    return data

def wait_port(port, process, seconds=5):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if process.poll() is not None: raise RuntimeError('process exited')
        try:
            with socket.create_connection(('127.0.0.1', port), .1): return
        except OSError: time.sleep(.05)
    raise TimeoutError('listener unavailable')

def connect(port, dest):
    s = socket.create_connection(('127.0.0.1', port), 10)
    s.settimeout(20)
    s.sendall(b'\x05\x01\x00')
    assert exact(s, 2) == b'\x05\x00'
    s.sendall(b'\x05\x01\x00\x01\x7f\x00\x00\x01' + dest.to_bytes(2, 'big'))
    return s, exact(s, 10)[1]

def main():
    import argparse
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--legacy-binaries', action='store_true', help='Test compatibility client/server launchers')
    args = parser.parse_args()
    args_namespace = args
    build = ['cargo', 'build', '--bins']
    subprocess.run(build, cwd=ROOT, check=True)
    import json
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    binaries = pathlib.Path(metadata['target_directory']) / 'debug'
    processes = []
    echo = socket.socket(); echo.bind(('127.0.0.1', 0)); echo.listen()
    def handle(s):
        with s:
            # Wait for FIN before sending response: verifies independent half-close.
            data = bytearray()
            while chunk := s.recv(65536): data.extend(chunk)
            s.sendall(data)
    def accept():
        while True:
            try: s, _ = echo.accept()
            except OSError: return
            threading.Thread(target=handle, args=(s,), daemon=True).start()
    threading.Thread(target=accept, daemon=True).start()
    try:
        with tempfile.TemporaryDirectory() as tmp:
            tmp = pathlib.Path(tmp); key, cert = tmp/'key.pem', tmp/'cert.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                            '-addext', 'subjectAltName=DNS:localhost',
                            '-addext', 'basicConstraints=critical,CA:FALSE',
                            '-addext', 'extendedKeyUsage=serverAuth'], check=True, capture_output=True)
            server_port, socks_port, bad_port = free_port(), free_port(), free_port()
            env = dict(os.environ, FOLDFIN_TOKEN=secrets.token_hex(32))
            def launch(binary, args, environment=env):
                command = [str(binaries/binary)] if args_namespace.legacy_binaries else [str(binaries/"foldfin"), binary]
                p = subprocess.Popen([*command, *args], env=environment)
                processes.append(p); return p
            server = launch('server', ['--listen', f'127.0.0.1:{server_port}', '--cert', str(cert), '--key', str(key), '--allow-private'])
            wait_port(server_port, server)
            client_args = ['--server', f'127.0.0.1:{server_port}', '--server-name', 'localhost', '--ca', str(cert)]
            client = launch('client', client_args + ['--listen', f'127.0.0.1:{socks_port}'])
            wait_port(socks_port, client)
            def transfer(_):
                payload = secrets.token_bytes(512 * 1024)
                s, status = connect(socks_port, echo.getsockname()[1])
                with s:
                    assert status == 0
                    s.sendall(payload); s.shutdown(socket.SHUT_WR)
                    assert exact(s, len(payload)) == payload
                    assert s.recv(1) == b''
            with concurrent.futures.ThreadPoolExecutor(max_workers=8) as pool:
                list(pool.map(transfer, range(8)))
            bad = launch('client', client_args + ['--listen', f'127.0.0.1:{bad_port}'], dict(env, FOLDFIN_TOKEN=secrets.token_hex(32)))
            wait_port(bad_port, bad)
            s, status = connect(bad_port, echo.getsockname()[1])
            s.close(); assert status != 0
            for args in [
                ['--server', f'127.0.0.1:{server_port}', '--server-name', 'localhost'],
                ['--server', f'127.0.0.1:{server_port}', '--server-name', 'wrong.invalid', '--ca', str(cert)],
            ]:
                invalid = launch('client', args + ['--listen', f'127.0.0.1:{free_port()}'])
                assert invalid.wait(timeout=20) != 0, 'invalid TLS peer accepted'
            private_port, denied_port = free_port(), free_port()
            restricted = launch('server', ['--listen', f'127.0.0.1:{private_port}', '--cert', str(cert), '--key', str(key)])
            wait_port(private_port, restricted)
            restricted_client = launch('client', ['--server', f'127.0.0.1:{private_port}', '--server-name', 'localhost', '--ca', str(cert), '--listen', f'127.0.0.1:{denied_port}'])
            wait_port(denied_port, restricted_client)
            s, status = connect(denied_port, echo.getsockname()[1])
            s.close(); assert status != 0, 'private destination accepted'
            with socket.socket() as idle:
                idle.bind(('127.0.0.1', 0)); idle.listen(); idle.settimeout(5)
                s, status = connect(socks_port, idle.getsockname()[1])
                with s:
                    assert status == 0
                    upstream, _ = idle.accept()
                    with upstream:
                        upstream.settimeout(5)
                        client.kill(); client.wait(timeout=5)
                        assert upstream.recv(1) == b'', 'upstream leaked after carrier loss'
            print('PASS: 8 concurrent 512KiB flows, half-close, wrong token, untrusted certificate, wrong TLS name, private destination rejection, upstream cleanup on carrier loss')
    finally:
        echo.close()
        for p in processes: p.terminate()
        for p in processes:
            try: p.wait(timeout=5)
            except subprocess.TimeoutExpired: p.kill(); p.wait()

if __name__ == '__main__': main()
