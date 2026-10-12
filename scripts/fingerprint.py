#!/usr/bin/env python3
"""Capture fresh Chrome and Foldfin ClientHellos on loopback; no TLS payload/auth."""
import argparse
import json
import os
import pathlib
import socket
import struct
import subprocess
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]


def grease(value):
    return value & 0x0f0f == 0x0a0a and value >> 8 == value & 255


def identifiers(values):
    return ['GREASE' if grease(value) else value for value in values]


def words(data):
    return list(struct.unpack(f'!{len(data) // 2}H', data))


def hello(records):
    payload = b''
    offset = 0
    record_lengths = []
    record_versions = []
    while offset < len(records):
        kind, version, size = struct.unpack('!BHH', records[offset:offset + 5])
        assert kind == 22
        record_lengths.append(size)
        record_versions.append(version)
        payload += records[offset + 5:offset + 5 + size]
        offset += 5 + size
    assert payload[0] == 1
    data = payload[4:4 + int.from_bytes(payload[1:4], 'big')]
    legacy_version = int.from_bytes(data[:2], 'big')
    position = 34
    session_size = data[position]; position += 1 + session_size
    size = int.from_bytes(data[position:position + 2], 'big'); position += 2
    ciphers = words(data[position:position + size]); position += size
    size = data[position]; position += 1
    compression = list(data[position:position + size]); position += size
    size = int.from_bytes(data[position:position + 2], 'big'); position += 2
    end = position + size
    extensions = []
    grease_extensions = []
    details = {}
    while position < end:
        kind, size = struct.unpack('!HH', data[position:position + 4]); position += 4
        value = data[position:position + size]; position += size
        extensions.append(kind)
        if grease(kind):
            grease_extensions.append({'position': len(extensions) - 1, 'length': size, 'data': value.hex()})
        if kind in [10, 13, 50]:
            details[str(kind)] = identifiers(words(value[2:]))
        elif kind == 43:
            details[str(kind)] = identifiers(words(value[1:]))
        elif kind == 16:
            protocols = []
            cursor = 2
            while cursor < len(value):
                length = value[cursor]; cursor += 1
                protocols.append(value[cursor:cursor + length].decode()); cursor += length
            details[str(kind)] = protocols
        elif kind == 51:
            shares = []
            cursor = 2
            while cursor < len(value):
                group, length = struct.unpack('!HH', value[cursor:cursor + 4]); cursor += 4
                shares.append({'group': identifiers([group])[0], 'key_length': length})
                cursor += length
            details[str(kind)] = shares
        elif kind == 0:
            details[str(kind)] = value[5:].decode()
        elif kind == 27:
            details[str(kind)] = words(value[1:])
        elif kind == 65037:
            enc_length = int.from_bytes(value[6:8], 'big')
            cursor = 8 + enc_length
            details[str(kind)] = {'type': value[0], 'kdf': int.from_bytes(value[1:3], 'big'),
                                  'aead': int.from_bytes(value[3:5], 'big'), 'enc_length': enc_length,
                                  'payload_length': int.from_bytes(value[cursor:cursor + 2], 'big')}
        elif kind not in [21, 35, 65037] and not grease(kind):
            details[str(kind)] = value.hex()
    return {'record_lengths': record_lengths, 'record_versions': record_versions, 'legacy_version': legacy_version,
            'session_id_length': session_size, 'cipher_suites': identifiers(ciphers),
            'compression': compression, 'extension_order': identifiers(extensions),
            'extension_set': sorted(kind for kind in extensions if not grease(kind)), 'grease_extensions': grease_extensions,
            'details': details}


def exact(stream, size):
    output = b''
    while len(output) < size:
        chunk = stream.recv(size - len(output))
        if not chunk:
            raise EOFError('incomplete ClientHello')
        output += chunk
    return output


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome', default='/opt/google/chrome/google-chrome')
    parser.add_argument('--samples', type=int, default=3)
    parser.add_argument('--output', type=pathlib.Path, default=ROOT / 'captures/baseline')
    parser.add_argument('--chrome-tls', action='store_true', help='capture the experimental Foldfin backend')
    args = parser.parse_args()
    if args.samples < 1:
        parser.error('--samples must be positive')
    if (args.output / 'report.json').exists():
        parser.error('output already contains a capture; choose a new --output directory')
    args.output.mkdir(parents=True, exist_ok=True)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    binary = pathlib.Path(metadata['target_directory']) / 'debug/client'
    build = ['cargo', 'build', '--bin', 'client']
    if args.chrome_tls:
        build += ['--features', 'chrome-tls']
    subprocess.run(build, cwd=ROOT, check=True)
    listener = socket.socket(); listener.bind(('127.0.0.1', 0)); listener.listen(); listener.settimeout(.2)
    port = listener.getsockname()[1]
    samples = []
    phase = 'startup'
    stop = threading.Event()
    def collect():
        while not stop.is_set():
            try:
                stream, _ = listener.accept()
            except socket.timeout:
                continue
            with stream:
                stream.settimeout(3)
                try:
                    records, handshake = b'', b''
                    while len(handshake) < 4 or len(handshake) < 4 + int.from_bytes(handshake[1:4], 'big'):
                        header = exact(stream, 5)
                        assert header[0] == 22
                        body = exact(stream, int.from_bytes(header[3:5], 'big'))
                        records += header + body; handshake += body
                    name = f'{phase}-{len(samples):02}'
                    (args.output / f'{name}.bin').write_bytes(records)
                    samples.append({'source': phase, 'file': f'{name}.bin', **hello(records)})
                except (EOFError, OSError, AssertionError):
                    pass
    thread = threading.Thread(target=collect); thread.start()
    capture = subprocess.Popen(['dumpcap', '-q', '-i', 'lo', '-f', f'tcp port {port}', '-w', str(args.output / 'clienthello.pcapng')],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        time.sleep(.5)
        if capture.poll() is not None:
            raise RuntimeError(capture.communicate()[1].decode())
        for source in ['chrome', 'foldfin']:
            phase = source
            for _ in range(args.samples):
                count = len(samples)
                with tempfile.TemporaryDirectory(prefix='foldfin-chrome-') as profile:
                    if source == 'chrome':
                        command = [args.chrome, '--headless', '--disable-background-networking', '--disable-component-update',
                                   '--no-first-run', '--no-default-browser-check', '--no-proxy-server', '--disable-quic',
                                   f'--user-data-dir={profile}', '--dump-dom', f'https://localhost:{port}/']
                    else:
                        command = [str(binary), '--server', f'127.0.0.1:{port}', '--server-name', 'localhost']
                        if args.chrome_tls:
                            command.append('--chrome-tls')
                    process = subprocess.Popen(command, env=dict(os.environ, FOLDFIN_TOKEN='0' * 64),
                                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    try:
                        process.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        process.terminate()
                        try:
                            process.wait(timeout=3)
                        except subprocess.TimeoutExpired:
                            process.kill(); process.wait()
                assert len(samples) > count, f'no ClientHello captured for {source}'
        version = subprocess.check_output([args.chrome, '--version']).decode().strip()
        report = {'chrome_version': version, 'foldfin_backend': 'chrome-tls' if args.chrome_tls else 'rustls',
                  'endpoint': f'localhost:{port}', 'samples': samples}
        (args.output / 'report.json').write_text(json.dumps(report, indent=2) + '\n')
        print(f'{version}; captured {len(samples)} ClientHellos in {args.output}')
        for source in ['chrome', 'foldfin']:
            sample = next(value for value in samples if value['source'] == source)
            print(source, json.dumps(sample))
    finally:
        stop.set(); thread.join(timeout=4); listener.close()
        capture.terminate()
        try:
            capture.wait(timeout=3)
        except subprocess.TimeoutExpired:
            capture.kill(); capture.wait()
        capture.stderr.close()


if __name__ == '__main__':
    main()
