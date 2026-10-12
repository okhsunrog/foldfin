#!/usr/bin/env python3
"""Compare Chrome and Foldfin HTTP/2 client traffic against a local TLS peer."""
import argparse
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parents[1]
PREFACE = b'PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n'
SETTINGS_NAMES = {
    1: 'header_table_size', 2: 'enable_push', 3: 'max_concurrent_streams',
    4: 'initial_window_size', 5: 'max_frame_size', 6: 'max_header_list_size',
    8: 'enable_connect_protocol', 9: 'no_rfc7540_priorities',
}


def exact(stream, size):
    data = bytearray()
    while len(data) < size:
        chunk = stream.recv(size - len(data))
        if not chunk:
            raise EOFError('peer closed')
        data.extend(chunk)
    return bytes(data)


def frame(kind, flags, stream_id, payload=b''):
    header = len(payload).to_bytes(3, 'big') + bytes([kind, flags]) + (stream_id & 0x7fffffff).to_bytes(4, 'big')
    return header + payload


def frame_details(raw):
    kind, flags, stream_id = raw[3], raw[4], int.from_bytes(raw[5:9], 'big') & 0x7fffffff
    payload = raw[9:]
    info = {'type': kind, 'flags': flags, 'stream_id': stream_id, 'length': len(payload)}
    if kind == 4 and not flags & 1:
        info['settings'] = [
            {'id': int.from_bytes(payload[i:i + 2], 'big'),
             'name': SETTINGS_NAMES.get(int.from_bytes(payload[i:i + 2], 'big'), 'unknown'),
             'value': int.from_bytes(payload[i + 2:i + 6], 'big')}
            for i in range(0, len(payload), 6)
        ]
    elif kind == 8 and len(payload) == 4:
        info['window_increment'] = int.from_bytes(payload, 'big') & 0x7fffffff
    elif kind == 2 and len(payload) == 5:
        info['priority'] = {'dependency': int.from_bytes(payload[:4], 'big') & 0x7fffffff,
                            'exclusive': bool(payload[0] & 0x80), 'weight': payload[4] + 1}
    elif kind == 1 and flags & 0x20:
        cursor = 1 if flags & 0x08 else 0
        dependency = int.from_bytes(payload[cursor:cursor + 4], 'big')
        info['priority'] = {'dependency': dependency & 0x7fffffff,
                            'exclusive': bool(dependency & 0x80000000),
                            'weight': payload[cursor + 4] + 1}
    return info


class CapturePeer:
    def __init__(self, mode, cert, key, keylog):
        self.mode = mode
        self.listener = socket.socket()
        self.listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.listener.bind(('127.0.0.1', 0))
        self.listener.listen()
        self.listener.settimeout(.2)
        self.port = self.listener.getsockname()[1]
        self.stop = threading.Event()
        self.request_seen = threading.Event()
        self.connections = []
        self.lock = threading.Lock()
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain(certfile=cert, keyfile=key)
        context.set_alpn_protocols(['h2'])
        context.keylog_filename = str(keylog)
        self.context = context
        self.thread = threading.Thread(target=self.accept, daemon=True)

    def start(self):
        self.thread.start()

    def accept(self):
        while not self.stop.is_set():
            try:
                conn, _ = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                return
            threading.Thread(target=self.handle, args=(conn,), daemon=True).start()

    def handle(self, raw_conn):
        details = {'frames': [], 'preface': False, 'alpn': None}
        with self.lock:
            self.connections.append(details)
        try:
            with self.context.wrap_socket(raw_conn, server_side=True) as conn:
                conn.settimeout(5)
                details['alpn'] = conn.selected_alpn_protocol()
                if details['alpn'] != 'h2' or exact(conn, len(PREFACE)) != PREFACE:
                    return
                details['preface'] = True
                conn.sendall(frame(4, 0, 0))
                while not self.stop.is_set():
                    head = exact(conn, 9)
                    size = int.from_bytes(head[:3], 'big')
                    raw = head + exact(conn, size)
                    item = frame_details(raw)
                    details['frames'].append(item)
                    kind, flags, stream_id = item['type'], item['flags'], item['stream_id']
                    if kind == 4 and not flags & 1:
                        conn.sendall(frame(4, 1, 0))
                    elif kind == 1:
                        self.request_seen.set()
                        # Empty successful response. Leave CONNECT open for the
                        # SOCKS client; finish ordinary browser GET streams.
                        response_flags = 4 if self.mode == 'foldfin' else 5
                        conn.sendall(frame(1, response_flags, stream_id, b'\x88'))
        except (EOFError, OSError, ssl.SSLError, TimeoutError):
            pass

    def close(self):
        self.stop.set()
        self.listener.close()
        self.thread.join(timeout=2)


def free_port():
    with socket.socket() as sock:
        sock.bind(('127.0.0.1', 0))
        return sock.getsockname()[1]


def start_capture(port, pcap):
    process = subprocess.Popen(['dumpcap', '-q', '-i', 'lo', '-f', f'tcp port {port}', '-w', str(pcap)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    time.sleep(.3)
    if process.poll() is not None:
        raise RuntimeError(process.communicate()[1].decode())
    return process


def request_socks(port):
    with socket.create_connection(('127.0.0.1', port), timeout=5) as sock:
        sock.settimeout(8)
        sock.sendall(b'\x05\x01\x00')
        if exact(sock, 2) != b'\x05\x00':
            raise RuntimeError('SOCKS no-auth negotiation failed')
        host = b'example.com'
        sock.sendall(b'\x05\x01\x00\x03' + bytes([len(host)]) + host + b'\x01\xbb')
        response = exact(sock, 10)
        if response[1] != 0:
            raise RuntimeError(f'local H2 peer rejected CONNECT: {response[1]}')


def decoded_frames(pcap, keylog, port):
    fields = [
        'frame.number', 'http2.type', 'http2.streamid', 'http2.settings.id',
        'http2.settings.header_table_size', 'http2.settings.enable_push',
        'http2.settings.max_concurrent_streams', 'http2.settings.initial_window_size',
        'http2.settings.max_frame_size', 'http2.settings.max_header_list_size',
        'http2.settings.extended_connect', 'http2.settings.no_rfc7540_priorities',
        'http2.headers.method', 'http2.headers.scheme', 'http2.headers.authority',
        'http2.headers.path', 'http2.headers.user_agent', 'http2.headers.accept',
        'http2.headers.accept_encoding', 'http2.headers.accept_language',
        'http2.headers.cache_control', 'http2.headers.authorization',
        'http2.headers.cookie', 'http2.headers.proxy_authorization',
    ]
    command = ['tshark', '-r', str(pcap), '-o', f'tls.keylog_file:{keylog}',
               '-Y', 'http2', '-T', 'fields',
               '-E', 'separator=\t', '-E', 'occurrence=a', '-E', 'aggregator=|']
    for field in fields:
        command += ['-e', field]
    output = subprocess.check_output(command, stderr=subprocess.DEVNULL, text=True)
    rows = []
    for line in output.splitlines():
        columns = line.split('\t')
        columns.extend([''] * (len(fields) - len(columns)))
        row = dict(zip(fields, columns))
        for field in ['http2.headers.authorization', 'http2.headers.cookie',
                      'http2.headers.proxy_authorization']:
            if row[field]:
                row[field] = '[redacted]'
        rows.append(row)
    return rows


def one_capture(mode, out, cert, key, client_binary=None):
    keylog = out / f'{mode}.keylog'
    keylog.touch(mode=0o600, exist_ok=False)
    pcap = out / f'{mode}.pcapng'
    peer = CapturePeer(mode, cert, key, keylog)
    port = peer.port
    capture = None
    child = None
    successful = False
    try:
        capture = start_capture(port, pcap)
        peer.start()
        if mode == 'chrome':
            profile = tempfile.TemporaryDirectory(prefix='foldfin-h2-chrome-')
            command = [
                '/opt/google/chrome/google-chrome', '--headless', '--disable-background-networking',
                '--disable-component-update', '--no-first-run', '--no-default-browser-check',
                '--no-proxy-server', '--disable-quic', '--ignore-certificate-errors',
                '--host-resolver-rules=MAP localhost 127.0.0.1', f'--user-data-dir={profile.name}',
                '--dump-dom', f'https://localhost:{port}/',
            ]
            child = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            try:
                child.wait(timeout=20)
            except subprocess.TimeoutExpired:
                raise RuntimeError('Chrome did not finish local HTTP/2 request')
            finally:
                profile.cleanup()
        else:
            child = subprocess.Popen([str(client_binary), '--chrome-tls', '--server', f'127.0.0.1:{port}',
                                     '--server-name', 'localhost', '--ca', str(cert),
                                     '--listen', f'127.0.0.1:{free_port()}'],
                                    env=dict(os.environ, FOLDFIN_TOKEN='0' * 64),
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            socks_port = int(child.args[child.args.index('--listen') + 1].rsplit(':', 1)[1])
            deadline = time.monotonic() + 15
            while time.monotonic() < deadline:
                if child.poll() is not None:
                    raise RuntimeError(f'Foldfin client exited with {child.returncode}')
                try:
                    with socket.create_connection(('127.0.0.1', socks_port), timeout=.1):
                        break
                except OSError:
                    time.sleep(.05)
            else:
                raise TimeoutError('Foldfin SOCKS listener did not start')
            request_socks(socks_port)
        if not peer.request_seen.wait(timeout=5):
            raise RuntimeError(f'{mode}: no HTTP/2 HEADERS frame captured')
        time.sleep(.3)
        successful = True
    finally:
        peer.close()
        if child is not None and child.poll() is None:
            child.terminate()
            try:
                child.wait(timeout=3)
            except subprocess.TimeoutExpired:
                child.kill()
                child.wait()
        if capture is not None:
            capture.terminate()
            try:
                capture.wait(timeout=3)
            except subprocess.TimeoutExpired:
                capture.kill()
                capture.wait()
            capture.stderr.close()
        if not successful:
            keylog.unlink(missing_ok=True)
    try:
        rows = decoded_frames(pcap, keylog, port)
    finally:
        keylog.unlink(missing_ok=True)
    return {'connections': peer.connections, 'decoded_frames': rows, 'pcap': pcap.name}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--output', type=pathlib.Path)
    args = parser.parse_args()
    if args.output is None:
        stamp = datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        args.output = ROOT / 'captures' / f'http2-chrome-154-{stamp}'
    report_path = args.output / 'report.json'
    if args.output.exists() and any(args.output.iterdir()):
        parser.error('output directory is not empty; choose a new directory')
    args.output.mkdir(parents=True, exist_ok=True)
    subprocess.run(['cargo', 'build', '--locked', '--features', 'chrome-tls', '--bin', 'client'],
                   cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--locked', '--no-deps', '--format-version', '1'], cwd=ROOT))
    client = pathlib.Path(metadata['target_directory']) / 'debug/client'
    with tempfile.TemporaryDirectory(prefix='foldfin-h2-cert-') as tmp:
        cert, key = pathlib.Path(tmp) / 'cert.pem', pathlib.Path(tmp) / 'key.pem'
        subprocess.run([
            'openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
            '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
            '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
            '-addext', 'extendedKeyUsage=serverAuth',
        ], check=True, capture_output=True)
        report = {'chrome_version': subprocess.check_output(['/opt/google/chrome/google-chrome', '--version'], text=True).strip()}
        for mode in ['chrome', 'foldfin']:
            report[mode] = one_capture(mode, args.output, cert, key, client)
    report_path.write_text(json.dumps(report, indent=2) + '\n')
    summary = {
        mode: {
            'client_frames': [frame for conn in report[mode]['connections'] for frame in conn['frames']],
            'decoded_frames': report[mode]['decoded_frames'],
        }
        for mode in ['chrome', 'foldfin']
    }
    def first_client_setting(mode):
        return next(frame['settings'] for conn in report[mode]['connections']
                    for frame in conn['frames'] if frame['type'] == 4 and not frame['flags'] & 1)
    def first_window_update(mode):
        return next((frame['window_increment'] for conn in report[mode]['connections']
                     for frame in conn['frames'] if frame['type'] == 8 and frame['stream_id'] == 0), None)
    summary['comparison'] = {
        'initial_settings_match': first_client_setting('chrome') == first_client_setting('foldfin'),
        'connection_window_update_match': first_window_update('chrome') == first_window_update('foldfin'),
        'chrome_initial_settings': first_client_setting('chrome'),
        'foldfin_initial_settings': first_client_setting('foldfin'),
        'chrome_connection_window_update': first_window_update('chrome'),
        'foldfin_connection_window_update': first_window_update('foldfin'),
    }
    if not summary['comparison']['initial_settings_match'] or not summary['comparison']['connection_window_update_match']:
        raise RuntimeError('Chrome HTTP/2 connection settings did not match')
    (args.output / 'summary.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps({mode: summary[mode]['client_frames'] for mode in ['chrome', 'foldfin']}, indent=2))


if __name__ == '__main__':
    main()
