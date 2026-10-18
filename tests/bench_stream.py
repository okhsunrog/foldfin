#!/usr/bin/env python3
"""Identical verified TCP workload for direct, SOCKS proxy and TUN comparisons.

Framed 64 KiB generated blocks, receiver goodput after warmup, SHA-256 integrity
and independent half-close. Python/checksum overhead is common to all modes;
this is a long-RTT comparison, not an intrinsic protocol CPU benchmark.
"""
import argparse
import hashlib
import json
import socket
import threading
import time

BLOCK = b'\x5a' * 65536
FRAME = len(BLOCK).to_bytes(4, 'big') + BLOCK


def exact(sock, length):
    out = bytearray()
    while len(out) < length:
        data = sock.recv(length-len(out))
        if not data: raise EOFError('premature EOF')
        out.extend(data)
    return out


def read_json(sock):
    out = bytearray()
    while len(out) < 4096:
        data = sock.recv(1)
        if not data: raise EOFError('missing JSON trailer')
        if data == b'\n': return json.loads(out)
        out.extend(data)
    raise ValueError('oversized control message')


def write_json(sock, value):
    sock.sendall(json.dumps(value).encode()+b'\n')


def send(sock, seconds):
    digest, count = hashlib.sha256(), 0
    started = time.monotonic()
    while time.monotonic()-started < seconds:
        sock.sendall(FRAME)
        digest.update(BLOCK)
        count += len(BLOCK)
    trailer = {'bytes': count, 'sha256': digest.hexdigest(),
               'sender_seconds': time.monotonic()-started}
    sock.sendall(b'\0' * 4)
    write_json(sock, trailer)
    sock.shutdown(socket.SHUT_WR)


def receive(sock, omit):
    digest, count, measured = hashlib.sha256(), 0, 0
    started = last = time.monotonic()
    worst_gap = 0
    while True:
        length = int.from_bytes(exact(sock, 4), 'big')
        if length == 0: break
        assert length == len(BLOCK), 'invalid frame length'
        data = exact(sock, length)
        now = time.monotonic()
        digest.update(data)
        count += length
        if now-started >= omit: measured += length
        worst_gap = max(worst_gap, now-last)
        last = now
    elapsed = last-started
    trailer = read_json(sock)
    assert count == trailer['bytes'] and digest.hexdigest() == trailer['sha256'], 'payload mismatch'
    return {'bytes': count, 'measured_bytes': measured, 'receiver_seconds': elapsed,
            'sender_seconds': trailer['sender_seconds'], 'omit_seconds': omit,
            'mbps': measured*8/max(elapsed-omit, .001)/1e6,
            'worst_block_gap_ms': worst_gap*1000, 'integrity': True}


def server(address):
    def handle(sock):
        with sock:
            sock.settimeout(60)
            sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            request = read_json(sock)
            if request.get('direction') == 'probe':
                sock.sendall(b'P' * 1024)
                return
            if request.get('direction') == 'timed-download':
                sock.sendall(b'R')
                try:
                    while True: sock.sendall(FRAME)
                except OSError:
                    return  # bounded receiver finished; no trailer/drain is needed
            assert 3 <= request['seconds'] <= 60 and request['omit'] == 2
            sock.sendall(b'R')
            if request['direction'] == 'upload':
                result = receive(sock, request['omit'])
                write_json(sock, result)
                sock.shutdown(socket.SHUT_WR)
            else:
                assert request['direction'] == 'download'
                send(sock, request['seconds']+request['omit'])
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind((address, 31992)); listener.listen()
        print('stream listener ready', flush=True)
        while True:
            sock, _ = listener.accept()
            threading.Thread(target=handle, args=(sock,), daemon=True).start()


def client(address, direction, seconds, socks):
    with socket.create_connection(('127.0.0.1', socks) if socks else (address, 31992), 15) as sock:
        sock.settimeout(60)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if socks:
            sock.sendall(b'\x05\x01\x00')
            assert exact(sock, 2) == b'\x05\x00'
            sock.sendall(b'\x05\x01\x00\x01'+socket.inet_aton(address)+(31992).to_bytes(2, 'big'))
            assert exact(sock, 10)[:2] == b'\x05\x00', 'SOCKS CONNECT denied'
        write_json(sock, {'direction': direction, 'seconds': seconds, 'omit': 2})
        assert exact(sock, 1) == b'R'
        if direction == 'upload':
            send(sock, seconds+2)
            result = read_json(sock)
            assert result['integrity']
        else:
            sock.shutdown(socket.SHUT_WR)
            result = receive(sock, 2)
        return result


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--server', action='store_true')
    parser.add_argument('--address', required=True)
    parser.add_argument('--direction', choices=['upload', 'download'])
    parser.add_argument('--seconds', type=int, default=20)
    parser.add_argument('--socks', type=int)
    args = parser.parse_args()
    if args.server: server(args.address)
    else: print(json.dumps(client(args.address, args.direction, args.seconds, args.socks)), flush=True)
