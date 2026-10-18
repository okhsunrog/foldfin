#!/usr/bin/env python3
"""Verified bulk TCP plus sequential short, new-connection requests on the same path.

Probe latency includes TCP/SOCKS CONNECT and a 1 KiB application response. Probes
start every 200 ms after the previous one completes; failures are counted, never
silently omitted. This is a comparison workload, not browser emulation.
"""
import argparse
from concurrent.futures import ThreadPoolExecutor
import json
import socket
import time
from bench_stream import BLOCK, exact, write_json


def connect(address, socks):
    sock = socket.create_connection(('127.0.0.1', socks) if socks else (address, 31992), 5)
    try:
        sock.settimeout(5)
        sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        if socks:
            sock.sendall(b'\x05\x01\x00')
            assert exact(sock, 2) == b'\x05\x00'
            sock.sendall(b'\x05\x01\x00\x01' + socket.inet_aton(address) + (31992).to_bytes(2, 'big'))
            assert exact(sock, 10)[:2] == b'\x05\x00'
        return sock
    except BaseException:
        sock.close()
        raise


def probe(address, socks):
    with connect(address, socks) as sock:
        write_json(sock, {'direction': 'probe'})
        assert exact(sock, 1024) == b'P' * 1024


def download(address, seconds, socks):
    with connect(address, socks) as sock:
        write_json(sock, {'direction': 'timed-download'})
        assert exact(sock, 1) == b'R'
        started = time.monotonic()
        deadline = started + seconds + 2
        count = measured = 0
        pending = bytearray()
        while (remaining := deadline-time.monotonic()) > 0:
            sock.settimeout(remaining)
            try:
                data = sock.recv(65540-len(pending))
            except TimeoutError:
                break
            if not data: raise EOFError('bulk stream ended before deadline')
            pending.extend(data)
            if len(pending) == 65540:
                assert int.from_bytes(pending[:4], 'big') == len(BLOCK)
                assert pending[4:] == BLOCK, 'payload mismatch'
                count += len(BLOCK)
                if time.monotonic()-started >= 2: measured += len(BLOCK)
                pending.clear()
        return {'bytes': count, 'measured_bytes': measured, 'mbps': measured*8/seconds/1e6,
                'integrity': True, 'omit_seconds': 2, 'partial_frame_bytes': len(pending)}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--address', required=True)
    parser.add_argument('--socks', type=int)
    parser.add_argument('--seconds', type=int, default=10)
    parser.add_argument('--flows', type=int, default=1)
    parser.add_argument('--direction', choices=['download'], required=True)
    args = parser.parse_args()
    assert 1 <= args.flows <= 16 and 3 <= args.seconds <= 60
    samples, failures = [], []
    started = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.flows) as pool:
        bulk = [pool.submit(download, args.address, args.seconds, args.socks)
                for _ in range(args.flows)]
        while not all(flow.done() for flow in bulk):
            before = time.monotonic()
            try:
                probe(args.address, args.socks)
                if before-started >= 2:
                    samples.append((time.monotonic()-before)*1000)
            except (OSError, EOFError, AssertionError) as error:
                failures.append({'after_seconds': before-started, 'error': str(error)})
            time.sleep(.2)
        flows = [flow.result() for flow in bulk]
        result = {'mbps': sum(flow['mbps'] for flow in flows),
                  'bytes': sum(flow['bytes'] for flow in flows),
                  'measured_bytes': sum(flow['measured_bytes'] for flow in flows),
                  'integrity': all(flow['integrity'] for flow in flows),
                  'bulk_flows': flows}
    values = sorted(samples)
    def percentile(p):
        return values[min(len(values)-1, int((len(values)-1)*p))] if values else None
    result['latency'] = {'samples_ms': samples, 'count': len(samples), 'failures': failures,
                         'p50_ms': percentile(.5), 'p95_ms': percentile(.95),
                         'max_ms': max(samples) if samples else None}
    print(json.dumps(result), flush=True)


if __name__ == '__main__':
    main()
