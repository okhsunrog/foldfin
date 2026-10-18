#!/usr/bin/env python3
"""Summarize mixed-workload results and outer TCP metadata; no detection claims.

Reads outgoing outer0 captures from each endpoint. TCP payload length includes
retransmissions, and zero-payload outer ACKs are separated from small data packets.
The observer is before receiver-side netem loss. TLS records are not reconstructed.
"""
import argparse
import json
from pathlib import Path
import re
import statistics

PACKET = re.compile(r'^(\d+\.\d+) IP (\S+) > (\S+): tcp (\d+)$')


def percentile(values, fraction):
    values = sorted(values)
    return values[int((len(values)-1)*fraction)] if values else None


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('runs', nargs='+', type=Path)
    args = parser.parse_args()
    result = []
    for path in args.runs:
        summary = json.loads((path/'summary.json').read_text())
        if not summary['cleanup'] or summary.get('failed_run'):
            raise ValueError(f'Run did not complete cleanly: {path}')
        captures = {}
        for file in path.glob('*-packets.log'):
            text = file.read_text()
            dropped = re.search(r'(\d+) packets dropped by kernel', text)
            if not dropped or int(dropped[1]):
                raise ValueError(f'Capture completeness not established: {file}')
            captures['client' if file.name.startswith('ffbc-') else 'server'] = [
                (float(m[1]), m[2], m[3].rstrip(':'), int(m[4]))
                for line in text.splitlines() if (m := PACKET.match(line))]
        if set(captures) != {'client', 'server'}:
            raise ValueError(f'Missing endpoint capture: {path}')
        for record in summary['results']:
            port = '31992' if record['profile'] == 'direct' else '8443'
            metadata = {}
            for side, packets in captures.items():
                selected = [(stamp, length) for stamp, src, dst, length in packets
                            if record['capture_start'] <= stamp <= record['capture_end']
                            and (src.endswith('.'+port) or dst.endswith('.'+port))]
                lengths = [length for _, length in selected if length]
                times = [stamp for stamp, length in selected if length]
                gaps = [(b-a)*1000 for a, b in zip(times, times[1:])]
                metadata[side] = {
                    'packets': len(selected), 'data_packets': len(lengths),
                    'tcp_payload_bytes': sum(lengths),
                    'data_packets_per_second': len(lengths)/(record['capture_end']-record['capture_start']),
                    'zero_payload_packets': sum(length == 0 for _, length in selected),
                    'small_data_fraction': sum(n <= 100 for n in lengths)/len(lengths) if lengths else None,
                    'median_tcp_payload': statistics.median(lengths) if lengths else None,
                    'data_gap_p95_ms': percentile(gaps, .95),
                }
            result.append({'run': path.name, 'cleanup': summary['cleanup'],
                           **record, 'outer_tcp': metadata})
    print(json.dumps(result, indent=2))


if __name__ == '__main__':
    main()
