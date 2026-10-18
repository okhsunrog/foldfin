#!/usr/bin/env python3
"""Controlled local release TCP proxy/CONNECT-IP benchmark; no host routes or remote access.

Both endpoints use the Foldfin CLI and real TUN, not the Floppa actor. Impairment
is applied to outer veth only. Results describe this workload, not a CPU ceiling.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import signal
import subprocess
import tempfile
import threading
import time

ROOT = Path(__file__).resolve().parents[1]


def run(*command, **kwargs):
    return subprocess.run(list(map(str, command)), check=True,
                          capture_output=True, text=True, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'target/release/foldfin')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--seconds', type=int, default=8)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--rtt-ms', type=float, default=200)
    parser.add_argument('--loss-percent', type=float, default=0)
    parser.add_argument('--telemetry', action='store_true', help='Sample TCP state and capture packet metadata')
    parser.add_argument('--workload', choices=['iperf', 'stream', 'mixed'], default='iperf')
    parser.add_argument('--modes', nargs='+', choices=['tun', 'proxy'], default=['tun'])
    parser.add_argument('--flows', type=int, default=1, help='Concurrent bulk flows for mixed workload')
    parser.add_argument('--directions', nargs='+', choices=['upload', 'download'], default=['upload', 'download'])
    parser.add_argument('--rate-mbps', type=float, default=0, help='Optional outer netem rate per direction')
    parser.add_argument('--disable-offloads', action='store_true', help='Disable veth GRO/GSO/TSO for packet-level loss')
    parser.add_argument('--tun-queue', type=int, default=500, help='TUN driver queue length in test namespaces only')
    parser.add_argument('--netem-placement', choices=['egress', 'ingress'], default='egress')
    parser.add_argument('--tcp-wmem-max', type=int, help='TCP autotune send maximum in test namespaces only')
    parser.add_argument('--profiles', nargs='+', choices=['rustls'],
                        default=['rustls'])
    args = parser.parse_args()
    assert 3 <= args.seconds <= 60 and 1 <= args.repeats <= 5
    assert 0 <= args.rtt_ms <= 1000 and 0 <= args.loss_percent <= 5
    assert args.workload in ['stream', 'mixed'] or args.modes == ['tun'], 'proxy requires stream workload'
    assert args.workload != 'mixed' or args.directions == ['download'], 'mixed workload uses bounded downloads'
    assert 1 <= args.flows <= 16 and (args.workload == 'mixed' or args.flows == 1)
    assert 0 <= args.rate_mbps <= 10000
    assert 100 <= args.tun_queue <= 20000
    if args.tcp_wmem_max is not None:
        assert 4*1024*1024 <= args.tcp_wmem_max <= 64*1024*1024
    binary = args.binary.resolve(strict=True)
    args.output.mkdir(parents=True, exist_ok=False)
    args.output.chmod(0o700)
    suffix = secrets.token_hex(4)
    namespaces = ['ffbc-'+suffix, 'ffbs-'+suffix]
    created, processes, files, captures = [], [], [], []
    env = dict(os.environ, FOLDFIN_TOKEN=secrets.token_hex(32))
    summary = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'binary_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'workload': 'Foldfin CLI, real TUN, iperf3 TCP, MTU 1280',
               'requested_rtt_ms': args.rtt_ms,
               'loss_percent_per_outer_direction': args.loss_percent,
               'seconds': args.seconds, 'omit_seconds': 2,
               'cpu': run('lscpu').stdout, 'results': [], 'cleanup': False}
    summary.update(workload=args.workload, modes=args.modes, telemetry=args.telemetry,
                   tun_queue=args.tun_queue, netem_placement=args.netem_placement,
                   tcp_wmem_max=args.tcp_wmem_max, kernel=os.uname().release,
                   rate_mbps=args.rate_mbps, offloads_disabled=args.disable_offloads, flows=args.flows)
    root = lambda *cmd, **kw: run('sudo', '-n', *cmd, **kw)

    def command(ns, *cmd):
        return ['sudo', '-n', '--preserve-env=FOLDFIN_TOKEN', 'ip', 'netns', 'exec', ns,
                'setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()),
                '--clear-groups', *map(str, cmd)]

    def launch(ns, name, *cmd):
        log = open(args.output/(name+'.log'), 'w'); files.append(log)
        proc = subprocess.Popen(command(ns, *cmd), env=env, stdout=log, stderr=log)
        processes.append(proc)
        return proc

    def stop(proc):
        if proc.poll() is None:
            proc.terminate()
            try: proc.wait(timeout=5)
            except subprocess.TimeoutExpired: proc.kill(); proc.wait(timeout=5)

    def ready(proc, name, needle):
        deadline = time.monotonic()+20
        while time.monotonic() < deadline:
            text = (args.output/(name+'.log')).read_text()
            if proc.poll() is not None: raise RuntimeError(text)
            if needle in text: return
            time.sleep(.05)
        raise TimeoutError(text)

    def save():
        (args.output/'summary.json').write_text(json.dumps(summary, indent=2))

    def transfer(cmd, name):
        samples, sampling_errors, stopped = [], [], threading.Event()
        def sample():
            try:
                while not stopped.is_set():
                    item = {'monotonic': time.monotonic()}
                    for ns in namespaces:
                        item[ns] = root('ip', 'netns', 'exec', ns, 'ss', '-tinm', timeout=5).stdout
                    samples.append(item)
                    stopped.wait(.5)
            except Exception as error:
                sampling_errors.append(str(error))
        thread = threading.Thread(target=sample, daemon=True) if args.telemetry else None
        if thread: thread.start()
        try:
            return subprocess.run(cmd, env=env, capture_output=True, text=True,
                                  timeout=args.seconds+35)
        finally:
            stopped.set()
            if thread:
                thread.join(timeout=12)
                assert not thread.is_alive(), 'TCP sampler did not finish'
                (args.output/(name+'-tcp.json')).write_text(json.dumps(samples, indent=2))
            if args.telemetry:
                state = {}
                for ns in namespaces:
                    state[ns] = {
                        'links': json.loads(root('ip', '-n', ns, '-j', '-s', 'link', 'show').stdout),
                        'qdisc': json.loads(root('ip', 'netns', 'exec', ns, 'tc', '-s', '-j', 'qdisc', 'show').stdout),
                        'nstat': root('ip', 'netns', 'exec', ns, 'nstat', '-az').stdout,
                    }
                (args.output/(name+'-network.json')).write_text(json.dumps(state, indent=2))
            if sampling_errors:
                (args.output/(name+'-telemetry-errors.json')).write_text(json.dumps(sampling_errors))
                raise RuntimeError(f'TCP telemetry failed: {name}: {sampling_errors}')

    try:
        root('true')
        with tempfile.TemporaryDirectory(prefix='ffbench-cert-') as tmp:
            cert, key = Path(tmp)/'cert.pem', Path(tmp)/'key.pem'
            run('openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', key, '-out', cert, '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost',
                '-addext', 'basicConstraints=critical,CA:FALSE',
                '-addext', 'extendedKeyUsage=serverAuth')
            for ns in namespaces:
                root('ip', 'netns', 'add', ns); created.append(ns)
                root('ip', '-n', ns, 'link', 'set', 'lo', 'up')
                if args.tcp_wmem_max:
                    root('ip', 'netns', 'exec', ns, 'sysctl', '-q', '-w',
                         f'net.ipv4.tcp_wmem=4096 16384 {args.tcp_wmem_max}')
            client_ns, server_ns = namespaces
            root('ip', 'link', 'add', 'outer0', 'netns', client_ns, 'type', 'veth',
                 'peer', 'name', 'outer0', 'netns', server_ns)
            for ns, outer, inner, peer in [
                (client_ns, '192.0.2.1/30', '198.18.0.1', '198.18.0.2'),
                (server_ns, '192.0.2.2/30', '198.18.0.2', '198.18.0.1'),
            ]:
                root('ip', '-n', ns, 'addr', 'add', outer, 'dev', 'outer0')
                root('ip', '-n', ns, 'link', 'set', 'outer0', 'up')
                root('ip', 'netns', 'exec', ns, 'ip', 'tuntap', 'add', 'dev', 'ffvpn0',
                     'mode', 'tun', 'user', str(os.getuid()))
                root('ip', '-n', ns, 'addr', 'add', inner+'/32', 'dev', 'ffvpn0')
                root('ip', '-n', ns, 'link', 'set', 'ffvpn0', 'mtu', '1280', 'txqueuelen', args.tun_queue, 'up')
                root('ip', '-n', ns, 'route', 'add', peer+'/32', 'dev', 'ffvpn0')
                if args.disable_offloads:
                    root('ip', 'netns', 'exec', ns, 'ethtool', '-K', 'outer0', 'gro', 'off', 'gso', 'off', 'tso', 'off')
                    (args.output/(ns+'-offloads.txt')).write_text(root('ip', 'netns', 'exec', ns, 'ethtool', '-k', 'outer0').stdout)
                if args.rtt_ms or args.loss_percent or args.rate_mbps:
                    impaired = 'outer0'
                    if args.netem_placement == 'ingress':
                        # Receiver-side placement avoids TCP Small Queues
                        # artifacts from keeping SKBs on the sender for 100 ms.
                        root('ip', '-n', ns, 'link', 'add', 'delay0', 'type', 'ifb')
                        root('ip', '-n', ns, 'link', 'set', 'delay0', 'up')
                        root('ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'add', 'dev', 'outer0', 'ingress')
                        root('ip', 'netns', 'exec', ns, 'tc', 'filter', 'add', 'dev', 'outer0',
                             'parent', 'ffff:', 'protocol', 'all', 'matchall', 'action',
                             'mirred', 'egress', 'redirect', 'dev', 'delay0')
                        impaired = 'delay0'
                    # Large enough queue to avoid netem's default 1000-packet cap
                    # becoming an accidental low-bandwidth link at 200 ms RTT.
                    root('ip', 'netns', 'exec', ns, 'tc', 'qdisc', 'add', 'dev', impaired,
                         'root', 'netem', 'limit', '100000', 'delay', f'{args.rtt_ms/2}ms',
                         'loss', f'{args.loss_percent}%',
                         *(['rate', f'{args.rate_mbps}mbit'] if args.rate_mbps else []))
            endpoint = launch(server_ns, 'endpoint', *(['iperf3', '-s', '-p', '31991']
                if args.workload == 'iperf' else [os.sys.executable, ROOT/'tests/bench_stream.py', '--server', '--address', '0.0.0.0']))
            if args.telemetry:
                for ns in namespaces:
                    log = open(args.output/(ns+'-packets.log'), 'w'); files.append(log)
                    capture = subprocess.Popen(
                        ['sudo', '-n', 'ip', 'netns', 'exec', ns, 'tcpdump',
                         '--immediate-mode', '-nn', '-tt', '-q', '-l', '-i', 'outer0', '-Q', 'out',
                         'tcp and (port 8443 or port 31991 or port 31992)'], stdout=log, stderr=log)
                    processes.append(capture)
                    captures.append(capture)
            time.sleep(.2)
            assert endpoint.poll() is None
            cases = [(p, mode, repeat) for p, mode in [('direct', None)] + [(p, mode) for mode in args.modes for p in args.profiles]
                     for repeat in range(args.repeats)]
            for profile, mode, repeat in cases:
                label = profile if args.workload == 'iperf' or profile == 'direct' else mode+'-'+profile
                server = client = None
                if profile != 'direct':
                    server = launch(server_ns, label+f'-{repeat+1}-server', binary, 'server',
                                    '--listen', '192.0.2.2:8443', '--cert', cert, '--key', key,
                                    *(['--tun', 'ffvpn0', '--vpn-local', '198.18.0.2', '--vpn-peer', '198.18.0.1']
                                      if mode == 'tun' else ['--allow-private']))
                    ready(server, label+f'-{repeat+1}-server', 'listening on')
                    client = launch(client_ns, label+f'-{repeat+1}-client', binary, 'client',
                                    '--server', '192.0.2.2:8443', '--server-name', 'localhost',
                                    '--ca', cert,
                                    *(['--tun', 'ffvpn0', '--vpn-local', '198.18.0.1', '--vpn-peer', '198.18.0.2']
                                      if mode == 'tun' else ['--listen', '127.0.0.1:1080']))
                    ready(client, label+f'-{repeat+1}-client', 'configuration confirmed' if mode == 'tun' else 'SOCKS5 listening')
                for direction in args.directions:
                    reverse = direction == 'download'
                    name = f'{label}-{repeat+1}-'+('download' if reverse else 'upload')
                    if args.workload in ['stream', 'mixed']:
                        cmd = command(client_ns, os.sys.executable, ROOT/('tests/bench_mixed.py' if args.workload == 'mixed' else 'tests/bench_stream.py'),
                            '--address', '198.18.0.2' if mode == 'tun' else '192.0.2.2',
                            '--seconds', args.seconds, '--direction', 'download' if reverse else 'upload',
                            *(['--socks', '1080'] if mode == 'proxy' else []),
                            *(['--flows', args.flows] if args.workload == 'mixed' else []))
                    else:
                        cmd = command(client_ns, 'iperf3', '-c',
                                 '192.0.2.2' if profile == 'direct' else '198.18.0.2',
                                 '-p', '31991', '-t', args.seconds, '-O', '2', '-J',
                                 '--get-server-output', *(['-R'] if reverse else []))
                    capture_start = time.time()
                    result = transfer(cmd, name)
                    capture_end = time.time()
                    (args.output/(name+'-stderr.log')).write_text(result.stderr)
                    try:
                        data = json.loads(result.stdout)
                    except json.JSONDecodeError:
                        (args.output/(name+'-stdout.log')).write_text(result.stdout)
                        summary['failed_run'] = {'name': name, 'returncode': result.returncode,
                                                 'error': 'invalid workload JSON; raw output retained'}
                        save()
                        raise
                    (args.output/(name+'.json')).write_text(json.dumps(data, indent=2))
                    if result.returncode or 'error' in data:
                        summary['failed_run'] = {'name': name, 'returncode': result.returncode,
                                                 'error': data.get('error')}
                        save()
                        raise RuntimeError(f'iperf failed: {name}: {data.get("error")}')
                    record = {'profile': profile, 'mode': mode, 'repeat': repeat+1,
                              'direction': 'download' if reverse else 'upload',
                              'mbps': data['mbps'] if args.workload in ['stream', 'mixed'] else data['end']['sum_received']['bits_per_second']/1e6,
                              'retransmits': None if args.workload in ['stream', 'mixed'] else data['end']['sum_sent'].get('retransmits')}
                    record.update(capture_start=capture_start, capture_end=capture_end)
                    if args.workload == 'mixed': record['latency'] = data['latency']
                    summary['results'].append(record); save()
                    print(f"{name}: {record['mbps']:.2f} Mbps", flush=True)
                if client: stop(client)
                if server: stop(server)
            for ns in namespaces:
                (args.output/(ns+'-qdisc.json')).write_text(
                    root('ip', 'netns', 'exec', ns, 'tc', '-s', '-j', 'qdisc', 'show').stdout)
    finally:
        errors = []
        for capture in captures:
            if capture.poll() is None:
                capture.send_signal(signal.SIGINT)
                try: capture.wait(timeout=5)
                except subprocess.TimeoutExpired: stop(capture)
        for ns in reversed(created):
            try:
                pids = root('ip', 'netns', 'pids', ns).stdout.split()
                if pids: root('kill', '-KILL', *pids)
                root('ip', 'netns', 'del', ns)
            except subprocess.SubprocessError as error: errors.append(str(error))
        for proc in processes: stop(proc)
        for file in files: file.close()
        remaining = root('ip', 'netns', 'list').stdout
        summary['cleanup'] = not errors and not any(ns in remaining for ns in namespaces)
        summary['cleanup_errors'] = errors
        save()
        if not summary['cleanup']: raise RuntimeError('namespace cleanup failed')


if __name__ == '__main__':
    main()
