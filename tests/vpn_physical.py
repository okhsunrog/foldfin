#!/usr/bin/env python3
"""Singapore CONNECT-IP acceptance/throughput through a physical NIC only."""
import argparse
import datetime
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import subprocess
import sys
import threading
import time

from vps import configuration
sys.path.insert(0, str(Path(__file__).resolve().parents[1]/'scripts'))
from network_policy import NetworkPolicy

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--binary', type=Path, default=ROOT/'target/release/foldfin')
    parser.add_argument('--configs', type=Path, default=ROOT.parent.parent/'cloud-forge/generated_configs/foldfin')
    parser.add_argument('--output', type=Path, required=True)
    parser.add_argument('--interface')
    parser.add_argument('--seconds', type=int, default=12)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--profiles', nargs='+', choices=['rustls'], default=['rustls'])
    parser.add_argument('--accept-only', action='store_true')
    parser.add_argument('--telemetry', action='store_true')
    args = parser.parse_args()
    assert 3 <= args.seconds <= 60 and 1 <= args.repeats <= 5
    binary = args.binary.resolve(strict=True)
    cfg = configuration(args.configs, 'singapore')
    assert cfg['FOLDFIN_SERVER_NAME'] == 'sg.okhsunrog.dev', 'Singapore only'
    address = socket.gethostbyname(cfg['FOLDFIN_SERVER_NAME'])
    assert ipaddress.ip_address(address).is_global
    _, port = cfg['FOLDFIN_SERVER'].rsplit(':', 1)
    remote = 'root@sg.okhsunrog.dev'
    suffix = secrets.token_hex(4)
    ns, veth, tag = 'ffwan-'+suffix, 'ffw'+suffix, 'foldfin-wan-'+suffix
    table = str(42000+secrets.randbelow(1000))
    network = ipaddress.ip_network(f'10.251.{1+secrets.randbelow(250)}.0/30')
    gateway_ns, client_ip = str(network[1]), str(network[2])
    args.output.mkdir(parents=True, exist_ok=False); args.output.chmod(0o700)
    undo, processes, logs, capture_units = [], [], [], []
    remote_dir, remote_created, remote_ready, public_source = '/tmp/'+tag, False, False, None
    env = dict(os.environ, FOLDFIN_TOKEN=cfg['FOLDFIN_TOKEN'])
    summary = {'timestamp_utc': datetime.datetime.now(datetime.timezone.utc).isoformat(),
               'client_sha256': hashlib.sha256(binary.read_bytes()).hexdigest(),
               'endpoint': f'{address}:{port}', 'namespace': ns, 'policy_table': table,
               'seconds': args.seconds, 'omit_seconds': 2, 'workload': 'SHA-256 framed TCP',
               'results': [], 'acceptance': {}, 'cleanup': False}
    def run(*cmd, check=True, **kw):
        return subprocess.run(list(map(str, cmd)), check=check, capture_output=True, text=True, **kw)
    def root(*cmd, **kw): return run('sudo', '-n', *cmd, **kw)
    def ssh(*cmd, **kw):
        return run('ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=10', remote,
                   shlex.join(map(str, cmd)), timeout=45, **kw)
    def ns_cmd(*cmd):
        return ['sudo', '-n', '--preserve-env=FOLDFIN_TOKEN', 'ip', 'netns', 'exec', ns,
                'setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()),
                '--clear-groups', *map(str, cmd)]
    def inside(*cmd, **kw): return run(*ns_cmd(*cmd), env=env, **kw)
    def save(): (args.output/'summary.json').write_text(json.dumps(summary, indent=2))
    def change(action, rollback): undo.append(rollback); action()
    def rule(family, chain, *parts):
        change(lambda: root('iptables', '-w', '-t', family, '-I', chain, '1', *parts),
               lambda: root('iptables', '-w', '-t', family, '-D', chain, *parts))
    def launch(name, *cmd):
        log = open(args.output/(name+'.log'), 'w'); logs.append(log)
        p = subprocess.Popen(ns_cmd(*cmd), env=env, stdout=log, stderr=log, start_new_session=True)
        processes.append(p); return p
    def stop(p):
        if p.poll() is None:
            os.killpg(p.pid, signal.SIGINT)
            try: p.wait(timeout=10)
            except subprocess.TimeoutExpired: os.killpg(p.pid, signal.SIGKILL); p.wait(timeout=5)
    def ready(p, name, needle):
        deadline = time.monotonic()+35
        while time.monotonic() < deadline:
            text = (args.output/(name+'.log')).read_text()
            if p.poll() is not None: raise RuntimeError(text)
            if needle in text: return
            time.sleep(.1)
        raise TimeoutError(text)
    def remote_helper(operation):
        result = ssh('uv', 'run', '--no-project', '--no-cache', 'python3',
                     remote_dir+'/vpn_physical_remote.py', operation, suffix, '--source', public_source, check=False)
        (args.output/('remote-'+operation+'.log')).write_text(result.stdout+result.stderr)
        if result.returncode:
            raise RuntimeError('remote '+operation+' failed: '+result.stderr)
        return result
    def transfer(label, *cmd):
        stopped, samples, errors = threading.Event(), [], []
        def sample():
            try:
                while not stopped.is_set():
                    samples.append({'time': time.time(), 'client': inside('ss', '-tinm', timeout=10).stdout,
                                    'server': ssh('ss', '-tinm', 'sport', '=', ':'+port).stdout})
                    stopped.wait(2)
            except Exception as error: errors.append(str(error))
        thread = threading.Thread(target=sample) if args.telemetry else None
        if thread: thread.start()
        try:
            return inside(*cmd, timeout=args.seconds+65, check=False)
        finally:
            stopped.set()
            if thread:
                thread.join(timeout=60)
                (args.output/(label+'-tcp.json')).write_text(json.dumps(samples, indent=2))
                assert not thread.is_alive() and not errors, 'TCP telemetry failed: '+str(errors)
    try:
        root('true')
        service = ssh('systemctl', 'show', 'foldfin', '-p', 'ActiveState', '-p', 'ExecStart').stdout
        assert 'ActiveState=active' in service and '--vpn-local 198.18.78.1' in service, 'configure Singapore CONNECT-IP first'
        summary['server_service'] = service
        summary['server_sha256'] = ssh('sha256sum', '/opt/foldfin/server').stdout.split()[0]
        summary['server_tcp_wmem'] = ssh('sysctl', '-n', 'net.ipv4.tcp_wmem').stdout.strip()
        summary['host_default_routes_before'] = run('ip', '-j', 'route', 'show', 'default', 'table', 'main').stdout
        summary['host_tcp_wmem_before'] = run('sysctl', '-n', 'net.ipv4.tcp_wmem').stdout.strip()
        routes = json.loads(summary['host_default_routes_before'])
        eligible = [r for r in routes if r.get('gateway') and (not args.interface or r['dev'] == args.interface)]
        route = min(eligible, key=lambda r: r.get('metric', 0)); dev, gateway = route['dev'], route['gateway']
        assert (Path('/sys/class/net')/dev/'device').exists(), 'physical NIC required'
        assert root('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == '1'
        assert not root('ip', 'route', 'show', 'table', table, check=False).stdout.strip()
        assert not run('ip', 'route', 'show', str(network)).stdout.strip()
        change(lambda: root('ip', 'netns', 'add', ns), lambda: root('ip', 'netns', 'del', ns))
        change(lambda: root('ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', 'outer0', 'netns', ns),
               lambda: root('ip', 'link', 'del', veth))
        root('ip', 'addr', 'add', gateway_ns+'/30', 'dev', veth); root('ip', 'link', 'set', veth, 'up')
        root('ip', '-n', ns, 'addr', 'add', client_ip+'/30', 'dev', 'outer0')
        root('ip', '-n', ns, 'link', 'set', 'outer0', 'up'); root('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        root('ip', '-n', ns, 'route', 'add', 'default', 'via', gateway_ns)
        change(lambda: root('ip', 'route', 'add', 'default', 'via', gateway, 'dev', dev, 'table', table),
               lambda: root('ip', 'route', 'del', 'default', 'via', gateway, 'dev', dev, 'table', table))
        change(lambda: root('ip', 'rule', 'add', 'from', str(network), 'table', table, 'priority', '89'),
               lambda: root('ip', 'rule', 'del', 'from', str(network), 'table', table, 'priority', '89'))
        comment = ['-m', 'comment', '--comment', tag]
        rule('nat', 'POSTROUTING', '-s', str(network), '-o', dev, *comment, '-j', 'MASQUERADE')
        rule('filter', 'FORWARD', '-i', veth, '-o', dev, *comment, '-j', 'ACCEPT')
        rule('filter', 'FORWARD', '-i', dev, '-o', veth, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', *comment, '-j', 'ACCEPT')
        root('ip', 'netns', 'exec', ns, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
        root('ip', 'netns', 'exec', ns, 'ip', 'tuntap', 'add', 'dev', 'ffvpn0', 'mode', 'tun', 'user', str(os.getuid()))
        root('ip', '-n', ns, 'addr', 'add', '198.18.78.2/32', 'dev', 'ffvpn0')
        root('ip', '-n', ns, 'link', 'set', 'ffvpn0', 'mtu', '1280', 'up')
        for prefix in ['198.18.78.1/32', '198.19.78.0/30']:
            root('ip', '-n', ns, 'route', 'add', prefix, 'dev', 'ffvpn0')
        summary.update(physical_interface=dev, gateway=gateway,
                       namespace_route=inside('ip', 'route', 'get', address).stdout,
                       forwarding_route=root('ip', 'route', 'get', address, 'from', client_ip, 'iif', veth).stdout)
        assert 'dev '+dev+' ' in summary['forwarding_route']
        capture_filter=f'host {address} and tcp and (port {port} or port 31992) and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'
        local_log = open(args.output/'physical-packets.log', 'w'); logs.append(local_log)
        p = subprocess.Popen(['sudo', '-n', 'tcpdump', '--immediate-mode', '-nn', '-l', '-i', dev, capture_filter],
                             stdout=local_log, stderr=local_log, start_new_session=True); processes.append(p)
        capture_unit = tag+'-capture'; capture_units.append(capture_unit)
        remote_log = open(args.output/'server-packets.log', 'w'); logs.append(remote_log)
        p = subprocess.Popen(['ssh', '-o', 'BatchMode=yes', remote, shlex.join([
            'systemd-run', '--quiet', '--pipe', '--wait', '--collect', '--unit', capture_unit,
            '--property', 'RuntimeMaxSec=1200', '--', 'tcpdump', '--immediate-mode', '-nn', '-l', '-i', 'any', capture_filter])],
            stdout=remote_log, stderr=remote_log); processes.append(p)
        deadline = time.monotonic()+20
        while 'listening on' not in (args.output/'server-packets.log').read_text():
            if p.poll() is not None or time.monotonic()>deadline: raise RuntimeError('remote capture not ready')
            time.sleep(.1)
        observer = subprocess.Popen(ns_cmd(sys.executable, '-c',
            'import json,socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),15); print(json.dumps(s.getsockname()),flush=True); sys.stdin.read()', address, port),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, text=True, env=env); processes.append(observer)
        local_socket = json.loads(observer.stdout.readline())
        peers = {line.split()[-1] for line in ssh('ss', '-tnH', 'state', 'established', 'sport', '=', ':'+port).stdout.splitlines()
                 if line.split()[-1].rsplit(':', 1)[-1] == str(local_socket[1])}
        assert len(peers) == 1, 'could not uniquely identify source on VPS'
        public_source = next(iter(peers)).rsplit(':', 1)[0]
        summary['marker_local_socket'] = local_socket
        assert ipaddress.ip_address(public_source).is_global
        observer.communicate('', timeout=5)
        summary['observed_source'] = public_source
        summary['server_return_route'] = ssh('ip', 'route', 'get', public_source).stdout
        ssh('mkdir', '-m', '755', remote_dir)
        remote_created = True
        run('scp', '-q', ROOT/'tests/vpn_physical_remote.py', ROOT/'tests/vpn_netns.py',
            ROOT/'tests/bench_stream.py', remote+':'+remote_dir+'/', timeout=45)
        remote_ready = True
        remote_helper('setup'); time.sleep(1)
        with NetworkPolicy(ns, 'ffvpn0') as policy:
            summary['network_policy'] = policy.snapshot
            # A proxy request to this VPS's own public IP is correctly rejected
            # by the production LOCAL destination firewall. Keep that policy.
            cases = [('direct', None)] + [(p, 'tun') for p in args.profiles]
            for profile, mode in cases:
                name = profile if mode is None else mode+'-'+profile
                client = None
                if mode:
                    client = launch(name, binary, 'client', '--server', f'{address}:{port}',
                        '--server-name', cfg['FOLDFIN_SERVER_NAME'], '--ca', args.configs/'singapore.pem',
                        *(['--tun', 'ffvpn0', '--vpn-local', '198.18.78.2', '--vpn-peer', '198.18.78.1',
                           '--vpn-peer-routes', '198.19.78.0/30'] if mode == 'tun' else []))
                    ready(client, name, 'configuration confirmed' if mode == 'tun' else 'SOCKS5 listening')
                if mode == 'tun':
                    echo = launch(name+'-echo', sys.executable, ROOT/'tests/vpn_netns.py', '--worker', 'echo',
                                  '--address', '198.18.78.2', '--expect-source', '198.19.78.2')
                    time.sleep(.3)
                    outputs = []
                    for target in ['198.18.78.1', '198.19.78.2']:
                        outputs.append(inside('ping', '-n', '-c', '2', '-W', '5', target, timeout=20).stdout)
                    outputs.append(inside(sys.executable, ROOT/'tests/vpn_netns.py', '--worker', 'probe',
                                          '--address', '198.19.78.2', timeout=60).stdout)
                    outputs.append(remote_helper('probe').stdout)
                    (args.output/(name+'-acceptance.log')).write_text('\n'.join(outputs))
                    summary['acceptance'][profile] = {'ipv4_tcp_udp_dns_icmp_reverse': True}
                    stop(echo)
                    print(name+': routed IPv4 acceptance PASS', flush=True); save()
                if not args.accept_only:
                    for repeat in range(args.repeats):
                        for direction in ['upload', 'download']:
                            label = f'{name}-{repeat+1}-{direction}'
                            result = transfer(label, sys.executable, ROOT/'tests/bench_stream.py',
                                '--address', '198.18.78.1' if mode == 'tun' else address,
                                '--direction', direction, '--seconds', args.seconds,
                                *(['--socks', '1080'] if mode == 'proxy' else []))
                            (args.output/(label+'-stdout.log')).write_text(result.stdout)
                            (args.output/(label+'-stderr.log')).write_text(result.stderr)
                            assert result.returncode == 0, f'{label} failed; raw output retained'
                            data = json.loads(result.stdout); assert data['integrity']
                            (args.output/(label+'.json')).write_text(json.dumps(data, indent=2))
                            record = {'profile': profile, 'mode': mode, 'direction': direction,
                                      'repeat': repeat+1, **data}
                            summary['results'].append(record); save()
                            print(f'{label}: {data["mbps"]:.2f} Mbps', flush=True)
                if client: stop(client)
                time.sleep(.5)
            summary['tcp_client_final'] = inside('ss', '-tinm').stdout
            summary['links_client_final'] = root('ip', '-n', ns, '-j', '-s', 'link').stdout
            summary['links_server_final'] = ssh('ip', '-j', '-s', 'link', 'show', 'ffvpn0').stdout
        assert not policy.snapshot['rollback_errors']
        summary['finished'] = True
    except BaseException as error:
        summary['error'] = str(error)
        raise
    finally:
        errors = []
        if remote_ready:
            try: remote_helper('cleanup')
            except Exception as error: errors.append('remote responder: '+str(error))
        for unit in capture_units:
            try: ssh('systemctl', 'stop', unit)
            except Exception as error: errors.append('capture: '+str(error))
        for p in processes:
            try:
                if p.poll() is None:
                    p.terminate()
                    try: p.wait(timeout=5)
                    except subprocess.TimeoutExpired: p.kill(); p.wait(timeout=5)
            except Exception as error: errors.append('process: '+str(error))
        pids = root('ip', 'netns', 'pids', ns, check=False).stdout.split()
        if pids: root('kill', '-KILL', *pids, check=False)
        for rollback in reversed(undo):
            try: rollback()
            except Exception as error: errors.append('local network: '+str(error))
        if remote_created:
            try: ssh('rm', '-rf', '--', remote_dir)
            except Exception as error: errors.append('remote files: '+str(error))
        for log in logs: log.close()
        summary['cleanup_errors'] = errors
        summary['cleanup'] = not errors and ns not in root('ip', 'netns', 'list').stdout.split()
        summary['host_default_routes_after'] = run('ip', '-j', 'route', 'show', 'default', 'table', 'main').stdout
        summary['host_tcp_wmem_after'] = run('sysctl', '-n', 'net.ipv4.tcp_wmem').stdout.strip()
        summary['server_tcp_wmem_after'] = ssh('sysctl', '-n', 'net.ipv4.tcp_wmem').stdout.strip()
        summary['server_active_after'] = ssh('systemctl', 'is-active', 'foldfin').stdout.strip()
        save()
        if not summary['cleanup']: raise RuntimeError('WAN cleanup failed: '+str(errors))
    assert summary['host_default_routes_before'] == summary['host_default_routes_after']
    assert summary['host_tcp_wmem_before'] == summary['host_tcp_wmem_after']
    assert summary['server_tcp_wmem'] == summary['server_tcp_wmem_after']
    assert summary['server_active_after'] == 'active'
    local_text, remote_text = (args.output/'physical-packets.log').read_text(), (args.output/'server-packets.log').read_text()
    assert public_source in remote_text and address in local_text, 'physical capture evidence missing'
    print('WAN acceptance/benchmark and cleanup PASS: '+str(args.output), flush=True)


if __name__ == '__main__':
    main()
