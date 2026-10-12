#!/usr/bin/env python3
"""Real TUN acceptance in disposable Linux namespaces; host routes stay untouched."""
import argparse
import concurrent.futures
import contextlib
import json
import os
import pathlib
import secrets
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCRIPT = pathlib.Path(__file__).resolve()

@contextlib.contextmanager
def diagnostics(directory, output=None, snapshot=None):
    try:
        yield
    except BaseException:
        if snapshot:
            snapshot()
        for name in ['server.log', 'client.log', 'echo.log']:
            print(f'{name}:\n{(directory/name).read_text()}', file=sys.stderr)
        raise
    finally:
        if output:
            for file in directory.glob('*.log'):
                shutil.copyfile(file, output/file.name)


def worker(role, address, expected_source=None):
    family = socket.AF_INET6 if ':' in address else socket.AF_INET
    if role == 'echo':
        tcp = socket.socket(family); tcp.bind((address, 31991)); tcp.listen()
        def handle(connection):
            with connection:
                payload = bytearray()
                while chunk := connection.recv(65536): payload.extend(chunk)
                connection.sendall(payload)
        def udp_loop(port, dns=False):
            with socket.socket(family, socket.SOCK_DGRAM) as udp:
                udp.bind((address, port))
                while True:
                    data, peer = udp.recvfrom(65536)
                    if expected_source:
                        assert peer[0] == expected_source, f'UDP source changed: {peer[0]}'
                    if dns:
                        # Standard single-question A response; input is test-generated.
                        data = data[:2] + b'\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00' + data[12:] + b'\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x01\x00\x04\xc6\x12\x00\x01'
                    udp.sendto(data, peer)
        for port, dns in [(31992, False), (31993, True)]:
            threading.Thread(target=udp_loop, args=(port, dns), daemon=True).start()
        while True:
            connection, peer = tcp.accept()
            if expected_source:
                assert peer[0] == expected_source, f'TCP source changed: {peer[0]}'
            threading.Thread(target=handle, args=(connection,), daemon=True).start()
    elif role == 'probe':
        def transfer(index):
            payload = bytes([index + 1]) * (512 * 1024)
            with socket.socket(family) as tcp:
                tcp.settimeout(12); tcp.connect((address, 31991))
                tcp.sendall(payload); tcp.shutdown(socket.SHUT_WR)
                result = bytearray()
                while chunk := tcp.recv(65536): result.extend(chunk)
                assert result == payload, 'TCP payload/half-close mismatch'
        with concurrent.futures.ThreadPoolExecutor(max_workers=4) as pool:
            list(pool.map(transfer, range(4)))
        with socket.socket(family, socket.SOCK_DGRAM) as udp:
            udp.settimeout(5)
            for size in [1, 100, 1200]:
                data = secrets.token_bytes(size); udp.sendto(data, (address, 31992))
                assert udp.recv(65536) == data, 'UDP mismatch'
            query = b'\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07foldfin\x04test\x00\x00\x01\x00\x01'
            udp.sendto(query, (address, 31993)); result = udp.recv(65536)
            assert result[:2] == query[:2] and result[2:4] == b'\x81\x80' and result[-4:] == b'\xc6\x12\x00\x01', 'DNS mismatch'
        print(f'{address}: 4 parallel TCP/FIN, UDP, DNS OK', flush=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--no-build', action='store_true', help='Reuse the current debug binaries')
    parser.add_argument('--binary', type=pathlib.Path, help='Use one already-built foldfin CLI for both roles')
    parser.add_argument('--output', type=pathlib.Path, help='Retain logs and packet metadata, without TLS keys')
    parser.add_argument('--routed', action='store_true', help='Add a third node behind the server')
    parser.add_argument('--worker', choices=['echo', 'probe'])
    parser.add_argument('--address')
    parser.add_argument('--expect-source')
    args = parser.parse_args()
    if args.worker:
        worker(args.worker, args.address, args.expect_source); return
    if args.binary:
        args.binary = args.binary.resolve(strict=True)
    if args.output:
        args.output.mkdir(parents=True, exist_ok=False)
        args.output.chmod(0o700)
    subprocess.run(['sudo', '-n', 'true'], check=True)
    build = ['cargo', 'build', '--bins']
    if not args.no_build and not args.binary:
        subprocess.run(build, cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    binaries = pathlib.Path(metadata['target_directory']) / 'debug'
    suffix = secrets.token_hex(4)
    namespaces = [f'foldfin-c-{suffix}', f'foldfin-s-{suffix}']
    created = []
    processes = []
    env = dict(os.environ, FOLDFIN_TOKEN=secrets.token_hex(32))
    def privileged(*cmd, **kwargs):
        return subprocess.run(['sudo', '-n', *cmd], check=True, **kwargs)
    def ns_cmd(ns, *cmd):
        return ['sudo', '-n', '--preserve-env=FOLDFIN_TOKEN', 'ip', 'netns', 'exec', ns,
                'setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()), '--clear-groups', *map(str, cmd)]
    def run(ns, *cmd):
        return subprocess.run(ns_cmd(ns, *cmd), check=True, env=env, timeout=45)
    def launch(ns, log, *cmd, environment=None):
        if args.binary and cmd[0] in [binaries/'server', binaries/'client']:
            cmd = (args.binary, pathlib.Path(cmd[0]).name, *cmd[1:])
        process = subprocess.Popen(ns_cmd(ns, *cmd), env=environment or env, stdout=log, stderr=log)
        processes.append(process); return process
    def snapshot():
        if not args.output:
            return
        for ns in created:
            for label, cmd in [('tcp', ['ss', '-tinm']), ('links', ['ip', '-s', 'link']),
                               ('routes', ['ip', 'route', 'show']), ('routes6', ['ip', '-6', 'route', 'show'])]:
                result = subprocess.run(['sudo', '-n', 'ip', 'netns', 'exec', ns, *cmd],
                                        capture_output=True, text=True, timeout=10)
                (args.output/(ns+'-'+label+'.txt')).write_text(result.stdout+result.stderr)
        pids = [str(p.pid) for p in processes if p.poll() is None]
        if pids:
            result = subprocess.run(['ps', '-p', ','.join(pids), '-o', 'pid,pcpu,stat,comm'],
                                    capture_output=True, text=True, timeout=10)
            (args.output/'processes.txt').write_text(result.stdout)
    try:
        with tempfile.TemporaryDirectory(prefix='foldfin-vpn-') as tmp:
            tmp = pathlib.Path(tmp)
            cert, key = tmp/'cert.pem', tmp/'key.pem'
            subprocess.run(['openssl', 'req', '-x509', '-newkey', 'rsa:2048', '-nodes', '-days', '1',
                '-keyout', str(key), '-out', str(cert), '-subj', '/CN=localhost',
                '-addext', 'subjectAltName=DNS:localhost', '-addext', 'basicConstraints=critical,CA:FALSE',
                '-addext', 'extendedKeyUsage=serverAuth'], check=True, capture_output=True)
            for ns in namespaces:
                privileged('ip', 'netns', 'add', ns); created.append(ns)
                privileged('ip', '-n', ns, 'link', 'set', 'lo', 'up')
                privileged('ip', 'netns', 'exec', ns, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
            client_ns, server_ns = namespaces
            # Create both veth ends directly in namespaces; no host network interface.
            privileged('ip', 'link', 'add', 'mc0', 'netns', client_ns, 'type', 'veth',
                       'peer', 'name', 'ms0', 'netns', server_ns)
            for ns, dev, outer, inner4, inner6 in [
                (client_ns, 'mc0', '192.0.2.1/30', '198.18.0.1/32', 'fd42:6d69:6d69::1/128'),
                (server_ns, 'ms0', '192.0.2.2/30', '198.18.0.2/32', 'fd42:6d69:6d69::2/128'),
            ]:
                privileged('ip', '-n', ns, 'addr', 'add', outer, 'dev', dev)
                privileged('ip', '-n', ns, 'link', 'set', dev, 'up')
                privileged('ip', 'netns', 'exec', ns, 'ip', 'tuntap', 'add', 'dev', 'ffvpn0', 'mode', 'tun', 'user', str(os.getuid()))
                privileged('ip', '-n', ns, 'addr', 'add', inner4, 'dev', 'ffvpn0')
                privileged('ip', '-n', ns, '-6', 'addr', 'add', inner6, 'dev', 'ffvpn0', 'nodad')
                privileged('ip', '-n', ns, 'link', 'set', 'ffvpn0', 'mtu', '1500', 'up')
                privileged('ip', '-n', ns, 'route', 'add', '198.18.0.0/24', 'dev', 'ffvpn0')
                privileged('ip', '-n', ns, '-6', 'route', 'add', 'fd42:6d69:6d69::/64', 'dev', 'ffvpn0')
            routed4, routed6 = '198.19.0.2', 'fd42:6d69:6c61::2'
            if args.routed:
                lan_ns = f'foldfin-l-{suffix}'
                privileged('ip', 'netns', 'add', lan_ns); created.append(lan_ns)
                privileged('ip', '-n', lan_ns, 'link', 'set', 'lo', 'up')
                privileged('ip', 'netns', 'exec', lan_ns, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
                privileged('ip', 'link', 'add', 'mls0', 'netns', server_ns, 'type', 'veth', 'peer', 'name', 'ml0', 'netns', lan_ns)
                for ns, dev, addr4, addr6 in [(server_ns, 'mls0', '198.19.0.1/24', 'fd42:6d69:6c61::1/64'),
                                             (lan_ns, 'ml0', routed4+'/24', routed6+'/64')]:
                    privileged('ip', '-n', ns, 'addr', 'add', addr4, 'dev', dev)
                    privileged('ip', '-n', ns, '-6', 'addr', 'add', addr6, 'dev', dev, 'nodad')
                    privileged('ip', '-n', ns, 'link', 'set', dev, 'up')
                privileged('ip', 'netns', 'exec', server_ns, 'sysctl', '-q', '-w', 'net.ipv4.ip_forward=1', 'net.ipv6.conf.all.forwarding=1')
                privileged('ip', '-n', client_ns, 'route', 'add', '198.19.0.0/24', 'dev', 'ffvpn0')
                privileged('ip', '-n', client_ns, '-6', 'route', 'add', 'fd42:6d69:6c61::/64', 'dev', 'ffvpn0')
                privileged('ip', '-n', lan_ns, 'route', 'add', '198.18.0.0/24', 'via', '198.19.0.1')
                privileged('ip', '-n', lan_ns, '-6', 'route', 'add', 'fd42:6d69:6d69::/64', 'via', 'fd42:6d69:6c61::1')
            if args.output:
                for ns in namespaces:
                    with open(args.output/(ns+'-packets.log'), 'w') as log:
                        processes.append(subprocess.Popen(
                            ['sudo', '-n', 'ip', 'netns', 'exec', ns, 'tcpdump',
                             '--immediate-mode', '-nn', '-l', '-i', 'any'],
                            stdout=log, stderr=log))
            with open(tmp/'server.log', 'w+') as server_log, open(tmp/'client.log', 'w+') as client_log, open(tmp/'echo.log', 'w+') as echo_log, diagnostics(tmp, args.output, snapshot):
                server = launch(server_ns, server_log, binaries/'server', '--listen', '192.0.2.2:8443', '--cert', cert, '--key', key,
                    '--tun', 'ffvpn0', '--vpn-local', '198.18.0.2,fd42:6d69:6d69::2', '--vpn-peer', '198.18.0.1,fd42:6d69:6d69::1',
                    *(['--vpn-local-routes', '198.19.0.0/24,fd42:6d69:6c61::/64'] if args.routed else []))
                def wait_log(path, needle, process):
                    deadline = time.monotonic() + 15
                    while time.monotonic() < deadline:
                        if process.poll() is not None: raise RuntimeError(path.read_text())
                        if needle in path.read_text(): return
                        time.sleep(.05)
                    raise TimeoutError(path.read_text())
                wait_log(tmp/'server.log', 'listening on', server)
                client_args = [binaries/'client', '--server', '192.0.2.2:8443', '--server-name', 'localhost', '--ca', cert,
                    '--tun', 'ffvpn0', '--vpn-local', '198.18.0.1,fd42:6d69:6d69::1', '--vpn-peer', '198.18.0.2,fd42:6d69:6d69::2']
                if args.routed: client_args += ['--vpn-peer-routes', '198.19.0.0/24,fd42:6d69:6c61::/64']
                client = launch(client_ns, client_log, *client_args)
                wait_log(tmp/'client.log', 'CONNECT-IP ready', client)
                wait_log(tmp/'client.log', 'configuration confirmed', client)
                with open(tmp/'rejected.log', 'w+') as rejected_log:
                    bad = launch(client_ns, rejected_log, *client_args,
                                 environment=dict(env, FOLDFIN_TOKEN=secrets.token_hex(32)))
                    assert bad.wait(timeout=20) != 0, 'wrong VPN token accepted'
                    duplicate = launch(client_ns, rejected_log, *client_args)
                    assert duplicate.wait(timeout=20) != 0, 'second static peer session accepted'
                    assert 'IP tunnel rejected' in (tmp/'rejected.log').read_text()
                for ns, addresses in [(client_ns, ['198.18.0.1', 'fd42:6d69:6d69::1']), (server_ns, ['198.18.0.2', 'fd42:6d69:6d69::2'])]:
                    for address in addresses:
                        launch(ns, echo_log, sys.executable, SCRIPT, '--worker', 'echo', '--address', address)
                if args.routed:
                    for address in [routed4, routed6]:
                        launch(lan_ns, echo_log, sys.executable, SCRIPT, '--worker', 'echo', '--address', address)
                time.sleep(.2)
                for ns, addresses in [(client_ns, ['198.18.0.2', 'fd42:6d69:6d69::2']), (server_ns, ['198.18.0.1', 'fd42:6d69:6d69::1'])]:
                    for address in addresses:
                        run(ns, 'ping', '-n', '-c', '2', '-W', '3', address)
                        # Exercise the IPv6 minimum MTU (1280-byte inner packet).
                        run(ns, 'ping', '-n', '-c', '1', '-W', '3', '-s', '1232' if ':' in address else '1472', address)
                        run(ns, sys.executable, SCRIPT, '--worker', 'probe', '--address', address)
                if args.routed:
                    for address in [routed4, routed6]:
                        run(client_ns, 'ping', '-n', '-c', '2', '-W', '3', address)
                        run(client_ns, sys.executable, SCRIPT, '--worker', 'probe', '--address', address)
                    for address in ['198.18.0.1', 'fd42:6d69:6d69::1']:
                        run(lan_ns, 'ping', '-n', '-c', '2', '-W', '3', address)
                        run(lan_ns, sys.executable, SCRIPT, '--worker', 'probe', '--address', address)
                    # A smaller routed link must report MTU errors back through the tunnel.
                    privileged('ip', '-n', server_ns, 'link', 'set', 'mls0', 'mtu', '1280')
                    # veth is a link, so both ends need the same MTU. Leaving
                    # the LAN end at 1500 drops return frames at the veth layer
                    # before IP forwarding can generate a PMTU error.
                    privileged('ip', '-n', lan_ns, 'link', 'set', 'ml0', 'mtu', '1280')
                    for address, size in [(routed4, '1472'), (routed6, '1452')]:
                        result = subprocess.run(ns_cmd(client_ns, 'ping', '-n', '-c', '1', '-W', '3', '-M', 'do', '-s', size, address),
                                                env=env, capture_output=True, text=True, timeout=10)
                        assert result.returncode != 0 and '1280' in result.stdout + result.stderr, result.stdout + result.stderr
                        run(client_ns, sys.executable, SCRIPT, '--worker', 'probe', '--address', address)
                    privileged('ip', '-n', server_ns, 'link', 'set', 'mls0', 'mtu', '1500')
                    privileged('ip', '-n', lan_ns, 'link', 'set', 'ml0', 'mtu', '1500')
                # Impair only the carrier interface, leaving the inner TUN untouched.
                privileged('ip', 'netns', 'exec', client_ns, 'tc', 'qdisc', 'add', 'dev', 'mc0', 'root', 'netem', 'delay', '10ms', 'loss', '1%')
                run(client_ns, sys.executable, SCRIPT, '--worker', 'probe', '--address', '198.18.0.2')
                privileged('ip', 'netns', 'exec', client_ns, 'tc', 'qdisc', 'del', 'dev', 'mc0', 'root')
                # Carrier loss must release the exclusive server TUN session.
                pids = subprocess.check_output(['sudo', '-n', 'ip', 'netns', 'pids', client_ns], text=True).split()
                privileged('kill', '-TERM', *pids)
                client.wait(timeout=10)
                for attempt in range(2):
                    try:
                        client = launch(client_ns, client_log, *client_args)
                        time.sleep(.3)
                        if client.poll() is None: break
                    except Exception:
                        if attempt: raise
                assert client.poll() is None, (tmp/'client.log').read_text()
                run(client_ns, 'ping', '-n', '-c', '2', '-W', '3', '198.18.0.2')
                snapshot()
                print('VPN namespace acceptance passed: dual-stack bidirectional IP, loss/delay, carrier cleanup', flush=True)
    finally:
        for ns in reversed(created):
            pids = subprocess.check_output(['sudo', '-n', 'ip', 'netns', 'pids', ns], text=True).split()
            if pids: subprocess.run(['sudo', '-n', 'kill', '-KILL', *pids], check=False)
            privileged('ip', 'netns', 'del', ns)
        for process in processes:
            process.wait(timeout=10)

if __name__ == '__main__':
    main()
