#!/usr/bin/env python3
"""Real routed VPN acceptance on Frankfurt only; local host routes are unchanged."""
import argparse
import json
import os
import pathlib
import secrets
import shlex
import socket
import subprocess
import sys
import tempfile
import threading
import time

from vps import configuration

ROOT = pathlib.Path(__file__).resolve().parents[1]


def copy_stream(source, destination):
    try:
        while data := source.recv(65536): destination.sendall(data)
        destination.shutdown(socket.SHUT_WR)
    except OSError:
        pass


def bridge(left, right):
    with left, right:
        thread = threading.Thread(target=copy_stream, args=(left, right), daemon=True)
        thread.start(); copy_stream(right, left); thread.join()


def relay_worker(path):
    # Inside the disposable namespace. Unix sockets keep outer TLS bytes on the
    # host's existing internet connection, without host forwarding/NAT changes.
    with socket.socket() as listener:
        listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        listener.bind(('127.0.0.1', 18445)); listener.listen()
        print('relay ready', flush=True)
        while True:
            connection, _ = listener.accept(); connection.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            upstream = socket.socket(socket.AF_UNIX); upstream.connect(path)
            threading.Thread(target=bridge, args=(connection, upstream), daemon=True).start()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--chrome-tls', action='store_true')
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--configs', type=pathlib.Path, default=ROOT.parent.parent/'cloud-forge/generated_configs/foldfin')
    parser.add_argument('--relay')
    args = parser.parse_args()
    if args.relay: relay_worker(args.relay); return
    raise SystemExit('Historical Frankfurt relay acceptance is disabled. Use tests/vpn_physical.py for physical Singapore acceptance or tests/vpn_netns.py locally.')
    subprocess.run(['sudo', '-n', 'true'], check=True)
    if not args.no_build:
        build = ['cargo', 'build', '--bin', 'client']
        if args.chrome_tls: build += ['--features', 'chrome-tls']
        subprocess.run(build, cwd=ROOT, check=True)
    metadata = json.loads(subprocess.check_output(['cargo', 'metadata', '--no-deps', '--format-version', '1'], cwd=ROOT))
    binary = pathlib.Path(metadata['target_directory'])/'debug/client'
    config = configuration(args.configs, 'europe')
    assert config['FOLDFIN_SERVER_NAME'] == 'eu.okhsunrog.dev', 'Frankfurt only'
    endpoint_host, endpoint_port = config['FOLDFIN_SERVER'].rsplit(':', 1)
    ssh_host = 'root@' + config['FOLDFIN_SERVER_NAME']
    suffix = secrets.token_hex(4)
    namespace = 'foldfin-live-' + suffix
    remote = '/tmp/foldfin-vpn-' + suffix
    processes = []
    created = False
    remote_created = False
    stop = threading.Event()
    def ssh(*cmd):
        return subprocess.run(['ssh', '-o', 'BatchMode=yes', ssh_host, shlex.join(map(str, cmd))], check=True, timeout=45)
    def privileged(*cmd):
        return subprocess.run(['sudo', '-n', *map(str, cmd)], check=True)
    def ns_cmd(*cmd):
        return ['sudo', '-n', '--preserve-env=FOLDFIN_TOKEN', 'ip', 'netns', 'exec', namespace,
                'setpriv', '--reuid', str(os.getuid()), '--regid', str(os.getgid()), '--clear-groups', *map(str, cmd)]
    env = dict(os.environ, FOLDFIN_TOKEN=config['FOLDFIN_TOKEN'])
    try:
        with tempfile.TemporaryDirectory(prefix='foldfin-live-') as tmp:
            tmp = pathlib.Path(tmp); unix_path = str(tmp/'carrier.sock')
            with socket.socket(socket.AF_UNIX) as listener:
                listener.bind(unix_path); listener.listen(); listener.settimeout(.2)
                def accept():
                    while not stop.is_set():
                        try: connection, _ = listener.accept()
                        except socket.timeout: continue
                        except OSError: return
                        try:
                            upstream = socket.create_connection((endpoint_host, int(endpoint_port)), timeout=15)
                            upstream.settimeout(None); upstream.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                            threading.Thread(target=bridge, args=(connection, upstream), daemon=True).start()
                        except OSError: connection.close()
                relay_thread = threading.Thread(target=accept, daemon=True); relay_thread.start()
                ssh('mkdir', '-m', '755', remote); remote_created = True
                subprocess.run(['scp', '-q', str(ROOT/'tests/vpn_vps_remote.py'), str(ROOT/'tests/vpn_netns.py'), ssh_host+':'+remote+'/'], check=True, timeout=30)
                ssh('python3', remote+'/vpn_vps_remote.py', 'setup', suffix)
                privileged('ip', 'netns', 'add', namespace); created = True
                privileged('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
                privileged('ip', 'netns', 'exec', namespace, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
                privileged('ip', 'netns', 'exec', namespace, 'ip', 'tuntap', 'add', 'dev', 'ffvpn0', 'mode', 'tun', 'user', os.getuid())
                privileged('ip', '-n', namespace, 'addr', 'add', '198.18.77.2/32', 'dev', 'ffvpn0')
                privileged('ip', '-n', namespace, 'link', 'set', 'ffvpn0', 'mtu', '1500', 'up')
                for route in ['198.18.77.1/32', '198.19.77.0/30']:
                    privileged('ip', '-n', namespace, 'route', 'add', route, 'dev', 'ffvpn0')
                with open(tmp/'client.log', 'w+') as log:
                    def launch(*cmd):
                        p = subprocess.Popen(ns_cmd(*cmd), env=env, stdout=log, stderr=log); processes.append(p); return p
                    def wait(marker, process):
                        deadline = time.monotonic()+20
                        while time.monotonic() < deadline:
                            if process.poll() is not None: raise RuntimeError((tmp/'client.log').read_text())
                            if marker in (tmp/'client.log').read_text(): return
                            time.sleep(.05)
                        raise TimeoutError((tmp/'client.log').read_text())
                    relay = launch(sys.executable, pathlib.Path(__file__).resolve(), '--relay', unix_path)
                    wait('relay ready', relay)
                    client_args = [binary, '--server', '127.0.0.1:18445', '--server-name', config['FOLDFIN_SERVER_NAME'],
                        '--ca', args.configs/'europe.pem', '--tun', 'ffvpn0', '--vpn-local', '198.18.77.2',
                        '--vpn-peer', '198.18.77.1', '--vpn-peer-routes', '198.19.77.0/30']
                    if args.chrome_tls: client_args += ['--chrome-tls']
                    client = launch(*client_args); wait('configuration confirmed', client)
                    echo = launch(sys.executable, ROOT/'tests/vpn_netns.py', '--worker', 'echo', '--address', '198.18.77.2', '--expect-source', '198.19.77.2')
                    time.sleep(.2)
                    for address in ['198.18.77.1', '198.19.77.2']:
                        subprocess.run(ns_cmd('ping', '-n', '-c', '2', '-W', '5', address), check=True, env=env, timeout=20)
                    subprocess.run(ns_cmd(sys.executable, ROOT/'tests/vpn_netns.py', '--worker', 'probe', '--address', '198.19.77.2'), check=True, env=env, timeout=45)
                    ssh('python3', remote+'/vpn_vps_remote.py', 'probe', suffix)
                    assert client.poll() is None and echo.poll() is None
                    print('PASS Frankfurt VPN: public TLS/H2 carrier, capsules, routed TCP/UDP/DNS/ICMP and reverse TCP/UDP/DNS; addresses preserved, no NAT', flush=True)
                    stop.set()
                relay_thread.join(timeout=1)
    finally:
        stop.set()
        if created:
            pids = subprocess.check_output(['sudo', '-n', 'ip', 'netns', 'pids', namespace], text=True).split()
            if pids: subprocess.run(['sudo', '-n', 'kill', '-KILL', *pids], check=False)
            privileged('ip', 'netns', 'del', namespace)
        for process in processes: process.wait(timeout=10)
        if remote_created:
            try: ssh('python3', remote+'/vpn_vps_remote.py', 'cleanup', suffix)
            finally: ssh('rm', '-rf', '--', remote)

if __name__ == '__main__': main()
