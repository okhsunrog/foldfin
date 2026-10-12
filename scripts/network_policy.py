#!/usr/bin/env python3
"""Apply temporary TUN/TCP policy in a named isolated namespace, then restore it.

No routes, DNS, socket flags or host sysctls are changed. This is a platform
adapter; the Rust packet library does not own network configuration.
"""
import argparse
import json
import os
from pathlib import Path
import re
import signal
import subprocess


class NetworkPolicy:
    def __init__(self, namespace, tun=None, tun_queue=10000, tcp_wmem_max=33554432):
        if not re.fullmatch(r'[a-zA-Z0-9_-]{1,64}', namespace):
            raise ValueError('invalid namespace name')
        if tun and not re.fullmatch(r'[a-zA-Z0-9_-]{1,15}', tun):
            raise ValueError('invalid TUN name')
        if not 100 <= tun_queue <= 20000 or not 4194304 <= tcp_wmem_max <= 67108864:
            raise ValueError('network policy outside allowed bounds')
        self.namespace, self.tun = namespace, tun
        self.tun_queue, self.tcp_wmem_max = tun_queue, tcp_wmem_max
        self.path = Path('/run/netns') / namespace
        self.identity = None
        self.undo = []
        self.snapshot = {}

    def command(self, *args):
        return subprocess.check_output(['sudo', '-n', 'ip', 'netns', 'exec',
                                        self.namespace, *map(str, args)], text=True).strip()

    @staticmethod
    def file_identity(path):
        try:
            state = os.stat(path)
            return state.st_dev, state.st_ino
        except PermissionError:
            return tuple(map(int, subprocess.check_output(
                ['sudo', '-n', 'stat', '-Lc', '%d:%i', str(path)], text=True).strip().split(':')))

    def check_identity(self):
        if self.file_identity(self.path) != self.identity:
            raise RuntimeError('namespace was replaced; refusing to alter it')

    def link(self):
        self.check_identity()
        return json.loads(self.command('ip', '-j', '-d', 'link', 'show', 'dev', self.tun))[0]

    def wmem(self):
        self.check_identity()
        return tuple(map(int, self.command('sysctl', '-n', 'net.ipv4.tcp_wmem').split()))

    def __enter__(self):
        self.identity = self.file_identity(self.path)
        if self.identity in [self.file_identity('/proc/self/ns/net'),
                             self.file_identity('/proc/1/ns/net')]:
            raise RuntimeError('host network namespace is forbidden')
        previous = self.wmem()
        desired = (*previous[:2], max(previous[2], self.tcp_wmem_max))
        before = self.link() if self.tun else None
        if before and (before.get('linkinfo', {}).get('info_kind') != 'tun'
                       or before.get('linkinfo', {}).get('info_data', {}).get('type') != 'tun'):
            raise RuntimeError('policy requires an existing TUN interface')
        self.snapshot = {'namespace': self.namespace, 'tcp_wmem_before': previous,
                         'tcp_wmem_applied': desired, 'tun_queue_before':
                         before['txqlen'] if before else None,
                         'tun_queue_applied': self.tun_queue if before else None}
        try:
            if before and before['txqlen'] != self.tun_queue:
                self.undo.append(('tun', before['ifindex'], before['txqlen']))
                self.command('ip', 'link', 'set', 'dev', self.tun, 'txqueuelen', self.tun_queue)
                assert self.link()['txqlen'] == self.tun_queue
            if previous != desired:
                self.undo.append(('wmem', desired, previous))
                self.command('sysctl', '-q', '-w', 'net.ipv4.tcp_wmem='+' '.join(map(str, desired)))
                assert self.wmem() == desired
            return self
        except BaseException:
            self.rollback()
            raise

    def rollback(self):
        errors = []
        for kind, identity, previous in reversed(self.undo):
            try:
                if not self.path.exists():
                    continue  # namespace destruction already discarded its settings
                self.check_identity()
                if kind == 'wmem':
                    current = self.wmem()
                    if current == identity:
                        self.command('sysctl', '-q', '-w', 'net.ipv4.tcp_wmem='+' '.join(map(str, previous)))
                    elif current != previous:
                        raise RuntimeError('tcp_wmem changed externally; leaving it untouched')
                else:
                    current = self.link()
                    if current['ifindex'] != identity:
                        raise RuntimeError('TUN was replaced; leaving it untouched')
                    if current['txqlen'] == self.tun_queue:
                        self.command('ip', 'link', 'set', 'dev', self.tun, 'txqueuelen', previous)
                    elif current['txqlen'] != previous:
                        raise RuntimeError('TUN queue changed externally; leaving it untouched')
            except Exception as error:
                errors.append(str(error))
        self.undo.clear()
        self.snapshot['rollback_errors'] = errors
        if errors:
            raise RuntimeError('network rollback failed: '+'; '.join(errors))

    def __exit__(self, *_):
        self.rollback()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--namespace', required=True)
    parser.add_argument('--tun')
    parser.add_argument('--tun-queue', type=int, default=10000)
    parser.add_argument('--tcp-wmem-max', type=int, default=33554432)
    parser.add_argument('--report', type=Path)
    parser.add_argument('command', nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ['--'] else args.command
    if not command:
        parser.error('a command after -- is required')
    def interrupted(*_):
        raise KeyboardInterrupt
    signal.signal(signal.SIGTERM, interrupted)
    policy = NetworkPolicy(args.namespace, args.tun, args.tun_queue, args.tcp_wmem_max)
    try:
        with policy:
            child = subprocess.Popen(['sudo', '-n', 'ip', 'netns', 'exec', args.namespace, *command],
                                     start_new_session=True)
            try:
                code = child.wait()
            except BaseException:
                subprocess.run(['sudo', '-n', 'kill', '-TERM', '--', '-'+str(child.pid)],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    subprocess.run(['sudo', '-n', 'kill', '-KILL', '--', '-'+str(child.pid)],
                                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                    child.wait(timeout=5)
                raise
    finally:
        if args.report:
            args.report.write_text(json.dumps(policy.snapshot, indent=2))
    raise SystemExit(code)


if __name__ == '__main__':
    main()
