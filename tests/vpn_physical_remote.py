#!/usr/bin/env python3
"""Singapore-only temporary routed responder and throughput endpoint."""
import argparse
from pathlib import Path
import re
import subprocess
import sys


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('operation', choices=['setup', 'probe', 'cleanup'])
    parser.add_argument('suffix')
    parser.add_argument('--source')
    args = parser.parse_args()
    assert re.fullmatch('[a-f0-9]{8}', args.suffix)
    tag = 'foldfin-wan-'+args.suffix
    ns, link = 'fflan-'+args.suffix, 'ffl'+args.suffix
    root = Path(__file__).resolve().parent
    def run(*cmd, check=True):
        return subprocess.run(list(map(str, cmd)), check=check, capture_output=True, text=True)
    # No credentials or global sysctl changes; all firewall changes have this tag.
    def rules():
        assert args.source and re.fullmatch(r'([0-9]{1,3}\.){3}[0-9]{1,3}', args.source)
        return [('-s', args.source+'/32', '-p', 'tcp', '--dport', '31992',
                 '-m', 'comment', '--comment', tag, '-j', 'ACCEPT'),
                ('-i', 'ffvpn0', '-s', '198.18.78.2/32', '-d', '198.18.78.1/32',
                 '-p', 'tcp', '--dport', '31992', '-m', 'comment', '--comment', tag, '-j', 'ACCEPT')]
    def cleanup():
        for unit in [tag+'-stream', tag+'-lan']:
            run('systemctl', 'stop', unit, check=False)
        for rule in rules():
            if run('iptables', '-w', '-C', 'INPUT', *rule, check=False).returncode == 0:
                run('iptables', '-w', '-D', 'INPUT', *rule)
        names = run('ip', 'netns', 'list').stdout.split()
        if ns in names:
            pids = run('ip', 'netns', 'pids', ns).stdout.split()
            if pids: run('kill', '-KILL', *pids)
            run('ip', 'netns', 'del', ns)
    if args.operation == 'cleanup':
        cleanup(); return
    if args.operation == 'probe':
        result = run('ip', 'netns', 'exec', ns, 'runuser', '-u', 'foldfin', '--',
                     'uv', 'run', '--no-project', '--no-cache', '--no-config', '--directory', root,
                     'python3', root/'vpn_netns.py',
                     '--worker', 'probe', '--address', '198.18.78.2')
        print(result.stdout, end=''); return
    assert '198.18.78.1' in run('ip', '-4', 'addr', 'show', 'ffvpn0').stdout
    assert not run('ip', 'route', 'show', '198.19.78.0/30').stdout.strip(), 'LAN prefix already in use'
    assert not run('ss', '-ltnH', 'sport', '=', ':31992').stdout.strip(), 'benchmark port already in use'
    assert run('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == '1'
    run('ip', 'netns', 'add', ns)
    try:
        run('ip', '-n', ns, 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'exec', ns, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
        run('ip', 'link', 'add', link, 'type', 'veth', 'peer', 'name', 'lan0', 'netns', ns)
        run('ip', 'addr', 'add', '198.19.78.1/30', 'dev', link)
        run('ip', 'link', 'set', link, 'mtu', '1280', 'up')
        run('ip', '-n', ns, 'addr', 'add', '198.19.78.2/30', 'dev', 'lan0')
        run('ip', '-n', ns, 'link', 'set', 'lan0', 'mtu', '1280', 'up')
        run('ip', '-n', ns, 'route', 'add', '198.18.78.2/32', 'via', '198.19.78.1')
        for rule in rules(): run('iptables', '-w', '-I', 'INPUT', '1', *rule)
        run('systemd-run', '--quiet', '--collect', '--unit', tag+'-stream',
            '--property', 'RuntimeMaxSec=1200', '--property', 'User=nobody',
            '--', '/usr/local/bin/uv', 'run', '--no-project', '--no-cache', '--no-config',
            '--directory', root, 'python3',
            root/'bench_stream.py', '--server', '--address', '0.0.0.0')
        run('systemd-run', '--quiet', '--collect', '--unit', tag+'-lan',
            '--property', 'RuntimeMaxSec=1200',
            '--property', 'ExecStopPost=/usr/sbin/ip netns del '+ns,
            '--', 'ip', 'netns', 'exec', ns, 'runuser', '-u', 'foldfin', '--',
            'uv', 'run', '--no-project', '--no-cache', '--no-config', '--directory', root,
            'python3', root/'vpn_netns.py',
            '--worker', 'echo', '--address', '198.19.78.2', '--expect-source', '198.18.78.2')
    except BaseException:
        cleanup(); raise
    print('Singapore routed responders ready', flush=True)


if __name__ == '__main__':
    try:
        main()
    except subprocess.CalledProcessError as error:
        print(error.stdout or '', file=sys.stderr)
        print(error.stderr or '', file=sys.stderr)
        raise
