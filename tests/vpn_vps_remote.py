#!/usr/bin/env python3
"""Scoped Frankfurt acceptance helper. No tokens, defaults, NAT or unrelated rules."""
import pathlib
import re
import subprocess
import sys

operation, suffix = sys.argv[1:3]
assert re.fullmatch('[a-f0-9]{8}', suffix)
namespace = 'foldfin-accept-' + suffix
unit = 'foldfin-vpn-accept-' + suffix
host_link, peer_link = 'mva' + suffix, 'mvb' + suffix
root = pathlib.Path(__file__).resolve().parent


def run(*args, **kwargs):
    return subprocess.run(list(args), check=True, **kwargs)


def cleanup():
    subprocess.run(['systemctl', 'stop', unit], check=False, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    present = subprocess.check_output(['ip', 'netns', 'list'], text=True).splitlines()
    if any(line.split()[0] == namespace for line in present):
        pids = subprocess.check_output(['ip', 'netns', 'pids', namespace], text=True).split()
        if pids: subprocess.run(['kill', '-KILL', *pids], check=False)
        run('ip', 'netns', 'del', namespace)


if operation == 'setup':
    assert not subprocess.check_output(['ip', 'route', 'show', '198.19.77.0/30'], text=True).strip(), 'test prefix already in use'
    assert subprocess.check_output(['sysctl', '-n', 'net.ipv4.ip_forward'], text=True).strip() == '1'
    run('ip', 'netns', 'add', namespace)
    try:
        run('ip', '-n', namespace, 'link', 'set', 'lo', 'up')
        run('ip', 'netns', 'exec', namespace, 'sysctl', '-q', '-w', 'net.ipv4.ping_group_range=0 2147483647')
        run('ip', 'link', 'add', host_link, 'type', 'veth', 'peer', 'name', peer_link, 'netns', namespace)
        run('ip', 'addr', 'add', '198.19.77.1/30', 'dev', host_link)
        run('ip', 'link', 'set', host_link, 'up')
        run('ip', '-n', namespace, 'addr', 'add', '198.19.77.2/30', 'dev', peer_link)
        run('ip', '-n', namespace, 'link', 'set', peer_link, 'up')
        run('ip', '-n', namespace, 'route', 'add', '198.18.77.2/32', 'via', '198.19.77.1')
        run('systemd-run', '--quiet', '--collect', '--unit', unit,
            '--property', 'RuntimeMaxSec=300', '--property', 'ExecStopPost=/usr/sbin/ip netns del ' + namespace,
            '--', 'ip', 'netns', 'exec', namespace, 'runuser', '-u', 'foldfin', '--',
            'python3', str(root/'vpn_netns.py'), '--worker', 'echo', '--address', '198.19.77.2', '--expect-source', '198.18.77.2')
        print('Frankfurt isolated LAN responder started', flush=True)
    except BaseException:
        cleanup(); raise
elif operation == 'probe':
    run('ip', 'netns', 'exec', namespace, 'runuser', '-u', 'foldfin', '--',
        'python3', str(root/'vpn_netns.py'), '--worker', 'probe', '--address', '198.18.77.2')
elif operation == 'cleanup':
    cleanup()
else:
    raise ValueError('unknown operation')
