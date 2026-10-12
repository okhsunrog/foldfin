#!/usr/bin/env python3
"""Short Singapore WireGuard handshake check on the physical underlay."""
import argparse
import datetime
import json
from pathlib import Path
import secrets
import shlex
import socket
import subprocess
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
SERVER = '66.179.31.173'
PORT = 58886
ADMIN = 'root@sg.okhsunrog.dev'


def run(*args, check=True, **kwargs):
    return subprocess.run(list(map(str, args)), capture_output=True, text=True,
                          check=check, timeout=20, **kwargs)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--marker', help=argparse.SUPPRESS)
    args = parser.parse_args()
    if args.marker:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, args.marker.encode()+b'\0')
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 51820)
            sock.sendto(b'foldfin-wg-path-control', (SERVER, PORT))
        return
    output = ROOT/'captures'/('wireguard-physical-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S'))
    output.mkdir(mode=0o700)
    suffix = secrets.token_hex(4)
    namespace, device, unit = 'ffwg-'+suffix, 'ffwg'+suffix, 'foldfin-wg-probe-'+suffix
    private_file = output/'temporary-private-key'
    peer = None
    processes, files = [], []
    remote_started = False
    def root(*cmd, **kw): return run('sudo', '-n', *cmd, **kw)
    def ssh(*cmd, **kw): return run('ssh', '-o', 'BatchMode=yes', '-o', 'ConnectTimeout=8', ADMIN, shlex.join(map(str, cmd)), **kw)
    result = {'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),
              'endpoint':f'{SERVER}:{PORT}', 'temporary_peer_address':'10.78.78.254/32'}
    try:
        root('true')
        route = json.loads(root('ip','-j','route','get',SERVER,'mark','51820').stdout)[0]
        physical = route['dev']
        assert (Path('/sys/class/net')/physical/'device').exists(), route
        result.update(physical_interface=physical, underlay_route=route)
        allowed = ssh('wg','show','wg0','allowed-ips').stdout
        # Do not take an address belonging to an existing peer.
        import ipaddress
        address = ipaddress.ip_address('10.78.78.254')
        for line in allowed.splitlines():
            for prefix in line.split()[1:]:
                assert address not in ipaddress.ip_network(prefix), 'temporary peer address overlaps'
        server_key = ssh('wg','show','wg0','public-key').stdout.strip()
        private = run('wg','genkey').stdout.strip()
        with private_file.open('x') as file:
            private_file.chmod(0o600)
            file.write(private+'\n')
        peer = run('wg','pubkey',input=private+'\n').stdout.strip()
        root('ip','netns','add',namespace)
        # Create the UDP socket in the host namespace, then move only the device.
        # Its fwmark bypasses the host VPN; namespace routes carry only inner IP.
        root('ip','link','add',device,'type','wireguard')
        root('wg','set',device,'private-key',private_file,'fwmark','51820',
             'peer',server_key,'allowed-ips','10.78.78.1/32','endpoint',f'{SERVER}:{PORT}')
        root('ip','link','set',device,'netns',namespace)
        root('ip','-n',namespace,'address','add','10.78.78.254/32','dev',device)
        root('ip','-n',namespace,'link','set',device,'up')
        root('ip','-n',namespace,'link','set','lo','up')
        root('ip','-n',namespace,'route','add','10.78.78.1/32','dev',device)
        ssh('wg','set','wg0','peer',peer,'allowed-ips','10.78.78.254/32')
        filt=f'host {SERVER} and udp port {PORT}'
        log=open(output/'local-packets.txt','w'); files.append(log)
        processes.append(subprocess.Popen(['sudo','-n','timeout','45','tcpdump','--immediate-mode','-nn','-l','-i',physical,filt],stdout=log,stderr=log,start_new_session=True))
        log=open(output/'server-packets.txt','w'); files.append(log)
        remote_started=True
        command=['systemd-run','--quiet','--pipe','--wait','--collect','--unit',unit,
                 '--property','RuntimeMaxSec=45','--property','KillSignal=SIGINT','--',
                 'tcpdump','--immediate-mode','-nn','-l','-i','eth0',
                 f'host {SERVER} and udp port {PORT} and not host 212.233.78.60']
        processes.append(subprocess.Popen(['ssh','-o','BatchMode=yes',ADMIN,shlex.join(command)],stdout=log,stderr=log))
        deadline=time.monotonic()+10
        while not all('listening on' in (output/name).read_text() for name in ['local-packets.txt','server-packets.txt']):
            if time.monotonic()>deadline: raise RuntimeError('capture startup timeout')
            time.sleep(.1)
        root(sys.executable,Path(__file__).resolve(),'--marker',physical)
        ping=subprocess.Popen(['sudo','-n','ip','netns','exec',namespace,'ping','-n','-c','3','-W','2','10.78.78.1'],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
        text,_=ping.communicate(timeout=10)
        result['inner_ping']={'returncode':ping.returncode,'output':text}
        deadline=time.monotonic()+8
        while True:
            stats=root('ip','netns','exec',namespace,'wg','show',device,'latest-handshakes').stdout.strip()
            timestamp=int(stats.split()[-1]) if stats else 0
            if timestamp or time.monotonic()>deadline: break
            time.sleep(1)
        result['client_handshake_timestamp']=timestamp
        remote=ssh('wg','show','wg0','latest-handshakes').stdout
        result['server_handshake_timestamp']=next(int(line.split()[1]) for line in remote.splitlines() if line.split()[0]==peer)
        result['handshake']=bool(timestamp and result['server_handshake_timestamp'])
        (output/'summary.json').write_text(json.dumps(result,indent=2))
        print(json.dumps(result,indent=2),flush=True)
        print('Artifacts:',output,flush=True)
    finally:
        if remote_started: ssh('systemctl','stop',unit,check=False)
        if peer: ssh('wg','set','wg0','peer',peer,'remove',check=False)
        root('ip','netns','del',namespace,check=False)
        root('ip','link','del',device,check=False)
        if processes:
            root('kill','-INT','--','-'+str(processes[0].pid),check=False)
        for process in processes: process.wait(timeout=10)
        for file in files: file.close()
        private_file.unlink(missing_ok=True)
    if not result.get('handshake'): raise SystemExit(1)


if __name__ == '__main__': main()
