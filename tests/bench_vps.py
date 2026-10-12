#!/usr/bin/env python3
"""Release Floppa/Foldfin throughput, Frankfurt only, isolated veth/NAT path.

uv run --no-project tests/bench_vps.py --seconds 12 --repeats 2
Temporary rules are removed in finally; raw iperf JSON contains no credentials.
"""
import argparse
import datetime
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import signal
import socket
import subprocess
import time

from vps import configuration

ROOT = Path(__file__).resolve().parents[1]
FLOPPA = ROOT.parent.parent / 'floppa-vpn'


def run(*cmd, check=True, **kw):
    return subprocess.run(list(map(str, cmd)), check=check, capture_output=True, text=True, **kw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--seconds', type=int, default=12)
    parser.add_argument('--repeats', type=int, default=2)
    parser.add_argument('--no-build', action='store_true')
    parser.add_argument('--underlay-interface', help='explicit existing underlay, e.g. sirius_nova; recorded in results')
    parser.add_argument('--output', type=Path, default=Path('/tmp') / ('foldfin-bench-' + datetime.datetime.now().strftime('%Y%m%d-%H%M%S')))
    args = parser.parse_args()
    raise SystemExit('Historical Frankfurt/Floppa benchmark is disabled. Use tests/vpn_physical.py for Singapore CLI/TUN measurements; see docs/BENCHMARKS.md.')
    assert 5 <= args.seconds <= 60 and 1 <= args.repeats <= 5
    if not args.no_build:
        subprocess.run(['cargo', 'build', '--release', '-p', 'floppa', '--features', 'default'], cwd=FLOPPA, check=True)
    meta = json.loads(run('cargo', 'metadata', '--no-deps', '--format-version', '1', cwd=FLOPPA).stdout)
    binary = Path(meta['target_directory']) / 'release/floppa'
    config_dir = ROOT.parent.parent / 'cloud-forge/generated_configs/foldfin'
    cfg = configuration(config_dir, 'europe')
    assert cfg['FOLDFIN_SERVER_NAME'] == 'eu.okhsunrog.dev'
    host, endpoint_port = cfg['FOLDFIN_SERVER'].rsplit(':', 1)
    address = socket.gethostbyname(host)
    remote = 'root@' + cfg['FOLDFIN_SERVER_NAME']
    suffix = secrets.token_hex(4)
    namespace, veth = 'ffbench-' + suffix, 'ffb' + suffix
    table = str(30000 + secrets.randbelow(10000))
    priority = '90'
    unit = 'foldfin-bench-' + suffix
    port = 25000 + secrets.randbelow(10000)
    # Dedicated randomly selected private /30; never flush shared tables/rules.
    subnet = f'10.253.{secrets.randbelow(250)+1}'
    local, client_ip = subnet + '.1', subnet + '.2'
    network = subnet + '.0/30'
    args.output.mkdir(parents=True, exist_ok=False)
    args.output.chmod(0o700)
    undo, processes, handles = [], [], []
    client = None
    def root(*cmd, **kw): return run('sudo', '-n', *cmd, **kw)
    def ssh(*cmd, **kw): return run('ssh', '-o', 'BatchMode=yes', remote, shlex.join(map(str, cmd)), timeout=30, **kw)
    def ns(*cmd, **kw): return root('ip', 'netns', 'exec', namespace, *cmd, **kw)
    def change(action, rollback):
        undo.append(rollback)
        action()
    def local_rule(chain, *rule):
        change(lambda: root('iptables', '-w', '-t', chain[0], '-I', chain[1], '1', *rule),
               lambda: root('iptables', '-w', '-t', chain[0], '-D', chain[1], *rule, check=False))
    def remote_rule(*rule):
        change(lambda: ssh('iptables', '-w', '-I', 'INPUT', '1', *rule),
               lambda: ssh('iptables', '-w', '-D', 'INPUT', *rule, check=False))
    def stop_client():
        nonlocal client
        if client is not None and client.poll() is None:
            os.killpg(client.pid, signal.SIGINT)
            try: client.wait(timeout=15)
            except subprocess.TimeoutExpired:
                os.killpg(client.pid, signal.SIGKILL); client.wait(timeout=5)
        client = None
    def server_cpu():
        return int(ssh('systemctl', 'show', 'foldfin', '-p', 'CPUUsageNSec', '--value').stdout.strip())
    try:
        root('true')
        routes = json.loads(run('ip', '-j', '-4', 'route', 'show', 'default', 'table', 'main').stdout)
        route = min((r for r in routes if r.get('gateway')), key=lambda r:r.get('metric', 0))
        dev, gateway = route['dev'], route['gateway']
        if args.underlay_interface:
            dev, gateway = args.underlay_interface, None
            root('ip','link','show',dev)
        default_route=['default'] + (['via',gateway] if gateway else []) + ['dev',dev,'table',table]
        assert not root('ip', 'route', 'show', 'table', table, check=False).stdout.strip()
        assert not json.loads(run('ip', '-j', 'route', 'show', network).stdout)
        assert root('sysctl', '-n', 'net.ipv4.ip_forward').stdout.strip() == '1', 'host forwarding disabled'
        change(lambda: root('ip', 'netns', 'add', namespace), lambda: root('ip', 'netns', 'del', namespace, check=False))
        change(lambda: root('ip', 'link', 'add', veth, 'type', 'veth', 'peer', 'name', 'outer0', 'netns', namespace), lambda: root('ip', 'link', 'del', veth, check=False))
        root('ip', 'addr', 'add', local + '/30', 'dev', veth); root('ip', 'link', 'set', veth, 'up')
        ns('ip', 'addr', 'add', client_ip + '/30', 'dev', 'outer0')
        ns('ip', 'link', 'set', 'outer0', 'up'); ns('ip', 'link', 'set', 'lo', 'up')
        ns('ip', 'route', 'add', 'default', 'via', local)
        change(lambda: root('ip','route','add',*default_route), lambda: root('ip','route','del',*default_route,check=False))
        change(lambda: root('ip', 'rule', 'add', 'from', network, 'table', table, 'priority', priority), lambda: root('ip', 'rule', 'del', 'from', network, 'table', table, 'priority', priority, check=False))
        tag = ('-m', 'comment', '--comment', unit)
        local_rule(('nat','POSTROUTING'), '-s', network, '-o', dev, *tag, '-j', 'MASQUERADE')
        local_rule(('filter','FORWARD'), '-i', veth, '-o', dev, *tag, '-j', 'ACCEPT')
        local_rule(('filter','FORWARD'), '-i', dev, '-o', veth, '-m', 'conntrack', '--ctstate', 'RELATED,ESTABLISHED', *tag, '-j', 'ACCEPT')
        # Observe the peer of a held outer connection: internet echo IP can differ
        # when the physical gateway itself exits on this VPS (hairpin routing).
        def peers():
            return set(ssh('ss','-tnH','state','established','sport','=',':'+endpoint_port).stdout.splitlines())
        before = peers()
        observer = subprocess.Popen(['sudo','-n','ip','netns','exec',namespace,os.sys.executable,'-c',
            'import socket,sys; s=socket.create_connection((sys.argv[1],int(sys.argv[2])),10); print("ready",flush=True); sys.stdin.read()',address,endpoint_port], stdin=subprocess.PIPE,stdout=subprocess.PIPE,text=True)
        processes.append(observer)
        assert observer.stdout.readline().strip() == 'ready'
        try:
            observed=peers()-before
            assert len(observed)==1, 'cannot uniquely identify benchmark peer'
            public_ip=next(iter(observed)).split()[3].rsplit(':',1)[0]
            socket.inet_aton(public_ip)
        finally:
            observer.communicate('',timeout=5)
        print('Observed outer peer: '+public_ip,flush=True)
        remote_rule('-s', public_ip+'/32', '-d', address+'/32', '-p','tcp','--dport',port,*tag,'-j','ACCEPT')
        remote_rule('-i','ffvpn0','-s','198.18.77.2/32','-d','198.18.77.1/32','-p','tcp','--dport',port,*tag,'-j','ACCEPT')
        change(lambda: ssh('systemd-run', '--quiet', '--collect', '--unit', unit, '--property', 'RuntimeMaxSec=1200', '--property', 'User=nobody', '--', '/usr/bin/iperf3', '-s', '-p', port), lambda: ssh('systemctl', 'stop', unit, check=False))
        time.sleep(.5)
        summary = {'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(), 'seconds':args.seconds, 'omit_seconds':2, 'repeats':args.repeats, 'endpoint':address, 'underlay_interface':dev, 'observed_outer_peer':public_ip, 'gateway':gateway, 'client_sha256':hashlib.sha256(binary.read_bytes()).hexdigest(), 'server_sha256':ssh('sha256sum','/opt/foldfin/server').stdout.split()[0], 'client_cpu':run('lscpu').stdout, 'server_cpu':ssh('lscpu').stdout, 'results':[]}
        ca = (config_dir/'europe.pem').read_text()
        for mode in ['direct', 'rustls']:
            if mode != 'direct':
                document = args.output/'private-config.json'
                document.write_text(json.dumps({'protocol':'foldfin','config':{'version':1,'endpoint':f'{address}:{endpoint_port}','server_name':cfg['FOLDFIN_SERVER_NAME'],'token':cfg['FOLDFIN_TOKEN'],'address':'198.18.77.2/32','peer':'198.18.77.1','routes':['198.18.77.1/32','198.19.77.0/30'],'dns':[],'mtu':1280,'additional_ca_pem':ca}}))
                document.chmod(0o600)
                log = open(args.output/f'{mode}-client.log','w'); handles.append(log)
                command=['sudo','-n','ip','netns','exec',namespace,'env',f'XDG_CONFIG_HOME={args.output}/config',str(binary),'connect','--config',str(document),'--no-dns']
                client=subprocess.Popen(command, stdout=log, stderr=log, start_new_session=True); processes.append(client)
                deadline=time.monotonic()+30
                while 'READY' not in (args.output/f'{mode}-client.log').read_text():
                    if client.poll() is not None or time.monotonic()>deadline: raise RuntimeError('client readiness failed: '+(args.output/f'{mode}-client.log').read_text())
                    time.sleep(.1)
                # sudo wrapper remains the tracked process; resolve real Floppa PID for CPU.
                pids=[pid for pid in root('ip','netns','pids',namespace).stdout.split() if root('cat',f'/proc/{pid}/comm').stdout.strip()=='floppa']
                assert len(pids)==1
                cpu_pid=int(pids[0])
            destination=address if mode=='direct' else '198.18.77.1'
            for repeat in range(args.repeats):
                for parallel in [1,4]:
                    for reverse in [False,True]:
                        name=f'{mode}-p{parallel}-'+('download' if reverse else 'upload')+f'-{repeat+1}'
                        cmd=['iperf3','-c',destination,'-p',port,'-t',args.seconds,'-O','2','-P',parallel,'-J','--get-server-output','--connect-timeout','5000']
                        if reverse: cmd.append('-R')
                        start_server=server_cpu(); start=time.monotonic()
                        def cpu():
                            stat=root('cat',f'/proc/{cpu_pid}/stat').stdout.rsplit(')',1)[1].split()
                            return (int(stat[11])+int(stat[12]))/os.sysconf('SC_CLK_TCK')
                        start_client=cpu() if mode!='direct' else 0
                        result=ns(*cmd, timeout=args.seconds+35)
                        elapsed=time.monotonic()-start
                        value=json.loads(result.stdout); assert 'error' not in value,value
                        (args.output/(name+'.json')).write_text(json.dumps(value,indent=2))
                        end=value['end']; record={'mode':mode,'parallel':parallel,'direction':'download' if reverse else 'upload','repeat':repeat+1,'mbps':end['sum_received']['bits_per_second']/1e6,'retransmits':end['sum_sent'].get('retransmits'),'server_foldfin_cpu_percent':(server_cpu()-start_server)/1e9/elapsed*100,'client_floppa_cpu_percent':(cpu()-start_client)/elapsed*100 if mode!='direct' else 0,'elapsed_seconds':elapsed,'iperf_client_cpu':end.get('cpu_utilization_percent')}
                        summary['results'].append(record)
                        (args.output/'summary.json').write_text(json.dumps(summary,indent=2))
                        print(f"{name}: {record['mbps']:.1f} Mbps; Floppa CPU {record['client_floppa_cpu_percent']:.1f}%, Foldfin server CPU {record['server_foldfin_cpu_percent']:.1f}%",flush=True)
            stop_client()
        print('Artifacts: '+str(args.output),flush=True)
    finally:
        stop_client()
        for proc in processes:
            if proc.poll() is None: proc.kill(); proc.wait(timeout=5)
        # Killing a sudo wrapper does not guarantee its child has exited.
        remaining=root('ip','netns','pids',namespace,check=False).stdout.split()
        if remaining: root('kill','-KILL',*remaining,check=False)
        for action in reversed(undo):
            try: action()
            except Exception as error: print('Cleanup failure: '+str(error),flush=True)
        for handle in handles: handle.close()
        # Config-store may persist credentials. Keep only logs and measurement JSON.
        root('rm','-rf','--',args.output/'config',args.output/'private-config.json',check=False)
        root('chown','-R',f'{os.getuid()}:{os.getgid()}',args.output,check=False)


if __name__ == '__main__': main()
