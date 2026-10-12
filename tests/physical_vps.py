#!/usr/bin/env python3
"""Physical-interface VPS acceptance; no implicit host VPN or socket relay."""
import argparse
import datetime
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
import time

from vps import configuration

ROOT = Path(__file__).resolve().parents[1]
SSH_USERS = {'moscow':'ubuntu', 'europe':'root', 'singapore':'root'}


def run(*cmd, check=True, **kwargs):
    return subprocess.run(list(map(str, cmd)), capture_output=True, text=True, check=check, **kwargs)


def probe(address):
    results = []
    for port in [22, 443, 8445]:
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'outer0\0')
            sock.settimeout(5)
            try:
                sock.connect((address, port))
                item = {'port':port,'connected':True,'local':sock.getsockname(),'seconds':time.monotonic()-started}
                if port == 22:
                    try: item['banner']=sock.recv(256).decode(errors='replace').strip()
                    except OSError as error: item['banner_error']=str(error)
            except OSError as error:
                item={'port':port,'connected':False,'seconds':time.monotonic()-started,'error':str(error)}
            results.append(item)
    print(json.dumps(results),flush=True)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--hosts',nargs='+',choices=list(SSH_USERS),default=['singapore'])
    parser.add_argument('--profiles',nargs='+',choices=['rustls'],default=['rustls'])
    parser.add_argument('--interface',help='physical interface, defaults to lowest-metric main-table default')
    parser.add_argument('--configs',type=Path,default=ROOT.parent.parent/'cloud-forge/generated_configs/foldfin')
    parser.add_argument('--client',type=Path)
    parser.add_argument('--output',type=Path,default=ROOT/'captures'/('physical-'+datetime.datetime.now().strftime('%Y%m%d-%H%M%S')))
    parser.add_argument('--probe')
    args=parser.parse_args()
    if args.probe: probe(args.probe); return
    args.output.mkdir(parents=True,exist_ok=False)
    args.output.chmod(0o700)
    meta=json.loads(run('cargo','metadata','--no-deps','--format-version','1',cwd=ROOT).stdout)
    binary=args.client or Path(meta['target_directory'])/'release/client'
    assert binary.is_file(),'build release client first'
    configs={host:configuration(args.configs,host) for host in args.hosts}
    addresses={host:socket.gethostbyname(cfg['FOLDFIN_SERVER_NAME']) for host,cfg in configs.items()}
    assert all(ipaddress.ip_address(ip).is_global for ip in addresses.values())
    suffix=secrets.token_hex(4)
    namespace='ffdirect-'+suffix; veth='ffd'+suffix; tag='foldfin-physical-'+suffix
    table=str(41000+secrets.randbelow(1000)); network=f'10.252.{1+secrets.randbelow(250)}.0/30'
    net=ipaddress.ip_network(network); gateway_ns=str(net[1]); client_ns=str(net[2])
    undo=[]; captures=[]; files=[]; remote_units=[]
    summary={'timestamp_utc':datetime.datetime.now(datetime.timezone.utc).isoformat(),'namespace':namespace,'network':network,'policy_table':table,'hosts':{}}
    def root(*cmd,**kw): return run('sudo','-n',*cmd,**kw)
    def ns(*cmd,**kw): return root('ip','netns','exec',namespace,*cmd,**kw)
    def ssh(host,*cmd,**kw):
        return run('ssh','-o','BatchMode=yes','-o','ConnectTimeout=10',SSH_USERS[host]+'@'+configs[host]['FOLDFIN_SERVER_NAME'],shlex.join(map(str,cmd)),timeout=30,**kw)
    def change(action,rollback): undo.append(rollback);action()
    def rule(family,chain,*items):
        change(lambda:root('iptables','-w','-t',family,'-I',chain,'1',*items),lambda:root('iptables','-w','-t',family,'-D',chain,*items))
    def save(): (args.output/'summary.json').write_text(json.dumps(summary,indent=2))
    try:
        root('true')
        routes=json.loads(run('ip','-j','-4','route','show','default','table','main').stdout)
        eligible=[r for r in routes if r.get('gateway') and (not args.interface or r['dev']==args.interface)]
        route=min(eligible,key=lambda r:r.get('metric',0)); dev,gateway=route['dev'],route['gateway']
        # A WireGuard/TUN device is not a physical interface, even when requested explicitly.
        assert (Path('/sys/class/net')/dev/'device').exists(),f'{dev} is not a physical NIC'
        assert root('sysctl','-n','net.ipv4.ip_forward').stdout.strip()=='1'
        assert not root('ip','route','show','table',table,check=False).stdout.strip()
        change(lambda:root('ip','netns','add',namespace),lambda:root('ip','netns','del',namespace))
        change(lambda:root('ip','link','add',veth,'type','veth','peer','name','outer0','netns',namespace),lambda:root('ip','link','del',veth,check=False))
        root('ip','addr','add',gateway_ns+'/30','dev',veth);root('ip','link','set',veth,'up')
        ns('ip','addr','add',client_ns+'/30','dev','outer0');ns('ip','link','set','outer0','up');ns('ip','link','set','lo','up')
        ns('ip','route','add','default','via',gateway_ns)
        change(lambda:root('ip','route','add','default','via',gateway,'dev',dev,'table',table),lambda:root('ip','route','del','default','via',gateway,'dev',dev,'table',table))
        change(lambda:root('ip','rule','add','from',network,'lookup',table,'priority','89'),lambda:root('ip','rule','del','from',network,'lookup',table,'priority','89'))
        comment=['-m','comment','--comment',tag]
        rule('nat','POSTROUTING','-s',network,'-o',dev,*comment,'-j','MASQUERADE')
        rule('filter','FORWARD','-i',veth,'-o',dev,*comment,'-j','ACCEPT')
        rule('filter','FORWARD','-i',dev,'-o',veth,'-m','conntrack','--ctstate','RELATED,ESTABLISHED',*comment,'-j','ACCEPT')
        try:
            summary['public_source_hint']=ns('curl','-4','--noproxy','*','--fail','--silent','--max-time','10','https://api.ipify.org',timeout=15).stdout.strip()
        except subprocess.SubprocessError:
            summary['public_source_hint']=None
        summary.update(physical_interface=dev,physical_gateway=gateway,client_address=client_ns,host_default_route=route,host_rules=run('ip','rule','show').stdout)
        # Only handshake/reset metadata; no authentication or payload dump.
        capture_filter='('+' or '.join('host '+ip for ip in addresses.values())+') and tcp and (port 22 or port 443 or port 8445) and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)'
        log=open(args.output/'local-packets.txt','w');files.append(log)
        local_capture=subprocess.Popen(['sudo','-n','timeout','300','tcpdump','--immediate-mode','-nn','-l','-i','any',capture_filter],stdout=log,stderr=log,start_new_session=True);captures.append(local_capture)
        for host in args.hosts:
            unit=tag+'-'+host
            admin=SSH_USERS[host]+'@'+configs[host]['FOLDFIN_SERVER_NAME']
            remote_log=open(args.output/(host+'-packets.txt'),'w');files.append(remote_log)
            command=['sudo','-n','systemd-run','--quiet','--pipe','--wait','--collect','--unit',unit,'--property','RuntimeMaxSec=300','--','tcpdump','--immediate-mode','-nn','-l','-i','any',f'host {addresses[host]} and ((dst host {addresses[host]} and (dst port 22 or dst port 443 or dst port 8445)) or (src host {addresses[host]} and (src port 22 or src port 443 or src port 8445))) and (tcp[tcpflags] & (tcp-syn|tcp-rst) != 0)' + (' and host '+summary['public_source_hint'] if summary.get('public_source_hint') else '')]
            remote_units.append((host,unit))
            process=subprocess.Popen(['ssh','-o','BatchMode=yes',admin,shlex.join(command)],stdout=remote_log,stderr=remote_log);captures.append(process)
            deadline=time.monotonic()+15
            while 'listening on' not in (args.output/(host+'-packets.txt')).read_text():
                if process.poll() is not None or time.monotonic()>deadline: raise RuntimeError('VPS capture unavailable: '+host)
                time.sleep(.1)
            item={'ip':addresses[host],'namespace_route':ns('ip','route','get',addresses[host]).stdout,'forwarding_route':root('ip','route','get',addresses[host],'from',client_ns,'iif',veth).stdout,'server_service':ssh(host,'sudo','-n','systemctl','show','foldfin','-p','ActiveState','-p','ExecStart').stdout,'server_listener':ssh(host,'sudo','-n','ss','-ltnp','sport','=',':8445').stdout}
            assert 'dev '+dev+' ' in item['forwarding_route'],item['forwarding_route']
            item['tcp']=json.loads(ns(sys.executable,Path(__file__).resolve(),'--probe',addresses[host],timeout=20).stdout)
            summary['hosts'][host]=item;save()
            print(host+': '+json.dumps(item['tcp']),flush=True)
            if not next(r['connected'] for r in item['tcp'] if r['port']==8445):
                item['foldfin']='not tested: TCP/8445 did not establish'
                diagnostics={}
                for label,cmd in [('icmp',['ping','-n','-c','2','-W','2',addresses[host]]),('tcp_traceroute',['traceroute','-n','-T','-p','8445','-q','1','-w','1','-m','16',addresses[host]])]:
                    try:
                        result=ns(*cmd,timeout=25,check=False)
                        diagnostics[label]={'returncode':result.returncode,'output':result.stdout+result.stderr}
                    except (OSError,subprocess.SubprocessError) as error:diagnostics[label]={'error':str(error)}
                if summary.get('public_source_hint'):
                    diagnostics['server_return_route']=ssh(host,'sudo','-n','ip','route','get',summary['public_source_hint']).stdout
                diagnostics['server_input_rules']=ssh(host,'sudo','-n','iptables','-S','INPUT').stdout
                item['diagnostics']=diagnostics;save();continue
            item['profiles']={}
            for profile in args.profiles:
                cmd=[sys.executable,ROOT/'tests/vps.py','--configs',args.configs,'--hosts',host,'--client',binary]
                result=ns('setpriv','--reuid',str(os.getuid()),'--regid',str(os.getgid()),'--clear-groups',*cmd,timeout=150,check=False)
                (args.output/(host+'-'+profile+'.txt')).write_text(result.stdout+result.stderr)
                item['profiles'][profile]={'passed':result.returncode==0,'returncode':result.returncode};save()
                print(host+' '+profile+': '+('PASS' if result.returncode==0 else 'FAIL'),flush=True)
        summary['finished']=True;save()
    finally:
        for host,unit in reversed(remote_units):
            try:ssh(host,'sudo','-n','systemctl','stop',unit,check=False)
            except Exception as error:print('Remote capture cleanup:',host,str(error),flush=True)
        if captures:
            root('kill','-INT','--',f'-{captures[0].pid}',check=False)
        for process in captures:
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        pids=root('ip','netns','pids',namespace,check=False).stdout.split()
        if pids:root('kill','-KILL',*pids,check=False)
        for rollback in reversed(undo):
            try:rollback()
            except Exception as error:print('Local cleanup:',str(error),flush=True)
        for file in files:file.close()
    print('Artifacts: '+str(args.output),flush=True)
    if not all(all(r['passed'] for r in item.get('profiles',{}).values()) and bool(item.get('profiles')) for item in summary['hosts'].values()):
        raise SystemExit(1)


if __name__=='__main__':main()
