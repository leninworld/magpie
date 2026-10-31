"""One standard hosted job; host only orchestrates Docker and inert inputs."""
from pathlib import Path
import hashlib
import json
import os
import platform
import re
import selectors
import shutil
import signal
import subprocess
import sys
import time
import urllib.parse
import urllib.request

P=Path(__file__).resolve().parent
S=P.parent/'source'
STATE=P.parent/'runtime'
BEGIN=time.monotonic()
DEADLINE_EPOCH=time.time()+50*60
OWN=None
LAST_SAMPLE=0
M=json.loads((P/'manifest.json').read_text())
RESULT={'status':'PREPARING','full_validation':False}
LOGS=[]
route=[line.split()[0] for line in Path('/proc/net/route').read_text().splitlines()[1:] if line.split()[1]=='00000000']
assert len(set(route))==1
RX=Path('/sys/class/net')/route[0]/'statistics/rx_bytes'
NETWORK_START=int(RX.read_text())

def guard():
    assert time.monotonic()-BEGIN<50*60,'HOST_TARGET_TIME'
    assert shutil.disk_usage(P).free>=3*1024**3,'HOST_DISK_PRESSURE'
    available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
    assert available>=1536*1024**2,'HOST_MEMORY_PRESSURE'
    assert int(RX.read_text())-NETWORK_START<4*1024**3,'HOST_NETWORK_CAP'

def command(label,args,seconds,cap=4*1024**2,monitor=True):
    global LAST_SAMPLE
    assert re.fullmatch('[a-z0-9-]+',label)
    target=STATE/(label+'.log');assert not target.exists()
    env={k:v for k,v in os.environ.items() if not any(x in k.upper() for x in ['TOKEN','SECRET','PASSWORD','CREDENTIAL'])}
    proc=subprocess.Popen(args,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,env=env,start_new_session=True)
    sel=selectors.DefaultSelector();sel.register(proc.stdout,selectors.EVENT_READ)
    chunks=[];size=0;t=time.monotonic();error=None
    try:
        while sel.get_map():
            guard();assert time.monotonic()-t<seconds,'COMMAND_TIME_'+label
            if monitor and OWN and time.monotonic()-LAST_SAMPLE>10:
                LAST_SAMPLE=time.monotonic()
                state=json.loads(command('state-'+str(len(LOGS)),['docker','inspect','--format','{{json .State}}',OWN],8,8192,False))
                assert not state['OOMKilled'],'CONTAINER_OOM'
                if state['Running']:
                    perc=command('memory-'+str(len(LOGS)),['docker','stats','--no-stream','--format','{{.MemPerc}}',OWN],8,8192,False).decode().strip()
                    assert re.fullmatch(r'[0-9]+(?:\.[0-9]+)?%',perc) and float(perc[:-1])<93.75,'CONTAINER_MEMORY'
            for key,_ in sel.select(.5):
                data=os.read(key.fd,8192)
                if not data:sel.unregister(key.fileobj);continue
                assert size+len(data)<=cap,'OUTPUT_CAP_'+label
                chunks.append(data);size+=len(data)
        assert proc.wait(timeout=3)==0,'COMMAND_FAILED_'+label
        return b''.join(chunks)
    except BaseException as ex:
        error=str(ex)
        if proc.poll() is None:
            try:os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError:pass
            try:proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try:os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError:pass
                proc.wait()
        raise
    finally:
        sel.close();target.write_bytes(b''.join(chunks))
        LOGS.append({'label':label,'args':args,'elapsed':time.monotonic()-t,'exit':proc.returncode,'bytes':size,'error':error})

def download(item,name):
    target=STATE/'inputs'/name;assert not target.exists()
    allowed={'nodejs.org','registry.npmjs.org','openaipublic.blob.core.windows.net','github.com','release-assets.githubusercontent.com','objects.githubusercontent.com'}
    class Redirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            assert urllib.parse.urlsplit(newurl).scheme=='https' and urllib.parse.urlsplit(newurl).hostname in allowed
            return super().redirect_request(req,fp,code,msg,headers,newurl)
    assert urllib.parse.urlsplit(item['url']).hostname in allowed
    h=hashlib.sha256();size=0;t=time.monotonic()
    with urllib.request.build_opener(Redirect()).open(item['url'],timeout=20) as response,target.open('xb') as out:
        assert response.status==200
        while True:
            guard();assert time.monotonic()-t<120,'DOWNLOAD_TIME'
            b=response.read(65536)
            if not b:break
            assert size+len(b)<=item['bytes'],'DOWNLOAD_SIZE'
            size+=len(b);h.update(b);out.write(b)
    assert size==item['bytes'] and h.hexdigest()==item['sha256'],'DOWNLOAD_IDENTITY'

try:
    assert platform.machine()=='x86_64' and os.getuid()==1001
    STATE.mkdir();(STATE/'inputs').mkdir()
    assert shutil.disk_usage(P).free>=18*1024**3,'WORKSPACE_DISK_ADMISSION'
    info=json.loads(command('docker-info',['docker','info','--format','{"root":{{json .DockerRootDir}},"memory":{{.MemTotal}},"cpus":{{.NCPU}}}'],15))
    assert info['cpus']>=4 and info['memory']>=10*1024**3
    assert shutil.disk_usage(info['root']).free>=18*1024**3,'DOCKER_DISK_ADMISSION'
    available=int(re.search(r'^MemAvailable:\s+(\d+)',Path('/proc/meminfo').read_text(),re.M)[1])*1024
    assert available>=10*1024**3,'MEMORY_ADMISSION'
    RESULT['admission']={'workspace_free':shutil.disk_usage(P).free,'docker_free':shutil.disk_usage(info['root']).free,'host_memory_available':available,'cpu':info['cpus']}
    command('pull',['docker','pull',M['image']],300)
    image=json.loads(command('image',['docker','image','inspect',M['image']],10,65536))[0]
    assert image['Architecture']=='amd64' and M['image'] in image['RepoDigests']
    RESULT['image_expanded_bytes']=image['Size']
    for name,item in M['downloads'].items():download(item,name)
    assert command('clean-source',['git','-C',str(S),'status','--porcelain'],10)==b''
    assert command('base',['git','-C',str(S),'rev-parse','HEAD'],10).decode().strip()==M['base']
    assert hashlib.sha256((P/'I1.patch').read_bytes()).hexdigest()==M['patch_sha256']
    command('patch-check',['git','-C',str(S),'apply','--check',str(P/'I1.patch')],15)
    command('patch',['git','-C',str(S),'apply',str(P/'I1.patch')],15)
    command('new-test-visible',['git','-C',str(S),'add','--intent-to-add','tools/setup-preflight/tests/test_husky_integration.py'],10)
    for x in M['source']:assert hashlib.sha256((S/x['path']).read_bytes()).hexdigest()==x['sha256']
    for n in ['cache','home','temp']: (STATE/n).mkdir()
    ident=os.environ['GITHUB_RUN_ID'];assert re.fullmatch('[0-9]+',ident)
    tag='magpie1823-validation:'+ident
    command('dedicated-account-image',['docker','build','--network=none','--tag',tag,'--file',str(P/'Dockerfile'),str(P)],90)
    assert time.monotonic()-BEGIN<8*60,'SETUP_CAP'
    name='magpie1823-validation-'+ident
    argv=['docker','create','--env','VALIDATION_DEADLINE_EPOCH='+str(DEADLINE_EPOCH),'--name',name,'--label','org.magpie1823.run='+ident,'--init','--read-only','--cpus','2','--memory','8g','--memory-swap','8g','--pids-limit','512','--security-opt','no-new-privileges','--cap-drop','ALL','--tmpfs','/fixtures:rw,size=512m,mode=1777','--mount','type=bind,src='+str(P)+',dst=/packet,readonly','--mount','type=bind,src='+str(S)+',dst=/project','--mount','type=bind,src='+str(STATE)+',dst=/runtime','--mount','type=bind,src='+str(STATE/'cache')+',dst=/cache','--mount','type=bind,src='+str(STATE/'home')+',dst=/home/validation','--mount','type=bind,src='+str(STATE/'temp')+',dst=/tmp','--mount','type=bind,src='+str(STATE/'inputs')+',dst=/inputs,readonly',tag,'python3','/packet/inside.py']
    cid=command('create',argv,20).decode().strip();assert re.fullmatch('[a-f0-9]{64}',cid);OWN=cid
    command('run',['docker','start','--attach',OWN],45*60)
    inspect=json.loads(command('final-state',['docker','inspect','--format','{{json .State}}',OWN],10,8192,False))
    assert not inspect['OOMKilled'] and inspect['ExitCode']==0
    inner=json.loads((STATE/'result.json').read_text());assert inner['status']=='FULL_VALIDATION_PASS'
    RESULT.update({'status':'FULL_VALIDATION_PASS','full_validation':True,'inside':inner})
except BaseException as ex:
    RESULT.update({'status':'STOP_NO_RETRY','error':type(ex).__name__+': '+str(ex)})
finally:
    if OWN:
        # Exact owned id only; no removals/prune, no shared or Mac service touched.
        proc=subprocess.Popen(['docker','stop','--time','5',OWN],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        try:proc.wait(timeout=10)
        except subprocess.TimeoutExpired:proc.kill();proc.wait()
        RESULT['owned_stop_exit']=proc.returncode
        RESULT['owned_stop_verified']=proc.returncode==0
    RESULT.update({'elapsed_seconds':time.monotonic()-BEGIN,'host_received_bytes':int(RX.read_text())-NETWORK_START,'commands':LOGS})
    if STATE.exists():(STATE/'host-result.json').write_text(json.dumps(RESULT,indent=2))
    encoded=json.dumps(RESULT,separators=(',',':'))
    assert len(encoded)<2*1024**2
    print('MAGPIE_RESULT_BEGIN\n'+encoded+'\nMAGPIE_RESULT_END',flush=True)
    if STATE.exists():
        for f in [STATE/'result.json',STATE/'validated.patch']:
            if f.exists():
                data=f.read_text();assert len(data)<1024**2
                print('MAGPIE_FILE_BEGIN '+f.name+'\n'+data+'\nMAGPIE_FILE_END',flush=True)
if STATE.exists():
    chosen=[]
    if not RESULT['full_validation']:
        inner_commands=STATE/'commands.json'
        if inner_commands.exists():
            history=json.loads(inner_commands.read_text())
            chosen += [x['label']+'.log' for x in history if x.get('failure')]
            chosen += [x['label']+'.log' for x in history[-4:]]
        chosen += [x['label']+'.log' for x in LOGS if x.get('error')]
        if LOGS:chosen.append(LOGS[-1]['label']+'.log')
    chosen += ['nonmanual.log','cold-lychee.log']
    emitted=0
    for name in dict.fromkeys(chosen):
        file=STATE/name
        if file.exists():
            data=file.read_bytes()
            if name!='nonmanual.log':data=data[-16384:]
            remaining=1536*1024-emitted
            if remaining<=0:break
            clipped=len(data)>remaining
            data=data[:remaining];emitted+=len(data)
            text=data.decode('utf-8','replace')
            text=re.sub(r'(?:gh[pousr]_[A-Za-z0-9_]{20,}|github_pat_[A-Za-z0-9_]{20,})','[redacted]',text)
            print('MAGPIE_LOG_BEGIN '+name+' clipped='+str(clipped)+'\n'+text+'\nMAGPIE_LOG_END',flush=True)
if not RESULT['full_validation']:sys.exit(1)
