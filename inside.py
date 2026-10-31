"""Magpie validation only inside the bounded dedicated Docker container."""
from pathlib import Path
import hashlib
import json
import os
import re
import selectors
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import xml.etree.ElementTree as ET

P = Path('/packet')
R = Path('/runtime')
S = Path('/project')
BEGIN = time.monotonic()
HOST_DEADLINE = float(os.environ['VALIDATION_DEADLINE_EPOCH'])
PHASE = 'bootstrap'
COMMANDS = []
M = json.loads((P/'manifest.json').read_text())
NETWORK_START = sum(int(x.read_text()) for x in Path('/sys/class/net').glob('*/statistics/rx_bytes') if x.parents[1].name!='lo')
PEAK = 0

def guard():
    global PEAK
    elapsed = time.monotonic()-BEGIN
    assert elapsed < 50*60 and time.time()<HOST_DEADLINE, 'INNER_TARGET_TIME'
    if PHASE == 'bootstrap':
        assert elapsed < 30*60, 'BOOTSTRAP_TIME'
    assert min(shutil.disk_usage(x).free for x in (S,R,Path('/cache'))) >= 3*1024**3, 'DISK_PRESSURE'
    cg = Path('/sys/fs/cgroup')
    current = int((cg/'memory.current').read_text())
    limit = int((cg/'memory.max').read_text())
    peak = int((cg/'memory.peak').read_text())
    stats=dict(x.split() for x in (cg/'memory.stat').read_text().splitlines())
    working=max(0,current-int(stats.get('inactive_file','0')))
    PEAK = max(PEAK, peak)
    events = dict(x.split() for x in (cg/'memory.events').read_text().splitlines())
    assert int(events['oom']) == 0 and int(events['oom_kill']) == 0, 'CGROUP_OOM'
    assert working < limit*0.9375, 'CGROUP_MEMORY_PRESSURE'
    received = sum(int(x.read_text()) for x in Path('/sys/class/net').glob('*/statistics/rx_bytes') if x.parents[1].name!='lo')-NETWORK_START
    assert received <= (3 if PHASE=='bootstrap' else 4)*1024**3, 'NETWORK_CAP'
    sample = {'elapsed':elapsed,'phase':PHASE,'memory_current':current,'working_set':working,'memory_peak':peak,'network_received':received}
    (R/'latest-resource.json').write_text(json.dumps(sample))
    return sample

def run(label, argv, seconds=300, accepted=(0,), cap=4*1024**2, env=None):
    assert re.fullmatch('[a-z0-9-]+',label) and not (R/(label+'.log')).exists()
    began = time.monotonic()
    proc = subprocess.Popen(argv,cwd=S,env=env,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
    selector = selectors.DefaultSelector()
    selector.register(proc.stdout,selectors.EVENT_READ)
    chunks=[]; size=0; failure=None
    try:
        while selector.get_map():
            guard()
            assert time.monotonic()-began<seconds, 'COMMAND_TIME_'+label
            for key,_ in selector.select(.5):
                data=os.read(key.fd,8192)
                if not data:
                    selector.unregister(key.fileobj); continue
                assert size+len(data)<=cap,'OUTPUT_CAP_'+label
                chunks.append(data); size+=len(data)
        status=proc.wait(timeout=3)
        assert status in accepted, 'COMMAND_FAILED_'+label+'_'+str(status)
        return b''.join(chunks)
    except BaseException as ex:
        failure=str(ex)
        if proc.poll() is None:
            try: os.killpg(proc.pid,signal.SIGTERM)
            except ProcessLookupError: pass
            try: proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                try: os.killpg(proc.pid,signal.SIGKILL)
                except ProcessLookupError: pass
                proc.wait()
        raise
    finally:
        selector.close()
        (R/(label+'.log')).write_bytes(b''.join(chunks))
        COMMANDS.append({'label':label,'argv':argv,'seconds':time.monotonic()-began,'exit':proc.returncode,'failure':failure,'output_bytes':size})
        (R/'commands.json').write_text(json.dumps(COMMANDS,indent=2))

def hashes():
    tracked=run('tracked-'+str(len(COMMANDS)),['git','ls-files','-z'],10).split(b'\0')
    return {os.fsdecode(x):hashlib.sha256((S/os.fsdecode(x)).read_bytes()).hexdigest() for x in tracked if x and (S/os.fsdecode(x)).is_file() and not (S/os.fsdecode(x)).is_symlink()}

result={'status':'RUNNING','full_validation':False}
try:
    assert os.getuid()==1001
    import pwd
    assert pwd.getpwuid(os.getuid()).pw_dir=='/home/validation'
    assert sys.version_info[:2]==(3,12)
    result['python_version']=sys.version
    assert re.fullmatch(r'uv 0\.11\.8(?: \(.*\))?',run('uv-version',['uv','--version'],10).decode().strip())
    git=run('git-version',['git','--version'],10).decode().strip()
    version=tuple(int(x) for x in re.search(r'(\d+)\.(\d+)\.(\d+)',git).groups())
    assert version>=(2,42,0)
    for exe in ['cc','make','ar','gpg','bash','git','python3']:
        assert shutil.which(exe), 'MISSING_PREREQUISITE_'+exe
    assert hashlib.sha256((P/'I1.patch').read_bytes()).hexdigest()==M['patch_sha256']
    assert run('source-head',['git','rev-parse','HEAD'],10).decode().strip()==M['base']
    for row in M['source']:
        assert hashlib.sha256((S/row['path']).read_bytes()).hexdigest()==row['sha256'], 'SOURCE_MISMATCH_'+row['path']
    node=Path('/inputs/node.tar.xz')
    assert node.stat().st_size==M['node']['bytes'] and hashlib.sha256(node.read_bytes()).hexdigest()==M['node']['sha256']
    tools=Path('/cache/tools');tools.mkdir()
    with tarfile.open(node,'r:xz') as archive:
        members=archive.getmembers()
        assert len(members)<20000 and sum(x.size for x in members)<512*1024**2
        for item in members:
            path=Path(item.name)
            assert not path.is_absolute() and '..' not in path.parts
            if item.issym() or item.islnk():
                assert not Path(item.linkname).is_absolute()
                # Official Node's links must resolve within its named root.
                resolved=(tools/path.parent/item.linkname).resolve()
                assert resolved.is_relative_to(tools/'node-v22.20.0-linux-x64')
        archive.extractall(tools,filter='data')
    jq=Path('/usr/bin/jq')
    assert jq.is_file() and not jq.is_symlink() and jq.stat().st_uid==0 and not os.access(jq,os.W_OK), 'JQ_NOT_TRUSTED_SYSTEM_FILE'
    assert hashlib.sha256(jq.read_bytes()).hexdigest()==M['downloads']['jq']['sha256']
    assert run('trusted-jq-version',[str(jq),'--version'],10).decode().strip()=='jq-1.8.1'
    os.environ['PATH']=str(tools/'node-v22.20.0-linux-x64/bin')+os.pathsep+os.environ['PATH']
    assert run('node-version',['node','--version'],10).decode().strip()=='v22.20.0'
    assert run('npm-version',['npm','--version'],10).decode().strip()=='10.9.3'
    os.environ.update({'UV_CACHE_DIR':'/cache/uv','PREK_HOME':'/cache/prek','CARGO_BUILD_JOBS':'2','MAGPIE_HUSKY_TARBALL':'/inputs/husky.tgz','TIKTOKEN_CACHE_DIR':'/cache/tiktoken'})
    assert Path(os.environ['MAGPIE_HUSKY_TARBALL']).stat().st_size==2448
    token=Path('/cache/tiktoken');token.mkdir()
    data=Path('/inputs/tokenizer.bpe').read_bytes()
    assert len(data)==1681126 and hashlib.sha256(data).hexdigest()==M['tokenizer']['sha256']
    (token/M['tokenizer']['cache_key']).write_bytes(data)
    run('frozen-sync',['uv','sync','--frozen','--all-packages','--group','dev'],600)
    assert re.fullmatch(r'prek 0\.5\.6(?: \(.*\))?',run('prek-version',['uv','run','--frozen','prek','--version'],15).decode().strip())
    # Do not use unfiltered install-hooks: it can fetch the prohibited manual CLI.
    # This real targeted check installs the Rust hook normally and measures its build.
    run('cold-lychee',['uv','run','--frozen','prek','run','lychee','--all-files'],1650)
    lychees=list(Path('/cache/prek/hooks').glob('rust-*/bin/lychee'))
    assert len(lychees)==1
    assert run('lychee-version',[str(lychees[0]),'--version'],15).decode().strip()=='lychee 0.24.2'
    locks=list(Path('/cache/prek').glob('**/lychee-0.24.2/Cargo.lock'))
    assert len(locks)==1 and hashlib.sha256(locks[0].read_bytes()).hexdigest()==M['lychee_lock_sha256']
    installed=list(Path('/cache/prek/hooks').glob('rust-*/.crates2.json'))
    assert len(installed)==1
    (R/'cargo-install.json').write_bytes(installed[0].read_bytes())
    rustcs=list(Path('/cache/prek/tools').glob('**/bin/rustc'))
    cargos=list(Path('/cache/prek/tools').glob('**/bin/cargo'))
    assert len(rustcs)==len(cargos)==1
    assert run('rustc-version',[str(rustcs[0]),'--version'],15).decode().startswith('rustc 1.99.1 ')
    run('cargo-version',[str(cargos[0]),'--version'],15)
    result['bootstrap']=guard()
    assert min(50*60-(time.monotonic()-BEGIN),HOST_DEADLINE-time.time())>=600, 'INSUFFICIENT_TIME_FOR_FULL_VALIDATION'
    PHASE='validation'
    # Generator exits1 on its first legitimate write; the check run must be clean.
    run('generate-hooks',['python3','tools/dev/sync-hook-managers.py'],60,accepted=(0,1))
    run('check-generated-hooks',['python3','tools/dev/sync-hook-managers.py','--check'],60)
    run('shared-blocks',['python3','tools/dev/check-shared-blocks.py','--fix'],120,accepted=(0,1))
    run('check-shared-blocks',['python3','tools/dev/check-shared-blocks.py'],120)
    run('skill-hashes',['python3','tools/dev/skill-surface-hash.py','--fix'],120,accepted=(0,1))
    run('check-skill-hashes',['python3','tools/dev/skill-surface-hash.py'],120)
    env=dict(os.environ,PYTHONPATH='tools/setup-preflight/src')
    run('fingerprint',['python3','-m','setup_preflight.isolated','write-constant'],60,accepted=(0,1),env=env)
    run('check-fingerprint',['python3','-m','setup_preflight.isolated','check-constant'],60,env=env)
    run('preflight-fixtures',['python3','tools/dev/render-preflight-fixtures.py'],120,accepted=(0,1))
    run('check-preflight-fixtures',['python3','tools/dev/render-preflight-fixtures.py','--check'],120)
    run('doc-counts',['python3','tools/dev/check-doc-sync.py','--fix'],120)
    run('check-doc-counts',['python3','tools/dev/check-doc-sync.py'],120)
    before=hashes()
    run('generate-hooks-second',['python3','tools/dev/sync-hook-managers.py','--check'],60)
    run('fingerprint-second',['python3','-m','setup_preflight.isolated','write-constant'],60,env=env)
    run('shared-blocks-second',['python3','tools/dev/check-shared-blocks.py'],120)
    run('skill-hashes-second',['python3','tools/dev/skill-surface-hash.py'],120)
    run('fixtures-second',['python3','tools/dev/render-preflight-fixtures.py','--check'],120)
    run('docs-second',['python3','tools/dev/check-doc-sync.py'],120)
    assert before==hashes(), 'GENERATOR_SECOND_RUN_CHANGED_SOURCE'
    changed=run('changed-paths',['git','diff','--name-only','HEAD'],10).decode().splitlines()
    assert set(x['path'] for x in M['source']).issubset(set(changed))
    (R/'changed-paths.txt').write_text('\n'.join(changed)+'\n')
    members=run('selected-members',['python3','tools/dev/ci-pytest-batches.py','--changed-file',str(R/'changed-paths.txt'),'--paths'],30).decode().splitlines()
    assert {'tools/agent-isolation','tools/setup-preflight','tools/dev','tools/sandbox-lint'}.issubset(set(members))
    result['selected_members']=members
    suite_env=dict(os.environ)
    suite_env.pop('MAGPIE_HUSKY_TARBALL',None)
    result['suite_husky_note']='Real Husky tests intentionally skip in default-temp member suites and must pass with zero skips in dedicated /fixtures lane.'
    for i,member in enumerate(members):
        assert (S/member).resolve().is_relative_to(S) and (S/member/'pyproject.toml').is_file()
        run('suite-'+str(i),['uv','run','--frozen','--directory',member,'--project','.','python','-m','pytest','--color=no','-n','2','--junitxml='+str(R/('suite-'+str(i)+'.xml'))],600,env=suite_env)
    run('real-husky',['uv','run','--frozen','--directory','tools/setup-preflight','--project','.','python','-m','pytest','tests/test_husky_integration.py','--color=no','--basetemp=/fixtures/real-husky','--junitxml='+str(R/'real-husky.xml')],180)
    doc=ET.parse(R/'real-husky.xml')
    cases=doc.findall('.//testcase')
    assert cases and not doc.findall('.//skipped') and not doc.findall('.//failure') and not doc.findall('.//error'), 'REAL_HUSKY_SKIP_OR_FAILURE'
    tested=hashes()
    run('nonmanual',['uv','run','--frozen','prek','run','--all-files','--skip','workspace-pytest'],600)
    assert tested==hashes(), 'NONMANUAL_CHANGED_TESTED_SOURCE'
    assert shutil.which('claude') is None, 'UNEXPECTED_CLAUDE_CLI'
    checked=[]
    for root in [Path('/cache/prek'),Path.home()]:
        for file in root.rglob('package.json'):
            assert file.stat().st_size<4*1024**2
            metadata=json.loads(file.read_text())
            assert metadata.get('name')!='@anthropic-ai/claude-code', 'PROHIBITED_CLI_PACKAGE'
            checked.append(str(file))
        for file in root.rglob('.prek-hook.json'):
            assert file.stat().st_size<1024**2
            assert '@anthropic-ai/claude-code' not in file.read_text(), 'PROHIBITED_HOOK_INSTALL'
        assert not list(root.glob('**/node_modules/@anthropic-ai/claude-code')), 'PROHIBITED_CLI_DIRECTORY'
    result['manual_cli_absent']={'package_manifests_checked':len(checked),'executable_absent':True}
    for i,folder in enumerate(Path('/cache/prek/hooks').glob('node-*')):
        # Record a normal resolver result; never compare with an invented snapshot.
        run('node-tree-'+str(i),['npm','ls','--global','--prefix',str(folder),'--all','--json'],30)
    for i,python in enumerate(Path('/cache/prek/hooks').glob('python-*/bin/python')):
        run('python-freeze-'+str(i),['uv','pip','freeze','--python',str(python)],30)
    totals=[]
    for xml in sorted(R.glob('suite-*.xml')):
        suites=ET.parse(xml).findall('.//testsuite')
        count={'file':xml.name,**{k:sum(int(x.get(k,'0')) for x in suites) for k in ['tests','failures','errors','skipped']}}
        assert count['tests']>0 and count['failures']==count['errors']==0, 'INVALID_SUITE_RESULT'
        totals.append(count)
    result.update({'status':'FULL_VALIDATION_PASS','full_validation':True,'real_husky_cases':len(cases),'test_suites':totals,'final_source_manifest_sha256':hashlib.sha256(json.dumps(tested,sort_keys=True).encode()).hexdigest(),'changed_source_hashes':{k:tested[k] for k in changed if k in tested},'resources':guard()})
    (R/'validated.patch').write_bytes(run('final-patch',['git','diff','--binary','HEAD'],15,cap=1024**2))
except BaseException as ex:
    result.update({'status':'STOP_NO_RETRY','error':type(ex).__name__+': '+str(ex)})
finally:
    result.update({'elapsed_seconds':time.monotonic()-BEGIN,'observed_cgroup_peak':PEAK,'commands':COMMANDS})
    (R/'result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({'status':result['status'],'elapsed_seconds':result['elapsed_seconds'],'error':result.get('error')}),flush=True)
if not result['full_validation']:
    sys.exit(1)
