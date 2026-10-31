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
    assert elapsed < 40*60 and time.time()<HOST_DEADLINE, 'INNER_TARGET_TIME'
    if PHASE == 'bootstrap':
        assert elapsed < 12*60, 'BOOTSTRAP_TIME'
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
    assert working < 9*1024**3, 'CGROUP_MEMORY_PRESSURE'
    received = sum(int(x.read_text()) for x in Path('/sys/class/net').glob('*/statistics/rx_bytes') if x.parents[1].name!='lo')-NETWORK_START
    assert received <= 3*1024**3, 'NETWORK_CAP'
    sample = {'elapsed':elapsed,'phase':PHASE,'memory_current':current,'working_set':working,'memory_peak':peak,'network_received':received}
    (R/'latest-resource.json').write_text(json.dumps(sample))
    return sample



def storage_snapshot(label):
    info = {}
    for name in ('/project', '/runtime', '/cache', '/tmp', '/home/validation'):
        row = {}
        for key, argv in [('blocks', ['df', '-h', name]), ('inodes', ['df', '-i', name])]:
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=5)
            assert proc.returncode == 0
            row[key] = proc.stdout
        info[name] = row
    with (R / 'storage.jsonl').open('a') as stream:
        stream.write(json.dumps({'label': label, 'mounts': info}) + '\n')


def run(label, argv, seconds=300, accepted=(0,), cap=4*1024**2, env=None):
    assert re.fullmatch('[a-z0-9-]+',label) and not (R/(label+'.log')).exists()
    storage_snapshot(label+'-before')
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
        storage_snapshot(label+'-after')

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
    assert not run('clean-baseline',['git','status','--porcelain'],10)
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
    os.environ.update({'PYTHONDONTWRITEBYTECODE':'1','PYTEST_XDIST_AUTO_NUM_WORKERS':'2','UV_HTTP_RETRIES':'0','UV_CACHE_DIR':'/cache/uv','PREK_HOME':'/cache/prek','CARGO_BUILD_JOBS':'2','TIKTOKEN_CACHE_DIR':'/cache/tiktoken'})
    token=Path('/cache/tiktoken');token.mkdir()
    data=Path('/inputs/tokenizer.bpe').read_bytes()
    assert len(data)==1681126 and hashlib.sha256(data).hexdigest()==M['tokenizer']['sha256']
    (token/M['tokenizer']['cache_key']).write_bytes(data)
    run('frozen-sync',['uv','sync','--frozen','--all-packages','--group','dev'],600)
    assert re.fullmatch(r'prek 0\.5\.6(?: \(.*\))?',run('prek-version',['uv','run','--frozen','prek','--version'],15).decode().strip())
    # Do not use unfiltered install-hooks: it can fetch the prohibited manual CLI.
    # This real targeted check installs the Rust hook normally and measures its build.
    MEMBER='tools/mail-source/imap'
    def package_pytest(label, extra=(), accepted=(0,)):
        return run(label,['uv','run','--frozen','--directory',MEMBER,'--project','.',
                          'python','-m','pytest','--color=no','-n','2',
                          '--junitxml='+str(R/(label+'.xml')),*extra],180,accepted=accepted)

    def junit(label, *, failures=False):
        tree=ET.parse(R/(label+'.xml'))
        cases=tree.findall('.//testcase')
        assert cases and not tree.findall('.//error'), 'EMPTY_OR_COLLECTION_ERROR_'+label
        failed=[x for x in cases if x.find('failure') is not None]
        skipped=[x for x in cases if x.find('skipped') is not None]
        assert not skipped, 'UNEXPECTED_SKIPS_'+label
        assert bool(failed)==failures, 'UNEXPECTED_TEST_OUTCOME_'+label
        return cases,failed

    package_pytest('baseline-full')
    baseline_cases,_=junit('baseline-full')
    run('patch-check',['git','apply','--check',str(P/'I1.patch')],15)
    run('apply-patch',['git','apply','--index',str(P/'I1.patch')],15)
    for row in M['source']:
        assert hashlib.sha256((S/row['path']).read_bytes()).hexdigest()==row['sha256']
    run('ruff-fix',['uv','run','--frozen','--directory',MEMBER,'--project','.',
                    'ruff','check','--fix','.'],60)
    run('ruff-format',['uv','run','--frozen','--directory',MEMBER,'--project','.',
                       'ruff','format','.'],60)
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
    assert time.time()+15*60 < float(os.environ['VALIDATION_TARGET_EPOCH']), 'INSUFFICIENT_TIME_FOR_FULL_VALIDATION'

    PHASE='validation'
    # The full required non-manual hook suite precedes the tests so every
    # byte that those hooks legitimately change is part of the tested result.
    run('nonmanual',['uv','run','--frozen','prek','run','--all-files','--skip','workspace-pytest'],900)
    run('zizmor',['uv','run','--frozen','zizmor','--config','.zizmor.yml','.'],120)
    changed=run('changed-paths',['git','diff','--name-only','HEAD'],10).decode().splitlines()
    assert set(changed)=={x['path'] for x in M['source']}, 'UNRELATED_SOURCE_MUTATION'
    (R/'changed-paths.txt').write_text('\n'.join(changed)+'\n')
    candidate={x['path']:(S/x['path']).read_bytes() for x in M['source']}
    (R/'formatter.diff').write_bytes(run('formatted-diff',['git','diff','--binary'],15,cap=1024**2))
    # The public-function regressions run with every production file restored
    # to the actual upstream base. No missing new-module collection oracle.
    production=[n for n in candidate if '/src/' in n]
    for index,name in enumerate(production):
        raw=run('baseline-production-'+str(index),['git','show','HEAD:'+name],10)
        (S/name).write_bytes(raw)
    package_pytest('baseline-regressions',[
        'tests/test_operations.py','tests/test_config_and_urls.py',
        'tests/test_create_draft.py','tests/test_cli_thread_ids.py','-k','bare'],accepted=(1,))
    _,failed=junit('baseline-regressions',failures=True)
    names=[x.get('name','') for x in failed]
    for prefix in ('test_read_thread_accepts_bare_message_id',
                   'test_drafts_and_sent_accept_bare_message_id',
                   'test_create_draft_accepts_bare_id_and_keeps_threading',
                   'test_thread_url_accepts_bare_id_and_emits_canonical_id',
                   'test_read_cli_accepts_bare_id'):
        assert any(name.startswith(prefix) for name in names), 'REGRESSION_NOT_REPRODUCED_'+prefix
    for case in failed:
        detail=''.join(case.find('failure').itertext())
        assert not any(x in detail for x in ('ImportError','ModuleNotFoundError','AttributeError')), 'HARNESS_FAILURE_NOT_ORACLE'
    for name in production:(S/name).write_bytes(candidate[name])
    assert all((S/n).read_bytes()==b for n,b in candidate.items())
    package_pytest('candidate-full')
    candidate_cases,_=junit('candidate-full')
    assert len(candidate_cases)>len(baseline_cases)
    assert {(x.get("classname"),x.get("name")) for x in baseline_cases}.issubset(
        {(x.get("classname"),x.get("name")) for x in candidate_cases}), "BASELINE_CASES_DROPPED"
    selected=run('selected-members',['python3','tools/dev/ci-pytest-batches.py',
                 '--changed-file',str(R/'changed-paths.txt'),'--paths'],30).decode().splitlines()
    assert MEMBER in selected and len(selected)==len(set(selected))
    for index,member in enumerate(selected):
        assert (S/member).resolve().is_relative_to(S)
        if member==MEMBER:continue
        label='dependent-'+str(index)
        run(label,['uv','run','--frozen','--directory',member,'--project','.',
                   'python','-m','pytest','--color=no','-n','2',
                   '--junitxml='+str(R/(label+'.xml'))],300)
        junit(label)
    # This is the actual upstream hook/selector on the exact branch changed
    # path list, equivalent to its --from-ref/--to-ref input without a commit.
    run('workspace-pytest',['uv','run','--frozen','prek','run','workspace-pytest','--files',*changed],300)
    assert all((S/n).read_bytes()==b for n,b in candidate.items()), 'TEST_CHANGED_SOURCE'
    # The root package has no runtime dependencies. The real uv build uses
    # the already populated official build-tool cache, with offline enforced.
    run('build-package',['uv','build',MEMBER,'--out-dir',str(R/'dist'),'--offline'],120)
    wheels=list((R/'dist').glob('*.whl'));sdists=list((R/'dist').glob('*.tar.gz'))
    assert len(wheels)==len(sdists)==1
    run('installed-venv',['uv','venv','--python',sys.executable,str(R/'installed')],30)
    run('install-wheel',['uv','pip','install','--python',str(R/'installed/bin/python'),
                         '--offline','--no-deps',str(wheels[0])],30)
    independent=R/'installed-cwd';independent.mkdir()
    installed_script=R/'installed-api.py'
    installed_script.write_text(r"""
import importlib.metadata,json,os,runpy,subprocess,sys
from pathlib import Path
os.chdir('/runtime/installed-cwd')
import imap_source
from imap_source.read_thread import read_thread
from imap_source.thread_url import resolve_thread_url
from imap_source.create_draft import create_draft
assert Path(imap_source.__file__).resolve().is_relative_to(Path('/runtime/installed'))
f=runpy.run_path('/project/tools/mail-source/imap/tests/conftest.py')
root='<report@example.org>'
config=f['make_config']()
def box():
 return f['FakeMailbox'].seed(INBOX=[f['build_message'](root,'report','reporter@example.org')],Drafts=[])
a=read_thread(box(),config,'report@example.org',since_days=90)
assert a==read_thread(box(),config,root,since_days=90) and a['thread_id']==root
assert resolve_thread_url(config,'report@example.org')==resolve_thread_url(config,root)
d=create_draft(box(),config,'report@example.org',body='synthetic',to=[],cc=[],from_address=None)
assert d['sent'] is False and d['thread_id']==root
env=dict(os.environ,IMAP_SOURCE_HOST='imap.example.org',IMAP_SOURCE_USER='triager@example.org',IMAP_SOURCE_PASSWORD='synthetic-only')
env.pop('PYTHONPATH',None)
for value in ('report@example.org',root):
 p=subprocess.run(['/runtime/installed/bin/imap-source-thread-url',value],env=env,capture_output=True,text=True,timeout=15)
 assert p.returncode==0,p.stderr
 payload=json.loads(p.stdout);assert payload['thread_id']==root and payload['url']=='imap://imap.example.org/INBOX;MSGID=report%40example.org'
print(json.dumps({'status':'PASS','distribution':importlib.metadata.version('imap-source'),'module':imap_source.__file__,'live_imap':False}))
""")
    env=dict(os.environ);env.pop('PYTHONPATH',None)
    run('installed-api-cli',[str(R/'installed/bin/python'),str(installed_script)],60,
        env=dict(env,PYTHONSAFEPATH='1'))
    assert all((S/n).read_bytes()==b for n,b in candidate.items()), 'BUILD_CHANGED_SOURCE'
    final=run('final-patch',['git','diff','--binary','--no-ext-diff','HEAD'],15,cap=1024**2)
    (R/'validated.patch').write_bytes(final)
    (R/'tested-hashes.json').write_text(json.dumps({n:hashlib.sha256(b).hexdigest() for n,b in candidate.items()},indent=2))
    assert shutil.which('claude') is None, 'UNEXPECTED_MANUAL_VENDOR_CLI'
    result.update(status='FULL_VALIDATION_PASS',full_validation=True,
                  baseline_cases=len(baseline_cases),regression_failures=len(failed),
                  candidate_cases=len(candidate_cases),selected_members=selected,
                  installed_package=True,live_imap=False,native_windows=False,
                  final_patch_sha256=hashlib.sha256(final).hexdigest(),resources=guard())
except BaseException as ex:
    result.update({'status':'STOP_NO_RETRY','error':type(ex).__name__+': '+str(ex)})
finally:
    result.update({'elapsed_seconds':time.monotonic()-BEGIN,'observed_cgroup_peak':PEAK,'commands':COMMANDS})
    (R/'result.json').write_text(json.dumps(result,indent=2))
    print(json.dumps({'status':result['status'],'elapsed_seconds':result['elapsed_seconds'],'error':result.get('error')}),flush=True)
if not result['full_validation']:
    sys.exit(1)
