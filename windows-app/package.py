from pathlib import Path
import argparse,base64,hashlib,json,os,subprocess,zipfile

root=Path(__file__).resolve().parents[1]
parser=argparse.ArgumentParser()
parser.add_argument('--release-dir',type=Path,default=root/'release/nvvpn-0.4.4')
parser.add_argument('--version',default=(root/'windows-app/release-version.txt').read_text().strip())
parser.add_argument('--commit',default='uncommitted')
args=parser.parse_args(); release=args.release_dir.resolve(); version=args.version
import re
if not re.fullmatch(r'0\.[0-9]+\.[0-9]+',version):raise RuntimeError('Invalid version')
out=release/'app'
go=Path(os.environ.get('NVVPN_GO',str(root/'tools/split-prototype/toolchain/go/bin/go.exe')))
goroot=go.resolve().parents[1]
env=os.environ.copy();env['GOPATH']=str(root/'tools/split-prototype/gopath');env['GOCACHE']=str(root/'tools/split-prototype/gocache');env['GOTOOLCHAIN']='local';env['GOPROXY']='off'
output=subprocess.check_output([str(go),'list','-tags','with_gvisor','-deps','-f','{{if .Module}}{{.Module.Path}}|{{.Module.Version}}|{{.Module.Dir}}{{end}}','.'],cwd=root/'windows-app/engine',env=env,text=True)
modules={}
for line in output.splitlines():
    if line.strip():
        name,version,directory=line.split('|');modules[name]=(version,Path(directory))
def read_notice(f):
    try:return f.read_text(encoding='utf-8-sig')
    except UnicodeDecodeError:return f.read_text(encoding='cp1252')

notices=['NVVPN '+version+'\n\nThe combined routing engine is provided under GPL-3.0-or-later. Third-party components retain their licenses. Source archive accompanies this build. No warranty. NVVPN is an independent project, not an official Amnezia application.\nSee NVVPN/windows-app/LICENSE-AUDIT.md and SOURCE-README.md inside NVVPN-Sources.zip.\n']
sourcezip=out/'NVVPN-Sources.zip'
manifest=[]
if version!=(root/'windows-app/release-version.txt').read_text().strip():raise RuntimeError('Source version mismatch')
with zipfile.ZipFile(sourcezip,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    z.writestr('BUILD-INFO.json',json.dumps({'version':version,'commit':args.commit,'platform':'windows-x64','go':'go1.27.4','dotnet':'4.8','inno':'7.1.1'},indent=2))
    for relative in ['windows-app/release-version.txt','windows-app/release-notes.txt','windows-app/RELEASE-GUIDE.md','windows-app/Updates.cs','windows-app/UpdateInstall.cs','windows-app/UpdateUI.cs','windows-app/UpdateTests.cs','windows-app/UpdateScenario.cs','windows-app/UpdateTrust.cs','windows-app/ReleaseTools.cs','windows-app/LocalDiagnostics.cs','windows-app/Agreement.cs','windows-app/AgreementDialog.cs','windows-app/AgreementTests.cs','windows-app/Agreement.ru.txt','windows-app/OWNER-DECISIONS.md','windows-app/assets/ConnectionArt.jpg','windows-app/assets/ART-PROVENANCE.md','windows-app/App.cs','windows-app/MainWindow.cs','windows-app/MainWindow.xaml','windows-app/Lifecycle.cs','windows-app/Startup.cs','windows-app/rebuild-source.ps1','windows-app/SOURCE-README.md','windows-app/LICENSE-AUDIT.md','windows-app/LICENSE-REMEDIATION.md','windows-app/OWN-CODE-LICENSE-DECISION.md','windows-app/build.ps1','windows-app/build-installer.ps1','windows-app/README.md','windows-app/package.py','windows-app/installer/NVVPN.iss','windows-app/installer/make-icon.ps1','src/Profile.cs','windows-app/app.manifest']:
        z.write(root/relative,'NVVPN/'+relative)
    for f in (root/'windows-app/engine').glob('*'):
        if f.is_file() and (f.suffix=='.go' or f.name in ('go.mod','go.sum')):z.write(f,'NVVPN/windows-app/engine/'+f.name)
    for i,(name,(version,directory)) in enumerate(sorted(modules.items())):
        if name.startswith('finlandvpn.local'):continue
        prefix='dependencies/'+str(i).zfill(3)
        license_files=[f for f in directory.iterdir() if f.is_file() and f.name.upper().startswith(('LICENSE','COPYING'))]
        if not license_files:raise RuntimeError('Missing license for '+name)
        license_text='\n'.join(read_notice(f) for f in license_files)
        if 'either version 3' in license_text:license_id='GPL-3.0-or-later'
        elif 'Mozilla Public License' in license_text:license_id='MPL-2.0'
        elif 'Apache License' in license_text:license_id='Apache-2.0'
        elif 'free and unencumbered' in license_text:license_id='Unlicense'
        elif 'Permission is hereby granted' in license_text:license_id='MIT'
        elif 'Redistribution and use in source and binary' in license_text:license_id='BSD-3-Clause' if ('Neither the name' in license_text or 'neither the name' in license_text) else 'BSD-2-Clause'
        else:raise RuntimeError('Unclassified license for '+name)
        escaped=''.join('!'+c.lower() if c.isupper() else c for c in name)
        cache=root/'tools/split-prototype/gopath/pkg/mod/cache/download'/escaped/'@v'
        modulezip=cache/(version+'.zip')
        if not modulezip.is_file():raise RuntimeError('Missing source module archive '+name)
        manifest.append({'module':name,'version':version,'source':prefix,'upstream':'https://'+name.removesuffix('/v3').removesuffix('/v2').removesuffix('/v5') if name.startswith('github.com/') else 'https://'+name,'license':license_id,'licenseFiles':{f.name:hashlib.sha256(f.read_bytes()).hexdigest() for f in license_files},'moduleZipSHA256':hashlib.sha256(modulezip.read_bytes()).hexdigest()})
        z.write(modulezip,'NVVPN/tools/split-prototype/gopath/pkg/mod/cache/download/'+escaped+'/@v/'+version+'.zip')
        for f in directory.rglob('*'):
            if not f.is_file() or '.git' in f.parts:continue
            relative=f.relative_to(directory).as_posix()
            z.write(f,prefix+'/'+relative)
            if f.name.upper().startswith(('LICENSE','COPYING','NOTICE','PATENTS')) and f.stat().st_size<1000000:
                notices.append('\n\n===== '+name+' '+version+' / '+relative+' =====\n'+read_notice(f))
    # Explicit metadata allowlist from the reviewed engine go.sum and compiled modules.
    # Never enumerate the developer's complete module cache (may contain unrelated projects).
    cache=root/'tools/split-prototype/gopath/pkg/mod/cache/download'
    metadata={}
    mod_sums={}
    for line in (root/'windows-app/engine/go.sum').read_text(encoding='utf-8').splitlines():
        name,version,checksum=line.split()
        if version.endswith('/go.mod'):mod_sums[(name,version[:-7])]=checksum
    used={(name,version) for name,(version,_) in modules.items() if version}
    for name,version in sorted(set(mod_sums)|used):
        escaped=''.join('!'+c.lower() if c.isupper() else c for c in name)
        escaped_version=''.join('!'+c.lower() if c.isupper() else c for c in version)
        for extension in ('.mod','.info') if (name,version) in used else ('.mod',):
            f=cache/escaped/'@v'/(escaped_version+extension)
            if not f.is_file():
                if (name,version) in used:raise RuntimeError('Missing used module metadata '+str(f))
                continue # An unused go.sum record does not require downloading its module graph.
            data=f.read_bytes()
            expected=mod_sums.get((name,version))
            if extension=='.mod' and expected:
                # Go dirhash.Hash1 with the single go.mod file.
                actual='h1:'+base64.b64encode(hashlib.sha256((hashlib.sha256(data).hexdigest()+'  go.mod\n').encode()).digest()).decode()
                if actual!=expected:raise RuntimeError('go.mod checksum mismatch '+name+' '+version)
            relative=f.relative_to(cache).as_posix()
            metadata[relative]={'sha256':hashlib.sha256(data).hexdigest(),'module':name,'version':version,'goSum':expected if extension=='.mod' else None}
            z.write(f,'NVVPN/tools/split-prototype/gopath/pkg/mod/cache/download/'+relative)
    z.writestr('MODULE-METADATA.json',json.dumps(metadata,indent=2))
    supplement=root/'vendor/license-supplement'
    provenance=json.loads((supplement/'PROVENANCE.json').read_text(encoding='utf-8'))
    for relative,record in provenance['files'].items():
        f=(supplement/relative).resolve()
        if not f.is_relative_to(supplement.resolve()) or not f.is_file():raise RuntimeError('Invalid supplement path '+relative)
        if hashlib.sha256(f.read_bytes()).hexdigest()!=record['sha256']:raise RuntimeError('Supplement checksum mismatch '+relative)
        z.write(f,'NVVPN/vendor/license-supplement/'+relative)
    z.write(supplement/'PROVENANCE.json','NVVPN/vendor/license-supplement/PROVENANCE.json')
    for relative in ['LICENSE','PATENTS','VERSION']:
        if (goroot/relative).is_file():z.write(goroot/relative,'Go-runtime-source/'+relative)
    for f in sorted((goroot/'src').rglob('*')):
        if f.is_file():
            z.write(f,'Go-runtime-source/src/'+f.relative_to(goroot/'src').as_posix())
            if f.name.upper().startswith(('LICENSE','COPYING','NOTICE','PATENTS')) and f.stat().st_size<1000000:
                notices.append('\n\n===== Go standard library / '+f.relative_to(goroot/'src').as_posix()+' =====\n'+read_notice(f))
    for relative in ['vendor/licenses/wintun-binary-LICENSE.txt','vendor/licenses/inno-setup-LICENSE.txt','vendor/sing-box-source/LICENSE']:
        z.write(root/relative,'NVVPN/'+relative)
    z.writestr('DEPENDENCIES.json',json.dumps(manifest,indent=2))
    z.write(supplement/'GPL-3.0.txt','LICENSE-GPL-3.0-or-later.txt')
    z.write(supplement/'LGPL-3.0.txt','LICENSE-LGPL-3.0.txt')
    z.write(root/'vendor/engine/wintun.dll','NVVPN/vendor/engine/wintun.dll')
    z.write(root/'vendor/licenses/wintun-binary-LICENSE.txt','LICENSE-WINTUN.txt')
notices.append('\n\n===== Wintun official binary =====\n'+(root/'vendor/licenses/wintun-binary-LICENSE.txt').read_text(encoding='utf-8-sig'))
notices.append('\n\n===== Go runtime =====\n'+(goroot/'LICENSE').read_text(encoding='utf-8'))
notices.append('\n\n===== Inno Setup installer =====\n'+(root/'vendor/licenses/inno-setup-LICENSE.txt').read_text(encoding='utf-8-sig'))
notices.append('\n\n===== Inno Setup bundled runtime components =====\n'+read_notice(supplement/'INNO-RUNTIME-NOTICES.txt'))
notices.append('\n\n===== GNU GPL version 3 (engine: version 3 or later) =====\n'+read_notice(supplement/'GPL-3.0.txt'))
notices.append('\n\n===== GNU LGPL version 3 =====\n'+read_notice(supplement/'LGPL-3.0.txt'))
notices.append('\n\n===== GNU LGPL version 2.1 (LZMA legacy license reference) =====\n'+read_notice(supplement/'LGPL-2.1.txt'))
notices.append('\n\n===== WinDivert 2.2.2 corresponding driver source =====\nOfficial v2.2.2 driver C source, headers and WDK/build scripts are in NVVPN/vendor/license-supplement/WinDivert-2.2.2-source.zip. Binary and source provenance hashes are in PROVENANCE.json and WINDIVERT-OFFICIAL-HASHES.json. See NVVPN/windows-app/LICENSE-REMEDIATION.md for limitations and rebuild guidance.\n')
notices.append('\n===== gVisor af_xdp_ebpf.o =====\nApache-2.0 in the ELF license section and exact upstream C source; supplemental source and build rule included. This Linux object is distributed with source dependencies, not linked into the Windows engine.\n')
(out/'THIRD-PARTY-NOTICES.txt').write_text(''.join(notices),encoding='utf-8')
(out/'README.txt').write_bytes((root/'windows-app/README.md').read_bytes())
(out/'DEPENDENCIES.json').write_text(json.dumps(manifest,indent=2),encoding='utf-8')
names=['NVVPN.exe','NVVPN.exe.config','NVVPN.Engine.exe','wintun.dll','NVVPN.Engine.exe.sha256','wintun.dll.sha256','README.txt','THIRD-PARTY-NOTICES.txt','DEPENDENCIES.json','NVVPN-Sources.zip']
hashes=''.join(hashlib.sha256((out/n).read_bytes()).hexdigest()+'  '+n+'\n' for n in names)
(out/'SHA256SUMS.txt').write_text(hashes,encoding='utf-8')
archive=release/('NVVPN-'+version+'-Windows-x64.zip')
with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED,compresslevel=6) as z:
    for n in names+['SHA256SUMS.txt']:z.write(out/n,'NVVPN-'+version+'/'+n)
print(json.dumps({'package':str(archive),'bytes':archive.stat().st_size,'sha256':hashlib.sha256(archive.read_bytes()).hexdigest(),'sourceModules':len(manifest)}))
