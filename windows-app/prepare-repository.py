"""Export an explicit source allowlist to a new local publication directory. Never pushes."""
from pathlib import Path
import argparse, ast, hashlib, json, re, shutil

root = Path(__file__).resolve().parents[1]
parser = argparse.ArgumentParser()
parser.add_argument('destination', type=Path)
parser.add_argument('--refresh', action='store_true', help='Update only allowlisted files; retain local Git history')
args = parser.parse_args()
destination = args.destination.resolve()
if destination == root or root.is_relative_to(destination):
    raise SystemExit('Destination must not be the working root or its parent')
if destination.exists() and not args.refresh:
    raise SystemExit('Destination exists; use a new directory')

tree = ast.parse((root/'windows-app/package.py').read_text(encoding='utf-8-sig'))
paths = set()
for node in ast.walk(tree):
    if isinstance(node, ast.For) and isinstance(node.target, ast.Name) and node.target.id == 'relative' and isinstance(node.iter, ast.List):
        for element in node.iter.elts:
            if isinstance(element, ast.Constant) and isinstance(element.value, str) and element.value.startswith(('windows-app/', 'src/', 'vendor/')):
                paths.add(element.value)
paths.add('windows-app/prepare-repository.py')
paths.update(('LICENSE','LICENSING.md'))
for p in (root/'windows-app/engine').iterdir():
    if p.is_file() and (p.suffix=='.go' or p.name in ('go.mod','go.sum')):
        paths.add(p.relative_to(root).as_posix())
provenance=json.loads((root/'vendor/license-supplement/PROVENANCE.json').read_text(encoding='utf-8'))
paths.add('vendor/license-supplement/PROVENANCE.json')
for relative in provenance['files']:
    paths.add('vendor/license-supplement/'+relative)
# Exact official DLL is needed by the documented source build; retain its license.
paths.add('vendor/engine/wintun.dll')
records={}
for relative in sorted(paths):
    p=root/relative
    if not p.resolve().is_relative_to(root) or p.is_symlink() or p.is_junction():
        raise SystemExit('Unsafe source path')
    for parent in p.parents:
        if parent==root: break
        if parent.is_symlink() or parent.is_junction(): raise SystemExit('Source path traverses a link')
    if p.suffix.lower() in ('.dpapi','.conf','.key','.pfx','.p12','.jks','.keystore') or 'private' in p.relative_to(root).parts:
        raise SystemExit('Private source rejected')
    data=p.read_bytes()
    if p.suffix.lower() in ('.cs','.go','.md','.txt','.ps1','.py','.iss','.json','.xaml'):
        text=data.decode('utf-8-sig', errors='replace')
        # Do not report matching contents, only fail the export.
        if re.search(r'-----BEGIN (?:RSA |OPENSSH |EC )?PRIVATE KEY-----|gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{30,}|sk-proj-[A-Za-z0-9_-]{20,}',text):
            # This publisher scanner contains the pattern as source text, not an actual credential.
            if relative!='windows-app/prepare-repository.py': raise SystemExit('Credential pattern rejected in '+relative)
        if re.search(r'[A-Z]:[\\/]Users[\\/]',text,re.I): raise SystemExit('Personal filesystem path rejected in '+relative)
    records[relative]={'sha256':hashlib.sha256(data).hexdigest(),'bytes':len(data)}
# Validate all inputs before making the destination visible.
destination.mkdir(parents=True,exist_ok=True)
for relative in sorted(paths):
    target=destination/relative
    if target.is_symlink() or target.is_junction(): raise SystemExit('Destination link rejected')
    target.parent.mkdir(parents=True,exist_ok=True)
    shutil.copyfile(root/relative,target)
(destination/'PUBLIC-FILES.json').write_text(json.dumps(records,indent=2),encoding='utf-8')
(destination/'.gitignore').write_text('private/\nartifacts/\nrelease/\nrebuilt-*/\n/tools/\n*.dpapi\n*.conf\n*.key\n*.pfx\n*.p12\n*.jks\n*.keystore\nwindows-app/installer/hashes.iss\nwindows-app/installer/NVVPN.ico\n',encoding='utf-8')
(destination/'README.md').write_text('''# NVVPN

Клиент Windows x64 на основе AmneziaWG. Владелец канала: tunnelnv-stack.
Контакт: tunnelnv@gmail.com. Исходники этого дерева соответствуют указанной в
windows-app/release-version.txt версии. Инструкции: windows-app/SOURCE-README.md
и windows-app/RELEASE-GUIDE.md.

Зависимости с точными версиями и материалами пересборки предоставляются полным
NVVPN-X.Y.Z-Source.zip вместе с каждым выпуском. Самого автоматического
GitHub Source code.zip недостаточно для автономной сборки без модулей.

Оригинальные части NVVPN: GPL-3.0-or-later, Copyright (C) 2026 NVVPN contributors.
Область действия: LICENSING.md. Лицензии, исходники и уведомления сторонних авторов
сохранены в соответствующих полных Source ZIP. Исторические аудиты сохранены.
Обновления: https://github.com/tunnelnv-stack/NVVPN/releases/latest
Подлинность обновлений проверяется подписью RSA-3072/SHA-256 манифеста и хешем
установщика. Authenticode-подписи издателя у EXE нет. Автоподключения VPN нет.

PUBLIC-FILES.json содержит проверенный список исходных файлов. Личные профили,
закрытые ключи, подписи и рабочие журналы исключены. Наличие сканера не заменяет
проверку истории Git и полного состава каждого архива перед публикацией.
''',encoding='utf-8')
print(json.dumps({'files':len(records),'destination':str(destination),'published':False}))
