"""Download exact source archives; no miner binary or private project data."""
import hashlib
import json
import sys
import tarfile
from pathlib import Path
from urllib.request import urlopen

root = Path(sys.argv[1]).resolve()
root.mkdir(parents=True, exist_ok=True)
manifest = json.loads(Path(__file__).with_name('sources.json').read_text())
for source in manifest['sources']:
    archive = root / (source['name'] + '.tar.gz')
    if not archive.exists():
        with urlopen(source['url'], timeout=120) as response:
            archive.write_bytes(response.read())
    if hashlib.sha256(archive.read_bytes()).hexdigest() != source['sha256']:
        raise SystemExit('SHA-256 incorrecto: ' + source['name'])
    destination = root / source['name']
    destination.mkdir(exist_ok=True)
    with tarfile.open(archive) as tar:
        members = tar.getmembers()
        prefix = members[0].name.split('/')[0] + '/'
        for member in members:
            if member.name == prefix[:-1]:
                continue
            if not member.name.startswith(prefix):
                raise SystemExit('Archivo fuente con estructura inesperada')
            member.name = member.name[len(prefix):]
            tar.extract(member, destination, filter='data')
    print(source['name'], source['version'], source['sha256'], flush=True)
