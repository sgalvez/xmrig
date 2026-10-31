"""Apply reviewed changes only to the exact pinned upstream files; fail on drift."""
import hashlib
import json
import shutil
import sys
from pathlib import Path


def apply(root):
    policy = Path(__file__).with_name('hardening')
    for change in json.loads((policy / 'changes.json').read_text()):
        path = root / change['path']
        content = path.read_bytes()
        digest = hashlib.sha256(content).hexdigest()
        if digest == change['after_sha256']:
            continue
        if digest != change['before_sha256']:
            raise ValueError('Unexpected upstream file: ' + change['path'])
        text = content.decode()
        for before, after in change['replacements']:
            if text.count(before) != 1:
                raise ValueError('Ambiguous patch: ' + change['path'])
            text = text.replace(before, after)
        if hashlib.sha256(text.encode()).hexdigest() != change['after_sha256']:
            raise ValueError('Patch result mismatch: ' + change['path'])
        path.write_bytes(text.encode())
    destination = root / 'src/personal'
    destination.mkdir(exist_ok=True)
    for header in policy.glob('*.h'):
        shutil.copyfile(header, destination / header.name)


if __name__ == '__main__':
    apply(Path(sys.argv[1]))
