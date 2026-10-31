"""Small atomic local records; do not follow symlinks or expose private files."""
import json
import os
import tempfile
from pathlib import Path


def read_json(path):
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    with os.fdopen(fd) as stream:
        raw = stream.read(4_000_001)
    if len(raw) > 4_000_000:
        raise ValueError('Registro demasiado grande')
    return json.loads(raw)


def write_json(path, data):
    path = Path(path)
    fd, temporary = tempfile.mkstemp(dir=path.parent)
    try:
        with os.fdopen(fd, 'w') as stream:
            json.dump(data, stream, indent=2)
            stream.write('\n')
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
