"""Digest of reviewed build inputs only, never downloaded/generated products."""
import hashlib
from pathlib import Path

POLICY = 'rvn-governor-4'
RECIPE_FILES = (
    '.dockerignore', 'Dockerfile', 'sources.json', 'fetch.py', 'build.sh',
    'mingw.cmake', 'windows-libs.cmake', 'provenance.py', 'recipe.py',
    'apply_hardening.py', 'hardening/changes.json', 'hardening/TlsPolicy.h',
    'hardening/GpuWait.h', 'hardening/DonationPolicy.h', 'hardening/GpuGovernor.h', 'hardening/OclGovernor.h',
    'verify_privacy.py',
)


def recipe_digest(root=None):
    root = Path(root) if root else Path(__file__).parent
    digest = hashlib.sha256()
    for name in sorted(RECIPE_FILES):
        path = root / name
        if path.is_symlink() or not path.is_file():
            raise ValueError('Falta un archivo regular de la receta: ' + name)
        digest.update(name.encode() + b'\0')
        digest.update(hashlib.sha256(path.read_bytes()).digest())
    return digest.hexdigest()
