import hashlib
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path
from recipe import POLICY, recipe_digest

out = Path(sys.argv[1])
sources = json.loads((out / 'sources.json').read_text())
record = {'engine': 'XMRig', 'version': '6.26.0', 'target': 'windows-x86_64',
          'commit': sources['xmrig_commit'], 'sources': sources['sources'],
          'sha256': hashlib.sha256((out / 'xmrig.exe').read_bytes()).hexdigest(),
          'compiler': subprocess.check_output(['x86_64-w64-mingw32-g++-posix', '--version'], text=True).splitlines()[0],
          'built_at': datetime.now(timezone.utc).isoformat(),
          'mining_validated': False, 'donation_percent': 0.5, 'security_policy': POLICY, 'recipe_sha256': recipe_digest()}
(out / 'build.json').write_text(json.dumps(record, indent=2) + '\n')
