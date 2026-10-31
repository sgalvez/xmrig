Reference integration sources for the existing personal lab

xmrig_personal/* and tests/* correspond to the same paths in
~/zerocool/xmrig-personal-lab. integration/web_status.py corresponds to
~/zerocool/ravencoin-miner-lab/web_status.py and requires that application's
existing dependencies. This is a versioned integration snapshot, not a new
wallet installation. No wallets, backups, keys or runtime configuration are
included. The terminal is read-only and never starts mining.

Tests: python3 -m unittest discover -s personal/lab/tests

Native governor details: doc/personal-governor.txt.
The local lab downloads the fork archive directly, pinned by engine commit
and SHA-256 in personal-build/sources.json. Idempotent source checks preserve
the reviewed TLS, donation and governor changes.

On the existing machine, after updating the local lab files:
  cd ~/zerocool/xmrig-personal-lab
  bash build-local.sh
  bash start.sh --resume

The new binary must be scanned, then tested on the real GPU before background
mining is authorized by the launcher. Old hash-specific Defender acceptance
and old mining validation do not authorize the new binary/profile.
