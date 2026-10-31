Windows supervisor used by the personal Ravencoin lab

These are the source and isolated tests of xmrig-personal-lab/windows-xmrig.ps1.
They are committed here so the fork's native controller and its independent
supervisor can be reviewed and tested together. Tests parse/load helpers and
mock Defender/process operations; they never launch a miner or alter Defender.

This directory is not a standalone wallet or installer. The existing lab CLI,
runtime, wallet and private configuration stay outside this public repository.
The production launcher is deployed in ~/zerocool/xmrig-personal-lab; its
default sibling runtime is ~/zerocool/ravencoin-miner-lab/.runtime. Explicit
-RuntimeRoot is available. Build manifests and external trust records are
required before Install/Probe/Start. Never copy a binary over these checks.

The default mining profile is rx9070xt-duty25-intensity65536-v1. A new engine
hash or profile requires another bounded test and own-pool-share validation.
The old Defender acceptance does not authorize the new executable hash.
