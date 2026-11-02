# Radeon power telemetry

The AMD PMLog board-power sensor (73) is preferred over ASIC power (23).
The identifier comes from AMD's MIT-licensed [ADL header at commit
84c881c](https://github.com/GPUOpen-LibrariesAndSDKs/display-library/blob/84c881cb2136f04287eb3af12de00a9e2867aa9e/include/adl_defines.h).
No driver settings are changed. The existing signed System32 ADL library is used
and the adapter is matched to the OpenCL PCI address, not its enumeration order.

`gpu-health` retains `power_w` and adds `power_scope` (`board`, `asic`, or
`unavailable`) and `power_source`. A supported zero is distinct from an absent
sensor. Invalid or unsupported board readings can fall back to ASIC readings,
but those must not be integrated as whole-card energy. Missing power is `null`.

Board watts fluctuate as the duty governor alternates work and rest. Energy
integrated from these samples is an estimate for the graphics card during the
observed session, not a calibrated wall-meter measurement or the entire PC's
consumption. CPU, disks and PSU losses are excluded. A new session starts a new
energy counter; no historic energy is reconstructed from previously absent data.
Thermal pause/resume remains 80/60 C and power telemetry cannot disable it.
