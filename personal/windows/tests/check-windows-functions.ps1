# Portable tests: parse the launcher and load ONLY its helper definitions.
# Never install, launch or stop a real miner in this test.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'
$tokens = $null
$parseErrors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$parseErrors)
if ($parseErrors.Count) { throw ($parseErrors | Out-String) }
$functions = $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]}, $true)
foreach ($definition in $functions) { . ([scriptblock]::Create($definition.Extent.Text)) }
function Assert-Equal($Actual, $Expected) {
    if ($Actual -cne $Expected) { throw "Expected [$Expected], got [$Actual]" }
}
Assert-Equal (Quote-Arg 'simple') '"simple"'
Assert-Equal (Quote-Arg 'C:\Folder with spaces\file.log') '"C:\Folder with spaces\file.log"'
Assert-Equal (Quote-Arg 'C:\folder\') '"C:\folder\\"'
Assert-Equal (Quote-Arg 'a"b') '"a\"b"'

$Exe = 'C:\expected\xmrig.exe'
$time = [DateTime]::UtcNow
$script:fakeProcess = [pscustomobject]@{Id=123; Path=$Exe; StartTime=$time}
function Get-Process { param($Id, $ErrorAction) return $script:fakeProcess }
$state = [pscustomobject]@{miner_pid=123; start_ticks=$time.ToUniversalTime().Ticks.ToString()}
Assert-Equal (Owned-Process $state).Id 123
$script:fakeProcess.Path = 'C:\other\xmrig.exe'
Assert-Equal (Owned-Process $state) $null
$script:fakeProcess.Path = $Exe
$script:fakeProcess.StartTime = $time.AddSeconds(1)
Assert-Equal (Owned-Process $state) $null
Assert-Equal (Owned-Process $null) $null

$energy = @{last=$null; watts=0.0; pci=''; wh=0.0; seconds=0.0; samples=0}
$health = @{power_scope='board';power_source='adl-pmlog-board';power_w=100;polled_ms=1000;pci='03:00.0'}
Update-BoardEnergy $energy $health
$health.power_w=200; $health.polled_ms=3000
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 2.0
if ([Math]::Abs($energy.wh - (150.0 * 2 / 3600)) -gt 0.00000001) { throw 'Incorrect energy integral' }
Update-BoardEnergy $energy $health
Assert-Equal $energy.samples 2
$health.polled_ms=20000
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 2.0 # Missing interval is not filled with assumed watts.
$health.power_scope='asic'; $health.polled_ms=22000
Update-BoardEnergy $energy $health
$health.power_scope='board'; $health.polled_ms=24000
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 2.0
$health.polled_ms=26000; $health.pci='73:00.0'
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 2.0
$health.polled_ms=28000; $health.power_w=0
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 4.0
$health.polled_ms=1000
Update-BoardEnergy $energy $health
Assert-Equal $energy.seconds 4.0
$health.polled_ms=2000; $health.power_w=[double]::NaN
Update-BoardEnergy $energy $health
Assert-Equal $energy.last $null
Write-Output 'PowerShell: syntax, argument quoting and process identity checks passed.'

function Assert-Throws([scriptblock]$Body) {
    $thrown = $false
    try { & $Body } catch { $thrown = $true }
    if (-not $thrown) { throw 'Expected a blocked operation.' }
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('xmrig-test-' + [guid]::NewGuid())
$Runtime = Join-Path $temp 'runtime'
$InstallRoot = Join-Path $temp 'XMRig-6.26.0'
[void][IO.Directory]::CreateDirectory($Runtime)
[void][IO.Directory]::CreateDirectory($InstallRoot)
$Exe = Join-Path $InstallRoot 'xmrig.exe'
$ScanFile = Join-Path $Runtime 'xmrig-scan.json'
$Utf8 = New-Object Text.UTF8Encoding($false)
$Engine = 'XMRig'
$SourceCommit = 'b3dc71ad9234ca870486ea1bab83dbdd902827e3'
$GpuId = 2
# Do not change SystemRoot: Windows cryptographic providers need the real DLLs.
function Get-GpuLibraryPath([string]$Name) { return Join-Path (Join-Path $temp 'System32') $Name }
[void][IO.Directory]::CreateDirectory((Join-Path $temp 'System32'))
foreach ($name in @('OpenCL.dll','atiadlxx.dll')) { [IO.File]::WriteAllText((Join-Path (Join-Path $temp 'System32') $name), 'Fixture, never loaded.') }
$Version = 'test'
$SecurityPolicy = 'rvn-governor-4'
$MiningProfile = 'rx9070xt-duty25-timerprecise-halt80-resume60-search300-nodonate-v6'
$BuildRoot = Join-Path $temp 'artifacts'
$TrustFile = Join-Path $temp 'trusted-build.json'
function Assert-StandardUser { } # Identity APIs require actual Windows; no elevation in fixtures.
$script:avEnabled = $true
$script:detections = @()
$script:scanCode = 0
$script:detectOnScan = $false
$script:badGpuSignature = $false
# These mocks never touch Windows, Defender, the network or a real executable.
function Get-MpComputerStatus { param($ErrorAction) return @{AntivirusEnabled=$script:avEnabled; RealTimeProtectionEnabled=$script:avEnabled} }
function Get-MpThreatDetection { param($ErrorAction) return $script:detections }
function Get-AuthenticodeSignature {
    param($LiteralPath)
    if ($script:badGpuSignature -and $LiteralPath -like '*atiadlxx.dll') { return @{Status='NotSigned'} }
    return @{Status='Valid'; SignerCertificate=@{Subject='CN=Windows, O=Microsoft Corporation'}}
}
function Start-Process {
    param($FilePath, $ArgumentList, $Verb, [switch]$Wait, [switch]$PassThru)
    if ($FilePath -notlike '*MpCmdRun.exe' -or $Verb -ne 'RunAs' -or $ArgumentList -notlike '*"-ScanType" "3"*') {
        throw 'Only the Defender custom scanner may be elevated.'
    }
    if ($script:detectOnScan) { $script:detections = @(@{Resources=@("file:_$Exe"); ThreatID=123}) }
    return @{ExitCode=$script:scanCode}
}
$env:ProgramData = $temp
$env:ProgramFiles = $temp
try {
    $legacy = Join-Path $Runtime 'security-block.json'
    [IO.File]::WriteAllText($legacy, '{"component":"SRBMiner-Multi"}')
    Assert-MinerAllowed
    [IO.File]::WriteAllText($legacy, '{}')
    Assert-Throws { Assert-MinerAllowed }
    [IO.File]::WriteAllText($legacy, '{"component":"SRBMiner-Multi"}')
    [IO.File]::WriteAllText($Exe, 'This is only a hash fixture, never executed.')
    $ExeHash = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
    $manifest = Join-Path $InstallRoot 'build.json'
    @{engine=$Engine;version=$Version;commit=$SourceCommit;target='windows-x86_64';sha256=$ExeHash;
      security_policy=$SecurityPolicy;recipe_sha256=('b'*64)} | ConvertTo-Json | Set-Content $manifest
    @{sha256=$ExeHash;commit=$SourceCommit;security_policy=$SecurityPolicy;recipe_sha256=('b'*64);
      manifest_sha256=(Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content $TrustFile
    # An injected DLL must be refused even when EXE/manifest are unchanged.
    [IO.File]::WriteAllText((Join-Path $InstallRoot 'atiadlxx.dll'), 'not a DLL')
    Assert-Throws { Check-Executable }
    Remove-Item (Join-Path $InstallRoot 'atiadlxx.dll')
    # Replacing the artifact and its adjacent manifest cannot update the external anchor.
    $originalManifest = Get-Content $manifest -Raw
    $replacement = $originalManifest.Replace($ExeHash, ('c'*64))
    [IO.File]::WriteAllText($manifest, $replacement, $Utf8)
    Assert-Throws { Load-Build $InstallRoot }
    [IO.File]::WriteAllText($manifest, $originalManifest, $Utf8)
    Assert-Throws { Ready-Executable } # Unscanned binary cannot run.
    Scan-Executable
    Ready-Executable
    $script:badGpuSignature = $true
    Assert-Throws { Ready-Executable }
    $script:badGpuSignature = $false
    $script:avEnabled = $false
    Assert-Throws { Ready-Executable }
    $script:avEnabled = $true
    $script:scanCode = 2
    Assert-Throws { Scan-Executable }
    Assert-Equal (Test-Path -LiteralPath $ScanFile) $false
    $script:scanCode = 0
    $script:detectOnScan = $true
    Assert-Throws { Scan-Executable } # Code 0 + remediated detection is NOT accepted.
    Assert-Equal (Test-Path -LiteralPath $ScanFile) $false
    Assert-Equal (Test-Path -LiteralPath (Join-Path $Runtime 'xmrig-security-block.json')) $true
    Assert-Throws { Check-Executable }
    Assert-Equal (Get-Content -LiteralPath $legacy -Raw) '{"component":"SRBMiner-Multi"}'
    $script:detections = @(@{Resources=@("file:_$BuildRoot/xmrig.exe"); ThreatID=456})
    Assert-Throws { Assert-DefenderReady }
    Assert-Equal (Get-Content (Join-Path $Runtime 'xmrig-security-block.json') -Raw | ConvertFrom-Json).threat_ids[0] 456
    Assert-Equal (Test-DetectionPath 'file:_\\WSL$\Ubuntu\home\test\.artifacts\windows\xmrig.exe' '\\wsl.localhost\Ubuntu\home\test\.artifacts\windows') $true
    Assert-Equal (Test-DetectionPath "file:_$BuildRoot-other/xmrig.exe" $BuildRoot) $false

    $config = @{pool='stratum.ravenminer.com:13838'; address=('R' + ('A' * 33)); worker='rx9070xt'}
    $settings = Miner-Config $config 2 'probe-aaaaaaaaaaaaaaaaaaaa' 'C:\logs with spaces\miner.log'
    Assert-Equal $settings.cpu.enabled $false
    Assert-Equal $settings.cuda.enabled $false
    Assert-Equal $settings.http.enabled $false
    Assert-Equal $settings.autosave $false
    Assert-Equal $settings.pools[0].algo 'kawpow'
    Assert-Equal $settings.pools[0].tls $true
    Assert-Equal $settings.pools[0].user ($config.address + '.probe-aaaaaaaaaaaaaaaaaaaa')
    # Windows PowerShell must preserve fractional intervals over a full trial.
    $clock = @{last=0.0; active_seconds=0.0; cooling_seconds=0.0; search_seconds=0.0; preparation_seconds=0.0; cooling=$false; phase='search'}
    for ($i=1; $i -le 300; $i++) { Update-TrialClock $clock ($i * (319.0 / 300.0)) $false 'search' }
    if ([Math]::Abs($clock.search_seconds - 319.0) -gt 0.000001) { throw 'Fractional intervals lost precision' }
    $clock = @{last=0.0; active_seconds=0.0; cooling_seconds=0.0; search_seconds=0.0; preparation_seconds=0.0; cooling=$false; phase='dag'}
    Update-TrialClock $clock 30 $false 'search'
    Assert-Equal $clock.search_seconds 0
    Assert-Equal $clock.preparation_seconds 30
    Update-TrialClock $clock 130 $true 'search'
    Update-TrialClock $clock 3730 $false 'search'
    Update-TrialClock $clock 3930 $false 'search'
    Assert-Equal $clock.search_seconds 300
    Assert-Equal $clock.cooling_seconds 3600
    Assert-Equal $clock.active_seconds 330
    Assert-Equal (Test-TrialComplete @{search_seconds=299} 1 300) $false
    Assert-Equal (Test-TrialComplete @{search_seconds=300} 0 300) $false
    Assert-Equal (Test-TrialComplete @{search_seconds=300} $null 300) $false
    Assert-Equal (Test-TrialComplete @{search_seconds=300} $true 300) $false
    Assert-Equal (Test-TrialComplete @{search_seconds=300} 1 300) $true
    Assert-Equal (Test-TrialComplete @{search_seconds=380} 1 300) $true
    Assert-Throws { Test-TrialComplete @{search_seconds=411} 0 300 }
    Assert-Throws { Update-TrialClock $clock 3929 $false 'search' }
    Assert-Equal $settings.opencl.kawpow[0].index 2
    Assert-Equal $settings.opencl.kawpow.Count 1
    Assert-Equal $settings.opencl.kawpow[0].'gpu-duty-percent' 25
    foreach ($value in @(0,4,101,$true,$null,60.0,'60')) {
        Assert-Throws { Get-DutyPercent @{gpu_duty_percent=$value} }
    }
    Assert-Equal (Get-DutyPercent ([pscustomobject]@{gpu_duty_percent=60})) 60
    Assert-Equal (Get-MiningProfile @{gpu_duty_percent=60}) 'rx9070xt-duty60-timerprecise-halt80-resume60-search300-nodonate-v6'
    Assert-Equal (Get-WaitMode @{}) 'precise'
    Assert-Equal (Get-WaitMode @{gpu_wait_mode='legacy'}) 'legacy'
    Assert-Equal $settings.opencl.kawpow[0].'gpu-precise-wait' $true
    $legacyConfig = @{} + $config
    $legacyConfig.gpu_wait_mode = 'legacy'
    Assert-Equal (Miner-Config $legacyConfig 2 'test' 'fixture.log').opencl.kawpow[0].'gpu-precise-wait' $false
    Assert-Throws { Get-WaitMode @{gpu_wait_mode='invalid'} }
    $higher = @{} + $config
    $higher.gpu_duty_percent = 60
    Assert-Equal (Miner-Config $higher 2 'test' 'fixture.log').opencl.kawpow[0].'gpu-duty-percent' 60
    Assert-Equal $settings.'donate-level' 0.0
    Assert-Equal $settings.'health-print-time' 2
    Assert-Throws { Assert-Validated $config }
    $validated = @{mining_profile=$MiningProfile;verified=$true;engine=$Engine;security_policy=$SecurityPolicy;sha256=$ExeHash;gpu_id=2;address=$config.address;worker=$config.worker;pool=$config.pool}
    $validated | ConvertTo-Json | Set-Content (Join-Path $Runtime 'xmrig-validation.json')
    Assert-Validated $config
    Assert-Throws { Assert-Validated $higher }
    $GpuId = 1
    Assert-Throws { Assert-Validated $config }
    $log = Join-Path $Runtime 'temperature.log'
    @('gpu-health {"v":1,"gpu":2,"edge_c":55,"hotspot_c":72,"memory_c":null,"power_w":null,"fan_rpm":1800}',
      'gpu-health {"v":1,"gpu":1,"edge_c":40,"hotspot_c":42}') | Set-Content $log
    Assert-Equal (Read-Temperature $log 2).temperature 72
    Assert-Equal (Read-Temperature $log 2).edge_c 55
    Assert-Equal (Read-Temperature $log 2).power_w $null
    Assert-Equal (Read-Temperature $log 2).fan_rpm 1800
    Assert-Equal (Read-Temperature $log 0) $null
    @('gpu-timing {"v":1,"gpu":2,"phase":"search","timer":"legacy-sleep","window_us":5000000,"batches":300,"batch_us":430000,"sleep_calls":300,"sleep_requested_us":400000,"sleep_actual_us":4500000}',
      'gpu-timing {"v":1,"gpu":1,"phase":"dag","timer":"waitable-high-resolution"}',
      'gpu-timing {invalid json}') | Set-Content $log
    Assert-Equal (Read-Timing $log 2).timer 'legacy-sleep'
    Assert-Equal (Read-Timing $log 2).batches 300
    Assert-Equal (Read-Timing $log 0) $null
    $cooling = @{state='cooling'; duty_percent=0}
    $running = @{state='running'; duty_percent=5}
    Assert-Equal (Assert-GpuTemperature @{edge_c=79;hotspot_c=79;memory_c=79} $running 10 $null) $null
    foreach ($sensor in @('edge_c','hotspot_c','memory_c')) {
        $hot = @{$sensor=80}
        Assert-Equal (Assert-GpuTemperature $hot $cooling 300 10) $null
        Assert-Equal (Assert-GpuTemperature $hot $running 10 $null) 10
        Assert-Equal (Assert-GpuTemperature $hot $running 12 10) 10
        Assert-Throws { Assert-GpuTemperature $hot $running 13 10 }
        Assert-Throws { Assert-GpuTemperature $hot @{state='cooling';duty_percent=5} 13 10 }
    }
    $clock = @{last=0.0; active_seconds=0.0; cooling_seconds=0.0; cooling=$false}
    Update-TrialClock $clock 50 $true
    Update-TrialClock $clock 3650 $true
    Assert-Equal $clock.active_seconds 50
    Assert-Equal $clock.cooling_seconds 3600
    Update-TrialClock $clock 3660 $false
    Update-TrialClock $clock 3910 $false
    Assert-Equal $clock.active_seconds 300
    Assert-Equal $clock.cooling_seconds 3610
    Assert-Equal $settings.opencl.kawpow[0].'gpu-duty-percent' 25
    Assert-Equal $settings.opencl.kawpow[0].intensity 65536
    'gpu-governor {"v":1,"gpu":2,"state":"cooling","phase":"dag","duty_percent":0}' | Set-Content $log
    Assert-Equal (Read-Governor $log 2).state 'cooling'
    Assert-Equal (Read-Governor $log 1) $null
    'gpu-governor {"v":1,"gpu":2,"state":"fault","reason":"sensor-missing-or-stale"}' | Add-Content $log
    Assert-Throws { Read-Governor $log 2 }
    @('[2026-10-30 01:00:00] miner speed 10s/60s/15m 35.25 34.00 n/a MH/s max 40.00 MH/s',
      '[2026-10-30 01:00:01] opencl accepted (15/0) diff 1M (12 ms)') | Set-Content $log
    $stats = Read-MinerStats $log
    Assert-Equal $stats.hashrate_10s_hs '35250000.00'
    Assert-Equal $stats.hashrate_15m_hs $null
    Assert-Equal $stats.accepted 15
    Assert-Equal $stats.rejected 0
    '[2026-10-30 01:00:02] miner speed 10s/60s/15m 0.0 1.5 n/a H/s max 5.5 H/s' | Set-Content $log
    Assert-Equal (Read-MinerStats $log).hashrate_10s_hs '0.0'
    Write-Output 'PowerShell: engine isolation, Defender gate, scan failures, TLS/payout/GPU arguments passed.'
} finally {
    Remove-Item -LiteralPath $temp -Recurse -Force
}
