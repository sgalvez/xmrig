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
$SourceCommit = 'a99b12b93969a9f658bc774718a723ffd4c88766'
$GpuId = 2
$env:SystemRoot = $temp
[void][IO.Directory]::CreateDirectory((Join-Path $temp 'System32'))
foreach ($name in @('OpenCL.dll','atiadlxx.dll')) { [IO.File]::WriteAllText((Join-Path (Join-Path $temp 'System32') $name), 'Fixture, never loaded.') }
$Version = 'test'
$SecurityPolicy = 'rvn-governor-1'
$MiningProfile = 'rx9070xt-duty25-intensity65536-v1'
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
    Assert-Equal $settings.opencl.kawpow[0].index 2
    Assert-Equal $settings.opencl.kawpow.Count 1
    Assert-Equal $settings.'donate-level' 0.5
    Assert-Equal $settings.'health-print-time' 2
    Assert-Throws { Assert-Validated $config }
    $validated = @{mining_profile=$MiningProfile;verified=$true;engine=$Engine;security_policy=$SecurityPolicy;sha256=$ExeHash;gpu_id=2;address=$config.address;worker=$config.worker;pool=$config.pool}
    $validated | ConvertTo-Json | Set-Content (Join-Path $Runtime 'xmrig-validation.json')
    Assert-Validated $config
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
    Assert-GpuTemperature @{hotspot_c=79;edge_c=55}
    Assert-Throws { Assert-GpuTemperature @{hotspot_c=80} }
    Assert-Throws { Assert-GpuTemperature @{edge_c=75} }
    Assert-Throws { Assert-GpuTemperature @{memory_c=80} }
    Assert-Equal $settings.opencl.kawpow[0].'gpu-duty-percent' 25
    Assert-Equal $settings.opencl.kawpow[0].intensity 65536
    'gpu-governor {"v":1,"gpu":2,"state":"cooling","phase":"dag","duty_percent":5}' | Set-Content $log
    Assert-Equal (Read-Governor $log 2).state 'cooling'
    Assert-Equal (Read-Governor $log 1) $null
    'gpu-governor {"v":1,"gpu":2,"state":"fault","reason":"temperature-cutoff"}' | Add-Content $log
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
