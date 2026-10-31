# Explicit consent regression: fake files, mocked Defender, no miner execution.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Parse failure' }
foreach ($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)) { . ([scriptblock]::Create($f.Extent.Text)) }
function Assert-True($Value) { if (-not $Value) { throw "Assertion failed: $scenario" } }
function Assert-Fails([scriptblock]$Body) { $failed=$false; try { & $Body } catch { $failed=$true }; Assert-True $failed }
function Assert-StandardUser { }
function Owned-Process($State) { return $null }
function Get-MpComputerStatus { param($ErrorAction) return @{AntivirusEnabled=$script:av;RealTimeProtectionEnabled=$script:av} }
function Get-MpThreat { param($ErrorAction) return $script:threats }
function Invoke-DefenderScan([string]$Directory) {
    Assert-True ($Directory -eq $InstallRoot)
    $script:scans++
    return @{ExitCode=$script:scanCode}
}
function Get-MpThreatDetection {
    param($ErrorAction)
    $script:queries++
    if ($script:changeDuring -and $script:queries -eq 2) { $script:detections[0].DetectionID='changed-during-accept' }
    return $script:detections
}
$Engine='XMRig'; $Version='6.26.0'; $SecurityPolicy='rvn-governor-4'
$SourceCommit='778ef0f43cd5d2e989f117298d2ab1c159b671e8'
$Utf8=New-Object Text.UTF8Encoding($false)
$base=Join-Path ([IO.Path]::GetTempPath()) ('xmrig-pua-test-'+[guid]::NewGuid())
$scenarios=@('success','missing-install','missing-install-directory','missing-source','wrong-hash','changed-source','changed-install','wrong-name','wrong-threat',
    'other-file','extra-resource','missing-id','missing-threat','other-block','other-detection','av-off','during-change')
try {
    foreach ($scenario in $scenarios) {
        $case=Join-Path $base $scenario
        $Runtime=Join-Path $case 'runtime'; $BuildRoot=Join-Path $case 'build'; $InstallRoot=Join-Path $case 'install'
        foreach ($dir in @($Runtime,$BuildRoot,$InstallRoot)) { [void][IO.Directory]::CreateDirectory($dir) }
        $Exe=Join-Path $InstallRoot 'xmrig.exe'
        $TrustFile=Join-Path $case 'trust.json'; $StateFile=Join-Path $Runtime 'status.json'; $ScanFile=Join-Path $Runtime 'scan.json'
        [IO.File]::WriteAllText($Exe,'Fixture, never executed.')
        Copy-Item $Exe (Join-Path $BuildRoot 'xmrig.exe')
        $ExpectedSha256=(Get-FileHash $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest=Join-Path $BuildRoot 'build.json'
        @{engine=$Engine;version=$Version;target='windows-x86_64';commit=$SourceCommit;sha256=$ExpectedSha256;security_policy=$SecurityPolicy;recipe_sha256=('a'*64)} | ConvertTo-Json | Set-Content $manifest
        Copy-Item $manifest (Join-Path $InstallRoot 'build.json')
        @{sha256=$ExpectedSha256;commit=$SourceCommit;security_policy=$SecurityPolicy;recipe_sha256=('a'*64);manifest_sha256=(Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content $TrustFile
        $block=Join-Path $Runtime 'xmrig-security-block.json'; $consent=Join-Path $Runtime 'xmrig-pua-consent.json'
        '{"component":"XMRig","threat_ids":[274600]}' | Set-Content $block
        $script:av=$true; $script:queries=0; $script:changeDuring=$false
        $script:scans=0; $script:scanCode=0
        $script:detections=@(@{DetectionID='current-pua';ThreatID=274600;Resources=@("file:_$Exe");ThreatStatusID=5})
        $script:threats=@(@{ThreatID=274600;ThreatName='PUA:Win32/Caypnamer.A!ml'})
        switch ($scenario) {
            'missing-install' { Remove-Item $Exe }
            'missing-install-directory' { Remove-Item $InstallRoot -Recurse -Force }
            'missing-source' { Remove-Item (Join-Path $BuildRoot 'xmrig.exe') }
            'wrong-hash' { $ExpectedSha256='f'*64 }
            'changed-source' { Add-Content (Join-Path $BuildRoot 'xmrig.exe') 'changed' }
            'changed-install' { Add-Content $Exe 'changed' }
            'wrong-name' { $script:threats[0].ThreatName='Trojan:Win32/Other' }
            'wrong-threat' { $script:detections[0].ThreatID=123 }
            'other-file' { $script:detections[0].Resources=@("file:_$InstallRoot/other.exe") }
            'extra-resource' { $script:detections[0].Resources+=@('file:_C:\other.exe') }
            'missing-id' { $script:detections[0].DetectionID=$null }
            'missing-threat' { $script:threats=@() }
            'other-block' { '{"component":"XMRig","threat_ids":[999]}' | Set-Content $block }
            'other-detection' { $script:detections+=@{DetectionID='other';ThreatID=999;Resources=@("file:_$Exe")} }
            'av-off' { $script:av=$false }
            'during-change' { $script:changeDuring=$true }
        }
        if ($scenario -in @('success','missing-install','missing-install-directory')) {
            Accept-Pua
            Assert-True (-not (Test-Path $block))
            Assert-True (Test-Path $consent)
            Assert-Fails { Check-Scan } # Consent is not a scan result.
            if ($scenario -ne 'success') {
                Assert-True (-not (Test-Path $Exe)) # Consent never copies/restores files.
                Assert-Fails { Assert-DefenderReady } # Cannot scan/start a missing EXE.
                Assert-DefenderReady -AllowMissingInstalled # Pre-install only.
                [void][IO.Directory]::CreateDirectory($InstallRoot)
                Copy-Item (Join-Path $BuildRoot 'build.json') (Join-Path $InstallRoot 'build.json')
                Copy-Item (Join-Path $BuildRoot 'xmrig.exe') $Exe
            }
            Assert-DefenderReady
            if ($scenario -eq 'success') {
                $oldReceipt = Get-Content -LiteralPath $consent -Raw
                $oldHash = $ExpectedSha256
                # A newly built source must not inherit consent for the old hash.
                Add-Content (Join-Path $BuildRoot 'xmrig.exe') 'new build fixture'
                $ExpectedSha256 = (Get-FileHash (Join-Path $BuildRoot 'xmrig.exe') -Algorithm SHA256).Hash.ToLowerInvariant()
                (Get-Content $manifest -Raw).Replace($oldHash, $ExpectedSha256) | Set-Content $manifest
                @{sha256=$ExpectedSha256;commit=$SourceCommit;security_policy=$SecurityPolicy;recipe_sha256=('a'*64);manifest_sha256=(Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content $TrustFile
                Assert-Fails { Assert-DefenderReady }
                Assert-DefenderReady -AllowMissingInstalled -PrepareUpgrade
                Assert-True ((Get-Content -LiteralPath $consent -Raw) -ceq $oldReceipt)
                Assert-Fails { Check-Scan }
                Copy-Item $manifest (Join-Path $InstallRoot 'build.json')
                Copy-Item (Join-Path $BuildRoot 'xmrig.exe') $Exe
                Assert-Fails { Assert-DefenderReady }
                # Regression: the old consent must not block the scanner itself.
                Assert-Fails { Scan-Executable }
                Assert-True ($script:scans -eq 1)
                Assert-True ((Get-Content -LiteralPath $consent -Raw) -ceq $oldReceipt)
                Assert-Fails { Check-Scan } # Old hash never grants scan/run permission.
                # If Defender no longer reports that incident, no exception is
                # needed; a successful fresh scan can authorize this exact build.
                $savedDetections=$script:detections; $savedThreats=$script:threats
                $script:detections=@(); $script:threats=@()
                $script:scanCode=2
                Assert-Fails { Scan-Executable }
                Assert-Fails { Check-Scan }
                $script:scanCode=0
                Scan-Executable
                Check-Scan
                Assert-True ((Get-Content -LiteralPath $consent -Raw) -ceq $oldReceipt)
                $script:detections=$savedDetections; $script:threats=$savedThreats
                Assert-Fails { Assert-DefenderReady } # Reappearing incident still blocks.
                Accept-Pua # Separate explicit acceptance, never part of Install.
                Assert-DefenderReady
                Assert-Fails { Check-Scan }
            }
            $script:detections[0].DetectionID='new-pua-same-threat'
            Assert-Fails { Assert-DefenderReady }
            Assert-True (Test-Path $block)
            $script:detections[0].DetectionID='current-pua'
            Add-Content $Exe 'tampered'
            Assert-Fails { Assert-DefenderReady }
        } else {
            Assert-Fails { Accept-Pua }
            Assert-True (Test-Path $block)
            Assert-True (-not (Test-Path $consent))
        }
    }
    Write-Output "PUA consent: $($scenarios.Count) scenarios passed. No Defender changes or miner execution."
} finally { if (Test-Path $base) { Remove-Item $base -Recurse -Force } }
