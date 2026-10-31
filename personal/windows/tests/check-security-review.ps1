# Regression tests for historical detections. All Windows/AV/process calls mocked.
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$source=Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Parse failure' }
foreach ($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)) { . ([scriptblock]::Create($f.Extent.Text)) }
function Assert-Equal($Actual,$Expected) { if ($Actual -cne $Expected) { throw "Expected $Expected, got $Actual" } }
function Assert-Fails([scriptblock]$Body) { $failed=$false; try { & $Body } catch { $failed=$true }; if (-not $failed) { throw "Expected failure ($scenario)" } }
function Assert-StandardUser { }
function Owned-Process($State) { return $null }
function Get-MpComputerStatus { param($ErrorAction) return @{AntivirusEnabled=$true;RealTimeProtectionEnabled=$true} }
function Get-MpThreatDetection { param($ErrorAction) return @($script:detections | ForEach-Object { [pscustomobject]$_ }) }
function Get-MpThreat { param($ErrorAction) return @($script:threats | ForEach-Object { [pscustomobject]$_ }) }
function Get-CimClass { param($Namespace,$ClassName,$ErrorAction) throw 'No WMI in portable test.' }
function Invoke-DefenderScan([string]$Directory) {
    Assert-Equal $Directory $BuildRoot
    $script:scans++
    switch ($script:duringScan) {
        'new' { $script:detections += @{DetectionID='new-id';ThreatID=251873;Resources=@("file:_$BuildRoot/xmrig.exe");ThreatStatusID=4;ActionSuccess=$true;AdditionalActionsBitMask=0} }
        'missing' { Remove-Item (Join-Path $BuildRoot 'xmrig.exe') }
        'changed' { [IO.File]::WriteAllText((Join-Path $BuildRoot 'xmrig.exe'),'changed') }
        'active' { $script:threats[0].IsActive=$true }
        'action-changed' { $script:detections[0].CleaningActionID=4 }
        'executed' { $script:threats[0].DidThreatExecute=$true }
    }
    return @{ExitCode=$script:scanCode}
}
$base=Join-Path ([IO.Path]::GetTempPath()) ('xmrig-review-test-'+[guid]::NewGuid())
$Utf8=New-Object Text.UTF8Encoding($false)
$Engine='XMRig'; $Version='6.26.0'; $SecurityPolicy='rvn-governor-1'
$SourceCommit='a99b12b93969a9f658bc774718a723ffd4c88766'
try {
    $scenarios = @('eight-success','eight-error','eight-missing-error','eight-executed','eight-missing-executed',
        'eight-allowed-execution','eight-missing-date','eight-reversed-dates','eight-current-build',
        'eight-action-changed','eight-executed-after','eight-new','eight-scan-failed','eight-missing-build-date',
        'eight-active','eight-pending','eight-failed-action','success','active','allowed','pending','failed-action','unknown','status-eight','missing-id','new','missing','changed','active-after','scan-failed')
    foreach ($scenario in $scenarios) {
        $case=Join-Path $base $scenario
        $Runtime=Join-Path $case 'runtime'; $BuildRoot=Join-Path $case 'build'; $InstallRoot=Join-Path $case 'install'
        [void][IO.Directory]::CreateDirectory($Runtime); [void][IO.Directory]::CreateDirectory($BuildRoot)
        $StateFile=Join-Path $Runtime 'status.json'; $ScanFile=Join-Path $Runtime 'xmrig-scan.json'
        $TrustFile=Join-Path $case 'trust.json'; $block=Join-Path $Runtime 'xmrig-security-block.json'
        $original='{"component":"XMRig","threat_ids":[251873]}'
        [IO.File]::WriteAllText($block,$original)
        $exe=Join-Path $BuildRoot 'xmrig.exe'
        [IO.File]::WriteAllText($exe,'Hash fixture, never executed.')
        $ExeHash=(Get-FileHash $exe -Algorithm SHA256).Hash.ToLowerInvariant()
        $manifest=Join-Path $BuildRoot 'build.json'
        @{built_at=$(if ($scenario -eq 'eight-missing-build-date') { $null } else { '2025-01-02T00:00:00Z' });engine=$Engine;version=$Version;target='windows-x86_64';commit=$SourceCommit;sha256=$ExeHash;security_policy=$SecurityPolicy;recipe_sha256=('a'*64)} | ConvertTo-Json | Set-Content $manifest
        @{sha256=$ExeHash;commit=$SourceCommit;security_policy=$SecurityPolicy;recipe_sha256=('a'*64);manifest_sha256=(Get-FileHash $manifest -Algorithm SHA256).Hash.ToLowerInvariant()} | ConvertTo-Json | Set-Content $TrustFile
        $script:detections=@(@{DetectionID='old-id';ThreatID=251873;Resources=@("file:_$BuildRoot/xmrig.exe");
            ThreatStatusID=4;ActionSuccess=$true;AdditionalActionsBitMask=0;InitialDetectionTime=[datetime]'2026-10-30T00:15:00Z';RemediationTime=[datetime]'2026-10-30T01:02:00Z'})
        $script:threats=@(@{ThreatID=251873;IsActive=$false})
        if ($scenario.StartsWith('eight-')) {
            $script:detections[0].ThreatStatusID=8
            $script:detections[0].CleaningActionID=9
            $script:detections[0].ThreatStatusErrorCode=0
            $script:detections[0].CurrentThreatExecutionStatusID=1
            $script:detections[0].InitialDetectionTime=[datetime]'2025-01-01T00:15:00Z'
            $script:detections[0].RemediationTime=[datetime]'2025-01-01T00:16:00Z'
            $script:threats[0].DidThreatExecute=$false
        }
        $script:scans=0; $script:scanCode=0; $script:duringScan=''
        switch ($scenario) {
            'eight-error' { $script:detections[0].ThreatStatusErrorCode=5 }
            'eight-missing-error' { $script:detections[0].Remove('ThreatStatusErrorCode') }
            'eight-executed' { $script:threats[0].DidThreatExecute=$true }
            'eight-missing-executed' { $script:threats[0].Remove('DidThreatExecute') }
            'eight-allowed-execution' { $script:detections[0].CurrentThreatExecutionStatusID=2 }
            'eight-missing-date' { $script:detections[0].RemediationTime=$null }
            'eight-reversed-dates' { $script:detections[0].RemediationTime=[datetime]'2024-01-01T00:00:00Z' }
            'eight-current-build' { $script:detections[0].RemediationTime=[datetime]'2025-01-02T00:00:00Z' }
            'eight-action-changed' { $script:duringScan='action-changed' }
            'eight-executed-after' { $script:duringScan='executed' }
            'eight-new' { $script:duringScan='new' }
            'eight-scan-failed' { $script:scanCode=2 }
            'eight-active' { $script:threats[0].IsActive=$true }
            'eight-pending' { $script:detections[0].AdditionalActionsBitMask=8 }
            'eight-failed-action' { $script:detections[0].ActionSuccess=$false }
            'active' { $script:threats[0].IsActive=$true }
            'allowed' { $script:detections[0].ThreatStatusID=5 }
            'pending' { $script:detections[0].AdditionalActionsBitMask=8 }
            'failed-action' { $script:detections[0].ActionSuccess=$false }
            'status-eight' { $script:detections[0].ThreatStatusID=8 }
            'unknown' { $script:threats=@() }
            'missing-id' { $script:detections[0].DetectionID=$null }
            'new' { $script:duringScan='new' }
            'missing' { $script:duringScan='missing' }
            'changed' { $script:duringScan='changed' }
            'active-after' { $script:duringScan='active' }
            'scan-failed' { $script:scanCode=2 }
        }
        if ($scenario -in @('success','eight-success')) {
            Review-RemovedDetection
            Assert-Equal (Test-Path $block) $false
            Assert-Equal $script:scans 1
            Assert-Equal @(Get-ChildItem (Join-Path $Runtime 'security-history')).Count 1
            Assert-DefenderReady
            Assert-Fails { Check-Scan } # Review never grants permission to execute installed miner.
            $script:detections[0].DetectionID='later-detection-same-threat-id'
            Assert-Fails { Assert-DefenderReady }
            Assert-Equal (Test-Path $block) $true
        } else {
            Assert-Fails { Review-RemovedDetection }
            Assert-Equal (Get-Content $block -Raw) $original
            Assert-Equal (Test-Path (Join-Path $Runtime 'xmrig-security-reviewed.json')) $false
            if ($scenario -eq 'status-eight') {
                Write-SecurityDiagnostic 6>$null
                $diagnostic = Get-Content (Join-Path $Runtime 'xmrig-security-diagnostic.json') -Raw | ConvertFrom-Json
                Assert-Equal $diagnostic.detections[0].ThreatStatusID 8
                Assert-Equal $diagnostic.threats[0].IsActive $false
                Assert-Equal $script:scans 0
                Assert-Equal (Get-Content $block -Raw) $original
            }
        }
    }
    Write-Output "Historical detection review: $($scenarios.Count) scenarios passed. No real Defender call or miner execution."
} finally { if (Test-Path $base) { Remove-Item $base -Recurse -Force } }
