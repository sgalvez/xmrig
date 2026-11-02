# Inert fixtures only. No Defender settings, network, installation or mining.
$ErrorActionPreference='Stop'
$tokens=$null;$errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'),[ref]$tokens,[ref]$errors)
if($errors.Count){throw ($errors|Out-String)}
foreach($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)){. ([scriptblock]::Create($f.Extent.Text))}
function Assert-True($Value){if(-not $Value){throw "Assertion failed: $scenario"}}
function Assert-Fails([scriptblock]$Body){$failed=$false;try{& $Body}catch{$failed=$true};Assert-True $failed}
function Assert-FailsWith([scriptblock]$Body,[string]$Message){
    $failure=$null;try{& $Body}catch{$failure=$_.Exception.Message}
    Assert-True ($null -ne $failure -and $failure -like $Message)
}
function Assert-StandardUser {}
function Owned-Process($State){return $null}
function Start-Process {throw 'Test forbids process execution.'}
function Set-MpPreference {throw 'Test forbids Defender changes.'}
function Add-MpPreference {throw 'Test forbids Defender changes.'}
function Remove-MpPreference {throw 'Test forbids Defender changes.'}
function Get-MpComputerStatus {param($ErrorAction) return @{AntivirusEnabled=$script:av;RealTimeProtectionEnabled=$script:av}}
function Get-MpThreat {param($ErrorAction) return $script:threats}
function Get-MpThreatDetection {
    param($ErrorAction)
    $script:queries++
    if($script:during -and $script:queries -eq 2){$script:detections[0].DetectionID='new-during-consent'}
    return $script:detections
}
$Engine='XMRig';$Version='6.26.0';$SourceCommit='a5de7a74c726b583b6bbfc3ccb045b09abf68db2';$SecurityPolicy='rvn-governor-4'
$Utf8=New-Object Text.UTF8Encoding($false)
$base=Join-Path ([IO.Path]::GetTempPath()) ('xmrig-risk-test-'+[guid]::NewGuid())
$scenarios=@('success','old-install','wrong-hash','changed-source','empty-source','missing-source','unknown-id','changed-name','extra-resource',
    'wrong-file','missing-id','missing-threat','phantom-block','av-off','during-change','mixed-unknown','rollback',
    'wacapew-remediated','wacapew-active','wacapew-executed','wacapew-unresolved','wacapew-source','wacapew-name','wacapew-pending')
try {
 foreach($scenario in $scenarios){
    $case=Join-Path $base $scenario;$Runtime=Join-Path $case 'runtime';$BuildRoot=Join-Path $case 'build';$InstallRoot=Join-Path $case 'install'
    foreach($dir in @($Runtime,$BuildRoot,$InstallRoot)){[void][IO.Directory]::CreateDirectory($dir)}
    $Exe=Join-Path $InstallRoot 'xmrig.exe';$StateFile=Join-Path $Runtime 'status.json';$ScanFile=Join-Path $Runtime 'scan.json';$TrustFile=Join-Path $case 'trust.json'
    $source=Join-Path $BuildRoot 'xmrig.exe';$manifest=Join-Path $BuildRoot 'build.json';$consent=Join-Path $Runtime 'xmrig-risk-consent.json';$block=Join-Path $Runtime 'xmrig-security-block.json'
    [IO.File]::WriteAllText($source,'Inert fixture. Never executed.')
    $ExpectedSha256=(Get-FileHash $source).Hash.ToLowerInvariant()
    @{engine=$Engine;version=$Version;target='windows-x86_64';commit=$SourceCommit;sha256=$ExpectedSha256;security_policy=$SecurityPolicy;recipe_sha256=('a'*64)}|ConvertTo-Json|Set-Content $manifest
    @{sha256=$ExpectedSha256;commit=$SourceCommit;security_policy=$SecurityPolicy;recipe_sha256=('a'*64);manifest_sha256=(Get-FileHash $manifest).Hash.ToLowerInvariant()}|ConvertTo-Json|Set-Content $TrustFile
    $script:av=$true;$script:queries=0;$script:during=$false
    $script:detections=@(
      @{DetectionID='original-h';ThreatID=2147814523;Resources=@("file:_$source");ThreatStatusID=1},
      @{DetectionID='original-b';ThreatID=2147735505;Resources=@("file:_$source");ThreatStatusID=3},
      @{DetectionID='old-pua';ThreatID=274600;Resources=@("file:_$Exe");ThreatStatusID=5},
      @{DetectionID='optimized-c';ThreatID=2147749372;Resources=@("file:_$source");ThreatStatusID=3})
    $script:threats=@(
      @{ThreatID=2147814523;ThreatName='Trojan:Win32/Wacatac.H!ml';IsActive=$true},
      @{ThreatID=2147735505;ThreatName='Trojan:Win32/Wacatac.B!ml';IsActive=$false},
      @{ThreatID=274600;ThreatName='PUA:Win32/Caypnamer.A!ml';IsActive=$false},
      @{ThreatID=2147749372;ThreatName='Trojan:Win32/Wacatac.C!ml';IsActive=$false})
    if($scenario -like 'wacapew-*'){
      $script:detections+=@{DetectionID='old-wacapew';ThreatID=265744;Resources=@("file:_$Exe");
        ThreatStatusID=3;ActionSuccess=$true;AdditionalActionsBitMask=0}
      $script:threats+=@{ThreatID=265744;ThreatName='Program:Win32/Wacapew.C!ml';IsActive=$false;DidThreatExecute=$false}
    }
    '{"component":"XMRig","threat_ids":[2147814523,2147735505,274600]}'|Set-Content $block
    switch($scenario){
      'old-install' {[IO.File]::WriteAllText($Exe,'Old inert fixture.');Copy-Item $manifest (Join-Path $InstallRoot 'build.json')}
      'wrong-hash' {$ExpectedSha256='f'*64}
      'changed-source' {Add-Content $source 'changed'}
      'empty-source' {[IO.File]::WriteAllBytes($source,[byte[]]@())}
      'missing-source' {Remove-Item -LiteralPath $source}
      'unknown-id' {$script:detections[0].ThreatID=999}
      'changed-name' {$script:threats[0].ThreatName='Trojan:Win32/Different'}
      'extra-resource' {$script:detections[0].Resources+=@('file:_C:\unrelated.exe')}
      'wrong-file' {$script:detections[0].Resources=@("file:_$BuildRoot\other.exe")}
      'missing-id' {$script:detections[0].DetectionID=$null}
      'missing-threat' {$script:threats=@($script:threats[1],$script:threats[2])}
      'phantom-block' {'{"component":"XMRig","threat_ids":[999]}'|Set-Content $block}
      'av-off' {$script:av=$false}
      'during-change' {$script:during=$true}
      'mixed-unknown' {$script:detections+=@{DetectionID='new';ThreatID=999;Resources=@("file:_$Exe")}}
      'rollback' {$script:during=$true;[IO.File]::WriteAllText($consent,'previous receipt')}
      'wacapew-active' {$script:threats[-1].IsActive=$true}
      'wacapew-executed' {$script:threats[-1].DidThreatExecute=$true}
      'wacapew-unresolved' {$script:detections[-1].ActionSuccess=$false}
      'wacapew-source' {$script:detections[-1].Resources=@("file:_$source")}
      'wacapew-name' {$script:threats[-1].ThreatName='Program:Win32/Wacapew.Other'}
      'wacapew-pending' {$script:detections[-1].AdditionalActionsBitMask=4}
    }
    if($scenario -in @('success','old-install','wacapew-remediated')){
      Accept-OwnerRisk
      Assert-True (-not(Test-Path $block));Assert-True (Test-Path $consent)
      $record=Get-Content $consent -Raw|ConvertFrom-Json
      Assert-True ($record.sha256 -ceq $ExpectedSha256 -and $record.keys.Count -eq $script:detections.Count)
      Assert-Fails {Check-Scan}
      Assert-DefenderReady -PrepareUpgrade
      Assert-Fails {Assert-DefenderReady} # Missing/old installation cannot run.
      Copy-Item $source $Exe -Force;Copy-Item $manifest (Join-Path $InstallRoot 'build.json') -Force
      Assert-DefenderReady
      if($scenario -eq 'wacapew-remediated'){
        $script:detections[-1].DetectionID='new-wacapew'
        Assert-Fails {Assert-DefenderReady}
        $script:detections[-1].DetectionID='old-wacapew'
        $script:threats[-1].IsActive=$true
        Assert-Fails {Assert-DefenderReady}
        $script:threats[-1].IsActive=$false
      }
      $script:detections[0].DetectionID='new-same-classification'
      Assert-Fails {Assert-DefenderReady};Assert-True (Test-Path $block)
      $script:detections[0].DetectionID='original-h'
      $script:detections[0].ThreatStatusID=3
      Assert-Fails {Assert-DefenderReady} # Changed incident is not inherited.
      $script:detections[0].ThreatStatusID=1
      Add-Content $Exe 'modified';Assert-Fails {Assert-DefenderReady}
      Copy-Item $source $Exe -Force
      Add-Content $source 'new build';Assert-Fails {Assert-DefenderReady -PrepareUpgrade}
    } else {
      switch($scenario){
        'wrong-hash' {Assert-FailsWith {Accept-OwnerRisk} '*no corresponde a esta compilacion*'}
        'changed-source' {Assert-FailsWith {Accept-OwnerRisk} '*contenido del ejecutable no coincide*'}
        'empty-source' {Assert-FailsWith {Accept-OwnerRisk} '*vacio (0 bytes)*'}
        'missing-source' {Assert-FailsWith {Accept-OwnerRisk} '*No se puede leer el ejecutable*'}
        default {Assert-Fails {Accept-OwnerRisk}}
      }
      Assert-True (Test-Path $block)
      if($scenario -eq 'rollback'){Assert-True ((Get-Content $consent -Raw) -ceq 'previous receipt')}
      else {Assert-True (-not(Test-Path $consent))}
    }
 }
 Write-Output "Risk consent: $($scenarios.Count) scenarios passed. No miner executed or Defender settings changed."
} finally {if(Test-Path $base){Remove-Item $base -Recurse -Force}}
