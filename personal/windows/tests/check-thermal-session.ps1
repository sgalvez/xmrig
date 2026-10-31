# Exercise the actual Run clause with fake processes and telemetry only.
$ErrorActionPreference = 'Stop'
$tokens=$null; $errors=$null
$source=Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'
$ast=[System.Management.Automation.Language.Parser]::ParseFile($source,[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Parse failure' }
foreach ($f in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst]},$true)) { . ([scriptblock]::Create($f.Extent.Text)) }
$runClause=$null
foreach ($switch in $ast.FindAll({param($n) $n -is [System.Management.Automation.Language.SwitchStatementAst]},$true)) {
    foreach ($clause in $switch.Clauses) {
        if ($clause.Item1.Value -eq 'Run') { $runClause=$clause.Item2.Extent.Text }
    }
}
if (-not $runClause) { throw 'Run clause not found' }
$runBody=[scriptblock]::Create($runClause.Substring(1,$runClause.Length-2))
function Ready-Executable { }
function Assert-Validated($Config) { }
function Read-Config { return @{address=('R'+'A'*33);worker='fixture';pool='fixture.invalid'} }
function Miner-Config { return @{} }
function Read-MinerStats { return @{} }
function Write-State($State) { $script:states += $State.Clone() }
function Read-Temperature {
    $t=if ($script:step -eq 0) { 80 } elseif ($script:step -eq 1) { 65 } else { 60 }
    return @{line="sample-$script:step";temperature=$t;edge_c=$t;hotspot_c=$t;memory_c=$t}
}
function Read-Governor {
    if ($script:scenario -eq 'fault') { throw 'sensor-missing-or-stale' }
    return [pscustomobject]@{log_line="governor-$script:step";state=$(if ($script:step -lt 2) {'cooling'} else {'running'});duty_percent=$(if ($script:step -lt 2) {0} else {5});phase='dag'}
}
function Start-Process {
    param($FilePath,$ArgumentList,$WorkingDirectory,$WindowStyle,[switch]$PassThru,$RedirectStandardOutput,$RedirectStandardError)
    $script:launches++
    return $script:process
}
function Start-Sleep {
    param($Seconds)
    $script:step++
    if ($script:step -eq 3) { [IO.File]::WriteAllText($CancelFile,'stop') }
    if ($script:step -gt 4) { throw 'Cancellation ignored' }
}
$base=Join-Path ([IO.Path]::GetTempPath()) ('thermal-session-'+[guid]::NewGuid())
$Utf8=New-Object Text.UTF8Encoding($false)
$Engine='XMRig';$Version='fixture';$GpuId=1;$TrialSeconds=0;$Exe='C:\fixture\never.exe'
try {
    foreach ($scenario in @('cool-resume-cancel','cancel-before-launch','fault')) {
        $script:scenario=$scenario
        $Runtime=Join-Path $base $scenario
        [void][IO.Directory]::CreateDirectory($Runtime)
        $StopFile=Join-Path $Runtime 'stop.request'
        $CancelFile=Join-Path $Runtime 'cancel-fixture.request'
        $key=[guid]::NewGuid().ToString('N')
        $script:step=0;$script:launches=0;$script:states=@()
        $script:process=[pscustomobject]@{Id=123;StartTime=[datetime]::UtcNow;HasExited=$false;ExitCode=0;Killed=$false}
        $script:process | Add-Member ScriptMethod Refresh { }
        $script:process | Add-Member ScriptMethod Kill { $this.Killed=$true; $this.HasExited=$true }
        $script:process | Add-Member ScriptMethod WaitForExit { }
        if ($scenario -eq 'cancel-before-launch') { [IO.File]::WriteAllText($CancelFile,'stop') }
        $failure=$null
        try { & $runBody } catch { $failure=$_.Exception.Message }
        if ($scenario -eq 'cancel-before-launch') {
            if ($failure -or $script:launches -ne 0) { throw 'Cancelled session launched a process or failed' }
        } else {
            if ($script:launches -ne 1 -or -not $script:process.Killed) { throw 'Owned process was not cleaned up' }
            if ($scenario -eq 'fault') {
                if ($failure -ne 'sensor-missing-or-stale') { throw "Sensor fault not surfaced: $failure" }
            } else {
                if ($failure) { throw $failure }
                if ($script:states[0].governor_state -ne 'cooling' -or $script:states[0].duty_percent -ne 0) { throw 'Thermal pause missing' }
                if ($script:states[2].governor_state -ne 'running') { throw 'Session did not resume' }
                if ($script:states[-1].running) { throw 'Session still reports running after Ctrl+C cancellation' }
            }
        }
    }
    Write-Output 'PowerShell: thermal pause/resume, cancellation before launch/during supervision and fault cleanup passed.'
} finally {
    if (Test-Path -LiteralPath $base) { Remove-Item -LiteralPath $base -Recurse -Force }
}
