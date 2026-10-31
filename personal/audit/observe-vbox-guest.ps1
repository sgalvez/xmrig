[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ExpectedManifestSha)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
Set-StrictMode -Version Latest

# These checks prevent accidental host execution. VirtualBox configuration is the boundary.
if ($env:COMPUTERNAME -ne 'XMRIG-AUDIT' -or $env:USERNAME -ne 'audituser' -or
    $PSScriptRoot -notmatch '^C:\\XmrigAudit\\[a-f0-9]{24}\\input$') {
    throw 'Observador exclusivo de la VM XMRIG-AUDIT; nunca ejecutar en el host.'
}
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) { throw 'Se requiere elevacion para Process Monitor.' }
$machine = Get-CimInstance Win32_ComputerSystem
if ($machine.Model -ne 'VirtualBox') { throw 'Modelo virtual inesperado.' }
if (@(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up').Count -ne 0 -or
    @(Get-NetRoute -ErrorAction Stop | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count -ne 0) {
    throw 'La VM tiene conectividad; no se ejecuta la muestra.'
}
$InputDir = $PSScriptRoot
$OutputDir = Join-Path (Split-Path $InputDir -Parent) 'output'
$manifestPath = Join-Path $InputDir 'manifest.json'
if ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant() -ne $ExpectedManifestSha) { throw 'Manifiesto distinto al preparado en el host.' }
$Manifest = Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json
if ($Manifest.run_id -ne (Split-Path (Split-Path $InputDir -Parent) -Leaf)) { throw 'Identidad de ejecucion distinta.' }
$ExpectedSha = [string]$Manifest.sample_sha256
$Sample = Join-Path $InputDir 'xmrig.exe'
$Procmon = Join-Path $InputDir 'Procmon64.exe'
$Trace = Join-Path $OutputDir 'trace.pml'
$ResultPath = Join-Path $OutputDir 'result.json'
$Result = [ordered]@{run_id=$Manifest.run_id; label=$Manifest.label; sample_sha256=$ExpectedSha
    started_utc=[DateTime]::UtcNow.ToString('o'); status='validating'; phases=@(); sample_started=$false
    network='no adapters/no default routes'; gpu='no GPU passthrough'; sample_privilege='administrator'
    verdict='not_assessed'; monitor_started=$false; capture_exported=$false }
$MonitorStarted = $false

function Write-Result {
    $script:Result | ConvertTo-Json -Depth 10 | Set-Content -LiteralPath $script:ResultPath -Encoding UTF8
}
function Assert-DefenderActive($Status) {
    if($null -eq $Status -or $Status.AMServiceEnabled -ne $true -or
       $Status.AntivirusEnabled -ne $true -or $Status.RealTimeProtectionEnabled -ne $true) {
        throw 'No se confirma Defender activo; muestra sin ejecutar.'
    }
}
function Save-Environment([string]$Name) {
    Get-CimInstance Win32_Service | Select-Object Name,State,StartMode,PathName |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$OutputDir\$Name-services.json" -Encoding UTF8
    Get-ScheduledTask | Select-Object TaskPath,TaskName,State |
        ConvertTo-Json -Depth 4 | Set-Content -LiteralPath "$OutputDir\$Name-tasks.json" -Encoding UTF8
    $values = foreach ($key in @('HKCU:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\Run',
        'HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce')) {
        if (Test-Path -LiteralPath $key) { [pscustomobject]@{path=$key;value=(Get-ItemProperty -LiteralPath $key | Out-String)} }
    }
    @($values) | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath "$OutputDir\$Name-autorun.json" -Encoding UTF8
    Save-Defender $Name
}
function Save-Defender([string]$Name) {
    try {
        $status = Get-MpComputerStatus -ErrorAction Stop | Select-Object AMServiceEnabled,AntivirusEnabled,
            RealTimeProtectionEnabled,BehaviorMonitorEnabled,AntivirusSignatureVersion,AntivirusSignatureLastUpdated
        $threats = @(Get-MpThreat -ErrorAction Stop | Select-Object ThreatID,ThreatName,IsActive,DidThreatExecute,Resources)
        $detections = @(Get-MpThreatDetection -ErrorAction Stop | Select-Object ThreatID,InitialDetectionTime,LastThreatStatusChangeTime,
            ActionSuccess,ThreatStatusID,ProcessName,Resources)
        [ordered]@{status=$status;threats=$threats;detections=$detections} | ConvertTo-Json -Depth 8 |
            Set-Content -LiteralPath "$OutputDir\$Name-defender.json" -Encoding UTF8
    } catch {
        [ordered]@{error=$_.Exception.Message;status='unknown'} | ConvertTo-Json |
            Set-Content -LiteralPath "$OutputDir\$Name-defender.json" -Encoding UTF8
    }
}
function Invoke-Sample([string]$Name, [string]$Arguments, [int]$Seconds) {
    $script:Monitor.Refresh()
    if ($script:Monitor.HasExited -or -not (Test-Path -LiteralPath $Trace)) { throw 'El observador ya no esta activo; no se inicia otra fase.' }
    Assert-DefenderActive (Get-MpComputerStatus -ErrorAction Stop)
    if ((Get-FileHash -LiteralPath $Sample).Hash.ToLowerInvariant() -ne $ExpectedSha) { throw 'La muestra cambio antes de ejecutarse.' }
    if ((Get-FileHash -LiteralPath $manifestPath).Hash.ToLowerInvariant() -ne $ExpectedManifestSha) { throw 'Manifiesto modificado durante la prueba.' }
    $phase = [ordered]@{name=$Name;arguments=$Arguments;started_utc=[DateTime]::UtcNow.ToString('o');
        timeout=$false;exit_code=$null;pid=$null;error=$null}
    $child = $null
    $clock = [Diagnostics.Stopwatch]::StartNew()
    $Result.status = 'phase-' + $Name
    Write-Result
    try {
        $options = @{FilePath=$Sample;WorkingDirectory=$InputDir;PassThru=$true
            RedirectStandardOutput="$OutputDir\$Name-stdout.txt";RedirectStandardError="$OutputDir\$Name-stderr.txt"}
        if ($Arguments) { $options.ArgumentList=$Arguments }
        $child=Start-Process @options
        # Keep a process handle while it is alive: PowerShell 5.1 may otherwise
        # lose ExitCode for a short-lived process after WaitForExit/Refresh.
        $null=$child.Handle
        $phase.pid=$child.Id
        $Result.sample_started=$true
        if (-not $child.WaitForExit($Seconds * 1000)) {
            $phase.timeout=$true
            & "$env:WINDIR\System32\taskkill.exe" /PID $child.Id /T /F | Out-Null
            if ($LASTEXITCODE -ne 0 -or -not $child.WaitForExit(10000)) { throw 'No se pudo detener el proceso de prueba.' }
        }
        $child.Refresh()
        $phase.exit_code=$child.ExitCode
    } catch {
        $phase.error=$_.Exception.Message
        throw
    } finally {
        if ($null -ne $child -and -not $child.HasExited) { Stop-Process -Id $child.Id -Force -ErrorAction SilentlyContinue }
        $phase.finished_utc=[DateTime]::UtcNow.ToString('o')
        $phase.elapsed_seconds=$clock.Elapsed.TotalSeconds
        $Result.phases += [pscustomobject]$phase
        Write-Result
    }
}

Start-Transcript -Path "$OutputDir\transcript.txt" | Out-Null
try {
    Write-Result
    Save-Environment 'before'
    Assert-DefenderActive (Get-MpComputerStatus -ErrorAction Stop)
    foreach ($property in $Manifest.files.PSObject.Properties) {
        if ($property.Name -notin @('xmrig.exe','Procmon64.exe','observe.ps1','offline-config.json')) { throw 'Nombre de entrada no permitido.' }
        if ((Get-FileHash -LiteralPath (Join-Path $InputDir $property.Name)).Hash.ToLowerInvariant() -ne $property.Value) {
            throw ('SHA incorrecto: ' + $property.Name)
        }
    }
    if ((Get-FileHash -LiteralPath $Procmon).Hash.ToLowerInvariant() -ne $Manifest.procmon_sha256) { throw 'Process Monitor distinto al firmado verificado en host.' }
    $script:Monitor=Start-Process -FilePath $Procmon -ArgumentList "/AcceptEula /Quiet /Minimized /Runtime 300 /BackingFile $Trace" -PassThru
    $MonitorStarted=$true
    $ready=Start-Process -FilePath $Procmon -ArgumentList '/AcceptEula /Quiet /WaitForIdle' -PassThru
    if (-not $ready.WaitForExit(45000)) { Stop-Process -Id $ready.Id -Force; throw 'Process Monitor no confirma inicio; muestra sin ejecutar.' }
    $ready.Refresh()
    if ($ready.ExitCode -ne 0 -or -not (Test-Path -LiteralPath $Trace) -or (Get-Item -LiteralPath $Trace).Length -eq 0) {
        throw 'No se confirma una captura activa; muestra sin ejecutar.'
    }
    $Result.monitor_started=$true
    $Result.control_started_utc=[DateTime]::UtcNow.ToString('o')
    $Result.status='blank-control'
    Write-Result
    Start-Sleep -Seconds 15
    $Result.control_finished_utc=[DateTime]::UtcNow.ToString('o')
    Invoke-Sample 'help' '--help' 15
    Invoke-Sample 'version' '--version' 15
    Invoke-Sample 'no-config' '' 20
    Invoke-Sample 'offline' ("--config=$InputDir\offline-config.json") 60
    # Let the observer receive the final Process Exit event before stopping it.
    Start-Sleep -Seconds 2
    $Result.status='observation_finished_no_security_verdict'
} catch {
    $Result.status='failed_or_blocked'
    $Result.error=$_.Exception.Message
    Write-Warning $Result.error
} finally {
    if ($MonitorStarted) {
        try {
            $stop=Start-Process -FilePath $Procmon -ArgumentList '/Terminate' -PassThru
            if (-not $stop.WaitForExit(30000)) { throw 'No se confirma cierre de la captura.' }
            if (Test-Path -LiteralPath $Trace) {
                $export=Start-Process -FilePath $Procmon -ArgumentList "/AcceptEula /Quiet /OpenLog $Trace /SaveAs $OutputDir\trace.csv" -PassThru
                if (-not $export.WaitForExit(120000)) { Stop-Process -Id $export.Id -Force; throw 'Exportacion de CSV vencida; se conserva PML.' }
                $export.Refresh()
                $Result.capture_exported=($export.ExitCode -eq 0 -and (Test-Path -LiteralPath "$OutputDir\trace.csv"))
            }
        } catch { $Result.capture_error=$_.Exception.Message }
    }
    try { Save-Environment 'after' } catch { $Result.environment_error=$_.Exception.Message }
    $Result.finished_utc=[DateTime]::UtcNow.ToString('o')
    Write-Result
    Stop-Transcript | Out-Null
    # Keep Windows running for evidence extraction. Host restores the baseline before another sample.
}
