[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$PackageSha)
$ErrorActionPreference='Stop'
$ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'XMRIG-AUDIT' -or $env:USERNAME -ne 'audituser' -or
    (Get-CimInstance Win32_ComputerSystem).Model -ne 'VirtualBox') { throw 'Mantenimiento exclusivo de la VM de auditoria.' }
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requiere elevacion en la VM.'}
if(@(Get-NetAdapter | Where-Object Status -eq 'Up').Count -or
   @(Get-NetRoute | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count){throw 'La VM debe seguir sin red.'}
$package=Join-Path $PSScriptRoot 'mpam-fe.exe'
if((Get-FileHash -LiteralPath $package).Hash.ToLowerInvariant() -ne $PackageSha){throw 'Paquete distinto al firmado por Microsoft y verificado en el host.'}
$before=Get-MpComputerStatus
$timer=[Diagnostics.Stopwatch]::StartNew()
$process=Start-Process $package -PassThru
$null=$process.Handle
if(-not $process.WaitForExit(300000)){throw 'Actualizador excedio el plazo. Revisar antes de repetir.'}
$process.Refresh()
do {
    $after=Get-MpComputerStatus
    if($after.AntivirusSignatureVersion -ne $before.AntivirusSignatureVersion){break}
    Start-Sleep -Seconds 5
} while($timer.Elapsed.TotalSeconds -lt 360)
$result=[ordered]@{package_sha256=$PackageSha;exit_code=$process.ExitCode
    before_version=$before.AntivirusSignatureVersion;after_version=$after.AntivirusSignatureVersion
    updated=$after.AntivirusSignatureLastUpdated.ToUniversalTime().ToString('o')
    antivirus_enabled=$after.AntivirusEnabled;realtime_enabled=$after.RealTimeProtectionEnabled
    engine_version=$after.AMEngineVersion;platform_version=$after.AMProductVersion
    elapsed_seconds=$timer.Elapsed.TotalSeconds;checked_utc=[DateTime]::UtcNow.ToString('o')}
$result|ConvertTo-Json|Set-Content (Join-Path $PSScriptRoot 'defender-update.json') -Encoding UTF8
if(-not $result.antivirus_enabled -or -not $result.realtime_enabled -or
    $result.after_version -eq $result.before_version){throw 'No se confirma la actualizacion con proteccion activa.'}
