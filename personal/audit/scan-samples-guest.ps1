[CmdletBinding()]
param([Parameter(Mandatory=$true)][ValidatePattern('^[a-f0-9]{64}$')][string]$ManifestSha)
$ErrorActionPreference='Stop'; $ProgressPreference='SilentlyContinue'
if($env:COMPUTERNAME -ne 'XMRIG-AUDIT' -or $env:USERNAME -ne 'audituser' -or
    (Get-CimInstance Win32_ComputerSystem).Model -ne 'VirtualBox'){throw 'Solo VM de auditoria.'}
$principal=New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
if(-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)){throw 'Requiere administrador en la VM.'}
if(@(Get-NetAdapter|Where-Object Status -eq 'Up').Count -or
   @(Get-NetRoute|Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0')).Count){throw 'La VM debe seguir sin red.'}
$manifestFile=Join-Path $PSScriptRoot 'manifest.json'
if((Get-FileHash $manifestFile).Hash.ToLowerInvariant() -ne $ManifestSha){throw 'Manifiesto distinto.'}
$manifest=Get-Content $manifestFile -Raw|ConvertFrom-Json
if($manifest.run_id -notmatch '^[a-f0-9]{24}$'){throw 'Identificador invalido.'}
$output=Join-Path 'C:\XmrigAuditScans' $manifest.run_id
if(Test-Path $output){throw 'Conservar el resultado previo; no sobrescribir.'}
New-Item -ItemType Directory -Path $output|Out-Null
$result=[ordered]@{run_id=$manifest.run_id;started_utc=[DateTime]::UtcNow.ToString('o');samples=@();
    sample_executed=$false;network='none';verdict='not_assessed';status='preparing'}
function Save-ScanResult {$script:result|ConvertTo-Json -Depth 12|Set-Content (Join-Path $script:output 'scans.json') -Encoding UTF8}
try {
    if($manifest.PSObject.Properties.Name -contains 'enable_pua_block'){
        if($manifest.enable_pua_block -isnot [bool]){throw 'Politica PUA invalida.'}
        if($manifest.enable_pua_block){
            $result.pua_before=(Get-MpPreference).PUAProtection
            # Strengthen protection only in the verified offline guest; never add exclusions.
            Set-MpPreference -PUAProtection Enabled
            $result.pua_after=(Get-MpPreference).PUAProtection
            if($result.pua_after -ne 1){throw 'No se confirmo bloqueo PUA en la VM.'}
        }
    }
    $status=Get-MpComputerStatus; $prefs=Get-MpPreference
    $result.defender=[ordered]@{platform=$status.AMProductVersion;engine=$status.AMEngineVersion;
        signature=$status.AntivirusSignatureVersion;updated=$status.AntivirusSignatureLastUpdated;
        realtime=$status.RealTimeProtectionEnabled;PUAProtection=$prefs.PUAProtection;
        MAPSReporting=$prefs.MAPSReporting;SubmitSamplesConsent=$prefs.SubmitSamplesConsent}
    if(-not $status.AntivirusEnabled -or -not $status.RealTimeProtectionEnabled){throw 'Defender no esta activo.'}
    $platform=Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    $scanner=Get-ChildItem -LiteralPath $platform -Directory | Where-Object Name -like ($status.AMProductVersion+'*') |
        Sort-Object Name -Descending | ForEach-Object {Join-Path $_.FullName 'MpCmdRun.exe'} | Select-Object -First 1
    if(-not $scanner){$scanner=Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe'}
    $signature=Get-AuthenticodeSignature -LiteralPath $scanner
    if($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation'){throw 'No se valida la firma del analizador Microsoft.'}
    $result.scanner=[ordered]@{path=$scanner;sha256=(Get-FileHash $scanner).Hash.ToLowerInvariant();signature=[string]$signature.Status}
    Save-ScanResult
    foreach($sample in $manifest.samples){
        if($sample.path -notmatch '^(original|fork|upstream|optimized)\\xmrig\.exe$' -or
           $sample.sha256 -notmatch '^[a-f0-9]{64}$'){throw 'Entrada de muestra invalida.'}
        $name=($sample.path -split '\\')[0]
        $file=Join-Path $PSScriptRoot $sample.path
        if((Get-FileHash $file).Hash.ToLowerInvariant() -ne $sample.sha256){throw 'SHA de muestra distinto.'}
        $phase=[ordered]@{name=$name;sha256=$sample.sha256;started_utc=[DateTime]::UtcNow.ToString('o');exit_code=$null;error=$null}
        $clock=[Diagnostics.Stopwatch]::StartNew()
        try {
            # The only executable launched is the signed Microsoft scanner.
            $p=Start-Process -FilePath $scanner -WorkingDirectory (Split-Path $scanner) -PassThru -ArgumentList @('-Scan','-ScanType','3','-File',('"'+$file+'"')) -RedirectStandardOutput "$output\$name-stdout.txt" -RedirectStandardError "$output\$name-stderr.txt"
            $null=$p.Handle
            if(-not $p.WaitForExit(180000)){throw 'El analizador no termino; conservar VM y revisar.'}
            $phase.exit_code=$p.ExitCode
        } catch {$phase.error=$_.Exception.Message;throw}
        finally {
            $phase.elapsed_seconds=$clock.Elapsed.TotalSeconds
            $phase.finished_utc=[DateTime]::UtcNow.ToString('o')
            $result.samples += [pscustomobject]$phase
            Save-ScanResult
        }
    }
    $result.status='scans_finished_no_security_verdict'
} catch {$result.status='failed_or_blocked';$result.error=$_.Exception.Message}
finally {
    try {
        $result.threats=@(Get-MpThreat|Select-Object ThreatID,ThreatName,IsActive,DidThreatExecute,Resources)
        $result.detections=@(Get-MpThreatDetection|Select-Object ThreatID,InitialDetectionTime,ActionSuccess,ThreatStatusID,Resources)
    } catch {$result.detection_error=$_.Exception.Message}
    $result.finished_utc=[DateTime]::UtcNow.ToString('o');Save-ScanResult
}
