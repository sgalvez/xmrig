# XMRig built from source runs on Windows; only public payout configuration crosses from WSL.
# Only the Microsoft Defender scan may request elevation; the miner never does.
[CmdletBinding()]
param(
    [Parameter(Mandatory=$true)]
    [ValidateSet('Install','Scan','Devices','Probe','Start','Run','Stop','Status','Review','Diagnostics','AcceptPua','AcceptRisk')][string]$Action,
    [ValidateRange(0,31)][int]$GpuId = 0,
    [string]$RuntimeRoot = '',
    [string]$ExpectedSha256 = '',
    [ValidatePattern('^[a-f0-9]{32}$')][string]$SessionId = ''
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
# Windows PowerShell may leave PSScriptRoot empty while binding defaults.
# Resolve the sibling integration directory only after entering the script body.
if ([string]::IsNullOrWhiteSpace($RuntimeRoot)) {
    $launcherDirectory = Split-Path -Parent $PSCommandPath
    $integrationDirectory = Join-Path (Split-Path -Parent $launcherDirectory) 'ravencoin-miner-lab'
    $RuntimeRoot = Join-Path $integrationDirectory '.runtime'
}
$Runtime = [IO.Path]::GetFullPath($RuntimeRoot)
$StateFile = Join-Path $Runtime 'status.json'
$StopFile = Join-Path $Runtime 'stop.request'
$CancelFile = if ($SessionId) { Join-Path $Runtime ('cancel-' + $SessionId + '.request') } else { $null }
$Version = '6.26.0'
$TrialSeconds = 0
if ($Action -eq 'Probe') { $TrialSeconds = 300; $Action = 'Run' }
$Engine = 'XMRig'
$ScanFile = Join-Path $Runtime 'xmrig-scan.json'
$ExeHash = ''
$SourceCommit = 'cfc5f4f78f539ad55fe82fc20493ba2287e0083c'
$SecurityPolicy = 'rvn-governor-4'
$ProjectRoot = Split-Path -Parent $PSCommandPath
$BuildRoot = Join-Path $ProjectRoot '.artifacts\windows'
$TrustFile = Join-Path $ProjectRoot '.trust\windows-build.json'
$InstallRoot = Join-Path $env:LOCALAPPDATA 'RavencoinPersonal\XMRig-6.26.0'
$Exe = Join-Path $InstallRoot 'xmrig.exe'
$Utf8 = New-Object System.Text.UTF8Encoding($false)
[void][System.IO.Directory]::CreateDirectory($Runtime)

function Write-State($State) {
    $temp = "$StateFile.$PID.tmp"
    [System.IO.File]::WriteAllText($temp, ($State | ConvertTo-Json -Depth 6), $Utf8)
    Move-Item -LiteralPath $temp -Destination $StateFile -Force
}
function Read-State {
    if (Test-Path -LiteralPath $StateFile) {
        return (Get-Content -LiteralPath $StateFile -Raw | ConvertFrom-Json)
    }
    return $null
}
function Assert-MinerAllowed {
    if (Test-Path -LiteralPath (Join-Path $Runtime 'xmrig-security-block.json')) {
        throw 'XMRig suspendido por deteccion de antivirus. Conserva la cuarentena y revisa el Historial de proteccion.'
    }
    Assert-LegacyIncidents
}
function Assert-LegacyIncidents {
    foreach ($prior in @(@('security-block.json','SRBMiner-Multi'), @('wildrig-security-block.json','WildRig-Multi'))) {
        $path = Join-Path $Runtime $prior[0]
        if (Test-Path -LiteralPath $path) {
            $incident = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
            if ($incident.component -ne $prior[1]) { throw 'Bloqueo de seguridad pendiente de identificar.' }
        }
    }
}
function Assert-DefenderEnabled {
    $av = Get-MpComputerStatus -ErrorAction Stop
    if (-not $av.AntivirusEnabled -or -not $av.RealTimeProtectionEnabled) {
        throw 'Defender debe estar activo con proteccion en tiempo real antes de usar XMRig.'
    }
}
function Get-MinerDetections {
    return @(Get-MpThreatDetection -ErrorAction Stop | Where-Object {
        $matched = $false
        foreach ($resource in $_.Resources) {
            foreach ($directory in @($InstallRoot, $BuildRoot)) {
                if (Test-DetectionPath $resource $directory) { $matched = $true }
            }
        }
        $matched
    })
}
function Assert-DefenderReady([switch]$AllowMissingInstalled, [switch]$PrepareUpgrade) {
    Assert-DefenderEnabled
    $detections = @(Get-MinerDetections)
    $riskFile = Join-Path $Runtime 'xmrig-risk-consent.json'
    if (Test-Path -LiteralPath $riskFile) {
        $risk = Get-Content -LiteralPath $riskFile -Raw | ConvertFrom-Json
        if ($risk.component -ne $Engine -or $risk.accepted -ne $true -or
            $risk.kind -ne 'explicit-owner-risk-consent' -or -not $risk.keys) {
            throw 'Aceptacion de riesgo local invalida.'
        }
        $riskThreats = @(Get-MpThreat -ErrorAction Stop)
        $accepted = @($detections | Where-Object {
            (Get-DetectionKey $_) -in $risk.keys -and (Test-OwnerRiskIncident $_ $riskThreats)
        })
        if ($accepted.Count) {
            Assert-RiskBuild $risk.sha256 -Preparation:($PrepareUpgrade -or $AllowMissingInstalled)
            $detections = @($detections | Where-Object {
                -not ((Get-DetectionKey $_) -in $risk.keys -and (Test-OwnerRiskIncident $_ $riskThreats))
            })
        }
    }
    $consentFile = Join-Path $Runtime 'xmrig-pua-consent.json'
    if (Test-Path -LiteralPath $consentFile) {
        $consent = Get-Content -LiteralPath $consentFile -Raw | ConvertFrom-Json
        if ($consent.component -ne $Engine -or $consent.accepted -ne $true -or -not $consent.keys) {
            throw 'Aceptacion PUA local invalida.'
        }
        $puaThreats = @(Get-MpThreat -ErrorAction Stop)
        $acceptedDetections = @($detections | Where-Object {
            (Get-DetectionKey $_) -in $consent.keys -and (Test-KnownPua $_ $puaThreats)
        })
        # A receipt for an absent incident grants no exception and must not
        # prevent a new, clean build from being scanned. Preserve it unchanged.
        if ($acceptedDetections.Count) {
            if ($PrepareUpgrade) { Assert-PuaUpgrade $consent.sha256 }
            else { Assert-PuaBuild $consent.sha256 -AllowMissingInstalled:$AllowMissingInstalled }
            $detections = @($detections | Where-Object {
                -not ((Get-DetectionKey $_) -in $consent.keys -and (Test-KnownPua $_ $puaThreats))
            })
        }
    }
    $reviewFile = Join-Path $Runtime 'xmrig-security-reviewed.json'
    if (Test-Path -LiteralPath $reviewFile) {
        $review = Get-Content -LiteralPath $reviewFile -Raw | ConvertFrom-Json
        if ($review.component -ne $Engine -or $review.completed -ne $true) { throw 'Registro de revision de seguridad invalido.' }
        $threats = @(Get-MpThreat -ErrorAction Stop)
        $detections = @($detections | Where-Object {
            -not ((Get-DetectionKey $_) -in $review.keys -and (Test-ReviewableDetection $_ $threats))
        })
    }
    if ($detections.Count) {
        $block = @{component=$Engine; version=$Version; detection='Microsoft Defender';
            threat_ids=@($detections | ForEach-Object { $_.ThreatID });
            resources=@($detections | ForEach-Object { $_.Resources });
            updated=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}
        [IO.File]::WriteAllText((Join-Path $Runtime 'xmrig-security-block.json'), ($block | ConvertTo-Json -Depth 6), $Utf8)
        throw 'Defender registra una deteccion en XMRig. Se suspende su ejecucion; conserva la cuarentena.'
    }
}
function Test-OwnerRiskIncident($Detection, $Threats) {
    # Owner-reviewed classifications only. New IDs, names, resources or incident
    # identities are never inherited, even when the executable hash is unchanged.
    $known = @{'274600'='PUA:Win32/Caypnamer.A!ml';
        '2147735505'='Trojan:Win32/Wacatac.B!ml';'2147749372'='Trojan:Win32/Wacatac.C!ml';
        '2147814523'='Trojan:Win32/Wacatac.H!ml';'265744'='Program:Win32/Wacapew.C!ml'}
    $expected = $known[[string]$Detection.ThreatID]
    if (-not $expected -or [string]::IsNullOrWhiteSpace($Detection.DetectionID)) { return $false }
    $matches = @($Threats | Where-Object { $_.ThreatID -eq $Detection.ThreatID })
    if (-not $matches.Count -or @($matches | Where-Object { $_.ThreatName -cne $expected }).Count) { return $false }
    # This classification was observed on the previous installation. It may
    # accompany a new pinned owner decision only while remediated and never
    # executed; it does not grant permission for active Wacapew detections.
    if ($Detection.ThreatID -eq 265744) {
        if ($Detection.ThreatStatusID -notin @(3,4) -or
            -not (Test-ReviewableDetection $Detection $Threats) -or
            @($matches | Where-Object { $_.DidThreatExecute -isnot [bool] -or $_.DidThreatExecute }).Count) { return $false }
    }
    if (-not @($Detection.Resources).Count) { return $false }
    foreach ($resource in $Detection.Resources) {
        $r = ([string]$resource).ToLowerInvariant().Replace('/', '\').Replace('\\wsl$\', '\\wsl.localhost\')
        $allowed = @($Exe, (Join-Path $BuildRoot 'xmrig.exe')) | ForEach-Object { 'file:_' + $_.ToLowerInvariant().Replace('/', '\').Replace('\\wsl$\', '\\wsl.localhost\') }
        if ($Detection.ThreatID -eq 265744) { $allowed = @($allowed[0]) }
        if ($r -notin $allowed) { return $false }
    }
    return $true
}
function Assert-RiskBuild([string]$Expected, [switch]$Preparation) {
    if ($Expected -cnotmatch '^[a-f0-9]{64}$') { throw 'Indica el SHA-256 completo que aceptas.' }
    $directories = @($BuildRoot)
    if (-not $Preparation) { Assert-InstallDirectory; $directories += $InstallRoot }
    foreach ($directory in $directories) {
        $build = Load-Build $directory
        if ($build.sha256 -cne $Expected) {
            throw 'La aceptacion de riesgo no corresponde a esta compilacion. Requiere un SHA y una decision nuevos.'
        }
        $file = Join-Path $directory 'xmrig.exe'
        try {
            $item = Get-Item -LiteralPath $file -ErrorAction Stop
            if ($item.PSIsContainer) { throw 'La ruta no es un archivo.' }
            $actual = (Get-FileHash -LiteralPath $file -Algorithm SHA256 -ErrorAction Stop).Hash.ToLowerInvariant()
        } catch {
            throw "No se puede leer el ejecutable: $file. Revisa su estado en Defender y recupera la copia verificada antes de continuar. No aceptes otro SHA para resolver este error. Detalle: $($_.Exception.Message)"
        }
        if ($item.Length -eq 0) {
            throw "El ejecutable esta vacio (0 bytes): $file. El manifiesto corresponde al SHA aceptado, pero falta recuperar la copia verificada. Revisa Defender; no registres el SHA del archivo vacio."
        }
        if ($actual -cne $Expected) {
            throw "El contenido del ejecutable no coincide con la compilacion aceptada: $file. Recupera la copia verificada; no aceptes este SHA como si fuera una nueva compilacion."
        }
    }
}
function Accept-OwnerRisk {
    Assert-StandardUser
    Assert-LegacyIncidents
    Assert-DefenderEnabled
    if (Owned-Process (Read-State)) { throw 'Deten el minero antes de registrar la decision.' }
    Assert-RiskBuild $ExpectedSha256 -Preparation
    $detections = @(Get-MinerDetections)
    $threats = @(Get-MpThreat -ErrorAction Stop)
    $selected = @($detections | Where-Object { Test-OwnerRiskIncident $_ $threats })
    if (-not $selected.Count) { throw 'No hay incidentes revisados elegibles para registrar esta decision.' }
    $blockFile = Join-Path $Runtime 'xmrig-security-block.json'
    $previous = $null
    if (Test-Path -LiteralPath $blockFile) {
        $previous = Get-Content -LiteralPath $blockFile -Raw | ConvertFrom-Json
        if ($previous.component -ne $Engine -or -not $previous.threat_ids -or
            @($previous.threat_ids | Where-Object { $_ -notin @($detections | ForEach-Object { $_.ThreatID }) }).Count) {
            throw 'El bloqueo local incluye incidentes que Defender no permite identificar.'
        }
    }
    $record = @{component=$Engine;accepted=$true;kind='explicit-owner-risk-consent';sha256=$ExpectedSha256;
        updated=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();keys=@($selected | ForEach-Object { Get-DetectionKey $_ });
        previous=$previous;detections=@($selected | Select-Object DetectionID,ThreatID,Resources,ThreatStatusID);
        threat_names=@($threats | Where-Object { $_.ThreatID -in @($selected | ForEach-Object { $_.ThreatID }) } | ForEach-Object { $_.ThreatName })}
    $path = Join-Path $Runtime 'xmrig-risk-consent.json'
    $old = if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw } else { $null }
    try {
        [IO.File]::WriteAllText("$path.tmp", ($record | ConvertTo-Json -Depth 8), $Utf8)
        Move-Item -LiteralPath "$path.tmp" -Destination $path -Force
        Assert-DefenderReady -PrepareUpgrade
    } catch {
        if ($null -ne $old) { [IO.File]::WriteAllText($path, $old, $Utf8) }
        else { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
        throw
    }
    $archive = Join-Path $Runtime 'security-history'
    [void][IO.Directory]::CreateDirectory($archive)
    [IO.File]::WriteAllText((Join-Path $archive ('risk-consent-' + [guid]::NewGuid().ToString('N') + '.json')),
        ($record | ConvertTo-Json -Depth 8), $Utf8)
    Remove-Item -LiteralPath $ScanFile -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $blockFile) { Remove-Item -LiteralPath $blockFile }
    Write-Host "Riesgo aceptado localmente para SHA-256 $ExpectedSha256 y los incidentes registrados."
    Write-Host 'No es una confirmacion de falso positivo. Defender no cambia; instalacion y analisis siguen siendo obligatorios.'
}
function Test-KnownPua($Detection, $Threats) {
    # Explicit owner consent is limited to this reviewed classification and file.
    # It is NOT a remediation verdict or a general exception for mining software.
    if ($Detection.ThreatID -ne 274600 -or [string]::IsNullOrWhiteSpace($Detection.DetectionID)) { return $false }
    $matches = @($Threats | Where-Object { $_.ThreatID -eq $Detection.ThreatID })
    if (-not $matches.Count) { return $false }
    foreach ($threat in $matches) {
        if ($threat.ThreatName -cne 'PUA:Win32/Caypnamer.A!ml') { return $false }
    }
    if (-not @($Detection.Resources).Count) { return $false }
    foreach ($resource in $Detection.Resources) {
        if (-not ([string]$resource).StartsWith('file:_', [StringComparison]::OrdinalIgnoreCase) -or
            ([string]$resource).Substring(6).Replace('/', '\') -ine $Exe.Replace('/', '\')) { return $false }
    }
    return $true
}
function Assert-PuaBuild([string]$Expected, [switch]$AllowMissingInstalled) {
    if ($Expected -cnotmatch '^[a-f0-9]{64}$') { throw 'Indica el SHA-256 completo del ejecutable que aceptas.' }
    if (Test-Path -LiteralPath $InstallRoot) { Assert-InstallDirectory }
    foreach ($directory in @($BuildRoot, $InstallRoot)) {
        # Consent and pre-install checks can use the trusted export when Defender
        # removed the installed EXE. Scan/execution checks still require both copies.
        if ($AllowMissingInstalled -and $directory -eq $InstallRoot -and
            -not (Test-Path -LiteralPath (Join-Path $directory 'xmrig.exe'))) { continue }
        $build = Load-Build $directory
        if ($build.sha256 -cne $Expected -or
            (Get-FileHash -LiteralPath (Join-Path $directory 'xmrig.exe') -Algorithm SHA256).Hash.ToLowerInvariant() -cne $Expected) {
            throw "La aceptacion PUA no corresponde a esta compilacion/archivo (SHA actual: $($build.sha256)). Hace falta revisar y aceptar explicitamente el nuevo SHA si la alerta persiste. No se inicia el minero."
        }
    }
}
function Assert-PuaUpgrade([string]$PreviouslyAccepted) {
    # Preparation only: keep the old receipt unchanged, copy a trusted new build,
    # then require the ordinary scan/consent gates before any execution.
    $build = Load-Build $BuildRoot
    $source = Join-Path $BuildRoot 'xmrig.exe'
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -cne $build.sha256) {
        throw 'La nueva compilacion no coincide con su registro de confianza.'
    }
    if ($build.sha256 -ceq $PreviouslyAccepted) {
        Assert-PuaBuild $PreviouslyAccepted -AllowMissingInstalled
        return
    }
    if ($PreviouslyAccepted -cnotmatch '^[a-f0-9]{64}$') { throw 'Aceptacion anterior sin SHA valido.' }
    if (Test-Path -LiteralPath $InstallRoot) { Assert-InstallDirectory }
    if (Test-Path -LiteralPath $Exe) {
        $installed = (Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant()
        if ($installed -cne $PreviouslyAccepted -and $installed -cne $build.sha256) {
            throw 'El ejecutable instalado cambio fuera de la compilacion registrada.'
        }
    }
    Write-Host 'Preparando nueva compilacion para analizar. La aceptacion PUA anterior no autoriza su ejecucion.'
}
function Accept-Pua {
    Assert-StandardUser
    Assert-LegacyIncidents
    Assert-DefenderEnabled
    if (Owned-Process (Read-State)) { throw 'Deten el minero antes de registrar la aceptacion PUA.' }
    Assert-PuaBuild $ExpectedSha256 -AllowMissingInstalled
    $detections = @(Get-MinerDetections)
    $threats = @(Get-MpThreat -ErrorAction Stop)
    $selected = @($detections | Where-Object { Test-KnownPua $_ $threats })
    if (-not $selected.Count) { throw 'No se encontro la PUA Caypnamer esperada sobre el ejecutable instalado.' }
    $blockFile = Join-Path $Runtime 'xmrig-security-block.json'
    $previous = $null
    if (Test-Path -LiteralPath $blockFile) {
        $previous = Get-Content -LiteralPath $blockFile -Raw | ConvertFrom-Json
        if ($previous.component -ne $Engine -or -not $previous.threat_ids -or
            @($previous.threat_ids | Where-Object { $_ -ne 274600 }).Count) {
            throw 'Hay otro incidente local pendiente; esta aceptacion solo cubre la PUA Caypnamer.'
        }
    }
    $record = @{component=$Engine; accepted=$true; kind='explicit-owner-pua-consent';
        sha256=$ExpectedSha256; keys=@($selected | ForEach-Object { Get-DetectionKey $_ });
        updated=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); previous=$previous;
        detections=@($selected | Select-Object DetectionID,ThreatID,Resources,ThreatStatusID);
        threat_name='PUA:Win32/Caypnamer.A!ml'}
    $path = Join-Path $Runtime 'xmrig-pua-consent.json'
    $old = if (Test-Path -LiteralPath $path) { Get-Content -LiteralPath $path -Raw } else { $null }
    try {
        [IO.File]::WriteAllText("$path.tmp", ($record | ConvertTo-Json -Depth 8), $Utf8)
        Move-Item -LiteralPath "$path.tmp" -Destination $path -Force
        # Re-query live detections: other alerts and changed incidents still block.
        Assert-DefenderReady -AllowMissingInstalled
    } catch {
        if ($null -ne $old) { [IO.File]::WriteAllText($path, $old, $Utf8) }
        else { Remove-Item -LiteralPath $path -ErrorAction SilentlyContinue }
        throw
    }
    $archive = Join-Path $Runtime 'security-history'
    [void][IO.Directory]::CreateDirectory($archive)
    [IO.File]::WriteAllText((Join-Path $archive ('pua-consent-' + [guid]::NewGuid().ToString('N') + '.json')),
        ($record | ConvertTo-Json -Depth 8), $Utf8)
    Remove-Item -LiteralPath $ScanFile -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $blockFile) { Remove-Item -LiteralPath $blockFile }
    Write-Host 'Aceptacion local de Caypnamer registrada para este SHA-256 e incidentes exactos.'
    Write-Host 'No se cambio Defender ni se inicio mineria. Debes permitir la alerta en Windows; el analisis de instalacion sigue siendo obligatorio.'
}
function Test-DetectionPath([string]$Resource, [string]$Directory) {
    if ([string]::IsNullOrWhiteSpace($Directory)) { return $false }
    # Defender uses file:_ and containerfile:_ prefixes and both WSL UNC aliases.
    $r = $Resource.ToLowerInvariant().Replace('/', '\').Replace('\\?\unc\', '\\').Replace('\\wsl$\', '\\wsl.localhost\').ToLowerInvariant()
    $d = $Directory.ToLowerInvariant().Replace('/', '\').Replace('\\?\unc\', '\\').Replace('\\wsl$\', '\\wsl.localhost\').TrimEnd('\').ToLowerInvariant()
    return $r.Contains($d + '\') -or $r.EndsWith($d)
}
function Get-DetectionKey($Detection) {
    $record = [ordered]@{}
    foreach ($field in @('DetectionID','ThreatID','InitialDetectionTime','LastThreatStatusChangeTime',
                        'RemediationTime','ThreatStatusID','ActionSuccess','AdditionalActionsBitMask',
                        'CleaningActionID','ThreatStatusErrorCode','CurrentThreatExecutionStatusID')) {
        $value = $Detection.$field
        $record[$field] = if ($value -is [DateTime]) { $value.ToUniversalTime().ToString('o') } else { [string]$value }
    }
    $record.resources = @($Detection.Resources | Sort-Object)
    $hash = [Security.Cryptography.SHA256]::Create()
    try { return ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes(($record | ConvertTo-Json -Compress -Depth 5))))).Replace('-','') }
    finally { $hash.Dispose() }
}
function Test-ReviewableDetection($Detection, $Threats) {
    # Eligibility for a NEW scan, never permission to run. Status 8 has no public
    # mapping in MSFT_MpThreatDetection; do not label it Removed or infer action 9.
    if ([string]::IsNullOrWhiteSpace($Detection.DetectionID) -or
        $Detection.ActionSuccess -isnot [bool] -or -not $Detection.ActionSuccess -or
        $Detection.ThreatStatusID -notin @(3,4,8) -or
        $null -eq $Detection.AdditionalActionsBitMask -or $Detection.AdditionalActionsBitMask -ne 0) { return $false }
    $matching = @($Threats | Where-Object { $_.ThreatID -eq $Detection.ThreatID })
    if (-not $matching.Count) { return $false }
    foreach ($threat in $matching) {
        if ($threat.IsActive -isnot [bool] -or $threat.IsActive) { return $false }
        if ($Detection.ThreatStatusID -eq 8 -and
            ($threat.DidThreatExecute -isnot [bool] -or $threat.DidThreatExecute)) { return $false }
    }
    if ($Detection.ThreatStatusID -eq 8) {
        # Independent documented evidence: blocked execution, successful action,
        # no error/pending work, inactive, never executed. Missing fields fail closed.
        if ($null -eq $Detection.ThreatStatusErrorCode -or $Detection.ThreatStatusErrorCode -ne 0 -or
            $Detection.CurrentThreatExecutionStatusID -ne 1 -or
            $Detection.InitialDetectionTime -isnot [datetime] -or
            $Detection.RemediationTime -isnot [datetime] -or
            $Detection.RemediationTime -lt $Detection.InitialDetectionTime -or
            $Detection.RemediationTime -gt [datetime]::UtcNow) { return $false }
    }
    return $true
}
function Write-SecurityDiagnostic {
    # Read-only Windows queries. Never scan, install, execute, remediate or approve.
    $detections = @(Get-MinerDetections)
    $ids = @($detections | ForEach-Object { $_.ThreatID } | Sort-Object -Unique)
    $report = [ordered]@{collected=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds();
        detections=@($detections | Select-Object DetectionID,ThreatID,ThreatStatusID,
            CleaningActionID,ActionSuccess,ThreatStatusErrorCode,AdditionalActionsBitMask,
            CurrentThreatExecutionStatusID,AMProductVersion,InitialDetectionTime,
            LastThreatStatusChangeTime,RemediationTime,Resources)}
    try {
        $report.threats = @(Get-MpThreat -ErrorAction Stop | Where-Object { $_.ThreatID -in $ids } |
            Select-Object ThreatID,ThreatName,IsActive,DidThreatExecute,Resources)
    } catch { $report.threat_query_error = $_.Exception.Message }
    try {
        $class = Get-CimClass -Namespace 'root/Microsoft/Windows/Defender' -ClassName MSFT_MpThreatDetection -ErrorAction Stop
        $report.provider_mappings = @{}
        foreach ($name in @('ThreatStatusID','CleaningActionID','CurrentThreatExecutionStatusID')) {
            $qualifiers = $class.CimClassProperties[$name].Qualifiers
            $report.provider_mappings[$name] = @{
                values=@($qualifiers['Values'].Value); value_map=@($qualifiers['ValueMap'].Value)
            }
        }
    } catch { $report.provider_mapping_error = $_.Exception.Message }
    $path = Join-Path $Runtime 'xmrig-security-diagnostic.json'
    $json = $report | ConvertTo-Json -Depth 10
    [IO.File]::WriteAllText($path, $json, $Utf8)
    Write-Host $json
    Write-Host "Diagnostico guardado: $path. No se modifico Defender ni el bloqueo local."
}
function Review-RemovedDetection {
    Assert-StandardUser
    Assert-LegacyIncidents
    Assert-DefenderEnabled
    if (Owned-Process (Read-State)) { throw 'Deten el minero antes de revisar el incidente.' }
    $blockFile = Join-Path $Runtime 'xmrig-security-block.json'
    $previous = $null
    if (Test-Path -LiteralPath $blockFile) {
        $previous = Get-Content -LiteralPath $blockFile -Raw | ConvertFrom-Json
        if ($previous.component -ne $Engine -or -not $previous.threat_ids) { throw 'Incidente local sin identificar; no se puede archivar.' }
    }
    $before = @(Get-MinerDetections)
    $threats = @(Get-MpThreat -ErrorAction Stop)
    $build = Load-Build $BuildRoot
    foreach ($detection in $before) {
        if (-not (Test-ReviewableDetection $detection $threats)) {
            throw "Defender no aporta evidencia suficiente para revisar el incidente $($detection.ThreatID): estado=$($detection.ThreatStatusID), accion=$($detection.ActionSuccess), pendientes=$($detection.AdditionalActionsBitMask). No se cambia el bloqueo."
        }
        if ($detection.ThreatStatusID -eq 8) {
            $builtAt = [DateTimeOffset]::MinValue
            # PS 7 decodes ISO dates as DateTime; PS 5 keeps strings. Preserve UTC.
            $buildTime = if ($build.built_at -is [datetime]) { $build.built_at.ToString('o') } else { [string]$build.built_at }
            if (-not [DateTimeOffset]::TryParse($buildTime, [ref]$builtAt) -or
                $builtAt -gt [DateTimeOffset]::UtcNow -or
                $detection.RemediationTime.ToUniversalTime() -ge $builtAt.UtcDateTime) {
                throw 'El incidente inactivo no es anterior a la compilacion actual; no se puede tratar como historico.'
            }
        }
    }
    foreach ($id in @($previous.threat_ids)) {
        if ($null -ne $id -and -not @($before | Where-Object { $_.ThreatID -eq $id }).Count) {
            throw 'Defender no devuelve el incidente local; no se puede asumir que fue resuelto.'
        }
    }
    $expectedHash = $ExeHash
    $source = Join-Path $BuildRoot 'xmrig.exe'
    if ((Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) { throw 'El archivo actual no coincide con la compilacion registrada.' }
    $keys = @($before | ForEach-Object { Get-DetectionKey $_ } | Sort-Object)
    # This scan reads the exported artifact. It never installs or starts the miner.
    $scan = Invoke-DefenderScan $BuildRoot
    Assert-DefenderEnabled
    $after = @(Get-MinerDetections)
    $afterThreats = @(Get-MpThreat -ErrorAction Stop)
    $afterKeys = @($after | ForEach-Object { Get-DetectionKey $_ } | Sort-Object)
    if ($scan.ExitCode -ne 0 -or ($keys -join ',') -cne ($afterKeys -join ',')) {
        throw 'El analisis fallo o cambio el historial de detecciones. Se conserva el bloqueo.'
    }
    foreach ($detection in $after) {
        if (-not (Test-ReviewableDetection $detection $afterThreats)) { throw 'Defender informa un incidente pendiente. Se conserva el bloqueo.' }
    }
    [void](Load-Build $BuildRoot)
    if ($ExeHash -ne $expectedHash -or (Get-FileHash -LiteralPath $source -Algorithm SHA256).Hash.ToLowerInvariant() -ne $expectedHash) {
        throw 'El ejecutable cambio o fue retirado durante el analisis. Se conserva el bloqueo.'
    }
    $archiveDir = Join-Path $Runtime 'security-history'
    [void][IO.Directory]::CreateDirectory($archiveDir)
    $archive = Join-Path $archiveDir ('xmrig-' + [guid]::NewGuid().ToString('N') + '.json')
    $record = @{component=$Engine; completed=$true; sha256=$expectedHash; keys=$keys;
                updated=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); previous=$previous;
                detections=@($after | Select-Object DetectionID,ThreatID,ThreatStatusID,CleaningActionID,
                    ActionSuccess,ThreatStatusErrorCode,AdditionalActionsBitMask,CurrentThreatExecutionStatusID,
                    Resources,InitialDetectionTime,RemediationTime);
                threats=@($afterThreats | Where-Object { $_.ThreatID -in @($after | ForEach-Object { $_.ThreatID }) } |
                    Select-Object ThreatID,IsActive,DidThreatExecute)}
    [IO.File]::WriteAllText($archive, ($record | ConvertTo-Json -Depth 8), $Utf8)
    $review = Join-Path $Runtime 'xmrig-security-reviewed.json'
    [IO.File]::WriteAllText("$review.tmp", ($record | ConvertTo-Json -Depth 8), $Utf8)
    Move-Item -LiteralPath "$review.tmp" -Destination $review -Force
    Remove-Item -LiteralPath $ScanFile -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $blockFile) { Remove-Item -LiteralPath $blockFile }
    Write-Host 'Incidente historico archivado tras verificar Defender y analizar el archivo actual. Falta instalar y probar la GPU.'
}
function Assert-StandardUser {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if ($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        throw 'Inicia el minero desde una terminal sin privilegios de administrador.'
    }
}
function Assert-InstallDirectory {
    $allowed = @('xmrig.exe','build.json','sources.json','LICENSE-xmrig.txt','LICENSE-libuv.txt','LICENSE-openssl.txt')
    $folder = Get-Item -LiteralPath $InstallRoot -Force
    if ($folder.Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'La instalacion no puede ser un enlace.' }
    foreach ($item in (Get-ChildItem -LiteralPath $InstallRoot -Force)) {
        if ($item.PSIsContainer -or ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) -or $item.Name -notin $allowed) {
            throw "Archivo inesperado en la instalacion: $($item.Name). No se cargara el minero."
        }
    }
}
function Get-GpuLibraryPath([string]$Name) {
    return Join-Path ([Environment]::GetFolderPath([Environment+SpecialFolder]::System)) $Name
}
function Assert-GpuLibraries {
    foreach ($name in @('OpenCL.dll', 'atiadlxx.dll')) {
        $path = Get-GpuLibraryPath $name
        if (-not (Test-Path -LiteralPath $path -PathType Leaf)) {
            throw "Falta la biblioteca de sistema $name. Revisa el controlador AMD; no copies DLL a la carpeta del minero."
        }
        $signature = Get-AuthenticodeSignature -LiteralPath $path
        if ($signature.Status -ne 'Valid') { throw "Firma no valida en $path. Revisa el controlador AMD." }
    }
}
function Check-Scan {
    if (-not (Test-Path -LiteralPath $ScanFile)) { throw 'Falta el analisis de Defender: python3 raven.py miner-scan' }
    $scan = Get-Content -LiteralPath $ScanFile -Raw | ConvertFrom-Json
    if ($scan.sha256 -ne $ExeHash -or $scan.path -ne $Exe -or $scan.completed -ne $true) {
        throw 'Analisis no correspondiente a este ejecutable. Ejecuta miner-scan.'
    }
}
function Invoke-DefenderScan([string]$Directory) {
    $platform = Join-Path $env:ProgramData 'Microsoft\Windows Defender\Platform'
    $scanner = Get-ChildItem -Path (Join-Path $platform '*\MpCmdRun.exe') -ErrorAction SilentlyContinue |
        Sort-Object FullName -Descending | Select-Object -First 1 -ExpandProperty FullName
    if (-not $scanner) { $scanner = Join-Path $env:ProgramFiles 'Windows Defender\MpCmdRun.exe' }
    $signature = Get-AuthenticodeSignature -LiteralPath $scanner
    if ($signature.Status -ne 'Valid' -or $signature.SignerCertificate.Subject -notmatch 'O=Microsoft Corporation') {
        throw 'No se pudo verificar la firma del analizador de Microsoft Defender.'
    }
    Write-Host 'Windows puede pedir autorizacion SOLO para el analizador firmado de Microsoft Defender.'
    $argv = @('-Scan','-ScanType','3','-File',$Directory)
    $scan = Start-Process -FilePath $scanner -ArgumentList (($argv | ForEach-Object { Quote-Arg $_ }) -join ' ') -Verb RunAs -Wait -PassThru
    return $scan
}
function Scan-Executable {
    Assert-MinerAllowed
    # Scanning a trusted replacement is preparation, never authorization to run.
    # Keep the strict current-hash gate AFTER the scan, before writing its receipt.
    Assert-DefenderReady -PrepareUpgrade
    Check-Executable
    Remove-Item -LiteralPath $ScanFile -ErrorAction SilentlyContinue
    $scan = Invoke-DefenderScan $InstallRoot
    # Exit 0 also includes successful remediation: check detection history and hash again.
    try { Assert-DefenderReady }
    catch { throw "Se ejecuto el analisis. La validacion posterior no autoriza XMRig: $($_.Exception.Message)" }
    if ($scan.ExitCode -ne 0) { throw "Defender no completo el analisis (codigo $($scan.ExitCode)); no se ejecutara XMRig." }
    Check-Executable
    $record = @{completed=$true; sha256=$ExeHash; path=$Exe; updated=[DateTimeOffset]::UtcNow.ToUnixTimeSeconds()}
    [IO.File]::WriteAllText($ScanFile, ($record | ConvertTo-Json), $Utf8)
    $currentConsent = $null
    if (Test-Path -LiteralPath (Join-Path $Runtime 'xmrig-pua-consent.json')) {
        $currentConsent = Get-Content -LiteralPath (Join-Path $Runtime 'xmrig-pua-consent.json') -Raw | ConvertFrom-Json
    }
    $riskConsent = $null
    if (Test-Path -LiteralPath (Join-Path $Runtime 'xmrig-risk-consent.json')) {
        $riskConsent = Get-Content -LiteralPath (Join-Path $Runtime 'xmrig-risk-consent.json') -Raw | ConvertFrom-Json
    }
    if ($riskConsent -and $riskConsent.sha256 -ceq $ExeHash) {
        Write-Host 'Analisis completado. Los incidentes registrados siguen aceptados por tu decision para este SHA; no es un dictamen de falso positivo.'
    } elseif ($currentConsent -and $currentConsent.sha256 -ceq $ExeHash) {
        Write-Host 'Analisis completado sin nuevas detecciones pendientes. La PUA Caypnamer sigue aceptada por tu decision; no es un dictamen de inocuidad.'
    } else {
        Write-Host 'Analisis completado sin detecciones registradas para esta carpeta. No constituye una garantia de inocuidad.'
    }
}
function Ready-Executable {
    Assert-StandardUser
    Check-Executable
    Assert-GpuLibraries
    Assert-DefenderReady
    Check-Scan
}
function Load-Build([string]$Directory) {
    $build = Get-Content -LiteralPath (Join-Path $Directory 'build.json') -Raw | ConvertFrom-Json
    if ($build.engine -ne $Engine -or $build.version -ne $Version -or
        $build.commit -ne $SourceCommit -or $build.target -ne 'windows-x86_64' -or
        $build.security_policy -ne $SecurityPolicy -or $build.recipe_sha256 -cnotmatch '^[a-f0-9]{64}$' -or
        $build.sha256 -cnotmatch '^[a-f0-9]{64}$') { throw 'Compilacion anterior o inesperada. Recompila con miner-build.' }
    if (-not (Test-Path -LiteralPath $TrustFile)) { throw 'Falta el registro externo de compilacion. Ejecuta miner-build.' }
    $trusted = Get-Content -LiteralPath $TrustFile -Raw | ConvertFrom-Json
    $manifestHash = (Get-FileHash -LiteralPath (Join-Path $Directory 'build.json') -Algorithm SHA256).Hash.ToLowerInvariant()
    if ($trusted.sha256 -cne $build.sha256 -or $trusted.commit -cne $SourceCommit -or
        $trusted.security_policy -cne $SecurityPolicy -or $trusted.recipe_sha256 -cne $build.recipe_sha256 -or
        $trusted.manifest_sha256 -cne $manifestHash) {
        throw 'El ejecutable/manifiesto no coincide con el registro externo de compilacion.'
    }
    $script:ExeHash = $build.sha256
    return $build
}
function Get-DutyPercent($Config) {
    $present = if ($Config -is [System.Collections.IDictionary]) { $Config.Contains('gpu_duty_percent') } else { $null -ne $Config.PSObject.Properties['gpu_duty_percent'] }
    if (-not $present) { return 25 }
    $value = $Config.gpu_duty_percent
    if (($value -isnot [int] -and $value -isnot [long]) -or $value -lt 5 -or $value -gt 100) {
        throw 'gpu_duty_percent debe ser un entero entre 5 y 100; el control termico no puede desactivarse.'
    }
    return [int]$value
}
function Get-MiningProfile($Config) {
    return ('rx9070xt-duty{0}-timer{1}-halt80-resume60-search300-nodonate-v6' -f (Get-DutyPercent $Config), (Get-WaitMode $Config))
}
function Get-WaitMode($Config) {
    $present = if ($Config -is [System.Collections.IDictionary]) { $Config.Contains('gpu_wait_mode') } else { $null -ne $Config.PSObject.Properties['gpu_wait_mode'] }
    if (-not $present) { return 'precise' }
    if ($Config.gpu_wait_mode -cnotin @('precise','legacy')) { throw 'gpu_wait_mode debe ser precise o legacy.' }
    return $Config.gpu_wait_mode
}
function Miner-Config($Config, [int]$Device, [string]$Worker, [string]$Log) {
    return @{
        autosave=$false; background=$false; colors=$false; title=$false; watch=$false;
        'donate-level'=0.0; 'donate-over-proxy'=0; 'log-file'=$Log;
        'print-time'=10; 'health-print-time'=2; dmi=$false;
        cpu=@{enabled=$false; 'huge-pages'=$false}; cuda=@{enabled=$false};
        http=@{enabled=$false}; randomx=@{rdmsr=$false; wrmsr=$false};
        opencl=@{enabled=$true; platform='AMD'; loader=(Get-GpuLibraryPath 'OpenCL.dll'); cache=$true; adl=$true;
            kawpow=@(@{index=$Device; intensity=65536; worksize=128; threads=@(-1); 'gpu-duty-percent'=(Get-DutyPercent $Config); 'gpu-precise-wait'=((Get-WaitMode $Config) -eq 'precise')})};
        pools=@(@{algo='kawpow'; coin='ravencoin'; url=$Config.pool; user="$($Config.address).$Worker";
            pass='x'; tls=$true; sni=$true; enabled=$true; keepalive=$false; nicehash=$false});
        retries=5; 'retry-pause'=5; 'pause-on-battery'=$true
    }
}
function Read-OpenClDevices {
    if (-not ('PersonalMining.OpenClInventory' -as [type])) {
        Add-Type -Path (Join-Path $ProjectRoot 'opencl-devices.cs')
    }
    return @([PersonalMining.OpenClInventory]::ReadAmd())
}
function Show-OpenClDevices {
    $devices = @(Read-OpenClDevices)
    if (-not $devices.Count) { throw 'No hay GPU en la plataforma AMD seleccionada.' }
    Write-Host "Plataforma AMD que usara XMRig: $($devices[0].PlatformIndex) / $($devices[0].PlatformVersion)"
    Write-Host 'ID GPU | Memoria GiB | Nombre / placa'
    foreach ($device in $devices) {
        Write-Host ('{0,6} | {1,11:N2} | {2} / {3}' -f $device.Id, ($device.MemoryBytes / 1GB), $device.Name, $device.BoardName)
    }
    Write-Host 'Usa el ID GPU de la RX 9070 XT (16 GiB), no el indice de plataforma.'
}
function Assert-Validated($Config) {
    $path = Join-Path $Runtime 'xmrig-validation.json'
    if (-not (Test-Path -LiteralPath $path)) { throw 'Falta validar shares propias: python3 raven.py mine-test --gpu-id ID' }
    $v = Get-Content -LiteralPath $path -Raw | ConvertFrom-Json
    if ($v.verified -ne $true -or $v.engine -ne $Engine -or $v.sha256 -ne $ExeHash -or $v.security_policy -ne $SecurityPolicy -or
        $v.mining_profile -ne (Get-MiningProfile $Config) -or $v.gpu_id -ne $GpuId -or $v.address -ne $Config.address -or
        $v.worker -ne $Config.worker -or $v.pool -ne $Config.pool) {
        throw 'La validacion no corresponde a esta GPU, ejecutable o direccion. Repite mine-test.'
    }
}
function Read-Temperature([string]$Log, [int]$Device) {
    $latest = $null
    if (Test-Path -LiteralPath $Log) {
        foreach ($line in (Get-Content -LiteralPath $Log -Tail 120)) {
            $plain = [regex]::Replace($line, '\x1b\[[0-9;]*m', '')
            if ($plain -match 'gpu-health (\{.*\})$') {
                try { $sample = $Matches[1] | ConvertFrom-Json } catch { continue }
                if ($sample.v -eq 1 -and $sample.gpu -eq $Device) {
                    $latest = @{line=$plain; temperature=$sample.hotspot_c; edge_c=$sample.edge_c;
                        hotspot_c=$sample.hotspot_c; memory_c=$sample.memory_c; sensor_source=$sample.source;
                        power_w=$sample.power_w; fan_rpm=$sample.fan_rpm; pci=$sample.pci;
                        power_scope=$(if ($sample.PSObject.Properties['power_scope']) { $sample.power_scope } else { 'unavailable' });
                        power_source=$(if ($sample.PSObject.Properties['power_source']) { $sample.power_source } else { 'unavailable' });
                        polled_ms=$sample.polled_ms}
                }
            }
        }
    }
    return $latest
}
function Update-BoardEnergy($Energy, $Health) {
    # Integrate distinct monotonic driver polls only. Never bridge missing data,
    # long gaps, device changes, or ASIC-only readings as whole-card energy.
    if (-not $Health -or $Health.power_scope -ne 'board' -or $Health.power_source -ne 'adl-pmlog-board' -or
        $null -eq $Health.power_w -or $null -eq $Health.polled_ms) { $Energy.last = $null; return }
    [double]$watts = $Health.power_w
    [double]$stamp = $Health.polled_ms
    if ([double]::IsNaN($watts) -or [double]::IsInfinity($watts) -or $watts -lt 0 -or $watts -gt 2000 -or
        [double]::IsNaN($stamp) -or [double]::IsInfinity($stamp) -or $stamp -lt 0) { $Energy.last = $null; return }
    if ($null -ne $Energy.last) {
        [double]$seconds = ($stamp - $Energy.last) / 1000.0
        if ($seconds -eq 0) { return }
        if ($seconds -gt 0 -and $seconds -le 5 -and $Energy.pci -eq $Health.pci) {
            $Energy.wh += (($Energy.watts + $watts) / 2.0) * $seconds / 3600.0
            $Energy.seconds += $seconds
        }
    }
    $Energy.last = $stamp
    $Energy.watts = $watts
    $Energy.pci = $Health.pci
    $Energy.samples += 1
}
function Read-Timing([string]$Log, [int]$Device) {
    $latest = $null
    if (Test-Path -LiteralPath $Log) {
        foreach ($line in (Get-Content -LiteralPath $Log -Tail 120)) {
            $plain = [regex]::Replace($line, '\x1b\[[0-9;]*m', '')
            if ($plain -match 'gpu-timing (\{.*\})$') {
                try { $sample = $Matches[1] | ConvertFrom-Json } catch { continue }
                if ($sample.v -eq 1 -and $sample.gpu -eq $Device) {
                    $latest = $sample
                    $latest | Add-Member -NotePropertyName log_line -NotePropertyValue $plain -Force
                }
            }
        }
    }
    return $latest
}
function Read-Governor([string]$Log, [int]$Device) {
    $latest = $null
    if (Test-Path -LiteralPath $Log) {
        foreach ($line in (Get-Content -LiteralPath $Log -Tail 120)) {
            $plain = [regex]::Replace($line, '\x1b\[[0-9;]*m', '')
            if ($plain -match 'gpu-governor (\{.*\})$') {
                try { $sample = $Matches[1] | ConvertFrom-Json } catch { continue }
                if ($sample.v -eq 1 -and $sample.gpu -eq $Device) {
                    if ($sample.state -eq 'fault') { throw "Control GPU detenido: $($sample.reason). Revisa el log y la refrigeracion." }
                    $latest = $sample
                    $latest | Add-Member -NotePropertyName log_line -NotePropertyValue $plain -Force
                }
            }
        }
    }
    return $latest
}
# Thermal pauses belong to the native governor. This independent watchdog
# faults only if it fails to stop submissions, not when it is cooling normally.
function Assert-GpuTemperature($Health, $Governor, [double]$Now, $HotSince) {
    if (-not $Health -or ($Health.edge_c -lt 80 -and $Health.hotspot_c -lt 80 -and $Health.memory_c -lt 80)) { return $null }
    if ($Governor -and $Governor.state -eq 'cooling' -and $Governor.duty_percent -eq 0) { return $null }
    if ($null -eq $HotSince) { return $Now }
    if (($Now - $HotSince) -ge 3) { throw 'El control GPU no confirma la pausa termica a 80 C. Minero detenido.' }
    return $HotSince
}
function Update-TrialClock($Clock, [double]$Now, [bool]$Cooling, [string]$Phase = '') {
    # Do not use Math.Max(0, delta): Windows PowerShell selects its integer
    # overload and rounds each interval, accumulating seconds of clock drift.
    [double]$elapsed = $Now - [double]$Clock.last
    if ($elapsed -lt 0) { throw 'El reloj monotono retrocedio.' }
    if ($Clock.cooling) { $Clock.cooling_seconds += $elapsed }
    else {
        $Clock.active_seconds += $elapsed
        if ($Clock.phase -eq 'search') { $Clock.search_seconds += $elapsed }
        else { $Clock.preparation_seconds += $elapsed }
    }
    $Clock.last = $Now
    $Clock.cooling = $Cooling
    $Clock.phase = $Phase
}
function Read-MinerStats([string]$Log) {
    $stats = @{}
    if (-not (Test-Path -LiteralPath $Log)) { return $stats }
    foreach ($line in (Get-Content -LiteralPath $Log -Tail 120)) {
        $plain = [regex]::Replace($line, '\x1b\[[0-9;]*m', '')
        if ($plain -match 'miner\s+speed 10s/60s/15m ([0-9.]+|n/a) ([0-9.]+|n/a) ([0-9.]+|n/a) (MH/s|H/s)\b') {
            $factor = 1
            if ($Matches[4] -eq 'MH/s') { $factor = 1000000 }
            $stats.rate_line = $plain
            foreach ($item in @(@(1,'hashrate_10s_hs'), @(2,'hashrate_60s_hs'), @(3,'hashrate_15m_hs'))) {
                $value = $Matches[$item[0]]
                $stats[$item[1]] = $null
                $parsed = [decimal]0
                if ([decimal]::TryParse($value, [Globalization.NumberStyles]::AllowDecimalPoint,
                        [Globalization.CultureInfo]::InvariantCulture, [ref]$parsed) -and
                        $parsed -le ([decimal]::MaxValue / $factor)) {
                    $stats[$item[1]] = ($parsed * $factor).ToString([Globalization.CultureInfo]::InvariantCulture)
                }
            }
        }
        if ($plain -match 'opencl\s+(?:accepted|rejected)\s+\((\d+)/(\d+)\)') {
            $stats.shares_line = $plain
            $stats.accepted = [long]$Matches[1]
            $stats.rejected = [long]$Matches[2]
        }
    }
    return $stats
}
function Owned-Process($State) {
    if (-not $State -or -not $State.miner_pid -or -not $State.start_ticks) { return $null }
    $p = Get-Process -Id $State.miner_pid -ErrorAction SilentlyContinue
    if ($p -and $p.Path -eq $Exe -and $p.StartTime.ToUniversalTime().Ticks.ToString() -eq $State.start_ticks) {
        return $p
    }
    return $null
}
function Check-Executable {
    Assert-MinerAllowed
    Assert-InstallDirectory
    [void](Load-Build $InstallRoot)
    if (-not (Test-Path -LiteralPath $Exe)) { throw 'Ejecuta primero: python3 raven.py miner-install' }
    if ((Get-FileHash -LiteralPath $Exe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExeHash) {
        throw 'El ejecutable no coincide con el SHA-256 verificado de XMRig 6.26.0.'
    }
}
function Read-Config {
    $c = Get-Content -LiteralPath (Join-Path $Runtime 'mining.json') -Raw | ConvertFrom-Json
    if ($c.network -ne 'ravencoin-mainnet' -or $c.algorithm -ne 'kawpow' -or
        $c.pool -ne 'stratum.ravenminer.com:13838' -or $c.mode -ne 'PPLNS' -or
        $c.address -cnotmatch '^R[1-9A-HJ-NP-Za-km-z]{25,34}$' -or
        $c.worker -cnotmatch '^[A-Za-z0-9_-]{1,32}$') { throw 'Configuracion invalida: ejecuta configure desde WSL.' }
    [void](Get-DutyPercent $c)
    return $c
}
function Quote-Arg([string]$Value) {
    # Windows CommandLineToArgvW quoting. Values ending in slash need doubled slashes.
    return '"' + [regex]::Replace([regex]::Replace($Value, '(\\*)"', '$1$1\"'), '(\\+)$', '$1$1') + '"'
}

# Prevent two launchers from racing, also across two WSL terminals.
$hash = [System.Security.Cryptography.SHA256]::Create()
$key = ([BitConverter]::ToString($hash.ComputeHash([Text.Encoding]::UTF8.GetBytes($Runtime.ToLowerInvariant())))).Replace('-','')
$mutex = New-Object Threading.Mutex($false, "Local\RavencoinPersonal-$key")
$held = $false
try {
    if ($Action -ne 'Run') {
        try { $held = $mutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $held = $true }
        if (-not $held) { throw 'Otra operacion del minero esta en curso.' }
    }
    switch ($Action) {
        'Diagnostics' { Write-SecurityDiagnostic }
        'Review' { Review-RemovedDetection }
        'AcceptPua' { Accept-Pua }
        'AcceptRisk' { Accept-OwnerRisk }
        'Install' {
            Assert-StandardUser
            Assert-MinerAllowed
            if (Owned-Process (Read-State)) { throw 'Deten primero la mineria con mine-stop.' }
            Assert-DefenderReady -AllowMissingInstalled -PrepareUpgrade
            $built = $BuildRoot
            [void](Load-Build $built)
            $sourceExe = Join-Path $built 'xmrig.exe'
            if ((Get-FileHash -LiteralPath $sourceExe -Algorithm SHA256).Hash.ToLowerInvariant() -ne $ExeHash) {
                throw 'El ejecutable compilado no coincide con su manifiesto.'
            }
            [void][IO.Directory]::CreateDirectory($InstallRoot)
            Assert-InstallDirectory
            try { Copy-Item -LiteralPath $sourceExe -Destination $Exe -Force }
            catch {
                $copyError = $_.Exception.Message
                Assert-DefenderReady
                throw "No se pudo copiar el ejecutable: $copyError"
            }
            Copy-Item -LiteralPath (Join-Path $built 'build.json') -Destination (Join-Path $InstallRoot 'build.json') -Force
            foreach ($name in @('LICENSE-xmrig.txt','LICENSE-libuv.txt','LICENSE-openssl.txt','sources.json')) {
                Copy-Item -LiteralPath (Join-Path $built $name) -Destination (Join-Path $InstallRoot $name) -Force
            }
            Scan-Executable
            Write-Host "XMRig $Version compilado localmente e instalado. Falta probar KAWPOW en la Radeon."
        }
        'Scan' { Scan-Executable }
        'Devices' {
            Ready-Executable
            Show-OpenClDevices
        }
        'Start' {
            Ready-Executable
            $config = Read-Config
            Assert-Validated $config
            $state = Read-State
            if (Owned-Process $state) { Write-Host "Ya hay un minero activo (PID $($state.miner_pid))."; break }
            if ($state -and $state.running -and (([DateTimeOffset]::UtcNow.ToUnixTimeSeconds() - $state.updated) -lt 30)) {
                throw 'El supervisor aun esta activo; usa mine-stop antes de reiniciar.'
            }
            Remove-Item -LiteralPath $StopFile -ErrorAction SilentlyContinue
            # Archive previous session logs so old accepted shares cannot look current.
            foreach ($name in @('miner.log','stdout.log','stderr.log','runner-error.log')) {
                $p = Join-Path $Runtime $name
                if (Test-Path -LiteralPath $p) { Move-Item -LiteralPath $p -Destination "$p.previous" -Force }
            }
            $started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
            $argv = @('-NoProfile','-NonInteractive','-ExecutionPolicy','Bypass','-File',$PSCommandPath,'-Action','Run','-GpuId',"$GpuId",'-RuntimeRoot',$Runtime)
            $runner = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -ArgumentList (($argv | ForEach-Object { Quote-Arg $_ }) -join ' ') -WindowStyle Hidden -PassThru -WorkingDirectory $InstallRoot
            for ($i=0; $i -lt 20; $i++) {
                Start-Sleep -Milliseconds 500
                $state = Read-State
                if ($state -and $state.updated -ge $started -and $state.runner_pid -eq $runner.Id) {
                    if (-not $state.running) { throw "El minero fallo al iniciar: $($state.error). Revisa python3 raven.py logs" }
                    Write-Host "XMRig iniciado en segundo plano: GPU $GpuId / KAWPOW / RavenMiner PPLNS."
                    Write-Host 'El inicio del proceso no confirma shares: revisa monitor y logs.'
                    return
                }
            }
            throw 'Sin confirmacion de inicio. Usa miner-status y revisa .runtime/runner-error.log antes de reintentar.'
        }
        'Run' {
            $miner = $null
            $state = @{engine=$Engine; version=$Version; running=$false; updated=0; runner_pid=$PID; error=$null}
            # A distinct mutex is held for the full lifetime of the supervisor.
            $runMutex = New-Object Threading.Mutex($false, "Local\RavencoinPersonalRun-$key")
            $runHeld = $false
            try {
                try { $runHeld = $runMutex.WaitOne(0) } catch [Threading.AbandonedMutexException] { $runHeld = $true }
                if (-not $runHeld) { throw 'Ya existe otro supervisor de mineria.' }
                Ready-Executable
                $config = Read-Config
                if ($TrialSeconds -eq 0) { Assert-Validated $config }
                Remove-Item -LiteralPath $StopFile -ErrorAction SilentlyContinue
                $started = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                $worker = $config.worker
                if ($TrialSeconds -gt 0) {
                    Remove-Item -LiteralPath (Join-Path $Runtime 'xmrig-probe.json') -ErrorAction SilentlyContinue
                    Remove-Item -LiteralPath (Join-Path $Runtime 'xmrig-validation.json') -ErrorAction SilentlyContinue
                    $worker = 'probe-' + [guid]::NewGuid().ToString('N').Substring(0,20)
                    Write-Host "Prueba KAWPOW de 5 minutos de busqueda, despues de preparar el DAG, en RavenMiner, GPU $GpuId, worker temporal $worker."
                }
                $log = Join-Path $Runtime 'miner.log'
                if (Test-Path -LiteralPath $log) { Move-Item -LiteralPath $log -Destination "$log.previous" -Force }
                $configFile = Join-Path $Runtime 'xmrig-config.json'
                $settings = Miner-Config $config $GpuId $worker $log
                [IO.File]::WriteAllText($configFile, ($settings | ConvertTo-Json -Depth 8), $Utf8)
                $argv = @('--config',$configFile)
                $healthSeen = $started
                $healthLine = ''
                $rateLine = ''
                $governorLine = ''
                $timingLine = ''
                $sharesLine = ''
                $lastProgress = $started - 5
                $trialCompleted = $false
                $watch = [Diagnostics.Stopwatch]::StartNew()
                $trialClock = @{last=0.0; active_seconds=0.0; cooling_seconds=0.0; search_seconds=0.0; preparation_seconds=0.0; cooling=$false; phase='starting'}
                $searchStarted = $null
                $hotSince = $null
                $energy = @{last=$null; watts=0.0; pci=''; wh=0.0; seconds=0.0; samples=0}
                Write-Host 'Pausa automatica a 80 C; reanuda cuando GPU, hotspot y memoria disponible bajen a 60 C. Ctrl+C detiene la sesion.'
                Write-Host ('Carga objetivo: {0}%. El control termico puede reducir la carga efectiva.' -f (Get-DutyPercent $config))
                # No API listener. Telemetry is read from the local log and public pool API.
                if ($CancelFile -and (Test-Path -LiteralPath $CancelFile)) { return }
                $miner = Start-Process -FilePath $Exe -ArgumentList (($argv | ForEach-Object { Quote-Arg $_ }) -join ' ') -WorkingDirectory (Split-Path $Exe) -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $Runtime 'stdout.log') -RedirectStandardError (Join-Path $Runtime 'stderr.log')
                $state = @{ engine=$Engine; version=$Version; running=$true; miner_pid=$miner.Id; runner_pid=$PID; gpu_id=$GpuId;
                    start_ticks=$miner.StartTime.ToUniversalTime().Ticks.ToString();
                    address=$config.address; worker=$worker; started=$started; trial=($TrialSeconds -gt 0); updated=0; error=$null;
                    target_duty_percent=(Get-DutyPercent $config); mining_profile=(Get-MiningProfile $config) }
                while (-not $miner.HasExited -and -not (Test-Path -LiteralPath $StopFile) -and -not ($CancelFile -and (Test-Path -LiteralPath $CancelFile))) {
                    $state.updated = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    $health = Read-Temperature $log $GpuId
                    if ($health -and $health.line -ne $healthLine -and $health.temperature -gt 0) {
                        $healthLine = $health.line
                        $healthSeen = $state.updated
                        $state.temperature_updated = $state.updated
                        foreach ($field in @('temperature','edge_c','hotspot_c','memory_c','sensor_source','pci','power_w','power_scope','power_source','fan_rpm')) {
                            $state[$field] = $health[$field]
                        }
                        Update-BoardEnergy $energy $health
                        $state.energy_kwh = if ($energy.seconds -gt 0) { $energy.wh / 1000.0 } else { $null }
                        $state.energy_measured_seconds = $energy.seconds
                        $state.energy_samples = $energy.samples
                        $state.energy_scope = 'board'
                        $state.power_average_w = if ($energy.seconds -gt 0) { $energy.wh * 3600.0 / $energy.seconds } else { $null }
                    }
                    $governor = Read-Governor $log $GpuId
                    if ($governor -and $governor.log_line -ne $governorLine) {
                        $governorLine = $governor.log_line
                        $state.governor_updated = $state.updated
                        $state.governor_state = $governor.state
                        $state.governor_reason = $governor.reason
                        $state.duty_percent = $governor.duty_percent
                        $state.governor_phase = $governor.phase
                        $state.dag_done = $governor.dag_done
                        $state.dag_total = $governor.dag_total
                    }
                    $timing = Read-Timing $log $GpuId
                    if ($timing -and $timing.log_line -ne $timingLine) {
                        $timingLine = $timing.log_line
                        $state.timing_updated = $state.updated
                        $state.timing = @{}
                        foreach ($field in @('phase','timer','window_us','batches','batch_us','max_batch_us','sleep_calls','sleep_requested_us','sleep_actual_us','max_sleep_us')) {
                            $state.timing[$field] = $timing.$field
                        }
                    }
                    $hotSince = Assert-GpuTemperature $health $governor $watch.Elapsed.TotalSeconds $hotSince
                    $phase = if ($state.governor_updated -and ($state.updated - $state.governor_updated) -le 5) { $state.governor_phase } else { '' }
                    if ($phase -eq 'search' -and $null -eq $searchStarted) { $searchStarted = $state.updated }
                    Update-TrialClock $trialClock $watch.Elapsed.TotalSeconds ($state.governor_state -eq 'cooling') $phase
                    $state.active_seconds = $trialClock.active_seconds
                    $state.cooling_seconds = $trialClock.cooling_seconds
                    $state.search_seconds = $trialClock.search_seconds
                    $state.preparation_seconds = $trialClock.preparation_seconds
                    $state.observed_seconds = $trialClock.last
                    $stats = Read-MinerStats $log
                    if ($stats.rate_line -and $stats.rate_line -ne $rateLine) {
                        $rateLine = $stats.rate_line
                        $state.hashrate_updated = $state.updated
                        foreach ($field in @('hashrate_10s_hs','hashrate_60s_hs','hashrate_15m_hs')) { $state[$field] = $stats[$field] }
                    }
                    if ($stats.shares_line -and $stats.shares_line -ne $sharesLine) {
                        $sharesLine = $stats.shares_line
                        $state.shares_updated = $state.updated
                        $state.accepted = $stats.accepted
                        $state.rejected = $stats.rejected
                    }
                    Write-State $state
                    if ($state.governor_updated -and ($state.updated - $state.governor_updated) -gt 10) { throw 'Control GPU sin latido reciente. Minero detenido.' }
                    if (($state.updated - $healthSeen) -gt 30) { throw 'Sin lectura reciente de temperatura ADL. Se detiene la prueba/mineria; revisa el controlador AMD.' }
                    if ($TrialSeconds -gt 0 -and $trialClock.search_seconds -ge $TrialSeconds) {
                        $trialCompleted = $true
                        break
                    }
                    if ($TrialSeconds -gt 0 -and $trialClock.preparation_seconds -ge 900) { throw 'La preparacion no termino en 15 minutos sin pausa termica. Revisa el progreso DAG; no se valida la prueba.' }
                    if (($state.updated - $lastProgress) -ge 5) {
                        $lastProgress = $state.updated
                        $label = if ($state.governor_state -eq 'cooling') { 'ENFRIANDO: esperando <=60 C' } elseif ($phase -eq 'dag') { 'PREPARANDO DAG' } elseif ($phase -eq 'search') { 'BUSCANDO SOLUCIONES' } else { 'ESPERANDO TELEMETRIA' }
                        Write-Host ("{0} | GPU {1} C | hotspot {2} C | memoria {3} C | activos {4:N0} s | enfriando {5:N0} s | Ctrl+C: detener" -f $label, $state.edge_c, $state.hotspot_c, $state.memory_c, $trialClock.active_seconds, $trialClock.cooling_seconds)
                        if ($TrialSeconds -gt 0) { Write-Host ("Prueba: {0:N1}/{1} s de busqueda; preparacion {2:N1} s (no cuenta)." -f $trialClock.search_seconds, $TrialSeconds, $trialClock.preparation_seconds) }
                        if ($phase -eq 'dag' -and $state.dag_total -gt 0) { Write-Host ("DAG: {0:N1}% de elementos preparados." -f (100.0 * $state.dag_done / $state.dag_total)) }
                        if (Test-Path -LiteralPath $log) { Get-Content -LiteralPath $log -Tail 2 | Write-Host }
                    }
                    Start-Sleep -Seconds 1
                    $miner.Refresh()
                }
                if ($miner.HasExited) { $state.error = "XMRig termino con codigo $($miner.ExitCode). Consulta los logs." }
            } catch {
                $state.error = $_.Exception.Message
                [System.IO.File]::WriteAllText((Join-Path $Runtime 'runner-error.log'), $state.error, $Utf8)
            } finally {
                if ($miner -and -not $miner.HasExited) { $miner.Kill(); $miner.WaitForExit() }
                if ($runHeld) {
                    $state.running = $false
                    $state.updated = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds()
                    Write-State $state
                    if ($TrialSeconds -gt 0 -and $config) {
                        $probe = @{engine=$Engine; sha256=$ExeHash; security_policy=$SecurityPolicy; mining_profile=(Get-MiningProfile $config); gpu_id=$GpuId; address=$config.address;
                            worker=$config.worker; pool=$config.pool; probe_worker=$worker; started=$started;
                            active_seconds=$state.active_seconds; cooling_seconds=$state.cooling_seconds;
                            search_seconds=$state.search_seconds; preparation_seconds=$state.preparation_seconds;
                            observed_seconds=$state.observed_seconds; search_started=$searchStarted;
                            ended=$state.updated; completed=($trialCompleted -eq $true); error=$state.error}
                        [IO.File]::WriteAllText((Join-Path $Runtime 'xmrig-probe.json'), ($probe | ConvertTo-Json), $Utf8)
                    }
                    $runMutex.ReleaseMutex()
                }
                $runMutex.Dispose()
            }
            if ($state.error) { throw $state.error }
        }
        'Stop' {
            [System.IO.File]::WriteAllText($StopFile, 'stop', $Utf8)
            $state = Read-State
            $p = Owned-Process $state
            if ($p) {
                # Exact path and process creation time were verified; never kill by name.
                Stop-Process -Id $p.Id
                Write-Host 'Minero detenido.'
            } else { Write-Host 'No hay un proceso de este minero activo.' }
            Start-Sleep -Seconds 6
        }
        'Status' {
            $state = Read-State
            if (-not $state) { Write-Host 'Minero aun no iniciado.'; break }
            $actual = [bool](Owned-Process $state)
            Write-Host "Proceso Windows activo: $actual"
            $state | ConvertTo-Json -Depth 6
        }
    }
} catch {
    Write-Error $_.Exception.Message -ErrorAction Continue
    exit 1
} finally {
    if ($held) { $mutex.ReleaseMutex() }
    $mutex.Dispose()
}
