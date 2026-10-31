# Prepare a clean Windows evaluation VM. This script NEVER stages or runs a miner.
[CmdletBinding()]
param(
    [ValidateSet('prepare', 'status', 'screenshot', 'start', 'stop', 'setup-control', 'guest-status', 'guest-admin-status', 'guest-control-proof', 'pause-work')]
    [string]$Action = 'prepare',
    [ValidateRange(1, 20)][int]$ImageIndex = 1,
    [ValidatePattern('^[a-f0-9]{32}$')][string]$ProofId
)
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$VBox = Join-Path $env:ProgramFiles 'Oracle\VirtualBox\VBoxManage.exe'
$Root = Join-Path $env:LOCALAPPDATA 'XmrigIsolatedAudit\VirtualBox'
$StatePath = Join-Path $Root 'state.json'
$ProjectRoot = Split-Path -Parent $PSScriptRoot
$Evidence = Join-Path $ProjectRoot '.runtime\vbox-audit'
# Link resolved from Microsoft's Evaluation Center Spanish x64 download, 2026-10-31.
$IsoUrl = 'https://software-static.download.prss.microsoft.com/dbazure/26300.9457.260913-1737.26h2_ge_release_svc_refresh_CLIENTENTERPRISEEVAL_OEMRET_x64FRE_es-es.iso'
$Iso = Join-Path $Root 'Windows11-Enterprise-Eval-es-es-x64.iso'
$VmName = 'Xmrig-Audit-Win11'

function Invoke-VBox([string[]]$Arguments) {
    Assert-WorkAllowed
    & $script:VBox @Arguments
    if ($LASTEXITCODE -ne 0) { throw "VBoxManage fallo ($LASTEXITCODE): $($Arguments[0]). Se conserva el estado para diagnostico." }
}
function Save-State {
    $script:State | ConvertTo-Json -Depth 5 | Set-Content -LiteralPath $script:StatePath -Encoding UTF8
}
function Set-PrivateDirectoryAcl([string]$Directory) {
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    # icacls requires '*' before a numeric SID. Grant access before removing
    # inherited entries so an error cannot leave the owner without an allow ACE.
    & icacls.exe $Directory /grant:r "*${sid}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' '*S-1-5-32-544:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudieron asignar permisos al usuario de Windows.' }
    & icacls.exe $Directory /inheritance:r | Out-Null
    if ($LASTEXITCODE -ne 0) { throw 'No se pudo restringir la herencia del directorio de la VM.' }
}
function Read-ManagedState {
    if (-not (Test-Path -LiteralPath $script:StatePath)) { throw 'Primero ejecuta -Action prepare.' }
    $s = Get-Content -LiteralPath $script:StatePath -Raw | ConvertFrom-Json
    $parsed = [guid]::Empty
    if ($s.name -ne $script:VmName -or -not [guid]::TryParse([string]$s.uuid, [ref]$parsed)) {
        throw 'Estado local invalido. No se opera sobre una VM desconocida.'
    }
    return $s
}
function Get-ManagedInfo {
    $lines = @(Invoke-VBox @('showvminfo', [string]$script:State.uuid, '--machinereadable'))
    $values = @{}
    foreach ($line in $lines) {
        if ([string]$line -match '^([^=]+)="(.*)"$') { $values[$Matches[1]] = $Matches[2] }
    }
    if ($values['UUID'] -ne [string]$script:State.uuid -or $values['name'] -ne $script:VmName) {
        throw 'La identidad de VirtualBox no coincide con el registro local.'
    }
    return $values
}
function Assert-Isolated($Info) {
    foreach ($i in 1..8) {
        if ($Info["nic$i"] -ne 'none') { throw "Adaptador $i habilitado o sin verificar; no se inicia la VM." }
    }
    if ($Info['clipboard'] -ne 'disabled' -or $Info['draganddrop'] -ne 'disabled' -or
        $Info['accelerate3d'] -ne 'off') { throw 'Integracion o aceleracion 3D no deshabilitada; no se inicia.' }
    foreach ($key in $Info.Keys) {
        if ($key -like 'SharedFolder*') { throw 'Hay carpetas compartidas; no se inicia la VM.' }
    }
}
function Assert-WorkAllowed {
    if ($script:Action -in @('pause-work', 'stop', 'status', 'screenshot')) { return }
    if (Test-Path -LiteralPath (Join-Path $script:Evidence 'stop-request.json')) {
        throw 'Trabajo detenido por Telegram. No se inicia ninguna accion; espera reanudacion explicita del usuario.'
    }
}
function Suspend-AuditWork {
    $info = Get-ManagedInfo
    if ($info['VMState'] -eq 'running') {
        Invoke-VBox @('controlvm', [string]$script:State.uuid, 'pause')
        $info = Get-ManagedInfo
    }
    # Busy states such as livesnapshotting are retried by the bot. No poweroff/kill.
    [ordered]@{ name=$script:State.name; uuid=$script:State.uuid; state=$info['VMState']
        confirmed=($info['VMState'] -in @('paused', 'poweroff', 'saved'))
        checked_utc=[DateTime]::UtcNow.ToString('o') } | ConvertTo-Json -Compress | Write-Output
}
function Export-Status {
    $info = Get-ManagedInfo
    New-Item -ItemType Directory -Path $script:Evidence -Force | Out-Null
    $summary = [ordered]@{
        name=$script:State.name; uuid=$script:State.uuid; state=$info['VMState']; stage=$script:State.stage
        checked_utc=[DateTime]::UtcNow.ToString('o'); miner_staged=$false
        note='VMState=running solo indica VM encendida; no confirma instalacion de Windows ni auditoria.'
    }
    $summary | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Evidence 'status.json') -Encoding UTF8
    $summary | ConvertTo-Json | Write-Host
    return $info
}
function Stop-GuestForSnapshot {
    $info = Get-ManagedInfo
    Assert-Isolated $info
    if ($info['VMState'] -eq 'poweroff') { return }
    if ($info['VMState'] -ne 'running') { throw 'La VM debe estar encendida o apagada, no pausada ni guardada.' }
    Invoke-VBox @('controlvm', [string]$script:State.uuid, 'acpipowerbutton')
    $deadline = [DateTime]::UtcNow.AddSeconds(120)
    while ([DateTime]::UtcNow -lt $deadline) {
        Start-Sleep -Seconds 5
        $info = Get-ManagedInfo
        if ($info['VMState'] -eq 'poweroff') { return }
        if ($info['VMState'] -ne 'running') { throw 'La VM cambio a un estado inesperado. No se fuerza su apagado.' }
        Write-Host 'Esperando apagado ordenado de Windows...'
    }
    throw 'Windows no se apago en 120 segundos. Apagalo desde Inicio dentro de la VM y repite setup-control.'
}
function Initialize-GuestControl {
    $additions = Join-Path (Split-Path -Parent $script:VBox) 'VBoxGuestAdditions.iso'
    if (-not (Test-Path -LiteralPath $additions)) { throw 'No se encuentra la ISO de Guest Additions instalada con VirtualBox.' }
    $baselinePath = Join-Path $script:Root 'clean-baseline.json'
    $baseline = $null
    if (Test-Path -LiteralPath $baselinePath) {
        $baseline = Get-Content -LiteralPath $baselinePath -Raw | ConvertFrom-Json
        $snapshotId = [guid]::Empty
        if ($baseline.vm_uuid -ne $script:State.uuid -or
            -not [guid]::TryParse([string]$baseline.snapshot_uuid, [ref]$snapshotId)) {
            throw 'El registro de la instantanea no corresponde a esta VM.'
        }
        $snapshots = (Invoke-VBox @('snapshot', [string]$script:State.uuid, 'list', '--machinereadable') | Out-String)
        if ($snapshots -notmatch [regex]::Escape([string]$baseline.snapshot_uuid)) { throw 'No se encuentra la instantanea registrada. No se sustituye por otra.' }
    }
    Stop-GuestForSnapshot
    if ($null -eq $baseline) {
        $name = 'windows-clean-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
        Invoke-VBox @('snapshot', [string]$script:State.uuid, 'take', $name, '--description',
            'Windows desktop confirmed by owner; offline baseline before miner audit. Guest Additions may already be installed.')
        $snapInfo = Get-ManagedInfo
        $snapshotId = [guid]::Empty
        if (-not [guid]::TryParse([string]$snapInfo['CurrentSnapshotUUID'], [ref]$snapshotId)) {
            throw 'Instantanea solicitada, pero no se pudo verificar su UUID. No se cambia el medio de instalacion.'
        }
        $baseline = [ordered]@{ vm_uuid=$script:State.uuid; snapshot_uuid=$snapshotId.ToString(); name=$name
            created_utc=[DateTime]::UtcNow.ToString('o'); desktop_confirmed_by='user'; miner_staged=$false }
        $baseline | ConvertTo-Json | Set-Content -LiteralPath $baselinePath -Encoding UTF8
    }
    $offInfo = Get-ManagedInfo
    Assert-Isolated $offInfo
    if ($offInfo['VMState'] -ne 'poweroff') { throw 'La VM ya no esta apagada. No se cambia el DVD.' }
    # Replace the existing unattended DVD only after preserving it in the baseline.
    Invoke-VBox @('storageattach', [string]$script:State.uuid, '--storagectl', 'SATA', '--port', '1', '--device', '0',
        '--type', 'dvddrive', '--medium', $additions)
    Invoke-VBox @('modifyvm', [string]$script:State.uuid, '--boot1', 'disk', '--boot2', 'dvd')
    $verified = Get-ManagedInfo
    Assert-Isolated $verified
    New-Item -ItemType Directory -Path $script:Evidence -Force | Out-Null
    $baseline | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Evidence 'clean-baseline.json') -Encoding UTF8
    Invoke-VBox @('startvm', [string]$script:State.uuid, '--type', 'headless')
    Write-Host "Instantanea conservada: $($baseline.name)"
    Write-Host 'Guest Additions montadas en el DVD de la VM. Si aun no estan instaladas, abre VBoxWindowsAdditions.exe como administrador y reinicia el invitado.'
    Write-Host 'Despues ejecuta -Action guest-status para comprobar el canal y los privilegios efectivos. No se inicio el minero.'
}
function Get-GuestStatusCommand {
    # A fixed read-only probe, not a user-supplied command or remote shell.
    $code = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$identity = [Security.Principal.WindowsIdentity]::GetCurrent()
$principal = New-Object Security.Principal.WindowsPrincipal($identity)
$os = Get-CimInstance Win32_OperatingSystem
$service = Get-Service VBoxService -ErrorAction Stop
$adapters = @(Get-NetAdapter -ErrorAction Stop | Where-Object Status -eq 'Up')
$routes = @(Get-NetRoute -ErrorAction Stop | Where-Object DestinationPrefix -in @('0.0.0.0/0','::/0'))
[ordered]@{
    user=$identity.Name
    administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    windows=$os.Caption; build=$os.BuildNumber; guest_service=[string]$service.Status
    active_network_adapters=$adapters.Count; default_routes=$routes.Count
    checked_utc=[DateTime]::UtcNow.ToString('o'); miner_executed=$false
} | ConvertTo-Json -Compress
'@
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
}
function Get-GuestControlProofCommand([string]$Nonce) {
    if ($Nonce -notmatch '^[a-f0-9]{32}$') { throw 'Identificador de prueba invalido.' }
    $probe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-GuestStatusCommand)))
    $code = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$report = & {
__STATUS_PROBE__
} | ConvertFrom-Json
if (-not $report.administrator) { throw 'La prueba requiere un proceso elevado.' }
if ($report.active_network_adapters -ne 0 -or $report.default_routes -ne 0) { throw 'La VM informa red activa; no se modifica el registro.' }
$nonce = '__NONCE__'
$key = 'HKLM:\SOFTWARE\XmrigAuditControlProof-' + $nonce
if (Test-Path -LiteralPath $key) { throw 'Ya existe la marca de prueba; no se sobrescribe.' }
$created = $false
$verified = $false
try {
    New-Item -Path $key -ErrorAction Stop | Out-Null
    $created = $true
    New-ItemProperty -LiteralPath $key -Name 'ProofNonce' -Value $nonce -PropertyType String -ErrorAction Stop | Out-Null
    $verified = (Get-ItemPropertyValue -LiteralPath $key -Name 'ProofNonce') -eq $nonce
    if (-not $verified) { throw 'La marca administrativa no coincide.' }
} finally {
    if ($created) { Remove-Item -LiteralPath $key -Recurse -Force -ErrorAction Stop }
}
$removed = -not (Test-Path -LiteralPath $key)
if (-not $removed) { throw 'No se pudo retirar la marca temporal.' }
$report | Add-Member -NotePropertyName proof_id -NotePropertyValue $nonce
$report | Add-Member -NotePropertyName action -NotePropertyValue 'create-read-delete-temporary-HKLM-marker'
$report | Add-Member -NotePropertyName registry_value_verified -NotePropertyValue $verified
$report | Add-Member -NotePropertyName registry_marker_removed -NotePropertyValue $removed
$report | ConvertTo-Json -Compress
'@
    $code = $code.Replace('__STATUS_PROBE__', $probe).Replace('__NONCE__', $Nonce)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
}
function Get-GuestAdminStatusCommand([string]$ControlProofId) {
    # The guest requests normal UAC consent for this one diagnostic or marker proof.
    # No service, scheduled task, UAC policy or permanent elevated channel is installed.
    $code = @'
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'
$probe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String('__PROBE__'))
$resultFile = Join-Path $env:TEMP ('xmrig-admin-probe-' + [guid]::NewGuid().ToString('N') + '.json')
$quotedResult = "'" + $resultFile.Replace("'", "''") + "'"
$elevatedCode = '$ProgressPreference = "SilentlyContinue"' + "`n" +
    '$result = & {' + "`n" + $probe + "`n}" + "`n" +
    '$result | Set-Content -Encoding UTF8 -LiteralPath ' + $quotedResult
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($elevatedCode))
try {
    $child = Start-Process -FilePath (Join-Path $PSHOME 'powershell.exe') -Verb RunAs -PassThru `
        -ArgumentList @('-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded)
    if (-not $child.WaitForExit(300000)) { throw 'La consulta elevada no termino. Revisa la ventana del invitado antes de repetir.' }
    if (-not (Test-Path -LiteralPath $resultFile)) { throw 'No hay resultado elevado. Revisa o acepta el aviso UAC dentro de la VM.' }
    $report = Get-Content -LiteralPath $resultFile -Raw | ConvertFrom-Json
    if (-not $report.administrator) { throw 'El proceso solicitado no obtuvo privilegios administrativos.' }
    $report | Add-Member -NotePropertyName elevation_method -NotePropertyValue 'interactive-uac-one-process'
    $report | ConvertTo-Json -Compress
} finally {
    if (Test-Path -LiteralPath $resultFile) { Remove-Item -LiteralPath $resultFile -Force }
}
'@
    $inner = Get-GuestStatusCommand
    if ($ControlProofId) { $inner = Get-GuestControlProofCommand $ControlProofId }
    $code = $code.Replace('__PROBE__', $inner)
    return [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($code))
}
function Export-GuestStatus([switch]$Elevated, [string]$ControlProofId) {
    $info = Get-ManagedInfo
    Assert-Isolated $info
    if ($info['VMState'] -ne 'running') { throw 'La VM debe estar encendida y Guest Additions instaladas.' }
    $passwordFile = Join-Path $script:Root 'guest-password.txt'
    if (-not (Test-Path -LiteralPath $passwordFile)) { throw 'No se encuentra la clave temporal de audituser.' }
    $encoded = Get-GuestStatusCommand
    $timeout = '180000'
    $filename = 'guest-status.json'
    if ($Elevated) {
        $encoded = Get-GuestAdminStatusCommand $ControlProofId
        $timeout = '480000'
        $filename = 'guest-admin-status.json'
        if ($ControlProofId) {
            $filename = 'control-proof-' + $ControlProofId + '.json'
            Write-Host 'Acepta UAC dentro de la VM: se creara, leera y eliminara una marca temporal HKLM para probar control administrativo.'
        } else {
            Write-Host 'Abre la ventana de la VM y acepta el aviso UAC de PowerShell. Solo se solicita una consulta elevada de estado.'
        }
    }
    $output = @(Invoke-VBox @('guestcontrol', [string]$script:State.uuid, 'run', '--exe',
        'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe', '--username', 'audituser',
        '--passwordfile', $passwordFile, '--timeout', $timeout, '--wait-stdout', '--wait-stderr', '--',
        '-NoProfile', '-NonInteractive', '-EncodedCommand', $encoded))
    $report = ($output -join "`n") | ConvertFrom-Json
    if ($ControlProofId -and ($report.proof_id -ne $ControlProofId -or -not $report.administrator -or
        -not $report.registry_value_verified -or -not $report.registry_marker_removed)) { throw 'Resultado de control administrativo incompleto o de otra prueba.' }
    New-Item -ItemType Directory -Path $script:Evidence -Force | Out-Null
    $report | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $script:Evidence $filename) -Encoding UTF8
    $report | ConvertTo-Json | Write-Host
    if (-not $report.administrator) { Write-Warning 'El canal responde sin elevacion efectiva. No se puede iniciar aun el observador administrativo.' }
    if ($report.active_network_adapters -ne 0 -or $report.default_routes -ne 0) { throw 'El invitado informa red activa; no continuar con la auditoria.' }
}

Assert-WorkAllowed
if (-not (Test-Path -LiteralPath $VBox)) { throw 'No se encuentra VBoxManage.exe en Program Files.' }
$version = (Invoke-VBox @('--version') | Out-String).Trim()
if ($version -notmatch '^7\.2\.') { throw "Este preparador requiere VirtualBox 7.2; detectado: $version" }

if ($Action -ne 'prepare') {
    $script:State = Read-ManagedState
    $info = Get-ManagedInfo
    switch ($Action) {
        'pause-work' { Suspend-AuditWork }
        'setup-control' { Initialize-GuestControl }
        'guest-status' { Export-GuestStatus }
        'guest-admin-status' { Export-GuestStatus -Elevated }
        'guest-control-proof' {
            if (-not $ProofId) { throw 'Indica -ProofId con 32 caracteres hexadecimales para correlacionar la prueba.' }
            Export-GuestStatus -Elevated -ControlProofId $ProofId
        }
        'status' { $null = Export-Status }
        'screenshot' {
            if ($info['VMState'] -ne 'running') { throw 'La VM no esta encendida; no hay pantalla que capturar.' }
            New-Item -ItemType Directory -Path $Evidence -Force | Out-Null
            $image = Join-Path $Evidence ('display-' + [DateTime]::UtcNow.ToString('yyyyMMdd-HHmmss') + '.png')
            Invoke-VBox @('controlvm', [string]$State.uuid, 'screenshotpng', $image)
            Write-Host "Captura: $image"
        }
        'start' {
            if ($State.stage -ne 'prepared') { throw 'Preparacion incompleta; revisa el error original antes de arrancar.' }
            Assert-Isolated $info
            if ($info['VMState'] -ne 'poweroff') { throw 'La VM no esta apagada. No se cambia su estado.' }
            Invoke-VBox @('startvm', [string]$State.uuid, '--type', 'headless')
        }
        'stop' {
            if ($info['VMState'] -ne 'running') { throw 'La VM no esta encendida.' }
            Invoke-VBox @('controlvm', [string]$State.uuid, 'acpipowerbutton')
            Write-Host 'Apagado ordenado solicitado; consulta status para confirmar que termino.'
        }
    }
    return
}

if (Test-Path -LiteralPath $StatePath) {
    $script:State = Read-ManagedState
    $null = Export-Status
    Write-Host 'La VM ya tiene un registro. No se reinstala ni se borran sus discos. Usa status/screenshot/start.'
    return
}
if (@(Invoke-VBox @('list', 'vms')) -match ('^"' + [regex]::Escape($VmName) + '" ')) {
    throw 'Ya existe una VM con ese nombre sin registro de este preparador. No se modifica.'
}
New-Item -ItemType Directory -Path $Root -Force | Out-Null
if ((Get-Item -LiteralPath $Root).Attributes -band [IO.FileAttributes]::ReparsePoint) { throw 'La carpeta de trabajo no puede ser un enlace.' }
# Keep the disposable guest password and unattended answer files private to this host account.
Set-PrivateDirectoryAcl $Root
if (-not (Test-Path -LiteralPath $Iso)) {
    $partial = $Iso + '.part'
    Write-Host 'Descargando ISO de evaluacion desde Microsoft (varios GB). Puede reanudarse repitiendo prepare.'
    & curl.exe --fail --location --proto '=https' --proto-redir '=https' --tlsv1.2 --retry 3 --connect-timeout 30 --continue-at - --output $partial $IsoUrl
    if ($LASTEXITCODE -ne 0) { throw 'Descarga incompleta. Se conserva .part; repite prepare para continuar.' }
    if ((Get-Item -LiteralPath $partial).Length -lt 1GB) { throw 'La descarga no tiene el tamano esperado de una ISO de Windows.' }
    Move-Item -LiteralPath $partial -Destination $Iso
}
Write-Host 'Calculando SHA-256 de la ISO y detectando el medio de instalacion...'
$isoHash = (Get-FileHash -LiteralPath $Iso -Algorithm SHA256).Hash.ToLowerInvariant()
$detected = @(Invoke-VBox @('unattended', 'detect', "--iso=$Iso", '--machine-readable'))
$detected | Set-Content -LiteralPath (Join-Path $Root 'iso-detection.txt') -Encoding UTF8
if (($detected -join "`n") -notmatch 'Windows11_64') { throw 'VirtualBox no identifica el medio como Windows 11 x64. Revisa iso-detection.txt.' }

$id = [guid]::NewGuid().ToString()
$script:State = [ordered]@{
    name=$VmName; uuid=$id; stage='creating'; created_utc=[DateTime]::UtcNow.ToString('o')
    iso_url=$IsoUrl; iso_sha256=$isoHash; hash_source='local fingerprint over HTTPS download; not a publisher hash comparison'
    image_index=$ImageIndex; vbox_version=$version; guest_user='audituser'; miner_staged=$false
}
Save-State
Invoke-VBox @('createvm', '--name', $VmName, '--uuid', $id, '--platform-architecture', 'x86', '--ostype', 'Windows11_64', '--basefolder', $Root, '--register')
$vmDir = Join-Path $Root $VmName
Invoke-VBox @('modifyvm', $id, '--memory', '8192', '--cpus', '4', '--firmware', 'efi', '--tpm-type', '2.0', '--ioapic', 'on',
    '--graphicscontroller', 'vboxsvga', '--vram', '128', '--accelerate-3d', 'off', '--clipboard-mode', 'disabled',
    '--clipboard-file-transfers', 'disabled', '--drag-and-drop', 'disabled', '--audio-enabled', 'off',
    '--usb-ohci', 'off', '--usb-ehci', 'off', '--usb-xhci', 'off', '--vrde', 'off', '--nested-hw-virt', 'off',
    '--nic1', 'none', '--nic2', 'none', '--nic3', 'none', '--nic4', 'none',
    '--nic5', 'none', '--nic6', 'none', '--nic7', 'none', '--nic8', 'none', '--boot1', 'dvd', '--boot2', 'disk', '--boot3', 'none', '--boot4', 'none')
Invoke-VBox @('modifynvram', $id, 'inituefivarstore')
Invoke-VBox @('modifynvram', $id, 'enrollmssignatures')
Invoke-VBox @('modifynvram', $id, 'enrollorclpk')
Invoke-VBox @('modifynvram', $id, 'secureboot', '--enable')
$disk = Join-Path $vmDir 'system.vdi'
Invoke-VBox @('createmedium', 'disk', '--filename', $disk, '--size', '81920', '--format', 'VDI', '--variant', 'Standard')
Invoke-VBox @('storagectl', $id, '--name', 'SATA', '--add', 'sata', '--controller', 'IntelAhci', '--portcount', '4', '--bootable', 'on')
Invoke-VBox @('storageattach', $id, '--storagectl', 'SATA', '--port', '0', '--device', '0', '--type', 'hdd', '--medium', $disk)
Invoke-VBox @('storageattach', $id, '--storagectl', 'SATA', '--port', '1', '--device', '0', '--type', 'dvddrive', '--medium', 'emptydrive')
$passwordFile = Join-Path $Root 'guest-password.txt'
$random = New-Object byte[] 24
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
try { $rng.GetBytes($random) } finally { $rng.Dispose() }
$password = 'Aa1!' + [Convert]::ToBase64String($random)
[IO.File]::WriteAllText($passwordFile, $password, [Text.Encoding]::ASCII)
$password = $null
# Installation only: no Guest Additions, test service, miner or host folder mappings.
# Keep unattended output local: it can include credentials expanded into its arguments.
& $VBox unattended install $id "--iso=$Iso" '--user=audituser' "--user-password-file=$passwordFile" `
    '--full-user-name=Isolated Audit' '--no-install-additions' '--no-install-txs' `
    '--locale=es_ES' '--language=es-ES' '--country=ES' '--time-zone=UTC' '--hostname=xmrig-audit.invalid' `
    "--image-index=$ImageIndex" "--auxiliary-base-path=$vmDir\Unattended-" *> (Join-Path $Root 'unattended-prepare.log')
if ($LASTEXITCODE -ne 0) { throw "No se preparo la instalacion. Revisa $Root\unattended-prepare.log localmente; puede contener credenciales, no lo publiques." }
Assert-Isolated (Get-ManagedInfo)
$State.stage = 'prepared'
Save-State
Invoke-VBox @('startvm', $id, '--type', 'headless')
$null = Export-Status
Write-Host 'Instalacion de Windows iniciada en headless. No se ha copiado ni ejecutado xmrig.exe.'
Write-Host 'Consulta -Action status o -Action screenshot para observar progreso. No se confirma aun que Windows haya terminado.'
