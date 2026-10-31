# Prepare a clean Windows evaluation VM. This script NEVER stages or runs a miner.
[CmdletBinding()]
param(
    [ValidateSet('prepare', 'status', 'screenshot', 'start', 'stop')]
    [string]$Action = 'prepare',
    [ValidateRange(1, 20)][int]$ImageIndex = 1
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

if (-not (Test-Path -LiteralPath $VBox)) { throw 'No se encuentra VBoxManage.exe en Program Files.' }
$version = (Invoke-VBox @('--version') | Out-String).Trim()
if ($version -notmatch '^7\.2\.') { throw "Este preparador requiere VirtualBox 7.2; detectado: $version" }

if ($Action -ne 'prepare') {
    $script:State = Read-ManagedState
    $info = Get-ManagedInfo
    switch ($Action) {
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
