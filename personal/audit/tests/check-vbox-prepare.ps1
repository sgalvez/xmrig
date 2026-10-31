param([string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'audit-isolated\vbox-windows.ps1'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw ($errors | Out-String) }
# Load selected functions only. Never execute the launcher's top-level code.
foreach ($name in @('Assert-Isolated', 'Get-ManagedInfo', 'Set-PrivateDirectoryAcl', 'Stop-GuestForSnapshot',
                    'Initialize-GuestControl', 'Get-GuestStatusCommand', 'Export-GuestStatus')) {
    $node = $ast.Find({ param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq $name }, $true)
    if (-not $node) { throw "Missing function: $name" }
    Invoke-Expression $node.Extent.Text
}
function Must-Throw([scriptblock]$Test) {
    $threw = $false
    try { & $Test } catch { $threw = $true }
    if (-not $threw) { throw 'Unsafe or unverifiable VM was accepted.' }
}
$good = @{ clipboard='disabled'; draganddrop='disabled'; accelerate3d='off' }
foreach ($i in 1..8) { $good["nic$i"] = 'none' }
Assert-Isolated $good
foreach ($i in 1..8) {
    foreach ($mode in @('nat', 'bridged', 'hostonly', 'intnet', 'null')) {
        $bad = $good.Clone(); $bad["nic$i"] = $mode
        Must-Throw { Assert-Isolated $bad }
    }
    $bad = $good.Clone(); $bad.Remove("nic$i")
    Must-Throw { Assert-Isolated $bad }
}
foreach ($pair in @(@('clipboard','bidirectional'), @('draganddrop','hosttoguest'), @('accelerate3d','on'), @('SharedFolderPathMachineMapping1','C:\Users'))) {
    $bad=$good.Clone(); $bad[$pair[0]]=$pair[1]
    Must-Throw { Assert-Isolated $bad }
}
foreach ($key in @('clipboard', 'draganddrop', 'accelerate3d')) {
    $bad=$good.Clone(); $bad.Remove($key)
    Must-Throw { Assert-Isolated $bad }
}
$script:VmName='Xmrig-Audit-Win11'
$script:State=@{ uuid='12345678-1234-1234-1234-123456789abc'; name=$script:VmName }
$script:FakeInfo=@('name="Xmrig-Audit-Win11"','UUID="12345678-1234-1234-1234-123456789abc"','VMState="poweroff"')
function Invoke-VBox([string[]]$Arguments) {
    if ($Arguments[0] -ne 'showvminfo' -or $Arguments[1] -ne $script:State.uuid) { throw 'Unexpected VM command in test.' }
    return $script:FakeInfo
}
$parsed=Get-ManagedInfo
if ($parsed['VMState'] -ne 'poweroff') { throw 'Machine info parser failed.' }
$script:FakeInfo=@('name="Another VM"','UUID="12345678-1234-1234-1234-123456789abc"')
Must-Throw { Get-ManagedInfo }
$script:FakeInfo=@('name="Xmrig-Audit-Win11"','UUID="00000000-1234-1234-1234-123456789abc"')
Must-Throw { Get-ManagedInfo }
# Exercise the real Windows ACL tool on a disposable directory, including a
# repeated call as happens when prepare resumes an interrupted download.
$aclTest = Join-Path ([IO.Path]::GetTempPath()) ('xmrig-acl-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $aclTest | Out-Null
try {
    foreach ($attempt in 1..2) {
        Set-PrivateDirectoryAcl $aclTest
        $acl = Get-Acl -LiteralPath $aclTest
        if (-not $acl.AreAccessRulesProtected) { throw 'Directory still inherits permissions.' }
        $currentSid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
        $rules = @($acl.GetAccessRules($true, $true, [Security.Principal.SecurityIdentifier]))
        foreach ($requiredSid in @($currentSid, 'S-1-5-18', 'S-1-5-32-544')) {
            $allowed = @($rules | Where-Object {
                $_.IdentityReference.Value -eq $requiredSid -and
                $_.AccessControlType -eq [Security.AccessControl.AccessControlType]::Allow -and
                ($_.FileSystemRights -band [Security.AccessControl.FileSystemRights]::FullControl) -eq [Security.AccessControl.FileSystemRights]::FullControl
            })
            if ($allowed.Count -eq 0) { throw "Missing full-control grant for $requiredSid" }
        }
        $probe = Join-Path $aclTest 'write-check.txt'
        [IO.File]::WriteAllText($probe, 'accessible')
        if ([IO.File]::ReadAllText($probe) -ne 'accessible') { throw 'Directory became inaccessible.' }
    }
} finally { Remove-Item -LiteralPath $aclTest -Recurse -Force }

# Parse the command that will run in the guest; never execute it on the CI host.
$probe = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String((Get-GuestStatusCommand)))
$null = [System.Management.Automation.Language.Parser]::ParseInput($probe, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw ($errors | Out-String) }

# Model VM state transitions. All VBox calls below are recorded, not executed.
$script:Calls = New-Object 'System.Collections.Generic.List[object]'
$script:InfoQueue = New-Object System.Collections.Queue
$off = $good.Clone(); $off['VMState']='poweroff'
$off['CurrentSnapshotUUID']='abcdef12-1234-1234-1234-123456789abc'
$running=$off.Clone(); $running['VMState']='running'
function Get-ManagedInfo {
    if ($script:InfoQueue.Count -gt 1) { return $script:InfoQueue.Dequeue() }
    return $script:InfoQueue.Peek()
}
function Start-Sleep { param([int]$Seconds) }
function Invoke-VBox([string[]]$Arguments) {
    $script:Calls.Add([object]$Arguments)
    if ($Arguments[0] -eq 'snapshot' -and $Arguments[2] -eq 'list') {
        return 'SnapshotUUID="abcdef12-1234-1234-1234-123456789abc"'
    }
}
$script:InfoQueue.Enqueue($off)
Stop-GuestForSnapshot
if ($script:Calls.Count -ne 0) { throw 'Already stopped VM was modified.' }
$script:InfoQueue.Clear(); $script:InfoQueue.Enqueue($running); $script:InfoQueue.Enqueue($off)
Stop-GuestForSnapshot
if ($script:Calls.Count -ne 1 -or $script:Calls[0][2] -ne 'acpipowerbutton') { throw 'Graceful shutdown sequence failed.' }
$script:Calls.Clear(); $paused=$off.Clone(); $paused['VMState']='paused'
$script:InfoQueue.Clear(); $script:InfoQueue.Enqueue($paused)
Must-Throw { Stop-GuestForSnapshot }
if ($script:Calls.Count -ne 0) { throw 'Paused VM was modified.' }
$aborted=$off.Clone(); $aborted['VMState']='aborted'
$script:InfoQueue.Clear(); $script:InfoQueue.Enqueue($running); $script:InfoQueue.Enqueue($aborted)
Must-Throw { Stop-GuestForSnapshot }
if ($script:Calls.Count -ne 1 -or $script:Calls[0][2] -ne 'acpipowerbutton') { throw 'Unexpected state caused forced shutdown.' }

$vmTest=Join-Path ([IO.Path]::GetTempPath()) ('xmrig-setup-test-' + [guid]::NewGuid().ToString('N'))
New-Item -ItemType Directory -Path $vmTest | Out-Null
try {
    $script:Root=$vmTest
    $script:Evidence=Join-Path $vmTest 'evidence'
    $script:VBox=Join-Path $vmTest 'VBoxManage.exe'
    [IO.File]::WriteAllText((Join-Path $vmTest 'VBoxGuestAdditions.iso'), 'inert test fixture, never mounted')
    $script:InfoQueue.Clear(); $script:InfoQueue.Enqueue($off)
    $script:Calls.Clear()
    Initialize-GuestControl
    $snapshotIndex=-1; $mountIndex=-1; $startIndex=-1
    for ($i=0; $i -lt $script:Calls.Count; $i++) {
        $call=$script:Calls[$i]
        if ($call[0] -eq 'snapshot' -and $call[2] -eq 'take') { $snapshotIndex=$i }
        if ($call[0] -eq 'storageattach') { $mountIndex=$i }
        if ($call[0] -eq 'startvm') { $startIndex=$i }
    }
    if ($snapshotIndex -lt 0 -or $mountIndex -le $snapshotIndex -or $startIndex -le $mountIndex) {
        throw 'Baseline was not created before mounting tools and starting VM.'
    }
    $baseline=Get-Content -LiteralPath (Join-Path $vmTest 'clean-baseline.json') -Raw | ConvertFrom-Json
    if ($baseline.snapshot_uuid -ne $off['CurrentSnapshotUUID']) { throw 'Wrong baseline identity stored.' }
    $script:Calls.Clear()
    Initialize-GuestControl
    if (@($script:Calls | Where-Object { $_[0] -eq 'snapshot' -and $_[2] -eq 'take' }).Count -ne 0) {
        throw 'Repeating setup replaced the clean baseline.'
    }
    $baseline.vm_uuid='00000000-1234-1234-1234-123456789abc'
    $baseline | ConvertTo-Json | Set-Content -LiteralPath (Join-Path $vmTest 'clean-baseline.json') -Encoding UTF8
    $script:Calls.Clear()
    Must-Throw { Initialize-GuestControl }
    if ($script:Calls.Count -ne 0) { throw 'Setup operated on a foreign baseline.' }
} finally { Remove-Item -LiteralPath $vmTest -Recurse -Force }
Write-Host 'Syntax, isolation, real ACLs, orderly shutdown and baseline sequencing passed. VM operations were simulated; no miner executed.'
