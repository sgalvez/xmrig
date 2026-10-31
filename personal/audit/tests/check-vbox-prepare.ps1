param([string]$ScriptPath = (Join-Path (Split-Path -Parent $PSScriptRoot) 'audit-isolated\vbox-windows.ps1'))
$ErrorActionPreference = 'Stop'
Set-StrictMode -Version Latest
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($ScriptPath, [ref]$tokens, [ref]$errors)
if (@($errors).Count) { throw ($errors | Out-String) }
# Load selected functions only. Never execute the launcher's top-level code.
foreach ($name in @('Assert-Isolated', 'Get-ManagedInfo', 'Set-PrivateDirectoryAcl')) {
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
Write-Host 'PowerShell syntax, VM identity, isolation and real Windows ACL checks passed. No download, VM or miner executed.'
