# Compile the interop declaration; simulate inventory without loading a GPU driver.
$ErrorActionPreference='Stop'
$root=Split-Path $PSScriptRoot
Add-Type -Path (Join-Path $root 'opencl-devices.cs')
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile((Join-Path $root 'windows-xmrig.ps1'),[ref]$tokens,[ref]$errors)
if ($errors.Count) { throw 'Launcher parse failure' }
$definition=$ast.FindAll({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Show-OpenClDevices'},$true)[0]
. ([scriptblock]::Create($definition.Extent.Text))
function Read-OpenClDevices { return $script:devices }
$script:devices=@(
    @{PlatformIndex=0;PlatformVersion='OpenCL test';Id=0;Name='gfx-integrated';BoardName='AMD Radeon Graphics';MemoryBytes=2GB},
    @{PlatformIndex=0;PlatformVersion='OpenCL test';Id=1;Name='gfx1201';BoardName='AMD Radeon RX 9070 XT';MemoryBytes=16GB}
)
$output=(Show-OpenClDevices 6>&1 | Out-String)
if ($output -notmatch '1\s+\|\s+16[.,]00\s+\| gfx1201 / AMD Radeon RX 9070 XT') {
    throw 'GPU index must stay 1 even when platform index is 0.'
}
if ($output -notmatch '0\s+\|\s+2[.,]00\s+\| gfx-integrated') { throw 'Integrated GPU missing.' }
$script:devices=@()
$failed=$false
try { Show-OpenClDevices } catch { $failed=$true }
if (-not $failed) { throw 'Empty GPU inventory must prevent the ID prompt.' }
Write-Output 'OpenCL interop compiles; device/platform distinction and empty inventory checks passed. No GPU driver called.'
