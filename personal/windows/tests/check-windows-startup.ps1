# Exercise parameter binding and initialization, without executing any action.
$ErrorActionPreference = 'Stop'
$source = Join-Path (Split-Path $PSScriptRoot) 'windows-xmrig.ps1'
$tokens = $null
$errors = $null
$ast = [System.Management.Automation.Language.Parser]::ParseFile($source, [ref]$tokens, [ref]$errors)
if ($errors.Count) { throw ($errors | Out-String) }
$initialization = @()
foreach ($statement in $ast.EndBlock.Statements) {
    if ($statement -is [System.Management.Automation.Language.FunctionDefinitionAst]) { break }
    $initialization += $statement.Extent.Text
}
$temp = Join-Path ([IO.Path]::GetTempPath()) ('xmrig-startup-' + [guid]::NewGuid())
$SimulatedScriptPath = Join-Path (Join-Path $temp 'xmrig-personal-lab') 'windows-xmrig.ps1'
$originalLocalAppData = $env:LOCALAPPDATA
$originalScriptRoot = $PSScriptRoot
try {
    $env:LOCALAPPDATA = Join-Path $temp 'LocalAppData'
    # Reproduce Windows PowerShell's empty automatic variable during binding.
    $PSScriptRoot = ''
    $code = $ast.ParamBlock.Extent.Text + "`n" + '$PSCommandPath = $SimulatedScriptPath' + "`n" +
        ($initialization -join "`n") + "`n" + 'return $Runtime'
    $initialize = [scriptblock]::Create($code)
    $actual = & $initialize -Action Status
    $expected = Join-Path (Join-Path $temp 'ravencoin-miner-lab') '.runtime'
    if ($actual -ne $expected) { throw "Expected default runtime $expected, got $actual" }
    $explicit = Join-Path $temp 'explicit runtime'
    $actual = & $initialize -Action Status -RuntimeRoot $explicit
    if ($actual -ne $explicit) { throw 'Explicit RuntimeRoot was not preserved.' }
    Write-Output 'PowerShell: empty PSScriptRoot during binding and explicit/default runtime paths passed.'
} finally {
    $PSScriptRoot = $originalScriptRoot
    $env:LOCALAPPDATA = $originalLocalAppData
    if (Test-Path -LiteralPath $temp) { Remove-Item -LiteralPath $temp -Recurse -Force }
}
