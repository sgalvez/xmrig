param([Parameter(Mandatory=$true)][string]$ScriptPath)
$ErrorActionPreference='Stop'
$tokens=$null; $errors=$null
$ast=[System.Management.Automation.Language.Parser]::ParseFile($ScriptPath,[ref]$tokens,[ref]$errors)
if(@($errors).Count){throw ($errors|Out-String)}
if($env:COMPUTERNAME -ne 'XMRIG-AUDIT'){
    $blocked=$false
    try { & $ScriptPath -ExpectedManifestSha ('a'*64) } catch { $blocked=$_.Exception.Message -like '*exclusivo de la VM*' }
    if(-not $blocked){throw 'La proteccion de ejecucion en host no rechazo el entorno.'}
}
# Only load the phase function. Processes, hashes and paths below are mocked.
$node=$ast.Find({param($n) $n -is [System.Management.Automation.Language.FunctionDefinitionAst] -and $n.Name -eq 'Invoke-Sample'},$true)
Invoke-Expression $node.Extent.Text
$script:Result=@{status='';sample_started=$false;phases=@()}
$script:Sample='C:\fixture\xmrig.exe'; $script:InputDir='C:\fixture'; $script:OutputDir='C:\fixture-output'
$script:Trace='C:\fixture-output\trace.pml'; $script:manifestPath='C:\fixture\manifest.json'
$script:ExpectedSha='a'*64; $script:ExpectedManifestSha='b'*64
$script:Started=0; $script:Tampered=$false
$script:Monitor=New-Object PSObject -Property @{HasExited=$false}
$script:Monitor | Add-Member ScriptMethod Refresh {}
function Write-Result {}
function Test-Path {return $true}
function Get-FileHash([string]$LiteralPath){
    $hash=if($LiteralPath -eq $script:Sample){if($script:Tampered){'c'*64}else{$script:ExpectedSha}}else{$script:ExpectedManifestSha}
    return @{Hash=$hash}
}
function Start-Process {
    $script:Started++
    $p=New-Object PSObject -Property @{Id=42;Handle=1;HasExited=$true;ExitCode=0}
    $p | Add-Member ScriptMethod WaitForExit {param($n) return $true}
    $p | Add-Member ScriptMethod Refresh {}
    return $p
}
Invoke-Sample 'help' '--help' 1
if($script:Started -ne 1 -or -not $Result.sample_started -or $Result.phases.Count -ne 1){throw 'No se registro la fase observada.'}
$script:Tampered=$true
$blocked=$false
try {Invoke-Sample 'version' '--version' 1} catch {$blocked=$true}
if(-not $blocked -or $script:Started -ne 1){throw 'Una muestra modificada se ejecuto.'}
$script:Tampered=$false; $script:Monitor.HasExited=$true
$blocked=$false
try {Invoke-Sample 'offline' '--config=fixture' 1} catch {$blocked=$true}
if(-not $blocked -or $script:Started -ne 1){throw 'La muestra se ejecuto sin monitor.'}
Write-Host 'Parser, host execution guard, sample hash and live-monitor gates passed. No sample executed.'
