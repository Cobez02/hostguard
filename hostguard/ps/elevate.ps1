# Runs elevated.ps1 with administrator rights for one request. Windows shows its UAC prompt; the
# caller (the dashboard or the command line) stays unelevated and waits for the result.
# Exit codes: whatever elevated.ps1 returned, or 1223 when the prompt was declined.
param([Parameter(Mandatory)][string]$ArgFile)
$ErrorActionPreference = 'Stop'
$script = Join-Path $PSScriptRoot 'elevated.ps1'
$ps = Join-Path $env:SystemRoot 'System32\WindowsPowerShell\v1.0\powershell.exe'
$id = [Security.Principal.WindowsIdentity]::GetCurrent()
$admin = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if ($admin) {
    & $ps -NoProfile -ExecutionPolicy Bypass -File $script -ArgFile $ArgFile
    exit $LASTEXITCODE
}
try {
    $p = Start-Process -FilePath $ps -Verb RunAs -PassThru -Wait -WindowStyle Hidden -ArgumentList @(
        '-NoProfile', '-ExecutionPolicy', 'Bypass', '-File', "`"$script`"", '-ArgFile', "`"$ArgFile`"")
    exit $p.ExitCode
}
catch {
    exit 1223
}
