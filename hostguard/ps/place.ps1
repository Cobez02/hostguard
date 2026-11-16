# Copies one file to its destination through the Background Intelligent Transfer Service.
#
# Why: a Python installed from the Microsoft Store runs in an app sandbox in which any NEW file
# it creates under AppData lands in a private copy that no other program sees. The transfer
# service runs outside that sandbox (as you, with no extra rights), so a file restored this way
# really is where it says it is. Source and destination come from HostGuard's quarantine code.
param(
    [Parameter(Mandatory)][string]$Source,
    [Parameter(Mandatory)][string]$Destination
)
$ErrorActionPreference = 'Stop'
try {
    Start-BitsTransfer -Source $Source -Destination $Destination -DisplayName 'HostGuard restore' -ErrorAction Stop
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
