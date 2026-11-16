# Creates one shortcut file, or reports where this user's Desktop and Start Menu folders are.
#
# The shortcut runs a windowless Python with HostGuard's launcher. Every value arrives as a
# parameter from hostguard/shortcuts.py; nothing here is built from text HostGuard read off the PC.
param(
    [switch]$Folders,
    [string]$Path,
    [string]$Target,
    [string]$Script,
    [string]$ScriptArgs = '',
    [string]$Icon = '',
    [string]$Description = '',
    [string]$WorkingDirectory = ''
)
$ErrorActionPreference = 'Stop'
try {
    if ($Folders) {
        @{ desktop = [Environment]::GetFolderPath('Desktop'); start_menu = [Environment]::GetFolderPath('Programs') } |
            ConvertTo-Json -Compress
        exit 0
    }
    if (-not $Path -or -not $Target -or -not $Script) { throw 'Path, Target and Script are required.' }
    $shell = New-Object -ComObject WScript.Shell
    $link = $shell.CreateShortcut($Path)
    $link.TargetPath = $Target
    $link.Arguments = ('"{0}" {1}' -f $Script, $ScriptArgs).Trim()
    if ($Icon) { $link.IconLocation = "$Icon,0" }
    if ($Description) { $link.Description = $Description }
    if ($WorkingDirectory) { $link.WorkingDirectory = $WorkingDirectory }
    $link.Save()
    exit 0
}
catch {
    [Console]::Error.WriteLine($_.Exception.Message)
    exit 1
}
