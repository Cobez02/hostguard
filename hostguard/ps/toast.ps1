# Shows one Windows notification. Title and text come from a JSON file, not from the command line,
# so nothing a finding contains can become part of a command.
param([Parameter(Mandatory)][string]$Json)
$ErrorActionPreference = 'Stop'
try {
    $d = Get-Content -LiteralPath $Json -Raw -Encoding UTF8 | ConvertFrom-Json
    [void][Windows.UI.Notifications.ToastNotificationManager, Windows.UI.Notifications, ContentType = WindowsRuntime]
    [void][Windows.Data.Xml.Dom.XmlDocument, Windows.Data.Xml.Dom.XmlDocument, ContentType = WindowsRuntime]
    $title = [System.Security.SecurityElement]::Escape([string]$d.title)
    $text = [System.Security.SecurityElement]::Escape([string]$d.text)
    $xml = New-Object Windows.Data.Xml.Dom.XmlDocument
    $xml.LoadXml("<toast><visual><binding template='ToastGeneric'><text>$title</text><text>$text</text></binding></visual></toast>")
    $appId = '{1AC14E77-02E7-4E5D-B744-2EB1AE5198B7}\WindowsPowerShell\v1.0\powershell.exe'
    $toast = New-Object Windows.UI.Notifications.ToastNotification $xml
    [Windows.UI.Notifications.ToastNotificationManager]::CreateToastNotifier($appId).Show($toast)
    exit 0
}
catch { exit 1 }
finally { Remove-Item -LiteralPath $Json -Force -ErrorAction SilentlyContinue }
