# HostGuard's only code that runs with administrator rights. It does one request and exits.
#
# The request is a JSON file: { "verb": "...", "args": { ... }, "result": "path for the answer" }.
# Every verb is on a fixed list and re-checks its own arguments, because the request file sits in
# a folder the logged-on user can write to: nothing here trusts it beyond "the user approved a
# HostGuard action". Core Windows processes and services are refused here as well as in Python.
#
# -DryRun parses the request, runs every check and reports what would change without changing it
# (it needs no administrator rights; the tests use it).
param(
    [Parameter(Mandatory)][string]$ArgFile,
    [switch]$DryRun
)
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue'

$script:Changes = New-Object System.Collections.ArrayList
$script:Data = @{}

function Finish([bool]$ok, [string]$message) {
    $out = @{ ok = $ok; message = $message; changes = @($script:Changes); data = $script:Data; dry_run = [bool]$DryRun }
    try { [IO.File]::WriteAllText($req.result, (ConvertTo-Json -InputObject $out -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false))) } catch { }
    if ($ok) { exit 0 } else { exit 1 }
}
function Refuse([string]$why) { Finish $false "refused: $why" }
function Change([string]$what, [scriptblock]$do) {
    [void]$script:Changes.Add($what)
    if (-not $DryRun) { & $do }
}
function Test-Admin {
    $id = [Security.Principal.WindowsIdentity]::GetCurrent()
    return (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}
function Rule-Exists([string]$name) {
    & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall show rule name="$name" | Out-Null
    return ($LASTEXITCODE -eq 0)
}
function Netsh-Rule([string[]]$parts) {
    $out = & "$env:SystemRoot\System32\netsh.exe" advfirewall firewall @parts 2>&1
    if ($LASTEXITCODE -ne 0) { throw "netsh failed: $($out | Out-String)" }
}

try { $req = Get-Content -LiteralPath $ArgFile -Raw -Encoding UTF8 | ConvertFrom-Json }
catch { Write-Error "unreadable request file"; exit 2 }
if (-not $req.result) { exit 2 }
$a = $req.args
$verb = [string]$req.verb
$stateHome = Split-Path -Parent (Split-Path -Parent ([IO.Path]::GetFullPath($ArgFile)))

if (-not $DryRun -and -not (Test-Admin)) { Finish $false 'administrator rights were not granted' }

$Critical = 'system', 'registry', 'smss', 'csrss', 'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'svchost',
    'fontdrvhost', 'dwm', 'msmpeng', 'nissrv', 'mpdefendercoreservice', 'securityhealthservice', 'sgrmbroker'
$ProtectedServices = 'windefend', 'wdnissvc', 'sense', 'mdcoresvc', 'wscsvc', 'mpssvc', 'bfe', 'eventlog', 'rpcss',
    'dcomlaunch', 'rpceptmapper', 'lsm', 'samss', 'plugplay', 'power', 'profsvc', 'schedule', 'winmgmt', 'cryptsvc',
    'dhcp', 'dnscache', 'nsi', 'lanmanworkstation', 'gpsvc', 'wuauserv', 'trustedinstaller', 'securityhealthservice',
    'coremessagingregistrar', 'systemeventsbroker', 'brokerinfrastructure', 'usermanager', 'termservice'
$AutorunKeys = @(
    '^Software\\(Wow6432Node\\)?Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunOnceEx|RunServices|RunServicesOnce|Policies\\Explorer\\Run)$',
    '^Software\\Microsoft\\Windows NT\\CurrentVersion\\Image File Execution Options\\[^\\]+$',
    '^Software\\Microsoft\\Windows NT\\CurrentVersion\\Windows$',
    '^Software\\Microsoft\\Command Processor$'
)
# Attack Surface Reduction rule ids, from Microsoft's ASR rules reference.
$AsrStandard = '56a863a9-875e-4185-98a7-b882c64b5ce5', '9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2', 'e6db77e5-3df2-4cf1-b95a-636979351e5b'
$AsrExtended = 'd4f940ab-401b-4efc-aadc-ad5f3c50688a', '5beb7efe-fd9a-4556-801d-275e5ffc04cc', 'd3e037e1-3eb8-44c8-a917-57927947596d',
    'c1db55ab-c21a-4637-bb3f-a12568109d35', 'be9ba2d9-53ea-4cdc-84e5-9b1eeee46550', '92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b'
$IsolationRules = 'HostGuard-Isolation-Out', 'HostGuard-Isolation-In'

function Get-Target([int]$procId, $created) {
    if ($procId -le 4) { Refuse 'that is a kernel pseudo-process' }
    $p = Get-Process -Id $procId -ErrorAction SilentlyContinue
    if (-not $p) { Refuse 'the process has already exited' }
    $genuine = (-not $p.Path) -or $p.Path.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)
    if (($Critical -contains $p.ProcessName.ToLower()) -and $genuine) { Refuse "$($p.ProcessName) is a core Windows process" }
    if ($created -and $p.StartTime) {
        $epoch = ([DateTimeOffset]$p.StartTime).ToUnixTimeMilliseconds() / 1000.0
        if ([Math]::Abs($epoch - [double]$created) -gt 2) { Refuse "process id $procId now belongs to a different program" }
    }
    return $p
}
function Open-Reg([int]$view) {
    $v = if ($view -eq 32) { [Microsoft.Win32.RegistryView]::Registry32 } else { [Microsoft.Win32.RegistryView]::Registry64 }
    return [Microsoft.Win32.RegistryKey]::OpenBaseKey([Microsoft.Win32.RegistryHive]::LocalMachine, $v)
}
function Check-RegPath([string]$path) {
    foreach ($rx in $AutorunKeys) { if ($path -match $rx) { return } }
    Refuse "the registry key '$path' is not an autorun location HostGuard manages"
}

try {
    switch ($verb) {

        'kill' {
            $p = Get-Target ([int]$a.pid) $a.created
            Change "stop process $($p.ProcessName) (pid $($p.Id))" { Stop-Process -Id $p.Id -Force }
            Finish $true "stopped $($p.ProcessName) (pid $($p.Id))"
        }

        { $_ -in 'suspend', 'resume' } {
            $p = Get-Target ([int]$a.pid) $a.created
            Change "$verb process $($p.ProcessName) (pid $($p.Id))" {
                Add-Type -Namespace HostGuard -Name Native -MemberDefinition @'
[DllImport("kernel32.dll", SetLastError = true)] public static extern IntPtr OpenProcess(uint access, bool inherit, int pid);
[DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtSuspendProcess(IntPtr h);
[DllImport("ntdll.dll")] public static extern int NtResumeProcess(IntPtr h);
'@
                $h = [HostGuard.Native]::OpenProcess(0x0800, $false, $p.Id)
                if ($h -eq [IntPtr]::Zero) { throw 'could not open the process' }
                try {
                    $st = if ($verb -eq 'suspend') { [HostGuard.Native]::NtSuspendProcess($h) } else { [HostGuard.Native]::NtResumeProcess($h) }
                    if ($st -ne 0) { throw ("the call failed with status 0x{0:X8}" -f $st) }
                }
                finally { [void][HostGuard.Native]::CloseHandle($h) }
            }
            Finish $true "$verb done for $($p.ProcessName) (pid $($p.Id))"
        }

        'quarantine' {
            $src = [IO.Path]::GetFullPath([string]$a.path)
            $dest = [IO.Path]::GetFullPath([string]$a.dest)
            if (-not (Test-Path -LiteralPath $src -PathType Leaf)) { Refuse 'the file does not exist' }
            if ($src.StartsWith($env:SystemRoot, [StringComparison]::OrdinalIgnoreCase)) { Refuse 'the file is inside the Windows folder' }
            $vault = Join-Path $stateHome 'quarantine'
            if ((Split-Path -Parent $dest) -ne $vault -or (Split-Path -Leaf $dest) -notmatch '^incoming-\d+-\d+\.bin$') {
                Refuse 'the destination is not the quarantine vault'
            }
            Change "move $src into the quarantine vault" { Move-Item -LiteralPath $src -Destination $dest -Force }
            Finish $true "moved $src to quarantine"
        }

        { $_ -in 'task-disable', 'task-enable' } {
            $full = [string]$a.task
            if ($full -notmatch '^\\(?:[^\\/:*?"<>|]+\\)*[^\\/:*?"<>|]+$') { Refuse 'not a task path' }
            $name = Split-Path -Leaf $full
            $path = (Split-Path -Parent $full).TrimEnd('\') + '\'
            if ($verb -eq 'task-disable' -and $path -like '\Microsoft\Windows\*' -and -not $a.force) { Refuse "that is one of Windows' own tasks" }
            if (-not (Get-ScheduledTask -TaskPath $path -TaskName $name -ErrorAction SilentlyContinue)) { Refuse 'no such task' }
            if ($verb -eq 'task-disable') { Change "disable task $full" { Disable-ScheduledTask -TaskPath $path -TaskName $name | Out-Null } }
            else { Change "enable task $full" { Enable-ScheduledTask -TaskPath $path -TaskName $name | Out-Null } }
            Finish $true "$verb done for $full"
        }

        { $_ -in 'service-disable', 'service-restore' } {
            $name = [string]$a.service
            if ($name -notmatch '^[A-Za-z0-9_.$ -]{1,256}$') { Refuse 'not a service name' }
            if ($ProtectedServices -contains $name.ToLower()) { Refuse "$name is a service Windows needs" }
            $key = "HKLM:\SYSTEM\CurrentControlSet\Services\$name"
            if (-not (Test-Path -LiteralPath $key)) { Refuse 'no such service' }
            $script:Data.previous_start = (Get-ItemProperty -LiteralPath $key).Start
            if ($verb -eq 'service-disable') {
                Change "stop and disable service $name" {
                    & "$env:SystemRoot\System32\sc.exe" stop $name | Out-Null
                    & "$env:SystemRoot\System32\sc.exe" config $name start= disabled | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "sc config failed ($LASTEXITCODE)" }
                }
            }
            else {
                $map = @{ 0 = 'boot'; 1 = 'system'; 2 = 'auto'; 3 = 'demand'; 4 = 'disabled' }
                $start = [int]$a.start
                if (-not $map.ContainsKey($start)) { Refuse 'unknown start type' }
                Change "set service $name start type to $($map[$start])" {
                    & "$env:SystemRoot\System32\sc.exe" config $name start= $map[$start] | Out-Null
                    if ($LASTEXITCODE -ne 0) { throw "sc config failed ($LASTEXITCODE)" }
                }
            }
            Finish $true "$verb done for $name"
        }

        { $_ -in 'reg-value-delete', 'reg-value-set' } {
            if ([string]$a.hive -ne 'HKLM') { Refuse 'only HKLM needs elevation' }
            $path = [string]$a.path
            Check-RegPath $path
            $name = [string]$a.name
            $base = Open-Reg ([int]$a.view)
            if ($verb -eq 'reg-value-delete') {
                Change "delete value '$name' under HKLM\$path" {
                    $k = $base.OpenSubKey($path, $true)
                    if (-not $k) { throw 'the key does not exist' }
                    $k.DeleteValue($name, $false); $k.Close()
                }
            }
            else {
                $kind = switch ([string]$a.type) { 'REG_DWORD' { 'DWord' } 'REG_MULTI_SZ' { 'MultiString' } default { 'String' } }
                $value = if ($kind -eq 'DWord') { [int]$a.value } elseif ($kind -eq 'MultiString') { [string[]]@($a.value) } else { [string]$a.value }
                Change "write value '$name' under HKLM\$path" {
                    $k = $base.CreateSubKey($path)
                    $k.SetValue($name, $value, [Microsoft.Win32.RegistryValueKind]$kind); $k.Close()
                }
            }
            Finish $true "$verb done for HKLM\$path : $name"
        }

        { $_ -in 'block-ip', 'unblock-ip' } {
            $ip = $null
            if (-not [Net.IPAddress]::TryParse([string]$a.ip, [ref]$ip)) { Refuse 'not an IP address' }
            if ([Net.IPAddress]::IsLoopback($ip)) { Refuse 'that is this PC' }
            $text = $ip.ToString()
            foreach ($dir in 'Out', 'In') {
                $rule = "HostGuard-Block-$text-$dir"
                if (Rule-Exists $rule) { Change "remove firewall rule $rule" { Netsh-Rule @('delete', 'rule', "name=$rule") } }
                if ($verb -eq 'block-ip') {
                    Change "add firewall rule $rule" {
                        Netsh-Rule @('add', 'rule', "name=$rule", "dir=$($dir.ToLower())", 'action=block', 'enable=yes', 'profile=any', "remoteip=$text")
                    }
                }
            }
            Finish $true "$verb done for $text"
        }

        'isolate' {
            foreach ($rule in $IsolationRules) {
                $dir = if ($rule -like '*-Out') { 'out' } else { 'in' }
                if (-not (Rule-Exists $rule)) {
                    Change "add firewall rule $rule (block every $dir`bound connection)" {
                        Netsh-Rule @('add', 'rule', "name=$rule", "dir=$dir", 'action=block', 'enable=yes', 'profile=any')
                    }
                }
            }
            if ($a.hard) {
                $up = @(Get-NetAdapter -Physical | Where-Object { $_.Status -eq 'Up' })
                $script:Data.adapters = @($up | ForEach-Object { $_.Name })
                Change "disable network adapters: $($script:Data.adapters -join ', ')" {
                    $dir = Join-Path $env:ProgramData 'HostGuard'
                    New-Item -ItemType Directory -Force -Path $dir | Out-Null
                    $script:Data.adapters | Set-Content -LiteralPath (Join-Path $dir 'isolated-adapters.txt') -Encoding UTF8
                    $up | Disable-NetAdapter -Confirm:$false
                }
            }
            Finish $true 'network isolated'
        }

        'release' {
            foreach ($rule in $IsolationRules) {
                if (Rule-Exists $rule) { Change "remove firewall rule $rule" { Netsh-Rule @('delete', 'rule', "name=$rule") } }
            }
            $list = Join-Path $env:ProgramData 'HostGuard\isolated-adapters.txt'
            if (Test-Path -LiteralPath $list) {
                $names = @(Get-Content -LiteralPath $list -Encoding UTF8 | Where-Object { $_ })
                Change "re-enable network adapters: $($names -join ', ')" {
                    foreach ($n in $names) { Enable-NetAdapter -Name $n -Confirm:$false -ErrorAction SilentlyContinue }
                    Remove-Item -LiteralPath $list -Force
                }
            }
            Finish $true 'network restored'
        }

        { $_ -in 'user-disable', 'user-enable' } {
            $name = [string]$a.user
            if ($name -notmatch '^[^\\/\[\]:;|=,+*?<>"@]{1,20}$') { Refuse 'not a local account name' }
            $u = Get-LocalUser -Name $name -ErrorAction SilentlyContinue
            if (-not $u) { Refuse 'no such local account' }
            if ($verb -eq 'user-disable') {
                if ($name -eq [string]$a.current -or $name -eq $env:USERNAME) { Refuse 'that is the account in use' }
                Change "disable account $name" { Disable-LocalUser -Name $name }
            }
            else { Change "enable account $name" { Enable-LocalUser -Name $name } }
            Finish $true "$verb done for $name"
        }

        'wmi-remove' {
            $ns = [string]$a.namespace
            if ($ns -notin 'root/subscription', 'root/default') { Refuse 'unexpected WMI namespace' }
            $consumer = [string]$a.consumer
            $bindings = @(Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding | Where-Object { $_.Consumer.Name -eq $consumer })
            $consumers = @(Get-CimInstance -Namespace $ns -ClassName __EventConsumer | Where-Object { $_.Name -eq $consumer })
            if (-not $consumers -and -not $bindings) { Refuse 'no such subscription' }
            if ($consumer -eq 'SCM Event Log Consumer') { Refuse "that is Windows' own subscription" }
            $script:Data.saved = @{
                consumers = @($consumers | ForEach-Object { $_ | Select-Object * -ExcludeProperty Cim*, PSComputerName })
                bindings  = @($bindings | ForEach-Object { @{ filter = [string]$_.Filter.Name; consumer = [string]$_.Consumer.Name } })
            }
            Change "remove WMI subscription '$consumer' from $ns" {
                $bindings | Remove-CimInstance
                $consumers | Remove-CimInstance
            }
            Finish $true "removed the WMI subscription '$consumer'"
        }

        'harden' {
            $on = [bool]$a.on
            $setting = [string]$a.setting
            switch ($setting) {
                'pua_block' { Change "set PUA protection to $(if ($on) { 'block' } else { 'audit' })" { Set-MpPreference -PUAProtection $(if ($on) { 'Enabled' } else { 'AuditMode' }) } }
                'network_protection' { Change "set network protection $(if ($on) { 'on' } else { 'off' })" { Set-MpPreference -EnableNetworkProtection $(if ($on) { 'Enabled' } else { 'Disabled' }) } }
                'controlled_folder_access' { Change "set controlled folder access $(if ($on) { 'on' } else { 'off' })" { Set-MpPreference -EnableControlledFolderAccess $(if ($on) { 'Enabled' } else { 'Disabled' }) } }
                'cloud_block_high' { Change "set cloud block level to $(if ($on) { 'High' } else { 'Default' })" { Set-MpPreference -CloudBlockLevel $(if ($on) { 'High' } else { 'Default' }) } }
                { $_ -in 'asr_standard', 'asr_extended' } {
                    $ids = if ($setting -eq 'asr_standard') { $AsrStandard } else { $AsrExtended }
                    foreach ($id in $ids) {
                        if ($on) { Change "enable ASR rule $id" { Add-MpPreference -AttackSurfaceReductionRules_Ids $id -AttackSurfaceReductionRules_Actions Enabled } }
                        else { Change "remove ASR rule $id" { Remove-MpPreference -AttackSurfaceReductionRules_Ids $id } }
                    }
                }
                'process_audit' {
                    $flag = if ($on) { 'enable' } else { 'disable' }
                    Change "$flag process-creation auditing with command lines" {
                        & "$env:SystemRoot\System32\auditpol.exe" /set /subcategory:"{0CCE922B-69AE-11D9-BED3-505054503030}" /success:$flag | Out-Null
                        $k = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit'
                        New-Item -Path $k -Force | Out-Null
                        Set-ItemProperty -Path $k -Name ProcessCreationIncludeCmdLine_Enabled -Value ([int]$on) -Type DWord
                    }
                }
                'script_block_logging' {
                    $k = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging'
                    if ($on) { Change 'enable PowerShell script block logging' { New-Item -Path $k -Force | Out-Null; Set-ItemProperty -Path $k -Name EnableScriptBlockLogging -Value 1 -Type DWord } }
                    else { Change 'disable PowerShell script block logging' { Remove-ItemProperty -Path $k -Name EnableScriptBlockLogging -ErrorAction SilentlyContinue } }
                }
                'event_log_readers' {
                    $user = [string]$a.user
                    if ($user -notmatch '^[^/\[\]:;|=,+*?<>"]{1,64}$') { Refuse 'not an account name' }
                    if ($on) { Change "add $user to Event Log Readers" { Add-LocalGroupMember -SID 'S-1-5-32-573' -Member $user -ErrorAction Stop } }
                    else { Change "remove $user from Event Log Readers" { Remove-LocalGroupMember -SID 'S-1-5-32-573' -Member $user -ErrorAction Stop } }
                }
                'rdp_off' {
                    Change "turn Remote Desktop $(if ($on) { 'off' } else { 'on' })" {
                        Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Terminal Server' -Name fDenyTSConnections -Value ([int]$on) -Type DWord
                    }
                }
                'rdp_private_only' {
                    Change "limit Remote Desktop firewall rules to $(if ($on) { 'private networks' } else { 'all networks' })" {
                        Set-NetFirewallRule -Group '@FirewallAPI.dll,-28752' -Profile $(if ($on) { 'Private' } else { 'Any' })
                    }
                }
                'one_click_isolation' {
                    $task = 'Isolate'; $folder = '\HostGuard\'
                    if ($on) {
                        Change 'register the one-click isolation task' {
                            $netsh = "$env:SystemRoot\System32\netsh.exe"
                            $acts = @(
                                (New-ScheduledTaskAction -Execute $netsh -Argument 'advfirewall firewall add rule name=HostGuard-Isolation-Out dir=out action=block enable=yes profile=any'),
                                (New-ScheduledTaskAction -Execute $netsh -Argument 'advfirewall firewall add rule name=HostGuard-Isolation-In dir=in action=block enable=yes profile=any')
                            )
                            $who = [Security.Principal.WindowsIdentity]::GetCurrent().Name
                            $principal = New-ScheduledTaskPrincipal -UserId $who -LogonType Interactive -RunLevel Highest
                            $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -ExecutionTimeLimit (New-TimeSpan -Minutes 2)
                            Register-ScheduledTask -TaskPath $folder -TaskName $task -Action $acts -Principal $principal -Settings $settings -Force `
                                -Description 'HostGuard: blocks all network traffic when run. It can only tighten; releasing needs an administrator.' | Out-Null
                        }
                    }
                    else { Change 'remove the one-click isolation task' { Unregister-ScheduledTask -TaskPath $folder -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue } }
                }
                'sysmon' {
                    if (-not $on) { Refuse "Microsoft's page gives no command to turn the built-in Sysmon off; use 'Turn Windows features on or off'" }
                    if (Get-Service -Name 'sysmon*' -ErrorAction SilentlyContinue) { Refuse 'a Sysmon service is already installed' }
                    Change 'enable the built-in Sysmon feature and start it with its default configuration' {
                        Enable-WindowsOptionalFeature -Online -FeatureName Sysmon -NoRestart | Out-Null
                        $exe = (Get-Command sysmon.exe -ErrorAction SilentlyContinue).Source
                        if (-not $exe) { throw 'the feature was enabled but sysmon.exe is not on the path yet; restart, then run: sysmon -i' }
                        if ($a.config -and (Test-Path -LiteralPath ([string]$a.config) -PathType Leaf)) { & $exe -accepteula -i ([string]$a.config) | Out-Null }
                        else { & $exe -accepteula -i | Out-Null }
                    }
                }
                default { Refuse "unknown hardening setting '$setting'" }
            }
            Finish $true "$setting set to $(if ($on) { 'on' } else { 'off' })"
        }

        'collect' {
            # Read-only: the facts a normal user cannot see, written where the unelevated scan can pick them up.
            $outdir = Join-Path $stateHome 'elevated'
            if ([IO.Path]::GetFullPath([string]$a.outdir) -ne $outdir) { Refuse 'unexpected output folder' }
            if ($DryRun) { Finish $true 'would collect administrator-only facts' }
            $ErrorActionPreference = 'SilentlyContinue'
            $owners = @{}
            Get-Process -IncludeUserName | ForEach-Object { $owners[[int]$_.Id] = $_.UserName }
            $procs = @(Get-CimInstance Win32_Process | ForEach-Object {
                    @{ pid = [int]$_.ProcessId; ppid = [int]$_.ParentProcessId; name = $_.Name; path = $_.ExecutablePath; cmdline = $_.CommandLine; user = $owners[[int]$_.ProcessId] }
                })
            $s = Get-MpComputerStatus; $p = Get-MpPreference
            $defender = @{
                status     = $s | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled, BehaviorMonitorEnabled,
                    IoavProtectionEnabled, OnAccessProtectionEnabled, NISEnabled, IsTamperProtected, AMRunningMode, AMProductVersion, AntivirusSignatureVersion,
                    AntivirusSignatureAge, QuickScanAge, FullScanAge, DefenderSignaturesOutOfDate, SmartAppControlState
                prefs      = $p | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection, DisableScriptScanning,
                    DisableArchiveScanning, MAPSReporting, SubmitSamplesConsent, CloudBlockLevel, PUAProtection, EnableNetworkProtection, EnableControlledFolderAccess,
                    @{ n = 'ExclusionPath'; e = { @($_.ExclusionPath) } }, @{ n = 'ExclusionProcess'; e = { @($_.ExclusionProcess) } },
                    @{ n = 'ExclusionExtension'; e = { @($_.ExclusionExtension) } }, @{ n = 'ExclusionIpAddress'; e = { @($_.ExclusionIpAddress) } },
                    @{ n = 'AsrIds'; e = { @($_.AttackSurfaceReductionRules_Ids) } }, @{ n = 'AsrActions'; e = { @($_.AttackSurfaceReductionRules_Actions) } }
                threats    = @(Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, CategoryID, IsActive, DidThreatExecute, @{ n = 'Resources'; e = { @($_.Resources) } })
                detections = @(Get-MpThreatDetection | Select-Object ThreatID, ProcessName, DomainUser, ActionSuccess, ThreatStatusID,
                    @{ n = 'Detected'; e = { if ($_.InitialDetectionTime) { $_.InitialDetectionTime.ToString('o') } } }, @{ n = 'Resources'; e = { @($_.Resources) } })
                products   = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct | Select-Object displayName, productState)
            }
            $secureboot = $null; try { $secureboot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { }
            $bitlocker = @(Get-BitLockerVolume | ForEach-Object { @{ mount = $_.MountPoint; protection = [string]$_.ProtectionStatus; status = [string]$_.VolumeStatus } })
            $sysmon = $null; try { $sysmon = [string](Get-WindowsOptionalFeature -Online -FeatureName Sysmon -ErrorAction Stop).State } catch { $sysmon = 'not offered on this build' }
            $files = @{}
            $i = 0
            foreach ($q in @($a.queries)) {
                $i++
                $file = Join-Path $outdir ("events-$i.xml")
                & "$env:SystemRoot\System32\wevtutil.exe" qe ([string]$q.log) "/q:$([string]$q.xpath)" /f:xml "/c:$([int]$q.max)" /rd:true 2>$null |
                    Set-Content -LiteralPath $file -Encoding UTF8
                if ($LASTEXITCODE -eq 0) { $files["events-$i.xml"] = [string]$q.log }
            }
            # Optional: Hayabusa (Sigma rules over the live event logs). It is only run from HostGuard's own
            # tools folder and only when its publisher signature verifies, because it runs elevated.
            $hayabusaFile = $null; $hayabusaSigner = $null
            if ($a.hayabusa) {
                $hexe = [IO.Path]::GetFullPath([string]$a.hayabusa)
                $toolsDir = (Join-Path $stateHome 'tools\hayabusa') + '\'
                if ($hexe.StartsWith($toolsDir, [StringComparison]::OrdinalIgnoreCase) -and (Test-Path -LiteralPath $hexe -PathType Leaf)) {
                    $sig = Get-AuthenticodeSignature -LiteralPath $hexe
                    if ($sig.Status -eq 'Valid') {
                        $hayabusaSigner = $sig.SignerCertificate.Subject
                        $level = [string]$a.hayabusa_level
                        if ($level -notin 'informational', 'low', 'medium', 'high', 'critical') { $level = 'medium' }
                        $hout = Join-Path $outdir 'hayabusa.jsonl'
                        Remove-Item -LiteralPath $hout -Force -ErrorAction SilentlyContinue
                        Push-Location (Split-Path -Parent $hexe)
                        try { & $hexe dfir-timeline -l -t jsonl -o $hout -w -m $level -q -N -K -C -Q 2>$null | Out-Null } finally { Pop-Location }
                        if (Test-Path -LiteralPath $hout) { $hayabusaFile = 'hayabusa.jsonl' }
                    }
                    else { $hayabusaSigner = "not run: its signature status is $($sig.Status)" }
                }
            }
            $latest = @{ when = [DateTimeOffset]::UtcNow.ToUnixTimeSeconds(); processes = $procs; defender = $defender; secureboot = $secureboot
                bitlocker = $bitlocker; sysmon_feature = $sysmon; event_files = $files; hayabusa_file = $hayabusaFile; hayabusa_signer = $hayabusaSigner
            }
            [IO.File]::WriteAllText((Join-Path $outdir 'latest.json'), (ConvertTo-Json -InputObject $latest -Depth 8 -Compress), (New-Object Text.UTF8Encoding($false)))
            Finish $true "collected $($procs.Count) processes and $($files.Count) event exports"
        }

        default { Refuse "unknown verb '$verb'" }
    }
}
catch {
    Finish $false "$($_.Exception.Message)"
}
