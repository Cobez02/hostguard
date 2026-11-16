# HostGuard read-only collectors. Each -What section prints one JSON document and changes nothing.
# Runs under Windows PowerShell 5.1 without administrator rights; sections that need more say so
# in their output instead of failing.
param(
    [Parameter(Mandatory)]
    [ValidateSet('signatures', 'tasks', 'wmi', 'defender', 'accounts', 'certs', 'bits', 'system', 'procstate', 'rdpfw')]
    [string]$What,
    [string]$InputFile = '',
    [string]$Arg = ''
)
$ErrorActionPreference = 'SilentlyContinue'
$ProgressPreference = 'SilentlyContinue'
[Console]::OutputEncoding = New-Object System.Text.UTF8Encoding($false)

function Emit($o) { [Console]::Out.Write((ConvertTo-Json -InputObject $o -Depth 8 -Compress)) }
function Iso($d) { if ($d) { ([datetime]$d).ToString('o') } else { $null } }

switch ($What) {

    'signatures' {
        # One Authenticode verdict per path listed in -InputFile (UTF-8, one path per line).
        # Get-AuthenticodeSignature checks embedded signatures and Windows catalog signatures.
        $list = [IO.File]::ReadAllLines($InputFile, [Text.Encoding]::UTF8)
        $out = foreach ($p in $list) {
            if (-not $p) { continue }
            try {
                $s = Get-AuthenticodeSignature -LiteralPath $p -ErrorAction Stop
                $c = $s.SignerCertificate
                [pscustomobject]@{
                    path    = $p
                    status  = [string]$s.Status
                    signer  = if ($c) { $c.Subject } else { '' }
                    issuer  = if ($c) { $c.Issuer } else { '' }
                    is_os   = [bool]$s.IsOSBinary
                    sigtype = [string]$s.SignatureType
                }
            }
            catch {
                [pscustomobject]@{ path = $p; status = 'Unreadable'; signer = ''; issuer = ''; is_os = $false; sigtype = '' }
            }
        }
        Emit @($out)
    }

    'tasks' {
        $out = foreach ($t in Get-ScheduledTask) {
            $acts = foreach ($a in $t.Actions) {
                $cls = $a.CimClass.CimClassName
                if ($cls -eq 'MSFT_TaskExecAction') {
                    @{ type = 'exec'; execute = $a.Execute; arguments = $a.Arguments; workdir = $a.WorkingDirectory }
                }
                elseif ($cls -eq 'MSFT_TaskComHandlerAction') { @{ type = 'com'; classid = $a.ClassId; data = $a.Data } }
                else { @{ type = $cls } }
            }
            $trigs = foreach ($g in $t.Triggers) { ($g.CimClass.CimClassName -replace '^MSFT_Task', '') -replace 'Trigger$', '' }
            [pscustomobject]@{
                name        = $t.TaskName
                path        = $t.TaskPath
                state       = [string]$t.State
                author      = $t.Author
                description = $t.Description
                date        = $t.Date
                user        = $t.Principal.UserId
                group       = $t.Principal.GroupId
                runlevel    = [string]$t.Principal.RunLevel
                hidden      = [bool]$t.Settings.Hidden
                actions     = @($acts)
                triggers    = @($trigs)
            }
        }
        Emit @($out)
    }

    'wmi' {
        # Permanent WMI event subscriptions: a classic fileless persistence spot.
        $filters = @(); $consumers = @(); $bindings = @(); $errors = @()
        foreach ($ns in 'root/subscription', 'root/default') {
            try {
                foreach ($f in Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop) {
                    $filters += @{ ns = $ns; name = $f.Name; query = $f.Query; event_ns = $f.EventNamespace }
                }
                foreach ($c in Get-CimInstance -Namespace $ns -ClassName __EventConsumer -ErrorAction Stop) {
                    $consumers += @{
                        ns = $ns; name = $c.Name; class = $c.CimClass.CimClassName
                        command = $c.CommandLineTemplate; exe = $c.ExecutablePath
                        script = $c.ScriptText; scriptfile = $c.ScriptFileName; engine = $c.ScriptingEngine
                    }
                }
                foreach ($b in Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop) {
                    $bindings += @{
                        ns = $ns; filter = [string]$b.Filter.Name; consumer = [string]$b.Consumer.Name
                        consumer_class = [string]$b.Consumer.CimClass.CimClassName
                    }
                }
            }
            catch { $errors += "${ns}: $($_.Exception.Message)" }
        }
        Emit @{ filters = @($filters); consumers = @($consumers); bindings = @($bindings); errors = @($errors) }
    }

    'defender' {
        $s = Get-MpComputerStatus
        $p = Get-MpPreference
        $status = $null
        if ($s) {
            $status = $s | Select-Object AMServiceEnabled, AntispywareEnabled, AntivirusEnabled, RealTimeProtectionEnabled,
                BehaviorMonitorEnabled, IoavProtectionEnabled, OnAccessProtectionEnabled, NISEnabled, IsTamperProtected,
                AMRunningMode, AMProductVersion, AMEngineVersion, AntivirusSignatureVersion, AntivirusSignatureAge,
                QuickScanAge, FullScanAge, DefenderSignaturesOutOfDate, SmartAppControlState, IsVirtualMachine,
                @{ n = 'SignatureUpdated'; e = { Iso $_.AntivirusSignatureLastUpdated } },
                @{ n = 'QuickScanEnd'; e = { Iso $_.QuickScanEndTime } },
                @{ n = 'FullScanEnd'; e = { Iso $_.FullScanEndTime } }
        }
        $prefs = $null
        if ($p) {
            $prefs = $p | Select-Object DisableRealtimeMonitoring, DisableBehaviorMonitoring, DisableIOAVProtection,
                DisableScriptScanning, DisableArchiveScanning, DisableBlockAtFirstSeen, MAPSReporting, SubmitSamplesConsent,
                CloudBlockLevel, PUAProtection, EnableNetworkProtection, EnableControlledFolderAccess,
                @{ n = 'ExclusionPath'; e = { @($_.ExclusionPath) } },
                @{ n = 'ExclusionProcess'; e = { @($_.ExclusionProcess) } },
                @{ n = 'ExclusionExtension'; e = { @($_.ExclusionExtension) } },
                @{ n = 'ExclusionIpAddress'; e = { @($_.ExclusionIpAddress) } },
                @{ n = 'AsrIds'; e = { @($_.AttackSurfaceReductionRules_Ids) } },
                @{ n = 'AsrActions'; e = { @($_.AttackSurfaceReductionRules_Actions) } },
                @{ n = 'AsrExclusions'; e = { @($_.AttackSurfaceReductionOnlyExclusions) } }
        }
        $threats = @(Get-MpThreat | Select-Object ThreatID, ThreatName, SeverityID, CategoryID, IsActive, DidThreatExecute,
            @{ n = 'Resources'; e = { @($_.Resources) } })
        $detections = @(Get-MpThreatDetection | Select-Object ThreatID, ProcessName, DomainUser, ActionSuccess,
            CurrentThreatExecutionStatusID, ThreatStatusID, CleaningActionID,
            @{ n = 'Detected'; e = { Iso $_.InitialDetectionTime } },
            @{ n = 'Resources'; e = { @($_.Resources) } })
        $products = @(Get-CimInstance -Namespace root/SecurityCenter2 -ClassName AntiVirusProduct |
                Select-Object displayName, productState, pathToSignedProductExe)
        Emit @{ status = $status; prefs = $prefs; threats = $threats; detections = $detections; products = $products }
    }

    'accounts' {
        $users = foreach ($u in Get-LocalUser) {
            @{
                name = $u.Name; enabled = [bool]$u.Enabled; sid = $u.SID.Value; lastlogon = Iso $u.LastLogon
                pwset = Iso $u.PasswordLastSet; pwrequired = [bool]$u.PasswordRequired
                source = [string]$u.PrincipalSource; description = $u.Description
            }
        }
        $groups = @{}
        # Administrators, Remote Desktop Users, Remote Management Users, Backup Operators, Hyper-V Administrators, Event Log Readers
        foreach ($sid in 'S-1-5-32-544', 'S-1-5-32-555', 'S-1-5-32-580', 'S-1-5-32-551', 'S-1-5-32-578', 'S-1-5-32-573') {
            $g = Get-LocalGroup -SID $sid
            if (-not $g) { continue }
            $members = @()
            try {
                $members = @(Get-LocalGroupMember -SID $sid -ErrorAction Stop | ForEach-Object {
                        @{ name = $_.Name; sid = $_.SID.Value; class = $_.ObjectClass; source = [string]$_.PrincipalSource }
                    })
            }
            catch { $members = @(@{ name = "(unreadable: $($_.Exception.Message))"; sid = ''; class = ''; source = '' }) }
            $groups[$sid] = @{ name = $g.Name; members = $members }
        }
        Emit @{ users = @($users); groups = $groups; current = [Security.Principal.WindowsIdentity]::GetCurrent().Name }
    }

    'certs' {
        $out = foreach ($store in 'LocalMachine\Root', 'CurrentUser\Root') {
            foreach ($c in Get-ChildItem "Cert:\$store") {
                @{
                    store = $store; thumbprint = $c.Thumbprint; subject = $c.Subject; issuer = $c.Issuer
                    notbefore = Iso $c.NotBefore; notafter = Iso $c.NotAfter; name = $c.FriendlyName
                }
            }
        }
        Emit @($out)
    }

    'bits' {
        $jobs = foreach ($j in Get-BitsTransfer) {
            @{
                id = [string]$j.JobId; name = $j.DisplayName; description = $j.Description; state = [string]$j.JobState
                type = [string]$j.TransferType; owner = $j.OwnerAccount; created = Iso $j.CreationTime
                files = @($j.FileList | ForEach-Object { @{ remote = $_.RemoteName; local = $_.LocalName } })
            }
        }
        $verbose = ''
        try { $verbose = (& "$env:SystemRoot\System32\bitsadmin.exe" /list /verbose 2>$null | Out-String) } catch { }
        Emit @{ jobs = @($jobs); verbose = $verbose }
    }

    'system' {
        $os = Get-CimInstance Win32_OperatingSystem
        $hot = Get-HotFix | Where-Object { $_.InstalledOn } | Sort-Object InstalledOn -Descending | Select-Object -First 1
        $fw = @(Get-NetFirewallProfile | ForEach-Object {
                @{ name = $_.Name; enabled = [bool]$_.Enabled; inbound = [string]$_.DefaultInboundAction; outbound = [string]$_.DefaultOutboundAction }
            })
        $shares = @(Get-SmbShare | ForEach-Object { @{ name = $_.Name; path = $_.Path; description = $_.Description } })
        $dns = @(Get-DnsClientServerAddress | Where-Object { $_.ServerAddresses } | ForEach-Object {
                @{ alias = $_.InterfaceAlias; family = [string]$_.AddressFamily; servers = @($_.ServerAddresses) }
            })
        $nets = @(Get-NetConnectionProfile | ForEach-Object { @{ name = $_.Name; alias = $_.InterfaceAlias; category = [string]$_.NetworkCategory } })
        $adapters = @(Get-NetAdapter | ForEach-Object {
                @{ name = $_.Name; description = $_.InterfaceDescription; status = [string]$_.Status; virtual = [bool]$_.Virtual; physical = [bool]$_.HardwareInterface }
            })
        $cache = @(Get-DnsClientCache | Select-Object -First 3000 | ForEach-Object { @{ name = $_.Entry; data = $_.Data; type = [string]$_.Type } })
        $secureboot = $null
        try { $secureboot = [bool](Confirm-SecureBootUEFI -ErrorAction Stop) } catch { $secureboot = $null }
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        Emit @{
            os         = @{ caption = $os.Caption; version = $os.Version; build = $os.BuildNumber; installed = Iso $os.InstallDate; booted = Iso $os.LastBootUpTime }
            hotfix     = if ($hot) { @{ id = $hot.HotFixID; installed = Iso $hot.InstalledOn } } else { $null }
            firewall   = $fw
            shares     = $shares
            dns        = $dns
            networks   = $nets
            adapters   = $adapters
            dnscache   = $cache
            secureboot = $secureboot
            elevated   = (New-Object Security.Principal.WindowsPrincipal $id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            user       = $id.Name
        }
    }

    'rdpfw' {
        # Which network profiles the enabled inbound Remote Desktop firewall rules apply to.
        $out = foreach ($r in Get-NetFirewallRule -Group '@FirewallAPI.dll,-28752') {
            if ($r.Enabled -eq 'True' -and $r.Direction -eq 'Inbound') {
                foreach ($p in ([string]$r.Profile -split ',\s*')) { @{ rule = $r.DisplayName; profile = $p } }
            }
        }
        Emit @($out)
    }

    'procstate' {
        # Is a process suspended? -Arg is the PID. Used to read a containment action back.
        $p = Get-Process -Id ([int]$Arg)
        if (-not $p) { Emit @{ exists = $false }; break }
        $threads = @($p.Threads)
        $suspended = @($threads | Where-Object { $_.ThreadState -eq 'Wait' -and $_.WaitReason -eq 'Suspended' }).Count
        Emit @{ exists = $true; threads = $threads.Count; suspended = $suspended; all_suspended = ($threads.Count -gt 0 -and $suspended -eq $threads.Count) }
    }
}
