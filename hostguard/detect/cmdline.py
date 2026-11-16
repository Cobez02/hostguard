"""Rules over command lines and script text.

The same table judges a running process, an autorun entry, a scheduled task action, a service
binary path, a logged PowerShell script block and a script file, so an attacker's command is
recognised wherever it shows up.

Some tokens are written in pieces (see `j`). They are names of attack tools, and antivirus
engines flag files that merely contain them, including a rules file like this one.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..util import decode_encoded_command, truncate


def j(*parts: str) -> str:
    return "".join(parts)


@dataclass(frozen=True)
class TextRule:
    id: str
    title: str
    severity: str
    confidence: str
    mitre: tuple
    pattern: re.Pattern
    scope: str = "both"          # cmdline | script | both
    why: str = ""
    unless: re.Pattern | None = None


@dataclass
class Hit:
    rule: TextRule
    match: str
    decoded: bool = False        # found inside a decoded -EncodedCommand payload
    context: list = field(default_factory=list)


def _c(p: str) -> re.Pattern:
    return re.compile(p, re.I | re.S)


_USERDIR = r"(?:\\users\\[^\\\"]+\\(?:appdata|downloads|desktop|documents|music|pictures|videos)\\|\\users\\public\\|\\programdata\\|\\windows\\temp\\|\\perflogs\\|\\\$recycle\.bin\\)"
_ARCHIVE_TEMP = r"(?:\\temp\\(?:temp\d+_[^\\]+\.zip|7z[^\\]+|rar\$[^\\]+|[^\\]+\.zip\.[^\\]+)\\)"
_FETCH = r"(?:downloadstring|downloaddata|downloadfile|invoke-webrequest|invoke-restmethod|\biwr\b|\birm\b|net\.webclient|\bcurl\b|\bwget\b|start-bitstransfer|msxml2\.xmlhttp|winhttp\.winhttprequest|system\.net\.http\.httpclient)"
_EXEC = r"(?:\biex\b|invoke-expression|\[scriptblock\]::create|\.invoke\(\))"
_SEC_SVC = r"(?:windefend|wdnissvc|sense|wscsvc|mpssvc|securityhealthservice|eventlog|wuauserv|mdcoresvc|sysmon(?:64)?)"

RULES: list[TextRule] = [
    # ---------------------------------------------------------------- download and run
    TextRule("cmd.download_cradle", "Downloads code from the internet and runs it in memory", "high", "medium",
             ("T1059.001", "T1105"),
             _c(rf"{_EXEC}.{{0,300}}{_FETCH}|{_FETCH}.{{0,400}}\|\s*(?:iex\b|invoke-expression)"),
             why="A download piped straight into an interpreter leaves no file for antivirus to scan. "
                 "It is how ClickFix lures and most droppers start, and also how some legitimate installers work."),
    TextRule("cmd.curl_pipe_shell", "Pipes a download into a shell", "high", "medium", ("T1059", "T1105"),
             _c(r"\bcurl(?:\.exe)?\s+[^|&]*https?://[^|&]*\|\s*(?:cmd|powershell|pwsh|bash|sh)\b"
                r"|\bfinger(?:\.exe)?\s+\S+@\S+\s*\|\s*cmd")),
    TextRule("cmd.mshta_remote", "mshta runs remote or inline script", "high", "high", ("T1218.005",),
             _c(r"\bmshta(?:\.exe)?\"?\s+.*(?:https?:|javascript:|vbscript:|\\\\[a-z0-9.-]+\\)")),
    TextRule("cmd.regsvr32_scriptlet", "regsvr32 loads a scriptlet (Squiblydoo)", "high", "high", ("T1218.010",),
             _c(r"\bregsvr32(?:\.exe)?\b.*(?:/i:\s*\"?(?:https?:|\\\\)|scrobj\.dll)")),
    TextRule("cmd.rundll32_script", "rundll32 runs script or a remote payload", "high", "high", ("T1218.011",),
             _c(r"\brundll32(?:\.exe)?\b.*(?:javascript:|vbscript:|mshtml\s*,\s*runhtmlapplication"
                r"|shell32(?:\.dll)?\s*,\s*shellexec_rundll\s+\"?\S*(?:powershell|cmd|mshta|wscript)"
                r"|url(?:\.dll)?\s*,\s*(?:openurl|fileprotocolhandler)\s+\"?\S+\.(?:hta|js|jse|vbs|vbe|wsf|scr|pif)\b)")),
    TextRule("cmd.rundll32_user_dll", "rundll32 loads a DLL from a user-writable folder", "medium", "medium",
             ("T1218.011",), _c(rf"\brundll32(?:\.exe)?\"?\s+\"?[a-z]:[^,\"]*{_USERDIR}[^,\"]*"),
             scope="cmdline"),
    TextRule("cmd.certutil_download", "certutil used as a downloader", "high", "high", ("T1105", "T1218"),
             _c(r"\bcertutil(?:\.exe)?\b.*[-/](?:urlcache|verifyctl)\b.*(?:https?|ftp):")),
    TextRule("cmd.certutil_decode", "certutil decodes a payload", "medium", "medium", ("T1140",),
             _c(r"\bcertutil(?:\.exe)?\b.*[-/](?:decode|decodehex)\b")),
    TextRule("cmd.bitsadmin_transfer", "bitsadmin downloads a file or sets a command", "medium", "medium",
             ("T1197", "T1105"), _c(r"\bbitsadmin(?:\.exe)?\b.*/(?:transfer|addfile|setnotifycmdline)\b")),
    TextRule("cmd.msiexec_remote", "msiexec installs a package from a URL", "high", "medium", ("T1218.007",),
             _c(r"\bmsiexec(?:\.exe)?\b.*[-/](?:i|package|q\w*)\b.*https?://")),
    TextRule("cmd.script_from_archive", "Script run straight out of an archive or the temp folder", "high", "medium",
             ("T1059.005", "T1059.007", "T1204.002"),
             _c(rf"\b(?:wscript|cscript)(?:\.exe)?\b.*(?:{_ARCHIVE_TEMP}|\\appdata\\local\\temp\\|\\downloads\\)"
                r"[^\"]*\.(?:js|jse|vbs|vbe|wsf|wsh)\b"), scope="cmdline"),
    TextRule("cmd.ps_file_from_temp", "PowerShell script run from Temp, Downloads or Public", "medium", "low",
             ("T1059.001",),
             _c(r"\b(?:powershell|pwsh)(?:\.exe)?\b.*-f(?:ile)?\s+\"?[^\"]*(?:\\downloads\\|\\users\\public\\)"
                r"[^\"]*\.ps1"), scope="cmdline"),
    TextRule("cmd.conhost_headless", "Hidden console host launches a command", "high", "medium", ("T1564.003",),
             _c(r"\bconhost(?:\.exe)?\"?\s+--headless\s+(?!--)\S"), scope="cmdline"),
    TextRule("cmd.wmic_xsl", "wmic runs a remote stylesheet (Squiblytwo)", "high", "high", ("T1220",),
             _c(r"\bwmic(?:\.exe)?\b.*/format:\s*\"?(?:https?:|\\\\)")),
    TextRule("cmd.wmic_process_create", "wmic starts a process", "medium", "low", ("T1047",),
             _c(r"\bwmic(?:\.exe)?\b.*\bprocess\s+call\s+create\b")),
    TextRule("cmd.lolbin_proxy", "Signed Windows tool used to run other code", "high", "medium",
             ("T1218", "T1127"),
             _c(r"\bcmstp(?:\.exe)?\b.*/s\b.*\.inf|\bmavinject(?:\.exe)?\b.*/injectrunning"
                r"|\bodbcconf(?:\.exe)?\b.*\bregsvr\b|\binstallutil(?:\.exe)?\b.*/logtoconsole=false"
                r"|\bmsxsl(?:\.exe)?\b.*https?:|\bieexec(?:\.exe)?\b.*https?:"
                r"|syncappvpublishingserver(?:\.vbs|\.exe)?\b.*;")),
    TextRule("cmd.ads_exec", "Runs code hidden in an alternate data stream", "high", "medium", ("T1564.004",),
             _c(r"\b(?:wscript|cscript|rundll32|regsvr32|mshta|forfiles|wmic)(?:\.exe)?\b[^|&]*"
                r"[a-z]:\\[^:\"\s|&]+:[^\\/:\"\s|&]+\.(?:exe|dll|js|vbs|ps1|hta)\b"), scope="cmdline"),

    # ---------------------------------------------------------------- PowerShell content
    TextRule("ps.amsi_bypass", "Tries to switch off the antimalware scan interface", "critical", "high",
             ("T1562.001",),
             _c(j("amsi", "utils") + "|" + j("amsi", "initfailed") + "|" + j("amsi", "scanbuffer")
                + "|" + j("amsi", "context") + r"|amsi\.dll.{0,200}virtualprotect")),
    TextRule("ps.reflective_load", "Loads a .NET assembly from memory", "high", "medium", ("T1620",),
             _c(r"(?:reflection\.assembly\]?(?:::|\.)load(?:file|from)?\s*\(|\[appdomain\]::currentdomain\.load\()"
                r".{0,300}(?:frombase64string|\[byte\[\]\]|downloaddata|gzipstream|deflatestream)"
                r"|(?:frombase64string|downloaddata).{0,300}reflection\.assembly\]?(?:::|\.)load\s*\(")),
    TextRule("ps.shellcode_api", "Allocates executable memory and starts a thread in it", "high", "medium",
             ("T1055", "T1106"),
             _c(r"virtualalloc(?:ex)?\b.{0,2000}(?:createthread|createremotethread|queueuserapc|writeprocessmemory)"
                r"|getdelegateforfunctionpointer.{0,600}virtualalloc|ntcreatethreadex|rtlcreateuserthread")),
    TextRule("ps.offensive_framework", "Known attack-framework command", "critical", "high",
             ("T1059.001", "T1003"),
             _c("|".join([j("invoke-", "mimi", "katz"), j("invoke-", "shell", "code"),
                          j("invoke-", "reflective", "pe", "injection"), j("invoke-", "dll", "injection"),
                          j("invoke-", "token", "manipulation"), j("invoke-", "kerbe", "roast"),
                          j("invoke-", "blood", "hound"), j("sharp", "hound"), j("invoke-", "psinject"),
                          j("invoke-", "wmiexec"), j("invoke-", "smbexec"), j("invoke-", "powershell", "tcp"),
                          j("invoke-", "empire"), j("get-", "gpp", "password"), j("get-", "key", "strokes"),
                          j("invoke-", "ninja", "copy"), j("invoke-", "credential", "injection"),
                          j("out-", "mini", "dump"), j("invoke-", "ru", "beus"), j("invoke-", "seat", "belt"),
                          j("invoke-", "power", "dump"), j("invoke-", "inveigh")]))),
    TextRule("ps.compressed_payload", "Unpacks and runs a compressed, encoded payload", "high", "medium",
             ("T1027", "T1140"),
             _c(r"(?:gzipstream|deflatestream).{0,400}frombase64string.{0,600}(?:\biex\b|invoke-expression|readtoend\(\))"
                r"|frombase64string.{0,400}(?:gzipstream|deflatestream).{0,600}(?:\biex\b|invoke-expression)")),
    TextRule("ps.socket_shell", "Opens a raw TCP connection and feeds it to a shell", "critical", "medium",
             ("T1059.001", "T1571"),
             _c(r"new-object\s+(?:system\.)?net\.sockets\.tcpclient\s*\(.{0,800}(?:getstream\(\)|\biex\b|invoke-expression)")),

    # ---------------------------------------------------------------- defence evasion
    TextRule("evade.defender_tamper", "Changes Microsoft Defender settings from a script", "high", "medium",
             ("T1562.001",),
             _c(r"\b(?:set|add)-mppreference\b[^|;]*-(?:disable\w+\s+(?:\$?true|1)\b|exclusion(?:path|process|extension|ipaddress)"
                r"|\w*defaultaction\s+(?:allow|noaction|6|9)\b|mapsreporting\s+(?:0|disabled)|submitsamplesconsent\s+(?:2|never))"
                r"|\bmpcmdrun(?:\.exe)?\b.*-removedefinitions")),
    TextRule("evade.security_service_stop", "Stops or disables a security service", "high", "high",
             ("T1562.001", "T1489"),
             _c(rf"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?(?:stop|delete|config)\s+\"?{_SEC_SVC}\b"
                rf"|\bnet1?(?:\.exe)?\s+stop\s+\"?{_SEC_SVC}\b|\bstop-service\b[^|;]*\b{_SEC_SVC}\b"
                r"|\btaskkill(?:\.exe)?\b.*\b(?:msmpeng|mssense|securityhealthservice|nissrv)\.exe")),
    TextRule("evade.firewall_off", "Turns Windows Firewall off", "high", "high", ("T1562.004",),
             _c(r"\bnetsh(?:\.exe)?\s+(?:advfirewall\s+set\s+\w+\s+state\s+off|firewall\s+set\s+opmode\s+(?:mode\s*=\s*)?disable)"
                r"|\bset-netfirewallprofile\b[^|;]*-enabled\s+(?:\$?false|0)\b")),
    TextRule("evade.log_clear", "Clears event logs or the change journal", "high", "high", ("T1070.001",),
             _c(r"\bwevtutil(?:\.exe)?\s+(?:cl|clear-log)\b|\bclear-eventlog\b|\bremove-eventlog\b"
                r"|\bfsutil(?:\.exe)?\s+usn\s+deletejournal")),
    TextRule("evade.safeboot", "Sets the PC to restart in safe mode", "high", "medium", ("T1562.009",),
             _c(r"\bbcdedit(?:\.exe)?\b.*\bsafeboot\b")),
    TextRule("evade.uac_hijack", "Registers a handler that a UAC-exempt program will run", "high", "high",
             ("T1548.002",),
             _c(r"\\software\\classes\\(?:ms-settings|mscfile|exefile|folder)\\shell\\open\\command")),

    # ---------------------------------------------------------------- impact
    TextRule("impact.shadow_delete", "Deletes backups or disables recovery", "critical", "high", ("T1490",),
             _c(r"\bvssadmin(?:\.exe)?\s+(?:delete\s+shadows|resize\s+shadowstorage)"
                r"|\bwmic(?:\.exe)?\s+shadowcopy\s+delete|\bwbadmin(?:\.exe)?\s+delete\s+(?:catalog|systemstatebackup|backup)"
                r"|\bbcdedit(?:\.exe)?\b.*(?:recoveryenabled\s+no|bootstatuspolicy\s+ignoreallfailures)"
                r"|win32_shadowcopy.{0,200}\.delete\(|\bdiskshadow\b.*delete\s+shadows")),

    # ---------------------------------------------------------------- credential theft
    TextRule("cred.lsass_dump", "Dumps the memory of the Windows credential store", "critical", "high",
             ("T1003.001",),
             _c(r"\bcomsvcs(?:\.dll)?\s*[, ]\s*#?(?:" + j("mini", "dump") + r"|24)\b"
                r"|\bprocdump(?:64)?(?:\.exe)?\b.*\blsass|\blsass(?:\.exe)?\b.{0,80}\.dmp\b"
                r"|\b" + j("nano", "dump") + r"\b|\brdrleakdiag(?:\.exe)?\b.*/fullmemdmp")),
    TextRule("cred.hive_dump", "Copies the account database or the domain database", "critical", "high",
             ("T1003.002", "T1003.003"),
             _c(r"\breg(?:\.exe)?\s+save\s+\"?hklm\\(?:sam|security|system)\b"
                r"|\besentutl(?:\.exe)?\b.*(?:ntds\.dit|\\config\\sam\b)|\bntdsutil(?:\.exe)?\b.*\b(?:ifm|create\s+full)\b")),
    TextRule("cred.dump_tool", "Credential-dumping tool command", "critical", "high", ("T1003",),
             _c("|".join([j("seku", "rlsa::"), j("lsa", "dump::"), r"kerberos::(?:ptt|golden|list)",
                          r"privilege::debug", j("mimi", "katz"), r"dpapi::(?:masterkey|cred|chrome)",
                          j("lazag", "ne"), j("pyp", "ykatz")]))),

    # ---------------------------------------------------------------- persistence and accounts
    TextRule("persist.reg_autorun", "Adds an autorun entry from the command line", "medium", "medium",
             ("T1547.001",),
             _c(r"\breg(?:\.exe)?\s+add\s+\"?hk(?:lm|cu|ey_local_machine|ey_current_user)\\software\\(?:wow6432node\\)?"
                r"microsoft\\windows\\currentversion\\(?:run|runonce|policies\\explorer\\run)\b"
                r"|(?:new-itemproperty|set-itemproperty)\b[^|;]*\\currentversion\\run\b")),
    TextRule("persist.reg_hijack", "Rewrites a logon, debugger or credential setting", "high", "high",
             ("T1546.012", "T1547.004", "T1112"),
             _c(r"\breg(?:\.exe)?\s+add\b.*(?:\\image file execution options\\[^\"]+\"?\s+/v\s+debugger"
                r"|\\winlogon\"?\s+/v\s+(?:shell|userinit)\b|\\wdigest\"?\s+/v\s+uselogoncredential\s+.*/d\s+1"
                r"|\\windows defender\b.*/v\s+disable\w+\s+.*/d\s+1|\\lsa\"?\s+/v\s+(?:runasppl|disablerestrictedadmin)\b)")),
    TextRule("persist.schtasks_payload", "Creates a scheduled task that runs a script host or a user-folder file",
             "medium", "medium", ("T1053.005",),
             _c(rf"\bschtasks(?:\.exe)?\b.*/create\b.*/tr\s+.*(?:powershell|pwsh|mshta|wscript|cscript|rundll32|regsvr32"
                rf"|cmd(?:\.exe)?\s+/c|{_USERDIR})"), scope="cmdline"),
    TextRule("persist.service_payload", "Creates a service that runs a shell or a user-folder file", "high", "high",
             ("T1543.003", "T1569.002"),
             _c(rf"\bsc(?:\.exe)?\s+(?:\\\\\S+\s+)?create\s+\S+.*binpath\s*=\s*\"?(?:cmd|%comspec%|powershell|pwsh|mshta|rundll32"
                rf"|[a-z]:[^\"]*{_USERDIR})"), scope="cmdline"),
    TextRule("persist.sticky_keys", "Replaces an accessibility tool that runs before logon", "critical", "high",
             ("T1546.008",),
             _c(r"\b(?:copy|move|xcopy|takeown|icacls|ren)\b.*\\system32\\(?:sethc|utilman|osk|magnify|narrator|displayswitch|atbroker)\.exe")),
    TextRule("account.add", "Creates a local account or adds one to a privileged group", "high", "medium",
             ("T1136.001", "T1098"),
             _c(r"\bnet1?(?:\.exe)?\s+user\s+(?!/)\S+\s+(?:\S+\s+)?/add\b"
                r"|\bnet1?(?:\.exe)?\s+localgroup\s+\"?(?:administrators|remote desktop users|remote management users)\"?\s+\S+\s+/add\b"
                r"|\bnew-localuser\b|\badd-localgroupmember\b[^|;]*(?:administrators|remote desktop users)")),
    TextRule("remote.rdp_enable", "Enables Remote Desktop from the command line", "medium", "medium", ("T1021.001",),
             _c(r"\breg(?:\.exe)?\s+add\b.*\\terminal server\"?\s+/v\s+fdenytsconnections\b.*/d\s+0"
                r"|\bset-itemproperty\b[^|;]*fdenytsconnections[^|;]*\b0\b")),

    # ---------------------------------------------------------------- remote control, tunnels, shells
    TextRule("shell.reverse", "Reverse shell command", "critical", "high", ("T1059", "T1571"),
             _c(r"\bn(?:c|cat)(?:\.exe)?\b[^|&]*\s-(?:e|c)\s+\"?(?:cmd|powershell|pwsh|/bin/(?:ba)?sh)\b|\bncat(?:\.exe)?\b.*--(?:sh-)?exec\b"
                r"|\bsocat(?:\.exe)?\b.*\bexec:|\bbash\s+-i\s+>&?\s*/dev/tcp/"
                r"|\bpython[\d.]*(?:\.exe)?\"?\s+-c\s+.*\bsocket\b.*\b(?:subprocess|pty\.spawn|os\.dup2)\b")),
    TextRule("remote.lateral_tool", "Remote-execution tool command", "high", "medium", ("T1021.002", "T1569.002"),
             _c(r"\b(?:psexec(?:64)?|paexec)(?:\.exe)?\b.*\\\\[a-z0-9.-]+|\b(?:wmiexec|smbexec|atexec|dcomexec)(?:\.py|\.exe)?\b")),
    TextRule("tunnel.tool", "Tunnelling tool exposes this PC or relays traffic", "medium", "medium", ("T1572", "T1090"),
             _c(r"(?:^|[\\\"\s])(?:ngrok|chisel|frpc|rathole|localtonet|gost|iox|ligolo(?:-ng)?(?:-agent)?|revsocks|pwnat|bore)(?:\.exe)?\"?(?:\s|$)"
                r"|\bcloudflared(?:\.exe)?\"?\s+.*\btunnel\b|\b(?:ssh|plink)(?:\.exe)?\"?\s+[^|&]*-R\s*\S*\d"),
             scope="cmdline"),
    TextRule("net.portproxy", "Adds a port-forwarding rule", "medium", "low", ("T1090.001",),
             _c(r"\bnetsh(?:\.exe)?\s+interface\s+portproxy\s+add\b")),
    TextRule("miner.cmdline", "Cryptocurrency miner arguments", "high", "high", ("T1496",),
             _c(r"stratum\+(?:tcp|ssl|tls)://|--donate-level\b|(?:^|[\\\"\s])xmrig(?:\.exe)?\b"
                r"|--algo[= ]\s*(?:rx/|cn/|randomx|kawpow|ethash)"
                r"|\s-o\s+\S*(?:nanopool|minexmr|supportxmr|2miners|f2pool|nicehash|moneroocean)\S*:\d+")),
    TextRule("exfil.cloud_copy", "Bulk upload to a file-sharing or cloud service", "medium", "medium",
             ("T1567.002",),
             _c(r"\brclone(?:\.exe)?\"?\s+(?:copy|sync|move)\b.*\b[a-z0-9_-]+:"
                r"|\bcurl(?:\.exe)?\b.*(?:-T|--upload-file|-F\s+\S*=@).*(?:transfer\.sh|file\.io|gofile\.io|0x0\.st|temp\.sh|catbox\.moe|anonfiles)")),
]

RULES_BY_ID = {r.id: r for r in RULES}

_PS_IMAGE = re.compile(r"(?:^|[\\\"\s/])(?:powershell|pwsh)(?:_ise)?(?:\.exe)?\b", re.I)
_HIDDEN = re.compile(r"(?:^|\s)[-/]w(?:i(?:n(?:d(?:o(?:w(?:s(?:t(?:y(?:l(?:e)?)?)?)?)?)?)?)?)?)?\s+[\"']?(?:h(?:i(?:d(?:d(?:e(?:n)?)?)?)?)?|1)\b", re.I)
_NOPROFILE = re.compile(r"(?:^|\s)[-/]nop(?:r(?:o(?:f(?:i(?:l(?:e)?)?)?)?)?)?\b", re.I)
_BYPASS = re.compile(r"(?:^|\s)[-/]e(?:x(?:e(?:c(?:u(?:t(?:i(?:o(?:n(?:p(?:o(?:l(?:i(?:c(?:y)?)?)?)?)?)?)?)?)?)?)?)?)?|p)\s+[\"']?(?:bypass|unrestricted)\b", re.I)
_URL = re.compile(r"https?://[^\s'\"|)<>]+", re.I)


def normalise(text: str) -> str:
    """Undo the cheap obfuscation tricks: cmd carets, PowerShell backticks, split string literals."""
    if not text:
        return ""
    t = text.replace("^", "").replace("`", "")
    t = re.sub(r"[\"']\s*\+\s*[\"']", "", t)
    return re.sub(r"[ \t]+", " ", t)


def match_text(text: str, scope: str = "cmdline") -> list[Hit]:
    """Every rule that fires on `text` (a command line when scope is 'cmdline', else script text)."""
    if not text:
        return []
    norm = normalise(text)[:200000]
    hits: list[Hit] = []
    for r in RULES:
        if r.scope not in ("both", scope):
            continue
        m = r.pattern.search(norm)
        if not m:
            continue
        if r.unless and r.unless.search(norm):
            continue
        hits.append(Hit(r, truncate(m.group(0), 300)))
    return hits


def powershell_flags(cmdline: str) -> dict:
    """What a PowerShell command line asks for, including the decoded -EncodedCommand payload."""
    out = {"is_powershell": bool(_PS_IMAGE.search(cmdline or "")), "hidden": False, "noprofile": False,
           "bypass": False, "decoded": None}
    if not out["is_powershell"]:
        return out
    out["hidden"] = bool(_HIDDEN.search(cmdline))
    out["noprofile"] = bool(_NOPROFILE.search(cmdline))
    out["bypass"] = bool(_BYPASS.search(cmdline))
    out["decoded"] = decode_encoded_command(cmdline)
    return out


def analyse_command(cmdline: str) -> list[Hit]:
    """Rule hits for one command line. Looks inside -EncodedCommand payloads too."""
    hits = match_text(cmdline, "cmdline")
    flags = powershell_flags(cmdline)
    if flags["decoded"]:
        seen = {h.rule.id for h in hits}
        for h in match_text(flags["decoded"], "script"):
            if h.rule.id not in seen:
                h.decoded = True
                hits.append(h)
    return hits


def urls_in(text: str) -> list[str]:
    seen: list[str] = []
    for u in _URL.findall(normalise(text or "")):
        u = u.rstrip(".,;'\"")
        if u not in seen:
            seen.append(u)
    return seen[:10]


# Bootstrap scripts that well-known projects publish and tell people to pipe into PowerShell.
# The technique is the same one malware uses, so the command is still reported, but as low.
# Only an exact host-and-path match counts.
KNOWN_INSTALLERS = {
    "astral.sh/uv/install.ps1": "uv", "claude.ai/install.ps1": "Claude Code", "ollama.com/install.ps1": "Ollama",
    "get.scoop.sh": "Scoop", "community.chocolatey.org/install.ps1": "Chocolatey", "chocolatey.org/install.ps1": "Chocolatey",
    "bun.sh/install.ps1": "Bun", "deno.land/install.ps1": "Deno", "get.pnpm.io/install.ps1": "pnpm",
    "ohmyposh.dev/install.ps1": "Oh My Posh", "aka.ms/install-powershell.ps1": "PowerShell",
}
_BARE_URL = re.compile(r"(?:\birm\b|\biwr\b|invoke-restmethod|invoke-webrequest|\bcurl\b|\bwget\b)\s+(?:-\w+\s+)*['\"]?"
                       r"((?:https?://)?[a-z0-9.-]+\.[a-z]{2,}(?:/[^\s'\"|;)]*)?)", re.I)


def known_installer(text: str) -> str | None:
    """The project name when every address in a download-and-run command is a published installer."""
    norm = normalise(text or "")
    found = set(_URL.findall(norm)) | {m.group(1) for m in _BARE_URL.finditer(norm)}
    names = set()
    for u in found:
        key = re.sub(r"^https?://(?:www\.)?", "", u.lower()).rstrip("/.,;'\"")
        if key not in KNOWN_INSTALLERS:
            return None
        names.add(KNOWN_INSTALLERS[key])
    return ", ".join(sorted(names)) if names else None


# Remote-access products. Legitimate when you installed them; a favourite of intruders and
# tech-support scammers when you did not. Matched on the image name.
REMOTE_TOOLS = [
    (re.compile(r"^anydesk", re.I), "AnyDesk"),
    (re.compile(r"^teamviewer|^tv_[wx]\d\d", re.I), "TeamViewer"),
    (re.compile(r"^(?:screenconnect|connectwisecontrol)", re.I), "ScreenConnect"),
    (re.compile(r"^rustdesk", re.I), "RustDesk"),
    (re.compile(r"^(?:client32|pcicfgui)\.exe$", re.I), "NetSupport Manager"),
    (re.compile(r"^(?:srserver|srservice|srfeature|sragent|strwinclt)", re.I), "Splashtop"),
    (re.compile(r"^(?:logmein|lmiguardian|lmi_rescue)", re.I), "LogMeIn"),
    (re.compile(r"^(?:ateraagent|agentpackage)", re.I), "Atera"),
    (re.compile(r"^(?:winvnc|tvnserver|vncserver|uvnc_service|tightvnc)", re.I), "VNC server"),
    (re.compile(r"^(?:rserver3|radmin)", re.I), "Radmin"),
    (re.compile(r"^(?:rutserv|rfusclient)", re.I), "Remote Utilities"),
    (re.compile(r"^(?:aa_v3|ammyy)", re.I), "Ammyy Admin"),
    (re.compile(r"^dwagent|^dwagsvc", re.I), "DWService"),
    (re.compile(r"^meshagent", re.I), "MeshCentral agent"),
    (re.compile(r"^supremo", re.I), "Supremo"),
    (re.compile(r"^remoting_host\.exe$", re.I), "Chrome Remote Desktop"),
    (re.compile(r"^parsecd?\.exe$", re.I), "Parsec"),
    (re.compile(r"^(?:quickassist|msra)\.exe$", re.I), "Windows Quick Assist / Remote Assistance"),
    (re.compile(r"^(?:zohoassist|za_connect|zaservice)", re.I), "Zoho Assist"),
    (re.compile(r"^(?:simplehelp|remote access-windows)", re.I), "SimpleHelp"),
    (re.compile(r"^(?:tailscaled?|tailscale-ipn)\.exe$", re.I), "Tailscale"),
    (re.compile(r"^(?:zerotier)", re.I), "ZeroTier"),
    (re.compile(r"^(?:sshd)\.exe$", re.I), "OpenSSH server"),
]


def remote_tool(image_name: str) -> str | None:
    for rx, product in REMOTE_TOOLS:
        if rx.search(image_name or ""):
            return product
    return None
