"""Security settings and system-wide configuration: Defender, accounts, trusted roots, hardening
values, the hosts file, proxies, and the commands a person recently typed or pasted."""

from __future__ import annotations

import os
import re

from .. import paths, reg, util

_POL_SYSTEM = r"SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
_TS = r"SYSTEM\CurrentControlSet\Control\Terminal Server"
_LSA = r"SYSTEM\CurrentControlSet\Control\Lsa"
_DEF_POL = r"SOFTWARE\Policies\Microsoft\Windows Defender"
_UNINSTALL = r"Software\Microsoft\Windows\CurrentVersion\Uninstall"
_INET = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
_REMOTE_NAMES = re.compile(
    r"anydesk|teamviewer|screenconnect|connectwise control|rustdesk|netsupport|splashtop|logmein|atera|"
    r"\bvnc\b|ultravnc|tightvnc|realvnc|radmin|remote utilities|ammyy|dwservice|dwagent|meshcentral|mesh agent|"
    r"supremo|chrome remote desktop|parsec|zoho assist|simplehelp|tailscale|zerotier|ngrok|remotepc|"
    r"gotomypc|goto resolve|bomgar|beyondtrust remote|iperius remote|aeroadmin|getscreen|hoptodesk", re.I)


def posture_registry() -> dict:
    g = lambda path, name, root=reg.HKLM: reg.get(root, path, name)  # noqa: E731
    start_opts = str(g(r"SYSTEM\CurrentControlSet\Control", "SystemStartOptions") or "")
    fw_pol = {}
    for prof in ("DomainProfile", "StandardProfile", "PublicProfile", "PrivateProfile"):
        v = g(rf"SOFTWARE\Policies\Microsoft\WindowsFirewall\{prof}", "EnableFirewall")
        if v is not None:
            fw_pol[prof] = v
    rtp = reg.values(reg.HKLM, _DEF_POL + r"\Real-Time Protection")
    return {
        "uac": {k: g(_POL_SYSTEM, k) for k in ("EnableLUA", "ConsentPromptBehaviorAdmin", "PromptOnSecureDesktop",
                                                 "LocalAccountTokenFilterPolicy", "FilterAdministratorToken")},
        "rdp": {"deny": g(_TS, "fDenyTSConnections"), "nla": g(_TS + r"\WinStations\RDP-Tcp", "UserAuthentication"),
                "port": g(_TS + r"\WinStations\RDP-Tcp", "PortNumber"),
                "assist": g(r"SYSTEM\CurrentControlSet\Control\Remote Assistance", "fAllowToGetHelp")},
        "lsa": {k: g(_LSA, k) for k in ("RunAsPPL", "RunAsPPLBoot", "DisableRestrictedAdmin", "LmCompatibilityLevel",
                                        "NoLMHash", "LimitBlankPasswordUse")},
        "wdigest": g(r"SYSTEM\CurrentControlSet\Control\SecurityProviders\WDigest", "UseLogonCredential"),
        "smb1_server": g(r"SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters", "SMB1"),
        "smb1_client_start": g(r"SYSTEM\CurrentControlSet\Services\mrxsmb10", "Start"),
        "always_install_elevated": [g(r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated"),
                                    g(r"SOFTWARE\Policies\Microsoft\Windows\Installer", "AlwaysInstallElevated", reg.HKCU)],
        "ps_scriptblock_logging": g(r"SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging", "EnableScriptBlockLogging"),
        "proc_cmdline_audit": g(_POL_SYSTEM + r"\Audit", "ProcessCreationIncludeCmdLine_Enabled"),
        "defender_policy": {
            "DisableAntiSpyware": g(_DEF_POL, "DisableAntiSpyware"), "DisableAntiVirus": g(_DEF_POL, "DisableAntiVirus"),
            "DisableRealtimeMonitoring": rtp.get("DisableRealtimeMonitoring"),
            "DisableBehaviorMonitoring": rtp.get("DisableBehaviorMonitoring"),
            "DisableOnAccessProtection": rtp.get("DisableOnAccessProtection"),
            "DisableScanOnRealtimeEnable": rtp.get("DisableScanOnRealtimeEnable"),
            "DisableIOAVProtection": rtp.get("DisableIOAVProtection"),
            "policy_exclusions": {k: list(reg.values(reg.HKLM, _DEF_POL + "\\Exclusions\\" + k))
                                  for k in ("Paths", "Processes", "Extensions")},
        },
        "firewall_policy": fw_pol,
        "wu_no_auto_update": g(r"SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU", "NoAutoUpdate"),
        "vbs": g(r"SYSTEM\CurrentControlSet\Control\DeviceGuard", "EnableVirtualizationBasedSecurity"),
        "hvci": g(r"SYSTEM\CurrentControlSet\Control\DeviceGuard\Scenarios\HypervisorEnforcedCodeIntegrity", "Enabled"),
        "driver_blocklist": g(r"SYSTEM\CurrentControlSet\Control\CI\Config", "VulnerableDriverBlocklistEnable"),
        "smartscreen": g(r"SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer", "SmartScreenEnabled"),
        "smartscreen_policy": g(r"SOFTWARE\Policies\Microsoft\Windows\System", "EnableSmartScreen"),
        "autologon": {"enabled": g(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "AutoAdminLogon"),
                      "password_stored": g(r"SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon", "DefaultPassword") is not None},
        "test_signing": "TESTSIGNING" in start_opts.upper(),
        "kernel_debug": bool(re.search(r"\bDEBUG\b", start_opts.upper())),
        "pending_reboot": reg.exists(reg.HKLM, r"SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired"),
        "wsh_enabled": g(r"SOFTWARE\Microsoft\Windows Script Host\Settings", "Enabled"),
    }


def root_certificates() -> list[dict]:
    """Trusted root certificates with where each one physically lives.

    Roots that Microsoft's programme distributes sit in AuthRoot. A root in your own account's
    store, or one added to the machine store by hand, was installed by a person or a program on
    this PC, and whoever holds its private key can read your HTTPS traffic.
    """
    stores = {
        "user": (reg.HKCU, r"Software\Microsoft\SystemCertificates\Root\Certificates"),
        "machine": (reg.HKLM, r"SOFTWARE\Microsoft\SystemCertificates\ROOT\Certificates"),
        "authroot": (reg.HKLM, r"SOFTWARE\Microsoft\SystemCertificates\AuthRoot\Certificates"),
        "policy": (reg.HKLM, r"SOFTWARE\Policies\Microsoft\SystemCertificates\Root\Certificates"),
        "user_policy": (reg.HKCU, r"Software\Policies\Microsoft\SystemCertificates\Root\Certificates"),
        "enterprise": (reg.HKLM, r"SOFTWARE\Microsoft\EnterpriseCertificates\Root\Certificates"),
    }
    where: dict[str, dict] = {}
    for label, (root, path) in stores.items():
        for thumb in reg.subkeys(root, path):
            entry = where.setdefault(thumb.upper(), {"stores": [], "installed": None})
            entry["stores"].append(label)
            if label in ("user", "machine", "policy", "user_policy", "enterprise"):
                entry["installed"] = entry["installed"] or reg.modified(root, path + "\\" + thumb)
    out = []
    seen = set()
    for c in util.as_list(util.run_ps("certs", timeout=60)):
        thumb = (c.get("thumbprint") or "").upper()
        if not thumb or thumb in seen:
            continue
        seen.add(thumb)
        info = where.get(thumb, {"stores": [], "installed": None})
        out.append({"thumbprint": thumb, "subject": c.get("subject") or "", "issuer": c.get("issuer") or "",
                    "not_before": c.get("notbefore"), "not_after": c.get("notafter"), "name": c.get("name") or "",
                    "stores": info["stores"], "installed": info["installed"]})
    return out


def hosts_file() -> dict:
    path = os.path.join(paths.SYSTEM32, r"drivers\etc\hosts")
    entries = []
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.split("#", 1)[0].strip()
                parts = line.split()
                if len(parts) >= 2:
                    entries.append({"ip": parts[0], "names": parts[1:]})
        mtime = os.stat(path).st_mtime
    except OSError as e:
        return {"path": path, "entries": [], "error": str(e)}
    return {"path": path, "entries": entries, "modified": mtime}


def proxy_settings() -> dict:
    out = {}
    for label, root in (("user", reg.HKCU), ("machine", reg.HKLM)):
        v = reg.values(root, _INET)
        out[label] = {"enabled": bool(v.get("ProxyEnable")), "server": reg.text(v.get("ProxyServer")),
                      "pac": reg.text(v.get("AutoConfigURL")), "override": reg.text(v.get("ProxyOverride"))}
    pol = reg.values(reg.HKLM, r"SOFTWARE\Policies\Microsoft\Windows\CurrentVersion\Internet Settings")
    out["policy"] = {"enabled": bool(pol.get("ProxyEnable")), "server": reg.text(pol.get("ProxyServer")),
                     "pac": reg.text(pol.get("AutoConfigURL"))}
    env = reg.values(reg.HKCU, "Environment")
    out["env"] = {k: reg.text(v) for k, v in env.items() if k.upper() in ("HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY")}
    return out


def typed_commands(history_lines: int = 4000) -> dict:
    """What was typed or pasted into the Run box, the Explorer address bar and PowerShell.

    A fake CAPTCHA page that tells someone to press Win+R and paste a command ("ClickFix") leaves
    the command here.
    """
    run = []
    for name, data in reg.values(reg.HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\RunMRU").items():
        if name.lower() != "mrulist" and isinstance(data, str):
            run.append(data[:-2] if data.endswith("\\1") else data)
    typed = [str(v) for v in reg.values(reg.HKCU, r"Software\Microsoft\Windows\CurrentVersion\Explorer\TypedPaths").values()
             if isinstance(v, str)]
    hist_path = os.path.join(os.environ.get("APPDATA", ""), r"Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt")
    history: list[str] = []
    try:
        with open(hist_path, "r", encoding="utf-8", errors="replace") as f:
            history = [ln.rstrip("\r\n") for ln in f.readlines()[-history_lines:]]
    except OSError:
        pass
    return {"run_box": run, "address_bar": typed, "ps_history": history, "ps_history_path": hist_path}


def installed_software() -> list[dict]:
    out, seen = [], set()
    for root, view in ((reg.HKLM, reg.V64), (reg.HKLM, reg.V32), (reg.HKCU, reg.V64)):
        for sub in reg.subkeys(root, _UNINSTALL, view):
            v = reg.values(root, _UNINSTALL + "\\" + sub, view)
            name = reg.text(v.get("DisplayName")).strip()
            if not name or name.lower() in seen:
                continue
            seen.add(name.lower())
            out.append({"name": name, "publisher": reg.text(v.get("Publisher")), "version": reg.text(v.get("DisplayVersion")),
                        "installed": reg.text(v.get("InstallDate")), "location": reg.text(v.get("InstallLocation")),
                        "remote_access": bool(_REMOTE_NAMES.search(name))})
    return out


def browser_policies() -> list[dict]:
    """Extensions forced on a browser by policy. On a home PC nothing should be here: adware and
    stealers use these keys so the extension cannot be removed."""
    out = []
    targets = [("Chrome", r"SOFTWARE\Policies\Google\Chrome"), ("Edge", r"SOFTWARE\Policies\Microsoft\Edge"),
               ("Brave", r"SOFTWARE\Policies\BraveSoftware\Brave"), ("Chromium", r"SOFTWARE\Policies\Chromium")]
    for browser, base in targets:
        for root in (reg.HKLM, reg.HKCU):
            for name, data in reg.values(root, base + r"\ExtensionInstallForcelist").items():
                out.append({"browser": browser, "scope": reg.ROOT_NAMES[root], "policy": "ExtensionInstallForcelist",
                            "value": reg.text(data)})
            vals = reg.values(root, base)
            for key in ("ProxyServer", "ProxyPacUrl", "HomepageLocation", "DefaultSearchProviderSearchURL",
                        "RemoteDebuggingAllowed"):
                if key in vals and reg.text(vals[key]):
                    out.append({"browser": browser, "scope": reg.ROOT_NAMES[root], "policy": key, "value": reg.text(vals[key])})
    for root in (reg.HKLM, reg.HKCU):
        for name, data in reg.values(root, r"SOFTWARE\Policies\Mozilla\Firefox\Extensions\Install").items():
            out.append({"browser": "Firefox", "scope": reg.ROOT_NAMES[root], "policy": "Extensions\\Install", "value": reg.text(data)})
    return out


def collect(log=None) -> dict:
    facts: dict = {"gaps": []}
    for key, what, timeout in (("system", "system", 120), ("defender", "defender", 120), ("accounts", "accounts", 60)):
        try:
            facts[key] = util.run_ps(what, timeout=timeout) or {}
        except util.CollectError as e:
            facts[key] = {}
            facts["gaps"].append(str(e))
    try:
        facts["certs"] = root_certificates()
    except util.CollectError as e:
        facts["certs"] = []
        facts["gaps"].append(str(e))
    facts["registry"] = posture_registry()
    facts["hosts"] = hosts_file()
    facts["proxy"] = proxy_settings()
    facts["typed"] = typed_commands()
    facts["software"] = installed_software()
    facts["browser_policies"] = browser_policies()
    if log:
        log(f"system: {len(facts['certs'])} roots, {len(facts['software'])} programs, "
            f"{len(facts['typed']['ps_history'])} PowerShell history lines")
    return facts
