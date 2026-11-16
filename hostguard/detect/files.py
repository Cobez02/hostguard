"""Rules over files found on disk (see collect.files for the fact format)."""

from __future__ import annotations

import os
import re
import time

from .. import pe, sigs, util
from ..model import Finding
from . import cmdline as cl
from . import content
from .persistence import ABUSABLE_DRIVERS
from .processes import BROWSERS, SYSTEM_IMAGES, double_extension

DAY = 86400.0
_SIG = {s.id: s for s in content.SIGNATURES}
_SHELL_HOSTS = {"cmd.exe", "powershell.exe", "pwsh.exe", "mshta.exe", "wscript.exe", "cscript.exe", "rundll32.exe",
                "regsvr32.exe", "msiexec.exe", "forfiles.exe", "conhost.exe", "bitsadmin.exe", "certutil.exe", "curl.exe",
                "ssh.exe", "explorer.exe"}
_DELIVERY_SCRIPTS = {".hta", ".sct", ".jse", ".vbe", ".wsf", ".wsh"}
_DISGUISE_AS = {".jpg", ".jpeg", ".png", ".gif", ".bmp", ".pdf", ".txt", ".mp3", ".mp4", ".csv", ".ico", ".xml", ".json"}
_INTERNET_ZONES = (3, 4)


def _origin(fact: dict) -> str:
    m = fact.get("motw") or {}
    url = m.get("host_url") or m.get("referrer_url") or ""
    host = re.match(r"^[a-z]+://([^/]+)", url, re.I)
    return host.group(1) if host else ""


def _from_internet(fact: dict) -> bool:
    return (fact.get("motw") or {}).get("zone") in _INTERNET_ZONES


def _evidence(fact: dict, sig: dict | None = None) -> dict:
    ev = {"path": fact["path"], "size": fact["size"], "modified": util.iso(fact.get("modified")),
          "created": util.iso(fact.get("created")), "sha256": fact.get("sha256")}
    if fact.get("type") == "pe":
        ev["signature"] = sigs.describe(sig)
    m = fact.get("motw")
    if m:
        ev["downloaded_from"] = m.get("host_url") or m.get("referrer_url") or f"internet zone {m.get('zone')}"
        if m.get("referrer_url") and m.get("host_url"):
            ev["linked_from"] = m["referrer_url"]
    return {k: v for k, v in ev.items() if v not in (None, "")}


def detect(facts: dict, sig_map: dict[str, dict], ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    now = time.time()
    out: list[Finding] = []
    old_unsigned: list[str] = []

    def add(fact, rule, title, sev, conf, desc, mitre=(), extra=None, sig=None, key_extra=(), actions=("quarantine",), tags=()):
        ev = _evidence(fact, sig)
        if extra:
            ev.update(extra)
        out.append(Finding(rule=rule, title=title, severity=sev, confidence=conf, category="file", description=desc,
                           evidence=ev, entity={"type": "file", "path": fact["path"], "sha256": fact.get("sha256")},
                           mitre=list(mitre), actions=list(actions), collector="files", tags=list(tags),
                           key_parts=(fact["path"], fact.get("sha256") or fact["size"], *key_extra)))

    for fact in facts.get("files") or []:
        name, ext, zone, path = fact["name"], fact["ext"], fact.get("zone"), fact["path"]
        sig = sigs.lookup(sig_map, path) if fact.get("type") == "pe" else None
        origin = _origin(fact)
        internet = _from_internet(fact)
        recent = (now - (fact.get("created") or fact.get("modified") or 0)) < 90 * DAY

        for sid in fact.get("signatures") or []:
            s = _SIG.get(sid)
            if not s:
                continue
            add(fact, "file.sig." + s.id, f"{s.title}: {name}", s.severity, "high" if s.need > 1 or s.id == "eicar" else "medium",
                f"The file contains byte patterns typical of {s.family or 'a known tool'}."
                + (" This is the harmless industry test file, not real malware." if s.id == "eicar" else ""),
                ("T1588.002",), sig=sig, key_extra=(s.id,), tags=("test",) if s.id == "eicar" else ())

        if "‮" in name:
            add(fact, "file.name.rtlo", f"File name uses a right-to-left override to hide its real extension: {name!r}", "high",
                "high", "The name contains an invisible character that makes Windows display it backwards, so "
                "'gpj.exe' can look like 'exe.jpg'.", ("T1036.002",), sig=sig)
        elif double_extension(name):
            add(fact, "file.name.double_extension", f"Program disguised with a document extension: {name}", "high", "high",
                "The real extension is hidden when Windows hides known file types.", ("T1036.007",), sig=sig)

        if fact.get("type") == "pe":
            summary = fact.get("pe") or {}
            pts, why = pe.score(summary) if summary else (0, [])
            untrusted = sigs.lacks_trust(sig)
            if fact.get("disguised") and ext in _DISGUISE_AS:
                add(fact, "file.pe.disguised", f"A program with a {ext} extension: {name}", "high" if untrusted else "medium",
                    "medium", "The file is a Windows executable but is named as if it were a picture or document. "
                    "Loaders store their payload this way.", ("T1036.008",), sig=sig)
            if name.lower() in SYSTEM_IMAGES and zone != "windows" and not sigs.is_microsoft(sig) and sig and sig["status"] != "Missing":
                add(fact, "file.pe.masquerade", f"A file named like the Windows component {name} outside the Windows folder", "high",
                    "medium", "Its name suggests a core Windows program, but Microsoft did not sign it.", ("T1036.005",), sig=sig)
            if sigs.is_tampered(sig):
                add(fact, "file.pe.tampered", f"Signed program modified after signing: {name}", "high", "medium",
                    "The publisher's signature no longer matches the file.", ("T1554",), sig=sig)
            if ext == ".sys" and zone in util.USER_WRITABLE:
                abusable = name.lower() in ABUSABLE_DRIVERS
                add(fact, "file.pe.driver_in_user_folder", f"Kernel driver file in a user folder: {name}", "high" if abusable else "medium",
                    "low", "Drivers live in the Windows driver store. One sitting in a user folder is being staged."
                    + (" This one is a known abusable driver." if abusable else ""), ("T1068",), sig=sig)
            if untrusted and zone in util.USER_WRITABLE:
                if pts >= 3:
                    sev = "high" if (internet or zone in util.HIGH_RISK) and recent else "medium"
                    add(fact, "file.pe.suspicious_unsigned", f"Unsigned program built to hide or inject: {name}", sev, "medium",
                        "Nobody signed it and it " + "; ".join(why) + ".", ("T1027.002", "T1055"), sig=sig,
                        extra={"indicators": why, "pe": {k: summary.get(k) for k in ("kind", "bits", "packer", "sections", "import_count")}})
                elif internet and recent and ext in (".exe", ".scr", ".com", ".pif", ".msi", ".dll"):
                    add(fact, "file.pe.unsigned_download", f"Unsigned program downloaded from the internet: {name}", "low", "low",
                        "No publisher vouches for it. Small open-source tools look like this; so does most malware. "
                        "Listed so you can confirm you meant to download it." + (f" It came from {origin}." if origin else ""),
                        ("T1204.002",), sig=sig)
                elif internet and ext in (".exe", ".scr", ".com", ".pif", ".msi"):
                    old_unsigned.append(path)

        elif fact.get("type") == "script":
            for h in cl.match_text(fact.get("text") or "", "script"):
                add(fact, "file.script." + h.rule.id, f"Script that {h.rule.title.lower()}: {name}", h.rule.severity,
                    "medium", (h.rule.why + " " if h.rule.why else "") + "The script is on disk; whether it ran is a "
                    "separate question the process and log checks answer.", h.rule.mitre, key_extra=(h.rule.id,),
                    extra={"matched": h.match, "urls": cl.urls_in(fact.get("text") or "")})
            if ext in _DELIVERY_SCRIPTS and internet:
                add(fact, "file.script.delivery_type", f"Downloaded {ext} file: {name}", "medium", "medium",
                    f"{ext} files run with full user rights when double-clicked and have almost no use today "
                    "except delivering malware." + (f" It came from {origin}." if origin else ""), ("T1204.002", "T1059"))

        elif fact.get("type") == "lnk":
            link = fact.get("lnk") or {}
            target, args = link.get("target") or "", link.get("args") or ""
            base = util.basename(target)
            command = f"{target} {args}".strip()
            if base in _SHELL_HOSTS and args:
                hits = cl.analyse_command(command)
                if hits:
                    add(fact, "file.lnk.payload", f"Shortcut that {hits[0].rule.title.lower()}: {name}", "high", "high",
                        "Opening this shortcut runs the command, not a document.", hits[0].rule.mitre + ("T1204.002", "T1547.009"),
                        extra={"target": target, "arguments": util.truncate(args, 900), "matched": hits[0].match})
                elif len(args) > 180 or re.search(r"https?://|\\\\[a-z0-9.-]+\\", args, re.I):
                    add(fact, "file.lnk.script_host", f"Shortcut runs {base} with a long or remote argument: {name}", "medium",
                        "medium", "Shortcut files are a common phishing attachment because the icon can be anything.",
                        ("T1204.002",), extra={"target": target, "arguments": util.truncate(args, 900)})
            elif base in BROWSERS and re.search(r"--(?:load-extension|proxy-server|proxy-pac-url|remote-debugging-port|disable-web-security)|https?://", args, re.I):
                add(fact, "file.lnk.browser_tampered", f"Browser shortcut carries extra switches: {name}", "medium", "low",
                    "Adware and stealers rewrite browser shortcuts to force an extension, a proxy or a start page.",
                    ("T1176", "T1547.009"), extra={"target": target, "arguments": util.truncate(args, 600)}, actions=())

        elif fact.get("type") == "url":
            text = fact.get("text") or ""
            m = re.search(r"^(?:URL|IconFile)\s*=\s*(\\\\[^\r\n]+|file:[^\r\n]+)", text, re.I | re.M)
            if m:
                add(fact, "file.url.remote_file", f"Internet shortcut points at a network share or local file: {name}", "medium",
                    "medium", "Opening the folder that holds it is enough for Windows to contact that address and offer "
                    "your logon hash.", ("T1187",), extra={"points_to": util.truncate(m.group(1), 300)})

        elif fact.get("type") == "office":
            if fact.get("macros") and internet:
                add(fact, "file.office.macro_download", f"Downloaded Office file with macros: {name}", "medium", "medium",
                    "Macros are programs. Office blocks them in files from the internet unless someone unblocks the file."
                    + (f" It came from {origin}." if origin else ""), ("T1204.002", "T1566.001"))

        elif fact.get("type") == "disk_image":
            add(fact, "file.disk_image_download", f"Downloaded disk image: {name}", "low", "low",
                "Files inside a mounted image lose the 'downloaded from the internet' mark, which is why malware is "
                "shipped in them." + (f" It came from {origin}." if origin else ""), ("T1553.005",))
        elif fact.get("type") in ("jar", "chm", "one", "appinstaller", "application", "xll", "wll") and internet:
            add(fact, "file.risky_type_download", f"Downloaded {ext} file: {name}", "low", "low",
                "This file type can run code when opened." + (f" It came from {origin}." if origin else ""), ("T1204.002",))

    if old_unsigned:
        out.append(Finding(rule="file.pe.unsigned_download_old", title=f"{len(old_unsigned)} older unsigned program(s) downloaded from the internet",
                           severity="info", confidence="low", category="file", collector="files",
                           description="Downloaded more than 90 days ago and never signed by a publisher. Listed for housekeeping.",
                           evidence={"files": old_unsigned[:40]}, key_parts=("old-unsigned",)))
    return out


def suspects(facts: dict, findings: list[Finding], limit: int = 40) -> list[str]:
    """Files worth a second opinion from Defender's on-demand scanner."""
    seen: list[str] = []
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
    for f in sorted(findings, key=lambda x: order[x.severity]):
        p = (f.entity or {}).get("path")
        if p and f.category == "file" and f.severity in ("critical", "high", "medium") and p not in seen and os.path.isfile(p):
            seen.append(p)
    return seen[:limit]
