"""Browser extensions: what is installed, where it came from and how much it can see.

A malicious extension needs no malware on disk at all, so no antivirus scan finds it. This reads
each browser profile's own records (nothing is changed).
"""

from __future__ import annotations

import json
import os

from .. import util
from ..model import Finding

_CHROMIUM = [("Chrome", "LOCALAPPDATA", r"Google\Chrome\User Data"), ("Edge", "LOCALAPPDATA", r"Microsoft\Edge\User Data"),
             ("Brave", "LOCALAPPDATA", r"BraveSoftware\Brave-Browser\User Data"), ("Vivaldi", "LOCALAPPDATA", r"Vivaldi\User Data"),
             ("Chromium", "LOCALAPPDATA", r"Chromium\User Data"), ("Opera", "APPDATA", r"Opera Software\Opera Stable")]
_LOCATION = {1: "store", 2: "external (preferences file)", 3: "external (registry)", 4: "unpacked folder", 5: "built in",
             6: "external download", 7: "policy", 8: "command line", 9: "policy", 10: "built in"}
_ALL_SITES = ("<all_urls>", "*://*/*", "http://*/*", "https://*/*", "file:///*")
_STORES = ("clients2.google.com/service/update2/crx", "edge.microsoft.com/extensionwebstorebase/", "extensions.brave.com",
           "extension-updates.opera.com", "update.vivaldi.com")
_POWERFUL = {"cookies", "webRequest", "webRequestBlocking", "debugger", "proxy", "nativeMessaging", "management",
             "clipboardRead", "history", "declarativeNetRequest", "scripting", "downloads", "privacy", "browsingData",
             "desktopCapture", "tabCapture"}


def _load(path: str):
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as f:
            return json.load(f)
    except (OSError, ValueError):
        return None


def _message(ext_dir: str, manifest: dict, value: str) -> str:
    if not (isinstance(value, str) and value.startswith("__MSG_")):
        return value if isinstance(value, str) else ""
    key = value[6:-2].lower()
    for loc in (manifest.get("default_locale") or "en", "en", "en_US"):
        data = _load(os.path.join(ext_dir, "_locales", loc, "messages.json")) or {}
        for k, v in data.items():
            if k.lower() == key and isinstance(v, dict):
                return str(v.get("message") or value)
    return value


def _chromium_profile(browser: str, profile_dir: str) -> list[dict]:
    out = []
    settings: dict = {}
    for fname in ("Secure Preferences", "Preferences"):
        data = _load(os.path.join(profile_dir, fname)) or {}
        ext = (data.get("extensions") or {}).get("settings") or {}
        for k, v in ext.items():
            if isinstance(v, dict):
                settings.setdefault(k, {}).update(v)
    for ext_id, s in settings.items():
        loc = s.get("location")
        if loc in (5, 10) or s.get("was_installed_by_default") and loc == 5:
            continue
        manifest = s.get("manifest") if isinstance(s.get("manifest"), dict) else None
        path = str(s.get("path") or "")
        ext_dir = path if os.path.isabs(path) else os.path.join(profile_dir, "Extensions", path)
        if manifest is None:
            manifest = _load(os.path.join(ext_dir, "manifest.json")) or {}
        if not manifest and not path:
            continue
        perms = [p for p in (manifest.get("permissions") or []) if isinstance(p, str)]
        hosts = [p for p in (manifest.get("host_permissions") or []) if isinstance(p, str)] + [p for p in perms if "://" in p or p == "<all_urls>"]
        for cs in manifest.get("content_scripts") or []:
            if isinstance(cs, dict):
                hosts += [m for m in (cs.get("matches") or []) if isinstance(m, str)]
        granted = s.get("active_permissions") or {}
        hosts += [h for h in (granted.get("explicit_host") or []) + (granted.get("scriptable_host") or []) if isinstance(h, str)]
        name = _message(ext_dir, manifest, manifest.get("name") or "") or ext_id
        out.append({"browser": browser, "profile": os.path.basename(profile_dir), "id": ext_id, "name": name,
                    "version": manifest.get("version") or "", "location": loc, "source": _LOCATION.get(loc, f"unknown ({loc})"),
                    "from_store": bool(s.get("from_webstore")), "enabled": s.get("state", 1) == 1 and not s.get("disable_reasons"),
                    "path": ext_dir, "all_sites": any(h in _ALL_SITES for h in hosts),
                    "powerful": sorted(set(perms) & _POWERFUL), "update_url": manifest.get("update_url") or "",
                    "default_install": bool(s.get("was_installed_by_default") or s.get("was_installed_by_oem"))})
    return out


def collect(log=None) -> dict:
    exts: list[dict] = []
    for browser, env, rel in _CHROMIUM:
        base = os.path.join(os.environ.get(env, ""), rel)
        if not os.path.isdir(base):
            continue
        profiles = [base] if browser == "Opera" else []
        if browser != "Opera":
            try:
                profiles = [e.path for e in os.scandir(base) if e.is_dir() and (e.name == "Default" or e.name.startswith("Profile "))]
            except OSError:
                profiles = []
        for prof in profiles:
            exts += _chromium_profile(browser, prof)
    ff = os.path.join(os.environ.get("APPDATA", ""), r"Mozilla\Firefox\Profiles")
    if os.path.isdir(ff):
        for e in os.scandir(ff):
            data = _load(os.path.join(e.path, "extensions.json")) or {}
            for a in data.get("addons") or []:
                if not isinstance(a, dict) or a.get("type") != "extension" or str(a.get("location", "")).startswith("app-builtin") \
                        or a.get("location") in ("app-system-defaults", "app-builtin-addons"):
                    continue
                if str(a.get("id", "")).endswith(("@mozilla.org", "@mozilla.com", "@search.mozilla.org")) \
                        and (a.get("signedState") in (2, 3, 4) or "archive.mozilla.org/pub/system-addons/" in str(a.get("sourceURI") or "")):
                    continue  # components Mozilla ships and updates itself
                perms = (a.get("userPermissions") or {})
                origins = [o for o in (perms.get("origins") or []) if isinstance(o, str)]
                exts.append({"browser": "Firefox", "profile": e.name, "id": a.get("id") or "", "name": (a.get("defaultLocale") or {}).get("name") or a.get("id") or "",
                             "version": a.get("version") or "", "location": a.get("location"), "source": str(a.get("location")),
                             "from_store": "addons.mozilla.org" in str(a.get("sourceURI") or ""), "enabled": bool(a.get("active")),
                             "path": a.get("path") or "", "all_sites": any(o in _ALL_SITES for o in origins),
                             "powerful": sorted(set(perms.get("permissions") or []) & _POWERFUL),
                             "signed_state": a.get("signedState"), "temporary": bool(a.get("temporarilyInstalled")),
                             "source_uri": a.get("sourceURI") or "", "default_install": False})
    if log:
        log(f"browser extensions: {len(exts)}")
    return {"extensions": exts}


def detect(facts: dict, ctx: dict | None = None) -> list[Finding]:
    out: list[Finding] = []
    broad: list[str] = []
    for x in facts.get("extensions") or []:
        if not x.get("enabled"):
            continue
        ev = {k: x.get(k) for k in ("browser", "profile", "name", "id", "version", "source", "path", "powerful", "all_sites", "update_url", "source_uri")}
        ev = {k: v for k, v in ev.items() if v not in (None, "", [])}
        label = f"{x['browser']} extension '{x['name']}'"
        key = (x["browser"], x["profile"], x["id"])
        reach = " It can read and change every site you visit." if x.get("all_sites") else ""
        if x["browser"] == "Firefox":
            if x.get("temporary") or (x.get("signed_state") is not None and x["signed_state"] < 1):
                out.append(Finding(rule="browser.ext.unsigned", title=f"{label} is not signed by Mozilla", severity="medium",
                                   confidence="medium", category="browser", collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="Release versions of Firefox refuse unsigned extensions, so this one was loaded by "
                                               "a developer option or another program." + reach))
            elif not x.get("from_store") and x.get("source_uri"):
                out.append(Finding(rule="browser.ext.sideloaded", title=f"{label} was installed from outside addons.mozilla.org", severity="low",
                                   confidence="low", category="browser", collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="It did not come through Mozilla's store listing." + reach))
        else:
            loc = x.get("location")
            store_listed = x.get("from_store") or any(s in str(x.get("update_url") or "") for s in _STORES)
            if loc in (7, 9):
                out.append(Finding(rule="browser.ext.policy", title=f"{label} is force-installed by policy", severity="high", confidence="medium",
                                   category="browser", collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="You cannot remove it from the browser. On a home PC no policy should exist; adware "
                                               "and stealers create one so their extension survives." + reach))
            elif loc in (4, 8):
                temp = util.path_zone(x.get("path") or "") in util.HIGH_RISK
                out.append(Finding(rule="browser.ext.unpacked", title=f"{label} is loaded from a folder, not from the store",
                                   severity="high" if temp else "medium", confidence="medium" if temp else "low", category="browser",
                                   collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="Developers load their own extensions this way. Malware does it too, because an "
                                               "unpacked extension is never reviewed by the store." + reach,
                                   entity={"type": "file", "path": x.get("path") or ""}))
            elif loc in (2, 3, 6) and not x.get("default_install"):
                out.append(Finding(rule="browser.ext.external", title=f"{label} was added by another program",
                                   severity="low" if store_listed else "medium",
                                   confidence="low", category="browser", collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="An installer registered it with the browser. Antivirus suites and PDF tools do "
                                               "this; so do bundled adware installers."
                                               + (" It updates from the browser's store, so the store has reviewed it." if store_listed else "")
                                               + reach))
            elif loc == 1 and not store_listed and not x.get("default_install"):
                out.append(Finding(rule="browser.ext.not_from_store", title=f"{label} did not come from the browser's store", severity="medium",
                                   confidence="low", category="browser", collector="browsers", evidence=ev, mitre=["T1176"], key_parts=key,
                                   description="It is installed like a store extension but the browser has no store record for it." + reach))
        if x.get("all_sites") and x.get("powerful"):
            broad.append(f"{x['browser']} / {x['profile']}: {x['name']} ({', '.join(x['powerful'][:5])})")
    if broad:
        out.append(Finding(rule="browser.ext.broad_access", title=f"{len(broad)} browser extension(s) can read every site you visit",
                           severity="info", confidence="low", category="browser", collector="browsers",
                           description="Not a finding by itself: password managers and ad blockers need this access. It is the "
                                       "list to check first if an account is ever taken over, because an extension that is "
                                       "sold or hijacked keeps its permissions.",
                           evidence={"extensions": broad[:40]}, mitre=["T1176"], key_parts=("broad",)))
    return out


def inventory(facts: dict) -> dict[str, dict]:
    return {f"{x['browser']}|{x['profile']}|{x['id']}": {"name": x["name"], "browser": x["browser"], "version": x["version"],
                                                        "source": x["source"]}
            for x in facts.get("extensions") or [] if x.get("enabled")}
