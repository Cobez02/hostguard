"""Free Windows protections that are off by default, as switches.

Each switch shows the state read from Windows, not the last thing clicked. Turning one on or off
goes through the elevated helper (one UAC prompt) and is logged like any other action.
"""

from __future__ import annotations

import os

from . import contain, elevate, reg, util
from .collect import system as c_system

ASR_STANDARD = ("56a863a9-875e-4185-98a7-b882c64b5ce5", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
                "e6db77e5-3df2-4cf1-b95a-636979351e5b")
ASR_EXTENDED = ("d4f940ab-401b-4efc-aadc-ad5f3c50688a", "5beb7efe-fd9a-4556-801d-275e5ffc04cc",
                "d3e037e1-3eb8-44c8-a917-57927947596d", "c1db55ab-c21a-4637-bb3f-a12568109d35",
                "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b")

# id, group, title, what it does, the catch
CATALOG = [
    ("pua_block", "Defender", "Block potentially unwanted apps",
     "Adware, bundlers and coin miners are blocked, not just noted.", ""),
    ("asr_standard", "Defender", "Attack surface reduction: standard rules",
     "Blocks credential theft from LSASS, abuse of vulnerable signed drivers, and WMI persistence. "
     "Microsoft's own recommended minimum.", ""),
    ("asr_extended", "Defender", "Attack surface reduction: script and Office rules",
     "Blocks Office starting other programs, obfuscated scripts, scripts launching downloads, macro API calls, "
     "executable mail attachments, and adds ransomware heuristics.",
     "Can block unusual developer or admin scripts. Turn it off again if something legitimate stops working."),
    ("network_protection", "Defender", "Network protection",
     "Connections to known malicious sites are blocked for every program, not only the browser.", ""),
    ("controlled_folder_access", "Defender", "Controlled folder access (ransomware protection)",
     "Only trusted programs may change files in Documents, Pictures and Desktop.",
     "Unknown programs, including your own scripts and some games, are blocked from saving there until you allow them."),
    ("cloud_block_high", "Defender", "Cloud protection level: High",
     "Defender blocks more aggressively on a cloud verdict.", "Slightly more false positives."),
    ("process_audit", "Visibility", "Record every program start with its command line",
     "Windows logs each process with its full command, so a command that ran and exited can still be investigated.",
     "The Security log needs administrator rights to read unless 'Let HostGuard read the Security log' is also on."),
    ("script_block_logging", "Visibility", "Record PowerShell scripts as they run",
     "The text of every PowerShell script is logged, decoded.", "Anything typed into PowerShell is logged, secrets included."),
    ("event_log_readers", "Visibility", "Let HostGuard read the Security log",
     "Adds your account to the Event Log Readers group so the monitor sees logons and process starts without elevation.",
     "Programs running as you can then read that log too. Takes effect at your next sign-in."),
    ("sysmon", "Visibility", "Sysmon (built into recent Windows 11)",
     "Detailed process, network and injection telemetry in the event log.",
     "Only on Windows builds that include the feature. Has no off switch here: use 'Turn Windows features on or off'."),
    ("rdp_private_only", "Exposure", "Remote Desktop: private networks only",
     "The firewall accepts Remote Desktop only on networks marked Private (such as a mesh VPN).", ""),
    ("rdp_off", "Exposure", "Turn Remote Desktop off",
     "This PC stops accepting remote logons.", "You can no longer connect to it remotely."),
    ("one_click_isolation", "Response", "One-click network isolation",
     "Registers a task that cuts the network without a UAC prompt, so automatic containment can use it.",
     "Any program running as you could trigger it. It can only cut the network; restoring it still needs your approval."),
]
_BY_ID = {c[0]: c for c in CATALOG}


def _states() -> dict[str, bool | None]:
    try:
        d = util.run_ps("defender", timeout=60) or {}
    except util.CollectError:
        d = {}
    pr = d.get("prefs") or {}
    asr = {str(i).lower(): a for i, a in zip(util.as_list(pr.get("AsrIds")), util.as_list(pr.get("AsrActions")))}
    r = c_system.posture_registry()
    try:
        acc = util.run_ps("accounts", timeout=60) or {}
    except util.CollectError:
        acc = {}
    me = str(acc.get("current") or "").lower()
    readers = [str(m.get("name") or "").lower() for m in ((acc.get("groups") or {}).get("S-1-5-32-573") or {}).get("members") or []]
    try:
        fw = util.as_list(util.run_ps("rdpfw", timeout=60))
    except util.CollectError:
        fw = []
    profiles = {str(x.get("profile")) for x in fw}
    known = bool(pr)
    return {
        "pua_block": pr.get("PUAProtection") == 1 if known else None,
        "asr_standard": all(asr.get(i) == 1 for i in ASR_STANDARD) if known else None,
        "asr_extended": all(asr.get(i) == 1 for i in ASR_EXTENDED) if known else None,
        "network_protection": pr.get("EnableNetworkProtection") == 1 if known else None,
        "controlled_folder_access": pr.get("EnableControlledFolderAccess") == 1 if known else None,
        "cloud_block_high": (pr.get("CloudBlockLevel") or 0) >= 2 if known else None,
        "process_audit": r.get("proc_cmdline_audit") == 1,
        "script_block_logging": r.get("ps_scriptblock_logging") == 1,
        "event_log_readers": me in readers if me else None,
        "sysmon": any(reg.exists(reg.HKLM, rf"SYSTEM\CurrentControlSet\Services\{n}") for n in ("Sysmon", "Sysmon64")),
        "rdp_private_only": (profiles <= {"Private"} and bool(profiles)) if fw else None,
        "rdp_off": (r.get("rdp") or {}).get("deny") != 0,
        "one_click_isolation": contain.ratchet_installed(),
    }


def status() -> list[dict]:
    states = _states()
    return [{"id": i, "group": g, "title": t, "detail": d, "caveat": c, "on": states.get(i)} for i, g, t, d, c in CATALOG]


def set_state(store, setting: str, on: bool, dry_run: bool = False) -> dict:
    if setting not in _BY_ID:
        return {"ok": False, "message": f"unknown setting '{setting}'"}
    args = {"setting": setting, "on": bool(on)}
    if setting == "event_log_readers":
        args["user"] = f"{os.environ.get('USERDOMAIN', '')}\\{os.environ.get('USERNAME', '')}".strip("\\")
    res = elevate.run("harden", args, dry_run=dry_run)
    if dry_run:
        return res
    now = _states().get(setting) if res.get("ok") else None
    if res.get("ok") and now is not None and now != on and setting not in ("event_log_readers", "sysmon"):
        res = {"ok": False, "message": f"Windows still reports '{_BY_ID[setting][2]}' as {'on' if now else 'off'}; "
                                       "Tamper Protection or a policy may have refused the change"}
    if store is not None:
        store.log_action("operator", "harden:" + setting, {"type": "setting", "name": setting, "on": bool(on)}, None,
                         state="done" if res.get("ok") else "failed", ok=bool(res.get("ok")),
                         result={"message": res.get("message"), "changes": res.get("changes")},
                         rollback={"kind": "harden", "setting": setting, "on": not on} if res.get("ok") else None)
    if res.get("ok"):
        res["message"] = f"{_BY_ID[setting][2]}: now {'on' if on else 'off'}"
    return res
