"""Rules over live network connections and listening ports."""

from __future__ import annotations

from collections import defaultdict

from .. import sigs, util
from ..model import Finding
from . import cmdline as cl

# Windows tools that have no business talking to the internet themselves. When one does, it is
# either being used as a downloader or someone else's code is running inside it.
NEVER_ONLINE = {"notepad.exe", "calc.exe", "mspaint.exe", "write.exe", "wordpad.exe", "rundll32.exe", "regsvr32.exe",
                "mshta.exe", "wscript.exe", "cscript.exe", "certutil.exe", "installutil.exe", "regasm.exe", "regsvcs.exe",
                "cmstp.exe", "msxsl.exe", "odbcconf.exe", "esentutl.exe", "cmd.exe", "conhost.exe", "dllhost.exe",
                "werfault.exe", "userinit.exe", "winlogon.exe", "lsass.exe", "csrss.exe", "smss.exe", "wininit.exe"}
# What one of them does reach out for by itself, by remote port. lsass.exe asks certificate authorities
# whether a certificate has been revoked, and that is plain HTTP to whatever network the authority's
# servers sit on. Only the real one is excused: a program that merely carries the name, running from
# somewhere else, is not.
EXPECTED_PORTS = {"lsass.exe": {80: "certificate checks"}}
SHELL_LISTENERS = {"cmd.exe", "powershell.exe", "pwsh.exe", "nc.exe", "ncat.exe", "nc64.exe", "socat.exe", "netcat.exe"}
ODD_PORTS = {4444: "the default port of Metasploit and many backdoors", 4445: "a common backdoor port",
             1337: "a common backdoor port", 31337: "a common backdoor port", 6667: "IRC, used by older botnets",
             6697: "IRC over TLS", 9001: "the Tor relay port", 9030: "the Tor directory port",
             3333: "a common cryptocurrency mining pool port", 14444: "a common mining pool port",
             45700: "a common mining pool port", 5555: "a common remote-shell and mining port",
             1080: "a SOCKS proxy port", 8333: "the Bitcoin network port"}
ADMIN_LISTEN = {3389: "Remote Desktop", 5900: "VNC", 5901: "VNC", 22: "SSH", 23: "Telnet", 5985: "Windows Remote Management",
                5986: "Windows Remote Management", 1080: "a SOCKS proxy", 9050: "Tor", 9150: "Tor", 4444: "a common backdoor port",
                2222: "SSH on an alternate port", 3390: "Remote Desktop on an alternate port"}


def _subject(process: dict, addresses: list[str], offered: list[str]) -> tuple[dict, list[str]]:
    """What containment would act on, and which of the offered actions fit.

    That is always the process. It is the address as well when the finding is about exactly one: then
    "block address" has an address to block. With several, blocking one would look like containment and
    leave the rest reachable, so that action is not offered and the process is the thing to stop.
    """
    unique = sorted(set(addresses))
    if len(unique) == 1:
        return {**process, "ip": unique[0]}, list(offered)
    return dict(process), [a for a in offered if a != "block_ip"]


def detect(facts: dict, sig_map: dict[str, dict], ctx: dict | None = None) -> list[Finding]:
    ctx = ctx or {}
    intel = ctx.get("bad_ips") or set()
    procs = {p["pid"]: p for p in facts.get("processes") or []}
    self_pids = set(ctx.get("self_pids") or ())
    out: list[Finding] = []
    listeners: dict[tuple, dict] = {}
    outbound: dict[str, dict] = defaultdict(lambda: {"remotes": set(), "pids": set()})

    def proc_of(pid: int) -> dict:
        return procs.get(pid) or {"pid": pid, "name": "?", "path": ""}

    def ev_proc(p: dict) -> dict:
        sig = sigs.lookup(sig_map, p.get("path"))
        return {"process": p.get("name"), "pid": p.get("pid"), "path": p.get("path"), "signature": sigs.describe(sig) if p.get("path") else None,
                "command_line": util.truncate(p.get("cmdline"), 500)}

    for c in facts.get("connections") or []:
        pid = c.get("pid") or 0
        if pid in self_pids:
            continue
        p = proc_of(pid)
        if c["state"] == "LISTEN":
            if util.is_loopback(c["laddr"]):
                continue
            key = (c["proto"], c["lport"], (p.get("path") or p.get("name") or "").lower())
            listeners.setdefault(key, {"proto": c["proto"], "port": c["lport"], "proc": p, "addrs": set()})["addrs"].add(c["laddr"])
        elif c["proto"] == "tcp" and c["state"] in ("ESTABLISHED", "SYN_SENT", "CLOSE_WAIT") and util.is_public_ip(c["raddr"]):
            key = (p.get("path") or p.get("name") or str(pid)).lower()
            outbound[key]["proc"] = p
            outbound[key]["remotes"].add((c["raddr"], c["rport"]))
            outbound[key]["pids"].add(pid)

    # ---- outbound
    for key, o in outbound.items():
        p = o["proc"]
        name = (p.get("name") or "").lower()
        sig = sigs.lookup(sig_map, p.get("path"))
        remotes = sorted(o["remotes"])
        ev = {**ev_proc(p), "remote": [f"{ip}:{port}" for ip, port in remotes[:12]]}
        ent = {"type": "process", "pid": p.get("pid"), "name": p.get("name"), "path": p.get("path") or "", "created": p.get("created")}
        bad = [ip for ip, _ in remotes if ip in intel]
        if bad:
            subject, actions = _subject(ent, bad[:1], ["suspend", "kill", "block_ip", "isolate"])
            out.append(Finding(rule="net.intel_match", title=f"{p.get('name')} is connected to a known malicious address: {bad[0]}",
                               severity="critical", confidence="high", category="network", collector="network",
                               description="The address is on a threat-intelligence blocklist of command-and-control servers.",
                               evidence={**ev, "listed": bad}, entity=subject, mitre=["T1071"], actions=actions,
                               key_parts=(key, bad[0])))
        if name in NEVER_ONLINE:
            genuine = not p.get("path") or util.path_zone(p["path"]) == "windows"
            expected = EXPECTED_PORTS.get(name, {}) if genuine else {}
            unexpected = [(ip, port) for ip, port in remotes if port not in expected]
            if unexpected:
                excused = "".join(f" Its {what} on port {port} are not counted here." for port, what in expected.items())
                subject, actions = _subject(ent, [ip for ip, _ in unexpected], ["suspend", "kill", "block_ip"])
                out.append(Finding(rule="net.lolbin_online", title=f"{p.get('name')} has a connection to the internet",
                                   severity="high", confidence="medium", category="network", collector="network",
                                   description="This Windows component does not make internet connections like this on its "
                                               "own. Either it was launched to download something, or other code is running "
                                               "inside it." + excused,
                                   evidence={**ev, "remote": [f"{ip}:{port}" for ip, port in unexpected[:12]]}, entity=subject,
                                   mitre=["T1218", "T1055", "T1071"], actions=actions, key_parts=(key,)))
        elif name in ("powershell.exe", "pwsh.exe"):
            hits = cl.analyse_command(p.get("cmdline") or "")
            out.append(Finding(rule="net.powershell_online", title="PowerShell has a connection to the internet",
                               severity="high" if hits else "low", confidence="medium" if hits else "low", category="network",
                               collector="network", description="Scripts that call web services do this legitimately. "
                                                                "So do download cradles and PowerShell implants.",
                               evidence=ev, entity=ent, mitre=["T1059.001", "T1071.001"], actions=["suspend", "kill"], key_parts=(key,)))
        elif p.get("path") and sigs.lacks_trust(sig) and util.path_zone(p["path"]) in util.USER_WRITABLE:
            zone = util.path_zone(p["path"])
            subject, actions = _subject(ent, [ip for ip, _ in remotes], ["suspend", "kill", "block_ip"])
            out.append(Finding(rule="net.unsigned_online", title=f"Unsigned program from a user-writable folder is talking to the internet: {p.get('name')}",
                               severity="medium" if zone in util.HIGH_RISK else "low", confidence="low", category="network",
                               collector="network", description="Nobody signed this program and it has an open connection to "
                                                                "a public address. Developer tools fit this description; so do implants.",
                               evidence=ev, entity=subject, mitre=["T1071"], actions=actions, key_parts=(key,)))
        odd = [(ip, port) for ip, port in remotes if port in ODD_PORTS]
        if odd and not sigs.is_valid(sig):
            ip, port = odd[0]
            subject, actions = _subject(ent, [ip], ["suspend", "kill", "block_ip"])
            out.append(Finding(rule="net.odd_port", title=f"{p.get('name')} is connected to {ip} on port {port}",
                               severity="medium", confidence="low", category="network", collector="network",
                               description=f"Port {port} is {ODD_PORTS[port]}, and the program is not signed by a known publisher.",
                               evidence=ev, entity=subject, mitre=["T1571"], actions=actions, key_parts=(key, port)))

    # ---- listeners
    exposed = []
    for (proto, port, _), ls in sorted(listeners.items(), key=lambda kv: kv[0][1]):
        p = ls["proc"]
        name = (p.get("name") or "").lower()
        sig = sigs.lookup(sig_map, p.get("path"))
        wide = any(util.is_wildcard_addr(a) for a in ls["addrs"])
        ent = {"type": "process", "pid": p.get("pid"), "name": p.get("name"), "path": p.get("path") or "", "created": p.get("created")}
        ev = {**ev_proc(p), "port": f"{proto}/{port}", "bound_to": sorted(ls["addrs"])}
        exposed.append(f"{proto}/{port}  {p.get('name')}" + (f"  ({p['path']})" if p.get("path") else ""))
        if name in SHELL_LISTENERS and proto == "tcp":
            out.append(Finding(rule="net.listen.shell", title=f"{p.get('name')} is listening for connections on port {port}",
                               severity="high", confidence="medium", category="network", collector="network",
                               description="A shell or netcat waiting for a connection is a bind shell: whoever connects gets a command prompt.",
                               evidence=ev, entity=ent, mitre=["T1059", "T1571"], actions=["suspend", "kill"], key_parts=(name, port)))
        elif proto == "tcp" and port in ADMIN_LISTEN and port != 3389:
            signed = sigs.is_valid(sig)
            out.append(Finding(rule="net.listen.remote_admin", title=f"{p.get('name')} accepts {ADMIN_LISTEN[port]} connections on port {port}",
                               severity="low" if signed else "medium", confidence="low", category="network", collector="network",
                               description="Other machines that can reach this PC can try to log in through it."
                                           + ("" if wide else " It is bound to specific addresses only."),
                               evidence=ev, entity=ent, mitre=["T1021"], actions=["kill"], key_parts=(name, port)))
        elif p.get("path") and sigs.lacks_trust(sig) and util.path_zone(p["path"]) in util.HIGH_RISK and wide:
            out.append(Finding(rule="net.listen.unsigned_temp", title=f"Unsigned program in a temporary folder accepts network connections: {p.get('name')}",
                               severity="medium", confidence="low", category="network", collector="network",
                               description="It is reachable from other machines on the network.",
                               evidence=ev, entity=ent, mitre=["T1571"], actions=["suspend", "kill"], key_parts=(name, port)))
    if exposed:
        out.append(Finding(rule="net.listen.inventory", title=f"{len(exposed)} port(s) on this PC accept connections from other machines",
                           severity="info", confidence="low", category="network", collector="network",
                           description="Listed for context. The firewall decides which of these are actually reachable.",
                           evidence={"listeners": exposed[:60]}, key_parts=("inventory",)))
    return out


def inventory(facts: dict) -> dict[str, dict]:
    """Network-facing listeners, for the baseline."""
    procs = {p["pid"]: p for p in facts.get("processes") or []}
    out = {}
    for c in facts.get("connections") or []:
        if c["state"] != "LISTEN" or util.is_loopback(c["laddr"]) or c["lport"] >= 49152:
            continue
        p = procs.get(c.get("pid") or 0) or {}
        # Keyed by the program's file name, never its full path: the path of a system service can only
        # be read with administrator data, and the same listener must not look new when a scan gains it.
        image = util.basename(p.get("path") or p.get("name") or "?").lower()
        out[f"{c['proto']}|{c['lport']}|{image}"] = {"port": c["lport"], "proto": c["proto"], "process": p.get("name"), "path": p.get("path")}
    return out
