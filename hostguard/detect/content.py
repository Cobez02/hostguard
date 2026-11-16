"""A short list of byte signatures for malware and attack tools.

This is a tripwire, not an antivirus database: Defender and optional YARA rules do the real
signature work. These catch the common case of an unobfuscated commodity tool sitting on disk.

Every token is stored in pieces and joined at import time, so this file does not itself look
like the things it describes to an antivirus engine.
"""

from __future__ import annotations

from dataclasses import dataclass


def j(*parts: str) -> bytes:
    return "".join(parts).encode("latin-1")


@dataclass(frozen=True)
class Sig:
    id: str
    title: str
    severity: str
    patterns: tuple            # byte strings
    need: int = 1              # how many distinct patterns must be present
    wide: bool = True          # also look for the UTF-16 form
    family: str = ""


# The EICAR test file is the industry's harmless stand-in for malware. HostGuard uses it for its self-test.
EICAR = j("X5O!P%@AP[4", "\\PZX54(P^)7CC)7}$", "EICAR-STANDARD-", "ANTIVIRUS-TEST-FILE!$H+H*")

SIGNATURES: list[Sig] = [
    Sig("eicar", "EICAR antivirus test file", "high", (EICAR,), wide=False, family="test file"),
    Sig("credential_dumper", "Credential-dumping tool", "critical",
        (j("genti", "lkiwi"), j("seku", "rlsa::"), j("mimi", "lib"), j("lsa", "dump::"), j("kiwi_", "msv1_0"),
         j("mimi", "katz")), need=2, family="credential theft"),
    Sig("cobalt_strike", "Cobalt Strike beacon markers", "critical",
        (j("%c%c%c%c%c%c%c%c%cMSSE-", "%d-server"), j("beacon", ".dll"), j("beacon", ".x64.dll"),
         j("%s as %s\\%s: ", "%d"), j("could not spawn %s ", "(token): %d"), j("ReflectiveLoader"),
         j("%02d/%02d/%02d %02d:%02d:%02d"), j("could not open process ", "token: %d (%u)")),
        need=3, family="remote access implant"),
    Sig("meterpreter", "Metasploit Meterpreter markers", "critical",
        (j("met", "srv.dll"), j("ext_server_", "stdapi"), j("stdapi_", "sys_process_execute"), j("core_", "channel_open"),
         j("meter", "preter")), need=2, family="remote access implant"),
    Sig("coin_miner", "Cryptocurrency miner", "high",
        (j("donate.v2.", "xmrig.com"), j("xm", "rig"), j("stratum+", "tcp://"), j("--donate-", "level"), j("cryptonight"),
         j("randomx")), need=3, family="coin miner"),
    Sig("commodity_rat", "Commodity remote-access trojan markers", "critical",
        (j("Async", "RAT"), j("Async", "Client"), j("Quasar.", "Common"), j("Quasar.", "Client"), j("Remcos", " Agent"),
         j("Dc", "Rat"), j("XWorm", " V"), j("Venom", "RAT"), j("nj", "RAT"), j("Nano", "Core"), j("Orcus.", "Shared"),
         j("Warzone", "RAT")), need=1, family="remote access trojan"),
    Sig("info_stealer", "Collects browser passwords, cookies and wallets", "high",
        (j("Login", " Data"), j("Web", " Data"), j("wallet", ".dat"), j("Local", " State"), j("\\Telegram Desktop", "\\tdata"),
         j("logins", ".json"), j("key4", ".db"), j("cookies", ".sqlite"), j("nkbihfbeogaeaoeh", "lefnkodbefgpgknn"),
         j("Exodus", "\\exodus.wallet"), j("discord", "\\Local Storage\\leveldb"), j("Electrum", "\\wallets"),
         j("\\Atomic", "\\Local Storage")), need=5, family="information stealer"),
    Sig("ransom_note", "Ransomware wording", "high",
        (j("your files have been ", "encrypted"), j("all your files are ", "encrypted"), j("decrypt", " your files"),
         j("vssadmin delete ", "shadows"), j(".onion"), j("bitcoin ", "wallet"), j("private ", "key")), need=4,
        family="ransomware"),
    Sig("uac_bypass_kit", "UAC-bypass toolkit markers", "high",
        (j("UAC", "Me"), j("Elevation:Administrator!", "new:"), j("{3E5FC7F9-9A51-4367-", "9063-A120244FBEC7}"),
         j("\\ms-settings\\shell", "\\open\\command")), need=2, family="privilege escalation"),
]


def scan(data: bytes) -> list[Sig]:
    """Signatures present in a block of bytes."""
    if not data:
        return []
    out = []
    lowered = None
    for sig in SIGNATURES:
        found = 0
        for p in sig.patterns:
            hit = p in data
            if not hit and sig.wide:
                hit = p.decode("latin-1").encode("utf-16-le") in data
            if not hit and sig.id not in ("eicar", "cobalt_strike"):
                if lowered is None:
                    lowered = data.lower()
                hit = p.lower() in lowered
            if hit:
                found += 1
                if found >= sig.need:
                    out.append(sig)
                    break
    return out
