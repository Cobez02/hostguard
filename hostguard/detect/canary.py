"""Rules over the canary report: what a change to a decoy document means.

There is one canary finding at a time, named for the strongest thing seen. Everything else that
was noticed goes into its evidence. From strongest to weakest:

    canary.ransomware    a decoy is no longer a document at all, or was swapped for another file
    canary.destroyed     decoys were deleted and nothing was left in their place
    canary.permissions   the owner or the access list of a decoy changed, or HostGuard was locked out
    canary.edited        a decoy changed and is still a sound document, or a new file sits beside it
    canary.settings      only what the folder above hands down changed, or a mark such as Read-only

A canary says that something is rewriting files. It cannot say which program. `writers` turns a
measurement of who was writing most at that moment into leads, and says plainly that they are leads.
"""

from __future__ import annotations

import hashlib
import os

from .. import sigs, util
from ..model import RESOLVED, Finding

RANK = ("canary.settings", "canary.edited", "canary.permissions", "canary.destroyed", "canary.ransomware")
_STRONG_PERMISSION = {"owner", "access", "encrypted"}
HEAVY_BYTES = 2 << 20       # a second: below both of these a program is not "writing heavily"
HEAVY_WRITES = 200


def _lines(items: list[str], limit: int = 12) -> str:
    return "\n".join(items[:limit]) + (f"\n... and {len(items) - limit} more" if len(items) > limit else "")


def _places(n: int) -> str:
    return "1 place" if n == 1 else f"{n} places"


def detect(report: dict) -> list[Finding]:
    """At most one finding: the state of the canaries, if it is not the state they were placed in."""
    folders = [f for f in report.get("folders") or [] if f["state"] != "unavailable"]
    record = report.get("record") or "ok"
    no_longer, gone, replaced, edited, new_files, notes, strong, weak = [], [], [], [], [], [], [], []
    hit: dict[str, set] = {name: set() for name in RANK}
    for fo in folders:
        missing_here = [f for f in fo["files"] if f["state"] == "missing"]
        strangers = fo.get("strangers") or []
        for s in strangers:
            line = os.path.join(fo["root"] if s.get("beside") else fo["path"], s["name"]) \
                + (f" ({s['bytes']:,} bytes)" if s.get("bytes") is not None else "")
            new_files.append(line)
            if s.get("note"):
                notes.append(line)
        if any(s.get("note") for s in strangers) or (missing_here and strangers):
            hit["canary.ransomware"].add(fo["path"])
        elif strangers:
            hit["canary.edited"].add(fo["path"])
        for f in fo["files"]:
            if f["state"] == "damaged":
                no_longer.append(f"{f['path']} (was {f['was_bytes']:,} bytes, is {f['now_bytes']:,}; now starts with {f['starts_with'] or 'nothing'})")
                hit["canary.ransomware"].add(fo["path"])
            elif f["state"] == "missing":
                twin = next((s["name"] for s in strangers if s.get("twin_of") == f["name"]), None)
                (replaced if strangers else gone).append(f["path"] + (f" (now {twin})" if twin else ""))
                hit["canary.ransomware" if strangers else "canary.destroyed"].add(fo["path"])
            elif f["state"] == "edited":
                edited.append(f"{f['path']} (was {f['was_bytes']:,} bytes, is {f['now_bytes']:,})")
                hit["canary.edited"].add(fo["path"])
            elif f["state"] == "locked":
                strong.append(f"{f['path']}: Windows refuses to let HostGuard read it")
                hit["canary.permissions"].add(fo["path"])
        for item, changes in [(fo["path"], fo.get("changes") or [])] + [(f["path"], f.get("changes") or []) for f in fo["files"]]:
            for c in changes:
                is_strong = c["kind"] in _STRONG_PERMISSION
                (strong if is_strong else weak).append(f"{item}: {c['text']}")
                hit["canary.permissions" if is_strong else "canary.settings"].add(fo["path"])
    if record == "damaged":
        hit["canary.destroyed"].add("record")
    elif record == "lost":
        hit["canary.edited"].add("record")
    rule = next((name for name in reversed(RANK) if hit[name]), None)
    if rule is None:
        return []

    s = report.get("summary") or {}
    where = len({p for name in RANK[RANK.index(rule):] for p in hit[name] if p != "record"})
    evidence = {
        "canaries": f"{s.get('files', 0)} decoy documents in {_places(s.get('folders', 0))}"
                    + (f", placed {util.iso(report['placed'])}" if report.get("placed") else ""),
        "no_longer_documents": _lines(no_longer),
        "swapped_for_other_files": _lines(replaced),
        "deleted": _lines(gone),
        "ransom_note": _lines(notes),
        "new_files_beside_them": _lines(new_files),
        "edited_in_place": _lines(edited),
        "owner_or_permissions": _lines(strong),
        "lesser_changes": _lines(weak),
        "the_record": {"damaged": "HostGuard's own list of its canaries (canaries.json in the state folder) was overwritten with "
                                  "something that is not a list",
                       "lost": "HostGuard's own list of its canaries (canaries.json in the state folder) was deleted while the "
                               "monitor was running; the canaries are checked from the copy the monitor remembers"}.get(record, ""),
        "untouched": f"{s.get('untouched', 0)} of {s.get('files', 0)}",
    }
    evidence = {k: v for k, v in evidence.items() if v}
    # What is wrong, as one value. If you mark the finding as dealt with, it stays that way until this changes.
    state = hashlib.sha1(repr(sorted((k, v) for k, v in evidence.items() if k != "untouched")).encode("utf-8", "replace")).hexdigest()[:12]

    again = "When it is over, press Replace the canaries on the Hardening tab to put fresh ones down."
    if rule == "canary.ransomware":
        title = f"Canary tripped: decoy documents were overwritten or swapped in {_places(where)}"
        severity, confidence, mitre = "critical", "high", ["T1486"]
        description = ("HostGuard keeps hidden decoy documents where a walk of a folder starts and nothing has a reason to write. "
                       "Some of them are no longer documents at all, or were swapped for other files. That is what ransomware "
                       "does to every file it reaches, and it reaches these first. Treat your own files as next.")
        remediation = ("If a request to suspend a program is waiting on the Overview tab, approve it: suspending can be undone. "
                       "If you cannot tell what is doing this, shut the PC down. That stops it, and the files it has not "
                       "reached stay as they are. " + again)
    elif rule == "canary.destroyed":
        title = ("HostGuard's list of its canaries was overwritten" if not where
                 else f"Canary tripped: decoy documents were deleted in {_places(where)}")
        severity, confidence, mitre = "high", "medium", ["T1485"]
        description = ("Hidden decoy documents that HostGuard keeps are gone, and nothing was left in their place. "
                       "A program clearing out folders does this. So does someone tidying up hidden folders by hand.")
        remediation = "If you deleted them yourself, nothing is wrong. Otherwise look at what was running at the time. " + again
    elif rule == "canary.permissions":
        title = f"Canary tripped: owner or permissions changed on decoy documents in {_places(where)}"
        severity, confidence, mitre = "high", "medium", ["T1222.001"]
        description = ("The decoy documents still hold what HostGuard put in them, but who owns them or who may change them is "
                       "different. Ransomware takes ownership of files and opens up their permissions before it rewrites them. "
                       "A tool that resets permissions across a whole folder tree leaves the same trace.")
        remediation = "If you changed permissions on these folders yourself, nothing is wrong. " + again
    elif rule == "canary.edited":
        title = ("HostGuard's list of its canaries was deleted" if not where
                 else f"A canary was changed without being damaged, in {_places(where)}")
        severity, confidence, mitre = "medium", "low", []
        description = ("A decoy document changed and is still a sound document of its kind, or a new file appeared beside the "
                       "decoys. An editor or a sync service does that. Ransomware leaves files that no longer open.")
        remediation = "Nothing needs stopping. " + again.replace("When it is over, press", "Press")
    else:
        title = f"Permissions handed down to canaries, or their marks, changed in {_places(where)}"
        severity, confidence, mitre = "low", "low", []
        description = ("The decoy documents are untouched. What changed is a permission they take from the folder above them, "
                       "or a mark such as Hidden or Read-only.")
        remediation = "Nothing needs stopping. " + again.replace("When it is over, press", "Press")
    return [Finding(rule=rule, title=title, severity=severity, confidence=confidence, category="file", collector="canaries",
                    description=description, remediation=remediation, evidence=evidence, mitre=mitre, actions=[],
                    entity={"type": "canary", "state": state}, key_parts=("canaries",))]


def dealt_with(store, finding: Finding) -> bool:
    """True when you already marked exactly this state of the canaries as dealt with.

    A state finding normally reopens when it is seen again. A tripped canary stays tripped until the
    canaries are replaced, so without this it would come back seconds after being closed."""
    row = store.get_finding(finding.key)
    return bool(row) and row["status"] == RESOLVED and (row.get("entity") or {}).get("state") == finding.entity.get("state")


def writers(rows: list[dict], sig_map: dict[str, dict]) -> tuple[str, list[Finding]]:
    """(who was writing most, as evidence lines; findings for the ones worth a request to suspend).

    rows: [{"pid", "name", "path", "created", "bytes_per_s", "writes_per_s", "written_bytes"}], busiest first.
    Windows counts everything a program writes, to disk, to pipes and to the network, so the numbers
    are a lead and never proof. Only an unsigned program or one of Windows' script hosts gets a
    finding: the same programs automatic containment is allowed to touch.
    """
    from ..contain import LOLBINS, NEVER, OPERATOR_ONLY
    lines, found = [], []
    for i, r in enumerate(rows):
        sig = sigs.lookup(sig_map, r.get("path"))
        rate = (f"{r['bytes_per_s'] / (1 << 30):.1f} GB" if r["bytes_per_s"] >= 1 << 30 else f"{r['bytes_per_s'] / (1 << 20):.1f} MB") \
            + f" a second in {r['writes_per_s']:.0f} writes"
        lines.append(f"{r['name']} (pid {r['pid']}): {rate}, {sigs.describe(sig)}" + (f", {r['path']}" if r.get("path") else ""))
        name = (r.get("name") or "").lower()
        heavy = r["bytes_per_s"] >= HEAVY_BYTES or r["writes_per_s"] >= HEAVY_WRITES
        if not heavy or not r.get("path") or name in NEVER or name in OPERATOR_ONLY or len(found) >= 2:
            continue
        if not (sigs.lacks_trust(sig) or name in LOLBINS):
            continue
        ahead = i == 0 and (len(rows) == 1 or r["bytes_per_s"] >= 2 * rows[1]["bytes_per_s"])
        why = "one of Windows' script hosts" if name in LOLBINS and not sigs.lacks_trust(sig) else sigs.describe(sig)
        actions = ["suspend", "kill"] + (["quarantine"] if util.path_zone(r["path"]) in util.USER_WRITABLE and name not in LOLBINS else [])
        found.append(Finding(
            rule="canary.writer", title=f"{r['name']} was writing heavily while canary documents were being overwritten",
            severity="high", confidence="medium" if ahead else "low", category="process", collector="canaries",
            description=("When HostGuard saw its decoy documents being overwritten, it measured which programs were writing. "
                         f"This one wrote {rate}" + (", far more than any other it could measure" if ahead else "")
                         + f", and it is {why}. That is a lead, not proof: Windows counts everything a program writes, to "
                           "disk, to pipes and to the network."),
            remediation="Suspend it. That stops it at once and can be undone from the action log if the program turns out to be yours.",
            evidence={"pid": r["pid"], "name": r["name"], "path": r["path"], "started": util.iso(r.get("created")),
                      "writing": rate, "written_since_it_started": f"{r.get('written_bytes', 0) / 1048576:.0f} MB",
                      "signature": sigs.describe(sig)},
            entity={"type": "process", "pid": r["pid"], "name": r["name"], "path": r["path"], "created": r.get("created")},
            actions=actions, mitre=["T1486"], key_parts=(r["path"],)))
    return _lines(lines, 8), found
