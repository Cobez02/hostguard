"""Command line for HostGuard. Every dashboard switch has a command here that does the same thing."""

from __future__ import annotations

import argparse
import json
import sys

from . import __version__, paths, report, util
from .model import ALLOWED, OPEN, RESOLVED, SEVERITIES
from .store import Store


def _out(obj) -> None:
    print(json.dumps(obj, indent=2, default=str))


def _need(store: Store, fid: str) -> dict:
    row = store.get_finding(fid)
    if not row:
        raise SystemExit(f"no finding matches '{fid}' (use the id from 'findings'; a prefix of 4+ characters is enough)")
    return row


def cmd_scan(a, store: Store) -> int:
    from . import scan
    elevated_data = None
    if a.use_elevated:
        from . import elevate
        elevated_data = elevate.load_latest()
    summary = scan.run(a.profile, store, log=None if a.quiet or a.json else lambda m: print("  " + m, flush=True),
                       elevated_data=elevated_data)
    if a.policy:
        from . import policy
        acted = policy.apply(store, summary.get("new_ids") or [], log=None if a.json else print)
        summary["policy"] = acted
    if a.json:
        _out(summary)
    else:
        print()
        print(report.text(store, min_severity=a.min_severity, detail=a.detail))
    level = summary["verdict"]["level"]
    return 2 if level == "compromised" else 1 if level == "suspicious" else 0


def cmd_status(a, store: Store) -> int:
    ov = report.overview(store)
    if a.json:
        from . import contain, monitor
        ov["isolation"] = contain.isolation_state()
        ov["monitor"] = monitor.status()
        ov["config"] = paths.load_config()
        _out(ov)
    else:
        print(report.text(store, min_severity="medium", include_posture=False))
    return 0


def cmd_findings(a, store: Store) -> int:
    statuses = None if a.all else (OPEN,)
    rows = store.findings(statuses, min_severity=a.severity, category=a.category)
    if a.json:
        _out(rows)
    else:
        for r in rows:
            print(f"{r['severity']:<8} {r['status']:<9} {r['id'][:8]}  {r['category']:<11} {r['title']}")
        print(f"\n{len(rows)} finding(s)")
    return 0


def cmd_show(a, store: Store) -> int:
    row = _need(store, a.id)
    _out(row) if a.json else print(report.finding_text(row))
    return 0


def cmd_disposition(a, store: Store) -> int:
    row = _need(store, a.id)
    status = {"allow": ALLOWED, "resolve": RESOLVED, "reopen": OPEN}[a.cmd]
    store.set_status(row["id"], status, a.note if a.note is not None else None)
    print(f"{row['id'][:8]} -> {status}: {row['title']}")
    return 0


def cmd_baseline(a, store: Store) -> int:
    if a.what == "accept":
        from . import scan
        n = scan.accept_baseline(store)
        print(f"Baseline accepted: {n} item(s) marked as known. Later scans report what is new.")
    else:
        t = store.baseline_time()
        new = store.inventory(only_new=True) if t else []
        print("Baseline: " + (f"accepted {util.iso(t)}; {len(new)} new item(s) since" if t else "not set"))
        for item in new[:50]:
            print(f"  new {item['kind']}: {util.truncate(item['data'].get('name') or item['key'], 100)}")
    return 0


def cmd_contain(a, store: Store) -> int:
    from . import contain
    if a.finding:
        row = _need(store, a.finding)
        entity, fid = row.get("entity") or {}, row["id"]
    else:
        entity, fid = {}, None
    for kv in a.target or []:
        k, _, v = kv.partition("=")
        entity[k] = int(v) if k == "pid" and v.isdigit() else v
    if not entity:
        raise SystemExit("give --finding ID or a target such as pid=1234, path=C:\\file.exe, ip=203.0.113.9")
    res = contain.execute(store, a.action, entity, actor="operator", finding_id=fid, dry_run=a.dry_run, force=a.force)
    _out(res) if a.json else print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
    return 0 if res.get("ok") else 1


def cmd_undo(a, store: Store) -> int:
    from . import contain
    res = contain.undo(store, a.action_id, actor="operator")
    print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
    return 0 if res.get("ok") else 1


def cmd_actions(a, store: Store) -> int:
    from . import contain
    if a.what in ("approve", "deny"):
        if a.action_id is None:
            raise SystemExit("give the action id")
        res = contain.decide(store, a.action_id, approve=a.what == "approve")
        print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
        return 0 if res.get("ok") else 1
    rows = store.actions(state="pending" if a.what == "pending" else None, limit=a.limit)
    if a.json:
        _out(rows)
        return 0
    for r in rows:
        t = r["target"]
        what = t.get("path") or t.get("name") or t.get("ip") or t.get("pid") or ""
        mark = "pending" if r["state"] == "pending" else "ok" if r["ok"] else "failed" if r["ok"] == 0 else r["state"]
        undone = " (undone)" if r.get("undone") else ""
        print(f"{r['id']:>4}  {util.iso(r['ts'])[:19]}  {r['actor']:<10} {r['action']:<16} {mark:<8}{undone}  {util.truncate(what, 90)}")
    return 0


def cmd_quarantine(a, store: Store) -> int:
    from . import quarantine
    if a.what == "list":
        items = quarantine.items()
        if a.json:
            _out(items)
        else:
            for it in items:
                print(f"{it['id']}  {util.iso(it['when'])[:19]}  {it['size']:>10}  {it['original']}")
            print(f"{len(items)} item(s) in quarantine at {quarantine.vault()}")
        return 0
    if not a.item:
        raise SystemExit("give the quarantine id")
    if a.what == "restore":
        res = quarantine.restore(a.item, overwrite=a.force)
    else:
        if not a.yes:
            raise SystemExit("deleting from quarantine is permanent; add --yes to confirm")
        res = quarantine.delete(a.item)
    print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
    return 0 if res.get("ok") else 1


def cmd_isolate(a, store: Store) -> int:
    from . import contain
    if a.what == "status":
        _out(contain.isolation_state())
        return 0
    res = contain.execute(store, "isolate" if a.what == "on" else "release", {"type": "host"}, actor="operator")
    print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
    return 0 if res.get("ok") else 1


def cmd_monitor(a, store: Store) -> int:
    from . import monitor
    if a.what == "run":
        return monitor.run(once=a.once)
    if a.what == "start":
        res = monitor.start()
    elif a.what == "stop":
        res = monitor.stop()
    else:
        res = monitor.status()
    _out(res)
    return 0


def cmd_ui(a, store: Store) -> int:
    from . import ui
    browser = not a.no_browser
    if a.what == "run":
        store.close()               # the dashboard opens the database per request; this one would only sit idle
        return ui.run(a.port, browser=browser)
    if a.what == "status":
        _out(ui.status(a.port))
        return 0
    if a.what == "stop":
        res = ui.stop(a.port)
        print(res["message"])
        return 0 if res.get("ok") else 1
    res = ui.open_dashboard(a.port, browser=browser)
    print(res["message"] + (f": {res['url']}" if res.get("url") else ""))
    if not res.get("ok"):
        return 1
    if res.get("opened"):
        print("It is open in your browser, signed in.")
        return 0
    if browser:
        print("No browser opened it. Paste this link into a browser on this PC yourself.")
    print(f"Sign-in link, works once: {res['sign_in_link']}")
    return 1 if browser else 0


def cmd_app(a, store: Store) -> int:
    """What a shortcut runs. There is no console then, so a problem is shown in a message box."""
    from . import ui, winapi
    store.close()
    res = ui.open_dashboard(a.port)
    if res.get("ok") and res.get("opened"):
        return 0
    if res.get("ok"):
        text = ("HostGuard is running, but no browser opened its dashboard.\n\n"
                "Open this link in a browser on this PC. It works once. Ctrl+C copies this message.\n\n" + res["sign_in_link"])
    else:
        text = "HostGuard's dashboard could not start.\n\n" + str(res.get("message"))
    print(text)
    winapi.message_box("HostGuard", text, error=not res.get("ok"))
    return 1


def cmd_shortcuts(a, store: Store) -> int:
    from . import shortcuts
    if a.what == "status":
        _out(shortcuts.status())
        return 0
    res = shortcuts.add() if a.what == "add" else shortcuts.remove()
    print(res["message"])
    return 0 if res.get("ok") else 1


def cmd_triage(a, store: Store) -> int:
    from . import agent
    ids = [_need(store, a.id)["id"]] if a.id else [r["id"] for r in store.findings((OPEN,), min_severity=a.min_severity)
                                                   if not r.get("verdict") or a.again][:a.limit]
    if not ids:
        print("Nothing to triage.")
        return 0
    for fid in ids:
        res = agent.triage(store, fid, model=a.model, endpoint=a.endpoint, log=None if a.json else print)
        _out(res) if a.json else print(f"\n{fid[:8]}: {res.get('verdict')} ({res.get('confidence')}): {res.get('summary')}\n")
    return 0


def cmd_ask(a, store: Store) -> int:
    from . import agent
    res = agent.investigate(store, " ".join(a.question), model=a.model, endpoint=a.endpoint, log=None if a.json else print)
    _out(res) if a.json else print("\n" + str(res.get("answer")))
    return 0


def cmd_harden(a, store: Store) -> int:
    from . import harden
    if a.what == "status":
        rows = harden.status()
        if a.json:
            _out(rows)
        else:
            for r in rows:
                print(f"{'on ' if r['on'] else 'off' if r['on'] is False else '?  '}  {r['id']:<22} {r['title']}")
        return 0
    if not a.name:
        raise SystemExit("give the setting id (see 'harden status')")
    res = harden.set_state(store, a.name, a.what == "apply")
    print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
    return 0 if res.get("ok") else 1


def cmd_canary(a, store: Store) -> int:
    from . import canary
    from .detect import canary as d_canary
    if a.what in ("on", "off", "replace"):
        if a.what == "off":
            res = canary.remove(log=lambda line: print("  " + line, flush=True))
        else:
            print("A hidden folder of decoy documents, and one hidden decoy beside it, go into each of these if Windows allows it:")
            for w in canary.roots():
                print(f"  {w['root']}  ({w['label']})")
            res = canary.place(log=lambda line: print("  " + line, flush=True))
        store.log_action("operator", "canary:remove" if a.what == "off" else "canary:place",
                         {"type": "canary", "name": res.get("name") or "canary files"}, None,
                         state="done" if res.get("ok") else "failed", ok=bool(res.get("ok")), result={"message": res.get("message")})
        print(("OK: " if res.get("ok") else "FAILED: ") + str(res.get("message")))
        return 0 if res.get("ok") else 1
    report = canary.check()
    found = d_canary.detect(report)
    b = canary.brief(report)
    if a.json:
        _out({**b, "detail": report["folders"], "finding": found[0].to_row() if found else None})
    elif not b["on"]:
        print("Canary files: " + ("the record of them cannot be read" if b["record"] in ("damaged", "unread") else
                                  "not placed. 'hostguard canary on' places them."))
    else:
        print(f"Canary files: {b['files']} in {b['folders']} place(s), placed {util.iso(b['placed'])}; "
              + ("none changed" if not b["changed"] else f"{b['changed']} CHANGED in {b['folders_changed']} place(s)")
              + (f"; {b['unread']} could not be checked" if b["unread"] else ""))
        for place in b["places"]:
            print(f"  {place['state']:<11} {place['path']}  ({place['label']})" + (f": {place['note']}" if place["note"] else ""))
        if found:
            print(f"\n{found[0].severity}: {found[0].title}")
    return 1 if found and found[0].severity in ("high", "critical") else 0


def cmd_elevated_scan(a, store: Store) -> int:
    from . import elevate, scan
    print("Requesting administrator rights to read what a normal scan cannot (a UAC prompt will appear)...")
    res = elevate.collect()
    if not res.get("ok"):
        print("FAILED: " + str(res.get("message")))
        return 1
    summary = scan.run(a.profile, store, log=lambda m: print("  " + m, flush=True), elevated_data=elevate.load_latest())
    print()
    print(report.text(store, min_severity="low"))
    return 2 if summary["verdict"]["level"] == "compromised" else 0


def cmd_report(a, store: Store) -> int:
    body = report.markdown(store) if a.format == "md" else json.dumps(
        {"overview": report.overview(store), "findings": store.findings((OPEN,))}, indent=2, default=str)
    if a.out:
        with open(a.out, "w", encoding="utf-8") as f:
            f.write(body)
        print(f"wrote {a.out}")
    else:
        print(body)
    return 0


def cmd_config(a, store: Store) -> int:
    if a.what == "set":
        if not a.key or a.value is None:
            raise SystemExit("usage: config set containment.mode auto")
        try:
            paths.set_value(a.key, a.value)
        except ValueError as e:
            raise SystemExit(str(e)) from None
        print(f"{a.key} = {a.value}")
    else:
        _out(paths.load_config())
    return 0


def cmd_reset(a, store: Store) -> int:
    if not a.yes:
        raise SystemExit("this forgets every finding, the baseline and the action log (quarantined files and settings "
                         "are kept); add --yes to confirm")
    import os
    path = store.path
    store.close()
    removed = 0
    for suffix in ("", "-wal", "-shm"):
        try:
            os.remove(str(path) + suffix)
            removed += 1
        except OSError:
            pass
    print(f"state database removed ({removed} file(s)); the next scan starts fresh")
    return 0


def cmd_selftest(a, store: Store) -> int:
    from . import selftest
    return selftest.run(live_defender=a.defender)


def cmd_components(a, store: Store) -> int:
    from . import addons, components
    if a.what in ("install", "remove"):
        plan = addons.plan(a.name or "")
        if not plan:
            raise SystemExit("name one of the downloadable add-ons: " + ", ".join(addons.PINS))
        if a.what == "install":
            print(f"Pinned on {plan['pinned_on']}; each file must match its SHA-256 or it is thrown away:")
            for f in plan["files"]:
                print(f"  {f['name']} ({f['size_text']}) from {f['source']}")
            res = addons.install(a.name, log=lambda line: print("  " + line, flush=True))
        else:
            res = addons.remove(a.name)
        print(res["message"])
        return 0 if res.get("ok") else 1
    rows = components.status()
    if a.json:
        _out(rows)
    else:
        for r in rows:
            print(f"{'installed' if r['installed'] else 'missing  '}  {r['id']:<14} {r['title']}: {r['detail']}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="hostguard", description="Agentic host detection and response for one Windows PC.")
    ap.add_argument("--version", action="version", version=f"hostguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("scan", help="look for signs of compromise")
    p.add_argument("--profile", choices=("quick", "full", "deep"), default="quick")
    p.add_argument("--json", action="store_true")
    p.add_argument("--quiet", action="store_true")
    p.add_argument("--detail", action="store_true", help="print the evidence under each finding")
    p.add_argument("--min-severity", choices=SEVERITIES, default="low")
    p.add_argument("--policy", action="store_true", help="apply the containment policy to what this scan finds")
    p.add_argument("--use-elevated", action="store_true", help="merge the latest elevated collection, if recent")
    p.set_defaults(fn=cmd_scan)

    p = sub.add_parser("status", help="the verdict and what is open")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_status)

    p = sub.add_parser("findings", help="list findings")
    p.add_argument("--all", action="store_true", help="include allowed, resolved and gone")
    p.add_argument("--severity", choices=SEVERITIES)
    p.add_argument("--category")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_findings)

    p = sub.add_parser("show", help="one finding in full")
    p.add_argument("id")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_show)

    for name, text in (("allow", "mark a finding as expected"), ("resolve", "mark a finding as dealt with"),
                       ("reopen", "put a finding back on the list")):
        p = sub.add_parser(name, help=text)
        p.add_argument("id")
        p.add_argument("--note")
        p.set_defaults(fn=cmd_disposition)

    p = sub.add_parser("baseline", help="accept the current autoruns, accounts and listeners as known")
    p.add_argument("what", choices=("accept", "status"))
    p.set_defaults(fn=cmd_baseline)

    p = sub.add_parser("contain", help="run a containment action")
    p.add_argument("action", choices=("suspend", "resume", "kill", "quarantine", "disable_autorun", "block_ip", "unblock_ip",
                                      "disable_user", "defender_scan"))
    p.add_argument("target", nargs="*", help="pid=1234 | path=C:\\x.exe | ip=203.0.113.9 | name=user")
    p.add_argument("--finding", help="act on this finding's subject")
    p.add_argument("--dry-run", action="store_true", help="check the guardrails and say what would happen")
    p.add_argument("--force", action="store_true", help="override a guardrail that protects signed or system files")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_contain)

    p = sub.add_parser("undo", help="reverse a containment action")
    p.add_argument("action_id", type=int)
    p.set_defaults(fn=cmd_undo)

    p = sub.add_parser("actions", help="the containment log, and approvals")
    p.add_argument("what", nargs="?", choices=("list", "pending", "approve", "deny"), default="list")
    p.add_argument("action_id", nargs="?", type=int)
    p.add_argument("--limit", type=int, default=50)
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_actions)

    p = sub.add_parser("quarantine", help="the quarantine vault")
    p.add_argument("what", choices=("list", "restore", "delete"))
    p.add_argument("item", nargs="?")
    p.add_argument("--force", action="store_true", help="restore over an existing file")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_quarantine)

    p = sub.add_parser("isolate", help="cut this PC off from the network (loopback keeps working)")
    p.add_argument("what", choices=("on", "off", "status"))
    p.set_defaults(fn=cmd_isolate)

    p = sub.add_parser("monitor", help="the real-time monitor")
    p.add_argument("what", choices=("run", "start", "stop", "status"))
    p.add_argument("--once", action="store_true", help="one pass, then exit")
    p.set_defaults(fn=cmd_monitor)

    p = sub.add_parser("ui", help="the dashboard: a page served to this PC only")
    p.add_argument("what", nargs="?", choices=("open", "start", "run", "stop", "status"), default="open",
                   help="open (default) starts it if needed and opens the browser; run serves in this window")
    p.add_argument("--port", type=int, default=8930)
    p.add_argument("--no-browser", action="store_true", help="do not open the browser; print a one-time sign-in link instead")
    p.set_defaults(fn=cmd_ui)

    p = sub.add_parser("app", help="open the dashboard the way the shortcut does: problems appear in a message box")
    p.add_argument("--port", type=int, default=8930)
    p.set_defaults(fn=cmd_app)

    p = sub.add_parser("shortcuts", help="Desktop and Start Menu shortcuts that open the dashboard")
    p.add_argument("what", choices=("add", "remove", "status"))
    p.set_defaults(fn=cmd_shortcuts)

    p = sub.add_parser("triage", help="have the agent investigate findings")
    p.add_argument("id", nargs="?")
    p.add_argument("--min-severity", choices=SEVERITIES, default="medium")
    p.add_argument("--limit", type=int, default=10)
    p.add_argument("--again", action="store_true", help="re-triage findings that already have a verdict")
    p.add_argument("--model")
    p.add_argument("--endpoint")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_triage)

    p = sub.add_parser("ask", help="ask the agent a question about this PC")
    p.add_argument("question", nargs="+")
    p.add_argument("--model")
    p.add_argument("--endpoint")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_ask)

    p = sub.add_parser("harden", help="free Windows protections that are off by default")
    p.add_argument("what", choices=("status", "apply", "revert"))
    p.add_argument("name", nargs="?")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_harden)

    p = sub.add_parser("canary", help="ransomware canaries: decoy documents that raise the alarm when something rewrites them")
    p.add_argument("what", nargs="?", choices=("status", "on", "off", "replace"), default="status",
                   help="on places them, replace puts a fresh set down, off removes the ones that are unchanged")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_canary)

    p = sub.add_parser("elevated-scan", help="scan again with administrator-only sources included (UAC prompt)")
    p.add_argument("--profile", choices=("quick", "full", "deep"), default="quick")
    p.set_defaults(fn=cmd_elevated_scan)

    p = sub.add_parser("report", help="write the findings as Markdown or JSON")
    p.add_argument("--format", choices=("md", "json"), default="md")
    p.add_argument("--out")
    p.set_defaults(fn=cmd_report)

    p = sub.add_parser("config", help="show or change settings")
    p.add_argument("what", nargs="?", choices=("show", "set"), default="show")
    p.add_argument("key", nargs="?")
    p.add_argument("value", nargs="?")
    p.set_defaults(fn=cmd_config)

    p = sub.add_parser("reset", help="forget all findings and the baseline")
    p.add_argument("--yes", action="store_true")
    p.set_defaults(fn=cmd_reset)

    p = sub.add_parser("selftest", help="check that detection, quarantine and containment work")
    p.add_argument("--defender", action="store_true", help="also drop an EICAR test file to confirm Defender reacts")
    p.set_defaults(fn=cmd_selftest)

    p = sub.add_parser("components", help="optional open-source add-ons: list them, download one, remove one")
    p.add_argument("what", nargs="?", choices=("list", "install", "remove"), default="list")
    p.add_argument("name", nargs="?", help="yara, hollows_hunter or hayabusa")
    p.add_argument("--json", action="store_true")
    p.set_defaults(fn=cmd_components)
    return ap


def app_main() -> int:
    """The windowless `hostguardw` command that pip installs: the same as `hostguard app`."""
    return main(["app"])


def main(argv: list[str] | None = None) -> int:
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(encoding="utf-8", errors="replace")
        except (AttributeError, ValueError):
            pass
    a = build_parser().parse_args(argv)
    store = Store()
    try:
        return int(a.fn(a, store) or 0)
    except KeyboardInterrupt:
        return 130
    finally:
        try:
            store.close()
        except Exception:
            pass
