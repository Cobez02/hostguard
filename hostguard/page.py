"""The dashboard page: one self-contained document with its own styles and script.

ui.py serves these templates. {{NONCE}} is replaced per response and named in the
Content-Security-Policy, so nothing here may use an inline style attribute or an inline event
handler: the browser would refuse it. All text that comes from the PC (file names, command lines,
model output) is put on the page as text, never as markup.
"""

_ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%232457d6' "
         "d='M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z'/%3E%3C/svg%3E")

_CSS = r"""
:root {
  color-scheme: light dark;
  --bg: #f4f5f7; --panel: #ffffff; --ink: #171a20; --muted: #5b6472; --line: #dde1e8; --soft: #eef1f5;
  --accent: #2457d6; --on-accent: #ffffff; --ok: #177245; --warn: #8f5405; --bad: #c2362b;
  --ok-bg: #e5f4ec; --warn-bg: #fdf1dc; --bad-bg: #fde8e6; --info-bg: #e8effd;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #0e1116; --panel: #161a21; --ink: #e6e9ef; --muted: #98a1b0; --line: #29303a; --soft: #1e242d;
    --accent: #7aa2ff; --on-accent: #0b1220; --ok: #4fc890; --warn: #f0b458; --bad: #ff8073;
    --ok-bg: #12301f; --warn-bg: #35280f; --bad-bg: #3a1a17; --info-bg: #18243d;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { font: 14px/1.5 "Segoe UI", system-ui, -apple-system, sans-serif; }
body { margin: 0; background: var(--bg); color: var(--ink); }
button, input, select, textarea { font: inherit; color: inherit; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
h1 { font-size: 20px; margin: 0 0 12px; }
h2 { font-size: 15px; margin: 0 0 10px; }
h3 { font-size: 12px; margin: 16px 0 4px; color: var(--muted); text-transform: uppercase; letter-spacing: .05em; }
p { margin: 0 0 10px; }
code { background: var(--soft); border-radius: 4px; padding: 1px 5px; font: 12.5px ui-monospace, Consolas, monospace; }

.top { position: sticky; top: 0; z-index: 5; background: var(--panel); border-bottom: 1px solid var(--line); }
.top-in { max-width: 1320px; margin: 0 auto; padding: 10px 20px 0; }
.brandrow { display: flex; align-items: center; gap: 14px; flex-wrap: wrap; }
.brand { display: flex; align-items: center; gap: 8px; font-size: 18px; font-weight: 700; }
.brand svg { width: 22px; height: 22px; fill: var(--accent); }
.pill { border-radius: 999px; padding: 3px 12px; font-weight: 600; background: var(--soft); }
.pill.ok { background: var(--ok-bg); color: var(--ok); }
.pill.warn { background: var(--warn-bg); color: var(--warn); }
.pill.bad { background: var(--bad-bg); color: var(--bad); }
.chips { display: flex; gap: 8px; flex-wrap: wrap; margin-left: auto; }
.chip { font-size: 12px; padding: 2px 10px; border: 1px solid var(--line); border-radius: 999px; color: var(--muted); }
.chip b { color: var(--ink); }
.chip.warn b { color: var(--warn); }
.chip.bad { border-color: var(--bad); }
.chip.bad b { color: var(--bad); }
#tabs { display: flex; gap: 2px; margin-top: 8px; overflow-x: auto; }
#tabs button { border: 0; border-bottom: 2px solid transparent; background: none; padding: 9px 14px; color: var(--muted);
  cursor: pointer; font-weight: 600; white-space: nowrap; }
#tabs button:hover { color: var(--ink); }
#tabs button[aria-selected="true"] { color: var(--accent); border-bottom-color: var(--accent); }
.count { display: inline-block; min-width: 18px; padding: 0 5px; margin-left: 4px; border-radius: 999px; background: var(--warn-bg);
  color: var(--warn); font-size: 11.5px; text-align: center; }

main { max-width: 1320px; margin: 0 auto; padding: 16px 20px 60px; }
body.locked main > section { opacity: .45; pointer-events: none; }
.tab { display: none; }
.tab.on { display: block; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(330px, 1fr)); gap: 14px; margin-bottom: 14px; align-items: start; }
.split { display: grid; grid-template-columns: minmax(0, 3fr) minmax(0, 2fr); gap: 14px; align-items: start; }
@media (max-width: 1050px) { .split { grid-template-columns: minmax(0, 1fr); } }
.card { background: var(--panel); border: 1px solid var(--line); border-radius: 10px; padding: 16px; min-width: 0; }
.detail { position: sticky; top: 104px; max-height: calc(100vh - 124px); overflow: auto; }
@media (max-width: 1050px) { .detail { position: static; max-height: none; } }
.help, .small { font-size: 12.5px; color: var(--muted); }
.help { margin-top: 10px; margin-bottom: 0; }
.small { overflow-wrap: anywhere; }
.muted { color: var(--muted); }
.ok { color: var(--ok); }
.warn { color: var(--warn); }
.bad { color: var(--bad); }
.row { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; margin-top: 10px; }
.row.first { margin-top: 0; margin-bottom: 10px; }
.row.end { justify-content: flex-end; }
.grow { flex: 1; min-width: 200px; }
.verdict { font-size: 20px; font-weight: 700; margin: 0 0 6px; }
.scroll { max-height: 440px; overflow: auto; }
.footer { margin-top: 24px; font-size: 12px; color: var(--muted); }

.b { border: 1px solid var(--line); background: var(--panel); border-radius: 7px; padding: 6px 12px; cursor: pointer; font-weight: 600; }
.b:hover:not(:disabled) { border-color: var(--accent); }
.b:disabled { opacity: .5; cursor: default; }
.b.primary { background: var(--accent); border-color: var(--accent); color: var(--on-accent); }
.b.danger { color: var(--bad); border-color: var(--bad); }
input[type="text"], input[type="search"], select, textarea { border: 1px solid var(--line); background: var(--panel);
  border-radius: 7px; padding: 6px 9px; }
textarea { width: 100%; min-height: 90px; resize: vertical; }
textarea.paths { font: 12px/1.45 ui-monospace, Consolas, monospace; }
label.check { display: inline-flex; align-items: center; gap: 6px; }

.switch { display: flex; align-items: center; gap: 10px; margin: 8px 0; cursor: pointer; position: relative; }
.switch input { position: absolute; opacity: 0; width: 1px; height: 1px; }
/* No transition on purpose: a switch must never be drawn, even for one frame, in a state other than the one read back. */
.switch .track { flex: none; width: 38px; height: 22px; border-radius: 999px; background: var(--muted); position: relative; }
.switch .track::after { content: ""; position: absolute; top: 3px; left: 3px; width: 16px; height: 16px; border-radius: 50%;
  background: #fff; box-shadow: 0 1px 2px rgba(0, 0, 0, .35); }
.switch input:checked + .track { background: var(--ok); }
.switch input:checked + .track::after { transform: translateX(16px); }
.switch input:disabled + .track { opacity: .4; }
.switch input:focus-visible + .track { outline: 2px solid var(--accent); outline-offset: 2px; }
.switch.danger input:checked + .track { background: var(--bad); }
.switch .lbl { font-weight: 600; }

dl.kv { display: grid; grid-template-columns: max-content minmax(0, 1fr); gap: 4px 14px; margin: 10px 0 0; }
dl.kv dt { color: var(--muted); }
dl.kv dd { margin: 0; overflow-wrap: anywhere; }
dl.ev { max-height: 340px; overflow: auto; }
dl.ev dd { font: 12px/1.45 ui-monospace, Consolas, monospace; white-space: pre-wrap; }

.msg { border-radius: 8px; padding: 9px 12px; margin-bottom: 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
.msg.info { background: var(--info-bg); }
.msg.ok { background: var(--ok-bg); }
.msg.warn { background: var(--warn-bg); color: var(--warn); }
.msg.error { background: var(--bad-bg); color: var(--bad); }

.tablewrap { overflow: auto; max-height: 66vh; border: 1px solid var(--line); border-radius: 8px; }
table { border-collapse: collapse; width: 100%; }
th, td { text-align: left; padding: 7px 10px; border-bottom: 1px solid var(--line); vertical-align: top; }
tr:last-child td { border-bottom: 0; }
th { position: sticky; top: 0; background: var(--soft); font-size: 12px; color: var(--muted); text-transform: uppercase; letter-spacing: .04em; }
tr.pick { cursor: pointer; }
tr.pick:hover, tr.sel { background: var(--soft); }
td.nowrap { white-space: nowrap; }
.sev { font-weight: 700; text-transform: capitalize; white-space: nowrap; }
.tag { display: inline-block; font-size: 11.5px; padding: 0 7px; margin-left: 6px; border-radius: 999px; background: var(--soft); color: var(--muted); }
.tag.ok { background: var(--ok-bg); color: var(--ok); }

.item { border-bottom: 1px solid var(--line); padding: 10px 0; }
.item:first-child { padding-top: 0; }
.item:last-child { border-bottom: 0; padding-bottom: 0; }
.item .switch { margin: 0 0 4px; }
ul.list { margin: 0; padding-left: 18px; }

details.job { border: 1px solid var(--line); border-radius: 8px; margin-bottom: 8px; }
details.job summary { padding: 7px 10px; cursor: pointer; }
details.job pre { margin: 0; padding: 8px 10px; max-height: 240px; overflow: auto; background: var(--soft); border-top: 1px solid var(--line);
  font: 12px/1.45 ui-monospace, Consolas, monospace; white-space: pre-wrap; overflow-wrap: anywhere; }
.answer { white-space: pre-wrap; background: var(--soft); border-radius: 8px; padding: 12px; max-height: 56vh; overflow: auto; overflow-wrap: anywhere; }

dialog { border: 1px solid var(--line); border-radius: 12px; background: var(--panel); color: var(--ink); padding: 20px; width: min(540px, 92vw); }
dialog::backdrop { background: rgba(8, 12, 20, .55); }
dialog h2 { font-size: 16px; }
dialog p { white-space: pre-wrap; overflow-wrap: anywhere; }
#toasts { position: fixed; right: 16px; bottom: 16px; display: flex; flex-direction: column; gap: 8px; z-index: 20; max-width: min(440px, 90vw); }
.toast { background: var(--ink); color: var(--bg); padding: 10px 14px; border-radius: 8px; box-shadow: 0 6px 20px rgba(0, 0, 0, .25); overflow-wrap: anywhere; }
.toast.error { background: #b3261e; color: #fff; }

.box { max-width: 560px; margin: 12vh auto; background: var(--panel); border: 1px solid var(--line); border-radius: 12px; padding: 28px; }
.note { background: var(--warn-bg); color: var(--warn); border-radius: 8px; padding: 9px 12px; }
.note:empty { display: none; }
"""

_BODY = r"""
<header class="top"><div class="top-in">
  <div class="brandrow">
    <div class="brand"><svg viewBox="0 0 24 24" aria-hidden="true"><path d="M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z"/></svg>HostGuard</div>
    <span class="pill" id="topVerdict">Reading the current state...</span>
    <div class="chips" id="topChips"></div>
  </div>
  <nav id="tabs" role="tablist" aria-label="Sections">
    <button role="tab" data-tab="overview" aria-selected="true">Overview<span class="count" id="cntPending" hidden></span></button>
    <button role="tab" data-tab="findings" aria-selected="false">Findings<span class="count" id="cntFindings" hidden></span></button>
    <button role="tab" data-tab="response" aria-selected="false">Response</button>
    <button role="tab" data-tab="agent" aria-selected="false">Agent</button>
    <button role="tab" data-tab="hardening" aria-selected="false">Hardening</button>
    <button role="tab" data-tab="settings" aria-selected="false">Settings</button>
  </nav>
</div></header>

<main>
  <div class="msg error" id="lock" role="alert" hidden></div>
  <div id="msgs"></div>

  <section class="tab on" id="tab-overview">
    <div class="grid">
      <div class="card">
        <h2>Is this PC compromised?</h2>
        <p class="verdict muted" id="verdict">Not scanned yet</p>
        <dl class="kv" id="scanKv"></dl>
        <div class="row">
          <button class="b primary" id="scanQuick">Quick scan</button>
          <button class="b" id="scanFull">Full scan</button>
          <button class="b" id="scanDeep">Deep scan</button>
          <button class="b" id="scanAdmin">Scan with admin rights</button>
        </div>
        <div class="row"><button class="b" id="baseline">Accept as baseline</button></div>
        <p class="help">Quick takes about a minute. Full adds your whole profile, ProgramData and 30 days of logs. Deep trusts
          nothing cached and asks Defender about every unsigned program. The admin scan adds the Security log, Defender's
          exclusion list and system processes after one Windows prompt.</p>
      </div>
      <div class="card">
        <h2>Protection</h2>
        <label class="switch"><input type="checkbox" role="switch" id="swMonitor" disabled><span class="track"></span>
          <span class="lbl">Real-time monitor</span></label>
        <label class="switch"><input type="checkbox" role="switch" id="swAutostart" disabled><span class="track"></span>
          <span>Start the monitor when I sign in to Windows</span></label>
        <dl class="kv" id="protKv"></dl>
        <div class="row">
          <button class="b" id="defQuick">Defender quick scan</button>
          <button class="b" id="defUpdate">Update definitions</button>
          <button class="b" id="selftest">Self-test</button>
        </div>
        <p class="help">Microsoft Defender stays the antivirus engine. HostGuard is the layer above it: the compromise check,
          change tracking, containment and the investigating agent.</p>
      </div>
    </div>
    <div class="grid">
      <div class="card"><h2>Waiting for your approval</h2><div id="pending" class="scroll"></div></div>
      <div class="card"><h2>Activity</h2><div id="tasks"></div></div>
    </div>
  </section>

  <section class="tab" id="tab-findings">
    <div class="split">
      <div class="card">
        <h2>Findings</h2>
        <div class="row first">
          <input type="search" id="fFilter" class="grow" placeholder="Filter by text" spellcheck="false" aria-label="Filter findings">
          <label class="check"><input type="checkbox" id="fLow"> Low and informational</label>
          <label class="check"><input type="checkbox" id="fPosture" checked> Hardening gaps</label>
        </div>
        <div class="tablewrap"><table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Area</th><th>Agent</th><th>Seen</th></tr></thead>
          <tbody id="findings"></tbody></table></div>
        <p class="help" id="fCount"></p>
      </div>
      <div class="card detail" id="detail"></div>
    </div>
  </section>

  <section class="tab" id="tab-response">
    <div class="grid">
      <div class="card">
        <h2>Containment</h2>
        <div class="row first"><label for="mode">When something is found</label>
          <select id="mode"><option value="off">Report only</option><option value="ask">Ask me first</option>
            <option value="auto">Contain automatically</option></select></div>
        <div id="autoBox" hidden>
          <div class="row first"><label for="autoSev">Act without asking on</label>
            <select id="autoSev"><option value="critical">critical findings only</option><option value="high">high and critical findings</option>
              <option value="medium">medium findings and above</option></select>
            <label for="autoConf">when confidence is</label>
            <select id="autoConf"><option value="high">high</option><option value="medium">medium or high</option></select></div>
        </div>
        <label class="switch"><input type="checkbox" role="switch" id="swIsoCrit" disabled><span class="track"></span>
          <span>Also cut the network on a critical finding</span></label>
        <label class="switch"><input type="checkbox" role="switch" id="swAgentEsc" disabled><span class="track"></span>
          <span>Let the agent's verdict trigger containment</span></label>
        <dl class="kv" id="containKv"></dl>
        <p class="help">Automatic mode only suspends unsigned programs and script hosts, quarantines unsigned files and switches
          off autoruns. Signed software, Windows components and folders you marked as your own are never touched. Everything
          it does can be undone in the action log, and it never raises a Windows prompt.</p>
      </div>
      <div class="card">
        <h2>Network isolation</h2>
        <label class="switch danger"><input type="checkbox" role="switch" id="swIsolate" disabled><span class="track"></span>
          <span class="lbl" id="isoLbl">State unknown</span></label>
        <dl class="kv" id="isoKv"></dl>
        <p class="help">Blocks every connection in and out with two firewall rules. This dashboard and a model running on this
          PC keep working. Turning it off always asks for administrator rights. Containers and virtual machines keep their
          own route.</p>
      </div>
    </div>
    <div class="grid">
      <div class="card"><h2>Quarantine</h2><div id="quarantine" class="scroll"></div></div>
      <div class="card"><h2>Action log</h2><div id="actions" class="scroll"></div></div>
    </div>
  </section>

  <section class="tab" id="tab-agent">
    <div class="grid">
      <div class="card">
        <h2>Triage agent</h2>
        <dl class="kv" id="agentKv"></dl>
        <div class="row"><label for="model">Model</label><select id="model"></select></div>
        <label class="switch"><input type="checkbox" role="switch" id="swOnline" disabled><span class="track"></span>
          <span>Let the agent check file hashes against an online catalogue</span></label>
        <div class="row"><button class="b primary" id="triageAll">Triage open findings</button></div>
        <p class="help">A language model investigates a finding with read-only tools and reports a verdict with its evidence.
          It has no tool that changes anything. A "benign" verdict closes nothing; a "malicious" one queues a request for
          you. With the online switch on, only a file's SHA-256 is sent, to CIRCL's hashlookup service.</p>
      </div>
      <div class="card">
        <h2>Ask about this PC</h2>
        <div class="row first"><input type="text" id="question" class="grow" spellcheck="false" aria-label="Question"
            placeholder="For example: what is listening on port 3389, and why?">
          <button class="b primary" id="ask">Ask</button></div>
        <div id="answer"></div>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-hardening">
    <div class="grid">
      <div class="card">
        <h2>Free Windows protections</h2>
        <p class="small">Each switch shows what Windows reports now. Changing one asks for administrator rights.</p>
        <div id="harden"><span class="muted">Reading the settings from Windows...</span></div>
      </div>
      <div class="card">
        <h2>Optional open-source add-ons</h2>
        <p class="small">HostGuard downloads nothing. Put a tool in its folder and the next scan uses it.</p>
        <div id="addons"></div>
      </div>
    </div>
  </section>

  <section class="tab" id="tab-settings">
    <div class="grid">
      <div class="card">
        <h2>Your own security tooling</h2>
        <p class="small">One folder per line. Findings inside stay visible but are marked down, and automatic containment
          never touches them.</p>
        <textarea class="paths" id="trusted" spellcheck="false" aria-label="Trusted folders"></textarea>
        <div class="row"><button class="b" id="trustedSave">Save</button></div>
      </div>
      <div class="card">
        <h2>Notifications</h2>
        <label class="switch"><input type="checkbox" role="switch" id="swNotify" disabled><span class="track"></span>
          <span>Show a Windows notification when the monitor finds something</span></label>
        <h3>What the last scan could not see</h3>
        <ul class="list small" id="notes"></ul>
      </div>
      <div class="card">
        <h2>This dashboard</h2>
        <dl class="kv" id="aboutKv"></dl>
        <div class="row"><button class="b" id="stopUi">Stop the dashboard</button></div>
        <p class="help">The dashboard answers on this PC only and signs you in with a link that works once. Stopping it does
          not stop the real-time monitor or Microsoft Defender.</p>
      </div>
    </div>
  </section>

  <p class="footer">HostGuard {{VERSION}}. Runs on this PC only.</p>
</main>

<dialog id="dlg" aria-labelledby="dlgTitle">
  <h2 id="dlgTitle"></h2>
  <p id="dlgText"></p>
  <textarea id="dlgInput" aria-label="Note" hidden></textarea>
  <div class="row end">
    <button class="b" id="dlgCancel">Cancel</button>
    <button class="b" id="dlgAlt" hidden></button>
    <button class="b primary" id="dlgOk">OK</button>
  </div>
</dialog>
<div id="toasts" aria-live="polite"></div>
"""

_JS = r"""
"use strict";
(() => {
  const $ = (id) => document.getElementById(id);
  const S = { data: null, sel: null, tab: "overview", lock: null, busy: false, working: false, hardenAt: 0, trustedDirty: false };
  const painted = new Map();
  const TABS = ["overview", "findings", "response", "agent", "hardening", "settings"];
  const ACTION_LABEL = { suspend: "Suspend", resume: "Resume", kill: "Stop for good", quarantine: "Quarantine file",
    disable_autorun: "Switch off autorun", block_ip: "Block address", unblock_ip: "Unblock address", disable_user: "Disable account",
    defender_scan: "Let Defender clean it", isolate: "Isolate network", release: "Restore network" };
  const LOCK_TEXT = {
    offline: "The dashboard is not answering. If it was stopped, open it again from the HostGuard dashboard shortcut. This page reconnects by itself.",
    signedout: "Signed out: the dashboard was restarted after this page was opened. Open it again from the HostGuard dashboard shortcut.",
    stopped: "The dashboard has been stopped. The real-time monitor is not affected. Open the dashboard again from its shortcut.",
  };

  // ------------------------------------------------------------ building blocks

  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v === null || v === undefined || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "text") n.textContent = v;
      else if (k.startsWith("on") && typeof v === "function") n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : String(v));
    }
    for (const kid of kids.flat(3)) {
      if (kid === null || kid === undefined || kid === false) continue;
      n.append(kid instanceof Node ? kid : document.createTextNode(String(kid)));
    }
    return n;
  }

  // Rebuild a part of the page only when what it shows has changed, so polling does not disturb
  // a selection, a scroll position or an open list.
  function paint(box, data, build) {
    const sig = JSON.stringify(data === undefined ? null : data);
    if (painted.get(box) === sig) return;
    painted.set(box, sig);
    const kids = build();
    box.replaceChildren(...(Array.isArray(kids) ? kids : [kids]).flat(3).filter(Boolean));
  }

  function kv(dl, pairs) {
    const rows = pairs.filter((p) => p && p[1] !== null && p[1] !== undefined && p[1] !== "");
    paint(dl, rows, () => rows.flatMap(([k, v, cls]) => [el("dt", { text: k }), el("dd", { class: cls || null, text: String(v) })]));
  }

  function msgs(box, list) {
    const rows = list.filter(Boolean);
    paint(box, rows, () => rows.map(([kind, text]) => el("div", { class: "msg " + kind, text })));
  }

  function toast(text, kind) {
    const t = el("div", { class: "toast" + (kind === "error" ? " error" : ""), role: "status", text });
    $("toasts").append(t);
    setTimeout(() => t.remove(), kind === "error" ? 9000 : 4500);
  }

  function flash(r, okText) {
    if (!r) return;
    if (r.error) toast(r.error, "error");
    else if (r.ok === false) toast(r.message || "That did not work.", "error");
    else toast(okText || r.message || "Done.");
  }

  // An in-page dialog. Without `input` it answers true, "alt" or false; with it, the text or null.
  function ask(o) {
    return new Promise((resolve) => {
      const d = $("dlg"), box = $("dlgInput"), wantsText = o.input !== undefined;
      $("dlgTitle").textContent = o.title;
      $("dlgText").textContent = o.text || "";
      box.hidden = !wantsText;
      box.value = wantsText ? o.input : "";
      $("dlgOk").textContent = o.ok || "OK";
      $("dlgOk").className = "b " + (o.danger ? "danger" : "primary");
      $("dlgCancel").textContent = o.cancel || "Cancel";
      $("dlgAlt").hidden = !o.alt;
      $("dlgAlt").textContent = o.alt || "";
      let answered = false;
      const finish = (value) => {
        if (answered) return;
        answered = true;
        if (d.open) d.close();
        resolve(value);
      };
      $("dlgOk").onclick = () => finish(wantsText ? box.value : true);
      $("dlgAlt").onclick = () => finish("alt");
      $("dlgCancel").onclick = () => finish(wantsText ? null : false);
      d.oncancel = (e) => { e.preventDefault(); finish(wantsText ? null : false); };
      d.showModal();
      (wantsText ? box : o.danger ? $("dlgCancel") : $("dlgOk")).focus();
    });
  }

  const when = (ts) => ts ? new Date(ts * 1000).toLocaleString() : "";
  const clock = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : "";
  const minute = () => Math.floor(Date.now() / 60000);
  const ago = (ts) => {
    if (!ts) return "";
    const s = Math.max(0, Date.now() / 1000 - ts);
    return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago";
  };
  const size = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? Math.round(n / 1024) + " KB" : n + " B";
  const sevClass = (s) => (s === "critical" || s === "high") ? "bad" : s === "medium" ? "warn" : "muted";
  const levelClass = (level) => ({ clean: "ok", review: "warn", suspicious: "warn", compromised: "bad" })[level] || "";
  const empty = (text) => el("span", { class: "muted", text });

  // ------------------------------------------------------------ talking to the dashboard

  function setLock(kind) {
    if (S.lock === "stopped" || S.lock === kind) return;
    S.lock = kind;
    document.body.classList.toggle("locked", !!kind);
    $("lock").hidden = !kind;
    $("lock").textContent = kind ? LOCK_TEXT[kind] : "";
  }

  async function api(path, body) {
    const opt = { method: body === undefined ? "GET" : "POST", headers: { "X-HostGuard": "1" }, credentials: "same-origin", cache: "no-store" };
    if (body !== undefined) {
      opt.headers["Content-Type"] = "application/json";
      opt.body = JSON.stringify(body);
    }
    let r;
    try {
      r = await fetch("/api/" + path, opt);
    } catch (e) {
      setLock("offline");
      return { error: "The dashboard is not answering." };
    }
    if (r.status === 401) {
      setLock("signedout");
      return { error: "Signed out." };
    }
    setLock(null);
    let j = null;
    try { j = await r.json(); } catch (e) { j = null; }
    if (!r.ok) return { error: (j && j.error) || "The request failed (" + r.status + ")." };
    return j || {};
  }

  async function act(path, body, okText) {
    const r = await api(path, body === undefined ? {} : body);
    flash(r, okText);
    setTimeout(refresh, 400);
    return r;
  }

  // A switch shows what was read back from Windows or from the settings, never the click itself:
  // the click only sends the request, and the next refresh moves the switch.
  function setSwitch(id, on, unknown) {
    const box = $(id);
    box.checked = on === true;
    box.disabled = !!unknown;
  }

  function actionSwitch(id, fn) {
    const box = $(id);
    box.addEventListener("click", (e) => {
      const want = box.checked;
      e.preventDefault();
      fn(want);
    });
  }

  // ------------------------------------------------------------ drawing

  function chip(label, value, cls) {
    return el("span", { class: "chip" + (cls ? " " + cls : "") }, label + " ", el("b", { text: value }));
  }

  function setCount(id, n) {
    $(id).textContent = n ? String(n) : "";
    $(id).hidden = !n;
  }

  function renderTop(d) {
    const v = d.verdict, pill = $("topVerdict");
    pill.className = "pill " + (d.last_scan ? levelClass(v.level) : "");
    pill.textContent = d.last_scan ? v.text : "Not scanned yet";
    const m = d.monitor || {}, f = d.defender || {}, iso = d.isolation || {}, c = d.containment || {};
    paint($("topChips"), [m.running, f.realtime, iso.isolated, c.mode], () => [
      chip("Monitor", m.running ? "on" : "off", m.running ? "" : "warn"),
      chip("Defender", f.realtime === true ? "on" : f.realtime === false ? "OFF" : "unknown", f.realtime === false ? "bad" : ""),
      chip("Network", iso.isolated === true ? "ISOLATED" : iso.isolated === false ? "connected" : "unknown", iso.isolated === true ? "bad" : ""),
      chip("Containment", { off: "report only", ask: "ask first", auto: "automatic" }[c.mode] || "unknown", ""),
    ]);
    setCount("cntFindings", d.findings.filter((x) => !x.posture && x.status === "open" && sevClass(x.severity) !== "muted").length);
    setCount("cntPending", d.pending.length);
  }

  function renderOverview(d) {
    const v = d.verdict, ls = d.last_scan, c = v.counts, p = v.posture_counts;
    $("verdict").className = "verdict " + (ls ? levelClass(v.level) : "muted");
    $("verdict").textContent = ls ? v.text : "Not scanned yet";
    kv($("scanKv"), [
      ["Last scan", ls ? `${when(ls.ended)} (${ls.profile}, ${ls.seconds} s${ls.elevated ? ", with administrator data" : ""})` : "never"],
      ["Open findings", `${c.critical} critical, ${c.high} high, ${c.medium} medium, ${c.low} low`],
      ["Hardening gaps", `${p.high} high, ${p.medium} medium, ${p.low} low`],
      ["Baseline", d.baseline_time ? "accepted " + when(d.baseline_time) : "not set yet"],
    ]);
    for (const id of ["scanQuick", "scanFull", "scanDeep", "scanAdmin"]) $(id).disabled = d.scanning;
    const m = d.monitor || {}, f = d.defender || {}, n = m.counters || {};
    setSwitch("swMonitor", m.running, false);
    setSwitch("swAutostart", m.autostart, false);
    kv($("protKv"), [
      ["Monitor", m.running ? `running (pid ${m.pid}); ${n.processes || 0} new processes, ${n.connections || 0} connections and ${n.findings || 0} findings since it started` : "stopped", m.running ? null : "warn"],
      ["Monitor error", m.last_error, "bad"],
      ["Defender real-time", f.error ? "unknown: " + f.error : f.realtime === true ? "on" : f.realtime === false ? "OFF" : "unknown", f.realtime === false ? "bad" : null],
      ["Tamper protection", f.tamper === true ? "on" : f.tamper === false ? "OFF" : null, f.tamper === false ? "bad" : null],
      ["Definitions", f.signature_age_days == null ? null : (f.signature_age_days === 0 ? "updated today" : f.signature_age_days + " day(s) old") + (f.version ? ` (${f.version})` : "")],
      ["Last Defender quick scan", f.quick_scan_age_days == null ? null : f.quick_scan_age_days > 60000 ? "never" : f.quick_scan_age_days === 0 ? "today" : f.quick_scan_age_days + " day(s) ago"],
    ]);
  }

  function renderPending(d) {
    paint($("pending"), [d.pending, minute()], () => d.pending.length ? d.pending.map((p) => {
      const t = p.target || {};
      const what = t.path || t.name || t.ip || (t.pid ? "pid " + t.pid : "") || t.type || "";
      return el("div", { class: "item" },
        el("div", {}, el("b", { text: (ACTION_LABEL[p.action] || p.action) + ": " }), String(what)),
        el("div", { class: "small", text: [p.finding_title, `asked by ${p.actor} ${ago(p.ts)}`, p.reason].filter(Boolean).join(" | ") }),
        el("div", { class: "row" },
          el("button", { class: "b primary", text: "Approve", onclick: () => act("approve", { action_id: p.id, approve: true }) }),
          el("button", { class: "b", text: "Deny", onclick: () => act("approve", { action_id: p.id, approve: false }) }),
          p.finding_id ? el("button", { class: "b", text: "Show the finding", onclick: () => { showTab("findings"); select(p.finding_id); } }) : null));
    }) : empty("Nothing is waiting."));
  }

  function renderTasks(d) {
    const box = $("tasks");
    const open = new Map([...box.querySelectorAll("details")].map((x) => [x.dataset.id, x.open]));
    paint(box, d.tasks.map((t) => [t.id, t.state, t.log.length]), () => d.tasks.length ? d.tasks.map((t, i) => {
      const pre = el("pre", { text: t.log.join("\n") || "(working...)" });
      const det = el("details", { class: "job", "data-id": t.id },
        el("summary", {}, el("b", { text: t.title }), " ",
          el("span", { class: t.state === "done" ? "ok" : t.state === "failed" ? "bad" : "warn", text: t.state }),
          el("span", { class: "muted", text: "  " + clock(t.started) })), pre);
      det.open = open.has(t.id) ? open.get(t.id) : i === 0;
      if (t.state === "running") requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
      return det;
    }) : empty("Nothing has run since the dashboard started."));
  }

  function shownFindings(d) {
    const low = $("fLow").checked, posture = $("fPosture").checked, q = $("fFilter").value.trim().toLowerCase();
    return d.findings.filter((f) => (posture || !f.posture)
      && (low || sevClass(f.severity) !== "muted" || f.status === "contained")
      && (!q || [f.title, f.rule, f.category, f.severity, ...f.tags].join(" ").toLowerCase().includes(q)));
  }

  function renderFindings(d) {
    const rows = shownFindings(d);
    $("fCount").textContent = `${rows.length} shown of ${d.findings.length} open. Select a row for its evidence and actions.`;
    paint($("findings"), [rows, S.sel, minute(), !!d.last_scan], () => rows.length ? rows.map((f) => {
      const v = f.verdict;
      return el("tr", { class: "pick" + (S.sel === f.id ? " sel" : ""), tabindex: "0", onclick: () => select(f.id),
          onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(f.id); } } },
        el("td", { class: "sev " + sevClass(f.severity), text: f.severity }),
        el("td", {}, f.title, f.tags.map((t) => el("span", { class: "tag", text: t })),
          f.status === "contained" ? el("span", { class: "tag ok", text: "contained" }) : null),
        el("td", { class: "nowrap muted", text: f.posture ? "hardening" : f.category }),
        el("td", { class: "nowrap " + (v ? (v.verdict === "malicious" ? "bad" : v.verdict === "suspicious" ? "warn" : "ok") : "muted"), text: v ? v.verdict : "" }),
        el("td", { class: "nowrap muted", text: ago(f.last_seen) }));
    }) : el("tr", {}, el("td", { colspan: "5", class: "muted", text: d.last_scan ? "Nothing matches at this level." : "Run a scan to fill this list." })));
  }

  async function select(id) {
    S.sel = id;
    if (S.data) renderFindings(S.data);
    await loadDetail(true);
  }

  async function loadDetail(reveal) {
    const box = $("detail");
    if (!S.sel) {
      paint(box, "none", () => el("p", { class: "muted", text: "Select a finding to see its evidence and what you can do about it." }));
      return;
    }
    const id = S.sel;
    const f = await api("finding?id=" + encodeURIComponent(id));
    if (S.sel !== id) return;                       // another row was picked while this one loaded
    if (f.error) {
      if (!S.lock) paint(box, f, () => el("div", { class: "msg error", text: f.error }));
      return;
    }
    paint(box, f, () => detailNodes(f));
    if (reveal && window.matchMedia("(max-width: 1050px)").matches) box.scrollIntoView({ behavior: "smooth", block: "start" });
  }

  function detailNodes(f) {
    const pairs = [];
    for (const [k, v] of Object.entries(f.evidence || {})) {
      if (v === null || v === "" || v === false) continue;
      pairs.push(el("dt", { text: k.replace(/_/g, " ") }), el("dd", { text: typeof v === "object" ? JSON.stringify(v, null, 1) : String(v) }));
    }
    const live = f.status === "open" || f.status === "contained";
    const buttons = (f.actions || []).filter((a) => ACTION_LABEL[a] && a !== "isolate").map((a) =>
      el("button", { class: "b" + (a === "kill" || a === "disable_user" ? " danger" : ""), text: ACTION_LABEL[a], onclick: () => contain(f, a) }));
    const vd = f.verdict;
    const facts = [`rule ${f.rule}`, `confidence ${f.confidence}`, `status ${f.status}`, `first seen ${when(f.first_seen)}`,
      (f.mitre || []).length ? "ATT&CK " + f.mitre.join(", ") : null].filter(Boolean).join(" | ");
    return [
      el("h2", {}, el("span", { class: "sev " + sevClass(f.severity), text: f.severity }), "  " + f.title),
      el("p", { text: f.description || "" }),
      el("p", { class: "small", text: facts }),
      f.remediation ? el("div", { class: "msg info", text: "What to do: " + f.remediation }) : null,
      f.note ? el("div", { class: "msg info", text: "Note: " + f.note }) : null,
      vd ? el("div", { class: "msg " + (vd.verdict === "malicious" ? "error" : vd.verdict === "suspicious" ? "warn" : "ok"),
        text: `Agent verdict (${vd.model || "model"}): ${vd.verdict}, confidence ${vd.confidence}\n${vd.summary || ""}`
          + ((vd.evidence || []).length ? "\n- " + vd.evidence.join("\n- ") : "") + (vd.note ? "\n" + vd.note : "") }) : null,
      pairs.length ? el("dl", { class: "kv ev" }, pairs) : null,
      el("div", { class: "row" }, live ? buttons : null,
        el("button", { class: "b", text: "Investigate with agent", onclick: () => act("triage", { id: f.id }) }),
        live ? el("button", { class: "b", text: "Expected (allow)", onclick: () => dispose(f, "allow") }) : null,
        live ? el("button", { class: "b", text: "Dealt with", onclick: () => dispose(f, "resolve") }) : null,
        live ? null : el("button", { class: "b", text: "Reopen", onclick: () => act("finding/status", { id: f.id, status: "reopen" }) })),
      (f.history || []).length ? el("p", { class: "help", text: "History: " + f.history.map((h) => `${when(h.ts)} ${h.actor} ${h.action} (${h.state})`).join("; ") }) : null,
    ];
  }

  async function contain(f, a) {
    if (a === "kill" || a === "disable_user") {
      const sure = await ask({ title: ACTION_LABEL[a] + "?", text: f.title + "\n\nThis one cannot be undone from here.", ok: ACTION_LABEL[a], danger: true });
      if (!sure) return;
    }
    await act("contain", { id: f.id, action: a });
  }

  async function dispose(f, status) {
    const note = await ask({ title: status === "allow" ? "Mark as expected" : "Mark as dealt with",
      text: f.title + "\n\nOptional note: why is this expected, or how was it dealt with?", input: f.note || "", ok: "Save" });
    if (note === null) return;
    const r = await act("finding/status", { id: f.id, status, note });
    if (!r.error) {
      S.sel = null;
      loadDetail(false);
    }
  }

  function renderResponse(d) {
    const c = d.containment || {}, auto = c.mode === "auto";
    if (document.activeElement !== $("mode")) $("mode").value = c.mode || "ask";
    $("autoBox").hidden = !auto;
    if (document.activeElement !== $("autoSev")) $("autoSev").value = c.auto_min_severity || "critical";
    if (document.activeElement !== $("autoConf")) $("autoConf").value = c.auto_min_confidence || "high";
    setSwitch("swIsoCrit", c.isolate_on_critical, false);
    setSwitch("swAgentEsc", c.agent_can_escalate, false);
    kv($("containKv"), [
      ["A flagged program is", auto ? ({ suspend: "suspended (it can be resumed)", kill: "stopped", none: "left running" }[c.process_action] || c.process_action) : null],
      ["Hourly limit", auto ? `${c.max_auto_actions_per_hour} automatic actions, then it asks` : null],
    ]);
    const iso = d.isolation || {}, unknown = iso.isolated !== true && iso.isolated !== false;
    setSwitch("swIsolate", iso.isolated === true, unknown);
    $("isoLbl").textContent = iso.isolated === true ? "ISOLATED: the network is cut" : iso.isolated === false ? "Connected" : "State unknown";
    kv($("isoKv"), [
      ["Firewall rules", iso.isolated === true ? "HostGuard-Isolation-Out and -In are present" : iso.isolated === false ? "not present" : "could not be read", iso.isolated === true ? "bad" : null],
      ["One-click task", iso.one_click_task ? "installed (cutting the network needs no prompt)" : "not installed (see Hardening)"],
    ]);
    paint($("quarantine"), d.quarantine, () => d.quarantine.length ? d.quarantine.map((i) => el("div", { class: "item" },
      el("div", { class: "small", text: i.original }),
      el("div", { class: "small", text: `${when(i.when)} | ${size(i.size)} | sha256 ${String(i.sha256 || "").slice(0, 16)}...` }),
      el("div", { class: "row" },
        el("button", { class: "b", text: "Restore", onclick: async () => {
          if (await ask({ title: "Put this file back where it was?", text: i.original, ok: "Restore" })) act("quarantine", { id: i.id, what: "restore" });
        } }),
        el("button", { class: "b danger", text: "Delete for good", onclick: async () => {
          if (await ask({ title: "Delete the quarantined copy for good?", text: i.original + "\n\nThis cannot be undone.", ok: "Delete for good", danger: true }))
            act("quarantine", { id: i.id, what: "delete" });
        } })))) : empty("Empty."));
    paint($("actions"), [d.actions, minute()], () => d.actions.length ? d.actions.map((x) => el("div", { class: "item" },
      el("div", {}, el("b", { text: (ACTION_LABEL[x.action] || x.action) + " " }),
        el("span", { class: x.state === "refused" || x.state === "denied" || x.ok === 0 || x.ok === false ? "bad" : x.undone || x.state === "approved" ? "muted" : "ok",
          text: x.undone ? "undone" : ["refused", "denied", "approved"].includes(x.state) ? x.state : x.ok ? "done" : x.state }),
        el("span", { class: "muted", text: `  ${x.actor}, ${ago(x.ts)}` })),
      el("div", { class: "small", text: (x.target || "") + (x.message ? " | " + x.message : "") }),
      x.undoable ? el("div", { class: "row" }, el("button", { class: "b", text: "Undo", onclick: () => act("undo", { action_id: x.id }) })) : null))
      : empty("No actions yet."));
  }

  function renderAgent(d) {
    const a = d.agent || {}, c = d.agent_cfg || {};
    kv($("agentKv"), [
      ["Endpoint", (c.endpoint || "") + (a.local === false ? " (NOT on this PC: finding details are sent there)" : " (on this PC)"), a.local === false ? "warn" : null],
      ["Status", a.ok === false ? "unavailable: " + a.message : a.message, a.ok === false ? "warn" : null],
      ["In memory now", (a.loaded || []).length ? a.loaded.join(", ") : null],
    ]);
    const models = a.models || [], box = $("model");
    if (document.activeElement !== box) {
      paint(box, [models, a.model, c.model], () => [
        el("option", { value: "", text: "Choose automatically" + (a.model && !c.model ? ` (${a.model})` : "") }),
        ...models.map((m) => el("option", { value: m, text: m }))]);
      box.value = c.model || "";
    }
    setSwitch("swOnline", c.online_lookups, false);
    $("triageAll").disabled = $("ask").disabled = a.ok !== true;
    const ans = d.answer;
    paint($("answer"), ans, () => ans ? [
      el("p", { class: "small", text: [when(ans.when), ans.question, ans.model, (ans.tools_used || []).length ? "checked: " + ans.tools_used.join(", ") : null].filter(Boolean).join(" | ") }),
      el("div", { class: "answer", text: ans.answer || "(the model gave no answer)" })]
      : el("p", { class: "muted", text: "The answer appears here, with the checks the agent ran to reach it." }));
  }

  function renderAddons(d) {
    const rows = d.addons || [];
    paint($("addons"), rows, () => rows.map((a) => el("div", { class: "item" },
      el("div", {}, el("b", { text: a.title }), el("span", { class: "tag" + (a.installed ? " ok" : ""), text: a.installed ? "installed" : "not installed" })),
      el("div", { class: "small", text: a.adds }),
      el("div", { class: "small", text: a.installed ? a.detail : [a.get, a.place].filter(Boolean).join(". ") }))));
  }

  function renderSettings(d) {
    if (!S.trustedDirty && document.activeElement !== $("trusted")) $("trusted").value = (d.trusted_paths || []).join("\n");
    setSwitch("swNotify", d.notify, false);
    const notes = (d.last_scan && d.last_scan.notes) || [];
    paint($("notes"), [notes, !!d.last_scan], () => (notes.length ? notes : [d.last_scan ? "Nothing was reported as unreadable." : "No scan has run yet."])
      .map((t) => el("li", { text: t })));
    kv($("aboutKv"), [
      ["Version", d.version],
      ["Address", location.origin + " (this PC only)"],
      ["State folder", d.state_folder],
      ["Administrator rights", d.elevated ? "this dashboard is running elevated" : "none (Windows asks when an action needs them)"],
      ["Python", d.sandboxed_python ? "Microsoft Store edition: its AppData is private, and HostGuard works around that" : null],
    ]);
  }

  async function refreshHardening(force) {
    if (!force && Date.now() - S.hardenAt < 15000) return;
    S.hardenAt = Date.now();
    const r = await api("hardening");
    if (r.error) {
      if (!S.lock) paint($("harden"), r, () => el("div", { class: "msg error", text: r.error }));
      return;
    }
    paint($("harden"), r.settings.map((s) => [s.id, s.on]), () => {
      const kids = [];
      let group = null;
      for (const s of r.settings) {
        if (s.group !== group) {
          group = s.group;
          kids.push(el("h3", { text: group }));
        }
        const box = el("input", { type: "checkbox", role: "switch" });
        box.checked = s.on === true;
        box.disabled = s.on === null;
        box.addEventListener("click", async (e) => {
          const want = box.checked;
          e.preventDefault();
          const sure = await ask({ title: (want ? "Turn on: " : "Turn off: ") + s.title,
            text: s.detail + (s.caveat ? "\n\nNote: " + s.caveat : "") + "\n\nWindows will ask for administrator rights.", ok: want ? "Turn on" : "Turn off" });
          if (sure) act("harden", { setting: s.id, on: want });
        });
        kids.push(el("div", { class: "item" },
          el("label", { class: "switch" }, box, el("span", { class: "track" }), el("span", { class: "lbl", text: s.title + (s.on === null ? " (state unknown)" : "") })),
          el("div", { class: "small", text: s.detail }), s.caveat ? el("div", { class: "small warn", text: s.caveat }) : null));
      }
      return kids;
    });
  }

  async function refresh() {
    if (S.busy || S.lock === "stopped") return;
    S.busy = true;
    try {
      const d = await api("status");
      if (d.error) return;
      S.data = d;
      const running = d.tasks.filter((t) => t.state === "running").map((t) => t.title);
      msgs($("msgs"), [
        running.length && ["info", "Working: " + running.join("; ") + ". Progress is under Activity on the Overview tab."],
        d.isolation && d.isolation.isolated === true && ["error", "This PC is isolated from the network. Turn the switch off under Response to reconnect."],
        d.defender && d.defender.realtime === false && ["error", "Microsoft Defender real-time protection is OFF."],
        !d.last_scan && ["warn", "No scan has run yet. Start with a quick scan."],
        d.pending.length && ["warn", (d.pending.length === 1 ? "1 containment request is" : d.pending.length + " containment requests are")
          + " waiting for your approval on the Overview tab."],
      ]);
      renderTop(d); renderOverview(d); renderPending(d); renderTasks(d); renderFindings(d); renderResponse(d);
      renderAgent(d); renderAddons(d); renderSettings(d);
      if (S.tab === "findings") loadDetail(false);
      if (S.working && !running.length && S.tab === "hardening") refreshHardening(true);   // a switch may just have been applied
      S.working = running.length > 0;
    } finally {
      S.busy = false;
    }
  }

  function showTab(name) {
    if (!TABS.includes(name)) name = "overview";
    S.tab = name;
    for (const b of document.querySelectorAll("#tabs button")) b.setAttribute("aria-selected", String(b.dataset.tab === name));
    for (const s of document.querySelectorAll("section.tab")) s.classList.toggle("on", s.id === "tab-" + name);
    try { history.replaceState(null, "", "#" + name); } catch (e) { /* the address bar is a convenience only */ }
    if (name === "hardening") refreshHardening(true);
    if (name === "findings") loadDetail(false);
  }

  // ------------------------------------------------------------ wiring

  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => { showTab(b.dataset.tab); refresh(); });
  for (const [id, profile] of [["scanQuick", "quick"], ["scanFull", "full"], ["scanDeep", "deep"]])
    $(id).addEventListener("click", () => act("scan", { profile }));
  $("scanAdmin").addEventListener("click", async () => {
    if (await ask({ title: "Scan with administrator rights?", ok: "Scan",
      text: "Windows will show one prompt. HostGuard then reads the Security log, Defender's exclusion list and system processes, changes nothing, and scans again." }))
      act("elevated-scan");
  });
  $("baseline").addEventListener("click", async () => {
    if (await ask({ title: "Accept the current state as the baseline?", ok: "Accept as baseline",
      text: "Every autorun, account, administrator, listening port, root certificate and browser extension present now is treated as known. Later scans flag anything new.\n\nDo this only after you have looked through the findings." }))
      act("baseline");
  });
  actionSwitch("swMonitor", (want) => act("monitor", { on: want }));
  actionSwitch("swAutostart", (want) => act("autostart", { on: want }));
  actionSwitch("swIsoCrit", (want) => act("setting", { key: "containment.isolate_on_critical", value: want }));
  actionSwitch("swNotify", (want) => act("setting", { key: "monitor.notify", value: want }));
  actionSwitch("swOnline", async (want) => {
    if (want && !(await ask({ title: "Allow online hash lookups?", ok: "Allow",
      text: "When the agent wants to know whether a file is a known, catalogued program, it will send that file's SHA-256 to hashlookup.circl.lu. Nothing else leaves this PC. With this off, the agent works from local evidence only." })))
      return;
    act("setting", { key: "agent.online_lookups", value: want });
  });
  actionSwitch("swAgentEsc", async (want) => {
    if (want && !(await ask({ title: "Let a language model's verdict trigger containment?", ok: "Allow",
      text: "Only a 'malicious' verdict with high confidence on a high or critical finding counts. The same guardrails apply and every action can be undone. A model can still be wrong, or be misled by what it reads." })))
      return;
    act("setting", { key: "containment.agent_can_escalate", value: want });
  });
  actionSwitch("swIsolate", async (want) => {
    const sure = await ask(want
      ? { title: "Cut this PC off from the network now?", ok: "Isolate this PC", danger: true,
          text: "Every connection in and out is blocked until you turn this off. This dashboard keeps working." }
      : { title: "Reconnect this PC to the network?", ok: "Reconnect",
          text: "Only do this once you are satisfied the threat is contained. Windows will ask for administrator rights." });
    if (sure) act("isolate", { on: want });
  });
  $("mode").addEventListener("change", async () => {
    const v = $("mode").value;
    $("mode").blur();
    if (v === "auto" && !(await ask({ title: "Contain automatically?", ok: "Contain automatically",
      text: "HostGuard will suspend unsigned programs and script hosts, quarantine unsigned files and switch off autoruns for findings at or above the threshold, without asking first.\n\nSigned software, Windows components and folders you marked as your own are never touched, and everything can be undone." }))) {
      refresh();
      return;
    }
    act("setting", { key: "containment.mode", value: v });
  });
  $("autoSev").addEventListener("change", () => { const v = $("autoSev").value; $("autoSev").blur(); act("setting", { key: "containment.auto_min_severity", value: v }); });
  $("autoConf").addEventListener("change", () => { const v = $("autoConf").value; $("autoConf").blur(); act("setting", { key: "containment.auto_min_confidence", value: v }); });
  $("model").addEventListener("change", () => { const v = $("model").value; $("model").blur(); act("setting", { key: "agent.model", value: v }); });
  $("triageAll").addEventListener("click", () => act("triage"));
  $("ask").addEventListener("click", () => {
    const q = $("question").value.trim();
    if (q) act("ask", { question: q });
  });
  $("question").addEventListener("keydown", (e) => { if (e.key === "Enter") $("ask").click(); });
  $("defQuick").addEventListener("click", () => act("defender", { what: "quick" }));
  $("defUpdate").addEventListener("click", () => act("defender", { what: "update" }));
  $("selftest").addEventListener("click", async () => {
    const how = await ask({ title: "Run the self-test?", ok: "Run", alt: "Run, and test Defender too",
      text: "The self-test checks detection, quarantine and containment on throwaway items it creates itself.\n\nThe second option also drops the harmless EICAR test file, so you can watch Defender react. That raises a real Defender alert." });
    if (how) act("selftest", { defender: how === "alt" });
  });
  for (const id of ["fLow", "fPosture"]) $(id).addEventListener("change", () => S.data && renderFindings(S.data));
  $("fFilter").addEventListener("input", () => S.data && renderFindings(S.data));
  $("trusted").addEventListener("input", () => { S.trustedDirty = true; });
  $("trustedSave").addEventListener("click", async () => {
    const list = $("trusted").value.split(/\r?\n/).map((s) => s.trim()).filter(Boolean);
    const r = await api("setting", { key: "trusted.paths", value: list });
    if (!r.error) S.trustedDirty = false;
    flash(r, "Saved. It applies from the next scan.");
    refresh();
  });
  $("stopUi").addEventListener("click", async () => {
    if (!(await ask({ title: "Stop the dashboard?", ok: "Stop the dashboard",
      text: "This page stops working until you open the dashboard again from its shortcut. The real-time monitor and Microsoft Defender are not affected." })))
      return;
    const r = await api("shutdown", {});
    if (r.error) flash(r);
    else setLock("stopped");
  });

  setInterval(() => {
    if (document.hidden && !S.working) return;      // a background tab only keeps asking while something is running
    refresh();
    if (S.tab === "hardening") refreshHardening(false);
  }, 3000);
  document.addEventListener("visibilitychange", () => { if (!document.hidden) refresh(); });
  showTab(location.hash.slice(1));
  refresh();
})();
"""

_HEAD = ('<!doctype html>\n<html lang="en">\n<head>\n<meta charset="utf-8">\n'
         '<meta name="viewport" content="width=device-width, initial-scale=1">\n{extra}<title>HostGuard</title>\n'
         '<link rel="icon" href="' + _ICON + '">\n<style nonce="{{NONCE}}">' + _CSS + '</style>\n</head>\n')

# The dashboard itself, for a signed-in browser.
PAGE = (_HEAD.replace("{extra}", "") + "<body>" + _BODY + '<script nonce="{{NONCE}}">' + _JS + "</script>\n</body>\n</html>\n")

# What anyone without a session sees. It holds no data and no key.
SIGN_IN = (_HEAD.replace("{extra}", "") + """<body>
<main class="box">
  <h1>HostGuard</h1>
  <p class="note">{{NOTE}}</p>
  <p>This dashboard opens through its own launcher, which signs you in with a link that works once.</p>
  <p>Double-click <b>HostGuard dashboard</b>, or run <code>python run.py ui</code> in the HostGuard folder.</p>
</main>
</body>
</html>
""")

# The answer to a good sign-in link: it sets the cookie and moves on, so the key does not stay in the address bar.
SIGNED_IN = (_HEAD.replace("{extra}", '<meta http-equiv="refresh" content="0;url=/">\n') + """<body>
<main class="box">
  <h1>HostGuard</h1>
  <p>Signed in. <a href="/">Open the dashboard</a></p>
</main>
</body>
</html>
""")
