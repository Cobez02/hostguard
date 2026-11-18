"""The dashboard page: one self-contained document with its own styles and script.

ui.py serves these templates. {{NONCE}} is replaced per response and named in the
Content-Security-Policy, so nothing here may use an inline style attribute or an inline event
handler: the browser would refuse it. All text that comes from the PC (file names, command lines,
model output) is put on the page as text, never as markup.

How it looks, and why:

  * Type is Bahnschrift, the DIN signage face that ships with Windows, so nothing is downloaded.
    Labels and readings are set condensed, sentences at normal width. Words written by the
    language model are set in a serif (Sitka), so advice is never mistaken for a measurement.
  * Colour is state, never decoration. The signal colours follow the safety-sign ladder: danger
    (critical), warning (high), caution (medium), then safe and notice. They are only ever fills
    with their own ink on top. Controls are drawn in ink alone.
  * Quiet when fine, loud when not. A clean verdict is a sentence beside a green bar; anything
    else floods its plate with the signal colour. A state that is as it should be gets no mark.
  * A section is a row of a datasheet: its name on the left, the substance in the middle, the
    explanation as a note on the right. Rules separate sections; nothing sits in a box.
"""

_ICON = ("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24'%3E%3Cpath fill='%232457d6' "
         "d='M12 2 4 5v6c0 5 3.4 9.4 8 11 4.6-1.6 8-6 8-11V5z'/%3E%3C/svg%3E")

_CSS = r"""
:root {
  color-scheme: light dark;
  --ground: #e8eae6; --well: #fbfcfa; --ink: #121513; --dim: #4c544f;
  --rule: rgba(18, 21, 19, .2); --edge: rgba(18, 21, 19, .55); --tint: rgba(18, 21, 19, .07);
  --danger: #c4161c; --on-danger: #fff; --warning: #e8710a; --on-warning: #121513; --caution: #f6b900; --on-caution: #121513;
  --safe: #1f7a4d; --on-safe: #fff; --notice: #0b5a94; --on-notice: #fff;
  --sans: Bahnschrift, "DIN Alternate", "Segoe UI", system-ui, sans-serif;
  --serif: "Sitka Text", Sitka, Cambria, Georgia, serif;
  --mono: "Cascadia Mono", Consolas, ui-monospace, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --ground: #2c3134; --well: #212528; --ink: #e8ebe6; --dim: #a8afaa;
    --rule: rgba(232, 235, 230, .2); --edge: rgba(232, 235, 230, .5); --tint: rgba(232, 235, 230, .08);
    --danger: #d9363c; --on-danger: #fff; --warning: #f5821f; --on-warning: #121513; --caution: #ffc81a; --on-caution: #121513;
    --safe: #3aa76d; --on-safe: #101412; --notice: #5aa9e6; --on-notice: #101412;
  }
}
* { box-sizing: border-box; }
[hidden] { display: none !important; }
html { font: 15px/1.5 var(--sans); font-variant-numeric: tabular-nums; }
body { margin: 0; background: var(--ground); color: var(--ink); }
button, input, select, textarea { font: inherit; color: inherit; }
h1, h2, h3, p, dl, dd, ul { margin: 0; }
:focus-visible { outline: 2px solid var(--notice); outline-offset: 2px; }
::selection { background: var(--notice); color: var(--on-notice); }
code { font: .87em var(--mono); background: var(--tint); border-radius: 2px; padding: 1px 5px; }

.frame { max-width: 1360px; margin: 0 auto; padding-left: 28px; padding-right: 28px; }
.top { position: sticky; top: 0; z-index: 5; background: var(--ground); border-bottom: 1px solid var(--ink); }
.masthead { display: flex; align-items: baseline; flex-wrap: wrap; gap: 2px 16px; padding-top: 13px; }
.brand { font-size: 21px; line-height: 1.3; font-weight: 700; font-stretch: 87%; }
.state { display: flex; align-items: baseline; gap: 9px; font-weight: 600; }
.state::before { content: ""; flex: none; width: 11px; height: 11px; background: var(--dim); }
.state.is-clean::before { background: var(--safe); }
.state.is-review::before { background: var(--caution); }
.state.is-suspicious::before { background: var(--warning); }
.state.is-compromised::before { background: var(--danger); }
.vitals { display: flex; flex-wrap: wrap; gap: 0 22px; margin-left: auto; font-stretch: 87%; }
.vitals div { display: flex; align-items: baseline; gap: 7px; }
.vitals dt { color: var(--dim); }
.vitals dd { font-weight: 600; }
#tabs { display: flex; gap: 2px; margin: 8px 0 0 -12px; overflow-x: auto; }
#tabs button { border: 0; border-bottom: 3px solid transparent; background: none; padding: 7px 12px 6px; color: var(--dim);
  font-weight: 600; white-space: nowrap; cursor: pointer; }
#tabs button:hover { color: var(--ink); }
#tabs button[aria-selected="true"] { color: var(--ink); border-bottom-color: var(--ink); }
.count { display: inline-block; min-width: 19px; margin-left: 7px; padding: 0 5px; border-radius: 2px; background: var(--caution);
  color: var(--on-caution); font-size: 12.5px; line-height: 19px; font-stretch: 87%; text-align: center; vertical-align: 1px; }

main { padding-top: 24px; }
body.locked main > section { opacity: .45; pointer-events: none; }
.tab { display: none; }
.tab.on { display: block; }
.footer { margin-top: 48px; padding: 14px 0 44px; border-top: 1px solid var(--rule); font-size: 13px; color: var(--dim); }

.msg { display: flex; align-items: baseline; gap: 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
.msg::before { content: ""; flex: none; width: 9px; height: 9px; background: var(--notice); }
.msg-warn::before { background: var(--caution); }
.msg-error { display: block; padding: 9px 14px; border-radius: 3px; background: var(--danger); color: var(--on-danger); font-weight: 600; }
.msg-error::before { content: none; }
.msg + .msg { margin-top: 6px; }
#lock, #msgs:not(:empty) { margin-bottom: 24px; }

/* The verdict. Quiet when clean: a bar and a sentence. Anything else floods the plate. */
.status { margin-bottom: 34px; padding: 2px 0 6px 22px; border-left: 12px solid var(--dim); }
.status.is-clean { border-left-color: var(--safe); }
.status.is-review, .status.is-suspicious, .status.is-compromised { padding: 20px 26px 24px; border-left: 0; border-radius: 5px; }
.status.is-review { background: var(--caution); color: var(--on-caution); }
.status.is-suspicious { background: var(--warning); color: var(--on-warning); }
.status.is-compromised { background: var(--danger); color: var(--on-danger); }
.verdict { font-size: clamp(27px, 3.1vw, 40px); line-height: 1.12; font-weight: 700; font-stretch: 87%; text-wrap: balance; }
.status .why { margin-top: 8px; max-width: 84ch; font-size: 16px; text-wrap: pretty; }
.status .row { margin-top: 16px; }
.status .b { border-color: currentColor; color: inherit; }
.status .b:hover:not(:disabled) { background: rgba(0, 0, 0, .1); }

/* A section is a datasheet row: name, substance, note. */
.block { display: grid; grid-template-columns: 200px minmax(0, 1fr) 300px; column-gap: 36px; padding: 24px 0 28px; border-top: 1px solid var(--rule); }
.sheet > .block:first-child, .sheet > :first-child > .block:first-child { border-top: 0; padding-top: 0; }
.block > h2 { grid-column: 1; font-size: 15px; font-weight: 700; text-wrap: balance; }
.block > .body { grid-column: 2; min-width: 0; }
.block > .note { grid-column: 3; font-size: 13px; color: var(--dim); }
.block.attn > h2::before { content: ""; display: inline-block; width: .6em; height: .6em; margin-right: .5em; background: var(--caution); }
.body > * + * { margin-top: 14px; }
.body > .switch + .switch { margin-top: 10px; }
.body > p { max-width: 70ch; }
@media (max-width: 1140px) {
  .block { grid-template-columns: 170px minmax(0, 1fr); }
  .block > .note { grid-column: 2; margin-top: 16px; max-width: 70ch; }
}
@media (max-width: 720px) {
  .frame { padding-left: 16px; padding-right: 16px; }
  .block { grid-template-columns: minmax(0, 1fr); row-gap: 10px; }
  .block > h2, .block > .body, .block > .note { grid-column: 1; }
  .vitals { margin-left: 0; }
  .top { position: static; }
}

.small { font-size: 13px; color: var(--dim); overflow-wrap: anywhere; }
.muted { color: var(--dim); }
.mono { font: 12.5px/1.5 var(--mono); overflow-wrap: anywhere; }
.nowrap { white-space: nowrap; }
.title { font-weight: 600; }
/* A state that needs a look carries a signal square. One that is as it should be carries nothing. */
.warn, .bad, .live { font-weight: 600; }
.warn::before, .bad::before, .live::before { content: ""; display: inline-block; width: .6em; height: .6em; margin-right: .5em; background: var(--caution); }
.bad::before { background: var(--danger); }
.live::before { background: var(--notice); }
.caveat { display: block; padding-left: 10px; border-left: 3px solid var(--caution); font-size: 13px; overflow-wrap: anywhere; }
.plate { display: inline-block; padding: 0 7px; border-radius: 2px; font-size: 13px; line-height: 20px; font-weight: 600; font-stretch: 87%;
  white-space: nowrap; vertical-align: 1px; }
.plate.sev { min-width: 66px; text-align: center; text-transform: capitalize; }
.p-danger { background: var(--danger); color: var(--on-danger); }
.p-warning { background: var(--warning); color: var(--on-warning); }
.p-caution { background: var(--caution); color: var(--on-caution); }
.p-safe { background: var(--safe); color: var(--on-safe); }
.p-none { box-shadow: inset 0 0 0 1px var(--edge); color: var(--dim); }

.row { display: flex; flex-wrap: wrap; align-items: center; gap: 8px; }
.row.end { justify-content: flex-end; }
.grow { flex: 1; min-width: 200px; }
.b { border: 1px solid var(--ink); border-radius: 3px; background: none; padding: 5px 13px; font-weight: 600; cursor: pointer; }
.b:hover:not(:disabled) { background: var(--tint); }
.b:active:not(:disabled) { background: var(--rule); }
.b:disabled { opacity: .45; cursor: default; }
.b.primary { background: var(--ink); color: var(--ground); }
.b.primary:hover:not(:disabled) { background: var(--ink); opacity: .85; }
.b.danger::before { content: ""; display: inline-block; width: .6em; height: .6em; margin-right: .5em; background: var(--danger); }
dialog .b.danger { border-color: var(--danger); background: var(--danger); color: var(--on-danger); }
dialog .b.danger::before { content: none; }
input[type="text"], input[type="search"], select, textarea { border: 1px solid var(--edge); border-radius: 3px; background: var(--well); padding: 6px 9px; }
input[type="checkbox"] { accent-color: var(--ink); }
textarea { display: block; width: 100%; min-height: 96px; resize: vertical; }
textarea.paths { font: 12.5px/1.5 var(--mono); }
label.check { display: inline-flex; align-items: center; gap: 7px; }

/* A switch says its state in words. No transition on purpose: a switch must never be drawn, even for one
   frame, in a state other than the one read back. A dashed one has not been read yet. */
.switch { display: flex; align-items: flex-start; gap: 12px; position: relative; cursor: pointer; }
.switch:has(input:disabled) { cursor: default; }
.switch input { position: absolute; opacity: 0; width: 1px; height: 1px; }
.switch .track { flex: none; position: relative; width: 54px; height: 24px; margin-top: -1px; border: 1.5px solid var(--ink); border-radius: 3px;
  font-size: 12.5px; line-height: 21px; font-weight: 600; font-stretch: 87%; }
.switch .track::before { content: "Off"; position: absolute; right: 7px; color: var(--dim); }
.switch .track::after { content: ""; position: absolute; top: 2px; bottom: 2px; left: 2px; width: 18px; border-radius: 1px; background: var(--ink); }
.switch input:checked + .track { background: var(--ink); }
.switch input:checked + .track::before { content: "On"; left: 8px; right: auto; color: var(--ground); }
.switch input:checked + .track::after { left: auto; right: 2px; background: var(--ground); }
.switch.danger input:checked + .track { border-color: var(--danger); background: var(--danger); }
.switch.danger input:checked + .track::before { color: var(--on-danger); }
.switch.danger input:checked + .track::after { background: var(--on-danger); }
.switch input:disabled + .track { border-style: dashed; border-color: var(--edge); background: none; }
.switch input:disabled + .track::before { content: "?"; left: 0; right: 0; text-align: center; color: var(--dim); }
.switch input:disabled + .track::after { content: none; }
.switch input:focus-visible + .track { outline: 2px solid var(--notice); outline-offset: 2px; }
.switch .lbl { font-weight: 600; }
.switch .txt { min-width: 0; max-width: 66ch; }
.switch .txt > * { display: block; }
.switch .txt > * + * { margin-top: 3px; }
.switch .txt > .caveat { margin-top: 6px; }

dl.kv { display: grid; grid-template-columns: 172px minmax(0, 1fr); gap: 5px 20px; }
dl.ev { grid-template-columns: 128px minmax(0, 1fr); }
dl.kv:empty { display: none; }
dl.kv dt { color: var(--dim); font-stretch: 87%; }
dl.kv dd { overflow-wrap: anywhere; }
dl.ev dd { font: 12.5px/1.5 var(--mono); white-space: pre-wrap; }

.item { padding: 14px 0; border-top: 1px solid var(--rule); }
.item:first-child { border-top: 0; padding-top: 0; }
.item:last-child { padding-bottom: 0; }
.item > * + * { margin-top: 3px; }
.item > .row { margin-top: 10px; }
.item > p, .item > .small { max-width: 78ch; }
.list.scroll { max-height: 460px; overflow: auto; padding-right: 10px; }
ul.plain { padding-left: 18px; max-width: 78ch; }
ul.plain li + li { margin-top: 4px; }

details.job { border-top: 1px solid var(--rule); }
details.job:first-child { border-top: 0; }
details.job summary { padding: 9px 0; cursor: pointer; }
details.job:first-child summary { padding-top: 0; }
details.job summary > * + * { margin-left: 10px; }
details.job pre { margin: 0 0 14px; padding: 10px 14px; max-height: 240px; overflow: auto; background: var(--well);
  font: 12.5px/1.55 var(--mono); white-space: pre-wrap; overflow-wrap: anywhere; }

/* Findings are a list to work through: the table on the left, the selected finding on the right. */
.bench { display: grid; grid-template-columns: minmax(0, 11fr) minmax(0, 9fr); column-gap: 28px; align-items: start; }
.worklist > * + * { margin-top: 16px; }
.tablewrap { overflow: auto; max-height: 68vh; }
table { border-collapse: separate; border-spacing: 0; width: 100%; }
th, td { text-align: left; vertical-align: top; padding: 10px 14px 10px 0; }
th:first-child, td:first-child { padding-left: 10px; }
th { position: sticky; top: 0; padding-top: 0; padding-bottom: 7px; border-bottom: 1px solid var(--ink); background: var(--ground);
  color: var(--dim); font-weight: 400; font-stretch: 87%; white-space: nowrap; }
td { border-bottom: 1px solid var(--rule); }
tr.pick { cursor: pointer; }
tr.pick:hover { background: var(--tint); }
tr.sel, tr.sel:hover { background: var(--well); }
/* Each cell paints one pixel over its neighbour, or a scaled display shows a seam between them. */
tr.sel td { box-shadow: 1px 0 0 var(--well); }
tr.sel td:first-child { box-shadow: inset 3px 0 0 var(--ink), 1px 0 0 var(--well); }
tr.sel td:last-child { box-shadow: none; }
td .small { margin-top: 2px; }
.detail { position: sticky; top: 118px; max-height: calc(100vh - 136px); overflow: auto; padding: 0 4px 4px 28px; border-left: 1px solid var(--rule); }
.detail > * + * { margin-top: 14px; }
.detail h2 { margin-top: 10px; font-size: 20px; line-height: 1.3; font-weight: 600; text-wrap: balance; }
.detail h3 { margin-top: 26px; font-size: 15px; font-weight: 700; }
.detail h3 + dl { margin-top: 8px; }
.detail > .row + .row { margin-top: 8px; }
.detail > p { max-width: 66ch; }

/* The agent's own words are set in a serif: this is advice from a model, not something HostGuard measured. */
.opinion { padding-left: 14px; border-left: 4px solid var(--edge); }
.opinion.o-danger { border-left-color: var(--danger); }
.opinion.o-warning { border-left-color: var(--warning); }
.opinion.o-safe { border-left-color: var(--safe); }
.opinion > * + * { margin-top: 8px; }
.opinion .plate { text-transform: capitalize; }
.said { max-width: 64ch; font: 15.5px/1.6 var(--serif); font-variant-numeric: lining-nums; white-space: pre-wrap; overflow-wrap: anywhere; }
ul.said { padding-left: 18px; white-space: normal; }
ul.said li + li { margin-top: 3px; }
.asked { font-weight: 600; }
.answer { max-height: 60vh; overflow: auto; padding-left: 16px; border-left: 4px solid var(--edge); }
#answer > * + * { margin-top: 10px; }
@media (max-width: 1050px) {
  .bench { grid-template-columns: minmax(0, 1fr); row-gap: 28px; }
  .detail { position: static; max-height: none; padding: 22px 0 0; border-left: 0; border-top: 1px solid var(--ink); scroll-margin-top: 124px; }
}
@media (max-width: 720px) {
  .detail { scroll-margin-top: 16px; }
  dl.kv, dl.ev { grid-template-columns: minmax(0, 1fr); row-gap: 0; }
  dl.kv dd + dt { margin-top: 8px; }
}

dialog { width: min(560px, 92vw); padding: 22px 24px; border: 2px solid var(--ink); border-radius: 4px; background: var(--ground); color: var(--ink); }
dialog::backdrop { background: rgba(12, 14, 13, .6); }
dialog h2 { font-size: 19px; line-height: 1.3; font-weight: 700; }
dialog p { margin-top: 10px; white-space: pre-wrap; overflow-wrap: anywhere; }
dialog textarea, dialog .row { margin-top: 16px; }
#toasts { position: fixed; right: 20px; bottom: 20px; z-index: 20; display: flex; flex-direction: column; gap: 8px; max-width: min(440px, 90vw); }
.toast { padding: 10px 14px; border-radius: 3px; background: var(--ink); color: var(--ground); font-weight: 600; overflow-wrap: anywhere; }
.toast.error { background: var(--danger); color: var(--on-danger); }

.door { max-width: 620px; margin: 14vh auto 0; padding: 0 28px; }
.door > * + * { margin-top: 12px; }
.door .brand { font-size: 27px; }
.door .caveat { font-size: 15px; }
.door .caveat:empty { display: none; }
"""

_BODY = r"""
<header class="top"><div class="frame">
  <div class="masthead">
    <div class="brand">HostGuard</div>
    <div class="state" id="topVerdict">Reading the current state...</div>
    <dl class="vitals" id="topChips"></dl>
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

<main class="frame">
  <div class="msg msg-error" id="lock" role="alert" hidden></div>
  <div id="msgs"></div>

  <section class="tab on" id="tab-overview">
    <div class="status" id="status">
      <h1 class="verdict" id="verdict">Not scanned yet</h1>
      <p class="why" id="verdictWhy"></p>
      <div class="row" id="verdictGo" hidden><button class="b" id="toFindings">Review the findings</button></div>
    </div>
    <div class="sheet">
      <section class="block attn" id="pendingBlock" hidden>
        <h2>Waiting for your approval</h2>
        <div class="body"><div class="list" id="pending"></div></div>
      </section>
      <section class="block">
        <h2>Scan</h2>
        <div class="body">
          <div class="row">
            <button class="b primary" id="scanQuick">Quick scan</button>
            <button class="b" id="scanFull">Full scan</button>
            <button class="b" id="scanDeep">Deep scan</button>
            <button class="b" id="scanAdmin">Scan with admin rights</button>
          </div>
          <dl class="kv" id="scanKv"></dl>
          <div class="row"><button class="b" id="baseline">Accept as baseline</button></div>
        </div>
        <p class="note">Quick takes about a minute. Full adds your whole profile, ProgramData and 30 days of logs. Deep trusts
          nothing cached and asks Defender about every unsigned program. The admin scan adds the Security log, Defender's
          exclusion list and system processes after one Windows prompt.</p>
      </section>
      <section class="block">
        <h2>Protection</h2>
        <div class="body">
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
        </div>
        <p class="note">Microsoft Defender stays the antivirus engine. HostGuard is the layer above it: the compromise check,
          change tracking, containment and the investigating agent.</p>
      </section>
      <section class="block">
        <h2>Activity</h2>
        <div class="body"><div id="tasks"></div></div>
      </section>
    </div>
  </section>

  <section class="tab" id="tab-findings">
    <div class="bench">
      <div class="worklist">
        <div class="row">
          <input type="search" id="fFilter" class="grow" placeholder="Filter by text" spellcheck="false" aria-label="Filter findings">
          <label class="check"><input type="checkbox" id="fLow"> Low and informational</label>
          <label class="check"><input type="checkbox" id="fPosture" checked> Hardening gaps</label>
        </div>
        <div class="tablewrap"><table>
          <thead><tr><th>Severity</th><th>Finding</th><th>Area</th><th>Agent</th><th>Seen</th></tr></thead>
          <tbody id="findings"></tbody></table></div>
        <p class="small" id="fCount"></p>
      </div>
      <div class="detail" id="detail"></div>
    </div>
  </section>

  <section class="tab" id="tab-response">
    <div class="sheet">
      <section class="block">
        <h2>Containment</h2>
        <div class="body">
          <div class="row"><label for="mode">When something is found</label>
            <select id="mode"><option value="off">Report only</option><option value="ask">Ask me first</option>
              <option value="auto">Contain automatically</option></select></div>
          <div class="row" id="autoBox" hidden><label for="autoSev">Act without asking on</label>
            <select id="autoSev"><option value="critical">critical findings only</option><option value="high">high and critical findings</option>
              <option value="medium">medium findings and above</option></select>
            <label for="autoConf">when confidence is</label>
            <select id="autoConf"><option value="high">high</option><option value="medium">medium or high</option></select></div>
          <label class="switch"><input type="checkbox" role="switch" id="swIsoCrit" disabled><span class="track"></span>
            <span>Also cut the network on a critical finding</span></label>
          <label class="switch"><input type="checkbox" role="switch" id="swAgentEsc" disabled><span class="track"></span>
            <span>Let the agent's verdict trigger containment</span></label>
          <dl class="kv" id="containKv"></dl>
        </div>
        <p class="note">Automatic mode only suspends unsigned programs and script hosts, quarantines unsigned files and switches
          off autoruns. Signed software, Windows components and folders you marked as your own are never touched. Everything
          it does can be undone in the action log, and it never raises a Windows prompt.</p>
      </section>
      <section class="block">
        <h2>Network isolation</h2>
        <div class="body">
          <label class="switch danger"><input type="checkbox" role="switch" id="swIsolate" disabled><span class="track"></span>
            <span class="lbl" id="isoLbl">State unknown</span></label>
          <dl class="kv" id="isoKv"></dl>
        </div>
        <p class="note">Blocks every connection in and out with two firewall rules. This dashboard and a model running on this
          PC keep working. Turning it off always asks for administrator rights. Containers and virtual machines keep their
          own route.</p>
      </section>
      <section class="block">
        <h2>Quarantine</h2>
        <div class="body"><div class="list scroll" id="quarantine"></div></div>
      </section>
      <section class="block">
        <h2>Action log</h2>
        <div class="body"><div class="list scroll" id="actions"></div></div>
      </section>
    </div>
  </section>

  <section class="tab" id="tab-agent">
    <div class="sheet">
      <section class="block">
        <h2>Triage agent</h2>
        <div class="body">
          <dl class="kv" id="agentKv"></dl>
          <div class="row"><label for="model">Model</label><select id="model"></select></div>
          <label class="switch"><input type="checkbox" role="switch" id="swOnline" disabled><span class="track"></span>
            <span>Let the agent check file hashes against an online catalogue</span></label>
          <div class="row"><button class="b" id="triageAll">Triage open findings</button></div>
        </div>
        <p class="note">A language model investigates a finding with read-only tools and reports a verdict with its evidence.
          It has no tool that changes anything. A "benign" verdict closes nothing; a "malicious" one queues a request for
          you. With the online switch on, only a file's SHA-256 is sent, to CIRCL's hashlookup service.</p>
      </section>
      <section class="block">
        <h2>Ask about this PC</h2>
        <div class="body">
          <div class="row"><input type="text" id="question" class="grow" spellcheck="false" aria-label="Question"
              placeholder="For example: what is listening on port 3389, and why?">
            <button class="b primary" id="ask">Ask</button></div>
          <div id="answer"></div>
        </div>
      </section>
    </div>
  </section>

  <section class="tab" id="tab-hardening">
    <div class="sheet">
      <section class="block">
        <h2>Ransomware canaries</h2>
        <div class="body">
          <label class="switch"><input type="checkbox" role="switch" id="swCanary" disabled><span class="track"></span>
            <span class="txt"><span class="lbl" id="canaryLbl">Canary files</span><span class="small" id="canaryHint" hidden></span></span></label>
          <dl class="kv" id="canaryKv"></dl>
          <div class="list" id="canaryPlaces" hidden></div>
          <div class="row" id="canaryRow" hidden>
            <button class="b" id="canaryWhere">Show where they are</button>
            <button class="b" id="canaryFresh">Replace the canaries</button>
            <button class="b" id="canaryFinding" hidden>Open the finding</button>
          </div>
        </div>
        <p class="note">A canary is a hidden folder of decoy documents, with one more beside it, named to sort first. A
          program working through your files reaches a decoy before any of them. The real-time monitor compares each
          decoy's contents, owner and permissions every few seconds, and a change becomes a finding. It cannot say
          which program made the change. A folder that OneDrive syncs takes its canary along.</p>
      </section>
      <div id="harden"><p class="muted">Reading the settings from Windows...</p></div>
      <section class="block">
        <h2>Open-source add-ons</h2>
        <div class="body"><div class="list" id="addons"></div></div>
        <p class="note">HostGuard downloads nothing by itself. Download fetches the release pinned in HostGuard's source from
          the project's GitHub page, checks its SHA-256 and unpacks it into the tools folder. You can also put a tool
          there by hand.</p>
      </section>
    </div>
  </section>

  <section class="tab" id="tab-settings">
    <div class="sheet">
      <section class="block">
        <h2>Your own security tooling</h2>
        <div class="body">
          <textarea class="paths" id="trusted" spellcheck="false" aria-label="Trusted folders"></textarea>
          <div class="row"><button class="b" id="trustedSave">Save folders</button></div>
        </div>
        <p class="note">One folder per line. Findings inside stay visible but are marked down, and automatic containment
          never touches them.</p>
      </section>
      <section class="block">
        <h2>Notifications</h2>
        <div class="body">
          <label class="switch"><input type="checkbox" role="switch" id="swNotify" disabled><span class="track"></span>
            <span>Show a Windows notification when the monitor finds something</span></label>
        </div>
      </section>
      <section class="block">
        <h2>What the last scan could not see</h2>
        <div class="body"><ul class="plain" id="notes"></ul></div>
      </section>
      <section class="block">
        <h2>This dashboard</h2>
        <div class="body">
          <dl class="kv" id="aboutKv"></dl>
          <div class="row"><button class="b" id="stopUi">Stop the dashboard</button></div>
        </div>
        <p class="note">The dashboard answers on this PC only and signs you in with a link that works once. Stopping it does
          not stop the real-time monitor or Microsoft Defender.</p>
      </section>
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
    defender_scan: "Let Defender clean it", isolate: "Isolate network", release: "Restore network",
    "canary:place": "Place canary files", "canary:remove": "Remove canary files" };
  const LOCK_TEXT = {
    offline: "The dashboard is not answering. If it was stopped, open it again from the HostGuard shortcut. This page reconnects by itself.",
    signedout: "Signed out: the dashboard was restarted after this page was opened. Open it again from the HostGuard shortcut.",
    stopped: "The dashboard has been stopped. The real-time monitor is not affected. Open the dashboard again from the HostGuard shortcut.",
  };
  // Which signal colour a state carries. Anything not listed here is drawn without one.
  const LEVEL = { clean: "is-clean", review: "is-review", suspicious: "is-suspicious", compromised: "is-compromised" };
  const SEVERITY = { critical: "danger", high: "warning", medium: "caution" };
  const VERDICT = { malicious: "danger", suspicious: "warning", benign: "safe" };
  const pick = (table, key) => Object.prototype.hasOwnProperty.call(table, key) ? table[key] : null;

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
    paint(box, rows, () => rows.map(([kind, text]) => el("div", { class: "msg msg-" + kind, text })));
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
  // With `info` it only tells: there is nothing to cancel.
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
      $("dlgCancel").hidden = !!o.info;
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

  const when = (ts) => ts ? new Date(ts * 1000).toLocaleString([], { dateStyle: "medium", timeStyle: "short" }) : "";
  const clock = (ts) => ts ? new Date(ts * 1000).toLocaleTimeString() : "";
  const minute = () => Math.floor(Date.now() / 60000);
  const ago = (ts) => {
    if (!ts) return "";
    const s = Math.max(0, Date.now() / 1000 - ts);
    return s < 90 ? "just now" : s < 5400 ? Math.round(s / 60) + " min ago" : s < 129600 ? Math.round(s / 3600) + " h ago" : Math.round(s / 86400) + " d ago";
  };
  const size = (n) => n > 1048576 ? (n / 1048576).toFixed(1) + " MB" : n > 1024 ? Math.round(n / 1024) + " KB" : n + " B";
  const days = (n) => n === 1 ? "1 day" : n + " days";
  const places = (n) => n === 1 ? "1 place" : n + " places";
  // "1 high, 2 medium" from a table of counts, or "" when there is nothing to count.
  const tally = (c) => ["critical", "high", "medium", "low"].filter((s) => c[s]).map((s) => c[s] + " " + s).join(", ");
  const needsALook = (severity) => pick(SEVERITY, severity) !== null;
  const empty = (text) => el("p", { class: "muted", text });
  const plate = (text, kind) => el("span", { class: "plate " + (kind ? "p-" + kind : "p-none"), text });
  const sevPlate = (severity) => el("span", { class: "plate sev p-" + (pick(SEVERITY, severity) || "none"), text: severity });

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

  // One reading in the line at the top. It gets a plate only when it is not as it should be.
  function vital(label, value, alarm) {
    return el("div", {}, el("dt", { text: label }), el("dd", {}, alarm ? plate(value, alarm) : value));
  }

  function setCount(id, n) {
    $(id).textContent = n ? String(n) : "";
    $(id).hidden = !n;
  }

  function renderTop(d) {
    const v = d.verdict, top = $("topVerdict");
    top.className = "state " + ((d.last_scan && pick(LEVEL, v.level)) || "");
    top.textContent = S.tab === "overview" ? "" : d.last_scan ? v.text : "Not scanned yet";     // Overview says it in full just below
    const m = d.monitor || {}, f = d.defender || {}, iso = d.isolation || {}, c = d.containment || {};
    paint($("topChips"), [m.running, f.realtime, iso.isolated, c.mode], () => [
      vital("Monitor", m.running ? "on" : "off", m.running ? null : "caution"),
      vital("Defender", f.realtime === true ? "on" : f.realtime === false ? "off" : "unknown", f.realtime === false ? "danger" : null),
      vital("Network", iso.isolated === true ? "isolated" : iso.isolated === false ? "connected" : "unknown", iso.isolated === true ? "danger" : null),
      vital("Containment", { off: "report only", ask: "ask first", auto: "automatic" }[c.mode] || "unknown", null),
    ]);
    setCount("cntFindings", d.findings.filter((x) => !x.posture && x.status === "open" && needsALook(x.severity)).length);
    setCount("cntPending", d.pending.length);
  }

  function renderOverview(d) {
    const v = d.verdict, ls = d.last_scan, open = tally(v.counts), trip = canaryAlarm(d);
    $("status").className = "status " + ((ls && pick(LEVEL, v.level)) || "");
    $("verdict").textContent = ls ? v.text : "Not scanned yet";
    $("verdictWhy").textContent = (trip ? trip.title + ". " : "") + (ls
      ? `Last checked ${ago(ls.ended)} by a ${ls.profile} scan${ls.elevated ? " with administrator data" : ""}. `
        + (open ? `Open findings: ${open}.` : "No open findings.")
      : "Start with a quick scan. It takes about a minute.");
    $("verdictGo").hidden = !(ls && v.level !== "clean");
    kv($("scanKv"), [
      ["Last scan", ls ? `${when(ls.ended)}, ${ls.profile}, ${ls.seconds} s${ls.elevated ? ", with administrator data" : ""}` : "never"],
      ["Hardening gaps", ls ? tally(v.posture_counts) || "none" : null],
      ["Baseline", d.baseline_time ? "accepted " + when(d.baseline_time) : "not set yet"],
    ]);
    for (const id of ["scanQuick", "scanFull", "scanDeep", "scanAdmin"]) $(id).disabled = d.scanning;
    const m = d.monitor || {}, f = d.defender || {}, n = m.counters || {}, c = d.canaries || {};
    setSwitch("swMonitor", m.running, false);
    setSwitch("swAutostart", m.autostart, false);
    kv($("protKv"), [
      ["Monitor", m.running ? `running (pid ${m.pid}); ${n.processes || 0} new processes, ${n.connections || 0} connections and ${n.findings || 0} findings since it started` : "stopped", m.running ? null : "warn"],
      ["Monitor error", m.last_error, "bad"],
      ["Canary files", !c.on ? "not placed (see Hardening)"
        : c.changed ? `${c.changed} of ${c.files} changed, in ${places(c.folders_changed)}`
        : `${c.files} in ${places(c.folders)}, none changed` + (m.running ? "" : "; not watched while the monitor is off"),
        c.on && c.changed ? "bad" : c.on && !m.running ? "warn" : null],
      ["Defender real-time", f.error ? "unknown: " + f.error : f.realtime === true ? "on" : f.realtime === false ? "off" : "unknown", f.realtime === false ? "bad" : null],
      ["Tamper protection", f.tamper === true ? "on" : f.tamper === false ? "off" : null, f.tamper === false ? "bad" : null],
      ["Definitions", f.signature_age_days == null ? null : (f.signature_age_days === 0 ? "updated today" : days(f.signature_age_days) + " old") + (f.version ? ` (${f.version})` : "")],
      ["Last Defender quick scan", f.quick_scan_age_days == null ? null : f.quick_scan_age_days > 60000 ? "never" : f.quick_scan_age_days === 0 ? "today" : days(f.quick_scan_age_days) + " ago"],
    ]);
  }

  // Requests only take up room while there are some.
  function renderPending(d) {
    $("pendingBlock").hidden = !d.pending.length;
    paint($("pending"), [d.pending, minute()], () => d.pending.map((p) => {
      const t = p.target || {};
      const what = t.path || t.name || t.ip || (t.pid ? "pid " + t.pid : "") || t.type || "";
      return el("div", { class: "item" },
        el("div", { class: "title", text: ACTION_LABEL[p.action] || p.action }),
        el("div", { class: "mono", text: String(what) }),
        p.finding_title ? el("div", { class: "small", text: p.finding_title }) : null,
        el("div", { class: "small", text: `Asked by ${p.actor} ${ago(p.ts)}${p.reason ? ": " + p.reason : ""}.` }),
        el("div", { class: "row" },
          el("button", { class: "b primary", text: "Approve", onclick: () => act("approve", { action_id: p.id, approve: true }) }),
          el("button", { class: "b", text: "Deny", onclick: () => act("approve", { action_id: p.id, approve: false }) }),
          p.finding_id ? el("button", { class: "b", text: "Show the finding", onclick: () => { showTab("findings"); select(p.finding_id); } }) : null));
    }));
  }

  function renderTasks(d) {
    const box = $("tasks");
    const open = new Map([...box.querySelectorAll("details")].map((x) => [x.dataset.id, x.open]));
    paint(box, d.tasks.map((t) => [t.id, t.state, t.log.length]), () => d.tasks.length ? d.tasks.map((t, i) => {
      const pre = el("pre", { text: t.log.join("\n") || "Working..." });
      const det = el("details", { class: "job", "data-id": t.id },
        el("summary", {}, el("span", { class: "muted", text: clock(t.started) }), el("b", { text: t.title }),
          el("span", { class: t.state === "failed" ? "bad" : t.state === "running" ? "live" : "muted", text: t.state })), pre);
      det.open = open.has(t.id) ? open.get(t.id) : i === 0;
      if (t.state === "running") requestAnimationFrame(() => { pre.scrollTop = pre.scrollHeight; });
      return det;
    }) : empty("Nothing has run since the dashboard started."));
  }

  function shownFindings(d) {
    const low = $("fLow").checked, posture = $("fPosture").checked, q = $("fFilter").value.trim().toLowerCase();
    return d.findings.filter((f) => (posture || !f.posture)
      && (low || needsALook(f.severity) || f.status === "contained")
      && (!q || [f.title, f.rule, f.category, f.severity, ...f.tags].join(" ").toLowerCase().includes(q)));
  }

  function renderFindings(d) {
    const rows = shownFindings(d);
    $("fCount").textContent = `${rows.length} shown of ${d.findings.length} open.`;
    const why = rows.length ? null : [!!$("fFilter").value.trim(), d.findings.length];      // what the empty list has to explain
    paint($("findings"), [rows, S.sel, minute(), !!d.last_scan, why], () => rows.length ? rows.map((f) => {
      const v = f.verdict, held = f.status === "contained";
      return el("tr", { class: "pick" + (S.sel === f.id ? " sel" : ""), tabindex: "0", onclick: () => select(f.id),
          onkeydown: (e) => { if (e.key === "Enter" || e.key === " ") { e.preventDefault(); select(f.id); } } },
        el("td", {}, sevPlate(f.severity)),
        el("td", {}, el("div", { text: f.title }),
          held || f.tags.length ? el("div", { class: "small" }, held ? plate("contained", "safe") : null, (held ? " " : "") + f.tags.join(", ")) : null),
        el("td", { class: "nowrap muted", text: f.posture ? "hardening" : f.category }),
        el("td", { class: "nowrap" }, v ? el("span", { class: v.verdict === "malicious" ? "bad" : v.verdict === "suspicious" ? "warn" : "muted", text: v.verdict }) : null),
        el("td", { class: "nowrap muted", text: ago(f.last_seen) }));
    }) : el("tr", {}, el("td", { colspan: "5", class: "muted", text: !d.last_scan ? "Run a scan to fill this list."
      : !d.findings.length ? "No open findings."
      : $("fFilter").value.trim() ? "Nothing matches that text."
      : `Nothing at medium or above. Tick a box above to see the other ${d.findings.length}.` })));
  }

  async function select(id) {
    S.sel = id;
    if (S.data) renderFindings(S.data);
    await loadDetail(true);
  }

  async function loadDetail(reveal) {
    const box = $("detail");
    if (!S.sel) {
      paint(box, "none", () => empty("Select a finding to see its evidence and what you can do about it."));
      return;
    }
    const id = S.sel;
    const f = await api("finding?id=" + encodeURIComponent(id));
    if (S.sel !== id) return;                       // another row was picked while this one loaded
    if (f.error) {
      if (!S.lock) paint(box, f, () => el("div", { class: "msg msg-error", text: f.error }));
      return;
    }
    paint(box, f, () => detailNodes(f));
    if (reveal && window.matchMedia("(max-width: 1050px)").matches)
      box.scrollIntoView({ behavior: window.matchMedia("(prefers-reduced-motion: reduce)").matches ? "auto" : "smooth", block: "start" });
  }

  // What the agent concluded, in its own words.
  function opinion(vd) {
    const kind = pick(VERDICT, vd.verdict);
    return el("div", { class: "opinion" + (kind ? " o-" + kind : "") },
      el("p", {}, plate(vd.verdict, kind), ` The agent's verdict, confidence ${vd.confidence}`,
        vd.model ? el("span", { class: "muted", text: ` (${vd.model})` }) : null),
      vd.summary ? el("p", { class: "said", text: vd.summary }) : null,
      (vd.evidence || []).length ? el("ul", { class: "said" }, vd.evidence.map((line) => el("li", { text: line }))) : null,
      vd.note ? el("p", { class: "small", text: vd.note }) : null);
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
    const record = [`Rule ${f.rule}, confidence ${f.confidence}, status ${f.status}.`, `First seen ${when(f.first_seen)}.`,
      (f.mitre || []).length ? `ATT&CK ${f.mitre.join(", ")}.` : null].filter(Boolean).join(" ");
    return [
      el("div", {}, sevPlate(f.severity)),
      el("h2", { text: f.title }),
      f.description ? el("p", { text: f.description }) : null,
      f.remediation ? el("p", {}, el("b", { text: "What to do: " }), f.remediation) : null,
      f.note ? el("p", {}, el("b", { text: "Note: " }), f.note) : null,
      f.verdict ? opinion(f.verdict) : null,
      el("div", { class: "row" }, live ? buttons : null,
        el("button", { class: "b", text: "Investigate with agent", onclick: () => act("triage", { id: f.id }) })),
      el("div", { class: "row" },
        live ? el("button", { class: "b", text: "Mark as expected", onclick: () => dispose(f, "allow") }) : null,
        live ? el("button", { class: "b", text: "Mark as dealt with", onclick: () => dispose(f, "resolve") }) : null,
        live ? null : el("button", { class: "b", text: "Reopen", onclick: () => act("finding/status", { id: f.id, status: "reopen" }) })),
      pairs.length ? el("h3", { text: "Evidence" }) : null,
      pairs.length ? el("dl", { class: "kv ev" }, pairs) : null,
      el("p", { class: "small", text: record }),
      (f.history || []).length ? el("p", { class: "small", text: "History: " + f.history.map((h) => `${when(h.ts)} ${h.actor} ${h.action} (${h.state})`).join("; ") + "." }) : null,
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
    const label = status === "allow" ? "Mark as expected" : "Mark as dealt with";
    const note = await ask({ title: label, ok: label, input: f.note || "",
      text: f.title + "\n\nOptional note: " + (status === "allow" ? "why is this expected?" : "how was it dealt with?") });
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
    $("isoLbl").textContent = iso.isolated === true ? "Isolated: the network is cut" : iso.isolated === false ? "Connected" : "State unknown";
    kv($("isoKv"), [
      ["Firewall rules", iso.isolated === true ? "HostGuard-Isolation-Out and -In are present" : iso.isolated === false ? "not present" : "could not be read", iso.isolated === true ? "bad" : null],
      ["One-click task", iso.one_click_task ? "installed (cutting the network needs no prompt)" : "not installed (see Hardening)"],
    ]);
    paint($("quarantine"), d.quarantine, () => d.quarantine.length ? d.quarantine.map((i) => el("div", { class: "item" },
      el("div", { class: "mono", text: i.original }),
      el("div", { class: "small", text: `Quarantined ${when(i.when)}, ${size(i.size)}, SHA-256 ${String(i.sha256 || "").slice(0, 16)}...` }),
      el("div", { class: "row" },
        el("button", { class: "b", text: "Restore", onclick: async () => {
          if (await ask({ title: "Put this file back where it was?", text: i.original, ok: "Restore" })) act("quarantine", { id: i.id, what: "restore" });
        } }),
        el("button", { class: "b danger", text: "Delete for good", onclick: async () => {
          if (await ask({ title: "Delete the quarantined copy for good?", text: i.original + "\n\nThis cannot be undone.", ok: "Delete for good", danger: true }))
            act("quarantine", { id: i.id, what: "delete" });
        } })))) : empty("Nothing is in quarantine."));
    paint($("actions"), [d.actions, minute()], () => d.actions.length ? d.actions.map((x) => {
      const failed = x.state === "refused" || x.state === "denied" || x.ok === 0 || x.ok === false;
      return el("div", { class: "item" },
        el("div", {}, el("span", { class: "title", text: ACTION_LABEL[x.action] || x.action }), " ",
          el("span", { class: failed ? "bad" : "muted", text: x.undone ? "undone" : ["refused", "denied", "approved"].includes(x.state) ? x.state : x.ok ? "done" : x.state }),
          el("span", { class: "muted", text: ` by ${x.actor}, ${ago(x.ts)}` })),
        x.target ? el("div", { class: "mono", text: x.target }) : null,
        x.message ? el("div", { class: "small", text: x.message }) : null,
        x.undoable ? el("div", { class: "row" }, el("button", { class: "b", text: "Undo", onclick: () => act("undo", { action_id: x.id }) })) : null);
    }) : empty("Nothing has been done yet."));
  }

  function renderAgent(d) {
    const a = d.agent || {}, c = d.agent_cfg || {};
    kv($("agentKv"), [
      ["Endpoint", (c.endpoint || "") + (a.local === false ? " (not on this PC: finding details are sent there)" : " (on this PC)"), a.local === false ? "warn" : null],
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
      ans.question ? el("p", { class: "asked", text: ans.question }) : null,
      el("div", { class: "said answer", text: ans.answer || "The model gave no answer." }),
      el("p", { class: "small", text: [ans.model, when(ans.when), (ans.tools_used || []).length ? "checked " + ans.tools_used.join(", ") : null].filter(Boolean).join(", ") + "." })]
      : empty("The answer appears here, with the checks the agent ran to reach it."));
  }

  function renderAddons(d) {
    const rows = d.addons || [];
    paint($("addons"), rows, () => rows.map((a) => el("div", { class: "item" },
      el("div", {}, el("span", { class: "title", text: a.title }), " ",
        el("span", { class: "muted", text: a.installed ? "installed" + (a.managed_version ? ", version " + a.managed_version : "") : "not installed" })),
      el("p", { text: a.adds }),
      el("div", { class: "small", text: a.installed ? a.detail : [a.get, a.place].filter(Boolean).join(". ") }),
      a.download ? el("div", { class: "row" },
        el("button", { class: "b", text: (a.installed ? "Download again" : "Download") + ` (${size(a.download.bytes)})`, onclick: () => installAddon(a) }),
        a.installed || a.managed_version ? el("button", { class: "b danger", text: "Remove", onclick: () => removeAddon(a) }) : null) : null)));
  }

  // The canary finding, while it is open and serious enough to say at the top of the page.
  function canaryAlarm(d) {
    const trip = (d.canaries || {}).alarm;
    return trip && pick(SEVERITY, trip.severity) !== "caution" && needsALook(trip.severity)
      && d.findings.some((f) => f.id === trip.id && f.status === "open") ? trip : null;
  }

  // The canaries as they are on disk at this moment, whatever the monitor has or has not reported yet.
  function renderCanaries(d) {
    const c = d.canaries || {}, m = d.monitor || {}, unknown = c.record === "damaged" || c.record === "unread";
    setSwitch("swCanary", c.on === true, unknown);
    $("canaryLbl").textContent = "Canary files" + (unknown ? " (state unknown)" : "");
    $("canaryHint").textContent = unknown ? "HostGuard's own list of its canaries cannot be read. Replacing the canaries starts a new list and leaves the old folders where they are."
      : c.on ? "" : `Turning this on puts hidden decoy documents in each of ${(c.plan || []).length} places.`;
    $("canaryHint").hidden = !$("canaryHint").textContent;
    kv($("canaryKv"), c.on ? [
      ["Decoy documents", c.changed ? `${c.changed} of ${c.files} changed, in ${places(c.folders_changed)}` : `${c.files} in ${places(c.folders)}, none changed`,
        c.changed ? "bad" : null],
      ["Not checked", c.unread ? `${c.unread}, because their folder is not there now or they are in use` : null],
      ["Checked", m.running && m.canary_checked ? `${ago(m.canary_checked)}, by the monitor` : "only during a scan, because the real-time monitor is off",
        m.running ? null : "warn"],
      ["Placed", when(c.placed)],
    ] : []);
    const odd = (c.places || []).filter((p) => p.state !== "intact");
    $("canaryPlaces").hidden = !odd.length;
    paint($("canaryPlaces"), odd, () => odd.map((p) => el("div", { class: "item" },
      el("div", { class: "mono", text: p.path }), el("div", { class: "small", text: p.note }))));
    $("canaryRow").hidden = !(c.on || unknown);
    $("canaryWhere").hidden = !c.on;
    $("canaryFinding").hidden = !(c.alarm && d.findings.some((f) => f.id === c.alarm.id));
  }

  async function installAddon(a) {
    const dl = a.download;
    const sure = await ask({ title: "Download " + a.title + "?", ok: "Download",
      text: "HostGuard will download:\n" + dl.files.map((f) => `- ${f.name} (${f.size_text}) from ${f.source}`).join("\n")
        + `\n\nEach file must match the size and SHA-256 written in HostGuard's source on ${dl.pinned_on}, or it is thrown away. `
        + `It is unpacked into ${a.folder}. Nothing is run now: later scans use it.\n\nLicence: ${a.licence}.` });
    if (sure) act("addon", { id: a.id, what: "install" });
  }

  async function removeAddon(a) {
    const sure = await ask({ title: "Remove " + a.title + "?", ok: "Remove", danger: true,
      text: `This deletes ${a.folder} and everything in it, including any files you put there yourself.` });
    if (sure) act("addon", { id: a.id, what: "remove" });
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

  // One switch of the Hardening tab: the control, what it does, and what turning it on can cost.
  function hardeningRow(s) {
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
    return el("div", { class: "item" }, el("label", { class: "switch" }, box, el("span", { class: "track" }),
      el("span", { class: "txt" },
        el("span", { class: "lbl", text: s.title + (s.on === null ? " (state unknown)" : "") }),
        el("span", { class: "small", text: s.detail }),
        s.caveat ? el("span", { class: "caveat", text: s.caveat }) : null)));
  }

  async function refreshHardening(force) {
    if (!force && Date.now() - S.hardenAt < 15000) return;
    S.hardenAt = Date.now();
    const r = await api("hardening");
    if (r.error) {
      if (!S.lock) paint($("harden"), r, () => el("div", { class: "msg msg-error", text: r.error }));
      return;
    }
    paint($("harden"), r.settings.map((s) => [s.id, s.on]), () => {
      const groups = [];
      for (const s of r.settings) {
        if (!groups.length || groups[groups.length - 1].name !== s.group) groups.push({ name: s.group, rows: [] });
        groups[groups.length - 1].rows.push(hardeningRow(s));
      }
      return groups.map((g, i) => el("section", { class: "block" },
        el("h2", { text: g.name }), el("div", { class: "body" }, el("div", { class: "list" }, g.rows)),
        i ? null : el("p", { class: "note", text: "These protections are built into Windows. Each switch shows what Windows reports now, and changing one asks for administrator rights." })));
    });
  }

  // The lines under the tabs: only what is out of the ordinary, and never what the tab in view already shows.
  function renderNotices(d) {
    const running = d.tasks.filter((t) => t.state === "running").map((t) => t.title), here = S.tab === "overview";
    const trip = canaryAlarm(d);
    msgs($("msgs"), [
      trip && !here && [trip.severity === "critical" ? "error" : "warn", trip.title + ". The finding says what to do."],
      running.length && ["info", "Working: " + running.join("; ") + (here ? "." : ". Progress is under Activity on the Overview tab.")],
      d.isolation && d.isolation.isolated === true && ["error", "This PC is isolated from the network. Turn the switch off under Response to reconnect."],
      d.defender && d.defender.realtime === false && ["error", "Microsoft Defender real-time protection is off."],
      d.pending.length && !here && ["warn", (d.pending.length === 1 ? "1 containment request is" : d.pending.length + " containment requests are")
        + " waiting for your approval on the Overview tab."],
    ]);
    return running;
  }

  async function refresh() {
    if (S.busy || S.lock === "stopped") return;
    S.busy = true;
    try {
      const d = await api("status");
      if (d.error) return;
      S.data = d;
      const running = renderNotices(d);
      renderTop(d); renderOverview(d); renderPending(d); renderTasks(d); renderFindings(d); renderResponse(d);
      renderAgent(d); renderAddons(d); renderCanaries(d); renderSettings(d);
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
    if (S.data) { renderNotices(S.data); renderTop(S.data); }
    if (name === "hardening") refreshHardening(true);
    if (name === "findings") loadDetail(false);
  }

  // ------------------------------------------------------------ wiring

  for (const b of document.querySelectorAll("#tabs button")) b.addEventListener("click", () => { showTab(b.dataset.tab); refresh(); });
  $("toFindings").addEventListener("click", () => { showTab("findings"); refresh(); });
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
  actionSwitch("swCanary", async (want) => {
    const plan = ((S.data && S.data.canaries) || {}).plan || [];
    const sure = await ask(want
      ? { title: "Place canary files?", ok: "Place them",
          text: "HostGuard will create a hidden folder holding four decoy documents, and one more hidden decoy beside it, in each of these places:\n\n"
            + plan.map((p) => `${p.root}   (${p.label})`).join("\n")
            + "\n\nTheir names start with an exclamation mark, so they sort first. A place Windows will not let HostGuard write to is skipped. If OneDrive or another service syncs one of these folders, it syncs the canary too." }
      : { title: "Remove the canary files?", ok: "Remove them",
          text: "HostGuard deletes each decoy document that is still exactly as it placed it, and then its folders that are empty. A decoy that has been changed is left where it is." });
    if (sure) act("canary", { on: want });
  });
  $("canaryFresh").addEventListener("click", async () => {
    if (await ask({ title: "Replace the canaries?", ok: "Replace them",
      text: "HostGuard removes the decoy documents that are unchanged and puts a fresh set down under a new folder name. Decoys that were changed stay where they are.\n\nDo this once you know why a canary changed." }))
      act("canary", { on: true });
  });
  $("canaryWhere").addEventListener("click", () => {
    const where = ((S.data && S.data.canaries) || {}).places || [];
    ask({ title: "Where the canaries are", ok: "Close", info: true,
      text: where.map((p) => `${p.path}   (${p.label})${p.note ? "\n    " + p.note : ""}`).join("\n")
        + "\n\nEach folder has one decoy document of the same name beside it. All of them are hidden: Explorer shows them when View > Show > Hidden items is ticked." });
  });
  $("canaryFinding").addEventListener("click", () => {
    const trip = ((S.data && S.data.canaries) || {}).alarm;
    if (trip) { showTab("findings"); select(trip.id); }
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
    flash(r, "Folders saved. They apply from the next scan.");
    refresh();
  });
  $("stopUi").addEventListener("click", async () => {
    if (!(await ask({ title: "Stop the dashboard?", ok: "Stop the dashboard",
      text: "This page stops working until you open the dashboard again from the HostGuard shortcut. The real-time monitor and Microsoft Defender are not affected." })))
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
<main class="door">
  <p class="brand">HostGuard</p>
  <p class="caveat">{{NOTE}}</p>
  <p>This dashboard opens through its own launcher, which signs you in with a link that works once.</p>
  <p>Double-click the <b>HostGuard</b> shortcut, or run <code>hostguard ui</code> in a terminal.</p>
</main>
</body>
</html>
""")

# The answer to a good sign-in link: it sets the cookie and moves on, so the key does not stay in the address bar.
SIGNED_IN = (_HEAD.replace("{extra}", '<meta http-equiv="refresh" content="0;url=/">\n') + """<body>
<main class="door">
  <p class="brand">HostGuard</p>
  <p>Signed in. <a href="/">Open the dashboard</a></p>
</main>
</body>
</html>
""")
