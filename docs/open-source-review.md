# Open-source options reviewed

Checked 16 November 2026. Two research passes opened each project's release page, licence file
or vendor documentation that day. Items marked (U) could not be confirmed from a primary source.
Version numbers go stale quickly: re-check a project's release page before installing it.

## Bottom line

1. **No open-source "agentic antivirus" is ready to adopt for one PC.** The LLM-in-the-loop
   projects that exist are either small MCP wrappers that need a server product behind them
   (Velociraptor, Wazuh, Defender for Endpoint) or SOC platforms built for teams (16 or more
   containers, no Windows sensor).
2. **Microsoft Defender Antivirus is a sound real-time engine and is already running.** It is not
   the best product in every lab test, but it is in the same band as paid consumer antivirus.
   Replacing it with ClamAV would be a large step down: ClamAV has no real-time protection on
   Windows.
3. **What a home PC lacks is the layer above the engine**: an answer to "am I compromised",
   visibility into persistence and behaviour, containment, and triage. Microsoft sells that layer
   as Defender for Endpoint. HostGuard is a free, local version of that layer.
4. **So the decision was: build the agent and response layer, keep Defender as the engine, and
   plug in open-source detection content as optional components.**

## How good is Defender on Windows 11?

| Lab test | Result |
|---|---|
| [AV-TEST, Jul-Aug 2026](https://www.av-test.org/en/antivirus/home-windows/windows-11/august-2026/microsoft-defender-antivirus-consumer-4.18-261414/) | 17.5 of 18, Top Product. Protection 6 of 6 (100% of 297 zero-day and 12,543 prevalent samples), usability 6 of 6, performance 5.5. 12 of 15 products scored a full 18. |
| [AV-Comparatives Real-World, Jul-Oct 2026](https://www.av-comparatives.org/tests/real-world-protection-test-july-october-2026/) | 97.3% (389 of 400), 1 false positive, STANDARD award, joint 16th of 20. The [Feb-May 2026](https://www.av-comparatives.org/tests/real-world-protection-test-february-may-2026/) round was 99.0%, ADVANCED+. |
| [AV-Comparatives Malware Protection, Sep 2026](https://www.av-comparatives.org/tests/malware-protection-test-september-2026/) | Online protection 99.89%, **offline detection 82.2%**, 28 false alarms, STANDARD. |
| [AV-Comparatives Performance, Sep 2026](https://www.av-comparatives.org/tests/performance-test-september-2026/) | Impact score 13.5, 11th of 20, ADVANCED. |
| [SE Labs Home, Jul-Sep 2026](https://selabs.uk/wp-content/uploads/2026/11/security-evaluation-test-report-home-endpoint-security-2026-10.pdf) | Protection 97%, legitimate accuracy 100%, total 99%, AAA. 2 of 100 attacks succeeded. |

Reading: solid, with two caveats. It dropped a band in the latest AV-Comparatives real-world
round, and it [leans on its cloud lookup](https://av-comparatives.org/is-microsoft-defender-enough/),
so offline detection is much weaker. Keep cloud-delivered protection on.

### What you do not get without Defender for Endpoint

Per Microsoft's own documentation ([EDR overview](https://learn.microsoft.com/en-us/defender-endpoint/overview-endpoint-detection-response),
[comparison](https://learn.microsoft.com/en-us/defender-endpoint/why-use-microsoft-defender-antivirus)):
behavioural telemetry kept for six months, alerts grouped into incidents, device isolation,
stop-and-quarantine, custom block and allow indicators, automatic attack disruption, automated
investigation and remediation, vulnerability management, advanced hunting.

| Paid EDR capability | HostGuard's free counterpart |
|---|---|
| Compromise assessment and hunting | `scan`: processes, network, persistence, logs, files, memory |
| Behavioural telemetry | Windows event logs, plus Sysmon if you enable it |
| Device isolation | `isolate`: firewall rules that block everything but loopback |
| Stop and quarantine | suspend or kill a process, quarantine a file, disable an autorun, all reversible |
| Automated investigation | the triage agent, running on a local model |
| Automatic disruption | automatic containment policy, off by default |
| Tamper resistance | **none**: see "Limits" in the README |

## Detection and response components

F = files, M = process memory, B = live behaviour, L = event logs, P = persistence, RT = real-time.

| Tool | Latest (date) | Licence | Detects, real-time, response | Notes |
|---|---|---|---|---|
| ClamAV | 1.5.4 (2026-08-07) | GPL-2.0 | F. On-demand only on Windows. | Wants about 3 GiB RAM. 1.5.4 fixed two memory-safety CVEs. |
| YARA | 4.6.0 (2026-10-27) | BSD-3 | F, M. On-demand. | Maintenance mode. |
| YARA-X | 1.23.0 (2026-11-05) | BSD-3 | F only. On-demand. | Process scanning is not implemented yet. |
| YARA Forge | weekly | GPL-3.0 tooling | Rule packs: core, extended, full. | Curated from public rule sets. |
| Sigma rules | r2026-07-01 | DRL 1.1 | Rules for L and B. | Attribution licence. |
| Hayabusa | 4.4.0 (2026-11-10) | AGPL-3.0 | L. Batch, can read live logs. | Signed binary. Best fit for Sigma on one PC. |
| Chainsaw | 2.18.0 (2026-11-15) | GPL-3.0 | L, MFT, shimcache, SRUM. Batch. | Moved to WithSecureOpenSource. |
| Sysmon | in Windows, or 15.22 | Free, closed | B to the event log. RT. Logs only. | See below. |
| Sysmon configs | sysmon-modular 2026-10-14 | MIT | Config XML. | SwiftOnSecurity's config was last changed in 2021. |
| Fibratus | 3.1.1 (2026-08-19) | Apache-2.0 | B, M (YARA). RT via ETW. Kill, isolate host. | MSI service, about 100 MB RAM. Signed. |
| Rustinel | 1.11.0 (2026-11-08) | Apache-2.0 | B (Sigma), F, M (YARA), IOCs. RT via ETW. Kill only. | First release February 2026. No anti-tamper. |
| Wazuh agent | 4.14.10 (2026-11-09) | GPL-2.0 | L, file integrity, config audit. | Only forwards. The server is Linux-only and wants 4 vCPU and 8 GiB. |
| Velociraptor | 0.77.3 (2026-10-05) | AGPL-3.0 | F, M, L, P through artifacts. | 31 security advisories dated 2026. Server is Linux-first. |
| osquery | 5.24.1 (2026-11-04) | Apache-2.0 or GPL-2.0 | P, B, L as SQL. | No response actions. |
| PE-sieve, HollowsHunter | 0.4.1.1, active | BSD-2 | M. On-demand. Can kill or suspend. | Best open tool for injected code. |
| Loki-RS | 2.13.1 (2026-09-27) | GPL-3.0 | F, M. On-demand. | Labelled beta. The Python Loki is deprecated. |
| capa | 10.0.0 (2026-10-16) | Apache-2.0 | F: static capability triage. | An analyst tool. |
| LOLDrivers | active | Apache-2.0 | About 700 known-bad drivers. | Windows' own driver blocklist is on by default but lags. |

Not open source despite the name or reputation: **OpenEDR** (source-available licence, last
binaries from 2022, needs Elasticsearch), **PersistenceSniper** (Commons Clause, last release
2024), **THOR Lite** and **Aurora Lite** (closed, free licence file). **Moneta** is abandoned
(2020).

### Sysmon is now part of Windows

Microsoft's page says Sysmon arrived as an optional Windows feature in Dev build 26300.7733
(February 2026) and then in 24H2 and 25H2 through KB5077241. It is off by default. Enabling it is
`Enable-WindowsOptionalFeature -Online -FeatureName Sysmon`, then `sysmon -i [config.xml]`; a
standalone Sysmon has to be uninstalled first.
Source: <https://learn.microsoft.com/en-us/windows/security/operating-system-security/sysmon/how-to-enable-sysmon>

Whether the feature is present on a given build needs an elevated check, so HostGuard reports it
from its administrator scan.

## LLM agents for endpoint defence

| Project | Stars, licence | What the agent can do | Verdict |
|---|---|---|---|
| [mgreen27/mcp-velociraptor](https://github.com/mgreen27/mcp-velociraptor) | 96, none | Windows triage; kill and quarantine behind a flag; Ollama by default | Self-described proof of concept. Needs a Velociraptor server. No licence, so no right to fork. |
| [socfortress/velociraptor-mcp-server](https://github.com/socfortress/velociraptor-mcp-server) | 43, AGPL-3.0 | Arbitrary VQL, read-only switch | v0.1.0. |
| [gensecaihq/Wazuh-MCP-Server](https://github.com/gensecaihq/Wazuh-MCP-Server) | 272, MIT | 41 read tools; 14 write tools behind opt-in, confirm, audit, rollback | Most mature, but needs a Wazuh manager. |
| [MenkW/Defender-MCP](https://github.com/MenkW/Defender-MCP) | 11, MIT | Isolate, scan, live response | Needs Defender for Endpoint. No use with consumer Defender. |
| sysmon-live, EventWhisper, OsqueryMcpServer, PersonalDeviceScanner-MCP | under 60 each | Read-only investigation | Demos. |
| [beenuar/AiSOC](https://github.com/beenuar/AiSOC) | 7,900, MIT | Triage of connector-fed alerts, human-approved response | 16 to 22 containers, 8 to 12 GB RAM, no Windows sensor. |
| [Vigil-SOC/vigil](https://github.com/Vigil-SOC/vigil) | 441, Apache-2.0 | Agents propose, analysts approve | Pre-1.0. Windows untested. Does not execute host isolation. |
| Tracecat, Argus, Wazuh-Autopilot, falcon-mcp | 64 to 3,900 | SOC automation over an existing SIEM or EDR | Team tooling. |
| [REMnux/remnux-mcp-server](https://github.com/REMnux/remnux-mcp-server) | 142, GPL-3.0 | Runs REMnux malware-analysis tools from an agent | Usable, for analysing a sample in a VM. |

No project was found that wraps the local Defender cmdlets or the Windows event log for an agent
on a single PC.

Design patterns worth copying, and copied into HostGuard: response tools off by default, an
explicit confirm step, an audit trail, rollback for every action, and never reporting an action
as done without reading the result back.

## Why build, and what is reused

- **Adopt as-is: rejected.** Nothing fits one PC without a server product behind it.
- **Replace Defender with an open-source engine: rejected.** ClamAV has no real-time protection on
  Windows. Fibratus and Rustinel are real behavioural engines, but each is a system service with
  its own rule language and no anti-tamper; they are good *sensors*, not replacements.
- **Build the layer above and plug components in: chosen.** HostGuard's core needs nothing but
  Python's standard library and Windows' own tools, so it works the moment it is copied to a PC
  and has almost no supply chain. Open-source content then extends it when you choose to install
  it:

| Optional component | Adds |
|---|---|
| Sysmon (in Windows) plus sysmon-modular | Complete process, network, injection and registry telemetry |
| Hayabusa plus Sigma rules | Thousands of community detection rules over the event logs |
| YARA 4.6 plus YARA Forge core rules | Content signatures for files and process memory |
| HollowsHunter | Deep injected-code scanning of every process |

## Free hardening switches and their defaults (Windows 11 Pro, unmanaged)

| Feature | Default |
|---|---|
| [Attack Surface Reduction rules](https://learn.microsoft.com/en-us/defender-endpoint/attack-surface-reduction-rules-overview) | Off until configured |
| [Controlled Folder Access](https://learn.microsoft.com/en-us/defender-endpoint/controlled-folder-access-configure) | Off |
| [PUA protection](https://learn.microsoft.com/en-us/defender-endpoint/detect-block-potentially-unwanted-apps-microsoft-defender-antivirus) | Not blocking (audit or off, Microsoft's pages disagree) |
| [Network Protection](https://learn.microsoft.com/en-us/defender-endpoint/enable-network-protection) | Off |
| [LSA protection](https://learn.microsoft.com/en-us/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection) | Automatic only on some new installs |
| [Smart App Control](https://support.microsoft.com/en-us/windows/smart-app-control-frequently-asked-questions-285ea03d-fa88-4d56-882e-6698afdb7003) | On in most cases; off with developer mode |
| [Vulnerable driver blocklist](https://learn.microsoft.com/en-us/windows/security/application-security/application-control/app-control-for-business/design/microsoft-recommended-driver-block-rules) | On since 22H2 |
| Tamper Protection | On (U): check `Get-MpComputerStatus` |
| [Credential Guard](https://learn.microsoft.com/en-us/windows/security/identity-protection/credential-guard/) | Not available on Pro |
| [PowerShell script block logging](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_logging?view=powershell-5.1) | Off, though suspicious blocks are logged anyway |
| [Command-line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing) | Off |

An Insider build such as 26300 may differ from these documented defaults. HostGuard reads the
real values from the PC instead of assuming them.
