# Security

HostGuard is a security tool. It runs with your rights and can ask for an administrator's, so a
flaw in it matters.

## Reporting a vulnerability

Please do not open a public issue. Use **Security > Report a vulnerability** on this repository,
which reaches the maintainer privately. Expect an answer within a week. A valid report is fixed,
credited to you if you want that, and mentioned in the release notes.

## What counts

- Anything that lets a web page, another user of the PC, or text read from the PC (file names,
  command lines, event log content, model output) make HostGuard run code, take a containment
  action, loosen a protection or disclose data.
- A way around a containment guardrail: the processes, files, services and accounts that can
  never be targets.
- A way to make the dashboard answer a request that did not come from its own signed-in page.
- A flaw in the elevated helper, `hostguard/ps/elevated.ps1`. It must refuse everything it was not
  built to do, whatever arguments it is given.

## What does not

- A program already running as you can stop HostGuard, edit its settings or read the dashboard's
  sign-in key. HostGuard is ordinary user-mode code and its README says so. Defender's Tamper
  Protection is the tamper-resistant layer.
- A detection that can be evaded. Missed detections are welcome as ordinary issues, ideally with
  the command line or a failing test.
