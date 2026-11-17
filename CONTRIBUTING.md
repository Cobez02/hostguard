# Contributing

Issues and pull requests are welcome. False positives and missed detections are the most useful
kind, especially with an example that reproduces them.

## Ground rules

Tests pin most of these. A change that breaks one needs a very good reason.

- **Standard library only.** No dependencies. Nothing is downloaded unless the user asks for an
  add-on, and then only a file pinned by address, size and SHA-256 in `hostguard/addons.py`.
- **The model advises, code decides.** The agent's tools are read-only. A "benign" verdict never
  closes or cancels anything.
- **Read back, never assume.** A switch shows what Windows reports, not what was clicked. An
  action is reported as done only after its effect was observed.
- **Unprivileged by default.** Elevated work goes through `hostguard/ps/elevated.ps1`, one request
  per prompt. A new verb refuses by default and comes with a dry-run test.
- **Text from the PC is data.** It never becomes part of a command line and never becomes markup
  on the dashboard.
- **Unknown is not guilty.** A fact that could not be read is reported as unread, not as bad.
- **On the page, colour is state.** A signal colour is a fill for a severity or an alarm, never
  decoration, and controls are drawn in ink. A state that is as it should be gets no mark. The
  typefaces are ones Windows ships, so the page loads nothing. `hostguard/page.py` opens with the
  full set of rules.
- A new detection rule comes with a test for what must fire and a test for what must stay quiet.

## Working on it

```
python -m unittest discover -s tests     # the whole suite
python tools/demo.py                     # the dashboard with invented data, for working on the page
python tools/make_icon.py                # rebuilds the icon
```

The tests need Windows. Some start throwaway processes and write throwaway files and per-user
registry values, then remove them. None asks for administrator rights.

Security problems go through the private channel described in [SECURITY.md](SECURITY.md).
