# Contributing

Issues and pull requests are welcome. False positives and missed detections are the most useful
kind, especially with an example that reproduces them.

## Ground rules

Tests pin most of these. A change that breaks one needs a very good reason.

- **Standard library only.** No dependencies and no downloads at run time.
- **The model advises, code decides.** The agent's tools are read-only. A "benign" verdict never
  closes or cancels anything.
- **Read back, never assume.** A switch shows what Windows reports, not what was clicked. An
  action is reported as done only after its effect was observed.
- **Unprivileged by default.** Elevated work goes through `hostguard/ps/elevated.ps1`, one request
  per prompt. A new verb refuses by default and comes with a dry-run test.
- **Text from the PC is data.** It never becomes part of a command line and never becomes markup
  on the dashboard.
- **Unknown is not guilty.** A fact that could not be read is reported as unread, not as bad.
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
