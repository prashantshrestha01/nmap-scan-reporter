# nmap-scan-reporter

Parse Nmap XML scan output into a prioritized, readable findings report.

## What it does

`nmap_reporter.py` reads Nmap XML (`nmap -oX scan.xml`) and produces:

- **Prioritized findings** — every open port grouped by host, ranked by risk, with a remediation note per finding
- **Markdown or console output** — Markdown tables for reports, plain text for the terminal
- **Diff mode** — compare two scans and list new hosts, gone hosts, new ports and gone ports

## Quick start

```bash
nmap -oX scan.xml 10.0.0.0/24
python3 nmap_reporter.py scan.xml
python3 nmap_reporter.py new.xml --markdown
python3 nmap_reporter.py new.xml --diff old.xml
```

No third-party packages are needed. Python 3.8+ only.

## Usage

```
python3 nmap_reporter.py <scan.xml> [--markdown] [--diff <old.xml>]
```

## Layout

```
nmap_reporter.py   # XML parser + risk ranking + renderers + diff (stdlib only)
tests/
  test_nmap_reporter.py   # builds scan XML in code, runs offline
```

## Design notes (custom mods)

- **Risk ranking weighs service type and known-bad exposures above raw port count.** Telnet, SMB and RDP open to the network score Critical/High even on a host with a single open port, while a host with many low-risk ports ranks below them. A host is never "worse" just because it has more ports.
- **Diff mode compares two scans.** New and gone hosts and ports are listed separately, so a rescan after remediation shows exactly what changed instead of requiring a manual side-by-side.
- **Every finding carries a remediation note.** The report is written to be handed to whoever owns the host, not just to be read by the scanner operator.

Run the tests with:

```bash
python3 -m unittest discover -s tests -v
```

*Built by Prashant Shrestha · Mississauga, ON 🇨🇦 · [LinkedIn](https://www.linkedin.com/in/cto-prashant/)*
