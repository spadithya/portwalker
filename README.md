# portwalker

> Multi-threaded TCP port scanner + service fingerprinter, written in Python.

**Status:** Work in progress.
**Mission 1 of the [cybersecurity-journey](../cyberjournal/LEARNING_PLAN.txt) portfolio.**
**Region of the infrastructure map:** TCP/IP, Linux, sockets.

---

## What it does

`portwalker` walks a target's TCP port range and reports which ports are open, what service appears to be running on each, and the banner the service returns on connect. It's a hand-built alternative to `nmap -sT -sV`, written to understand what a port scanner actually does under the hood.

## Requirements

Python 3.8+ — standard library only, **no third-party dependencies**. Clone and run.

## Usage

```bash
python3 portwalker.py <target> -p 1-1000 --threads 100 --timeout 1 --json results.json
```

| Flag | Description |
|---|---|
| `<target>` | IP address or hostname to scan |
| `-p`, `--ports` | Ports to scan: `1-1000`, `22,80,443`, or a mix (default: `1-1000`) |
| `--threads` | Number of concurrent workers (default: 100) |
| `--timeout` | Socket timeout in seconds (default: 1.0) |
| `--json` | Optional: write structured results to a file |

### Real example

```console
$ python3 portwalker.py scanme.nmap.org -p 1-1000 --threads 100
Scanning scanme.nmap.org (1000 ports, 100 threads, 1.0s timeout)...
  scanme.nmap.org:22 open -> SSH-2.0-OpenSSH_6.6.1p1 Ubuntu-2ubuntu2.13
  scanme.nmap.org:80 open -> Server: Apache/2.4.7 (Ubuntu)

Done. 2 open port(s): [22, 80]
Took 1.2s for 1000 ports.
```

JSON output round-trips cleanly through `jq`:

```console
$ python3 portwalker.py 192.168.0.73 -p 21,22,80 --json out.json
$ jq '.open_ports[] | {port, banner}' out.json
{ "port": 21, "banner": "220 (vsFTPd 3.0.5)" }
{ "port": 22, "banner": "SSH-2.0-OpenSSH_10.2p1 Ubuntu-2ubuntu3.2" }
{ "port": 80, "banner": "Server: Apache/2.4.66 (Ubuntu)" }
```

## Repository layout

```
portwalker/
├── portwalker.py        ← the scanner (this is the tool)
├── README.md            ← you are here
├── LICENSE              ← MIT
└── docs/                ← build journal (this was a learning project)
    ├── 00_PRIME.md      ← orientation notes, written before building
    ├── 02_CTF_NOTES.md  ← matched TryHackMe / HTB rooms
    └── 99_RECAP.md      ← what I learned, written after shipping
```

`portwalker` was built as Mission 1 of a project-based security learning track, so the `docs/` folder keeps the learning journal alongside the tool. If you just want to *use* the scanner, you only need `portwalker.py`.

## Done when

- [x] Scanner finds the same open ports as `nmap` on my Kali VM
- [x] Banner grabbing works against at least 3 different services (SSH, HTTP, FTP)
- [x] JSON output mode works and round-trips through `jq`
- [x] README has real usage examples (not just planned ones)
- [x] Repo has a LICENSE, .gitignore, and clean commit history
- [ ] **~90-second asciinema demo** recorded, uploaded, and embedded in this README
- [ ] `99_RECAP.md` is filled in

## Demo

_Recorded with `asciinema rec` once the scanner works end to end. The cast will be embedded here and linked from the portfolio landing page._

```bash
# What the recording will show:
python3 portwalker.py scanme.nmap.org -p 1-1000 --threads 100
python3 portwalker.py 192.168.0.73 -p 22,80,443 --json out.json && jq . out.json
```

## Ethical use

Scan only systems you own or are explicitly authorized to scan. See [Section 6 of the parent plan](../cyberjournal/LEARNING_PLAN.txt) for the legal/ethical guardrails. `scanme.nmap.org` is the one public host that exists specifically for scanner practice.

## License

MIT — see [LICENSE](LICENSE).
