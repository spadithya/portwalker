# portwalker

> Multi-threaded TCP port scanner + service fingerprinter, written in Python.

**Status:** Work in progress.
**Mission 1 of the [cybersecurity-journey](../cyberjournal/LEARNING_PLAN.txt) portfolio.**
**Region of the infrastructure map:** TCP/IP, Linux, sockets.

---

## What it does (planned)

`portwalker` walks a target's TCP port range and reports which ports are open, what service appears to be running on each, and the banner the service returns on connect. It's a hand-built alternative to `nmap -sT -sV`, written to understand what a port scanner actually does under the hood.

## Usage (planned)

```bash
portwalker <target> -p 1-1000 --threads 100 --timeout 1 --json results.json
```

| Flag | Description |
|---|---|
| `<target>` | IP address or hostname to scan |
| `-p` | Port range (e.g. `1-1000`, `22,80,443`) |
| `--threads` | Number of concurrent workers (default: 50) |
| `--timeout` | Socket timeout in seconds (default: 1) |
| `--json` | Optional: write structured results to file |

## Mission folder layout

```
portwalker/
├── README.md            ← you are here
├── 00_PRIME.md          ← orientation reading, done BEFORE building
├── 01_PROJECT/          ← the actual scanner code
├── 02_CTF_NOTES.md      ← matched TryHackMe / HTB rooms
└── 99_RECAP.md          ← what I learned, filled in AFTER shipping
```

## Done when

- [ ] Scanner finds the same open ports as `nmap` on my Kali VM
- [ ] Banner grabbing works against at least 3 different services (SSH, HTTP, FTP)
- [ ] JSON output mode works and round-trips through `jq`
- [ ] README has real usage examples (not just planned ones)
- [ ] Repo has a LICENSE, .gitignore, and clean commit history
- [ ] **~90-second asciinema demo** recorded, uploaded, and embedded in this README
- [ ] `99_RECAP.md` is filled in

## Demo

_Recorded with `asciinema rec` once the scanner works end to end. The cast will be embedded here and linked from the portfolio landing page._

```bash
# What the recording will show:
portwalker scanme.nmap.org -p 1-1000 --threads 100
portwalker 192.168.1.1 -p 22,80,443 --json out.json && jq . out.json
```

## Ethical use

Scan only systems you own or are explicitly authorized to scan. See [Section 6 of the parent plan](../cyberjournal/LEARNING_PLAN.txt) for the legal/ethical guardrails. `scanme.nmap.org` is the one public host that exists specifically for scanner practice.

## License

TBD — likely MIT once the first version ships.
