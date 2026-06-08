# 02 · CTF Notes — Live-fire Reinforcement

> Matched rooms only. Don't grind random rooms — pick the ones that reinforce what `portwalker` is teaching you.

---

## Matched rooms

### TryHackMe · Nmap (`furthernmap`)
- URL: https://tryhackme.com/room/furthernmap
- Why this one: walks through every scan type your tool will (and won't) implement.
- Notes:
  - [ ] Started
  - [ ] Completed

### TryHackMe · Network Services
- URL: https://tryhackme.com/room/networkservices
- Why this one: gives you the service-side perspective on the ports you're scanning. Helps you reason about what banner grabbing reveals.
- Notes:
  - [ ] Started
  - [ ] Completed

---

## Things to write down as you go

For each room:

1. **A flag/observation that surprised you.** One sentence.
2. **One command or technique you want to remember.** Paste the exact command.
3. **How it relates to portwalker.** Where would this idea show up in your scanner?

---

## Optional stretch

- **Try Hack Me · Hydra** — different category (auth attacks), but worth noting how `hydra` reuses the same "many sockets fast" idea your scanner uses.
- Scan `scanme.nmap.org` with both `nmap -sS` and `nmap -sT`. Eyeball the differences. Compare with what `portwalker` reports.
