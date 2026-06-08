# 00 · Prime — Orientation Before Building

> Goal of this stage: get familiar with the topic landscape *before* writing code. What is it, why does it exist, where does it sit in the stack, what tools already do this? No hands-on yet — just orientation.

---

## Read / watch list

- [x] **Professor Messer · OSI Model** (~7 min, YouTube) — where TCP/IP sits relative to the rest of the stack.
- [x] **Professor Messer · IPv4 Addressing** (~7 min, YouTube) — IPs, subnets, what "a host" means.
- [x] **TCP 3-way handshake** — read any clear write-up. Diagram the SYN / SYN-ACK / ACK exchange in your own notes.
- [x] **Nmap docs · front page** — skim the scan types section: SYN scan, connect scan, UDP scan, what each one actually sends.
- [x] **Run once:** `nmap -sV scanme.nmap.org` — eyeball the output. What info comes back? Where does it come from?

## Questions to keep in mind while reading

These don't need answers yet — they should be live in your head while you read so the right ideas stick.

1. Why does the 3-way handshake exist at all? What would TCP look like without it?
2. What does "an open port" actually mean from the server's perspective?
3. Why is a SYN scan considered "stealthier" than a full TCP connect scan?
4. When `nmap` says a port is running `OpenSSH 8.9p1`, where did it get that string?
5. What's the difference between scanning one port on one host vs 1000 ports on one host vs 1 port on 1000 hosts — which is louder?

## Tool landscape (just be aware these exist)

| Tool | What it is |
|---|---|
| `nmap` | The reference port scanner. You're building a tiny subset of it. |
| `masscan` | Internet-scale scanner, packets-per-second focused. |
| `rustscan` | Modern wrapper, parallelizes nmap. |
| `unicornscan` | Asynchronous, less common. |
| Python `socket` | The standard-library primitive you'll build on top of. |
| `scapy` | Lower-level — lets you craft raw packets. Comes back in Mission 4. |

## What you should NOT be doing yet

- Writing code
- Optimizing anything
- Memorizing nmap flags

Done with this file when every checkbox is ticked and you can answer the 5 questions above out loud, in a sentence each.
