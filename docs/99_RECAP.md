# 99 · Recap — Things I Learned From portwalker

> Date completed: June-08-2026

---

## What I built

A port scanner and banner grabber, very similar to `nmap -sT -sV`. It uses threading to scan fast: because most of the time is spent *waiting* on filtered/closed ports, those waits happen in parallel instead of one after another. It also captures the banner the service sends back after the TCP 3-way handshake. HTTP is a special case — it doesn't send a banner on its own, so we send it an initial request first and read the banner in the reply. Because the scanner completes the full connection, it isn't stealthy: it's really the operating system doing the work, with the Python code just asking the OS to perform the standard 3-way handshake.

I set up a separate Ubuntu VM and modified its firewall to test the scanner, because `scanme.nmap.org` isn't very consistent — its rate limiter sometimes throttles the scan by silently dropping the packets I send.

## Five questions to answer

### 1. Which TCP scan types exist, and how do they differ?
Several exist; the two main ones are:
- **Connect scan (`-sT`)** — the "vanilla" scan. It completes the full 3-way handshake through the OS, so it needs no root access. This is what portwalker does. The trade-off is that it's loud — it shows up in the target's logs.
- **SYN scan (`-sS`)** — a "half-open" scan. It sends SYN, gets SYN/ACK, then sends RST without finishing the handshake. It needs root (raw packets) but is stealthier.

Others exist too (FIN/NULL/Xmas, and UDP `-sU`). Note that `-sV` is **not** a scan type — it's *version detection* (banner grabbing) layered on top of a scan.


### 2. Why is a SYN scan considered stealthier than a full TCP connect scan?
A SYN scan never completes the handshake — it sends RST after receiving SYN/ACK — so the target's *application/service* often never logs the connection. That's why it's considered stealthier. It isn't invisible, though: a network IDS or firewall watching the wire can still see the SYN packets either way.

### 3. What does banner grabbing reveal that a port number alone doesn't?
Banner grabbing reveals the actual service running on the port and its version number — information a port number alone can only guess at (the port is just a convention).

### 4. How does my scanner compare to nmap? Where does nmap clearly win?
Mine does one thing: a TCP connect scan with basic banner grabbing, against a single IPv4 host. nmap clearly wins almost everywhere else:
- **Scan types** — nmap can do stealthy SYN scans, UDP, and FIN/NULL/Xmas; mine only does full connect scans.
- **Version detection** — nmap matches responses against a large service-probe database; mine just reads the first banner and sends one fixed HTTP request.
- **Speed at scale** — nmap uses adaptive timing and retransmission tuning; mine uses a fixed timeout and a fixed thread count.
- **Extras** — OS detection, host discovery, IPv6, the NSE scripting engine, and many output formats. Mine has none of these.

Where mine "wins": it's tiny, dependency-free (standard library only), and I understand every line of it — which was the whole point of building it.

### 5. Which region of the infrastructure map did this Mission light up?
**TCP/IP, Linux, and sockets** — the network and transport layers (L3/L4) of the stack. This mission lit up how ports, the 3-way handshake, and the OS socket API actually work underneath the tools I'd normally just run.

---

## What surprised me

Threading. I learned it's ideal for port scanning because scans spend most of their time *waiting*. Python's GIL means only one thread can run Python code at a time, so threads can't run CPU work in true parallel — but a thread that's blocked waiting on a socket *releases* the GIL, so the waits overlap and the scan gets dramatically faster (115s → under a second in my tests). The biggest surprise was realizing concurrency doesn't speed up the *work* — it just stops the *waiting* from happening one piece at a time. (For CPU-bound work you'd use multiprocessing instead, which isn't needed here.)

## What I'd do differently next time

Now that I understand connect scans and the basic structure, I'd add more features to bring it closer to nmap — SYN scanning, UDP, a proper version-detection database, and tunable timing.

## How this connects to earlier / later Missions

- **Earlier:** (none — this is M1)
- **Later:**
  - `packetsleuth` (M4) will see my scanner's traffic on the wire — I'll watch my own SYN packets fly past.
  - `tinyforest` (M5) starts with port scanning to find domain services.
  - `gauntlet` (M12) — `portwalker` is step 1 of the kill chain.

## Lessons learned (one-liners, for the resume)

- Hand-building a mini `nmap -sT -sV` taught me how TCP works and what a port scan actually does under the hood.
- Learned concurrency with threads and its building blocks — futures and `as_completed`.
- Full-connect scans are loud, not stealthy — they complete the handshake and land in the target's logs. To stay quieter, scan select ports instead of sweeping, which helps avoid IDS detection.
