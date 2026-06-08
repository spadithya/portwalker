#!/usr/bin/env python3
"""portwalker — a hand-built TCP port scanner.

A connect-scan port scanner with banner grabbing. Walks a TCP port
range, reports which ports are open, and reads the banner each open
service announces -- a hand-built subset of `nmap -sT -sV`.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def probe_port(host, port, timeout=1.0):
    """Connect to one port. If open, grab its banner on the SAME socket.

    This merges what used to be two functions (scan_port + grab_banner)
    into ONE connection. Before, every open port got connected to twice
    -- two full 3-way handshakes. Now we connect once: complete the
    handshake to learn if it's open, and if so, listen on that same
    open socket for whatever the service announces.

    Returns a result dict {port, open, banner} for OPEN ports, or
    None for closed/filtered ports (nothing worth reporting).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            # The connect scan: 0 means the handshake completed -> open.
            if sock.connect_ex((host, port)) != 0:
                return None  # closed (RST) or filtered (timeout)

            # Port is open. Try to read a banner on the connection we
            # already have. Services like SSH/FTP greet us immediately;
            # silent ones (HTTP, until we send a request) just time out
            # here and leave banner = None -- still a valid open port.
            banner = None
            try:
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip() or None
            except (socket.timeout, OSError):
                pass

            return {"port": port, "open": True, "banner": banner}
    except OSError:
        # e.g. host unreachable, too many open files -- treat as not open.
        return None


def scan(host, start, end, threads=100, timeout=1.0):
    """Scan ports `start`..`end` concurrently. Return open results sorted.

    Hands every port to a thread pool running probe_port. Threads let
    the per-port waits overlap -- which matters in proportion to how
    much waiting there is (lots, against a filtered/rate-limited host;
    almost none against a LAN host that RSTs instantly).

    Why threads despite the GIL: this is I/O-bound. A thread blocked on
    a socket releases the GIL, so other threads genuinely run.
    """
    results = []
    ports = range(start, end + 1)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        # Map each pending future back to the port it's probing, so we
        # know which port a finished result belongs to.
        future_to_port = {
            pool.submit(probe_port, host, port, timeout): port
            for port in ports
        }
        # as_completed yields each future the moment it finishes -- in
        # completion order, not submission order.
        for future in as_completed(future_to_port):
            result = future.result()
            if result is not None:  # None = closed/filtered, skip
                results.append(result)
                banner = result["banner"]
                shown = banner if banner else "(no banner)"
                print(f"  {host}:{result['port']} open -> {shown}")

    return sorted(results, key=lambda r: r["port"])


if __name__ == "__main__":
    target = "192.168.0.73"
    start, end = 1, 1000

    print(f"Scanning {target} ports {start}-{end} (threaded)...")
    began = time.perf_counter()
    found = scan(target, start, end, threads=100)
    elapsed = time.perf_counter() - began

    open_ports = [r["port"] for r in found]
    print(f"\nDone. {len(found)} open port(s): {open_ports}")
    print(f"Took {elapsed:.1f}s for {end - start + 1} ports.")
