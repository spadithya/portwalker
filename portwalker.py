#!/usr/bin/env python3
"""portwalker — a hand-built TCP port scanner.

A connect-scan port scanner with banner grabbing. Walks a TCP port
range, reports which ports are open, and reads the banner each open
service announces -- a hand-built subset of `nmap -sT -sV`.

Usage:
    python3 portwalker.py <target> -p 1-1000 --threads 100 --timeout 1
    python3 portwalker.py 192.168.0.73 -p 22,80,443 --json out.json
"""

import argparse
import json
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


def _http_server_line(data):
    """Pull a concise banner out of a raw HTTP response.

    An HTTP reply looks like:
        HTTP/1.1 200 OK\r\n
        Date: ...\r\n
        Server: Apache/2.4.65 (Ubuntu)\r\n    <- the version info we want
        ...
    We prefer the Server: header (that's the version, like nmap shows).
    If there isn't one, we fall back to the status line (first line).
    """
    text = data.decode("utf-8", errors="replace")
    lines = text.split("\r\n")
    for line in lines:
        if line.lower().startswith("server:"):
            return line.strip()
    # No Server header -- return the status line, or None if empty.
    return lines[0].strip() or None if lines else None


def probe_port(host, port, timeout=1.0):
    """Connect to one port. If open, grab its banner on the SAME socket.

    Connects once: completes the handshake to learn if the port is open,
    and if so, listens on that same open socket for the service's banner.

    Returns a result dict {port, open, banner} for OPEN ports, or
    None for closed/filtered ports (nothing worth reporting).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)

            # The connect scan: 0 means the handshake completed -> open.
            if sock.connect_ex((host, port)) != 0:
                return None  # closed (RST) or filtered (timeout)

            # Step 1 -- listen passively. SSH/FTP greet us immediately,
            # so we often get the banner for free just by waiting.
            banner = None
            try:
                data = sock.recv(1024)
                banner = data.decode("utf-8", errors="replace").strip() or None
            except (socket.timeout, OSError):
                pass

            # Step 2 -- if silent, it may be waiting for US to speak first
            # (HTTP does this). Send a minimal request and read the reply.
            if banner is None:
                try:
                    sock.sendall(b"GET / HTTP/1.0\r\n\r\n")
                    data = sock.recv(2048)
                    banner = _http_server_line(data)
                except (socket.timeout, OSError):
                    pass

            return {"port": port, "open": True, "banner": banner}
    except OSError:
        # e.g. host unreachable, too many open files -- treat as not open.
        return None


def scan(host, ports, threads=100, timeout=1.0):
    """Probe every port in `ports` concurrently. Return open results sorted.

    `ports` is any iterable of port numbers. Threads let the per-port
    waits overlap -- which matters in proportion to how much waiting
    there is. This is I/O-bound work, so the GIL doesn't get in the way:
    a thread blocked on a socket releases it for the others.
    """
    results = []

    with ThreadPoolExecutor(max_workers=threads) as pool:
        future_to_port = {
            pool.submit(probe_port, host, port, timeout): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            result = future.result()
            if result is not None:  # None = closed/filtered, skip
                results.append(result)
                shown = result["banner"] or "(no banner)"
                print(f"  {host}:{result['port']} open -> {shown}")

    return sorted(results, key=lambda r: r["port"])


def parse_ports(spec):
    """Turn a port spec string into a sorted list of port numbers.

    Accepts ranges, lists, or a mix:
        "1-1000"        -> [1, 2, ..., 1000]
        "22,80,443"     -> [22, 80, 443]
        "1-100,443,8080"-> [1..100, 443, 8080]

    Uses a set so overlaps (e.g. "1-100,50") don't scan a port twice.
    Raises ValueError on garbage, which main() turns into a clean error.
    """
    ports = set()
    for part in spec.split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            low, high = part.split("-", 1)
            low, high = int(low), int(high)
            if low > high:
                raise ValueError(f"range {part!r} is backwards")
            ports.update(range(low, high + 1))
        else:
            ports.add(int(part))
    if not ports:
        raise ValueError("no ports to scan")
    # Guard the valid TCP port range.
    if min(ports) < 1 or max(ports) > 65535:
        raise ValueError("ports must be between 1 and 65535")
    return sorted(ports)


def main():
    parser = argparse.ArgumentParser(
        description="portwalker — a hand-built TCP connect scanner with banner grabbing."
    )
    parser.add_argument("target", help="IP address or hostname to scan")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="port spec: '1-1000', '22,80,443', or a mix (default: 1-1000)")
    parser.add_argument("--threads", type=int, default=100,
                        help="number of concurrent workers (default: 100)")
    parser.add_argument("--timeout", type=float, default=1.0,
                        help="socket timeout in seconds (default: 1.0)")
    parser.add_argument("--json", metavar="FILE",
                        help="optional: write structured results to this file")
    args = parser.parse_args()

    # parse_ports can fail on bad input -- catch it and exit cleanly.
    try:
        ports = parse_ports(args.ports)
    except ValueError as exc:
        parser.error(f"bad --ports value: {exc}")

    print(f"Scanning {args.target} ({len(ports)} ports, "
          f"{args.threads} threads, {args.timeout}s timeout)...")
    began = time.perf_counter()
    found = scan(args.target, ports, threads=args.threads, timeout=args.timeout)
    elapsed = time.perf_counter() - began

    open_ports = [r["port"] for r in found]
    print(f"\nDone. {len(found)} open port(s): {open_ports}")
    print(f"Took {elapsed:.1f}s for {len(ports)} ports.")

    # Structured output: dump everything we know into a JSON file that
    # round-trips through `jq`. We already have result dicts, so this is
    # mostly assembling a top-level object around them.
    if args.json:
        report = {
            "target": args.target,
            "ports_scanned": len(ports),
            "elapsed_seconds": round(elapsed, 3),
            "open_ports": found,
        }
        with open(args.json, "w") as f:
            json.dump(report, f, indent=2)
        print(f"Wrote results to {args.json}")


if __name__ == "__main__":
    main()
