#!/usr/bin/env python3
"""portwalker — a hand-built TCP port scanner.

Step 1: the core primitive. Can we tell if a single port is open?
Everything else in this project grows around this one function.
"""

import socket
import time


def scan_port(host, port, timeout=1.0):
    """Return True if `port` on `host` is open, False otherwise.

    This is a TCP *connect* scan: we ask the OS to complete a full
    3-way handshake (SYN -> SYN/ACK -> ACK). If the handshake succeeds,
    something is listening -> the port is open. If the connection is
    refused (the OS sends back RST) or times out (silence / filtered),
    we treat the port as not-open.
    """
    # AF_INET = IPv4, SOCK_STREAM = TCP. This is the same primitive
    # every TCP program is built on top of.
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # How long to wait on silence before giving up. This is the knob
    # that becomes the --timeout flag later. Too low = miss slow hosts,
    # too high = filtered ports drag forever.
    sock.settimeout(timeout)

    try:
        # connect_ex() runs the handshake and returns an error code
        # instead of raising: 0 means success (port open). Anything
        # else (connection refused, timeout) means not open.
        result = sock.connect_ex((host, port))
        return result == 0
    finally:
        # Always release the socket, open or not.
        sock.close()


def scan_range(host, start, end, timeout=1.0):
    """Scan ports `start`..`end` (inclusive), one at a time, in order.

    This is the simplest possible way to scan a range: a plain loop.
    It works -- but it's SEQUENTIAL. Every port waits for the previous
    one to finish. The closed ports answer instantly (RST), but every
    filtered port costs a full `timeout` of silence before we move on.
    That cost is why step 3 will be threading.
    """
    open_ports = []
    for port in range(start, end + 1):
        if scan_port(host, port, timeout):
            open_ports.append(port)
            print(f"  {host}:{port} -> open")
    return open_ports


if __name__ == "__main__":
    target = "scanme.nmap.org"
    start, end = 1, 100

    print(f"Scanning {target} ports {start}-{end} (sequential)...")
    began = time.perf_counter()
    found = scan_range(target, start, end)
    elapsed = time.perf_counter() - began

    print(f"\nDone. {len(found)} open port(s): {found}")
    print(f"Took {elapsed:.1f}s for {end - start + 1} ports.")
