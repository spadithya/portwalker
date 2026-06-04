#!/usr/bin/env python3
"""portwalker — a hand-built TCP port scanner.

Step 1: the core primitive. Can we tell if a single port is open?
Everything else in this project grows around this one function.
"""

import socket


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


if __name__ == "__main__":
    # A tiny hardcoded demo so we can run this and watch it work.
    # scanme.nmap.org is the one public host that exists for scanner
    # practice. From your nmap scan we KNOW the answers: 22 and 80 are
    # open, and something like 23 (telnet) is closed.
    target = "scanme.nmap.org"
    for port in (22, 80, 23):
        state = "open" if scan_port(target, port) else "closed/filtered"
        print(f"{target}:{port} -> {state}")
