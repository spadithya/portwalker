#!/usr/bin/env python3
"""portwalker — a hand-built TCP port scanner.

Step 1: the core primitive. Can we tell if a single port is open?
Everything else in this project grows around this one function.
"""

import socket
import time
from concurrent.futures import ThreadPoolExecutor, as_completed


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


def grab_banner(host, port, timeout=2.0):
    """Connect to an open port and return whatever the service announces.

    Many services greet you the instant you connect -- SSH sends its
    version string, FTP sends a 220 welcome line. We just connect and
    *listen*. Whatever bytes come back IS the banner. This is exactly
    how nmap fills its VERSION column: the service tells on itself.

    Returns the banner string, or None if the port is closed or the
    service says nothing (some services stay silent until YOU speak --
    HTTP is the classic example; we handle that next).
    """
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(timeout)
            if sock.connect_ex((host, port)) != 0:
                return None  # not open, nothing to grab

            # recv() blocks until the service sends something or we time
            # out. Up to 1024 bytes is plenty for a greeting line.
            data = sock.recv(1024)

            # Bytes off the wire -> text. errors="replace" keeps us from
            # crashing on non-text bytes; .strip() trims trailing newline.
            banner = data.decode("utf-8", errors="replace").strip()
            return banner or None
    except (socket.timeout, OSError):
        # Timeout = service stayed silent. OSError = connection issue.
        return None


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


def scan_threaded(host, start, end, threads=100, timeout=1.0):
    """Scan ports `start`..`end` concurrently using a pool of workers.

    Same primitive (scan_port) as before -- the ONLY change is that
    many ports are in-flight at once instead of one at a time. While
    one worker sits waiting out a 1s timeout on a filtered port,
    99 others are doing the same wait *simultaneously*. The waits
    overlap, so total time collapses toward "one timeout" instead of
    "one timeout per port".

    Why threads work here even with Python's GIL: this is I/O-bound
    work. A thread blocked on a socket releases the GIL while it waits,
    so other threads genuinely run. (The GIL only bites CPU-bound work.)
    """
    open_ports = []
    ports = range(start, end + 1)

    with ThreadPoolExecutor(max_workers=threads) as pool:
        # Hand every port to the pool. future_to_port lets us remember
        # which port each pending result belongs to.
        future_to_port = {
            pool.submit(scan_port, host, port, timeout): port
            for port in ports
        }
        # as_completed yields each future the moment it finishes, in
        # whatever order they complete -- not the order we submitted.
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            if future.result():
                open_ports.append(port)
                print(f"  {host}:{port} -> open")

    return sorted(open_ports)


if __name__ == "__main__":
    target = "scanme.nmap.org"
    start, end = 1, 100

    print(f"Scanning {target} ports {start}-{end} (threaded)...")
    began = time.perf_counter()
    found = scan_threaded(target, start, end, threads=100)
    elapsed = time.perf_counter() - began

    print(f"\nDone. {len(found)} open port(s): {found}")
    print(f"Took {elapsed:.1f}s for {end - start + 1} ports.\n")

    # Now grab a banner off each open port we found.
    print("Banners:")
    for port in found:
        banner = grab_banner(target, port)
        print(f"  {target}:{port} -> {banner!r}")
