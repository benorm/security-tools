# Socket Port Scanner

> A TCP Connect scanner built with pure `socket` — overcoming the thread-safety
> limits of the SYN scan (Scapy) version, and adding banner grabbing to detect
> service versions.

English | [한국어](./README.md)

---

## Overview

This project started from the limits hit in [syn-scanner](../syn-scanner). The
Scapy-based SYN scanner was unstable under multithreading due to thread-safety
issues — raising the worker count caused crashes. Rewriting it with pure `socket`,
using the kernel's normal `connect()`, greatly improved both stability and speed.

It also reads the banner a service sends on connection, collecting not just open
ports but **service version information** as well.

---

## SYN Scan vs Connect Scan

The two approaches fundamentally diverge on whether they use the kernel.

| | SYN scan (syn-scanner) | Connect scan (this project) |
|---|---|---|
| Implementation | Scapy, raw socket | pure socket |
| Kernel | bypassed (crafts packets directly) | used (normal connect) |
| Handshake | incomplete (SYN→SYN/ACK→RST) | complete (SYN→SYN/ACK→ACK) |
| Privileges | root (sudo) required | normal user |
| thread-safe | ❌ no | ✅ yes |
| Stealth | high (fewer logs) | low (connection completed) |

The core is a **stealth-vs-stability trade-off**. SYN scan is stealthy but not
thread-safe; Connect scan gives up stealth in exchange for stability and speed.

---

## Features

- **TCP Connect scan**: stable port detection via the kernel's connect()
- **thread-safe multithreading**: an independent socket per thread → stable even at hundreds/thousands of workers
- **Banner grabbing**: reads service banners on open ports to collect version info
- **Flexible port specs**: ranges (`1-1000`), lists (`22,80,443`), and mixes
- **Service identification**: labels well-known ports

---

## Installation & Usage

### Requirements

- Python 3.7+ (standard library only, no external dependencies)
- **No root privileges required**

### Examples

```bash
# Default scan (ports 1-1000)
python3 socket_scanner.py -t 192.168.0.10

# Port range
python3 socket_scanner.py -t 192.168.0.10 -p 1-10000

# Specific ports
python3 socket_scanner.py -t 192.168.0.10 -p 22,80,443,3306,8080

# Adjust workers (stable even when high)
python3 socket_scanner.py -t 192.168.0.10 -p 1-10000 -w 500

# Help
python3 socket_scanner.py --help
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t`, `--target` | Target IP to scan (required) | — |
| `-p`, `--ports` | Port range/list | `1-1000` |
| `-w`, `--workers` | Number of concurrent workers | `100` |

---

## How It Works

### Connect scan

If `connect()` succeeds, the port is open. Since the kernel completes the 3-way
handshake, checking the return value is enough.

```
connect_ex() == 0  → OPEN
connect_ex() != 0  → CLOSED
```

Unlike a SYN scan, there's no need to analyze response packet flags directly —
the kernel summarizes whether the connection was established as a return value.

### Banner grabbing

Some services send a banner on connection. Reading it reveals the service type
and version.

```
Connect to MySQL → receive "8.0.46 ... caching_sha2_password"
→ not only is the port open, but MySQL 8.0.46 is running
```

Services like HTTP that wait for the client to speak first send no banner, so
banner reads are handled to fail silently without affecting the open/closed
verdict.

---

## Performance Comparison (vs SYN scan)

Measured results scanning 10,000 ports. To compare the scan methods themselves,
**banner grabbing was excluded from these measurements**. (Numbers vary by environment.)

| Metric | SYN scan (Scapy) | Connect scan (socket) |
|--------|-----------------|----------------------|
| 40+ workers | crash (thread-unsafe) | stable |
| 1000 workers | crash | **stable** |
| 15 workers, elapsed | ~26 s | ~0.4 s |
| Speed difference | baseline | ~**65× faster** |

### Why the difference

Two factors multiply together.

1. **thread-safe**: socket creates an independent socket per thread, so there's
   no resource contention. Scapy shares an internal sniffer, crashing from race
   conditions when workers increase. So socket can scale workers far higher.

2. **per-scan speed**: socket delegates heavy work (packet assembly, response
   matching) to the kernel (fast C code). Scapy does this at the Python level,
   which is slow. So even at the same worker count (15), socket is far faster.

---

## Limitations & Future Work

- **No stealth**: it completes the connection, leaving traces in target logs (inherent to Connect scan)
- **Basic banner parsing**: extracting only the version from banners with binary
  mixed in would need per-protocol parsing → currently just filters printable chars
- **Cost of banner grabbing**: services that send no banner (HTTP, etc.) incur a
  wait equal to the timeout, lengthening the scan. It's a trade-off for obtaining
  version info; separating the connect and recv timeouts would improve it
- **No result export**: console output only → add JSON/CSV export

---

## License

Licensed under **GPL v2** per this repository's policy. (See the top-level [LICENSE](../LICENSE).)

## Disclaimer

This tool is intended for learning and for **testing systems you own or are
authorized to test**. Unauthorized scanning may carry legal consequences.

---

**Author**: Benorm
