# SYN Port Scanner

> A TCP SYN scanner built with Scapy to understand how nmap works under the hood —
> and to analyze the technical limits encountered while adding multithreading.

English | [한국어](./README.md)

---

## Overview

A port scanner that reproduces, at the packet level, the process `nmap` uses to
classify ports as open or closed — without relying on existing tools. It crafts
and sends SYN packets with Scapy, then interprets the TCP flags in the response
to determine each port's state.

Beyond just "a scanner that works," the focus is on analyzing the
**file descriptor limits** and **Scapy's thread-safety issues** discovered while
introducing multithreading.

---

## Features

- **SYN scan**: half-open scanning that never completes the 3-way handshake
- **Multithreading**: concurrent port scanning via `ThreadPoolExecutor`
- **Flexible port specs**: ranges (`1-1000`), lists (`22,80,443`), and mixes (`1-100,8080`)
- **Service identification**: labels well-known ports (80 → HTTP, etc.)
- **Result summary**: shows open ports only; closed ports are counted

---

## Installation & Usage

### Requirements

- Python 3.7+
- Scapy (`pip install scapy` or `sudo apt install python3-scapy`)
- **root privileges** (required for raw sockets)

### Examples

```bash
# Default scan (ports 1-1000)
sudo python3 scanner.py -t 192.168.0.10

# Port range
sudo python3 scanner.py -t 192.168.0.10 -p 1-10000

# Specific ports
sudo python3 scanner.py -t 192.168.0.10 -p 22,80,443,3306,8080

# Adjust worker count
sudo python3 scanner.py -t 192.168.0.10 -p 1-10000 -w 15

# Help
python3 scanner.py --help
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-t`, `--target` | Target IP to scan (required) | — |
| `-p`, `--ports` | Port range/list | `1-1000` |
| `-w`, `--workers` | Number of concurrent workers | `15` |

---

## How It Works

A SYN scan checks a port's state without completing the TCP connection.

```
scanner → SYN → target
scanner ← SYN/ACK ← target   (open: a service responds)
scanner ← RST/ACK ← target   (closed: rejected immediately)
scanner ← (no reply)          (assumed filtered)
```

The port state is derived from the response's TCP flags:

- `SYN/ACK` → **OPEN**
- `RST/ACK` → **CLOSED**
- no reply → **FILTERED**

Unlike a normal `connect()` scan, it never sends the final ACK, so the connection
is never fully established — leaving fewer traces in application-level logs.

---

## What I Learned · Limits Encountered

The bulk of the time on this project went not into "making it work," but into
understanding *why* it works the way it does.

### 1. raw sockets and the kernel

Scapy bypasses the kernel's TCP/IP stack and crafts packets directly. As a result,
the kernel never records the scanner's SYN in its connection table, and treats the
target's SYN/ACK as an "unknown connection" — automatically replying with RST.
Ironically, this automatic RST is what keeps the SYN scan's connection incomplete.

### 2. The speed–stability trade-off of multithreading

A sequential scan (one worker) is slow because the wait time for each port's
response accumulates. Multithreading parallelizes that waiting and speeds things
up dramatically — but raising the worker count without limit causes problems.

- Raising workers to 1000 exceeded `select()`'s file descriptor limit (1024),
  crashing with `filedescriptor out of range`
- In other words, concurrency boosts speed but is bound by system resource limits

### 3. Scapy's thread-safety limit (the key finding)

Raising the worker count (empirically, intermittently from around 20) triggered
`OSError: [Errno 9] Bad file descriptor`. Analysis showed this was **not** a matter
of file descriptor count, but of **Scapy not being thread-safe**: multiple threads
tearing down Scapy's internal sockets/sniffer concurrently caused a race condition.
The failure is probabilistic — it can occur below 20 and sometimes not above it.

I acknowledged this limit and set a worker count that runs reliably (default 15).
The fundamental fix is to use low-level sockets directly instead of Scapy, which
I've left as future work.

---

## Limitations & Future Work

- **Scapy thread-safety**: unstable at high concurrency → consider a pure `socket` rewrite
- **No retransmission**: a missed reply is misjudged as FILTERED → add retry logic
- **No result export**: console output only → add JSON/CSV export
- **No version detection**: only checks if a port is open → consider banner grabbing

---

## License

This project uses [Scapy](https://scapy.net/) (GPL v2) and is therefore licensed
under **GPL v2**.

## Disclaimer

This tool is intended for learning and for **testing systems you own or are
authorized to test**. Unauthorized scanning may carry legal consequences.

---

**Author**: Benorm
