# netscan

> A network scanner that combines host discovery (ICMP, ARP) and port scanning
> (TCP, UDP) in one tool, building on the two earlier scanners and adding
> UDP accuracy and service identification.

English | [한국어](./README.md)

---

## Overview

[syn-scanner](../syn-scanner) and [socket-scanner](../socket-scanner) only scanned
the ports of "one IP you already know". A real assessment starts one step earlier:
**which hosts are alive in the network**.

netscan splits the scan into two stages.

```
Stage 1 discovery:  --icmp / --arp  → results merged by IP
                    -Pn → skip discovery and pass every target through
Stage 2 port scan:  --tcp / --udp   → (host × port) jobs on a thread pool
                    open TCP ports: banner, HTTP Server header, MySQL version
```

The problems met while building each stage (ARP flux, the Linux ICMP rate limit,
servers that never speak first) are recorded here, along with how nmap and masscan
handle the same problems.

---

## Features

- **ICMP host discovery**: Scapy `sr1()` + thread pool (layer 3)
- **ARP host discovery**: Scapy `srp()` batch send (layer 2, local segment only)
- **Skip discovery (`-Pn`)**: port-scan hosts that ignore ICMP and ARP
- **TCP Connect scan**: OPEN / CLOSED / FILTERED, no root required
- **UDP scan**: OPEN / CLOSED / OPEN|FILTERED / FILTERED, no root required
- **UDP accuracy (`--udp-delay`)**: per-host send interval to cope with the ICMP rate limit
- **Service identification**: server-first banners, the HTTP `Server` header when the server stays silent, and the version from the MySQL handshake
- **Input validation**: targets (CIDR / single IP), ports, worker counts and timeouts are rejected before the scan starts (fail fast)

---

## Installation & Usage

### Requirements

- Python 3.8+
- Scapy (`pip install scapy`, used only for ICMP and ARP discovery)
- ICMP and ARP discovery use raw sockets and **require root**. Port scanning (`-Pn --tcp/--udp`) uses kernel sockets only and does not

### Examples

```bash
# Discover a local subnet with ARP, then scan TCP 1-1000
sudo python3 netscan.py -n 192.168.0.0/24 -i eth1 --arp --tcp

# Use ICMP and ARP together and merge the results
sudo python3 netscan.py -n 192.168.0.0/24 -i eth1 --icmp --arp

# Specific TCP ports on a single host, no discovery (no root needed)
python3 netscan.py -n 192.168.0.5 -Pn --tcp -p 22,80,3306,8080

# UDP 1-100, 1-second interval per host (default)
python3 netscan.py -n 192.168.0.5 -Pn --udp -u 1-100

# Help
python3 netscan.py -h
```

### Options

| Option | Description | Default |
|--------|-------------|---------|
| `-n`, `--network` | Target. A subnet (`192.168.0.0/24`) or a single IP (required) | — |
| `-i`, `--iface` | Send interface (needed for ARP) | — |
| `-v`, `--verbose` | Show Scapy internal warnings | off |
| **Stage 1: host discovery** | | |
| `--icmp` / `--arp` | Discovery method (merged when both are used) | — |
| `-Pn`, `--skip-discovery` | Skip discovery and port-scan every target | off |
| `-t`, `--timeout` | ICMP / ARP reply wait (seconds) | `2` |
| `--icmp-workers` | ICMP concurrent workers | `50` |
| **Stage 2: port scan** | | |
| `--tcp` / `--udp` | Port scan method | — |
| `-p`, `--tcp-ports` | TCP ports (`--ports` also works) | `1-1000` |
| `-u`, `--udp-ports` | UDP ports | `53,67,68,69,123,137,161,500,514,1900,5353` |
| `--tcp-workers` / `--udp-workers` | Concurrent workers | `100` / `20` |
| `--tcp-timeout` / `--udp-timeout` | Reply wait per port (seconds) | `1` / `2` |
| `--udp-delay` | Interval between UDP probes to the same host (seconds), `0` = no interval | `1` |

---

## How It Works

### 1. Host discovery: ARP is more accurate than ICMP

| | ICMP | ARP |
|---|---|---|
| Layer | 3 (`sr1()`) | 2 (`srp()`) |
| Concurrency | Thread pool (`sr1()` blocks) | None (`srp()` already batches) |
| Firewall | Can block it | Cannot (a host that ignores ARP cannot talk on the LAN) |
| Reach | Anywhere routable | Same layer-2 segment only |

Even when sending ICMP locally, Scapy sends **ARP first** to learn the destination
MAC. Local ICMP therefore rides on top of ARP and cannot be more accurate than it
(measured: /24 subnet, ICMP 18.4 s vs ARP 2.1 s).

**Layer-2 sends bypass routing.** Without an interface, `srp()` goes out the default
interface and scans the wrong segment. On a multi-homed host, leaving out `-i` found
1 host instead of 3, and the same IP came back with a different MAC. The cause is
Linux's weak host model (**ARP flux**): it answers ARP with the MAC of the interface
the request arrived on. It is not a wrong MAC but "the MAC of another link", and it
only became clear after following the path with tcpdump.

### 2. TCP Connect scan

```
connect_ex() == 0             → OPEN      (SYN-ACK)
connect_ex() == ECONNREFUSED  → CLOSED    (RST)
anything else (timeout etc.)  → FILTERED  (no reply)
```

FILTERED is the most expensive state. With no reply, the scan waits out the full
timeout. This is why firewalls slow scans down.

### 3. UDP scan and the ICMP rate limit

UDP has no "refuse" signal. A closed port is only visible through the **ICMP Port
Unreachable** the target kernel sends back. When a UDP socket is `connect()`ed, the
kernel delivers that ICMP as a `ConnectionRefusedError`, so no root is needed.

```
UDP reply received       → OPEN
ConnectionRefusedError   → CLOSED         (ICMP Port Unreachable)
timeout                  → OPEN|FILTERED  (open ports and firewalls are both silent)
other OSError            → FILTERED       (other ICMP errors)
```

The catch is that **Linux rate-limits ICMP errors per destination IP**. It is a token
bucket holding up to 6 tokens per peer (`XRLIM_BURST_FACTOR`), refilled by 1 token
every `icmp_ratelimit` (1000 ms). With no token, the ICMP is simply not generated,
so closed ports are misreported as OPEN|FILTERED.

`--udp-delay` reserves a "next allowed send time" per host, so probes to the same
host are at least 1 second apart while different hosts are scanned in parallel.
Send interval and reply wait are decoupled: while one probe waits for its timeout,
the next one still goes out a second later. Jobs are also queued port-first
`(p1,h1)(p1,h2)…`, so concurrent work spreads across hosts.

Measured (Linux target, 30 closed ports):

| Setting | Result | Time |
|---|---|---|
| `--udp-delay 0` | CLOSED 8 / OPEN\|FILTERED 22 | 4.0 s |
| `--udp-delay 1` (default) | **CLOSED 30** (same on repeat) | 29.0 s |

CLOSED 8 is the 6-token bucket plus 1–2 tokens refilled over 4 seconds; the kernel
constants show up directly in the result. Reducing the workers to 1 did not fix it,
because a closed port's ICMP returns immediately and the next probe goes out right
away. **Accuracy is set by the interval to each host, not by the number of workers.**

### 4. Skipping discovery (`-Pn`)

Discovery is a **filter**: a host dropped here is never port-scanned. macOS stealth
mode ignores ping and sends no RST for closed ports, but ports with a real service
still accept connections. ICMP discovery alone would have missed this host's two
open ports.

ARP still happens with `-Pn`. `connect()` needs the destination MAC to send a SYN, so
**the kernel performs ARP itself**. It does not report the result to the program,
though, so a missing host also shows up as FILTERED. TCP Connect alone cannot tell
"blocked by a firewall" from "no such host".

### 5. Service identification

A name assigned from the port number is only a convention. What the server says
about itself is the evidence.

| Case | Method | Measured example |
|---|---|---|
| Server speaks first | Collect the banner as is | `SSH-2.0-...` |
| MySQL handshake | Check protocol version (10) and the length field, then read up to the first NUL | `MySQL 8.0.46` |
| Silence | Send `HEAD / HTTP/1.0`, read the `Server` header | `nginx/1.31.1`, `Apache/2.4.67 (Debian)` |

HTTP is tried based on **silence, not the port number**, so web services on
non-standard ports are identified too. On the macOS host above, ports 5000 and 7000,
labeled `unknown`, turned out to be `AirTunes/980.77.5` (an AirPlay receiver, built
on HTTP and RTSP). Port 8080 was labeled `HTTP-Proxy` but was actually Apache.

The structure also explains why the MySQL banner looked garbled as `J8.0.46K...`.
The leading `J` (0x4A = 74) is not a character but the packet length field, and the
garbage after the version is the authentication salt.

---

## Design Decisions

- **Separate timeout knobs only where behavior differs**: discovery (ICMP, ARP) shares
  `-t`, while TCP and UDP port scans each get their own. A closed TCP port answers
  immediately with RST, but silence is a normal UDP result, so waiting means
  something different
- **Targets in CIDR**: a single IP becomes `/32`. Taking only the last octet would not
  say which network is meant, so it is not supported
- **Concurrency only at blocking points**: `sr1()` and `connect()` block, so they use a
  thread pool; `srp()` already batches, so it does not (threads would lose replies to
  pcap socket contention)
- **Defaults live only in argparse**: function arguments have no defaults, so "what is
  the default?" has exactly one answer

---

## Comparison with nmap and masscan

| Topic | netscan | nmap | masscan |
|---|---|---|---|
| Skip discovery | `-Pn` | `-Pn` | No discovery stage |
| UDP rate limit | Fixed interval `--udp-delay` | Raises the delay automatically when replies go missing (`--scan-delay`, `--max-scan-delay`) | Favors speed, gives up on closed detection |
| Timeout | Fixed per stage / protocol | Adjusted from measured RTT | Single `--wait` |
| Service identification | Banner + HTTP + MySQL | `nmap-service-probes` fingerprint DB | Some banners |

---

## Limitations & Future Work

- **Few protocol-specific UDP probes**: only DNS (53) and NTP (123) send data the
  service understands. Others get an empty datagram, so even open ports stay silent
  and remain OPEN|FILTERED (e.g. mDNS 5353 on a Linux target)
- **UDP is slow**: one port per second per host for accuracy. 1000 ports on one host take about 17 minutes
- **Connect scans are not stealthy**: the connection completes, so the target logs it
- **No HTTPS**: the `Server` header is not read over TLS
- **No result export**: console output only

---

## License

Licensed under **GPL v2** per this repository's policy. (See the top-level [LICENSE](../LICENSE).)

## Disclaimer

This tool is intended for learning and for **testing systems you own or are
authorized to test**. Unauthorized scanning may carry legal consequences.

---

**Author**: Benorm
