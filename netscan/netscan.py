import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, ICMP, sr1, Ether, ARP, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import errno
import socket
import time


SERVICE_NAMES = {
    "tcp": {
        21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
        80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
        3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
    },
    "udp": {
        53: "DNS", 67: "DHCP-Server", 68: "DHCP-Client", 69: "TFTP",
        123: "NTP", 137: "NetBIOS-NS", 161: "SNMP", 500: "IKE",
        514: "Syslog", 1900: "SSDP", 5353: "mDNS",
    },
}

# UDP 프로토콜별 프로브: 서비스가 "이해하는" 데이터를 보내야 응답이 온다
UDP_PROBES = {
    # DNS: example.com A 레코드 질의
    53: (b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
         b"\x07example\x03com\x00\x00\x01\x00\x01"),
    # NTP: v3 클라이언트 요청 (첫 바이트 0x1b + 47바이트 0)
    123: b"\x1b" + b"\x00" * 47,
}

DEFAULT_UDP_PORTS = "53,67,68,69,123,137,161,500,514,1900,5353"


# ── ICMP ────────────────────────────────────────────────

def ping_host(target):
    """한 호스트에 ICMP ping을 보내 살아있는지 확인"""
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    return target, (response is not None)


def icmp_scan(network, max_workers=50, **kwargs):
    """ICMP 에코 요청으로 대역을 스캔 (3계층, 멀티스레딩).

    sr1()은 호출당 타겟 하나를 블로킹 처리하므로 스레드 풀로 병렬화한다.
    라우팅 테이블이 송신 인터페이스를 결정하므로 iface 지정이 불필요하다.
    로컬 세그먼트에서는 Scapy가 목적지 MAC을 얻기 위해 내부적으로 ARP를 먼저 수행한다.
    """
    targets = [network + str(i) for i in range(1, 255)]
    alive = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(ping_host, t): t for t in targets
        }
        for future in as_completed(future_to_target):
            target, is_alive = future.result()
            if is_alive:
                alive.append({"ip": target, "mac": None})

    return alive


# ── ARP ─────────────────────────────────────────────────

def arp_scan(network, iface=None, timeout=2, **kwargs):
    """ARP 요청으로 로컬 세그먼트를 스캔 (2계층, 일괄 전송).

    srp()가 다중 타겟 송신과 응답 수집을 비동기로 처리하므로
    스레드를 쓰지 않는다. 스레드를 쓰면 pcap 소켓 경합으로 응답이 유실된다.

    주의: 2계층 전송은 라우팅을 거치지 않는다. iface를 생략하면
    패킷 내용과 무관하게 conf.iface로 나가 다른 세그먼트를 스캔하게 된다.
    """
    targets = [network + str(i) for i in range(1, 255)]
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=0)
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for snd, rcv in answered]


# ── TCP ─────────────────────────────────────────────────

def clean_banner(data):
    """수신 데이터에서 출력 가능한 문자만 남긴다"""
    text = data.decode(errors="ignore")
    return "".join(c for c in text if c.isprintable()).strip() or None


def tcp_probe(ip, port, timeout=1):
    """TCP connect로 포트 하나를 검사하고, 열려 있으면 배너를 수집한다.

    connect_ex() 반환값으로 세 상태를 구분한다.
      0            → OPEN     (SYN-ACK 수신, 연결 성립)
      ECONNREFUSED → CLOSED   (RST 수신, 호스트가 거부 응답)
      그 외        → FILTERED (무응답, 방화벽이 버린 것으로 추정)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        result = s.connect_ex((ip, port))
        if result == errno.ECONNREFUSED:
            return ip, port, "CLOSED", None
        if result != 0:
            return ip, port, "FILTERED", None

        banner = None
        try:
            banner = clean_banner(s.recv(1024))
        except OSError:
            pass    # 배너가 없어도 열림 판정에는 영향 없음
        return ip, port, "OPEN", banner
    finally:
        s.close()


# ── UDP ─────────────────────────────────────────────────

def udp_probe(ip, port, timeout=2):
    """UDP 데이터그램을 보내 포트 상태를 추정한다.

    UDP 소켓에 connect()를 하면 커널이 해당 상대의 ICMP 오류를
    이 소켓의 예외로 전달한다. 이를 이용해 root 없이 판정한다.
      UDP 응답 수신            → OPEN
      ConnectionRefusedError   → CLOSED        (ICMP Port Unreachable)
      timeout                  → OPEN|FILTERED (열린 포트도, 방화벽도 무응답)
      그 외 OSError            → FILTERED      (호스트 차단 등 다른 ICMP 오류)
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(timeout)
    try:
        s.connect((ip, port))
        s.send(UDP_PROBES.get(port, b""))
        data = s.recv(1024)
        return ip, port, "OPEN", clean_banner(data)
    except ConnectionRefusedError:
        return ip, port, "CLOSED", None
    except socket.timeout:
        return ip, port, "OPEN|FILTERED", None
    except OSError:
        return ip, port, "FILTERED", None
    finally:
        s.close()


# ── 포트 스캔 공통 ──────────────────────────────────────

def port_scan(probe, hosts, ports, max_workers):
    """발견된 호스트들의 포트를 지정한 probe 함수로 스캔 (멀티스레딩).

    connect()/recv()는 블로킹이므로 스레드 풀로 병렬화한다.
    스레드마다 독립된 커널 소켓을 쓰므로 Scapy와 달리 thread-safe하다.
    (호스트 × 포트) 조합 전체를 하나의 풀에 넣어 처리한다.
    """
    results = {h["ip"]: [] for h in hosts}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(probe, h["ip"], p)
                   for h in hosts for p in ports]
        for future in as_completed(futures):
            ip, port, state, banner = future.result()
            results[ip].append((port, state, banner))
    return results


def parse_ports(ports_str):
    """'1-1000', '22,80,443', '1-100,8080' 형태를 포트 리스트로 변환"""
    ports = []
    for part in ports_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


# ── 공통 ────────────────────────────────────────────────

DISCOVERY = {
    "icmp": ("ICMP", icmp_scan),
    "arp": ("ARP", arp_scan),
}


def sort_hosts(hosts):
    """마지막 옥텟 기준 정렬"""
    return sorted(hosts, key=lambda h: int(h["ip"].split(".")[-1]))


def merge_hosts(*host_lists):
    """여러 발견 결과를 IP 기준으로 합친다. MAC은 아는 쪽을 우선한다."""
    merged = {}
    for hosts in host_lists:
        for h in hosts:
            if h["ip"] not in merged or (h["mac"] and not merged[h["ip"]]["mac"]):
                merged[h["ip"]] = h
    return list(merged.values())


def print_report(label, hosts, elapsed):
    print(f"\n[+] {label} 스캔 결과: {len(hosts)}대 발견 ({elapsed:.1f}초)")
    for h in hosts:
        mac = h["mac"] if h["mac"] else "-"
        print(f"    {h['ip']:<16} {mac}")


def print_port_report(proto, results, elapsed):
    print(f"\n[+] {proto.upper()} 포트 스캔 결과 ({elapsed:.1f}초)")
    names = SERVICE_NAMES[proto]
    for ip in sorted(results, key=lambda x: int(x.split(".")[-1])):
        entries = sorted(results[ip])

        counts = {}
        for _, state, _ in entries:
            counts[state] = counts.get(state, 0) + 1
        summary = " / ".join(f"{st} {n}" for st, n in counts.items())
        print(f"\n    [{ip}]  {summary}")

        for port, state, banner in entries:
            if state != "OPEN":
                continue
            line = f"      {port:>5}/{proto}  {names.get(port, 'unknown'):<11}"
            if banner:
                line += f" {banner[:60]}"
            print(line)


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캐너 (netscan)")
    parser.add_argument("-n", "--network", required=True,
                        help="스캔할 네트워크 앞 3옥텟 (예: 192.168.0.)")
    parser.add_argument("--icmp", action="store_true",
                        help="ICMP 호스트 발견")
    parser.add_argument("--arp", action="store_true",
                        help="ARP 호스트 발견 (로컬 세그먼트 전용)")
    parser.add_argument("--tcp", action="store_true",
                        help="발견된 호스트에 TCP Connect 포트 스캔")
    parser.add_argument("--udp", action="store_true",
                        help="발견된 호스트에 UDP 포트 스캔")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="TCP 스캔 포트. 기본값: 1-1000")
    parser.add_argument("-u", "--udp-ports", default=DEFAULT_UDP_PORTS,
                        help=f"UDP 스캔 포트. 기본값: {DEFAULT_UDP_PORTS}")
    parser.add_argument("-i", "--iface",
                        help="송신 인터페이스. ARP 스캔에 필요")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="ICMP 동시 작업자 수. 기본값: 50")
    parser.add_argument("--tcp-workers", type=int, default=100,
                        help="TCP 동시 작업자 수. 기본값: 100")
    parser.add_argument("--udp-workers", type=int, default=20,
                        help="UDP 동시 작업자 수. 기본값: 20")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="ARP 응답 대기 시간(초). 기본값: 2")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Scapy 내부 경고 출력 (디버깅용)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

    selected = [k for k in DISCOVERY if getattr(args, k)]
    if not selected:
        parser.error("호스트 발견 방식을 하나 이상 지정하세요 (--icmp / --arp)")

    if args.arp and not args.iface:
        print("[!] ARP 스캔에 --iface가 지정되지 않았습니다.")
        print("[!] 2계층 전송은 라우팅을 거치지 않으므로 기본 인터페이스로 "
              "나가 다른 세그먼트를 스캔할 수 있습니다.\n")

    print(f"[*] {args.network}0/24 대역 스캔 시작")

    # 1단계: 호스트 발견
    found = []
    for key in selected:
        label, scanner = DISCOVERY[key]
        print(f"\n[*] {label} 스캔 중...")
        start = time.time()
        try:
            hosts = scanner(args.network, iface=args.iface,
                            max_workers=args.workers, timeout=args.timeout)
        except PermissionError:
            print(f"[!] {label} 스캔에는 root 권한이 필요합니다 (sudo)")
            continue
        except OSError as e:
            print(f"[!] {label} 스캔 실패: {e}")
            continue
        print_report(label, sort_hosts(hosts), time.time() - start)
        found.append(hosts)

    # 2단계: 포트 스캔
    port_jobs = []
    if args.tcp:
        port_jobs.append(("tcp", tcp_probe, args.ports, args.tcp_workers))
    if args.udp:
        port_jobs.append(("udp", udp_probe, args.udp_ports, args.udp_workers))
    if not port_jobs:
        return

    targets = sort_hosts(merge_hosts(*found))
    if not targets:
        print("\n[!] 발견된 호스트가 없어 포트 스캔을 건너뜁니다.")
        return

    for proto, probe, ports_str, workers in port_jobs:
        ports = parse_ports(ports_str)
        print(f"\n[*] {proto.upper()} 스캔 중... "
              f"(호스트 {len(targets)}대 × 포트 {len(ports)}개)")
        start = time.time()
        results = port_scan(probe, targets, ports, workers)
        print_port_report(proto, results, time.time() - start)


if __name__ == "__main__":
    main()