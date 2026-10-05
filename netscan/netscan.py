import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, ICMP, sr1, Ether, ARP, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import errno
import socket
import time


SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
}


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
            data = s.recv(1024)
            text = data.decode(errors="ignore")
            banner = "".join(c for c in text if c.isprintable()).strip() or None
        except OSError:
            pass    # 배너가 없어도 열림 판정에는 영향 없음
        return ip, port, "OPEN", banner
    finally:
        s.close()


def tcp_scan(hosts, ports, max_workers=100):
    """발견된 호스트들의 포트를 TCP Connect로 스캔 (4계층, 멀티스레딩).

    connect()는 블로킹이므로 스레드 풀로 병렬화한다.
    스레드마다 독립된 커널 소켓을 쓰므로 Scapy와 달리 thread-safe하다.
    (호스트 × 포트) 조합 전체를 하나의 풀에 넣어 처리한다.
    """
    results = {h["ip"]: [] for h in hosts}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(tcp_probe, h["ip"], p)
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


def print_tcp_report(results, elapsed):
    print(f"\n[+] TCP 포트 스캔 결과 ({elapsed:.1f}초)")
    for ip in sorted(results, key=lambda x: int(x.split(".")[-1])):
        entries = sorted(results[ip])
        open_ports = [e for e in entries if e[1] == "OPEN"]
        closed = sum(1 for e in entries if e[1] == "CLOSED")
        filtered = sum(1 for e in entries if e[1] == "FILTERED")

        print(f"\n    [{ip}]  OPEN {len(open_ports)} / "
              f"CLOSED {closed} / FILTERED {filtered}")
        for port, state, banner in open_ports:
            service = SERVICE_NAMES.get(port, "unknown")
            line = f"      {port:>5}/tcp  {service:<11}"
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
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="TCP 스캔 포트 (예: 1-1000, 22,80,443). 기본값: 1-1000")
    parser.add_argument("-i", "--iface",
                        help="송신 인터페이스. ARP 스캔에 필요")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="ICMP 동시 작업자 수. 기본값: 50")
    parser.add_argument("--tcp-workers", type=int, default=100,
                        help="TCP 동시 작업자 수. 기본값: 100")
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
    if args.tcp:
        targets = sort_hosts(merge_hosts(*found))
        if not targets:
            print("\n[!] 발견된 호스트가 없어 TCP 스캔을 건너뜁니다.")
            return
        ports = parse_ports(args.ports)
        print(f"\n[*] TCP 스캔 중... (호스트 {len(targets)}대 × 포트 {len(ports)}개)")
        start = time.time()
        results = tcp_scan(targets, ports, max_workers=args.tcp_workers)
        print_tcp_report(results, time.time() - start)


if __name__ == "__main__":
    main()