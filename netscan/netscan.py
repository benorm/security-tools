"""netscan: 호스트 발견과 포트 스캔을 한 번에 하는 네트워크 스캐너.

1단계 호스트 발견:  --icmp(3계층) / --arp(2계층), 또는 -Pn으로 건너뛰기
2단계 포트 스캔:    --tcp(TCP Connect) / --udp(UDP + ICMP 오류 판정)
                    열린 TCP 포트는 배너·HTTP Server 헤더·MySQL 버전을 수집

예) sudo python3 netscan.py -n 192.168.0.0/24 -i eth1 --arp --tcp
    python3 netscan.py -n 192.168.0.5 -Pn --udp -u 1-100

ICMP·ARP 발견은 raw 소켓을 쓰므로 root가 필요하고, 포트 스캔은 커널 소켓을 쓰므로 필요 없다.
"""

import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, ICMP, sr1, Ether, ARP, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import errno
import ipaddress
import socket
import threading
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

# 서버가 먼저 말하지 않는 TCP 포트에 보내는 요청. HEAD는 본문 없이 헤더만 받는다
HTTP_PROBE = b"HEAD / HTTP/1.0\r\n\r\n"


# ── ICMP ────────────────────────────────────────────────

def ping_host(target, timeout):
    """한 호스트에 ICMP ping을 보내 살아있는지 확인"""
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=timeout, verbose=0)
    return target, (response is not None)


def icmp_scan(targets, max_workers, timeout, **kwargs):
    """ICMP 에코 요청으로 대역을 스캔 (3계층, 멀티스레딩).

    sr1()은 호출당 타겟 하나를 블로킹 처리하므로 스레드 풀로 병렬화한다.
    라우팅 테이블이 송신 인터페이스를 결정하므로 iface 지정이 불필요하다.
    로컬 세그먼트에서는 Scapy가 목적지 MAC을 얻기 위해 내부적으로 ARP를 먼저 수행한다.
    """
    alive = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_target = {
            executor.submit(ping_host, t, timeout): t for t in targets
        }
        for future in as_completed(future_to_target):
            target, is_alive = future.result()
            if is_alive:
                alive.append({"ip": target, "mac": None})

    return alive


# ── ARP ─────────────────────────────────────────────────

def arp_scan(targets, iface, timeout, **kwargs):
    """ARP 요청으로 로컬 세그먼트를 스캔 (2계층, 일괄 전송).

    srp()가 다중 타겟 송신과 응답 수집을 비동기로 처리하므로
    스레드를 쓰지 않는다. 스레드를 쓰면 pcap 소켓 경합으로 응답이 유실된다.

    주의: 2계층 전송은 라우팅을 거치지 않는다. iface를 생략하면
    패킷 내용과 무관하게 conf.iface로 나가 다른 세그먼트를 스캔하게 된다.
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=targets)
    answered, _ = srp(packet, timeout=timeout, iface=iface, verbose=0)
    return [{"ip": rcv.psrc, "mac": rcv.hwsrc} for snd, rcv in answered]


# ── TCP (포트 상태 + 배너 수집) ─────────────────────────

def clean_banner(data):
    """수신 데이터에서 출력 가능한 문자만 남긴다"""
    text = data.decode(errors="ignore")
    return "".join(c for c in text if c.isprintable()).strip() or None


def mysql_version(data):
    """MySQL 초기 핸드셰이크 패킷이면 서버 버전 문자열만 꺼낸다. 아니면 None.

    패킷 구조: [길이 3B, little-endian][순번 1B][프로토콜 버전 1B = 10]
              [서버 버전 문자열 ... \x00][연결 ID, salt 등 바이너리]
    길이 필드가 실제 수신 길이와 맞는지까지 확인해 다른 바이너리 배너를 걸러낸다.
    """
    if len(data) < 6 or data[4] != 10:
        return None
    if int.from_bytes(data[:3], "little") != len(data) - 4:
        return None
    end = data.find(b"\x00", 5)
    if end == -1:
        return None
    return "MySQL " + data[5:end].decode(errors="ignore")


def http_server(data):
    """HTTP 응답에서 Server 헤더 값을 꺼낸다. 헤더가 없으면 상태 줄을 돌려준다.

    헤더 이름은 대소문자를 구분하지 않는다 (Server / server 모두 같은 헤더).
    """
    lines = data.decode(errors="ignore").split("\r\n")
    for line in lines[1:]:
        name, _, value = line.partition(":")
        if name.strip().lower() == "server":
            return value.strip() or None
    return lines[0].strip() or None


def grab_banner(s):
    """서버가 먼저 보내는 배너를 기다리고, 없으면 HTTP 요청을 보내 본다.

    SSH·FTP·MySQL은 연결 직후 서버가 먼저 말하지만 HTTP는 요청을 기다린다.
    그래서 timeout 동안 기다려도 아무것도 안 오면 HTTP_PROBE를 보낸다.
    포트 번호로 HTTP를 추정하지 않으므로 비표준 포트의 웹 서버도 식별된다.
    """
    try:
        data = s.recv(1024)
        if not data:
            return None     # TCP의 b"" = 상대가 연결을 닫음
        return mysql_version(data) or clean_banner(data)
    except socket.timeout:
        pass

    s.sendall(HTTP_PROBE)
    data = s.recv(1024)
    if data.startswith(b"HTTP/"):
        return http_server(data)
    return clean_banner(data)


def tcp_probe(ip, port, timeout):
    """TCP connect로 포트 하나를 검사하고, 열려 있으면 배너를 수집한다.

    connect_ex() 반환값으로 세 상태를 구분한다.
      0            → OPEN     (SYN-ACK 수신, 연결 성립)
      ECONNREFUSED → CLOSED   (RST 수신, 호스트가 거부 응답)
      그 외        → FILTERED (무응답, 방화벽이 버린 것으로 추정)
    배너 수집 방식은 grab_banner() 참고.
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
            banner = grab_banner(s)
        except OSError:
            pass    # 배너가 없어도 열림 판정에는 영향 없음
        return ip, port, "OPEN", banner
    finally:
        s.close()


# ── UDP ─────────────────────────────────────────────────

def udp_probe(ip, port, timeout):
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

class HostPacer:
    """호스트별 송신 간격을 지킨다 (UDP의 ICMP rate limit 대응).

    리눅스는 상대 IP마다 ICMP 오류를 약 1초에 1개만 보낸다. 더 촘촘히 보내면
    닫힌 포트의 ICMP Port Unreachable이 생략돼 OPEN|FILTERED로 잘못 판정된다.
    워커는 보내기 전에 그 호스트의 다음 송신 시각을 예약하고 그때까지 잔다.
    락은 예약하는 순간에만 잡으므로 다른 호스트로 가는 워커를 막지 않는다.
    """

    def __init__(self, delay):
        self.delay = delay
        self.next_send = {}
        self.lock = threading.Lock()

    def wait(self, ip):
        with self.lock:
            now = time.monotonic()
            slot = max(now, self.next_send.get(ip, now))
            self.next_send[ip] = slot + self.delay
        time.sleep(slot - now)


def port_scan(probe, hosts, ports, max_workers, timeout, delay):
    """대상 호스트들의 포트를 지정한 probe 함수로 스캔 (멀티스레딩).

    connect()/recv()는 블로킹이므로 스레드 풀로 병렬화한다.
    스레드마다 독립된 커널 소켓을 쓰므로 Scapy와 달리 thread-safe하다.
    (호스트 × 포트) 조합 전체를 하나의 풀에 넣어 처리한다.
    delay > 0이면 같은 호스트로의 송신 사이에 delay초 이상 간격을 둔다.
    """
    pacer = HostPacer(delay) if delay else None

    def job(ip, port):
        if pacer:
            pacer.wait(ip)
        return probe(ip, port, timeout)

    results = {h["ip"]: [] for h in hosts}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 포트 우선 순서 (p1,h1) (p1,h2) ... (p2,h1): 동시에 도는 작업이
        # 여러 호스트로 흩어져, 간격을 기다리며 자는 워커가 줄어든다
        futures = [executor.submit(job, h["ip"], p)
                   for p in ports for h in hosts]
        for future in as_completed(futures):
            ip, port, state, banner = future.result()
            results[ip].append((port, state, banner))
    return results


def parse_ports(ports_str):
    """'1-1000', '22,80,443', '1-100,8080' 형태를 포트 리스트로 변환.

    argparse의 type으로 쓰므로 잘못된 값은 ArgumentTypeError로 알린다.
    중복은 제거하고 오름차순으로 돌려준다.
    """
    ports = set()
    try:
        for part in ports_str.split(","):
            if "-" in part:
                start, end = (int(x) for x in part.split("-"))
            else:
                start = end = int(part)
            if not 1 <= start <= end <= 65535:
                raise ValueError
            ports.update(range(start, end + 1))
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"잘못된 포트 지정: '{ports_str}' (예: 22,80 / 1-1000, 범위 1-65535)")
    return sorted(ports)


def parse_network(value):
    """'192.168.0.0/24'(대역) 또는 '192.168.0.5'(단일 호스트)를 받는다.

    ip_network()는 '/'가 없으면 /32로 해석하므로 두 형태를 같은 방식으로 다룬다.
    strict=False: '192.168.0.5/24'처럼 호스트 비트가 섞여도 대역으로 바로잡는다.
    """
    try:
        return ipaddress.ip_network(value, strict=False)
    except ValueError:
        raise argparse.ArgumentTypeError(
            f"잘못된 대상: '{value}' (예: 192.168.0.0/24 또는 192.168.0.5)")


def positive_int(value):
    """1 이상의 정수만 허용 (작업자 수)"""
    n = int(value)
    if n < 1:
        raise argparse.ArgumentTypeError(f"1 이상이어야 합니다: {value}")
    return n


def non_negative_float(value):
    """0 이상의 실수만 허용 (간격, 초 단위. 0 = 간격 없음)"""
    x = float(value)
    if x < 0:
        raise argparse.ArgumentTypeError(f"0 이상이어야 합니다: {value}")
    return x


def positive_float(value):
    """0보다 큰 실수만 허용 (timeout, 초 단위)"""
    x = float(value)
    if x <= 0:
        raise argparse.ArgumentTypeError(f"0보다 커야 합니다: {value}")
    return x


# ── 공통 ────────────────────────────────────────────────

DISCOVERY = {
    "icmp": ("ICMP", icmp_scan),
    "arp": ("ARP", arp_scan),
}


def sort_hosts(hosts):
    """IP 주소 순서로 정렬"""
    return sorted(hosts, key=lambda h: ipaddress.ip_address(h["ip"]))


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
    for ip in sorted(results, key=ipaddress.ip_address):
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
    parser.add_argument("-n", "--network", required=True, type=parse_network,
                        help="스캔 대상. 대역(192.168.0.0/24) 또는 "
                             "단일 호스트(192.168.0.5)")
    parser.add_argument("-i", "--iface",
                        help="송신 인터페이스. ARP 스캔에 필요")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Scapy 내부 경고 출력 (디버깅용)")

    disc = parser.add_argument_group("1단계: 호스트 발견")
    disc.add_argument("--icmp", action="store_true",
                      help="ICMP 호스트 발견")
    disc.add_argument("--arp", action="store_true",
                      help="ARP 호스트 발견 (로컬 세그먼트 전용)")
    disc.add_argument("-t", "--timeout", type=positive_float, default=2,
                      help="ICMP·ARP 응답 대기 시간(초). 기본값: 2")
    disc.add_argument("--icmp-workers", type=positive_int, default=50,
                      help="ICMP 동시 작업자 수. 기본값: 50")
    disc.add_argument("-Pn", "--skip-discovery", action="store_true",
                      help="호스트 발견을 건너뛰고 대상 전체를 포트 스캔. "
                           "ICMP·ARP에 응답하지 않는 호스트용")

    scan = parser.add_argument_group("2단계: 포트 스캔")
    scan.add_argument("--tcp", action="store_true",
                      help="TCP Connect 포트 스캔 (root 불필요)")
    scan.add_argument("--udp", action="store_true",
                      help="UDP 포트 스캔 (root 불필요)")
    scan.add_argument("-p", "--tcp-ports", "--ports", type=parse_ports,
                      default="1-1000",
                      help="TCP 스캔 포트. 기본값: 1-1000")
    scan.add_argument("-u", "--udp-ports", type=parse_ports,
                      default=DEFAULT_UDP_PORTS,
                      help=f"UDP 스캔 포트. 기본값: {DEFAULT_UDP_PORTS}")
    scan.add_argument("--tcp-workers", type=positive_int, default=100,
                      help="TCP 동시 작업자 수. 기본값: 100")
    scan.add_argument("--udp-workers", type=positive_int, default=20,
                      help="UDP 동시 작업자 수. 기본값: 20")
    scan.add_argument("--tcp-timeout", type=positive_float, default=1,
                      help="TCP 포트당 응답 대기 시간(초). 기본값: 1")
    scan.add_argument("--udp-timeout", type=positive_float, default=2,
                      help="UDP 포트당 응답 대기 시간(초). 기본값: 2")
    scan.add_argument("--udp-delay", type=non_negative_float, default=1,
                      help="같은 호스트로 보내는 UDP 프로브 간격(초). "
                           "ICMP rate limit으로 닫힌 포트를 놓치지 않게 함. "
                           "0이면 간격 없음. 기본값: 1")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

    port_jobs = []
    if args.tcp:
        port_jobs.append(("tcp", tcp_probe, args.tcp_ports,
                          args.tcp_workers, args.tcp_timeout, 0))
    if args.udp:
        port_jobs.append(("udp", udp_probe, args.udp_ports,
                          args.udp_workers, args.udp_timeout, args.udp_delay))

    selected = [k for k in DISCOVERY if getattr(args, k)]
    if args.skip_discovery:
        if selected:
            parser.error("-Pn은 발견 단계를 건너뛰므로 --icmp / --arp와 "
                         "함께 쓸 수 없습니다")
        if not port_jobs:
            parser.error("-Pn에는 포트 스캔 방식이 필요합니다 (--tcp / --udp)")
    elif not selected:
        parser.error("호스트 발견 방식을 하나 이상 지정하세요 "
                     "(--icmp / --arp, 또는 -Pn)")

    if args.arp and not args.iface:
        print("[!] ARP 스캔에 --iface가 지정되지 않았습니다.")
        print("[!] 2계층 전송은 라우팅을 거치지 않으므로 기본 인터페이스로 "
              "나가 다른 세그먼트를 스캔할 수 있습니다.\n")

    # hosts(): 네트워크·브로드캐스트 주소 제외 (/24면 .1~.254, /32면 자기 자신)
    candidates = [str(ip) for ip in args.network.hosts()]
    print(f"[*] {args.network} 스캔 시작 (대상 {len(candidates)}개)")

    # 1단계: 호스트 발견
    found = []
    for key in selected:
        label, scanner = DISCOVERY[key]
        print(f"\n[*] {label} 스캔 중...")
        start = time.time()
        try:
            hosts = scanner(candidates, iface=args.iface,
                            max_workers=args.icmp_workers,
                            timeout=args.timeout)
        except PermissionError:
            print(f"[!] {label} 스캔에는 root 권한이 필요합니다 (sudo)")
            continue
        except OSError as e:
            print(f"[!] {label} 스캔 실패: {e}")
            continue
        print_report(label, sort_hosts(hosts), time.time() - start)
        found.append(hosts)

    # -Pn: 발견 결과 대신 후보 전체를 포트 스캔 대상으로 삼는다
    if args.skip_discovery:
        print("\n[*] 호스트 발견 생략 (-Pn): 대상 전체를 포트 스캔합니다")
        found.append([{"ip": ip, "mac": None} for ip in candidates])

    # 2단계: 포트 스캔
    if not port_jobs:
        return

    targets = sort_hosts(merge_hosts(*found))
    if not targets:
        print("\n[!] 발견된 호스트가 없어 포트 스캔을 건너뜁니다.")
        return

    for proto, probe, ports, workers, timeout, delay in port_jobs:
        print(f"\n[*] {proto.upper()} 스캔 중... "
              f"(호스트 {len(targets)}대 × 포트 {len(ports)}개)")
        start = time.time()
        results = port_scan(probe, targets, ports, workers, timeout, delay)
        print_port_report(proto, results, time.time() - start)


if __name__ == "__main__":
    main()