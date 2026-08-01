#!/usr/bin/env python3
"""
SYN 포트 스캐너 (Scapy 기반)

TCP SYN 스캔을 사용해 대상 호스트의 열린 포트를 탐지하는 도구.
멀티스레딩으로 다수 포트를 동시에 스캔하며, 명령행 인자로
대상/포트/작업자 수를 지정할 수 있다.

사용 예:
    sudo python3 simply_scanner.py -t 192.168.0.10 -p 1-1000 -w 15

주의:
    - raw socket 사용으로 root 권한(sudo)이 필요하다.
    - Scapy는 thread-safe하지 않아 작업자 수를 너무 높이면
      "Bad file descriptor" 오류가 발생할 수 있다 (기본값 15 권장).

Author: Benorm
License: GPL v2 (Scapy 의존성에 따름)
"""

from scapy.all import IP, TCP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time

# 잘 알려진 포트 번호 → 서비스 이름 대응표
SERVICE_NAMES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 143: "IMAP", 443: "HTTPS",
    3306: "MySQL", 3389: "RDP", 8080: "HTTP-Proxy",
}


def scan_port(target, port):
    """포트 하나의 상태를 검사한다.

    SYN 패킷을 보내고 응답의 TCP 플래그로 상태를 판별한다.
    - SYN/ACK 응답 → 열림 (OPEN)
    - RST/ACK 응답 → 닫힘 (CLOSED)
    - 무응답      → 필터링 추정 (FILTERED)

    Args:
        target (str): 스캔 대상 IP.
        port (int): 검사할 포트 번호.

    Returns:
        str: "OPEN", "CLOSED", "FILTERED" 중 하나.
    """
    response = sr1(IP(dst=target)/TCP(dport=port, flags="S"), timeout=1, verbose=0)

    if response and response.haslayer(TCP):
        if response[TCP].flags == "SA":
            return "OPEN"
        elif response[TCP].flags == "RA":
            return "CLOSED"
    return "FILTERED"


def scan_host(target, ports, max_workers=15):
    """여러 포트를 멀티스레딩으로 동시에 검사한다.

    Args:
        target (str): 스캔 대상 IP.
        ports (list[int]): 검사할 포트 번호 목록.
        max_workers (int): 동시 작업자(스레드) 수. 기본값 15.

    Returns:
        dict[int, str]: {포트번호: 상태} 형태의 결과.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        # 각 포트를 작업자에게 배정 (실행 예약)
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }
        # 완료되는 대로 결과 수거
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            results[port] = future.result()
    return results


def parse_ports(ports_str):
    """포트 문자열을 정수 리스트로 변환한다.

    '1-1000'(범위)과 '22,80,443'(목록), 둘을 섞은
    '1-100,8080' 형식을 모두 지원한다.

    Args:
        ports_str (str): 포트 지정 문자열.

    Returns:
        list[int]: 포트 번호 리스트.
    """
    ports = []
    for part in ports_str.split(","):
        if "-" in part:                       # 범위 (예: 1-1000)
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:                                 # 단일 포트 (예: 80)
            ports.append(int(part))
    return ports


def print_results(target, results):
    """스캔 결과를 보기 좋게 출력한다.

    열린 포트만 표시하고, 닫힌 포트는 개수만 요약한다.

    Args:
        target (str): 스캔 대상 IP.
        results (dict[int, str]): {포트번호: 상태} 결과.
    """
    print(f"\n[*] 타겟 {target} 스캔 결과\n")

    for port in sorted(results.keys()):
        state = results[port]
        if state == "CLOSED":
            continue   # 닫힌 포트는 건너뜀
        service = SERVICE_NAMES.get(port, "unknown")
        print(f"  포트 {port} ({service}): {state}")

    open_ports = sorted([p for p, s in results.items() if s == "OPEN"])
    closed_count = sum(1 for s in results.values() if s == "CLOSED")

    print(f"\n[+] 열린 포트 {len(open_ports)}개: {open_ports}")
    print(f"[-] 닫힌 포트 {closed_count}개 (생략됨)")
    print("[*] 스캔 완료")


def main():
    """명령행 인자를 파싱하고 스캔을 실행한다."""
    parser = argparse.ArgumentParser(description="Scapy 기반 SYN 포트 스캐너")
    parser.add_argument("-t", "--target", required=True,
                        help="스캔할 대상 IP (필수)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="포트 범위 (예: 1-1000 또는 22,80,443). 기본값: 1-1000")
    parser.add_argument("-w", "--workers", type=int, default=15,
                        help="동시 작업자 수. Scapy 특성상 너무 높이면 불안정. 기본값: 15")
    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print(f"[*] 스캔 시작: {args.target} (포트 {len(ports)}개, 작업자 {args.workers}명)")
    start = time.time()
    results = scan_host(args.target, ports, max_workers=args.workers)
    elapsed = time.time() - start

    print_results(args.target, results)
    print(f"[*] 소요 시간: {elapsed:.1f}초")


if __name__ == "__main__":
    main()