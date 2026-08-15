#!/usr/bin/env python3
"""
socket 기반 TCP Connect 포트 스캐너

커널의 정상 connect()를 사용해 대상 호스트의 열린 포트를 탐지하고,
서비스가 보내는 배너를 읽어 버전 정보를 수집하는 도구.

SYN 스캔(Scapy) 버전과 달리 커널의 TCP 스택을 사용하므로
root 권한이 필요 없고, 스레드마다 독립적인 소켓을 생성하여
thread-safe하다. 이 덕분에 작업자 수를 크게 높여도 안정적이다.

사용 예:
    python3 socket_scanner.py -t 192.168.0.10 -p 1-10000 -w 500

Author: Benorm
License: GPL v2
"""

import socket
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
    """포트 하나를 검사하고, 열려 있으면 배너를 수집한다.

    커널의 connect()로 TCP 연결을 시도한다(3-way handshake 완성).
    연결에 성공하면 서비스가 먼저 보내는 배너를 읽어 반환한다.

    Args:
        target (str): 스캔 대상 IP.
        port (int): 검사할 포트 번호.

    Returns:
        tuple[str, str | None]: (상태, 배너).
            상태는 "OPEN" 또는 "CLOSED".
            배너는 수집된 문자열, 없으면 None.
    """
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(1)
    result = s.connect_ex((target, port))

    if result != 0:
        s.close()
        return "CLOSED", None

    # 포트가 열렸으면 배너 읽기 시도
    banner = None
    try:
        data = s.recv(1024)
        text = data.decode(errors="ignore")
        # 출력 가능한 문자만 남겨 바이너리/제어문자를 제거
        banner = ''.join(c for c in text if c.isprintable()).strip()
        if not banner:
            banner = None
    except Exception:
        pass    # 배너가 없거나 수신 실패해도 열림 판정에는 영향 없음

    s.close()
    return "OPEN", banner


def scan_host(target, ports, max_workers=100):
    """여러 포트를 멀티스레딩으로 동시에 검사한다.

    Args:
        target (str): 스캔 대상 IP.
        ports (list[int]): 검사할 포트 번호 목록.
        max_workers (int): 동시 작업자(스레드) 수. 기본값 100.

    Returns:
        dict[int, tuple[str, str | None]]: {포트: (상태, 배너)}.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_port = {
            executor.submit(scan_port, target, port): port
            for port in ports
        }
        for future in as_completed(future_to_port):
            port = future_to_port[future]
            results[port] = future.result()
    return results


def parse_ports(ports_str):
    """포트 문자열을 정수 리스트로 변환한다.

    '1-1000'(범위), '22,80,443'(목록), '1-100,8080'(혼합)을 지원한다.

    Args:
        ports_str (str): 포트 지정 문자열.

    Returns:
        list[int]: 포트 번호 리스트.
    """
    ports = []
    for part in ports_str.split(","):
        if "-" in part:
            start, end = part.split("-")
            ports.extend(range(int(start), int(end) + 1))
        else:
            ports.append(int(part))
    return ports


def print_results(target, results, elapsed):
    """스캔 결과를 보기 좋게 출력한다.

    열린 포트만 표시하고, 배너가 있으면 함께 보여준다.
    닫힌 포트는 개수만 요약한다.

    Args:
        target (str): 스캔 대상 IP.
        results (dict): {포트: (상태, 배너)} 결과.
        elapsed (float): 소요 시간(초).
    """
    print(f"\n[*] 타겟 {target} 스캔 결과\n")

    for port in sorted(results.keys()):
        state, banner = results[port]
        if state == "CLOSED":
            continue
        service = SERVICE_NAMES.get(port, "unknown")
        line = f"  포트 {port} ({service}): {state}"
        if banner:
            line += f"  →  {banner[:60]}"
        print(line)

    open_ports = sorted([p for p, (s, b) in results.items() if s == "OPEN"])
    closed_count = sum(1 for (s, b) in results.values() if s == "CLOSED")

    print(f"\n[+] 열린 포트 {len(open_ports)}개: {open_ports}")
    print(f"[-] 닫힌 포트 {closed_count}개 (생략됨)")
    print(f"[*] 소요 시간: {elapsed:.1f}초")


def main():
    """명령행 인자를 파싱하고 스캔을 실행한다."""
    parser = argparse.ArgumentParser(description="socket 기반 TCP Connect 포트 스캐너")
    parser.add_argument("-t", "--target", required=True,
                        help="스캔할 대상 IP (필수)")
    parser.add_argument("-p", "--ports", default="1-1000",
                        help="포트 범위 (예: 1-1000 또는 22,80,443). 기본값: 1-1000")
    parser.add_argument("-w", "--workers", type=int, default=100,
                        help="동시 작업자 수. 기본값: 100")
    args = parser.parse_args()

    ports = parse_ports(args.ports)

    print(f"[*] 스캔 시작: {args.target} (포트 {len(ports)}개, 작업자 {args.workers}명)")
    start = time.time()
    results = scan_host(args.target, ports, max_workers=args.workers)
    elapsed = time.time() - start

    print_results(args.target, results, elapsed)


if __name__ == "__main__":
    main()