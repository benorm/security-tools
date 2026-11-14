#!/usr/bin/env python3
"""ids - 네트워크 스캔 탐지기

출발지 IP별로 최근 window초 동안 접근한 목적지 포트를 프로토콜(TCP SYN, UDP)마다
따로 기록하고, 서로 다른 포트 수가 threshold 이상이면 포트 스캔으로 경보한다.
--log를 주면 경보를 JSON Lines(한 줄 = 경보 하나)로도 기록한다.
"""
import argparse
import json
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import IP, TCP, UDP, sniff

# SYN만 켜지고 ACK는 꺼진 패킷 = 연결 시작 요청 (SYN-ACK 응답은 제외)
SYN_ONLY = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
DEFAULT_FILTER = f"({SYN_ONLY}) or udp"

# 프로토콜별 탐지 규칙. Snort·Suricata 관례상 signature_id 1000000 이상은 사용자 정의 규칙
RULES = {
    "TCP": {"signature_id": 1000001, "signature": "TCP 포트 스캔 의심"},
    "UDP": {"signature_id": 1000002, "signature": "UDP 포트 스캔 의심"},
}


def positive_int(value):
    number = int(value)
    if number < 1:
        raise argparse.ArgumentTypeError(f"1 이상이어야 합니다: {value}")
    return number


def positive_float(value):
    number = float(value)
    if number <= 0:
        raise argparse.ArgumentTypeError(f"0보다 커야 합니다: {value}")
    return number


def fmt_time(t):
    """캡처 시각을 HH:MM:SS.mmm 형식으로"""
    return time.strftime("%H:%M:%S", time.localtime(t)) + f".{int(t % 1 * 1000):03d}"


class PortScanDetector:
    """출발지별 시간 창 안에서 접근한 서로 다른 포트 수로 포트 스캔 판단"""

    def __init__(self, window, threshold):
        self.window = window
        self.threshold = threshold
        self.history = defaultdict(deque)  # 출발지 → deque[(시각, 목적지 포트)]
        self.alerted = {}                  # 출발지 → 마지막 경보 시각

    def check(self, src, dport, now):
        """패킷 하나를 기록하고, 경보 조건을 넘으면 포트 집합을 돌려준다"""
        events = self.history[src]
        events.append((now, dport))
        while now - events[0][0] > self.window:  # 창 밖으로 나간 기록 제거
            events.popleft()

        ports = {port for _, port in events}
        if len(ports) < self.threshold:
            return None
        if now - self.alerted.get(src, float("-inf")) < self.window:
            return None  # 같은 출발지는 window초에 한 번만 경보
        self.alerted[src] = now
        return ports


def build_alert(now, proto, src, dst, ports, window):
    """경보 하나를 Suricata eve.json과 비슷한 필드 구조의 dict로"""
    return {
        "timestamp": datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds"),
        "event_type": "alert",
        "src_ip": src,
        "dest_ip": dst,
        "proto": proto,
        "alert": {**RULES[proto], "category": "port-scan"},
        "scan": {"window": window, "port_count": len(ports), "ports": sorted(ports)},
    }


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캔 탐지기")
    parser.add_argument("-i", "--iface", required=True,
                        help="감시할 인터페이스")
    parser.add_argument("-f", "--filter", default=DEFAULT_FILTER,
                        help="BPF 캡처 필터 (기본: TCP SYN + UDP)")
    parser.add_argument("-w", "--window", type=positive_float, default=10.0,
                        help="탐지 시간 창, 초 (기본: %(default)s)")
    parser.add_argument("-T", "--threshold", type=positive_int, default=15,
                        help="시간 창 안의 서로 다른 포트 수 기준 (기본: %(default)s)")
    parser.add_argument("-l", "--log",
                        help="경보를 JSON Lines로 덧붙여 기록할 파일")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="받은 TCP SYN·UDP 패킷을 모두 출력")
    args = parser.parse_args()

    log_file = None
    if args.log:
        try:
            # buffering=1: 줄 단위로 바로 디스크에 씀 → tail -f·수집기가 즉시 읽음
            log_file = open(args.log, "a", encoding="utf-8", buffering=1)
        except OSError as e:
            parser.error(f"로그 파일을 열 수 없습니다: {e}")

    # 프로토콜마다 따로 셈: TCP 22와 UDP 22는 다른 포트
    detectors = {proto: PortScanDetector(args.window, args.threshold) for proto in RULES}

    def handle(pkt):
        if IP not in pkt:
            return
        if TCP in pkt:
            proto, l4 = "TCP", pkt[TCP]
        elif UDP in pkt:
            proto, l4 = "UDP", pkt[UDP]
        else:
            return
        src, dst, dport, now = pkt[IP].src, pkt[IP].dst, l4.dport, float(pkt.time)
        if args.verbose:
            kind = "SYN" if proto == "TCP" else "UDP"
            print(f"{fmt_time(now)} {kind} {src}:{l4.sport} > {dst}:{dport}")

        ports = detectors[proto].check(src, dport, now)
        if not ports:
            return
        listed = sorted(ports)
        sample = ", ".join(map(str, listed[:10])) + (", ..." if len(listed) > 10 else "")
        print(f"[!] {fmt_time(now)} {RULES[proto]['signature']}: {src} → "
              f"{args.window:g}초 안에 포트 {len(ports)}개 ({sample})")
        if log_file:
            alert = build_alert(now, proto, src, dst, ports, args.window)
            log_file.write(json.dumps(alert, ensure_ascii=False) + "\n")

    print(f"[*] {args.iface} 감시 시작 (창 {args.window:g}초, 기준 포트 {args.threshold}개"
          f"{', 로그 ' + args.log if args.log else ''}), Ctrl+C로 종료")
    try:
        sniff(iface=args.iface, filter=args.filter, store=False, prn=handle)
    finally:
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
