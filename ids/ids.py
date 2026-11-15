#!/usr/bin/env python3
"""ids - 네트워크 스캔 탐지기

출발지 IP별로 최근 window초 동안 건드린 대상을 규칙마다 따로 기록하고,
서로 다른 대상 수가 threshold 이상이면 경보한다.
  - TCP SYN·UDP: 대상 = 목적지 포트 (포트 스캔)
  - ARP 요청:    대상 = 물어본 IP   (호스트 스윕)
--log를 주면 경보를 JSON Lines(한 줄 = 경보 하나)로도 기록한다.
"""
import argparse
import ipaddress
import json
import time
from collections import defaultdict, deque
from datetime import datetime

from scapy.all import ARP, IP, TCP, UDP, sniff

# SYN만 켜지고 ACK는 꺼진 패킷 = 연결 시작 요청 (SYN-ACK 응답은 제외)
SYN_ONLY = "tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn"
DEFAULT_FILTER = f"({SYN_ONLY}) or udp or arp"

# 탐지 규칙. Snort·Suricata 관례상 signature_id 1000000 이상은 사용자 정의 규칙
# target: 로그의 scan 필드에서 대상 목록을 담을 이름
RULES = {
    "TCP": {"signature_id": 1000001, "signature": "TCP 포트 스캔 의심",
            "category": "port-scan", "target": "ports"},
    "UDP": {"signature_id": 1000002, "signature": "UDP 포트 스캔 의심",
            "category": "port-scan", "target": "ports"},
    "ARP": {"signature_id": 1000003, "signature": "ARP 스윕 의심",
            "category": "host-sweep", "target": "hosts"},
}

ARP_REQUEST = 1  # ARP op: 1 = who-has(요청), 2 = is-at(응답)


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


def sort_targets(targets):
    """포트(int)는 숫자순, IP(str)는 주소순 (문자열 정렬이면 .10이 .2보다 앞섬)"""
    return sorted(targets, key=lambda t: ipaddress.ip_address(t) if isinstance(t, str) else t)


class ScanDetector:
    """출발지별 시간 창 안에서 건드린 서로 다른 대상(포트·IP) 수로 스캔 판단"""

    def __init__(self, window, threshold):
        self.window = window
        self.threshold = threshold
        self.history = defaultdict(deque)  # 출발지 → deque[(시각, 대상)]
        self.alerted = {}                  # 출발지 → 마지막 경보 시각

    def check(self, src, target, now):
        """패킷 하나를 기록하고, 경보 조건을 넘으면 대상 집합을 돌려준다"""
        events = self.history[src]
        events.append((now, target))
        while now - events[0][0] > self.window:  # 창 밖으로 나간 기록 제거
            events.popleft()

        targets = {t for _, t in events}
        if len(targets) < self.threshold:
            return None
        if now - self.alerted.get(src, float("-inf")) < self.window:
            return None  # 같은 출발지는 window초에 한 번만 경보
        self.alerted[src] = now
        return targets


def build_alert(now, proto, src, dst, targets, window):
    """경보 하나를 Suricata eve.json과 비슷한 필드 구조의 dict로"""
    rule = RULES[proto]
    alert = {
        "timestamp": datetime.fromtimestamp(now).astimezone().isoformat(timespec="milliseconds"),
        "event_type": "alert",
        "src_ip": src,
    }
    if dst:  # ARP 스윕은 대상이 여러 IP라 하나의 목적지가 없음
        alert["dest_ip"] = dst
    alert.update({
        "proto": proto,
        "alert": {k: rule[k] for k in ("signature_id", "signature", "category")},
        "scan": {"window": window, f"{rule['target'][:-1]}_count": len(targets),
                 rule["target"]: sort_targets(targets)},
    })
    return alert


def classify(pkt):
    """패킷을 (규칙, 출발지, 목적지, 대상, 출력용 설명)으로. 탐지 대상이 아니면 None"""
    if ARP in pkt:
        arp = pkt[ARP]
        # 요청만 셈. 출발지 0.0.0.0(DHCP 중복 확인 probe)·자기 IP 알림(gratuitous)은 스윕이 아님
        if arp.op != ARP_REQUEST or arp.psrc in ("0.0.0.0", arp.pdst):
            return None
        return "ARP", arp.psrc, None, arp.pdst, f"ARP who-has {arp.pdst} tell {arp.psrc}"
    if IP not in pkt:
        return None
    if TCP in pkt:
        proto, l4, kind = "TCP", pkt[TCP], "SYN"
    elif UDP in pkt:
        proto, l4, kind = "UDP", pkt[UDP], "UDP"
    else:
        return None
    src, dst = pkt[IP].src, pkt[IP].dst
    return proto, src, dst, l4.dport, f"{kind} {src}:{l4.sport} > {dst}:{l4.dport}"


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캔 탐지기")
    parser.add_argument("-i", "--iface", required=True,
                        help="감시할 인터페이스")
    parser.add_argument("-f", "--filter", default=DEFAULT_FILTER,
                        help="BPF 캡처 필터 (기본: TCP SYN + UDP + ARP)")
    parser.add_argument("-w", "--window", type=positive_float, default=10.0,
                        help="탐지 시간 창, 초 (기본: %(default)s)")
    parser.add_argument("-T", "--threshold", type=positive_int, default=15,
                        help="시간 창 안의 서로 다른 대상(포트·IP) 수 기준 (기본: %(default)s)")
    parser.add_argument("-l", "--log",
                        help="경보를 JSON Lines로 덧붙여 기록할 파일")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="탐지 대상 패킷(TCP SYN·UDP·ARP 요청)을 모두 출력")
    args = parser.parse_args()

    log_file = None
    if args.log:
        try:
            # buffering=1: 줄 단위로 바로 디스크에 씀 → tail -f·수집기가 즉시 읽음
            log_file = open(args.log, "a", encoding="utf-8", buffering=1)
        except OSError as e:
            parser.error(f"로그 파일을 열 수 없습니다: {e}")

    # 규칙마다 따로 셈: TCP 22와 UDP 22는 다른 포트, ARP는 포트가 아니라 IP를 셈
    detectors = {proto: ScanDetector(args.window, args.threshold) for proto in RULES}

    def handle(pkt):
        result = classify(pkt)
        if not result:
            return
        proto, src, dst, target, desc = result
        now = float(pkt.time)
        if args.verbose:
            print(f"{fmt_time(now)} {desc}")

        targets = detectors[proto].check(src, target, now)
        if not targets:
            return
        listed = sort_targets(targets)
        sample = ", ".join(map(str, listed[:10])) + (", ..." if len(listed) > 10 else "")
        unit = "포트" if RULES[proto]["target"] == "ports" else "IP"
        print(f"[!] {fmt_time(now)} {RULES[proto]['signature']}: {src} → "
              f"{args.window:g}초 안에 {unit} {len(targets)}개 ({sample})")
        if log_file:
            alert = build_alert(now, proto, src, dst, targets, args.window)
            log_file.write(json.dumps(alert, ensure_ascii=False) + "\n")

    print(f"[*] {args.iface} 감시 시작 (창 {args.window:g}초, 기준 {args.threshold}개"
          f"{', 로그 ' + args.log if args.log else ''}), Ctrl+C로 종료")
    try:
        sniff(iface=args.iface, filter=args.filter, store=False, prn=handle)
    finally:
        if log_file:
            log_file.close()


if __name__ == "__main__":
    main()
