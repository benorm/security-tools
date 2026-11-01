#!/usr/bin/env python3
"""ids - 네트워크 스캔 탐지기 (1단계: 패킷 캡처)"""
import argparse

from scapy.all import sniff


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캔 탐지기")
    parser.add_argument("-i", "--iface", required=True,
                        help="감시할 인터페이스")
    parser.add_argument("-f", "--filter", default="tcp or udp or icmp or arp",
                        help="BPF 캡처 필터 (기본: %(default)s)")
    args = parser.parse_args()

    print(f"[*] {args.iface} 감시 시작 (필터: {args.filter}), Ctrl+C로 종료")
    sniff(iface=args.iface, filter=args.filter, store=False,
          prn=lambda pkt: print(pkt.summary()))


if __name__ == "__main__":
    main()