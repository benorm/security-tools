import logging
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

from scapy.all import IP, ICMP, sr1, Ether, ARP, srp
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time


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


# ── 공통 ────────────────────────────────────────────────

SCANNERS = {
    "icmp": ("ICMP", icmp_scan),
    "arp": ("ARP", arp_scan),
}


def sort_hosts(hosts):
    """마지막 옥텟 기준 정렬"""
    return sorted(hosts, key=lambda h: int(h["ip"].split(".")[-1]))


def print_report(label, hosts, elapsed):
    print(f"\n[+] {label} 스캔 결과: {len(hosts)}대 발견 ({elapsed:.1f}초)")
    if not hosts:
        return
    for h in hosts:
        mac = h["mac"] if h["mac"] else "-"
        print(f"    {h['ip']:<16} {mac}")


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캐너 (netscan)")
    parser.add_argument("-n", "--network", required=True,
                        help="스캔할 네트워크 앞 3옥텟 (예: 192.168.0.)")
    parser.add_argument("--icmp", action="store_true",
                        help="ICMP 스캔 수행")
    parser.add_argument("--arp", action="store_true",
                        help="ARP 스캔 수행 (로컬 세그먼트 전용)")
    parser.add_argument("-i", "--iface",
                        help="송신 인터페이스. ARP 스캔에 필요")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="ICMP 동시 작업자 수. 기본값: 50")
    parser.add_argument("-t", "--timeout", type=int, default=2,
                        help="ARP 응답 대기 시간(초). 기본값: 2")
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="Scapy 내부 경고 출력 (디버깅용)")
    args = parser.parse_args()

    if args.verbose:
        logging.getLogger("scapy.runtime").setLevel(logging.WARNING)

    selected = [k for k in SCANNERS if getattr(args, k)]
    if not selected:
        parser.error("스캔 방식을 하나 이상 지정하세요 (--icmp / --arp)")

    if args.arp and not args.iface:
        print("[!] ARP 스캔에 --iface가 지정되지 않았습니다.")
        print("[!] 2계층 전송은 라우팅을 거치지 않으므로 기본 인터페이스로 "
              "나가 다른 세그먼트를 스캔할 수 있습니다.\n")

    print(f"[*] {args.network}0/24 대역 스캔 시작")

    for key in selected:
        label, scanner = SCANNERS[key]
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


if __name__ == "__main__":
    main()