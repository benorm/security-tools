from scapy.all import IP, ICMP, sr1
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import time


def ping_host(target):
    """한 호스트에 ICMP ping을 보내 살아있는지 확인"""
    packet = IP(dst=target)/ICMP()
    response = sr1(packet, timeout=1, verbose=0)
    return target, (response is not None)


def icmp_scan(network, max_workers=50):
    """네트워크 대역을 멀티스레딩으로 ICMP 스캔.

    network는 '192.168.0.' 형태의 앞 3옥텟(끝에 점 포함).
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
                print(f"  {target}: 살아있음 (UP)")
                alive.append(target)

    return sorted(alive)


def main():
    parser = argparse.ArgumentParser(description="네트워크 스캐너 (netscan)")
    parser.add_argument("-n", "--network", required=True,
                        help="스캔할 네트워크 앞 3옥텟 (예: 192.168.0.)")
    parser.add_argument("-w", "--workers", type=int, default=50,
                        help="동시 작업자 수. 기본값: 50")
    args = parser.parse_args()

    print(f"[*] {args.network}0/24 대역 스캔 시작\n")
    start = time.time()
    alive = icmp_scan(args.network, max_workers=args.workers)
    elapsed = time.time() - start

    print(f"\n[+] 살아있는 호스트 {len(alive)}개: {alive}")
    print(f"[*] 소요 시간: {elapsed:.1f}초")


if __name__ == "__main__":
    main()