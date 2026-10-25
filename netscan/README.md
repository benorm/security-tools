# netscan

> 호스트 발견(ICMP·ARP)과 포트 스캔(TCP·UDP)을 한 번에 하는 네트워크 스캐너.
> 앞선 두 스캐너에서 배운 것을 하나의 도구로 묶고,
> UDP 정확도와 서비스 식별까지 직접 구현했다.

[English](./README.en.md) | 한국어

---

## 개요

[syn-scanner](../syn-scanner)와 [socket-scanner](../socket-scanner)는
"이미 아는 IP 하나"의 포트만 스캔했다. 실제 점검은 그 앞 단계, 즉
**대역 안에 어떤 호스트가 살아 있는지**부터 시작한다.

netscan은 스캔을 두 단계로 나눈다.

```
1단계 호스트 발견:  --icmp / --arp  → IP 기준으로 결과 병합
                    -Pn → 발견을 건너뛰고 대상 전체를 그대로 넘김
2단계 포트 스캔:    --tcp / --udp   → 발견된 호스트 × 포트 조합을 스레드 풀로 스캔
                    열린 TCP 포트는 배너·HTTP Server 헤더·MySQL 버전 수집
```

각 단계를 만들며 마주친 문제(ARP flux, 리눅스 ICMP rate limit, 말하지 않는
서버)와 nmap·masscan은 같은 문제를 어떻게 다루는지도 함께 기록했다.

---

## 주요 기능

- **ICMP 호스트 발견**: Scapy `sr1()` + 스레드 풀 (3계층)
- **ARP 호스트 발견**: Scapy `srp()` 일괄 전송 (2계층, 로컬 세그먼트 전용)
- **발견 건너뛰기 (`-Pn`)**: ICMP·ARP에 응답하지 않는 호스트도 포트 스캔
- **TCP Connect 스캔**: OPEN / CLOSED / FILTERED, root 불필요
- **UDP 스캔**: OPEN / CLOSED / OPEN|FILTERED / FILTERED, root 불필요
- **UDP 정확도 (`--udp-delay`)**: 호스트별 송신 간격으로 ICMP rate limit 대응
- **서비스 식별**: 서버가 먼저 보내는 배너, 무응답이면 HTTP `Server` 헤더, MySQL 핸드셰이크에서 버전 추출
- **입력 검증**: 대상(CIDR/단일 IP)·포트·작업자 수·timeout을 스캔 전에 거절 (fail fast)

---

## 설치 및 사용법

### 요구 사항

- Python 3.8+
- Scapy (`pip install scapy`, ICMP·ARP 발견에만 사용)
- ICMP·ARP 발견은 raw 소켓을 쓰므로 **root 필요**. 포트 스캔(`-Pn --tcp/--udp`)은 커널 소켓만 쓰므로 root 불필요

### 사용 예

```bash
# 로컬 대역을 ARP로 발견한 뒤 TCP 1-1000 스캔
sudo python3 netscan.py -n 192.168.0.0/24 -i eth1 --arp --tcp

# ICMP와 ARP를 함께 써서 발견 결과를 병합
sudo python3 netscan.py -n 192.168.0.0/24 -i eth1 --icmp --arp

# 발견 없이 단일 호스트의 특정 TCP 포트 (root 불필요)
python3 netscan.py -n 192.168.0.5 -Pn --tcp -p 22,80,3306,8080

# UDP 1-100, 호스트당 1초 간격 (기본값)
python3 netscan.py -n 192.168.0.5 -Pn --udp -u 1-100

# 도움말
python3 netscan.py -h
```

### 옵션

| 옵션 | 설명 | 기본값 |
|------|------|--------|
| `-n`, `--network` | 대상. 대역(`192.168.0.0/24`) 또는 단일 IP (필수) | — |
| `-i`, `--iface` | 송신 인터페이스 (ARP에 필요) | — |
| `-v`, `--verbose` | Scapy 내부 경고 출력 | 끔 |
| **1단계: 호스트 발견** | | |
| `--icmp` / `--arp` | 발견 방식 (함께 쓰면 병합) | — |
| `-Pn`, `--skip-discovery` | 발견 생략, 대상 전체를 포트 스캔 | 끔 |
| `-t`, `--timeout` | ICMP·ARP 응답 대기(초) | `2` |
| `--icmp-workers` | ICMP 동시 작업자 수 | `50` |
| **2단계: 포트 스캔** | | |
| `--tcp` / `--udp` | 포트 스캔 방식 | — |
| `-p`, `--tcp-ports` | TCP 포트 (`--ports`도 가능) | `1-1000` |
| `-u`, `--udp-ports` | UDP 포트 | `53,67,68,69,123,137,161,500,514,1900,5353` |
| `--tcp-workers` / `--udp-workers` | 동시 작업자 수 | `100` / `20` |
| `--tcp-timeout` / `--udp-timeout` | 포트당 응답 대기(초) | `1` / `2` |
| `--udp-delay` | 같은 호스트로 보내는 UDP 프로브 간격(초), `0`이면 간격 없음 | `1` |

---

## 동작 원리

### 1. 호스트 발견: ARP가 ICMP보다 정확하다

| | ICMP | ARP |
|---|---|---|
| 계층 | 3계층 (`sr1()`) | 2계층 (`srp()`) |
| 동시성 | 스레드 풀 (`sr1()`이 블로킹) | 없음 (`srp()`가 이미 일괄 처리) |
| 방화벽 | 막을 수 있음 | 막을 수 없음 (ARP에 답하지 않으면 로컬 통신 불가) |
| 범위 | 라우팅되는 곳 어디든 | 같은 2계층 세그먼트만 |

로컬에서 ICMP를 보내도 Scapy는 목적지 MAC을 얻으려고 **ARP를 먼저** 보낸다.
그래서 로컬 ICMP는 ARP 위에 얹혀 동작하고, ARP보다 정확할 수 없다
(실측: /24 대역 ICMP 18.4초, ARP 2.1초).

**2계층 전송은 라우팅을 거치지 않는다.** `srp()`에 인터페이스를 지정하지
않으면 기본 인터페이스로 나가 엉뚱한 세그먼트를 스캔한다. 멀티홈 환경에서
`-i`를 빼면 3대 대신 1대만 발견됐고, 같은 IP의 MAC이 다르게 나왔다.
원인은 리눅스의 weak host model(**ARP flux**): 요청이 들어온 인터페이스의
MAC으로 응답한다. 틀린 MAC이 아니라 "다른 링크의 MAC"이며,
tcpdump로 경로를 확인하고서야 드러났다.

### 2. TCP Connect 스캔

```
connect_ex() == 0             → OPEN      (SYN-ACK)
connect_ex() == ECONNREFUSED  → CLOSED    (RST)
그 외 (timeout 등)            → FILTERED  (무응답)
```

FILTERED가 가장 비싸다. 응답이 없으니 timeout을 꽉 채워 기다린다.
방화벽이 스캔을 느리게 만드는 이유다.

### 3. UDP 스캔과 ICMP rate limit

UDP에는 "거절" 신호가 없다. 닫힌 포트는 상대 커널이 보내는
**ICMP Port Unreachable**로만 알 수 있다. UDP 소켓에 `connect()`를 해 두면
커널이 이 ICMP를 `ConnectionRefusedError`로 전달해 주므로 root 없이 판정할 수 있다.

```
UDP 응답 수신            → OPEN
ConnectionRefusedError   → CLOSED         (ICMP Port Unreachable)
timeout                  → OPEN|FILTERED  (열린 포트도, 방화벽도 무응답)
그 외 OSError            → FILTERED       (다른 ICMP 오류)
```

문제는 **리눅스가 ICMP 오류를 상대 IP마다 제한**한다는 점이다.
상대 IP별로 최대 6장(`XRLIM_BURST_FACTOR`), `icmp_ratelimit`(1000ms)마다
1장씩 적립되는 토큰 버킷이다. 표가 없으면 ICMP를 만들지 않고 버린다.
그래서 닫힌 포트가 OPEN|FILTERED로 잘못 판정된다.

`--udp-delay`는 호스트마다 "다음에 보내도 되는 시각"을 예약해,
같은 호스트로는 1초 이상 간격을 두고 다른 호스트로는 병렬로 보낸다.
송신 간격과 응답 대기가 분리되어, 한 프로브가 timeout을 기다리는 동안에도
다음 프로브는 1초 뒤에 나간다. 작업 순서도 포트 우선 `(p1,h1)(p1,h2)…`으로
넣어 동시에 도는 작업이 여러 호스트로 흩어지게 했다.

실측 (리눅스 대상, 닫힌 포트 30개):

| 설정 | 결과 | 시간 |
|---|---|---|
| `--udp-delay 0` | CLOSED 8 / OPEN\|FILTERED 22 | 4.0초 |
| `--udp-delay 1` (기본) | **CLOSED 30** (2회 반복 동일) | 29.0초 |

CLOSED 8은 버킷 6장 + 4초 동안 적립된 1~2장이다. 커널 상수가 결과 숫자로
그대로 보인다. 작업자를 1개로 줄여도 해결되지 않았다. 닫힌 포트는 ICMP가 즉시
돌아와 다음 프로브가 바로 나가기 때문이다. **정확도를 결정하는 건 작업자 수가
아니라 한 호스트로 보내는 간격**이다.

### 4. 발견 건너뛰기 (`-Pn`)

발견 단계는 **필터**다. 여기서 빠진 호스트는 포트 스캔도 하지 않는다.
macOS 은폐 모드는 ping에 답하지 않고 닫힌 포트에 RST도 보내지 않지만,
실제 서비스 중인 포트는 연결을 받는다. ICMP 발견만 했다면 이 호스트의
열린 포트 2개를 놓쳤다.

`-Pn`이어도 ARP는 일어난다. `connect()`가 SYN을 보내려면 목적지 MAC이 필요해서
**커널이 자동으로 ARP**를 하기 때문이다. 다만 결과를 프로그램에 알려 주지 않으므로,
없는 호스트도 FILTERED로 보인다. TCP Connect만으로는 "방화벽 차단"과
"호스트 없음"을 구분할 수 없다.

### 5. 서비스 식별

포트 번호로 붙인 이름은 관례일 뿐이다. 서버가 직접 밝힌 값이 증거다.

| 단계 | 방법 | 실측 예 |
|---|---|---|
| 서버가 먼저 말함 | 배너를 그대로 수집 | `SSH-2.0-...` |
| MySQL 핸드셰이크 | 프로토콜 버전(10)과 길이 필드를 확인한 뒤 첫 NUL까지 추출 | `MySQL 8.0.46` |
| 무응답 | `HEAD / HTTP/1.0` 전송 후 `Server` 헤더 | `nginx/1.31.1`, `Apache/2.4.67 (Debian)` |

HTTP는 **포트 번호가 아니라 침묵**을 보고 시도한다. 그래서 비표준 포트의
웹 서비스도 식별된다. 위의 macOS 호스트에서 이름표가 `unknown`이던 5000·7000번은
`AirTunes/980.77.5`(AirPlay 수신기, HTTP·RTSP 기반)로 드러났다.
8080번의 이름표는 `HTTP-Proxy`였지만 실제로는 Apache였다.

MySQL 배너가 `J8.0.46K...`처럼 깨져 보였던 이유도 구조로 설명된다.
맨 앞 `J`(0x4A = 74)는 글자가 아니라 패킷 길이 필드이고, 뒤의 깨진 문자는
인증용 난수(salt)다.

---

## 설계 결정

- **timeout 손잡이는 성격이 다른 곳에만 따로**: 발견(ICMP·ARP)은 `-t` 하나,
  포트 스캔은 TCP·UDP 따로. TCP는 닫힘이 RST로 즉시 오지만 UDP는 무응답이 정상
  결과라 기다리는 시간의 의미가 다르다
- **대상은 CIDR**: 단일 IP는 자동으로 `/32`. 마지막 옥텟만 받는 방식은 어느
  네트워크인지 알 수 없어 쓰지 않았다
- **동시성은 블로킹 지점에만**: `sr1()`·`connect()`는 블로킹이라 스레드 풀,
  `srp()`는 이미 일괄 처리라 스레드를 쓰지 않는다 (쓰면 pcap 소켓 경합으로 응답 유실)
- **기본값은 argparse 한 곳에만**: 함수 인자에는 기본값을 두지 않아
  "기본값이 무엇인가"에 답이 하나만 있게 했다

---

## nmap·masscan과 비교

| 주제 | netscan | nmap | masscan |
|---|---|---|---|
| 발견 생략 | `-Pn` | `-Pn` | 발견 단계 없음 |
| UDP rate limit | 고정 간격 `--udp-delay` | 응답 누락을 보고 간격 자동 증가 (`--scan-delay`, `--max-scan-delay`) | 속도 우선, 닫힘 판정 포기 |
| timeout | 단계·프로토콜별 고정값 | 측정한 RTT로 자동 조절 | `--wait` 하나 |
| 서비스 식별 | 배너 + HTTP + MySQL | `nmap-service-probes` 지문 DB | 배너 일부 |

---

## 한계 및 향후 개선

- **UDP 프로토콜별 프로브가 적음**: DNS(53)·NTP(123)만 서비스가 이해하는 데이터를 보낸다.
  나머지는 빈 데이터그램이라 열린 포트도 대답하지 않아 OPEN|FILTERED로 남는다
  (예: 리눅스 대상의 mDNS 5353)
- **UDP는 느리다**: 정확도를 위해 호스트당 초당 1포트. 한 호스트 1000포트면 약 17분
- **Connect 스캔은 은밀하지 않다**: 연결을 완성하므로 대상 로그에 남는다
- **HTTPS 미지원**: TLS 위의 HTTP는 `Server` 헤더를 읽지 못한다
- **결과 저장 없음**: 화면 출력만 지원

---

## 라이선스

이 저장소 정책에 따라 **GPL v2**를 따른다. (최상위 [LICENSE](../LICENSE) 참고)

## 면책

이 도구는 학습 및 **본인 소유·허가받은 환경에서의 테스트** 목적으로만
사용해야 한다. 허가 없는 스캔은 법적 책임을 물을 수 있다.

---

**Author**: Benorm
