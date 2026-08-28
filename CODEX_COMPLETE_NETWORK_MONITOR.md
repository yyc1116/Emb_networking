# Codex Task: Complete the Raspberry Pi Network Monitor / Alert Prototype

## 0. 你的角色

你是這個專案的 Embedded Linux / Networking pair programmer。

請直接在目前 repository 上完成專案，但要遵守以下開發方式：

- Codex 所在的外部環境**不一定有 Buildroot toolchain，也不一定能執行 AArch64 binary**。
- 真正 authoritative 的編譯環境是我的 Ubuntu VM。
- 真正 authoritative 的 runtime 環境是 Raspberry Pi 3 B+。
- 因此你可以在外部環境完成程式設計、重構、靜態檢查與可行的 host-side 檢查，但**不要假裝 target build 或 GPIO runtime 已驗證**。
- 每完成一個 milestone，都要給我 VM 中應執行的 cross-compile command，以及 Raspberry Pi 上的測試方法。
- 我會把 compiler/linker/runtime output 回傳給你；你要根據真實輸出繼續修到完成。

不要因為你無法直接進 VM 就停止工作。先把 repository 中能完成的部分做完，並把 target-specific verification 明確列出。

---

# 1. 專案目標

在 Raspberry Pi 3 B+ / Buildroot Linux 上實作一個：

> Protocol-aware Network Monitor + Rule-based Alert + GPIO LED + Simple Port Scan Detection

目前**不是完整 Firewall**，因為這一版以 `libpcap` 被動抓包，只能：

```text
observe
parse
classify
log
alert
trigger LED
```

不能真正：

```text
ACCEPT / DROP
```

不要偷偷改成 Netfilter、NFQUEUE、eBPF、XDP、nftables-only 或其他架構。

之後才可能把它演進成真正 Firewall / Router。

---

# 2. Target Environment

Target：

```text
Raspberry Pi 3 B+
AArch64 / ARM64
Buildroot Linux
```

已知 target 已包含：

```text
libpcap
tcpdump
```

Cross compiler 在 VM 中，路徑由我執行時提供，例如：

```bash
~/homework/buildroot/output/host/bin/aarch64-linux-gcc
```

不要把這個絕對路徑 hard-code 進 repository。

Build 應支援：

```bash
make CC=/path/to/aarch64-linux-gcc
```

目前 libpcap 採 dynamic linking。

---

# 3. Library / Header 使用原則

不要為了練習而重造已有 library。

## 應直接使用

### libpcap

使用：

```c
#include <pcap.h>
```

或 target 實際可用的等價 header。

使用 libpcap API 完成：

- interface capture
- capture loop
- packet callback
- pcap error handling

---

## Protocol headers

如果 Linux / libc 已提供合適且清楚的 protocol definitions，可以使用，例如：

```c
#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if_arp.h>
```

但使用前必須考慮：

- captured length
- IPv4 IHL
- TCP data offset
- alignment
- malformed / truncated packet
- network byte order

不要把 packet buffer 在未驗證長度與 alignment 的情況下無條件 cast 成任意 struct。

如果 system struct 在某個位置不適合安全解析，可以用：

```text
memcpy into a local aligned struct
```

或明確 byte parsing。

不要為了「自己寫 header」而重新定義整套 TCP/IP protocol。

---

## 自己的 `.h` 應該用來定義專案介面

例如：

```text
capture.h
parser.h
packet_info.h
rules.h
logger.h
gpio_led.h
scan_detector.h
```

它們定義的是：

- 我們自己的 function interface
- `PacketInfo`
- rule/action types
- logger API
- GPIO abstraction
- scan detector state

而不是取代 libpcap 或 Linux networking headers。

---

# 4. 目標 Architecture

```text
Network Interface
       │
       ▼
    libpcap
       │
       ▼
  Packet Parser
       │
       ├── Ethernet
       ├── ARP
       └── IPv4
             ├── ICMP
             ├── TCP
             └── UDP
       │
       ▼
   PacketInfo
       │
       ├──────────────► Scan Detector
       │                    │
       ▼                    ▼
   Rule Engine          ALERT Event
       │                    │
       └─────────┬──────────┘
                 ▼
             Event Layer
          ┌──────┼─────────┐
          ▼      ▼         ▼
       Terminal  Log      LED
```

重點：

> Parser 只負責「這是什麼封包」；Rule Engine / Scan Detector 才負責「要對它做什麼」。

---

# 5. CLI

程式名稱暫定：

```text
netmon
```

至少支援：

```bash
netmon -i <interface>
```

建議完整 CLI：

```bash
netmon \
  -i eth0 \
  -l /var/log/netmon.log \
  --scan-window 10 \
  --scan-threshold 20
```

GPIO 完成後加入類似：

```bash
--gpio-chip /dev/gpiochip0
--gpio-line <line-number>
--no-led
```

GPIO line 不可以 hard-code 成你猜測的 Raspberry Pi pin。

如果未提供 GPIO 或 GPIO init 失敗，程式應可以依合理 policy：

- 明確報錯後退出；或
- 在 `--no-led` 模式正常執行

請選擇清楚、一致的行為並寫入 README。

---

# 6. Milestone 1 — Stable libpcap Capture

完成：

- 指定 interface
- `pcap_open_live()`
- continuous capture
- callback
- 顯示 capture length / packet length（debug 階段即可）
- Ctrl+C clean shutdown
- `pcap_close()`
- 清楚的 error handling

不要把 interface 寫死為：

```text
eth0
```

所有 packet parsing 都以：

```text
pcap_pkthdr.caplen
```

作為真正可安全讀取的 buffer 長度。

---

# 7. Milestone 2 — Ethernet / ARP

## Ethernet

解析：

```text
source MAC
destination MAC
EtherType
```

辨識：

```text
0x0800 -> IPv4
0x0806 -> ARP
0x86DD -> IPv6
```

IPv6 第一版只需辨識並輸出：

```text
[IPv6] packet observed
```

不必完整解析。

---

## ARP

至少辨識：

```text
ARP Request
ARP Reply
```

輸出：

```text
[ARP] REQUEST 192.168.1.20 asks for 192.168.1.1
```

或：

```text
[ARP] REPLY 192.168.1.1 is-at aa:bb:cc:dd:ee:ff
```

ARP 預設：

```text
Terminal: INFO
Log: YES
LED: NO
```

---

# 8. Milestone 3 — IPv4

解析：

```text
version
IHL
total length
source IP
destination IP
protocol
```

必須正確處理：

```text
IHL != 5
```

也就是 IPv4 header 不可以永遠假設 20 bytes。

辨識：

```text
1  -> ICMP
6  -> TCP
17 -> UDP
```

其他 protocol：

```text
[IPv4] protocol=<number>
```

可以記錄，但不需深入解析。

---

# 9. Milestone 4 — ICMP / TCP / UDP

## ICMP

至少辨識：

```text
Echo Request
Echo Reply
```

輸出：

```text
[ICMP] Echo Request 192.168.1.10 -> 192.168.1.20
```

預設行為：

```text
Echo Request:
    Terminal: INFO
    Log: YES
    LED: one short pulse

Echo Reply:
    Terminal: INFO
    Log: YES
    LED: NO
```

---

## TCP

至少解析：

```text
source port
destination port
sequence number
acknowledgment number
TCP header length
flags
```

至少顯示：

```text
SYN
ACK
FIN
RST
```

必要時可顯示組合，例如：

```text
SYN,ACK
FIN,ACK
```

輸出：

```text
[TCP] 192.168.1.10:51234 -> 192.168.1.20:22 FLAGS=SYN SERVICE_HINT=SSH
```

---

## UDP

解析：

```text
source port
destination port
length
```

輸出：

```text
[UDP] 192.168.1.10:53122 -> 8.8.8.8:53 SERVICE_HINT=DNS
```

---

# 10. Service Hint

只做 common-port hint，不做 Deep Packet Inspection。

至少：

```text
TCP 22      -> SSH
TCP 80      -> HTTP
TCP 443     -> HTTPS

UDP 53      -> DNS
UDP 67      -> DHCP
UDP 68      -> DHCP
```

必須使用：

```text
SERVICE_HINT
```

不要宣稱：

```text
port 443 == HTTPS
```

因為 port number 只是常見服務慣例。

---

# 11. PacketInfo

Parser 完成後，把解析結果放進 project-owned data structure。

概念可以是：

```c
typedef struct {
    bool has_ethernet;
    uint8_t src_mac[6];
    uint8_t dst_mac[6];
    uint16_t ether_type;

    bool has_ipv4;
    uint32_t src_ipv4;
    uint32_t dst_ipv4;
    uint8_t ip_protocol;

    bool has_ports;
    uint16_t src_port;
    uint16_t dst_port;

    bool has_tcp;
    uint8_t tcp_flags;

    size_t captured_length;
    size_t wire_length;
} PacketInfo;
```

這只是方向。

請根據 codebase 做合理設計。

避免一個 struct 塞進大量沒有語意的 magic values。

---

# 12. Milestone 5 — Logger

需要兩種輸出：

## Terminal

可讀性優先。

例如：

```text
[INFO ] ARP REQUEST 192.168.1.20 asks for 192.168.1.1
[INFO ] UDP 192.168.1.10:53122 -> 8.8.8.8:53 SERVICE_HINT=DNS
[ALERT] TCP 192.168.1.50:51544 -> 192.168.1.20:22 FLAGS=SYN SERVICE_HINT=SSH
```

---

## Log File

預設：

```text
/var/log/netmon.log
```

但允許 CLI 改路徑。

格式要適合：

```text
grep
awk
shell scripts
```

例如：

```text
2026-08-28T09:30:21+08:00 INFO UDP SRC=192.168.1.10 SPORT=53122 DST=8.8.8.8 DPORT=53 SERVICE_HINT=DNS
```

不要把第一版做成 database。

---

# 13. Milestone 6 — Rule Engine

Parser 不直接控制 LED，也不直接決定 ALERT。

Rule Engine 接收：

```text
PacketInfo
```

輸出：

```text
Event / Actions
```

第一版 action：

```text
PRINT
LOG
ALERT
LED_SHORT
LED_LONG
LED_RAPID
```

或語意等價的設計。

---

# 14. 第一版固定 Rules

請先實作以下預設 policy。

## Rule A — ARP

```text
任何 ARP Request / Reply
```

行為：

```text
Terminal = INFO
Log      = YES
LED      = OFF
```

---

## Rule B — Normal TCP / UDP

一般 TCP / UDP：

```text
Terminal = INFO
Log      = YES
LED      = OFF
```

---

## Rule C — ICMP Echo Request

```text
ICMP Echo Request
```

行為：

```text
Terminal = INFO
Log      = YES
LED      = SHORT
```

LED pattern：

```text
ON  100 ms
OFF
```

---

## Rule D — SSH Connection Attempt

條件：

```text
TCP
destination port = 22
SYN = 1
ACK = 0
```

也就是典型 initial TCP SYN。

行為：

```text
Terminal = ALERT
Log      = YES
LED      = LONG
```

LED pattern：

```text
ON  500 ms
OFF
```

輸出：

```text
[ALERT] SSH connection attempt SRC=... SPORT=... DST=... DPORT=22
```

---

## Rule E — DNS

```text
UDP destination port 53
```

行為：

```text
Terminal = INFO
Log      = YES
LED      = OFF
SERVICE_HINT = DNS
```

---

# 15. LED 實作要求

優先使用：

```text
libgpiod
```

不要優先使用 deprecated：

```text
/sys/class/gpio
```

GPIO code 必須與 networking code 分離，例如：

```text
gpio_led.c
gpio_led.h
```

提供類似：

```text
led_init()
led_short()
led_long()
led_rapid()
led_shutdown()
```

但 API 可以依實作調整。

## 重要：LED 不可以阻塞 packet capture callback

不要在 libpcap callback 裡直接：

```c
sleep(...)
usleep(500000)
```

因為這會讓 packet processing 卡住。

請讓 LED event 使用：

- dedicated worker thread；或
- non-blocking timer/event mechanism；或
- 其他簡單但不阻塞 capture loop 的方式

第一版不需要複雜 thread pool。

一個小型 LED worker 即可。

如果 GPIO 尚未在 Buildroot 啟用：

1. networking monitor 仍應可用 `--no-led` 編譯/執行；
2. 告訴我 Buildroot 需要啟用的 libgpiod package；
3. GPIO support 可以用 build option 控制。

例如：

```bash
make ENABLE_GPIO=0
make ENABLE_GPIO=1
```

具體 Makefile 設計由你決定。

---

# 16. Milestone 7 — Simple Port Scan Detection

實作一個簡單 stateful IDS rule。

只關注：

```text
TCP initial SYN
```

也就是：

```text
SYN=1
ACK=0
```

依 source IPv4 address 維護近期狀態。

初始 detection policy：

```text
window = 10 seconds
threshold = 20 unique destination ports
```

當同一 source IP 在 10 秒內碰到至少 20 個不同 destination TCP ports：

```text
[ALERT] Possible port scan SRC=192.168.1.100 UNIQUE_PORTS=20 WINDOW=10s
```

行為：

```text
Terminal = ALERT
Log      = YES
LED      = RAPID
```

LED rapid pattern：

```text
ON  100 ms
OFF 100 ms
ON  100 ms
OFF 100 ms
ON  100 ms
OFF
```

避免同一個 scan 每收到一個 packet 就無限重複 alert。

請設計合理 cooldown / one-alert-per-window 機制。

`window` 與 `threshold` 應可由 CLI 調整：

```bash
--scan-window 10
--scan-threshold 20
```

---

# 17. Malformed / Truncated Packet Safety

這是 mandatory requirement。

任何：

```c
packet + offset
```

前必須確認：

```text
caplen >= offset + required_size
```

不要只相信：

```text
IPv4 total length
UDP length
TCP data offset
```

因為 packet 可能：

- truncated
- malformed
- intentionally malicious

程式不可以因此：

```text
segmentation fault
out-of-bounds read
undefined behavior
```

遇到無法完整解析的封包，可以：

```text
skip
debug log
malformed counter
```

但不能 crash。

---

# 18. Endianness

所有 wire-format multi-byte fields 都要正確處理 network byte order。

使用：

```c
ntohs()
ntohl()
htons()
htonl()
```

或等價安全方式。

不要依賴 AArch64 是 little-endian 這件事。

---

# 19. Fragmentation

第一版不要求完整 IPv4 fragment reassembly。

如果 IPv4 是 fragment，而目前 fragment 不含足夠完整的 L4 header：

```text
不要硬解析 TCP/UDP
```

可以記錄：

```text
[IPv4] fragmented packet
```

README 中要說明這項限制。

---

# 20. Build System

如果 repo 現在沒有合理 build system，使用簡單 Makefile。

不要一開始導入複雜 CMake。

Makefile 不要 hard-code VM 路徑。

推薦：

```make
CC ?= gcc
CPPFLAGS ?=
CFLAGS ?= -O2 -Wall -Wextra -Wpedantic
LDFLAGS ?=
LDLIBS += -lpcap
```

target build 由我執行：

```bash
make clean
make CC=/path/to/aarch64-linux-gcc
```

GPIO enabled 時再加入正確的 `libgpiod` dependency。

不要把：

```text
/home/<user>/...
```

寫進 Makefile。

不要直接 link 某個絕對路徑 `.so`。

---

# 21. External Codex Environment 規則

如果 Codex 所在機器不是 Buildroot VM：

## 可以做

- inspect code
- edit code
- compile platform-independent modules if possible
- static reasoning
- warnings cleanup
- parser unit tests using synthetic buffers / saved packet data if方便
- README / Makefile development

## 不可以宣稱已驗證

除非真的執行過，否則不要說：

```text
AArch64 target build passed
GPIO works
libgpiod version compatible
Raspberry Pi runtime passed
```

請改成：

```text
target verification required
```

並給我確切 command。

---

# 22. Test Plan

每完成一個 milestone，提供：

```text
VM build command
Pi run command
traffic generation command
expected output
failure indicators
```

---

## Build

我會在 VM 執行類似：

```bash
make clean
make CC=~/homework/buildroot/output/host/bin/aarch64-linux-gcc
```

然後：

```bash
file netmon
readelf -d netmon | grep NEEDED
```

預期：

```text
AArch64 ELF
libpcap.so...
libc.so.6
```

GPIO 開啟後可能還會看到：

```text
libgpiod.so...
```

---

## ARP

例如：

```bash
arping <raspberry-pi-ip>
```

期待：

```text
[INFO] ARP ...
```

LED：

```text
OFF
```

---

## ICMP

```bash
ping <raspberry-pi-ip>
```

期待：

```text
[INFO] ICMP Echo Request ...
```

LED：

```text
100 ms short pulse
```

---

## SSH

```bash
ssh <raspberry-pi-ip>
```

期待 initial SYN：

```text
[ALERT] ... DPORT=22 ... SYN ...
```

LED：

```text
500 ms long pulse
```

注意完整 TCP connection 後續 ACK/data 不應每包都觸發長亮。

---

## DNS

產生 DNS query。

期待：

```text
[INFO] UDP ... DPORT=53 SERVICE_HINT=DNS
```

LED：

```text
OFF
```

---

## Port Scan

另一台 host：

```bash
nmap <raspberry-pi-ip>
```

期待 threshold 達到時：

```text
[ALERT] Possible port scan ...
```

LED：

```text
3 quick pulses
```

---

# 23. tcpdump / Wireshark 作為 Ground Truth

parser output 應與：

```text
tcpdump
Wireshark
```

交叉驗證。

如果：

```text
our parser
```

與：

```text
tcpdump / Wireshark
```

對相同 packet 顯示不同：

```text
IP
port
flags
protocol
```

請先檢查我們自己的 parser。

---

# 24. 建議 Source Layout

根據現有 repository 調整，不需要機械式照抄：

```text
src/
├── main.c
├── capture.c
├── parser.c
├── logger.c
├── rules.c
├── scan_detector.c
└── gpio_led.c

include/
├── capture.h
├── parser.h
├── packet_info.h
├── logger.h
├── rules.h
├── scan_detector.h
└── gpio_led.h
```

如果目前 project 很小，可以少拆。

原則：

```text
one responsibility per module
```

不要為了架構漂亮而過度工程化。

---

# 25. README

完成後 README 至少要包含：

- project purpose
- architecture
- what it can detect
- what it cannot do
- why this is not yet a real firewall
- dependencies
- build commands
- cross-compile commands
- runtime usage
- CLI options
- GPIO configuration
- LED meanings
- test commands
- known limitations
- future Netfilter / Router direction

---

# 26. 明確 Non-goals

目前不要做：

```text
real packet DROP
Netfilter firewall
NFQUEUE
nftables management
Router
NAT
DHCP server
DNS server
IP forwarding management
kernel module
eBPF
XDP
DPI
TLS decryption
full IDS signature engine
Web UI
database
cloud service
```

---

# 27. 最終預期行為摘要

## ARP

```text
看到
↓
terminal INFO
↓
write log
↓
LED 不亮
```

## 一般 TCP / UDP

```text
看到
↓
parse IP/port/flags
↓
show service hint if known
↓
terminal INFO
↓
write log
↓
LED 不亮
```

## ICMP Echo Request

```text
看到 ping request
↓
terminal INFO
↓
write log
↓
LED 短亮 100 ms
```

## SSH initial SYN

```text
TCP dst port 22
SYN=1 ACK=0
↓
terminal ALERT
↓
write log
↓
LED 長亮 500 ms
```

## DNS

```text
UDP dst port 53
↓
SERVICE_HINT=DNS
↓
terminal INFO
↓
write log
↓
LED 不亮
```

## Port Scan

```text
same source IP
+ TCP initial SYN
+ >=20 unique destination ports
+ within 10 seconds
↓
Possible Port Scan ALERT
↓
write log
↓
LED 快閃 3 次
```

---

# 28. 完成條件

專案完成時應達成：

1. 可以指定 capture interface。
2. libpcap 可以穩定抓包。
3. 可解析 Ethernet。
4. 可辨識 ARP。
5. 可解析 IPv4。
6. 可辨識 IPv6 frame。
7. 可解析 ICMP Echo Request / Reply。
8. 可解析 TCP ports / seq / ack / header length / flags。
9. 可解析 UDP ports / length。
10. 有 common service hint。
11. 有統一 PacketInfo。
12. parser 與 rule engine 分離。
13. terminal output 正常。
14. log file 正常。
15. ICMP 可以觸發 short LED。
16. SSH initial SYN 可以觸發 long LED。
17. port scan detector 可以觸發 rapid LED。
18. LED 不阻塞 packet capture。
19. malformed / truncated packet 不會 crash。
20. Ctrl+C clean shutdown。
21. Makefile 不 hard-code cross compiler。
22. 可以用 Buildroot cross compiler 編譯。
23. README 完整。
24. 明確說明目前不是實際 blocking firewall。

---

# 29. 立即開始執行

請現在直接：

1. inspect repository；
2. 找出現有 source / header / build files；
3. 理解目前 libpcap test 的 control flow；
4. 保留能用的現有程式；
5. 依上述 milestone 持續完成整個專案；
6. 能在外部環境驗證的就實際驗證；
7. 需要 Buildroot VM / Raspberry Pi 才能驗證的項目，列出精確 command；
8. 我回傳錯誤後直接修正，不要重新從頭設計；
9. 持續做到所有 completion criteria 都已實作，或只剩下必須由真實硬體驗證的項目。

不要一次 dump 一個完全脫離現有 repository 的新專案。

請以「現有 codebase → 小步修改 → 可編譯 → 可測試 → 下一步」的方式完成。
