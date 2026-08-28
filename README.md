# netmon

`netmon` 是一個跑在 Raspberry Pi 3 B+ / Buildroot Linux 上的被動式網路監控原型。它使用 `libpcap` 抓取封包，解析常見 L2/L3/L4 標頭，套用固定規則輸出 `INFO` / `ALERT`，寫入 log，並在可用時透過 `libgpiod` 驅動 LED 提示事件。

第一版的定位是：

- Protocol-aware Network Monitor
- Rule-based Alert
- Optional GPIO LED notifier
- Simple TCP port scan detection

它現在不是完整 firewall，因為這一版只做被動觀察與分類，不會真正 `ACCEPT` / `DROP` 封包。

## 架構

資料流如下：

```text
libpcap capture
  -> parser
  -> PacketInfo
  -> rules
  -> terminal/log event
  -> optional LED worker

TCP initial SYN
  -> scan detector
  -> extra ALERT event
```

模組分工：

- `src/main.c`: CLI、初始化、訊號處理、模組接線
- `src/capture.c`: `pcap_open_live()`、capture loop、`pcap_breakloop()`
- `src/parser.c`: Ethernet / ARP / IPv4 / ICMP / TCP / UDP 安全解析
- `src/rules.c`: 將 `PacketInfo` 轉成事件與 LED 動作
- `src/logger.c`: terminal 與 log file 格式化輸出
- `src/scan_detector.c`: 10 秒視窗內的 unique destination port 掃描偵測
- `src/gpio_led.c`: 非阻塞 LED worker，避免卡住 packet capture callback

## 可偵測內容

- ARP Request / Reply
- IPv4
- IPv6 frame observed
- ICMP Echo Request / Echo Reply
- TCP ports / flags / sequence / acknowledgment / header length
- UDP ports / length
- common-port `SERVICE_HINT`
  - TCP 22 -> SSH
  - TCP 80 -> HTTP
  - TCP 443 -> HTTPS
  - UDP 53 -> DNS
  - UDP 67 / 68 -> DHCP
- simple port scan
  - 同一個 source IPv4
  - 在 `--scan-window` 秒內
  - 對至少 `--scan-threshold` 個不同 TCP destination ports 發送 initial SYN

## 不做的事情

第一版明確 non-goals：

- 真正丟棄封包
- Netfilter / NFQUEUE / nftables 管理
- Router / NAT / DHCP server / DNS server
- eBPF / XDP / kernel module
- DPI / TLS decryption / 完整 IDS signature engine
- Web UI / database / cloud service

## 安全解析原則

- 任何 `packet + offset` 前都先檢查 `captured_length`
- 不盲信 IPv4 total length、UDP length、TCP data offset
- IPv4 IHL 不固定假設為 20 bytes
- IPv4 fragment 若目前 fragment 沒有完整 L4 header，不硬解析 TCP/UDP
- malformed / truncated packet 不應造成 crash

## Build

一般 Linux host：

```bash
make clean
make
make test-parser
```

指定交叉編譯器：

```bash
make clean
make CC=/path/to/aarch64-linux-gcc
```

啟用 GPIO：

```bash
make clean
make ENABLE_GPIO=1 CC=/path/to/aarch64-linux-gcc
```

Build 變數：

- `CC`
- `CPPFLAGS`
- `CFLAGS`
- `LDFLAGS`
- `ENABLE_GPIO=0|1`

注意：

- 不要把 VM 內的 cross compiler 絕對路徑 hard-code 進 Makefile
- `libpcap` 採 dynamic linking
- `ENABLE_GPIO=1` 時需要 `libgpiod`
- `make test-parser` 是 host-side synthetic parser safety test

## 執行方式

至少需要指定介面：

```bash
./netmon -i eth0
```

完整範例：

```bash
./netmon \
  -i eth0 \
  -l /var/log/netmon.log \
  --scan-window 10 \
  --scan-threshold 20 \
  --gpio-chip /dev/gpiochip0 \
  --gpio-line 17
```

停用 LED：

```bash
./netmon -i eth0 --no-led
```

CLI 選項：

- `-i <interface>`: 必填，抓包介面
- `-l <log_path>`: log 路徑，預設 `/var/log/netmon.log`
- `--scan-window <seconds>`: scan detection 時窗，預設 `10`
- `--scan-threshold <count>`: unique destination ports 門檻，預設 `20`
- `--gpio-chip <path>`: GPIO chip 路徑，預設 `/dev/gpiochip0`
- `--gpio-line <line>`: GPIO line number
- `--no-led`: 停用 LED

## LED 行為

- ICMP Echo Request -> `SHORT`
  - ON 100 ms
  - OFF
- SSH initial SYN -> `LONG`
  - ON 500 ms
  - OFF
- Port scan alert -> `RAPID`
  - ON 100 ms
  - OFF 100 ms
  - ON 100 ms
  - OFF 100 ms
  - ON 100 ms
  - OFF

LED 實作是非阻塞的：

- packet capture callback 只 enqueue event
- 不在 callback 中 `sleep()` / `usleep()`

如果 LED 被要求但目前條件不滿足，程式會明確警告並降級繼續執行，例如：

- 沒有提供 `--gpio-line`
- binary 沒有用 `ENABLE_GPIO=1` 編譯
- `libgpiod` 初始化失敗

## 輸出範例

Terminal：

```text
[INFO ] ARP REQUEST 192.168.1.20 asks for 192.168.1.1
[INFO ] ICMP Echo Request 192.168.1.10 -> 192.168.1.20
[ALERT] TCP 192.168.1.50:51544 -> 192.168.1.20:22 FLAGS=SYN SERVICE_HINT=SSH
[ALERT] Possible port scan SRC=192.168.1.100 UNIQUE_PORTS=20 WINDOW=10s
```

Log file：

```text
2026-08-28T09:30:21+08:00 INFO UDP SRC=192.168.1.10 SPORT=53122 DST=8.8.8.8 DPORT=53 LEN=48 SERVICE_HINT=DNS
2026-08-28T09:30:28+08:00 ALERT TCP SRC=192.168.1.50 SPORT=51544 DST=192.168.1.20 DPORT=22 FLAGS=SYN SEQ=1 ACKNUM=0 HLEN=20 SERVICE_HINT=SSH
```

## Milestone 驗證指令

以下命令是 target-specific verification。若你在 Ubuntu VM 或 Raspberry Pi 上跑出真實輸出，我可以再根據結果幫你補修。

### Milestone 1: Stable libpcap Capture

VM build：

```bash
make clean
make CC=~/homework/buildroot/output/host/bin/aarch64-linux-gcc
file netmon
readelf -d netmon | grep NEEDED
```

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
```

Traffic generation：

```bash
ping -c 2 <pi-ip>
```

Expected：

- 程式成功開啟介面並持續抓包
- `Ctrl+C` 可以乾淨停止
- `file netmon` 顯示 AArch64 ELF
- `readelf -d netmon | grep NEEDED` 至少看到 `libpcap.so` 與 `libc.so.6`

Failure indicators：

- `Failed to open interface`
- `pcap loop failed`
- `Ctrl+C` 無法停止

### Milestone 2: Ethernet / ARP

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
```

Traffic generation：

```bash
arping -c 2 -I eth0 <gateway-ip>
```

Expected：

- terminal 出現 `ARP REQUEST` 或 `ARP REPLY`
- log file 有 ARP 紀錄
- LED 不觸發

Failure indicators：

- 沒有任何 ARP 輸出
- ARP IP / MAC 欄位明顯錯誤

### Milestone 3: IPv4

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
```

Traffic generation：

```bash
ping -c 1 8.8.8.8
```

Expected：

- IPv4 封包被辨識
- ICMP / TCP / UDP 之外的 IPv4 protocol 至少能列印 `PROTOCOL=<number>`

Failure indicators：

- 所有 IPv4 都被當成 malformed
- IHL 不為 20 bytes 的封包導致 crash

### Milestone 4: ICMP / TCP / UDP

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
```

ICMP traffic：

```bash
ping -c 2 <pi-ip>
```

SSH traffic：

```bash
ssh <pi-ip>
```

DNS traffic：

```bash
nslookup openai.com 8.8.8.8
```

Expected：

- Echo Request 顯示 `ICMP Echo Request`
- Echo Reply 顯示 `ICMP Echo Reply`
- SSH initial SYN 顯示 `ALERT`
- UDP/53 顯示 `SERVICE_HINT=DNS`

Failure indicators：

- TCP flags 顯示錯誤
- DNS 沒有 hint
- SSH 不是只有 initial SYN 被提升成 alert

### Milestone 5: Logger

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
tail -f /tmp/netmon.log
```

Expected：

- terminal 為可讀格式
- log line 可用 `grep` / `awk` 處理
- timestamp 為 ISO-8601 風格含 timezone

Failure indicators：

- log 沒有 flush
- log 欄位缺漏過多，不易以 shell 處理

### Milestone 6: Rule Engine

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log
```

Expected：

- parser 只負責解析，不直接決定 LED 或 ALERT
- ARP / normal TCP / normal UDP -> `INFO`
- ICMP Echo Request -> `INFO` + short LED action
- SSH initial SYN -> `ALERT` + long LED action

Failure indicators：

- parser 直接內嵌 UI / GPIO 邏輯
- 規則判斷互相混在 parser 裡

### Milestone 7: Port Scan Detection

Pi run：

```bash
sudo ./netmon -i eth0 --no-led -l /tmp/netmon.log --scan-window 10 --scan-threshold 20
```

Traffic generation：

```bash
for p in $(seq 1 25); do
  nc -zv <pi-ip> "$p"
done
```

Expected：

- 同一來源在 10 秒內碰到至少 20 個不同 destination ports 時，出現一次 `Possible port scan`
- 不會每個 SYN 都重複 alert

Failure indicators：

- 少量連線就誤報
- 每個符合條件的後續封包都重複 alert

## Ground Truth 對照

可使用：

```bash
tcpdump -ni eth0 -vv
```

或把封包抓下來用 Wireshark 對照：

```bash
sudo tcpdump -ni eth0 -w capture.pcap
```

建議對照欄位：

- Ethernet MAC
- EtherType
- ARP opcode / sender / target
- IPv4 src/dst / protocol / IHL / fragmentation
- TCP ports / flags / seq / ack / header length
- UDP ports / length

## 已知限制

- 不做 IPv4 fragment reassembly
- IPv6 第一版只辨識 observed，不做深入解析
- `SERVICE_HINT` 是 common-port hint，不代表真實應用層協定已被確認
- 未在這個外部環境宣稱完成 AArch64 target build、GPIO runtime、或 Raspberry Pi 真機驗證

## 下一步方向

如果之後要演進成真正 firewall / router，比較合理的方向會是：

- Netfilter / NFQUEUE 整合
- 封包決策與真正 `ACCEPT` / `DROP`
- 狀態追蹤與更完整的 IDS policy
- Router / NAT / forwarding 管理
