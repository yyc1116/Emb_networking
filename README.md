# netmon

`netmon` 是一個跑在 Raspberry Pi 3 B+ / Buildroot Linux 上的被動式網路監控原型。它使用 `libpcap` 抓取封包，解析常見 L2/L3/L4 標頭，套用固定規則輸出 `INFO` / `ALERT`，寫入 log，並可透過 `libgpiod` 驅動 LED 與 TM1637 四位七段顯示器。

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
  -> optional display counters -> display worker -> TM1637

TCP initial SYN
  -> scan detector
  -> extra ALERT event
  -> immutable scan snapshot -> display worker (current window maximum)
```

模組分工：

- `src/main.c`: CLI、初始化、訊號處理、模組接線
- `src/capture.c`: `pcap_open_live()`、capture loop、`pcap_breakloop()`
- `src/parser.c`: Ethernet / ARP / IPv4 / ICMP / TCP / UDP 安全解析
- `src/rules.c`: 將 `PacketInfo` 轉成事件與 LED 動作
- `src/logger.c`: terminal 與 log file 格式化輸出
- `src/scan_detector.c`: 10 秒視窗內的 unique destination port 掃描偵測
- `src/gpio_led.c`: 非阻塞 LED worker，避免卡住 packet capture callback
- `src/display.c`: 累計數字、掃描快照交接、獨立顯示 worker 與固定輪播
- `src/tm1637.c`: libgpiod 1.x 開漏 GPIO、TM1637 通訊與數字段碼

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
make test-display
```

如果你只想先建出測試 binary、不執行它：

```bash
make test-parser-build
make test-display-build
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
- 所有版本使用 pthread；只有 `ENABLE_GPIO=1` 時需要 `libgpiod` 1.x（沿用既有 LED API，未遷移至 2.x）
- 切換 `ENABLE_GPIO`、編譯器或編譯旗標前，先執行 `make clean`
- `make test-parser` 會建置並執行 host-side synthetic parser safety test
- `make test-parser-build` 只建置測試程式，不執行
- `make test-display` 驗證數字、掃描視窗、SSH 去重、worker 交接、慢速輸出與失敗降級；使用模擬 GPIO，不需接實體顯示器
- `make test-display-build` 只建置顯示測試；測試使用 GNU linker 的 `--wrap` 注入時間與配置失敗

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
- `--display none|tm1637`: 預設 `none`，明確選擇 `tm1637` 才啟用顯示器
- `--display-clk <line>`、`--display-dio <line>`: TM1637 的 GPIO line offset，啟用時必填
- `--display-brightness <0..7>`: 亮度，預設 `3`

顯示器與 LED 共用 `--gpio-chip` 指定的 chip，但使用不同 line。CLK、DIO 必須不同，也不能與同時啟用的 LED line 衝突。`--no-led` 不會停用顯示器。

## TM1637 顯示行為

只顯示四位數字 `TCCC`，保留前導零，冒號及小數點關閉：

| 顯示 | 意義 | 例子 |
| --- | --- | --- |
| `1CCC` | 啟動後 ICMP Echo Request 累計 | `1004`：4 次 |
| `2CCC` | 啟動後 SSH initial SYN 規則事件累計 | `2002`：2 次 |
| `3CCC` | 當前 scan window 中，單一來源最多的 unique TCP destination ports | `3017`：17 個 |

- 啟動先顯示 `1000`，每約一秒固定輪播 `1 → 2 → 3`，不因事件插播。
- 當頁數值約每 100 ms 檢查更新；數字相同時不重複傳送。
- Type 1／2 不定期清零。內部保留累計值（到 `UINT64_MAX` 飽和），顯示最多為 `999`；程式重啟才歸零。
- Type 2 沿用原規則的 5 秒 SYN 重傳去重；相同來源／目的 IP、port 及 TCP sequence 的重傳會刷新去重時間，被降為 INFO 的事件不再加一。它不是每個原始 SYN 都計數，也不代表 SSH 登入成功次數。
- Type 3 是即時視窗狀態，不是累計告警次數。來源 A 有 8 個 port、B 有 12 個時顯示 `3012`，不加成 20。
- 每個 port 沿用「距離最後出現時間 **超過** `--scan-window` 秒才過期」的規則；重複 port 只刷新時間。觸發告警不清零，數量仍可繼續增加。
- 沒有新流量時，worker 仍會依快照時間排除過期 port；全部過期後顯示 `3000`。重新傳來的 SYN 可能延後歸零。

Capture 執行緒只更新計數、建立並發布最新的不可變掃描快照，不等待顯示器。快照包含按來源分組的 port 最後出現時間；worker 不碰正在修改的偵測器。快照透過原子交換交接，尚未取用的舊快照會被回收，不排隊累積。快照建立成本與目前追蹤 port 數成正比，這仍是小規模原型。

顯示初始化、快照配置或 GPIO／ACK 通訊失敗時，會警告並停用顯示器，監控、terminal、log 與 LED 繼續運作；不自動重試。所有 GPIO 通訊及延遲均在顯示 worker，正常退出時清空並關閉顯示。沒有接顯示器時使用預設 `--display none`。

### 接線範例：Pi 3 B+ 與四位 TM1637

以下 GPIO 編號是 BCM／gpiochip line offset，**不是實體針腳編號**。先以目標機的 GPIO 資訊確認 chip 與 line 對應。

| 訊號 | Pi GPIO | Pi 實體針腳 | 連接方式 |
| --- | --- | --- | --- |
| CLK | GPIO27 | 13 | 經雙向 3.3V↔5V 電位轉換器接模組 CLK |
| DIO | GPIO22 | 15 | 經雙向 3.3V↔5V 電位轉換器接模組 DIO |
| VCC | 5V 電源 | 2 或 4 | 模組 VCC 及轉換器高壓側 |
| 低壓參考 | 3.3V 電源 | 1 或 17 | 轉換器低壓側 |
| GND | GND | 6 | Pi、轉換器及模組共地 |
| LED（選用） | GPIO17 | 11 | 保留既有 LED 與限流電阻 |

使用適合開漏訊號的雙向轉換器，各側需有對應電壓的上拉。DIO 在 ACK 時會由 TM1637 拉低，不能用單向轉換器。這個基準接法依 TM1637 資料表的 5V 工作條件規劃；若實際模組支援 3.3V，需依該模組規格確認，不能假定所有模組相同。Pi 的 GPIO 為 3.3V 邏輯，不直接接到模組的 5V 上拉。

參考：[TM1637 資料表](https://m5stack.oss-cn-shenzhen.aliyuncs.com/resource/docs/datasheet/unit/digi_clock/TM1637.pdf)、[Raspberry Pi GPIO 電壓規格](https://www.raspberrypi.com/documentation/computers/raspberry-pi.html#voltage-specifications)。

只使用顯示器：

```bash
sudo ./netmon -i eth0 -l /tmp/netmon.log --no-led \
  --display tm1637 --display-clk 27 --display-dio 22 --display-brightness 3
```

同時保留 LED：

```bash
sudo ./netmon -i eth0 -l /tmp/netmon.log --gpio-line 17 \
  --display tm1637 --display-clk 27 --display-dio 22
```

### 展示與實機驗收

1. 確認啟動訊息有 `display=tm1637`，拍攝 `1000 → 2000 → 3000` 輪播。
2. 從 VM 執行 `ping -c 4 <pi-ip>`，在沒有其他 Echo Request 的情況下觀察 `1004`。
3. 執行 `ssh -o ConnectTimeout=3 <pi-ip>`，對照去重後的 ALERT 與 Type 2 增加；連線被拒絕也可產生 SYN 事件。
4. 在 scan window 內對多個 port 發送 SYN，對照 Type 3 增長與 `PORT_SCAN` log。掃描若包含 port 22，也可能增加 Type 2。
5. 停止測試流量，在最後一個 SYN 過期後確認 Type 3 回到 `3000`，Type 1／2 保留。
6. 同時啟用 LED，確認 SHORT／LONG／RAPID 保留；Ctrl+C 後確認顯示清空，重新啟動計數歸零。

建議旁邊放「1＝ICMP、2＝SSH、3＝掃描視窗」對照卡。收集 log 與 tcpdump 證據時可執行：

```bash
sh scripts/run_pi_evidence.sh -i eth0 --no-led \
  --display tm1637 --display-clk 27 --display-dio 22
```

腳本未提供 `--gpio-line` 時自動停用 LED，仍保留舊版 LED 執行方式及 `netmon_gpio_final.log` 檔名。模擬測試不能代替實際接線、電壓與 TM1637 畫面驗證；上述實機步驟需在 Pi 執行並保留證據後才能記為通過。

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

注意：若 `netmon` 是跑在 Pi 上，最穩定的 DNS 驗證方式是直接在 Pi 上執行 `nslookup`，或確認 DNS 封包真的會經過 Pi 正在監控的介面。

Expected：

- Echo Request 顯示 `ICMP Echo Request`
- Echo Reply 顯示 `ICMP Echo Reply`
- SSH initial SYN 顯示 `ALERT`
- UDP/53 顯示 `SERVICE_HINT=DNS`

Failure indicators：

- TCP flags 顯示錯誤
- DNS 沒有 hint
- SSH 同一次連線嘗試因 retransmission 被重複 alert

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

注意：需要讓整段掃描在 `--scan-window` 內完成，並且真的送到至少 20 個不同 destination ports，否則不會觸發 alert。

Expected：

- 同一來源在 10 秒內碰到至少 20 個不同 destination ports 時，出現一次 `Possible port scan`
- 不會每個 SYN 都重複 alert

Failure indicators：

- 少量連線就誤報
- 每個符合條件的後續封包都重複 alert

## 時間校正提醒

如果 Pi 的 `date` 顯示類似 `1970-01-01`，代表系統時間還沒同步。這不一定是 `netmon` 的邏輯錯誤，但會讓 log timestamp 失真，建議先校時再做最終驗證。

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
