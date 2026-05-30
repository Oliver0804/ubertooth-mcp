# ubertooth-mcp 使用說明

把 Ubertooth One 透過 MCP 開放給 Claude Code 等 LLM agent，做 2.4GHz 藍牙研究：
BLE 嗅探、Bluetooth Classic（BR/EDR）探索/跟隨、AFH 跳頻圖譜、頻譜掃描。

> ⚠️ 只嗅探你有權限的流量。本工具用於資安研究、除錯自己的裝置與授權測試。

---

## 1. 前置需求

| 項目 | 說明 |
|------|------|
| Ubertooth One | 接上 USB（驗證於韌體 `2020-12-R1`, API 1.07） |
| `ubertooth-*` host 工具 | 在 PATH 上，或用 `UBERTOOTH_BIN_DIR` 指向其所在目錄 |
| `tshark`（選用） | 只有 pcap 解碼工具（`pcap_summary` 等）需要 |
| Python | ≥ 3.10 |

本機編好的 binary 在 `/Users/oliver/code/goodtools/.deps/bin`，venv 在 repo 內 `.venv`。

---

## 2. 註冊到 Claude Code

```bash
claude mcp add ubertooth -s user \
  -e UBERTOOTH_BIN_DIR=/Users/oliver/code/goodtools/.deps/bin \
  -- /Users/oliver/code/goodtools/ubertooth-mcp/.venv/bin/ubertooth-mcp
```

確認：

```bash
claude mcp get ubertooth     # 應顯示 ✓ Connected
```

移除：`claude mcp remove ubertooth -s user`

---

## 3. 核心概念：擷取是「session」

會持續跑的嗅探工具（`ble_sniff_start` / `classic_sniff_start` / `raw_dump_start`）採
**背景 session 模型，一次只能跑一個**：

```
ble_sniff_start(...)   → 回傳 session id，背景開始擷取，立即返回
capture_status()       → 輪詢：已擷取 bytes、log 尾巴、是否還在跑
capture_stop()         → 送 SIGINT 讓工具優雅關射頻、寫完整 pcap，回傳檔案路徑
pcap_summary(<id>)     → 用 tshark 解碼
```

`capture_stop` 用 **SIGINT 而非 SIGKILL**，這樣 pcap trailer 才會被寫完整。
擷取檔存在 `~/.ubertooth-mcp/captures/`，檔名即 session id。

而 `device_status` / `read_registers` / `spectrum_scan` / `afh_map` 是**同步**的（跑完直接回結果），擷取進行中呼叫它們會被擋下（裝置一次只能被一個操作佔用）。

---

## 4. 工具總覽

### 板子管理
| 工具 | 參數 | 用途 |
|------|------|------|
| `device_status` | — | 韌體/API 版本、序號、part id、偵測到幾顆 |
| `reset_device` | — | 完整重置（之後會在 USB 重新列舉） |
| `identify` | — | 閃所有 LED 以實體定位板子 |
| `read_registers` | `start=0, end=15` | 讀 CC2400 射頻暫存器（已解碼成人類可讀） |

### 頻譜（同步）
| 工具 | 參數 | 用途 |
|------|------|------|
| `spectrum_scan` | `duration_seconds=4, low_freq=2402, high_freq=2480` | 掃 2.4GHz，回傳每頻率峰值 RSSI、最強峰值、WiFi ch1/6/11 壅塞度 |

### BLE 嗅探（session）
| 工具 | 參數 | 用途 |
|------|------|------|
| `ble_sniff_start` | `mode, target_mac, adv_channel` | `mode`：`advertising`(只看廣播) / `follow`(跟隨連線) / `promiscuous`(嗅探既有連線)。`target_mac` 鎖定單一裝置；`adv_channel` 37/38/39 |

### Bluetooth Classic / BR-EDR（session）
| 工具 | 參數 | 用途 |
|------|------|------|
| `classic_sniff_start` | `lap, uap, channel, survey=True` | 無 LAP+survey → 探索所有 piconet；只給 lap → 推算 uap；lap+uap → 跟隨跳頻解碼 |

### 其他
| 工具 | 參數 | 用途 |
|------|------|------|
| `raw_dump_start` | `modulation=le\|classic` | 擷取原始位元/符號流到 .bin（低階） |
| `afh_map` | `lap, uap, duration_seconds=15` | 偵測某 piconet 的 AFH 跳頻圖譜 |
| `capture_status` / `capture_stop` / `list_captures` | — | 管理當前 session |
| `pcap_summary` | `id_or_path` | BLE 封包數、PDU 型別統計、廣播者排行 |
| `ble_advertisers` | `id_or_path` | 唯一廣播者清單（含 company id / 名稱） |
| `dissect_packets` | `id_or_path, display_filter, limit=100` | 逐包記錄，可帶 Wireshark display filter |

---

## 5. 常見工作流程（直接跟 Claude 說即可）

### A. 看看附近有哪些 BLE 裝置
> 「用 ubertooth 嗅探 BLE 廣播 10 秒，然後列出唯一的廣播者」

Claude 會：`ble_sniff_start(mode="advertising")` → 等 → `capture_stop()` → `ble_advertisers(<id>)`

### B. 跟隨某個 BLE 裝置的連線
> 「跟隨 MAC 22:44:66:88:aa:cc 的 BLE 連線，我等下會讓它重新連線」

Claude：`ble_sniff_start(mode="follow", target_mac="22:44:66:88:aa:cc")` → 你觸發裝置重新連線（重開 App / 關開藍牙）→ `capture_status()` 確認抓到 → `capture_stop()` → `dissect_packets(<id>)`

> 一顆 Ubertooth 一次只聽一個廣播通道，CONNECT_IND 可能在別的通道發生而漏抓 —— 換 `adv_channel=38/39` 多試幾次很正常。

### C. 探索 Bluetooth Classic piconet
> 「用 survey 模式掃 Classic 藍牙 20 秒，找出有哪些 piconet」

Claude：`classic_sniff_start(survey=True)` → 等 → `capture_stop()`，從 log 看 LAP/UAP。
拿到 LAP/UAP 後可 `afh_map(lap, uap)` 取跳頻圖譜。

### D. 看 2.4GHz 頻譜壅塞
> 「掃一下 2.4GHz 頻譜，看 WiFi 哪個通道最忙」

Claude：`spectrum_scan(duration_seconds=5)`（同步，直接回峰值與 WiFi 通道壅塞度）

---

## 6. 限制

- 單顆 Ubertooth **一次只聽一個 BLE 廣播通道**（37/38/39）→ 連線建立的 CONNECT_IND 可能漏抓，重試正常。
- **加密**連線只能抓到密文，除非同時抓到配對過程或已有金鑰。
- 最穩定的是 **BLE 4.x / 1M PHY**；BLE 5 的 2M/Coded PHY 與 CSA #2 支援有限。
- **macOS** 上 `ubertooth-scan` / `ubertooth-follow` 無法使用（需 Linux BlueZ）。

---

## 7. 疑難排解

| 症狀 | 處理 |
|------|------|
| `ubertooth-util not found` | 設 `UBERTOOTH_BIN_DIR` 指向 binary 目錄，或加進 PATH |
| `a capture is running...` | 先 `capture_stop()` 再做同步操作 |
| 同步工具報 libusb 錯誤 | 多半是裝置正被別的擷取佔用，或被別的程式抓住；`capture_stop()` 或拔插 |
| `tshark not found` | `brew install wireshark`（只影響解碼工具） |
| pcap 是空的 | 確認用 `capture_stop()`（SIGINT）而非直接砍程序；該頻段當下沒流量也會是空的 |
| dylib 載入失敗 | binary 的 rpath 沒指到 lib；MCP 已自動補 `DYLD_FALLBACK_LIBRARY_PATH=<bin>/../lib` |
