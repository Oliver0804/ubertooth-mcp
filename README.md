# ubertooth-mcp

An [MCP](https://modelcontextprotocol.io) server that exposes an **Ubertooth One**
to LLM agents (Claude Code, etc.) for 2.4 GHz Bluetooth research — BLE sniffing,
Bluetooth Classic (BR/EDR) discovery/following, AFH mapping, and spectrum scanning.

It is a thin, robust wrapper around the compiled `ubertooth-*` host CLI tools
(there is no Python binding for `libubertooth`), modelled on the same FastMCP +
async-capture-session conventions as
[`cynthion-mcp`](https://github.com/Oliver0804/cynthion-mcp).

## Requirements

- An Ubertooth One on USB (tested against firmware `2020-12-R1`, API 1.07).
- The compiled `ubertooth-*` host tools on `PATH`, or point `UBERTOOTH_BIN_DIR`
  at the directory containing them. (See "Building the host tools" below.)
- `tshark` (from Wireshark) — optional, only needed for the pcap decode tools.

## Install

```bash
pip install -e .
```

Register with Claude Code:

```bash
claude mcp add ubertooth -- ubertooth-mcp
# if the tools aren't on PATH:
claude mcp add ubertooth -e UBERTOOTH_BIN_DIR=/path/to/ubertooth/bin -- ubertooth-mcp
```

📖 完整使用說明（繁中，含工作流程與疑難排解）：[`docs/USAGE.md`](docs/USAGE.md)

## Tools

| Tool | What it does |
|------|--------------|
| `device_status` | Firmware/API version, serial, part id, device count |
| `reset_device` / `identify` | Full reset / flash LEDs to locate the board |
| `read_registers` | Decoded CC2400 radio registers |
| `spectrum_scan` | Bounded 2.4 GHz RSSI sweep → peaks + Wi-Fi congestion (synchronous) |
| `ble_sniff_start` | BLE advertising / follow / promiscuous → pcap (async session) |
| `classic_sniff_start` | Bluetooth Classic survey / follow → pcapng (async session) |
| `raw_dump_start` | Raw symbol/bit stream → .bin (async session) |
| `afh_map` | Detect a piconet's adaptive frequency-hopping map (bounded) |
| `capture_status` / `capture_stop` / `list_captures` | Manage the active session |
| `pcap_summary` / `ble_advertisers` / `dissect_packets` | tshark-backed decode |

### Capture-session model

The continuous sniffers run as **background sessions** — only one at a time:

```
ble_sniff_start(mode="follow", target_mac="22:44:66:88:aa:cc")
  → returns a session id, capture runs in the background
capture_status()   → poll bytes captured / log tail
capture_stop()     → SIGINT the tool so it flushes the pcap, returns the path
pcap_summary(<id>) → decode it
```

`capture_stop` sends `SIGINT` (not `SIGKILL`) so the ubertooth tool stops the
radio cleanly and writes a valid pcap trailer.

## Limitations

- A single Ubertooth listens on **one BLE advertising channel at a time** (37/38/39),
  so the `CONNECT_IND` that starts a connection can be missed — retries are normal.
- **Encrypted** connections are captured as ciphertext unless you also catch the
  pairing or already have the keys.
- Best with **BLE 4.x / 1M PHY**; BLE 5 2M/Coded PHY and CSA #2 support is limited.
- On **macOS**, `ubertooth-scan` and `ubertooth-follow` are unavailable (they need
  Linux BlueZ / `libbluetooth`).

> ⚠️ Only sniff traffic you are authorised to. This is for security research,
> debugging your own devices, and authorised testing.

## Building the host tools

See the upstream [ubertooth](https://github.com/greatscottgadgets/ubertooth) repo.
On macOS with Homebrew deps, the build needed:
`-DCMAKE_POLICY_VERSION_MINIMUM=3.5 -DENABLE_PYTHON=OFF -DCMAKE_C_FLAGS=-I/opt/homebrew/include`,
plus building a matching `libbtbb` first.
