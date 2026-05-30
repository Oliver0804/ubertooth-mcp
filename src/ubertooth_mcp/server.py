"""MCP server entrypoint — exposes Ubertooth One sniffing tools over stdio.

Deliberately NOT using ``from __future__ import annotations`` — FastMCP builds
per-tool pydantic argument models and needs annotations to evaluate to real
objects (e.g. ``Literal[...]``) through the @_safe wrapper.
"""

import functools
import inspect
import logging
import os
import re
import sys
import traceback
from pathlib import Path
from typing import Literal

from mcp.server.fastmcp import FastMCP

from . import _bin, capture, hardware, specan, tshark as tshark_mod

log = logging.getLogger("ubertooth_mcp")


def _safe(fn):
    """Turn unhandled exceptions into structured error dicts.

    A single libusb timeout or "device busy" shouldn't take down the stdio
    server and force a Claude Code restart. We preserve ``__signature__`` so
    FastMCP still introspects the real parameter schema.
    """
    sig = inspect.signature(fn)

    @functools.wraps(fn)
    def wrapper(*args, **kwargs):
        try:
            return fn(*args, **kwargs)
        except Exception as e:
            log.warning("tool %s failed: %s", fn.__name__, e)
            return {
                "error": f"{type(e).__name__}: {e}",
                "tool": fn.__name__,
                "traceback_tail": traceback.format_exc().strip().splitlines()[-3:],
            }

    wrapper.__signature__ = sig
    return wrapper


mcp = FastMCP(
    name="ubertooth",
    instructions=(
        "Drive an Ubertooth One for 2.4GHz Bluetooth research.\n"
        "  - device_status / reset_device / identify / read_registers: board mgmt\n"
        "  - spectrum_scan: bounded 2.4GHz RSSI sweep (synchronous)\n"
        "  - ble_sniff_start: BLE advertising/follow/promiscuous -> pcap (async session)\n"
        "  - classic_sniff_start: Bluetooth Classic (BR/EDR) survey/follow -> pcapng\n"
        "  - afh_map: detect a piconet's adaptive frequency-hopping map\n"
        "  - raw_dump_start: raw symbol/bit stream capture\n"
        "Sniffing tools are SESSIONS: start one, poll capture_status, then "
        "capture_stop to flush the pcap. Only ONE capture runs at a time. "
        "Decode stored pcaps with pcap_summary / ble_advertisers / dissect_packets.\n"
        "NOTE: on macOS ubertooth-scan/-follow are unavailable (need Linux BlueZ)."
    ),
)

_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")
_HEX_RE = re.compile(r"^[0-9a-fA-F]+$")


def _ensure_idle():
    st = capture.status()
    if st and st.get("running"):
        raise RuntimeError(
            f"a capture is running (id={st['id']}, tool={st['tool']}); "
            f"call capture_stop() before using the radio for this operation"
        )


# - board management ---------------------------------------------------------


@mcp.tool()
@_safe
def device_status() -> dict:
    """Firmware/API version, serial number, part id and number of Uberteeth attached."""
    return hardware.get_status()


@mcp.tool()
@_safe
def reset_device() -> dict:
    """Full reset of the Ubertooth (re-enumerates on USB afterwards)."""
    _ensure_idle()
    return hardware.reset_device()


@mcp.tool()
@_safe
def identify() -> dict:
    """Flash all LEDs to physically locate the board."""
    _ensure_idle()
    return hardware.identify()


@mcp.tool()
@_safe
def read_registers(start: int = 0, end: int = 15) -> dict:
    """Read decoded CC2400 radio registers in the index range [start, end]."""
    _ensure_idle()
    return hardware.read_registers(start=start, end=end)


# - spectrum (bounded, synchronous) ------------------------------------------


@mcp.tool()
@_safe
def spectrum_scan(duration_seconds: float = 4.0,
                  low_freq: int = 2402,
                  high_freq: int = 2480) -> dict:
    """Sweep the 2.4GHz band for a few seconds and summarise RSSI per frequency.

    Blocks for ``duration_seconds`` (capped at 30). Returns peak RSSI by MHz,
    the strongest peaks, and congestion at Wi-Fi channels 1/6/11.
    """
    _ensure_idle()
    return specan.spectrum_scan(duration_seconds, low_freq, high_freq)


# - BLE sniffing (async session) ---------------------------------------------


@mcp.tool()
@_safe
def ble_sniff_start(
    mode: Literal["advertising", "follow", "promiscuous"] = "advertising",
    target_mac: str | None = None,
    adv_channel: Literal[37, 38, 39] = 37,
) -> dict:
    """Start a BLE capture (ubertooth-btle) writing a pcap. Returns a session id.

    Modes:
      - 'advertising': print/capture advertisements only (-n), no connection following
      - 'follow': follow connections (-f); set ``target_mac`` to only follow one device
      - 'promiscuous': recover and sniff already-established connections (-p)

    A single Ubertooth listens on ONE advertising channel at a time, so the
    CONNECT_IND that starts a connection may land on a channel you're not on —
    retries are normal. ``target_mac`` is dotted hex, e.g. '22:44:66:88:aa:cc'.
    Stop with capture_stop to flush the pcap; decode with pcap_summary.
    """
    _ensure_idle()
    if target_mac is not None and not _MAC_RE.match(target_mac):
        raise ValueError(f"target_mac must look like 11:22:33:44:55:66, got {target_mac!r}")

    mode_flag = {"advertising": "-n", "follow": "-f", "promiscuous": "-p"}[mode]
    cid = capture._new_id()
    out_path = capture.CAPTURES_DIR / f"{cid}.pcap"
    args = [mode_flag, f"-A{adv_channel}", "-q", str(out_path)]
    if target_mac:
        args.append(f"-t{target_mac}/48")
    label = f"ble-{mode} ch{adv_channel}" + (f" target={target_mac}" if target_mac else "")

    capture.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    capture.start("ubertooth-btle", args, label=label,
                  out_path=out_path, out_kind="pcap")
    return capture.status()


# - Bluetooth Classic / BR-EDR (async session) -------------------------------


@mcp.tool()
@_safe
def classic_sniff_start(
    lap: str | None = None,
    uap: str | None = None,
    channel: int | None = None,
    survey: bool = True,
) -> dict:
    """Start a Bluetooth Classic capture (ubertooth-rx) writing a pcapng.

    - No LAP + survey=True: discover all piconets (LAPs/UAPs) — start here.
    - lap only: calculate the UAP for that LAP.
    - lap + uap: follow the piconet's hopping and decode packets.

    ``lap`` is 6 hex digits, ``uap`` is 2 hex digits. ``channel`` fixes a BT
    channel (default firmware behaviour otherwise). Stop with capture_stop.
    """
    _ensure_idle()
    for name, val, n in (("lap", lap, 6), ("uap", uap, 2)):
        if val is not None and (not _HEX_RE.match(val) or len(val) != n):
            raise ValueError(f"{name} must be {n} hex digits, got {val!r}")
    if uap is not None and lap is None:
        raise ValueError("uap requires lap")

    cid = capture._new_id()
    out_path = capture.CAPTURES_DIR / f"{cid}.pcapng"
    args = ["-r", str(out_path)]
    if survey and lap is None:
        args.append("-z")
    if lap:
        args += ["-l", lap]
    if uap:
        args += ["-u", uap]
    if channel is not None:
        args += ["-c", str(channel)]
    label = "classic-survey" if (survey and lap is None) else \
            f"classic lap={lap}" + (f" uap={uap}" if uap else "")

    capture.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    capture.start("ubertooth-rx", args, label=label,
                  out_path=out_path, out_kind="pcapng")
    return capture.status()


# - raw symbol dump (async session) ------------------------------------------


@mcp.tool()
@_safe
def raw_dump_start(modulation: Literal["le", "classic"] = "le") -> dict:
    """Capture a raw received bit/symbol stream (ubertooth-dump) to a .bin file.

    'le' uses LE modulation (-l), 'classic' uses classic modulation (-c).
    Low-level — most use cases want ble_sniff_start / classic_sniff_start instead.
    """
    _ensure_idle()
    cid = capture._new_id()
    out_path = capture.CAPTURES_DIR / f"{cid}.bin"
    flag = "-l" if modulation == "le" else "-c"
    args = [flag, "-d", str(out_path)]
    capture.CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
    capture.start("ubertooth-dump", args, label=f"raw-dump {modulation}",
                  out_path=out_path, out_kind="raw")
    return capture.status()


# - AFH map (bounded) --------------------------------------------------------


@mcp.tool()
@_safe
def afh_map(lap: str, uap: str, duration_seconds: float = 15.0) -> dict:
    """Detect a piconet's Adaptive Frequency Hopping channel map (ubertooth-afh).

    Requires ``lap`` (6 hex) and ``uap`` (2 hex) of the target piconet — get
    these from classic_sniff_start survey mode first. Runs for
    ``duration_seconds`` then returns the observed map text.
    """
    _ensure_idle()
    for name, val, n in (("lap", lap, 6), ("uap", uap, 2)):
        if not _HEX_RE.match(val) or len(val) != n:
            raise ValueError(f"{name} must be {n} hex digits, got {val!r}")
    text = _bin.run_timed("ubertooth-afh", ["-l", lap, "-u", uap, "-r"],
                          duration=duration_seconds)
    return {"lap": lap, "uap": uap, "duration_s": duration_seconds, "output": text.strip()}


# - session control ----------------------------------------------------------


@mcp.tool()
@_safe
def capture_status() -> dict | None:
    """Status of the active (or most recently finished) capture session, or None."""
    return capture.status()


@mcp.tool()
@_safe
def capture_stop() -> dict:
    """Stop the active capture (SIGINT, so the pcap is flushed) and return its stats."""
    return capture.stop()


@mcp.tool()
@_safe
def list_captures() -> list:
    """List capture files under ~/.ubertooth-mcp/captures/."""
    return capture.list_captures()


# - decode (tshark-backed) ---------------------------------------------------


@mcp.tool()
@_safe
def pcap_summary(id_or_path: str) -> dict:
    """BLE packet count, advertising PDU-type breakdown and top advertiser MACs."""
    return tshark_mod.pcap_summary(id_or_path)


@mcp.tool()
@_safe
def ble_advertisers(id_or_path: str) -> dict:
    """Unique BLE advertisers in a capture with packet counts and company ids."""
    return tshark_mod.ble_advertisers(id_or_path)


@mcp.tool()
@_safe
def dissect_packets(id_or_path: str, display_filter: str | None = None,
                    limit: int = 100) -> dict:
    """Per-packet records from a capture via tshark, with optional display filter.

    Example filters: ``btle.advertising_header.pdu_type == 0x05`` (CONNECT_IND),
    ``btle.advertising_address == 11:22:33:44:55:66``.
    """
    return tshark_mod.dissect(id_or_path, display_filter=display_filter, limit=limit)


# - entrypoint ---------------------------------------------------------------


def main() -> None:
    logging.basicConfig(
        level=os.environ.get("UBERTOOTH_MCP_LOG", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
        stream=sys.stderr,
    )
    mcp.run("stdio")


if __name__ == "__main__":
    main()
