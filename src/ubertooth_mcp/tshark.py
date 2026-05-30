"""tshark-backed decode helpers for ubertooth BLE / Classic pcaps.

The sniffing tools already write Wireshark-native pcaps (DLT_BLUETOOTH_LE_LL_WITH_PHDR
for ``ubertooth-btle -q``, BR/EDR baseband for ``ubertooth-rx``). These helpers
turn a stored capture into LLM-friendly structured records instead of raw hex.

``tshark`` is an optional external dependency; tools degrade with a clear error
if it isn't installed.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from collections import Counter
from pathlib import Path

from .capture import CAPTURES_DIR

TSHARK_EXE = shutil.which("tshark") or "/opt/homebrew/bin/tshark"

# BLE advertising PDU type → name (Core spec Vol 6, Part B, 2.3).
ADV_PDU_NAMES = {
    "0x00": "ADV_IND", "0x01": "ADV_DIRECT_IND", "0x02": "ADV_NONCONN_IND",
    "0x03": "SCAN_REQ", "0x04": "SCAN_RSP", "0x05": "CONNECT_IND",
    "0x06": "ADV_SCAN_IND", "0x07": "ADV_EXT_IND", "0x08": "AUX_CONNECT_RSP",
}


def _have_tshark() -> bool:
    return Path(TSHARK_EXE).exists() or shutil.which("tshark") is not None


def resolve_pcap(id_or_path: str) -> Path:
    """Accept either a capture id (looked up in CAPTURES_DIR) or a direct path."""
    p = Path(id_or_path)
    if p.is_file():
        return p
    for ext in (".pcap", ".pcapng"):
        cand = CAPTURES_DIR / f"{id_or_path}{ext}"
        if cand.is_file():
            return cand
    raise FileNotFoundError(
        f"no pcap for {id_or_path!r} (looked for a file path and "
        f"{CAPTURES_DIR}/{id_or_path}.pcap[ng])"
    )


def _run_fields(pcap: Path, fields: list[str], display_filter: str | None,
                limit: int | None) -> list[list[str]]:
    if not _have_tshark():
        raise RuntimeError("tshark not found — install wireshark/tshark to use decode tools")
    args = [TSHARK_EXE, "-r", str(pcap), "-T", "fields"]
    for f in fields:
        args += ["-e", f]
    args += ["-E", "separator=\t", "-E", "occurrence=f"]
    if display_filter:
        args += ["-Y", display_filter]
    if limit:
        args += ["-c", str(limit)]
    cp = subprocess.run(args, capture_output=True, text=True, timeout=60)
    rows = []
    for line in cp.stdout.splitlines():
        rows.append(line.split("\t"))
    return rows


def pcap_summary(id_or_path: str) -> dict:
    """Packet count, BLE advertising PDU-type breakdown and top advertiser MACs."""
    pcap = resolve_pcap(id_or_path)
    rows = _run_fields(
        pcap,
        ["btle.advertising_header.pdu_type", "btle.advertising_address"],
        display_filter=None, limit=None,
    )
    pdu = Counter()
    adv = Counter()
    for row in rows:
        ptype = row[0] if len(row) > 0 else ""
        addr = row[1] if len(row) > 1 else ""
        if ptype:
            pdu[ADV_PDU_NAMES.get(ptype, ptype)] += 1
        if addr:
            adv[addr] += 1
    return {
        "pcap_path": str(pcap),
        "total_packets": len(rows),
        "pdu_type_counts": dict(pdu.most_common()),
        "top_advertisers": [{"address": a, "packets": c} for a, c in adv.most_common(20)],
    }


def ble_advertisers(id_or_path: str) -> dict:
    """Unique BLE advertisers with packet counts and (where present) company id."""
    pcap = resolve_pcap(id_or_path)
    rows = _run_fields(
        pcap,
        ["btle.advertising_address", "btcommon.eir_ad.entry.company_id",
         "btcommon.eir_ad.entry.device_name"],
        display_filter="btle.advertising_address", limit=None,
    )
    seen: dict[str, dict] = {}
    for row in rows:
        addr = row[0] if len(row) > 0 else ""
        if not addr:
            continue
        rec = seen.setdefault(addr, {"address": addr, "packets": 0,
                                     "company_ids": set(), "names": set()})
        rec["packets"] += 1
        if len(row) > 1 and row[1]:
            rec["company_ids"].add(row[1])
        if len(row) > 2 and row[2]:
            rec["names"].add(row[2])
    out = []
    for rec in seen.values():
        rec["company_ids"] = sorted(rec["company_ids"])
        rec["names"] = sorted(rec["names"])
        out.append(rec)
    out.sort(key=lambda r: -r["packets"])
    return {"pcap_path": str(pcap), "unique_advertisers": len(out), "advertisers": out}


def dissect(id_or_path: str, display_filter: str | None = None,
            limit: int = 100) -> dict:
    """Per-packet records via ``tshark -T json``.

    ``display_filter`` takes Wireshark display-filter syntax, e.g.
    ``btle.advertising_header.pdu_type == 0x05`` (CONNECT_IND only), or
    ``btle.advertising_address == 11:22:33:44:55:66``.
    """
    pcap = resolve_pcap(id_or_path)
    if not _have_tshark():
        raise RuntimeError("tshark not found — install wireshark/tshark to use decode tools")
    args = [TSHARK_EXE, "-r", str(pcap), "-T", "json",
            "-e", "frame.number", "-e", "frame.time_relative",
            "-e", "btle.advertising_address", "-e", "_ws.col.info",
            "-E", "occurrence=f"]
    if display_filter:
        args += ["-Y", display_filter]
    if limit:
        args += ["-c", str(limit)]
    cp = subprocess.run(args, capture_output=True, text=True, timeout=60)
    try:
        raw = json.loads(cp.stdout or "[]")
    except json.JSONDecodeError:
        raw = []
    packets = []
    for entry in raw:
        layers = entry.get("_source", {}).get("layers", {})
        packets.append({
            "frame": (layers.get("frame.number") or [""])[0],
            "time_s": (layers.get("frame.time_relative") or [""])[0],
            "adv_address": (layers.get("btle.advertising_address") or [""])[0],
            "info": (layers.get("_ws.col.info") or [""])[0],
        })
    return {
        "pcap_path": str(pcap),
        "display_filter": display_filter,
        "returned": len(packets),
        "packets": packets,
    }
