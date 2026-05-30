"""Bounded ``ubertooth-util`` / ``ubertooth-debug`` operations.

These all complete quickly (a USB control transfer or two) so they run
synchronously via ``_bin.run`` rather than the capture-session machinery. They
will fail with a "device busy" style error if a capture is currently running —
that's expected; stop the capture first.
"""

from __future__ import annotations

import re
from dataclasses import asdict, dataclass


@dataclass
class DeviceStatus:
    connected: bool
    count: int | None
    firmware_version: str | None
    api_version: str | None
    serial_number: str | None
    part_id: str | None
    raw: str | None = None


def _util(args: list[str]) -> str:
    from . import _bin
    cp = _bin.run("ubertooth-util", args, timeout=10.0)
    return (cp.stdout or "") + (cp.stderr or "")


def get_status() -> dict:
    """Read firmware version, API version, serial number, part id and count."""
    from . import _bin

    # -N prints the number of Uberteeth; 0 (or an error) means none attached.
    count_out = _util(["-N"])
    m = re.search(r"(\d+)", count_out)
    count = int(m.group(1)) if m else None
    if not count:
        return asdict(DeviceStatus(
            connected=False, count=count or 0,
            firmware_version=None, api_version=None,
            serial_number=None, part_id=None, raw=count_out.strip(),
        ))

    ver_out = _util(["-v"])
    fw = api = None
    m = re.search(r"Firmware version:\s*(\S+)\s*\(API:([0-9.]+)\)", ver_out)
    if m:
        fw, api = m.group(1), m.group(2)

    serial = None
    m = re.search(r"Serial No:\s*([0-9a-fA-F]+)", _util(["-s"]))
    if m:
        serial = m.group(1)

    part = None
    m = re.search(r"Part ID:\s*(\S+)", _util(["-p"]))
    if m:
        part = m.group(1)

    return asdict(DeviceStatus(
        connected=True, count=count,
        firmware_version=fw, api_version=api,
        serial_number=serial, part_id=part,
    ))


def reset_device() -> dict:
    """Issue a full reset (``ubertooth-util -r``). Device re-enumerates afterwards."""
    out = _util(["-r"])
    return {"ok": True, "output": out.strip()}


def identify() -> dict:
    """Flash all LEDs on the board (``ubertooth-util -I``) to physically locate it."""
    out = _util(["-I"])
    return {"ok": True, "output": out.strip()}


def read_registers(start: int = 0, end: int = 15) -> dict:
    """Read CC2400 radio registers via ``ubertooth-debug -r <start>-<end>``.

    Returns the human-readable decoded text plus a parsed name→value map for
    the registers in the range. Useful for low-level radio state inspection.
    """
    from . import _bin
    cp = _bin.run("ubertooth-debug", ["-r", f"{start}-{end}"], timeout=10.0)
    text = (cp.stdout or "") + (cp.stderr or "")
    regs = {}
    for m in re.finditer(r"%(\w+)\s*=\s*(0x[0-9a-fA-F]+)", text):
        regs[m.group(1)] = m.group(2)
    return {"start": start, "end": end, "registers": regs, "raw": text.strip()}
