"""2.4 GHz spectrum scan via ``ubertooth-specan``.

Unlike the sniffing tools this is *bounded*: we run specan for a fixed number
of seconds writing raw samples to a temp file, then parse and summarise. The
on-disk format written by ``ubertooth-specan -d`` is a flat stream of 3-byte
records: a big-endian uint16 frequency in MHz followed by a signed int8 RSSI.
"""

from __future__ import annotations

import os
import signal
import struct
import subprocess
import tempfile
import time
from pathlib import Path

from . import _bin


def spectrum_scan(duration_seconds: float = 4.0,
                  low_freq: int = 2402,
                  high_freq: int = 2480) -> dict:
    """Sweep ``low_freq``..``high_freq`` MHz for ``duration_seconds`` and summarise.

    Returns peak RSSI per frequency, the strongest peaks overall, and the peak
    near the three non-overlapping Wi-Fi channels (1/6/11) as a quick read on
    band congestion.
    """
    duration_seconds = max(0.5, min(float(duration_seconds), 30.0))
    tmp = Path(tempfile.gettempdir()) / f"ubertooth-specan-{int(time.time())}.bin"

    argv = [_bin.resolve("ubertooth-specan"),
            "-d", str(tmp),
            "-l", str(low_freq), "-u", str(high_freq)]
    proc = subprocess.Popen(
        argv, env=_bin.tool_env(),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        time.sleep(duration_seconds)
    finally:
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=3.0)
        except subprocess.TimeoutExpired:
            proc.kill()

    data = tmp.read_bytes() if tmp.exists() else b""
    try:
        tmp.unlink()
    except OSError:
        pass

    peak: dict[int, int] = {}
    n = len(data) // 3
    for i in range(n):
        f = (data[i * 3] << 8) | data[i * 3 + 1]
        r = struct.unpack("b", data[i * 3 + 2 : i * 3 + 3])[0]
        if low_freq <= f <= high_freq:
            if f not in peak or r > peak[f]:
                peak[f] = r

    top = sorted(peak.items(), key=lambda kv: -kv[1])[:8]
    wifi = {}
    for ch, cf in {"ch1": 2412, "ch6": 2437, "ch11": 2462}.items():
        vals = [v for f, v in peak.items() if cf - 10 <= f <= cf + 10]
        if vals:
            wifi[ch] = max(vals)

    return {
        "duration_s": duration_seconds,
        "range_mhz": [low_freq, high_freq],
        "samples": n,
        "frequencies_seen": len(peak),
        "peak_rssi_by_mhz": {str(f): peak[f] for f in sorted(peak)},
        "top_peaks": [{"mhz": f, "rssi": r} for f, r in top],
        "wifi_channel_peaks": wifi,
    }
