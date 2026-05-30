"""Async capture-session manager for the continuous ubertooth sniffing tools.

``ubertooth-btle``, ``ubertooth-rx`` and ``ubertooth-dump`` run until
interrupted. We model each run as a background subprocess writing its output
(pcap / pcapng / raw) to a file under ``~/.ubertooth-mcp/captures/``, mirroring
the start/status/stop session model used by cynthion-mcp.

Only one capture runs at a time — a single Ubertooth can't be claimed twice,
and serialising keeps the device state predictable for the LLM.

Stopping sends SIGINT (Ctrl-C) to the process group: the ubertooth tools
install a SIGINT handler that stops the radio cleanly and flushes the pcap
trailer, so SIGINT (not SIGKILL) is what produces a valid capture file.
"""

from __future__ import annotations

import os
import signal
import subprocess
import threading
import time
import uuid
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import _bin

CAPTURES_DIR = Path.home() / ".ubertooth-mcp" / "captures"


@dataclass
class CaptureSession:
    id: str
    tool: str           # e.g. "ubertooth-btle"
    label: str          # human description, e.g. "ble-advertising ch37"
    argv: list[str]
    out_path: Path      # pcap / pcapng / raw output
    out_kind: str       # "pcap" | "pcapng" | "raw"
    log_path: Path      # stdout+stderr of the tool
    started_at: float
    _proc: Any = field(default=None, repr=False)
    finished_at: float | None = None
    returncode: int | None = None
    error: str | None = None


_active: CaptureSession | None = None
_lock = threading.Lock()


def _new_id() -> str:
    return time.strftime("%Y%m%d-%H%M%S") + "-" + uuid.uuid4().hex[:6]


def start(tool: str, args: list[str], *, label: str, out_path: Path,
          out_kind: str) -> CaptureSession:
    """Spawn ``tool args`` as a background capture writing to ``out_path``.

    ``args`` must already include whatever flag points the tool at ``out_path``
    (e.g. ``-q <path>`` for ubertooth-btle). The caller builds the argv; this
    just owns the process lifecycle.
    """
    global _active
    with _lock:
        if _active is not None and _active.finished_at is None:
            raise RuntimeError(
                f"a capture is already running (id={_active.id}, tool={_active.tool}); "
                f"call capture_stop() first"
            )

        CAPTURES_DIR.mkdir(parents=True, exist_ok=True)
        argv = [_bin.resolve(tool), *args]
        log_path = out_path.with_suffix(out_path.suffix + ".log")

        logf = open(log_path, "wb")
        # start_new_session=True puts the child in its own process group so we
        # can signal the whole group on stop without touching this server.
        proc = subprocess.Popen(
            argv,
            env=_bin.tool_env(),
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
        )

        # Tie the session id to the output filename so callers that built
        # out_path from an id can look the capture back up by that same id.
        session = CaptureSession(
            id=out_path.stem,
            tool=tool,
            label=label,
            argv=argv,
            out_path=out_path,
            out_kind=out_kind,
            log_path=log_path,
            started_at=time.time(),
            _proc=proc,
        )
        _active = session
        return session


def _file_size(p: Path) -> int:
    try:
        return p.stat().st_size
    except OSError:
        return 0


def _log_tail(p: Path, n: int = 8) -> list[str]:
    try:
        lines = p.read_text(errors="replace").splitlines()
        return lines[-n:]
    except OSError:
        return []


def status() -> dict | None:
    """Status of the active (or most recently finished) capture, or None."""
    if _active is None:
        return None
    s = _active
    proc: subprocess.Popen | None = s._proc
    if proc is not None and s.finished_at is None:
        rc = proc.poll()
        if rc is not None:
            # Process exited on its own (e.g. -t timeout elapsed, or it errored).
            s.returncode = rc
            s.finished_at = time.time()
    return {
        "id": s.id,
        "tool": s.tool,
        "label": s.label,
        "running": s.finished_at is None,
        "started_at": s.started_at,
        "elapsed_s": round((s.finished_at or time.time()) - s.started_at, 2),
        "finished_at": s.finished_at,
        "returncode": s.returncode,
        "out_path": str(s.out_path),
        "out_kind": s.out_kind,
        "out_bytes": _file_size(s.out_path),
        "log_tail": _log_tail(s.log_path),
        "error": s.error,
    }


def stop() -> dict:
    """Stop the active capture cleanly (SIGINT) and return its final status."""
    global _active
    with _lock:
        if _active is None or _active.finished_at is not None:
            raise RuntimeError("no active capture to stop")
        s = _active
        proc: subprocess.Popen = s._proc

    if proc.poll() is None:
        # SIGINT the process group so the ubertooth tool flushes its pcap.
        try:
            os.killpg(os.getpgid(proc.pid), signal.SIGINT)
        except ProcessLookupError:
            pass
        try:
            proc.wait(timeout=5.0)
        except subprocess.TimeoutExpired:
            # Escalate: TERM then KILL.
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGTERM)
                proc.wait(timeout=3.0)
            except (ProcessLookupError, subprocess.TimeoutExpired):
                try:
                    os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
                except ProcessLookupError:
                    pass

    s.returncode = proc.poll()
    s.finished_at = time.time()
    return status()


def list_captures() -> list[dict]:
    """List capture output files stored under ~/.ubertooth-mcp/captures/."""
    if not CAPTURES_DIR.exists():
        return []
    out = []
    for p in sorted(CAPTURES_DIR.iterdir()):
        if p.suffix == ".log" or not p.is_file():
            continue
        st = p.stat()
        out.append({
            "id": p.stem,
            "path": str(p),
            "kind": p.suffix.lstrip("."),
            "size": st.st_size,
            "mtime": st.st_mtime,
        })
    return out
