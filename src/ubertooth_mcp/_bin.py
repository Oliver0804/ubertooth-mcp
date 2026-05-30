"""Locating the compiled ``ubertooth-*`` host binaries and running them.

There is no Python binding for libubertooth — the host side is C, exposed as a
family of CLI tools (``ubertooth-util``, ``ubertooth-btle``, ...). This module
is the single place that knows *where* those binaries live and *how* to invoke
them with the right dylib search path, so every other module shells out through
here instead of hard-coding paths.

Resolution order for the binary directory:
  1. ``UBERTOOTH_BIN_DIR`` env var, if set
  2. whatever ``shutil.which`` finds on PATH
  3. the project-local build prefix this repo was developed against

On macOS the binaries link ``libubertooth`` / ``libbtbb`` from a sibling
``../lib`` directory; we export ``DYLD_FALLBACK_LIBRARY_PATH`` so they load even
if the install rpath was not baked in (e.g. a fresh build before
``install_name_tool`` rpath fixups).
"""

from __future__ import annotations

import os
import signal
import subprocess
import tempfile
import time
import shutil
from pathlib import Path

# Where this repo's ubertooth host tools were built during bring-up. Acts as a
# last-resort fallback when the tools are not on PATH and no env var is set.
_DEFAULT_PREFIX_BIN = Path("/Users/oliver/code/goodtools/.deps/bin")


def bin_dir() -> Path | None:
    """Best guess at the directory holding the ``ubertooth-*`` executables."""
    env = os.environ.get("UBERTOOTH_BIN_DIR")
    if env:
        return Path(env)
    which = shutil.which("ubertooth-util")
    if which:
        return Path(which).parent
    if (_DEFAULT_PREFIX_BIN / "ubertooth-util").exists():
        return _DEFAULT_PREFIX_BIN
    return None


def resolve(tool: str) -> str:
    """Return the absolute path to ``tool`` (e.g. ``ubertooth-btle``).

    Raises FileNotFoundError with an actionable message if it can't be found —
    the LLM should surface this rather than silently failing.
    """
    d = bin_dir()
    if d is not None:
        cand = d / tool
        if cand.exists():
            return str(cand)
    on_path = shutil.which(tool)
    if on_path:
        return on_path
    raise FileNotFoundError(
        f"{tool} not found. Set UBERTOOTH_BIN_DIR to the directory containing "
        f"the compiled ubertooth-* binaries, or add them to PATH."
    )


def tool_env() -> dict:
    """Process environment with the libubertooth/libbtbb dylib path added."""
    env = dict(os.environ)
    d = bin_dir()
    if d is not None:
        lib = d.parent / "lib"
        if lib.is_dir():
            prev = env.get("DYLD_FALLBACK_LIBRARY_PATH", "")
            env["DYLD_FALLBACK_LIBRARY_PATH"] = (
                f"{lib}:{prev}" if prev else str(lib)
            )
    return env


def run(tool: str, args: list[str], timeout: float = 15.0) -> subprocess.CompletedProcess:
    """Run a short-lived ubertooth tool to completion and capture its output.

    For continuous tools (btle/rx/dump live capture) use ``capture.py`` instead —
    this is for bounded utility calls (util/debug/specan-to-file/afh).
    """
    argv = [resolve(tool), *args]
    return subprocess.run(
        argv,
        env=tool_env(),
        capture_output=True,
        text=True,
        timeout=timeout,
    )


def run_timed(tool: str, args: list[str], duration: float) -> str:
    """Run a continuous tool for ``duration`` seconds, then SIGINT it and return
    its combined stdout/stderr text.

    For tools (like ubertooth-afh) that print to stdout and don't exit on their
    own. SIGINT lets them stop the radio cleanly before we read the output.
    """
    duration = max(0.5, min(float(duration), 120.0))
    tmp = Path(tempfile.gettempdir()) / f"ubertooth-{tool}-{int(time.time())}.out"
    with open(tmp, "wb") as out:
        proc = subprocess.Popen(
            [resolve(tool), *args],
            env=tool_env(),
            stdout=out, stderr=subprocess.STDOUT,
            start_new_session=True,
        )
        try:
            proc.wait(timeout=duration)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(os.getpgid(proc.pid), signal.SIGINT)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=3.0)
            except subprocess.TimeoutExpired:
                proc.kill()
    try:
        text = tmp.read_text(errors="replace")
        tmp.unlink()
    except OSError:
        text = ""
    return text
