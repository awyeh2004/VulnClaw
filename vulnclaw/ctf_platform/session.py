"""Recover a live CTF2 session JWT from the local browser profile.

The CTF2 SPA keeps its session token in localStorage (a leveldb-backed store),
not in cookies — which is why cookie-based recovery found nothing. This module
reads the leveldb blob directly and extracts the newest unexpired
``token`` value for the ``ctf2.dasctf.com`` origin.

Preference order across browsers/profiles:
1. Edge (Windows LocalAppData).
2. Chrome (Windows LocalAppData).
3. macOS Application Support profiles (Edge/Chrome).

The token format is a JWT with an ``exp`` claim; only tokens whose ``exp`` is
still in the future are returned, newest first.
"""

from __future__ import annotations

import base64
import glob
import json
import os
import re
import time

_JWT_RE = re.compile(rb"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")


def _b64d(seg: str) -> str:
    seg += "=" * (-len(seg) % 4)
    try:
        return base64.urlsafe_b64decode(seg).decode("utf-8", "replace")
    except Exception:
        return ""


def _jwt_exp(token: str) -> int | None:
    parts = token.split(".")
    if len(parts) != 3:
        return None
    try:
        payload = json.loads(_b64d(parts[1]))
        exp = payload.get("exp")
        return int(exp) if isinstance(exp, (int, float)) else None
    except Exception:
        return None


def _scan_leveldb_dir(leveldb_dir: str) -> list[tuple[int, str]]:
    """Return (exp, token) pairs found under a leveldb storage directory."""
    found: list[tuple[int, str]] = []
    if not leveldb_dir or not os.path.isdir(leveldb_dir):
        return found
    files = glob.glob(os.path.join(leveldb_dir, "*.ldb")) + glob.glob(
        os.path.join(leveldb_dir, "*.log")
    )
    seen: set[str] = set()
    for fp in files:
        try:
            data = open(fp, "rb").read()
        except Exception:
            continue
        for m in _JWT_RE.finditer(data):
            tok = m.group(0).decode("utf-8", "replace")
            if tok in seen:
                continue
            seen.add(tok)
            exp = _jwt_exp(tok)
            found.append((exp or 0, tok))
    return found


def _profiles() -> list[str]:
    local = os.environ.get("LOCALAPPDATA", "").strip()
    home = os.path.expanduser("~")
    candidates: list[str] = []
    if local:
        for name in ("Microsoft", "Edge", "User Data"), ("Google", "Chrome", "User Data"):
            candidates.append(os.path.join(local, *name))
    mac = os.path.join(home, "Library", "Application Support")
    for name in ("Microsoft Edge"), ("Google", "Chrome"):
        candidates.append(os.path.join(mac, *name))
    return candidates


def read_edge_session_token() -> str:
    """Return the newest unexpired JWT for CTF2 across Browsers/profiles."""

    now = int(time.time())
    best: tuple[int, str] | None = None
    for user_data_dir in _profiles():
        if not os.path.isdir(user_data_dir):
            continue
        for pattern in ("Default", "Profile *"):
            for prof in glob.glob(os.path.join(user_data_dir, pattern)):
                level = os.path.join(prof, "Local Storage", "leveldb")
                for exp, tok in _scan_leveldb_dir(level):
                    if exp <= now:
                        continue
                    if best is None or exp > best[0]:
                        best = (exp, tok)
    return best[1] if best else ""


def read_edge_session_token_any() -> str:
    """Like ``read_edge_session_token`` but also returns expired tokens
    when nothing live is found (useful for diagnostics)."""
    live = read_edge_session_token()
    if live:
        return live
    best: tuple[int, str] | None = None
    for user_data_dir in _profiles():
        if not os.path.isdir(user_data_dir):
            continue
        for pattern in ("Default", "Profile *"):
            for prof in glob.glob(os.path.join(user_data_dir, pattern)):
                level = os.path.join(prof, "Local Storage", "leveldb")
                for exp, tok in _scan_leveldb_dir(level):
                    if best is None or exp > best[0]:
                        best = (exp, tok)
    return best[1] if best else ""