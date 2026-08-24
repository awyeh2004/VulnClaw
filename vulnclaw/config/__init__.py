"""URL utility functions — shared across infrastructure and domain layers.

修改者: Nyaecho
修改时间: 2026-07-08
修改原因: 消除 V1 违规 — mcp/lifecycle.py 基础设施层不应反向依赖
         agent/builtin_tools.py 领域层，将纯 URL 工具函数抽取到
         基础设施层 config/ 包中。
"""

from __future__ import annotations

from urllib.parse import urlparse


def infer_port_from_url(url: str) -> int | None:
    """Infer request port from URL.

    Returns the explicit port if present in the URL, otherwise infers
    from the scheme (443 for https, 80 for http), or None if unknown.
    Never raises on a malformed port (e.g. trailing ``~`` from a paste).
    """
    from vulnclaw.config.url_utils import infer_port_from_url as _infer

    return _infer(url)
