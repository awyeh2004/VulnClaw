"""http_probe_batch tool: grouped HTTP probing with body dedup."""

from __future__ import annotations

import asyncio
import hashlib
import json
import re
import time
from typing import TYPE_CHECKING, Any
from urllib.parse import urljoin, urlparse

import httpx

from vulnclaw.agent.agent_state import clip_text, one_line
from vulnclaw.agent.tools._shared import _runtime_config
from vulnclaw.config.source_render import render_highlighted_source_block
from vulnclaw.config.url_utils import infer_port_from_url, normalized_origin
from vulnclaw.utils.http_client import bypass_proxy_for, is_local_target, resolve_egress_proxy

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


_HTTP_PROBE_ALLOWED_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}
_HTTP_PROBE_MAX_REQUESTS = 30
_HTTP_PROBE_DEFAULT_TIMEOUT = 10.0
_HTTP_PROBE_DEFAULT_BODY_CHARS_LIMIT = 0
_HTTP_PROBE_REDIRECT_STATUSES = {301, 302, 303, 307, 308}
_HTTP_PROBE_BATCH_BUDGET = 300.0
_HTTP_PROBE_SENSITIVE_HEADER_NAMES = {
    "authorization",
    "proxy-authorization",
    "x-api-key",
    "api-key",
    "x-auth-token",
    "x-access-token",
}


def _group_http_probe_batch(
    items: list[dict[str, Any]], egress_proxy: str
) -> list[tuple[list[dict[str, Any]], str]]:
    """Split a probe batch into ``(group, proxy)`` pairs -- one client per group.

    ``targets=`` keeps the *system* proxy away from loopback/private hosts: httpx
    defaults to ``trust_env=True`` and ignores the Windows ProxyOverride bypass
    list, so a running proxy tool would send the batch from the wrong source
    address (and internal hosts would read as unreachable). ``targets_need_direct()``
    is an EVERY test, so a batch that mixes an internal host with a public one
    cannot share one client -- the factory's documented remedy is one client per
    group.

    An operator-configured egress proxy (``network.http_proxy`` /
    ``VULNCLAW_HTTP_PROXY``) supersedes that split, because private hosts are then
    exactly what the tunnel exists to reach -- **but loopback keeps its own
    proxy-less client**. Round-1 (2026-10-09) postmortem: loopback used to ride the
    group that received the tunnel, and ``egress_settings`` only keeps an
    *all-local* target set direct, so a batch mixing ``127.0.0.1`` with a target
    silently aimed the local request at the far end of the tunnel -- while this
    function's predecessor comment claimed the opposite.
    """
    local: list[dict[str, Any]] = []
    direct: list[dict[str, Any]] = []
    proxied: list[dict[str, Any]] = []
    for item in items:
        url = str(item.get("url") or "")
        if is_local_target(url):
            local.append(item)
        elif bypass_proxy_for(url):
            direct.append(item)
        else:
            proxied.append(item)

    groups: list[tuple[list[dict[str, Any]], str]] = [
        (local, ""),                 # this machine: never the tunnel
        (direct, egress_proxy),      # internal/private: tunnel when one is configured
        (proxied, egress_proxy),     # public: environment proxy, or the tunnel
    ]
    return [(group, proxy) for group, proxy in groups if group]


async def execute_http_probe_batch(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run HTTP probes for URL/param/header/body variants."""
    # make_http_client and the scope/port enforcers live in the facade (or are
    # patched there by tests), so resolve them from builtin_tools at call time.
    from vulnclaw.agent import builtin_tools as _bt

    specs = args.get("requests", [])
    if not isinstance(specs, list) or not specs:
        return "[!] http_probe_batch requires a non-empty requests array"
    specs = specs[:_HTTP_PROBE_MAX_REQUESTS]

    base_url = str(args.get("base_url", "") or "").strip()
    timeout = _bounded_float(args.get("timeout", _HTTP_PROBE_DEFAULT_TIMEOUT), 1.0, 30.0)
    follow_redirects = bool(args.get("follow_redirects", True))
    verify_tls = bool(args.get("verify_tls", False))
    max_body_chars = _coerce_nonnegative_int(
        args.get("max_body_chars"),
        default=_HTTP_PROBE_DEFAULT_BODY_CHARS_LIMIT,
    )

    prepared: list[dict[str, Any]] = []
    for index, raw_spec in enumerate(specs, start=1):
        if not isinstance(raw_spec, dict):
            prepared.append({"index": index, "error": "request spec must be an object"})
            continue
        prepared.append(_prepare_http_probe_request(agent, base_url, index, raw_spec))

    def _run() -> str:
        results: list[dict[str, Any]] = []
        deadline = time.monotonic() + _HTTP_PROBE_BATCH_BUDGET
        budget_exhausted = time.monotonic() >= deadline
        # Group the batch by whether a request must bypass the system proxy.
        #
        # targets= keeps the system proxy out of the way for loopback/private
        # targets: httpx defaults to trust_env=True and ignores the Windows
        # ProxyOverride bypass list, so a running proxy tool would send the batch at
        # the wrong source address (and internal targets would look unreachable).
        # Public targets still honour the environment proxy.
        #
        # ONE client cannot do both: trust_env is fixed per client, and
        # targets_need_direct() is an EVERY test — handing it the whole batch keeps
        # the environment proxy for every request, so a spec whose raw_url overrides
        # a public base_url with an internal host would still be proxied and then
        # reported unreachable. That is the failure this bypass exists to prevent,
        # so build one client per group. A raw_url is not a rare shape:
        # http_probe_batch is used for exactly this kind of host/path mixing.
        #
        # The grouping itself lives in _group_http_probe_batch (loopback /
        # internal / public -- one proxy per group); specs that failed preparation
        # are answered below without a request.
        request_items: list[dict[str, Any]] = []
        for item in prepared:
            if item.get("error"):
                results.append(item)
            else:
                request_items.append(item)

        egress_proxy = resolve_egress_proxy(_runtime_config(agent))
        for group, group_proxy in _group_http_probe_batch(request_items, egress_proxy):
            with _bt.make_http_client(
                targets=[str(item.get("url") or "") for item in group],
                proxy=group_proxy,
                follow_redirects=False,
                timeout=timeout,
                verify=verify_tls,
                headers={"User-Agent": "VulnClaw-http_probe_batch/1.0"},
            ) as client:
                for item in group:
                    if budget_exhausted or time.monotonic() >= deadline:
                        budget_exhausted = True
                        results.append(
                            {
                                **item,
                                "error": "[budget_exceeded] batch time budget exceeded",
                            }
                        )
                        continue
                    results.append(
                        _execute_one_http_probe(
                            client,
                            item,
                            max_body_chars,
                            agent=agent,
                            follow_redirects=follow_redirects,
                        )
                    )

        # Two groups means the append order is no longer spec order.
        results.sort(key=lambda entry: entry.get("index") or 0)
        seen = getattr(agent.runtime, "seen_body_hashes", None)
        if isinstance(seen, dict):
            return _format_http_probe_batch(results, seen_hashes=seen)
        return _format_http_probe_batch(results)

    return await asyncio.to_thread(_run)


def _bounded_float(value: Any, lower: float, upper: float) -> float:
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return lower
    return max(lower, min(parsed, upper))


def _coerce_nonnegative_int(value: Any, *, default: int = 0) -> int:
    if value is None:
        return default
    try:
        parsed = int(value)
    except (TypeError, ValueError):
        return default
    return max(0, parsed)


def _prepare_http_probe_request(
    agent: AgentContext,
    base_url: str,
    index: int,
    spec: dict[str, Any],
) -> dict[str, Any]:
    # Scope/port enforcers stay in the facade and are patched there by tests.
    from vulnclaw.agent import builtin_tools as _bt

    method = str(spec.get("method", "GET") or "GET").upper()
    label = str(spec.get("label", "") or "")
    if method not in _HTTP_PROBE_ALLOWED_METHODS:
        return {"index": index, "label": label, "error": f"method {method} is not allowed"}

    uses_raw_url = bool(spec.get("raw_url"))
    requested_url = str(spec.get("raw_url") or spec.get("url") or base_url or "").strip()
    if not requested_url:
        return {"index": index, "label": label, "error": "missing url/raw_url/base_url"}
    url = _resolve_probe_url(base_url, requested_url)
    parsed = urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return {"index": index, "label": label, "url": url, "error": "url must be http(s)"}

    host_violation = _bt.enforce_host_path_constraints(
        agent,
        host=parsed.hostname.lower(),
        path=(parsed.path or "/").rstrip("/") or "/",
        target=parsed.hostname,
    )
    if host_violation:
        return {"index": index, "label": label, "url": url, "error": host_violation}

    port = infer_port_from_url(url)
    if port is not None:
        port_violation = _bt.enforce_port_constraints(agent, [port], target=parsed.hostname)
        if port_violation:
            return {"index": index, "label": label, "url": url, "error": port_violation}

    return {
        "index": index,
        "label": label,
        "method": method,
        "url": url,
        "raw_url": uses_raw_url,
        "params": None if uses_raw_url else _object_or_none(spec.get("params")),
        "headers": _string_dict(spec.get("headers")),
        "cookies": _string_dict(spec.get("cookies")),
        "data": spec.get("data", spec.get("body")),
        "json": spec.get("json") if "json" in spec else None,
    }


def _resolve_probe_url(base_url: str, requested_url: str) -> str:
    parsed = urlparse(requested_url)
    if parsed.scheme:
        return requested_url
    if not base_url:
        return requested_url
    return urljoin(base_url.rstrip("/") + "/", requested_url)


def _object_or_none(value: Any) -> Any:
    return value if isinstance(value, (dict, list, tuple, str)) else None


def _string_dict(value: Any) -> dict[str, str]:
    if not isinstance(value, dict):
        return {}
    return {str(k): str(v) for k, v in value.items() if k is not None and v is not None}


def _jsonish_one_line(value: Any, limit: int = 700) -> str:
    if isinstance(value, (dict, list, tuple)):
        rendered = json.dumps(value, ensure_ascii=False, separators=(",", ":"))
    else:
        rendered = str(value)
    return one_line(rendered, limit)


def _masked_probe_headers(headers: dict[str, str]) -> dict[str, str]:
    masked: dict[str, str] = {}
    for key, value in (headers or {}).items():
        normalized = str(key).lower()
        if normalized in _HTTP_PROBE_SENSITIVE_HEADER_NAMES:
            masked[str(key)] = "[masked]"
        else:
            masked[str(key)] = str(value)
    return masked


def _cookies_need_exact_header(cookies: dict[str, str]) -> bool:
    for value in (cookies or {}).values():
        text = str(value)
        if any(marker in text for marker in (";", "{", "}", '"', "'", "\r", "\n")):
            return True
    return False


def _probe_request_surface_lines(item: dict[str, Any]) -> list[str]:
    lines = [f"request={item.get('method', 'GET')} {item.get('url', '')}"]
    if item.get("params") is not None:
        lines.append(f"params={_jsonish_one_line(item.get('params'))}")
    headers = item.get("headers") or {}
    if headers:
        lines.append(f"headers={_jsonish_one_line(_masked_probe_headers(headers))}")
    cookies = item.get("cookies") or {}
    if cookies:
        note = (
            " [exact-cookie-note: value contains raw delimiters; prefer headers.Cookie "
            "when byte-exact delivery matters]"
            if _cookies_need_exact_header(cookies)
            else ""
        )
        lines.append(f"cookies={_jsonish_one_line(cookies)}{note}")
    if item.get("data") is not None:
        lines.append(f"body={_jsonish_one_line(item.get('data'))}")
    if item.get("json") is not None:
        lines.append(f"json={_jsonish_one_line(item.get('json'))}")
    return lines


def _execute_one_http_probe(
    client: httpx.Client,
    item: dict[str, Any],
    max_body_chars: int,
    *,
    agent: AgentContext,
    follow_redirects: bool,
) -> dict[str, Any]:
    started = time.perf_counter()
    try:
        response, redirect_error = _request_with_scoped_redirects(
            client,
            item,
            agent=agent,
            follow_redirects=follow_redirects,
        )
        if redirect_error:
            return {
                **item,
                "error": redirect_error,
                "duration_ms": max(0, int((time.perf_counter() - started) * 1000)),
            }
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        body = response.text or ""
        body_output, body_truncated = _body_with_optional_limit(body, max_body_chars)
        digest = hashlib.sha256(response.content or b"").hexdigest()[:12]
        return {
            **item,
            "status": response.status_code,
            "effective_url": str(response.url),
            "length": len(response.content or b""),
            "hash": digest,
            "response_headers": dict(response.headers),
            "title": _extract_html_title(body),
            "signals": _http_body_signals(body, 800),
            "decoded_source": render_highlighted_source_block(body, max_chars=max_body_chars),
            "body_chars": len(body),
            "body": body_output,
            "body_truncated": body_truncated,
            "duration_ms": duration_ms,
            "location": response.headers.get("location", ""),
            "content_type": response.headers.get("content-type", ""),
        }
    except httpx.HTTPError as exc:
        duration_ms = max(0, int((time.perf_counter() - started) * 1000))
        return {
            **item,
            "error": f"{exc.__class__.__name__}: {one_line(str(exc), 220)}",
            "duration_ms": duration_ms,
        }


def _request_with_scoped_redirects(
    client: httpx.Client,
    item: dict[str, Any],
    *,
    agent: AgentContext,
    follow_redirects: bool,
) -> tuple[httpx.Response, str | None]:
    """Follow probe redirects only after checking every destination host/path.

    ``http_probe_batch`` used to pass ``follow_redirects=True`` to httpx after
    validating only the initial URL. A target-controlled 302 could therefore
    pivot the batch outside task constraints. Keep httpx on one hop and apply
    the same host/path/port gates before each next request.

    Credentials follow the same-origin rule as MCP fetch: a cross-origin hop
    must not keep Authorization, Proxy-Authorization, Cookie, or the caller's
    cookie jar. Otherwise a scope-valid redirect could leak a session token to
    an unrelated host.
    """
    current = dict(item)
    method = str(current["method"])
    current_url = str(current["url"])
    original_client_cookies = getattr(client, "cookies", None)

    def _finish(response: httpx.Response, error: str | None) -> tuple[httpx.Response, str | None]:
        if original_client_cookies is not None:
            client.cookies = original_client_cookies
        return response, error

    for _ in range(21):
        response = client.request(
            method,
            current_url,
            params=current.get("params"),
            headers=current.get("headers") or None,
            cookies=current.get("cookies") or None,
            data=current.get("data"),
            json=current.get("json"),
            follow_redirects=False,
        )
        if not follow_redirects or response.status_code not in _HTTP_PROBE_REDIRECT_STATUSES:
            return _finish(response, None)
        location = response.headers.get("location")
        if not location:
            return _finish(response, None)
        next_url = urljoin(current_url, location)
        parsed = urlparse(next_url)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            return _finish(response, (
                f"[constraint_violation] redirect target is not an http(s) URL: {next_url}"
            ))
        from vulnclaw.agent import builtin_tools as _bt
        violation = _bt.enforce_host_path_constraints(
            agent,
            host=parsed.hostname.lower(),
            path=(parsed.path or "/").rstrip("/") or "/",
            target=parsed.hostname,
        )
        if violation:
            return _finish(response, f"{violation} (redirect target: {next_url})")
        port = infer_port_from_url(next_url)
        if port is not None:
            port_violation = _bt.enforce_port_constraints(agent, [port], target=parsed.hostname)
            if port_violation:
                return _finish(response, f"{port_violation} (redirect target: {next_url})")

        old = normalized_origin(current_url)
        new = normalized_origin(next_url)
        cross_origin = old != new
        if cross_origin:
            headers = dict(current.get("headers") or {})
            for name in list(headers):
                if str(name).lower() in {"authorization", "proxy-authorization", "cookie"}:
                    headers.pop(name, None)
            current["headers"] = headers or None
            current["cookies"] = None
            if original_client_cookies is not None:
                client.cookies = httpx.Cookies()

        current_url = next_url
        current["params"] = None
        if response.status_code in {301, 302, 303} and method not in {"GET", "HEAD"}:
            method = "GET"
            current["data"] = None
            current["json"] = None
    return _finish(
        httpx.Response(508, request=httpx.Request("GET", current_url)),
        "[constraint_violation] redirect limit exceeded",
    )


def _extract_html_title(body: str) -> str:
    match = re.search(r"<title[^>]*>(.*?)</title>", body or "", re.IGNORECASE | re.DOTALL)
    if not match:
        return ""
    return one_line(re.sub(r"<[^>]+>", "", match.group(1)), 120)


def _http_body_signals(body: str, limit: int) -> str:
    text = str(body or "")
    lines: list[str] = []
    markers = (
        "flag",
        "ctf{",
        "error",
        "exception",
        "sql",
        "warning",
        "<form",
        "<input",
        "href=",
        "token",
        "admin",
        "select",
        "union",
    )
    for line in text.splitlines():
        stripped = line.strip()
        if not stripped:
            continue
        lower = stripped.lower()
        if any(marker in lower for marker in markers):
            lines.append(one_line(stripped, 240))
        if len(lines) >= 5:
            break
    if lines:
        return clip_text("\n".join(lines), limit)
    visible = re.sub(r"<[^>]+>", " ", text)
    visible = re.sub(r"\s+", " ", visible).strip()
    return clip_text(visible, min(limit, 500))


def _body_with_optional_limit(body: str, max_body_chars: int) -> tuple[str, bool]:
    text = str(body or "")
    if max_body_chars > 0 and len(text) > max_body_chars:
        return text[:max_body_chars], True
    return text, False


def _format_http_probe_batch(
    results: list[dict[str, Any]],
    seen_hashes: dict[str, str] | None = None,
) -> str:
    """Format probe results with body dedup.

    Identical bodies are only printed once. When ``seen_hashes`` is provided it
    is mutated in place: newly discovered bodies are stored as a short summary,
    and bodies already recorded (in this batch or an earlier call) are reduced
    to a one-line reference instead of re-printing the full body.
    """
    lines = [f"# http_probe_batch results ({len(results)} request(s))"]
    hashes: dict[str, list[str]] = {}
    for item in results:
        label = f" {item['label']}" if item.get("label") else ""
        if item.get("error"):
            url = item.get("url", "")
            duration = f" {item.get('duration_ms')}ms" if item.get("duration_ms") is not None else ""
            request_surface = "\n".join(
                f"    {line}" for line in _probe_request_surface_lines(item)
            )
            surface = f"\n{request_surface}" if request_surface else ""
            lines.append(f"[{item['index']}] ERROR{label}{duration} {url} :: {item['error']}{surface}")
            continue
        hash_value = str(item.get("hash", ""))
        hashes.setdefault(hash_value, []).append(str(item["index"]))
        raw_note = " raw-url" if item.get("raw_url") else ""
        location = f" location={item['location']}" if item.get("location") else ""
        title = f" title={item['title']!r}" if item.get("title") else ""
        content_type = (
            f" type={one_line(item.get('content_type', ''), 80)}"
            if item.get("content_type")
            else ""
        )
        body_text = str(item.get("body", "") or "")
        body_note = (
            f" truncated_to={len(body_text)}" if item.get("body_truncated") else ""
        )
        dedup_note = ""
        meaningful = bool(hash_value and body_text.strip() and len(body_text) > 80)
        if meaningful and seen_hashes is not None:
            if hash_value in seen_hashes:
                dedup_note = f" (body already seen: {seen_hashes[hash_value]})"
            else:
                seen_hashes[hash_value] = one_line(
                    re.sub(r"<[^>]+>", " ", body_text), 120
                )
        body_block = ""
        if not dedup_note:
            body_block = f"\n    body:\n{body_text if body_text else '(empty body)'}"
        lines.append(
            "\n".join(
                [
                    (
                        f"[{item['index']}] {item['method']}{raw_note}{label} "
                        f"{item['status']} len={item['length']} hash={item['hash']} "
                        f"{item['duration_ms']}ms{location}{content_type}{title}"
                    ),
                    f"    url={item['effective_url']}",
                    f"    response_headers={_jsonish_one_line(item.get('response_headers', {}), 1800)}",
                    *[f"    {line}" for line in _probe_request_surface_lines(item)],
                    *[
                        f"    {line}"
                        for line in str(item.get("decoded_source") or "").splitlines()
                    ],
                    f"    signals={item['signals'] or '(empty body)'}",
                    f"    body_length={item.get('body_chars', 0)}{body_note}",
                ]
            )
            + (f"    {dedup_note}" if dedup_note else "")
            + body_block
        )

    same_body_groups = [ids for ids in hashes.values() if len(ids) > 1]
    if same_body_groups:
        lines.append("Same-body groups: " + "; ".join(",".join(ids) for ids in same_body_groups))
    return "\n".join(lines)
