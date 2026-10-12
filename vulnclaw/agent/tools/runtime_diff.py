"""runtime_diff_probe: local parser/filter differential checks (regex + PHP serialize)."""

from __future__ import annotations

import asyncio
import base64
import re
import shutil
import tempfile
import time
from pathlib import Path
from typing import TYPE_CHECKING, Any
from urllib.parse import quote

from vulnclaw.agent.agent_state import one_line

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


_PHP_SERIALIZE_LENGTH_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])([OC]):([0-9]+):")
_PHP_SERIALIZE_STRING_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9_])s:([0-9]+):")


def _runtime_diff_candidates(args: dict[str, Any]) -> list[tuple[str, str]]:
    """Build a compact candidate table for parser/filter differential probing."""

    payload = str(args.get("payload") or "")
    explicit = args.get("candidates") or []
    mutations = args.get("mutations") or ["signed_lengths", "leading_zero_lengths"]
    if isinstance(mutations, str):
        mutations = [mutations]
    mutation_set = {str(item).strip().lower() for item in mutations if str(item).strip()}

    candidates: list[tuple[str, str]] = []
    if payload:
        candidates.append(("original", payload))

    if "signed_lengths" in mutation_set and payload:
        signed = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(r"\1:+\2:", payload)
        if signed != payload:
            candidates.append(("signed object/class lengths", signed))

    if "leading_zero_lengths" in mutation_set and payload:
        padded = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(
            lambda match: f"{match.group(1)}:0{match.group(2)}:",
            payload,
        )
        if padded != payload:
            candidates.append(("zero-padded object/class lengths", padded))

    if "lowercase_type" in mutation_set and payload:
        lowered = _PHP_SERIALIZE_LENGTH_TOKEN_RE.sub(
            lambda match: f"{match.group(1).lower()}:{match.group(2)}:",
            payload,
        )
        if lowered != payload:
            candidates.append(("lowercase object/class token", lowered))

    if "uppercase_string_type" in mutation_set and payload:
        upper_s = _PHP_SERIALIZE_STRING_TOKEN_RE.sub(r"S:\1:", payload)
        if upper_s != payload:
            candidates.append(("uppercase string token", upper_s))

    if isinstance(explicit, list):
        for index, item in enumerate(explicit, start=1):
            if isinstance(item, dict):
                value = str(item.get("payload") or item.get("value") or "")
                label = str(item.get("label") or f"candidate {index}")
            else:
                value = str(item or "")
                label = f"candidate {index}"
            if value:
                candidates.append((label, value))

    deduped: list[tuple[str, str]] = []
    seen: set[str] = set()
    for label, value in candidates:
        if value in seen:
            continue
        seen.add(value)
        deduped.append((label, value))
    return deduped[:40]


def _parse_python_regex(pattern: str) -> tuple[str, int]:
    """Parse a PCRE-style /pattern/flags string for lightweight local checks."""

    raw = str(pattern or "")
    flags = 0
    if len(raw) >= 2 and raw.startswith("/"):
        escaped = False
        for index in range(len(raw) - 1, 0, -1):
            if raw[index] != "/" or escaped:
                escaped = raw[index] == "\\" and not escaped
                continue
            body = raw[1:index]
            suffix = raw[index + 1 :]
            if "i" in suffix:
                flags |= re.IGNORECASE
            if "s" in suffix:
                flags |= re.DOTALL
            if "m" in suffix:
                flags |= re.MULTILINE
            return body, flags
    return raw, flags


def _execute_regex_diff_probe(args: dict[str, Any]) -> str:
    filter_regex = str(args.get("filter_regex") or args.get("regex") or "")
    candidates = _runtime_diff_candidates(args)
    if not filter_regex:
        return "[!] runtime_diff_probe regex mode requires filter_regex"
    if not candidates:
        return "[!] runtime_diff_probe requires payload or candidates"

    pattern, flags = _parse_python_regex(filter_regex)
    lines = [
        "# runtime_diff_probe - regex",
        f"filter_regex={filter_regex}",
        f"candidate_count={len(candidates)}",
    ]
    try:
        compiled = re.compile(pattern, flags)
    except re.error as exc:
        return f"[!] runtime_diff_probe invalid regex for Python check: {exc}"

    for index, (label, value) in enumerate(candidates, start=1):
        hit = bool(compiled.search(value))
        lines.extend(
            [
                f"\n[{index}] {label}",
                f"filter_hit={str(hit).lower()}",
                f"length={len(value)}",
                f"urlencoded={quote(value, safe='')}",
                f"raw={value}",
            ]
        )
    return "\n".join(lines)


def _strip_php_open_close_tags(code: str) -> str:
    text = str(code or "").strip()
    text = re.sub(r"^\s*<\?php", "", text, flags=re.IGNORECASE)
    text = re.sub(r"\?>\s*$", "", text)
    return text.strip()


def _b64_php_string(value: str) -> str:
    return base64.b64encode(str(value or "").encode("utf-8", errors="replace")).decode("ascii")


def _detect_target_runtime(agent: AgentContext, args: dict[str, Any]) -> str:
    # _agent_state_for_tool lives in the facade (depends on evidence store
    # helpers that stay there), so resolve it at call time.
    from vulnclaw.agent import builtin_tools as _bt

    explicit = str(args.get("target_runtime") or "").strip()
    if explicit:
        return one_line(explicit, 120)
    agent_state = _bt._agent_state_for_tool(agent)
    if agent_state is None:
        return ""
    for evidence in reversed(getattr(agent_state, "evidence", [])[-24:]):
        text = "\n".join(
            part
            for part in (
                getattr(evidence, "summary", ""),
                getattr(evidence, "preview", ""),
                getattr(evidence, "content", "")[:4000],
            )
            if part
        )
        match = re.search(r"\bPHP/([0-9]+(?:\.[0-9]+){0,2})\b", text, re.IGNORECASE)
        if match:
            return f"PHP/{match.group(1)}"
        match = re.search(r"\bPHP\s+([0-9]+(?:\.[0-9]+){0,2})\b", text, re.IGNORECASE)
        if match:
            return f"PHP/{match.group(1)}"
    return ""


def _build_php_runtime_diff_script(
    *,
    filter_regex: str,
    candidates: list[tuple[str, str]],
    class_defs: str,
) -> str:
    entries = []
    for label, payload in candidates:
        entries.append(
            "array('label'=>base64_decode('%s'),'payload'=>base64_decode('%s'))"
            % (_b64_php_string(label), _b64_php_string(payload))
        )
    class_block = _strip_php_open_close_tags(class_defs)
    return "\n".join(
        [
            "<?php",
            "error_reporting(E_ALL);",
            class_block,
            "$filter = base64_decode('%s');" % _b64_php_string(filter_regex),
            "$candidates = array(%s);" % ",".join(entries),
            "echo \"# runtime_diff_probe - php_serialize\\n\";",
            "echo \"local_php_version=\" . PHP_VERSION . \"\\n\";",
            "echo \"filter_regex=\" . $filter . \"\\n\";",
            "echo \"candidate_count=\" . count($candidates) . \"\\n\";",
            "foreach ($candidates as $i => $item) {",
            "    $label = $item['label'];",
            "    $payload = $item['payload'];",
            "    echo \"\\n[\" . ($i + 1) . \"] \" . $label . \"\\n\";",
            "    echo \"length=\" . strlen($payload) . \"\\n\";",
            "    if ($filter !== '') {",
            "        $hit = @preg_match($filter, $payload);",
            "        echo \"filter_hit=\" . var_export($hit, true) . \"\\n\";",
            "    } else {",
            "        echo \"filter_hit=not_tested\\n\";",
            "    }",
            "    ob_start();",
            "    $result = @unserialize($payload);",
            "    $ok = !($result === false && $payload !== 'b:0;');",
            "    if (is_object($result)) {",
            "        $result_class = get_class($result);",
            "    } else {",
            "        $result_class = '';",
            "    }",
            "    $result_type = gettype($result);",
            "    unset($result);",
            "    $side = ob_get_clean();",
            "    echo \"unserialize_ok=\" . ($ok ? 'true' : 'false') . \"\\n\";",
            "    echo \"result_type=\" . $result_type . \"\\n\";",
            "    if ($result_class !== '') { echo \"result_class=\" . $result_class . \"\\n\"; }",
            "    if ($side !== '') { echo \"side_effect_output=\" . json_encode($side) . \"\\n\"; }",
            "    echo \"urlencoded=\" . rawurlencode($payload) . \"\\n\";",
            "    echo \"raw=\" . $payload . \"\\n\";",
            "}",
            "?>",
        ]
    )


async def _execute_php_serialize_diff_probe(
    args: dict[str, Any],
    *,
    target_runtime: str = "",
) -> str:
    # The spawn seam and the sanitized environment stay in the facade namespace
    # (tests patch _spawn_captured there), so resolve them at call time.
    from vulnclaw.agent import builtin_tools as _bt

    filter_regex = str(args.get("filter_regex") or args.get("regex") or "")
    candidates = _runtime_diff_candidates(args)
    if not candidates:
        return "[!] runtime_diff_probe requires payload or candidates"

    php = shutil.which("php")
    if not php:
        return "[!] runtime_diff_probe php_serialize mode requires php in PATH"

    timeout_ms = max(1000, min(int(args.get("timeout_ms") or 10000), 120000))
    max_output_chars = int(args.get("max_output_chars") or 0)
    class_defs = str(args.get("class_defs") or "")
    script = _build_php_runtime_diff_script(
        filter_regex=filter_regex,
        candidates=candidates,
        class_defs=class_defs,
    )

    tmp_dir = Path(tempfile.mkdtemp(prefix="vulnclaw-runtime-diff-"))
    script_path = tmp_dir / "probe.php"
    script_path.write_text(script, encoding="utf-8")
    started = time.perf_counter()
    try:
        loop = asyncio.get_running_loop()
        returncode, proc_stdout, proc_stderr, proc_timed_out = await loop.run_in_executor(
            None,
            lambda: _bt._spawn_captured(
                [php, str(script_path)],
                cwd=str(tmp_dir),
                env=_bt.sanitized_exec_env(),
                timeout_s=timeout_ms / 1000,
            ),
        )
    finally:
        try:
            script_path.unlink(missing_ok=True)
            tmp_dir.rmdir()
        except Exception:
            pass

    if proc_timed_out:
        return (
            f"[!] runtime_diff_probe timed out after {timeout_ms}ms\n"
            "Output:\n(process tree terminated)"
        )

    elapsed_ms = int((time.perf_counter() - started) * 1000)
    output = proc_stdout or ""
    if proc_stderr:
        output += ("\n" if output else "") + "[stderr]\n" + proc_stderr
    if not output:
        output = "(no output)"
    raw = "\n".join(
        [
            f"Command: {php} {script_path.name}",
            f"Exit code: {returncode}",
            f"Wall time: {elapsed_ms}ms",
            "Output:",
            output,
        ]
    )
    local_match = re.search(r"local_php_version=([0-9]+(?:\.[0-9]+){0,2})", output)
    local_runtime = f"PHP/{local_match.group(1)}" if local_match else ""
    has_signed_candidate = any(label == "signed object/class lengths" for label, _ in candidates)
    target_is_php5 = bool(re.search(r"PHP/5(?:\.|$)", target_runtime, re.IGNORECASE))
    if target_runtime and local_runtime and target_runtime.lower() != local_runtime.lower():
        if target_is_php5 and has_signed_candidate:
            for label, payload in candidates:
                if label != "signed object/class lengths":
                    continue
                raw += (
                    "\n[remote_verification_required] signed object/class length candidate "
                    f"targets {target_runtime} and bypasses digit-only object filters. "
                    "REMOTE VERIFICATION OUTRANKS LOCAL unserialize_ok=false when the local "
                    "PHP runtime is newer/different. Replay this exact candidate against the "
                    "remote endpoint before declaring the bypass dead.\n"
                    f"remote_candidate_raw={payload}\n"
                    f"remote_candidate_urlencoded={quote(payload, safe='')}"
                )
        note = (
            f"[compatibility_note] target_runtime={target_runtime}; local_runtime={local_runtime}. "
            "Local parser behavior may differ from the target; do not discard filter-missed "
            "candidates solely because the local runtime rejected them."
        )
        if target_is_php5 and has_signed_candidate:
            note += (
                " PHP 5.x serialized parsers may accept signed object/class length tokens "
                "such as O:+n:/C:+n: while regex filters like /[oc]:\\d+:/i miss them; "
                "remote-verify the exact URL-encoded signed candidate."
            )
        raw += "\n" + note
    if max_output_chars > 0 and len(raw) > max_output_chars:
        clip = max_output_chars // 2
        return raw[:clip] + "\n...[truncated by max_output_chars]...\n" + raw[-clip:]
    return raw


async def execute_runtime_diff_probe(agent: AgentContext, args: dict[str, Any]) -> str:
    """Run compact local parser/filter differential checks.

    This tool is intentionally general-purpose: the model decides when a target
    has a regex/string filter in front of a runtime parser and needs a fast
    local table of "accepted by parser, missed by filter" candidates.
    """

    mode = str(args.get("mode") or args.get("parser") or "regex").strip().lower()
    if mode in {"regex", "generic", "filter"}:
        return _execute_regex_diff_probe(args)
    if mode in {"php_serialize", "php_unserialize", "php-serialize", "php"}:
        # The PHP runtime probe is an equivalent-arbitrary-execution primitive
        # (model-supplied class_defs are interpreted by php): it goes through
        # the same per-request approval gate as shell/python.
        from vulnclaw.agent.exec_gate import GateRequest, get_execution_gate

        class_defs = str(args.get("class_defs") or "")
        gate = get_execution_gate(getattr(agent, "config", None))
        outcome = await gate.authorize(
            GateRequest(
                kind="php_diff",
                display=class_defs or "(no class_defs; runtime diff only)",
                cwd="",
                detail=(
                    f"php runtime probe · filter={str(args.get('filter_regex') or '')[:120]}"
                    + (f" · target_runtime={_detect_target_runtime(agent, args)}"
                       if _detect_target_runtime(agent, args) else "")
                ),
            ),
            run_id=str(getattr(getattr(agent, "runtime", None), "run_id", "") or ""),
        )
        if not outcome.approved:
            return outcome.refusal_text("runtime_diff_probe(php)")
        return await _execute_php_serialize_diff_probe(
            args,
            target_runtime=_detect_target_runtime(agent, args),
        )
    return "[!] runtime_diff_probe mode must be regex or php_serialize"
