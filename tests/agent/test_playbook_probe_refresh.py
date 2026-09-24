"""探测后按**实测特征**重查笔记库，并把"换条目"打进运行日志。

背景（交接文档 §3 任务 1）：开局的查询键是**题名**，信息量极低 —— 真实写法
``([Weblogic]SSRF)`` 下 `challenge_class_signature` 只有 ``Weblogic ssrf``。整轮不会再评估，
除非模型自己去调 `lookup_playbook` 工具。而第一次真实响应里有的是可用特征：
页面标题、``Server`` / ``X-Powered-By`` 头、页面自己链接的路径、表单字段名。

本文件的用例分两类：

* **抽取**：`probe_signature` 只从已记录的 HTTP 证据里取特征，复用
  `builtin_tools` 里现成的 helper（不另写一套抽取逻辑），并且不碰网络、不调模型；
* **行为**：换条目必须同时满足"特征变了"且"答案变了"，换的时候必须
  emit ``playbook_refreshed`` + 操作者可见 notice；没换要留旧简报；异常不得中断 solve。
"""

from __future__ import annotations

import json
from types import SimpleNamespace

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent import playbook_refresh as pr
from vulnclaw.agent import solver
from vulnclaw.agent.agent_state import AgentState, EvidenceRecord

GOAL = "Solve CTF2 challenge [Weblogic]CVE-2017-10271 (category Real, difficulty Easy)"
ORIGIN = "http://direct-ctf2.dasctf.com:27532"

LONG_STEPS = (
    "LOCK: /wls-wsat/CoordinatorPortType is unauthenticated; the flag is written into "
    "the docroot served by /bea_wls_internal/. CONFIRMED: ProcessBuilder.start() is "
    "non-blocking, so a timing oracle is invalid and the command does run; write a JSP "
    "shell into the exploded docRoot and read the flag from it. ANGLES: [hit] xmldecoder."
)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _write_note(slug: str, name: str, fingerprint: str, *, source: str = pb.SOURCE_CURATED) -> None:
    block = [
        "---",
        f"name: {name}",
        f"fingerprint: {fingerprint}",
        "status: validated",
        f"source: {source}",
        "---",
        "",
        LONG_STEPS,
        "",
    ]
    (pb.PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")


def _probe_output(*, url: str, title: str, server: str, powered_by: str = "", body: str = "") -> str:
    """One recorded ``http_probe_batch`` result, in the tool's real output shape.

    Shape copied from ``builtin_tools._format_http_probe_batch``: the status line
    carries ``title=...``, ``response_headers=`` is a one-line JSON object and the body
    follows an indented ``body:`` marker.
    """
    headers = {"Server": server, "Content-Type": "text/html"}
    if powered_by:
        headers["X-Powered-By"] = powered_by
    page = body or f"<html><head><title>{title}</title></head><body>ok</body></html>"
    return "\n".join(
        [
            "# http_probe_batch results (1 request(s))",
            f"[0] GET 200 len={len(page)} hash=abc123 42ms title={title!r}",
            f"    url={url}",
            f"    response_headers={json.dumps(headers, separators=(',', ':'))}",
            f"    request=GET {url}",
            "    signals=(none)",
            f"    body_length={len(page)}",
            "    body:",
            "\n".join(f"        {line}" for line in page.splitlines()),
        ]
    )


def _evidence(raw: str, *, evidence_id: str = "e001", tool: str = "http_probe_batch"):
    return EvidenceRecord(id=evidence_id, tool=tool, content=raw, summary=raw[:80])


WEBLOGIC_PAGE = _probe_output(
    url="http://direct-ctf2.dasctf.com:27532/console/login/LoginForm.jsp",
    title="Weblogic Server Console",
    server="Weblogic Server 12.2.1.3",
    powered_by="Servlet/3.1 JSP/2.3",
    body=(
        "<html><head><title>Weblogic Server Console</title></head><body>"
        '<a href="/wls-wsat/CoordinatorPortType">wls</a>'
        '<a href="/bea_wls_internal/">docroot</a>'
        '<form action="/console/login/LoginForm.jsp" method="post">'
        '<input type="text" name="j_username">'
        '<input type="password" name="j_password">'
        "</form></body></html>"
    ),
)

OTHER_PAGE = _probe_output(
    url="http://direct-ctf2.dasctf.com:27532/",
    title="ThinkPHP ThinkPHP",
    server="nginx",
    powered_by="PHP/7.2.1",
    body=(
        "<html><head><title>ThinkPHP ThinkPHP</title></head><body>"
        '<a href="/index.php?s=captcha">captcha</a>'
        '<a href="/public/index.php">public</a>'
        '<form action="/index.php?s=index" method="post">'
        '<input type="text" name="username">'
        "</form></body></html>"
    ),
)


def _runtime(**extra):
    runtime = SimpleNamespace(prior_playbook_brief="")
    for key, value in extra.items():
        setattr(runtime, key, value)
    return runtime


def _refresh(runtime, evidence, *, notices=None, events=None):
    notices = notices if notices is not None else []
    events = events if events is not None else []
    changed = solver._refresh_prior_playbooks_after_probe(
        origin=ORIGIN,
        goal=GOAL,
        runtime=runtime,
        evidence=evidence,
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: events.append((kind, payload)),
    )
    return changed, notices, events


# ── 抽取：只用实测特征，且复用现成 helper ─────────────────────────────────

def test_the_query_is_built_from_the_measured_page():
    signature = pr.probe_signature([_evidence(WEBLOGIC_PAGE)])
    lowered = signature.lower()
    assert "weblogic" in lowered, "the page title must be used"
    assert pr._normalized(signature), "the query must not be empty"
    # 头、路径、表单字段名都要出现（都是"实测的页面特征"）
    assert "12.2.1.3" in lowered or "12" in lowered, signature
    for expected in ("wls", "wsat", "j_username", "j_password"):
        assert expected in lowered, f"{expected} missing from {signature!r}"


def test_the_query_carries_the_powered_by_header():
    signature = pr.probe_signature([_evidence(WEBLOGIC_PAGE)])
    assert "servlet" in signature.lower() or "jsp" in signature.lower(), signature


# ── 真实运行里模型用的工具，不是制式探测工具 ────────────────────────────────
#
# 这是第一组冷/热配对实测发现的最严重问题：真实 CTF2 运行里模型调用的是
# `python_execute`(8 次) 与 `shell_command`(5 次)，**从不**调用
# `http_probe_batch` / `fetch` / `http_request`（日志里 `body:` 标记与
# `response_headers=` 行各出现 0 次）。当时 `HTTP_EVIDENCE_TOOLS` 只列了制式工具，
# 于是 `probe_signature` 对每次真实运行都返回 ""，**整个重查是死代码**，
# 而单测因为夹具用了制式格式而全绿。

def test_python_execute_output_is_readable_evidence():
    """模型的 python_execute 输出（没有 body: 标记）必须能取到特征。"""
    raw = (
        "[+] Python execution result (trusted-local): probe\n"
        "GET /wls-wsat/CoordinatorPortType -> 200 :: 'Web Services WSAT10Service'\n"
        "GET /bea_wls_internal/ -> 200 len=0\n"
    )
    signature = pr.probe_signature([_evidence(raw, tool="python_execute")])
    assert signature, "a python_execute probe result must yield a query"
    assert "wls" in signature.lower() and "wsat" in signature.lower(), signature


def test_shell_command_curl_output_is_readable_evidence():
    raw = (
        "HTTP/1.1 200 OK\n"
        "Server: Weblogic Server 10.3.6\n"
        "Content-Type: text/html\n\n"
        '<html><head><title>Weblogic Server Console</title></head></html>'
    )
    signature = pr.probe_signature([_evidence(raw, tool="shell_command")])
    assert "weblogic" in signature.lower(), signature


def test_the_evidence_tool_set_covers_what_the_model_actually_calls():
    """名单必须包含实测会被调用的工具；否则重查只会在纸面上工作。"""
    for tool in ("python_execute", "shell_command", "http_probe_batch", "fetch"):
        assert tool in pr.HTTP_EVIDENCE_TOOLS, tool


def test_a_tool_plumbing_output_yields_no_query():
    """只有工具自身的管道信息 → 不是页面特征 → 不许换简报。"""
    raw = (
        "[+] Python execution result (trusted-local): cmd='true' status=500 "
        "elapsed=0.4s cmd='sleep 6' status=500 elapsed=0.2s\n"
    )
    assert pr.probe_signature([_evidence(raw, tool="python_execute")]) == ""


def test_a_server_error_page_yields_no_query():
    """实测：运行里第一条 HTTP 结果是未授权错误页，标题是 "Error 404--Not Found"。

    它是真页面、有真 `<title>`，能过"这是页面吗"的所有检查，却不标识任何题目 ——
    用它换简报会把按题名建好的简报换成按模板套话建的，比不换更差。
    """
    raw = (
        "status: 500 o.txt -> 404\n"
        '<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.0 Draft//EN">\n'
        "<HTML><HEAD><TITLE>Error 404--Not Found</TITLE></HEAD>\n"
        '<BODY BGCOLOR="black" TEXT="white"><FONT FACE="Helvetica" COLOR="black">'
        "Not Found</FONT></BODY></HTML>"
    )
    assert pr.probe_signature([_evidence(raw, tool="python_execute")]) == ""


def test_a_page_with_a_real_title_is_never_treated_as_template_noise():
    """反面对照：真实框架页面的标题必须留下（不能把整套错误页过滤误伤真页面）。"""
    raw = "<html><head><title>Weblogic Server Console</title></head><body>ok</body></html>"
    signature = pr.probe_signature([_evidence(raw, tool="python_execute")])
    assert "weblogic" in signature.lower(), signature


def test_generic_paths_and_params_do_not_flood_the_query():
    """`/static/`、`/api/`、`?id=` 这类人人都有，进了查询就是噪声。"""
    raw = _probe_output(
        url="http://t/",
        title="Shop",
        server="nginx",
        body=(
            '<a href="/static/css/app.css">a</a><a href="/api/v1/items?id=3">b</a>'
            '<a href="/login">c</a><a href="/product/detail?sku=9">d</a>'
        ),
    )
    signature = pr.probe_signature([_evidence(raw)]).lower()
    assert "product" in signature and "detail" in signature, signature
    assert "sku" in signature, signature
    assert "static" not in signature and "login" not in signature, signature


def test_the_query_has_a_length_cap():
    """查询越长，`score`(=查询 token 被笔记包含的比例)越低 —— 必须封顶。"""
    many = "".join(f'<a href="/alpha{i}/beta{i}?gamma{i}=1">x</a>' for i in range(40))
    raw = _probe_output(url="http://t/", title="A B C D E F", server="x", body=many)
    signature = pr.probe_signature([_evidence(raw)])
    assert len(pr._normalized(signature)) <= pr.MAX_PROBE_TOKENS


def test_duplicate_values_are_deduped():
    group = {}
    assert pr._dedupe_keep_order(["Weblogic", "weblogic", "WEBLOGIC"], 10) == ["Weblogic"]
    assert group == {}


def test_no_http_evidence_means_no_query():
    """非 HTTP 证据（shell / python 输出）不能被当成页面特征。"""
    records = [
        _evidence("total 0\ndrwxr-xr-x", evidence_id="e001", tool="shell_command"),
        _evidence("print('hi')", evidence_id="e002", tool="python_execute"),
    ]
    assert pr.probe_signature(records) == ""


def test_a_repeated_probe_does_not_change_the_signature():
    """同一页面探两次，查询必须一模一样（否则每次探测都抖动提示词）。"""
    first = pr.probe_signature([_evidence(WEBLOGIC_PAGE, evidence_id="e001")])
    second = pr.probe_signature([_evidence(WEBLOGIC_PAGE, evidence_id="e002")])
    assert not pr.new_signature_only(first, second)
    assert pr.new_signature_only("", first)


def test_two_different_pages_are_different_queries():
    assert pr.new_signature_only(
        pr.probe_signature([_evidence(WEBLOGIC_PAGE)]),
        pr.probe_signature([_evidence(OTHER_PAGE)]),
    )


# ── 替换判据 ──────────────────────────────────────────────────────────────

def test_a_different_hit_set_replaces():
    replace, reason = pr.should_replace(
        [{"slug": "old", "score": 0.5}], [{"slug": "new", "score": 0.9}]
    )
    assert replace and "hit set changed" in reason


def test_a_swapped_note_replaces():
    """换的是"哪几条笔记进提示词"，判据就只看条目集合。"""
    replace, reason = pr.should_replace(
        [{"slug": "a"}, {"slug": "b"}], [{"slug": "b"}, {"slug": "a"}]
    )
    assert replace is False, f"same set, different order must not rewrite the prompt: {reason}"
    replace, _ = pr.should_replace([{"slug": "a"}], [{"slug": "b"}])
    assert replace is True


def test_a_score_only_change_does_not_replace():
    """同一批笔记、分数变了：不换（分数没人能标定，且换了也看不出差别）。"""
    old = [{"slug": "same", "score": 0.500}]
    new = [{"slug": "same", "score": 0.123}]
    replace, reason = pr.should_replace(old, new)
    assert not replace and "same notes" in reason


def test_an_empty_new_result_never_replaces():
    replace, reason = pr.should_replace([{"slug": "old", "score": 0.9}], [])
    assert not replace and "kept the previous brief" in reason


# ── 端到端：重查真的换了简报、并进了日志 ──────────────────────────────────

def test_the_refresh_is_logged_when_the_notes_change(store):
    """验收的关键证据：`[playbook] refreshed <slug> score=…` 这一行。"""
    _write_note(
        "weblogic-wls",
        "Weblogic wls-wsat CoordinatorPortType",
        "weblogic server console wls wsat coordinatorporttype loginform",
    )
    _write_note(
        "thinkphp-captcha",
        "ThinkPHP captcha RCE",
        "thinkphp captcha index public username nginx",
    )
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = _runtime()
    # 开局注入（题名键）——这台假设先命中了 ThinkPHP 那条
    opening = [{"slug": "thinkphp-captcha", "score": 0.5, "query_kind": "class"}]
    runtime.prior_playbook_brief = "OLD BRIEF"
    runtime.prior_playbook_slugs = [m["slug"] for m in opening]
    runtime.prior_playbook_scores = {"thinkphp-captcha": 0.5}

    changed, notices, events = _refresh(runtime, [_evidence(WEBLOGIC_PAGE)], notices=notices, events=events)

    assert changed is True
    assert runtime.prior_playbook_brief != "OLD BRIEF"
    assert "Weblogic wls-wsat CoordinatorPortType" in runtime.prior_playbook_brief
    assert "Replace only steps" not in runtime.prior_playbook_brief
    # 事件
    kind, payload = events[-1]
    assert kind == "playbook_refreshed"
    assert payload["hits"], payload
    assert payload["hits"][0]["slug"] == "weblogic-wls"
    assert payload["query"], "the event must show what was asked"
    assert payload["replaced"] == ["thinkphp-captcha"]
    # 操作者可见的一行
    refreshed = [n for n in notices if "refreshed" in n]
    assert refreshed, notices
    assert "weblogic-wls" in refreshed[0] and "score=" in refreshed[0]
    assert "probe key:" in refreshed[0]


def test_the_replaced_brief_keeps_the_three_usage_constraints(store):
    """换简报不得换掉那三条使用约束（相关性判断靠它们）。"""
    _write_note("weblogic-wls", "Weblogic wls", "weblogic server console wls wsat")
    runtime = _runtime(prior_playbook_brief="OLD", prior_playbook_slugs=[], prior_playbook_scores={})
    changed, _, _ = _refresh(runtime, [_evidence(WEBLOGIC_PAGE)])
    assert changed
    brief = runtime.prior_playbook_brief
    assert "OWN stated vulnerability class wins" in brief
    assert "VERIFY its stated premise on THIS target" in brief
    assert "attack the vulnerability the challenge actually asks for" in brief


def test_an_unchanged_page_keeps_the_brief(store):
    _write_note("weblogic-wls", "Weblogic wls", "weblogic server console wls wsat")
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = _runtime(prior_playbook_brief="OLD", prior_playbook_slugs=[], prior_playbook_scores={})
    first, notices, events = _refresh(runtime, [_evidence(WEBLOGIC_PAGE, evidence_id="e001")], notices=notices, events=events)
    assert first is True
    brief_after_first = runtime.prior_playbook_brief
    # 同一页面再来一条证据：查询相同 → 不换、不抖、不再发事件
    second, notices2, events2 = _refresh(
        runtime, [_evidence(WEBLOGIC_PAGE, evidence_id="e002")], notices=[], events=[]
    )
    assert second is False
    assert runtime.prior_playbook_brief == brief_after_first
    assert events2 == []
    assert notices2 == [], "an unchanged probe must not spam the operator log"


def test_already_consumed_evidence_is_not_re_read(store):
    _write_note("weblogic-wls", "Weblogic wls", "weblogic server console wls wsat")
    runtime = _runtime(prior_playbook_brief="OLD", prior_playbook_slugs=[], prior_playbook_scores={})
    record = _evidence(WEBLOGIC_PAGE, evidence_id="e001")
    assert _refresh(runtime, [record])[0] is True
    assert _refresh(runtime, [record])[0] is False


def test_a_refresh_that_matches_nothing_keeps_the_old_brief(store):
    """空结果不是"开局召回错了"的证据，旧简报必须留着。"""
    _write_note(
        "weblogic-wls",
        "Weblogic wls-wsat",
        "weblogic server console wls wsat",
    )
    notices: list[str] = []
    runtime = _runtime(
        prior_playbook_brief="OPENING BRIEF",
        prior_playbook_slugs=["weblogic-wls"],
        prior_playbook_scores={"weblogic-wls": 0.9},
    )
    changed, notices, events = _refresh(runtime, [_evidence(OTHER_PAGE)], notices=notices)
    assert changed is False
    assert runtime.prior_playbook_brief == "OPENING BRIEF"
    assert events == []
    assert any("probe re-query" in n for n in notices), notices


def test_the_refresh_budget_is_bounded_and_reported(store):
    _write_note("weblogic-wls", "Weblogic wls", "weblogic server console wls wsat")
    notices: list[str] = []
    runtime = _runtime(
        prior_playbook_brief="OLD",
        prior_playbook_slugs=[],
        prior_playbook_scores={},
        prior_playbook_refresh_limit=1,
    )
    assert _refresh(runtime, [_evidence(WEBLOGIC_PAGE, evidence_id="e001")])[0] is True
    assert runtime.prior_playbook_refresh_count == 1
    # 预算用完之后：再来一个新页面也不再重查，并且把这件事说清楚
    changed, notices, events = _refresh(
        runtime, [_evidence(OTHER_PAGE, evidence_id="e002")], notices=notices
    )
    assert changed is False
    assert events == []
    assert any("budget spent" in n for n in notices), notices


def test_a_broken_extractor_cannot_break_the_run(store, monkeypatch):
    import vulnclaw.agent.builtin_tools as bt

    def _boom(*args, **kwargs):  # noqa: ARG001
        raise RuntimeError("extractor is broken")

    monkeypatch.setattr(bt, "_extract_html_title", _boom)
    runtime = _runtime(prior_playbook_brief="OLD")
    with pytest.raises(RuntimeError):
        # 函数自身不吞异常（调用点负责兜底），但绝不能把简报改坏
        _refresh(runtime, [_evidence(WEBLOGIC_PAGE)])
    assert runtime.prior_playbook_brief == "OLD"


def test_gated_rows_are_logged_after_a_probe_too(store):
    """被门槛挡掉的条目在重查路径上同样可见（否则查不出"为什么没注入"）。"""
    _write_note("weblogic-only", "Weblogic note", "weblogic")
    notices: list[str] = []
    runtime = _runtime(prior_playbook_brief="OLD", prior_playbook_slugs=[], prior_playbook_scores={})
    changed, notices, _ = _refresh(runtime, [_evidence(WEBLOGIC_PAGE)], notices=notices)
    assert changed is False, "a framework-only hit must not be injected by the re-query"
    assert "OLD" in runtime.prior_playbook_brief
    assert "Weblogic note" not in runtime.prior_playbook_brief
    assert any("gated" in n and "weblogic-only" in n for n in notices), notices


# ── 开局注入也要报"被挡条目" ───────────────────────────────────────────────

def test_the_opening_injection_logs_gated_rows(store):
    _write_note("weblogic-only", "Weblogic note", "weblogic")
    notices: list[str] = []
    hits = solver._inject_prior_playbooks(
        origin=ORIGIN,
        goal=GOAL,
        runtime=_runtime(),
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: None,
    )
    assert hits == 0
    assert any("gated 1 below the 2-token overlap floor" in n for n in notices), notices
    assert any("weblogic-only=1" in n for n in notices), notices


def test_the_opening_injection_reports_gated_rows_next_to_the_hits(store):
    """有命中时，"被挡了什么"也要一起说，否则看不到丢了哪些。"""
    _write_note(
        "weblogic-ok", "Weblogic CVE-2017-10271 real easy", "weblogic cve real easy"
    )
    _write_note("weblogic-only", "Weblogic other", "weblogic")
    notices: list[str] = []
    hits = solver._inject_prior_playbooks(
        origin=ORIGIN,
        goal=GOAL,
        runtime=_runtime(),
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: None,
    )
    assert hits >= 1
    assert any("injected" in n and "gated" in n for n in notices), notices


def test_the_injected_event_carries_the_overlap_count(store):
    """日志里要能看出"重叠了几个 token" —— 门槛的判据就是这个数。"""
    _write_note(
        "weblogic-ok", "Weblogic CVE-2017-10271 real easy", "weblogic cve real easy"
    )
    events: list[tuple[str, dict]] = []
    solver._inject_prior_playbooks(
        origin=ORIGIN,
        goal=GOAL,
        runtime=_runtime(),
        stream_sink=SimpleNamespace(on_notice=lambda m: None),
        emit=lambda kind, payload: events.append((kind, payload)),
    )
    _, payload = events[0]
    assert payload["hits"][0]["overlap_tokens"] >= 2


# ── 主循环接线：探测之后才重查 ────────────────────────────────────────────

class _Sink:
    def __init__(self):
        self.notices: list[str] = []
        self.chunks: list[str] = []

    def on_notice(self, message):
        self.notices.append(message)

    def on_chunk(self, text):
        self.chunks.append(text)


class _Context:
    def __init__(self, state):
        self.state = SimpleNamespace(agent_state=state, save=lambda: None)
        self.messages: list[str] = []

    def add_user_message(self, text):
        self.messages.append(text)

    def add_assistant_message(self, text):
        self.messages.append(text)


class _Agent:
    def __init__(self, state, runtime):
        self.context = _Context(state)
        self.runtime = runtime
        self._subagent_ctx = SimpleNamespace(event_sink=None)
        self.session_state = SimpleNamespace(task_constraints=None, target=ORIGIN)
        self.config = SimpleNamespace(safety=SimpleNamespace(python_execute_enabled=True))
        self.active_role = None
        # No `_finding_parser` attribute on purpose: the loop guards that hook with
        # hasattr(), and a None placeholder would be called instead of skipped.


def test_the_solve_loop_re_queries_after_the_first_probe(store, monkeypatch):
    """端到端：第 1 步没有证据 → 不重查；第 2 步拿到探测结果 → 重查并替换简报。"""
    import asyncio

    _write_note(
        "weblogic-wls",
        "Weblogic wls-wsat CoordinatorPortType",
        "weblogic server console wls wsat coordinatorporttype j_username",
    )
    state = AgentState()
    runtime = SimpleNamespace(
        blackboard=None, prior_playbook_brief="", auto_skill_input=""
    )
    agent = _Agent(state, runtime)
    sink = _Sink()
    events: list[tuple[str, dict]] = []
    calls = {"n": 0}

    async def _fake_llm(*args, **kwargs):  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 2:
            # 第一次探测的现场：工具结果已经落进证据
            state.evidence.append(_evidence(WEBLOGIC_PAGE, evidence_id="e001"))
        return ""

    monkeypatch.setattr(solver, "call_llm_auto", _fake_llm)
    monkeypatch.setattr(solver, "inject_messages", lambda agent: None)
    monkeypatch.setattr(solver, "subagents_available", lambda agent: False)

    async def _noop_finalize(*args, **kwargs):  # noqa: ARG001
        return ""

    monkeypatch.setattr(solver, "finalize_parent", _noop_finalize)
    monkeypatch.setattr(
        "vulnclaw.agent.playbook.capture_run_notes", lambda **kwargs: None
    )

    asyncio.run(
        solver._solve_impl(
            agent,
            origin=ORIGIN,
            goal=GOAL,
            max_steps=3,
            stream_sink=sink,
            on_event=lambda kind, payload: events.append((kind, payload)),
        )
    )

    refreshed = [payload for kind, payload in events if kind == "playbook_refreshed"]
    assert refreshed, [kind for kind, _ in events]
    assert refreshed[0]["hits"][0]["slug"] == "weblogic-wls"
    assert runtime.prior_playbook_brief, "the brief must be replaced"
    assert "Re-matched AFTER the first probe" in runtime.prior_playbook_brief
    assert any("refreshed" in n for n in sink.notices), sink.notices
    assert calls["n"] >= 2


def test_the_solve_loop_survives_a_broken_refresh(store, monkeypatch):
    """重查抛异常不得中断 solve（沿用现有 try/except 风格）。"""
    import asyncio

    state = AgentState()
    runtime = SimpleNamespace(
        blackboard=None, prior_playbook_brief="OPENING", auto_skill_input=""
    )
    agent = _Agent(state, runtime)
    calls = {"n": 0}

    async def _fake_llm(*args, **kwargs):  # noqa: ARG001
        calls["n"] += 1
        if calls["n"] == 2:
            state.evidence.append(_evidence(WEBLOGIC_PAGE, evidence_id="e001"))
        return ""

    def _boom(**kwargs):  # noqa: ARG001
        raise RuntimeError("refresh exploded")

    monkeypatch.setattr(solver, "call_llm_auto", _fake_llm)
    monkeypatch.setattr(solver, "inject_messages", lambda agent: None)
    monkeypatch.setattr(solver, "subagents_available", lambda agent: False)

    async def _noop_finalize(*args, **kwargs):  # noqa: ARG001
        return ""

    monkeypatch.setattr(solver, "finalize_parent", _noop_finalize)
    monkeypatch.setattr(solver, "_refresh_prior_playbooks_after_probe", _boom)
    monkeypatch.setattr(
        "vulnclaw.agent.playbook.capture_run_notes", lambda **kwargs: None
    )

    result = asyncio.run(
        solver._solve_impl(
            agent,
            origin=ORIGIN,
            goal=GOAL,
            max_steps=3,
            stream_sink=_Sink(),
            on_event=lambda kind, payload: None,
        )
    )
    assert calls["n"] >= 2, "the loop must keep running after a failed refresh"
    assert runtime.prior_playbook_brief == "OPENING"
    assert result is not None
