"""goal 的「身份」从哪来：平台固定句的题名，以及无身份时向平台补一次元数据。

实测依据（2026-10-07，349 个 session / 285 条笔记）：

* 平台最常用的启动句是 ``用 ctf2 工具解练习场 <pid> 的题目 <cid>：<name>。``，
  签名（``challenge_class_signature``）对 ``：Quoted-printable`` 这种**不带方括号、
  不带引号**的题名**返回空串** —— `_CLASS_TAG_RE` 要方括号、`_CLASS_QUOTED_RE`
  要引号。带方括号的 ``[HDCTF2019]信号分析`` 一直有效，正是它掩盖了这个 bug。
* 结果是 349 个 session 里 **164 个（47%）的 goal 完全无身份**（无类别签名、无
  host/IP、无方括号题名），注入查询只剩「origin + goal 原文」这一条，于是**任何
  以题目为键的笔记都够不着**：那条记录了所需手法的笔记实测 score 0.000、交集 0，
  注入退化成「从 N 条抄了同一句 goal 的 auto 笔记里随便挑 3 条」。
* 同一句模板 ``capture the flag 解出附件 flag（misc forensics 取证 incident response）``
  出现 17 次、**11 次未解出**（65%，全库最差）。

所以本文件钉两件事：题名必须算身份（A），无身份时用平台元数据补一条 class 查询（B）。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent import playbook as pb
from vulnclaw.agent import solver

PRACTICE = "b9bbb32f-f186-458f-b90b-12440c0f6aea"
CHALLENGE = "33143a25-6c9e-4a44-8b41-2e7bf4d0b0f1"
SENTENCE = f"用 ctf2 工具解练习场 {PRACTICE} 的题目 {CHALLENGE}："
#: 触发本轮排查的那个 goal：平台自带描述模板，不含任何身份。
TEMPLATE_GOAL = "capture the flag 解出附件 flag（misc forensics 取证 incident response）"
#: 有 host 的 goal 不需要补元数据 —— URL 本身就是跨实例可复用的那个 token。
HOST_GOAL = "attack http://10.0.172.250:80, capture the flag and output it"


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


_UNSET: object = object()


def _run_injection(*, origin: str, goal: str, identity_hint: object = _UNSET):
    notices: list[str] = []
    events: list[tuple[str, dict]] = []
    runtime = SimpleNamespace(prior_playbook_brief="")
    extra = {} if identity_hint is _UNSET else {"identity_hint": identity_hint}
    hits = solver._inject_prior_playbooks(
        origin=origin,
        goal=goal,
        runtime=runtime,
        stream_sink=SimpleNamespace(on_notice=notices.append),
        emit=lambda kind, payload: events.append((kind, payload)),
        **extra,
    )
    return hits, notices, events, runtime


# ── A：任务句里的题名 ──────────────────────────────────────────────────────

def test_a_plain_title_in_the_task_sentence_is_an_identity():
    """改前这里是空串：题名就在句子里，抽取器却只认方括号和引号。"""
    sig = pb.challenge_class_signature(
        SENTENCE + "Quoted-printable。解题过程中用 ctf2_agent_log_note 记录思路。"
    )
    assert "Quoted-printable" in sig


def test_a_title_with_parentheses_and_slashes_survives_intact():
    sig = pb.challenge_class_signature(SENTENCE + "传感器 (Sensor, Manchester/OOK)。")
    assert "传感器 (Sensor, Manchester/OOK)" in sig


def test_a_bracketed_title_keeps_the_tag_without_padding_the_query():
    """方括号题名走 ``_CLASS_TAG_RE``，题名本身**不再**叠加进去（round-9 审查）。

    实测（224 条真实 goal + 真实笔记库，查询列表 = target fingerprint + class）：
    把任务句题名并进**已有**签名会让 11 条目标的查询结果集改变，其中
    ``[GeoServer] CVE-2024-36401`` 丢掉了对口的 ``geoserver-cve-2024-36401-wfs-jxpath-rce``
    —— ``Playbook.score`` 是「查询词被笔记命中的比例」，查询变长只会降分，而任务句原文
    又恰好出现在 auto 笔记里，curated 笔记因此被挤出 ``limit=2``。题名现在是**兜底**：
    只在其它抽取器一无所获时使用（见下面两条用例）。
    """
    sig = pb.challenge_class_signature(SENTENCE + "[HDCTF2019]信号分析。")
    assert "HDCTF2019" in sig, "方括号标签一直是能用的那条路径"
    assert "信号分析" not in sig, "有身份时不再叠加题名，否则会挤掉对口笔记"


def test_a_task_title_that_only_pads_an_existing_identity_is_skipped():
    """同一条目标句：有 CVE 身份时不加题名，没有身份时题名兜底。"""
    with_cve = pb.challenge_class_signature(SENTENCE + "[ActiveMQ]CVE-2015-5254 未授权反序列化")
    assert "CVE-2015-5254" in with_cve
    assert "未授权反序列化" not in with_cve


def test_a_bare_id_after_the_colon_does_not_masquerade_as_a_title():
    """句子总是以 id 后接冒号结尾，所以捕获到 id 形态就说明题名根本没写。"""
    sig = pb.challenge_class_signature(SENTENCE + "f3bc-4d61-9612-85421ee6452c")
    assert "f3bc-4d61-9612-85421ee6452c" not in sig


def test_the_generic_template_goal_still_has_no_identity():
    """这正是 B 的触发条件 —— 不能因为 A 的改动凭空长出身份。"""
    assert pb.challenge_class_signature(TEMPLATE_GOAL) == ""


# ── B：无身份时向平台补一条查询 ────────────────────────────────────────────

def test_only_a_goal_without_a_host_is_worth_a_platform_lookup():
    assert solver._goal_names_a_target(HOST_GOAL) is True
    assert solver._goal_names_a_target(TEMPLATE_GOAL) is False


def test_an_unusable_ref_yields_no_hint_and_never_raises():
    """契约：跑到关键路径上，任何失败都只能是「没有 hint」。"""
    solver._PLATFORM_HINT_MEMO.clear()
    assert solver._platform_identity_hint("") == ""
    assert solver._platform_identity_hint("just-a-bare-host") == ""
    assert solver._platform_identity_hint("nosuchplatform:practice:a:b") == ""


def test_the_hint_is_resolved_once_per_ref(monkeypatch):
    """一次 run 解一次 ref；后续 turn（以及失败）不重复付网络代价。"""
    solver._PLATFORM_HINT_MEMO.clear()
    import vulnclaw.platforms.bootstrap as bootstrap
    import vulnclaw.platforms.registry as registry

    seen: list[str] = []

    class _Adapter:
        def parse_ref(self, tail: str) -> str:
            return tail

        async def read_challenge(self, ref: str):
            seen.append(ref)
            return SimpleNamespace(
                name="信号分析", category="MISC", difficulty="", attachments=()
            )

    monkeypatch.setattr(bootstrap, "ensure_adapters", lambda: None)
    monkeypatch.setattr(registry, "adapter_for", lambda token: _Adapter())

    first = solver._platform_identity_hint("ctf2:practice:p:c")
    second = solver._platform_identity_hint("ctf2:practice:p:c")
    assert first == "信号分析 category MISC"
    assert second == first
    assert len(seen) == 1, "每个 ref 每个进程只查一次"


def test_an_identity_free_goal_is_looked_up_by_the_platform_metadata(monkeypatch):
    captured: dict[str, list[tuple[str, str]]] = {}

    def _fake_lookup(queries):
        captured["queries"] = list(queries)
        return [], []

    monkeypatch.setattr(solver, "_lookup_prior_playbooks", _fake_lookup)
    monkeypatch.setattr(
        solver, "_platform_identity_hint", lambda origin: "信号分析 category MISC sign.wav"
    )

    hits, notices, _events, _runtime = _run_injection(
        origin="ctf2:practice:p:c", goal=TEMPLATE_GOAL
    )
    assert hits == 0
    kinds = dict(captured["queries"])
    assert kinds["class"] == "信号分析 category MISC sign.wav"
    assert any("no challenge identity" in n for n in notices), notices


def test_a_host_goal_does_not_spend_a_platform_lookup(monkeypatch):
    spent: list[str] = []
    monkeypatch.setattr(solver, "_lookup_prior_playbooks", lambda queries: ([], []))
    monkeypatch.setattr(
        solver, "_platform_identity_hint", lambda origin: spent.append(origin) or "never"
    )
    _run_injection(origin="http://10.0.172.250:80", goal=HOST_GOAL)
    assert spent == [], "URL 本身就是那个跨实例可复用的 token，无需再问平台"


def test_the_hint_rescues_a_note_the_bare_goal_cannot_reach(store, monkeypatch):
    """端到端：同一个 goal、同一条笔记，差别只在平台是否答得出题目身份。

    笔记按题目为键（``信号分析`` / ``Manchester`` / ``sign.wav``），与 goal 模板零
    交集 —— 这正是实测里 score 0.000 的那种笔记。

    ``_platform_identity_hint`` 本身**不打桩**：让真实的 memo / 线程 / 异常兜底都跑
    一遍，只把最外层的平台适配器换成假的；对认不出的 ref 抛错，来模拟"平台答不出"。
    """
    pb.save_playbook(
        name="信号分析 (Manchester/OOK)",
        fingerprint="MISC 信号分析 Manchester OOK 解调 sign.wav 位反转 sensor ID 校验",
        steps=(
            "LOCK: OOK + 802.3 Manchester 的传感器包，先把 sign.wav 包络解调成比特流，"
            "再按 8 bit 反转还原，最后用题面给出的 sensor ID 做校验。"
        ),
        status="validated",
    )

    import vulnclaw.platforms.bootstrap as bootstrap
    import vulnclaw.platforms.registry as registry

    resolvable = "ctf2:practice:b9bbb32f:01e78f03"

    class _Adapter:
        def parse_ref(self, tail: str) -> str:
            token = f"ctf2:{tail}"
            if resolvable.rsplit(":", 1)[-1] not in token:
                raise RuntimeError("platform cannot describe this ref")
            return token

        async def read_challenge(self, ref: str):
            return SimpleNamespace(
                name="[HDCTF2019]信号分析",
                category="MISC",
                difficulty="",
                attachments=(SimpleNamespace(name="sign.wav"),),
            )

    monkeypatch.setattr(bootstrap, "ensure_adapters", lambda: None)
    monkeypatch.setattr(registry, "adapter_for", lambda token: _Adapter())
    solver._PLATFORM_HINT_MEMO.clear()

    # 平台答不出这个 ref：goal 与笔记零交集，一条都注入不了。
    blind, _notices, _events, _runtime = _run_injection(
        origin="ctf2:practice:b9bbb32f:ffffffff", goal=TEMPLATE_GOAL
    )
    assert blind == 0

    # 平台答得出：同一条笔记变得可达。
    hits, notices, events, runtime = _run_injection(origin=resolvable, goal=TEMPLATE_GOAL)
    assert hits >= 1, "平台元数据必须让这条笔记可达"
    assert "Prior-run notes" in runtime.prior_playbook_brief
    assert events and events[0][0] == "playbook_injected"
    assert any("no challenge identity" in n for n in notices), notices


# ── C：解析必须离开事件循环（round-9 事故：同步等待卡住整个 loop） ─────────────

def test_the_solve_path_looks_the_hint_up_without_stalling_the_loop(monkeypatch):
    """回归：``pool.submit(_fetch).result(timeout=8.0)`` 阻塞的是**调用线程**。

    原实现的注释写着「fetch runs in a worker thread so a caller that is already
    inside an event loop (or a hung socket) cannot stall the solve」——worker 只兜住了
    socket，等待仍发生在调用线程，而唯一的生产调用者就是 solve 协程，所以每个无身份
    的 run 都把 loop（以及 loop 上的兄弟协程）卡住最多 ``_PLATFORM_HINT_TIMEOUT``。

    这里用一个 0.3s 的慢查询 + 一个每 20ms 走一步的兄弟协程钉住它：兄弟协程必须在
    查询进行期间持续推进。若有人把 ``_platform_identity_hint_async`` 简化回同步调用，
    本用例会因为兄弟协程几乎不动而失败。
    """
    import asyncio
    import time

    solver._PLATFORM_HINT_MEMO.clear()
    ticks: list[float] = []

    def _slow_fetch(origin: str) -> str:
        time.sleep(0.3)
        return "信号分析 category MISC"

    monkeypatch.setattr(solver, "_fetch_platform_identity", _slow_fetch)

    # 窗口必须在查询**开始之前**算好：若在兄弟协程体里算，它只会在查询结束后才开始
    # 计时，于是无论 loop 有没有被占住都能凑够 tick 数 —— 那样的用例抓不住回归
    # （第一版就是这么写的，用「故意同步阻塞」的变体验证时会误过）。
    deadline = time.monotonic() + 0.3

    async def main() -> str:
        async def sibling() -> None:
            while time.monotonic() < deadline:
                ticks.append(time.monotonic())
                await asyncio.sleep(0.02)

        task = asyncio.ensure_future(sibling())
        try:
            return await solver._platform_identity_hint_async("ctf2:practice:p:c")
        finally:
            await task

    started = time.monotonic()
    hint = asyncio.run(main())
    elapsed = time.monotonic() - started

    assert hint == "信号分析 category MISC"
    assert elapsed >= 0.3, "慢查询必须真的发生过，否则本用例没有说服力"
    assert len(ticks) >= 5, f"兄弟协程在查询期间只推进了 {len(ticks)} 次 —— loop 被占住了"


def test_the_async_form_keeps_the_never_raises_and_memo_contract(monkeypatch):
    """异步形态必须保持同步形态的契约：不抛、把失败也 memo 化。"""
    import asyncio

    solver._PLATFORM_HINT_MEMO.clear()
    calls: list[str] = []

    def _boom(origin: str) -> str:
        calls.append(origin)
        raise RuntimeError("platform cannot describe this ref")

    monkeypatch.setattr(solver, "_fetch_platform_identity", _boom)

    first = asyncio.run(solver._platform_identity_hint_async("ctf2:practice:p:c"))
    second = asyncio.run(solver._platform_identity_hint_async("ctf2:practice:p:c"))

    assert first == "" and second == ""
    assert calls == ["ctf2:practice:p:c"], "失败也要 memo，不能每个 turn 重查一次"


def test_a_pre_resolved_hint_does_not_trigger_the_blocking_form(monkeypatch):
    """solve 路径在 loop 之外解析好 hint 再传进来，注入器不得再同步查一次。"""
    captured: dict[str, list[tuple[str, str]]] = {}

    def _fake_lookup(queries):
        captured["queries"] = list(queries)
        return [], []

    def _boom(origin: str):  # pragma: no cover - 只有回归时才会被调用
        raise AssertionError(
            "blocking _platform_identity_hint must not run when the solve path "
            "already resolved the hint off-loop"
        )

    monkeypatch.setattr(solver, "_lookup_prior_playbooks", _fake_lookup)
    monkeypatch.setattr(solver, "_platform_identity_hint", _boom)

    hits, notices, _events, _runtime = _run_injection(
        origin="ctf2:practice:p:c", goal=TEMPLATE_GOAL, identity_hint="信号分析 category MISC"
    )
    assert hits == 0
    assert dict(captured["queries"])["class"] == "信号分析 category MISC"
    assert any("no challenge identity" in n for n in notices), notices


def test_an_unresolved_hint_falls_back_to_the_sync_form(monkeypatch):
    """同步调用方（含既有 9 处测试）传 None 时仍走阻塞形态 —— 契约不变。"""
    captured: dict[str, list[tuple[str, str]]] = {}

    def _fake_lookup(queries):
        captured["queries"] = list(queries)
        return [], []

    monkeypatch.setattr(solver, "_lookup_prior_playbooks", _fake_lookup)
    monkeypatch.setattr(
        solver, "_platform_identity_hint", lambda origin: "信号分析 category MISC"
    )
    _run_injection(origin="ctf2:practice:p:c", goal=TEMPLATE_GOAL, identity_hint=None)
    assert dict(captured["queries"])["class"] == "信号分析 category MISC"


def test_the_identity_free_gate_matches_the_injector_branch():
    """生产调用点与注入器分支共用同一个判定，不允许各自漂移。"""
    assert solver._goal_is_identity_free(TEMPLATE_GOAL) is True
    assert solver._goal_is_identity_free(HOST_GOAL) is False
    # A 的改动在这里也要生效：题名本身就算身份，不该再花一次平台请求。
    assert solver._goal_is_identity_free(SENTENCE + "Quoted-printable。") is False
