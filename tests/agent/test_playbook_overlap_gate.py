"""最小重叠门槛：把"单 token 查询满分命中"这种退化召回挡掉。

实测依据（2026-09-23，交接文档 §0/§3 任务 2）：

* `Playbook.score` = **查询 token 被笔记包含的比例** —— 它衡量的是**召回**，不是相关性；
* 于是查询只有 1 个 token（真实的 `([Weblogic]SSRF)` 写法下签名可能只有 `'Weblogic'`）
  时，**任何** Weblogic 笔记都拿满分 1.0，命中率 4/4 但其中没有相关性信息；
* 实测的伤害现场：一条 Weblogic XMLDecoder 反序列化笔记被注入进 Weblogic **SSRF** 题，
  日志词频显示运行被带偏（`ssrf` 28 → 3，`bea_wls_internal` 2 → 41）。

规则：**一次命中至少要与该条笔记重叠 2 个不同 token**（`MIN_OVERLAP_TOKENS`），
否则该条笔记不算命中。门槛在 `lookup_playbook_multi` 内对**合并后的行**生效，
所以它对 `target` / `class` 两种键一视同仁 —— 单 token 的 `target` 查询同样会退化。

**选定的语义（测试里写清）**：门槛是"查询侧任意一个键与该笔记重叠 ≥2 个不同 token"。
`lookup_playbook`（单键原语、也是模型自己调的工具）**不过门槛**，保留全量召回。

**已知的召回代价（有意的）**：门槛会砍掉一部分真实命中。上面那条反序列化笔记对
`'Weblogic ssrf'` 查询的重叠只有 1（`weblogic`），所以它**不再被注入** —— 这正好是
被实测证明会带偏运行的那一条。被砍掉的条目全部进运行日志（`gated ...`）,否则以后
没人知道某道题为什么没有注入。
"""

from __future__ import annotations

import pytest

from vulnclaw.agent import playbook as pb

LONG_STEPS = (
    "LOCK: a concrete lock description long enough to pass the quality gate.\n"
    "CONFIRMED: witnessed in evidence.\n"
    "ANGLES: [hit] one angle."
)


@pytest.fixture()
def store(tmp_path, monkeypatch):
    monkeypatch.setattr(pb, "CONFIG_DIR", tmp_path)
    monkeypatch.setattr(pb, "PLAYBOOKS_DIR", tmp_path / "playbooks")
    pb.ensure_dirs()
    return tmp_path / "playbooks"


def _write(slug: str, fingerprint: str, *, name: str = "", source: str = pb.SOURCE_CURATED) -> None:
    block = [
        "---",
        f"name: {name or slug}",
        f"fingerprint: {fingerprint}",
        "status: validated",
        f"source: {source}",
        "---",
        "",
        LONG_STEPS,
        "",
    ]
    (pb.PLAYBOOKS_DIR / f"{slug}.md").write_text("\n".join(block), encoding="utf-8")


# ── 门槛本身 ──────────────────────────────────────────────────────────────

def test_a_single_token_query_is_not_a_class_hit(store):
    """`"Weblogic"` 单词查询不得对同框架笔记判为命中（交接文档点名的回归）。"""
    _write("weblogic-deser", "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal")
    assert pb.lookup_playbook_multi([("class", "Weblogic")], limit=2) == []


def test_the_floor_is_two_distinct_tokens(store):
    assert pb.MIN_OVERLAP_TOKENS == 2, "门槛值变了就要重新量一遍召回代价"


def test_two_token_overlap_still_hits(store):
    """2 token 重叠仍正常命中（交接文档点名的回归）。"""
    _write(
        "weblogic-deser",
        "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal",
        name="Weblogic XMLDecoder deserialization note",
    )
    rows = pb.lookup_playbook_multi([("class", "Weblogic XMLDecoder")], limit=2)
    assert [r["slug"] for r in rows] == ["weblogic-deser"]
    assert rows[0]["overlap_tokens"] >= 2


def test_rows_carry_the_overlap_count_for_the_log(store):
    _write("weblogic-note", "Weblogic ssrf uddiexplorer operator portlet")
    rows = pb.lookup_playbook_multi([("class", "Weblogic ssrf")], limit=2)
    assert rows[0]["overlap_tokens"] == 2


def test_a_single_query_token_cannot_be_padded_into_a_hit(store):
    """重复同一个 token 不能凑过门槛：门槛数的是**不同** token。"""
    _write("weblogic-note", "Weblogic ssrf uddiexplorer")
    assert pb.lookup_playbook_multi([("class", "Weblogic Weblogic")], limit=2) == []


def test_the_floor_is_not_derived_from_the_score(store):
    """分数受查询长度影响，不能反推重叠数。

    查询 2 个 token 全部命中 → 分数 1.0（与单 token 查询的 1.0 无法区分）；
    查询 12 个 token 命中 2 个 → 分数只有 0.167 却**过**门槛。所以门槛必须用
    重叠 token 数，不能用 `score >= 某阈值`。
    """
    _write("weblogic-note", "Weblogic ssrf uddiexplorer")
    short = pb.lookup_playbook_multi([("class", "Weblogic ssrf")], limit=1)
    long = pb.lookup_playbook_multi(
        [("class", "Weblogic ssrf alpha bravo charlie delta echo foxtrot golf hotel india")],
        limit=1,
    )
    assert short[0]["score"] == 1.0
    assert long, "a 2-token overlap must pass even when the query dilutes the score"
    assert long[0]["score"] < 0.2, "score-based gating would have wrongly blocked this"


def test_either_key_can_carry_the_qualifying_overlap(store):
    """门槛对 target/class 一视同仁：短签不够时，长 target 键仍然救得回来。"""
    _write("weblogic-note", "Weblogic ssrf uddiexplorer portlet", name="Weblogic SSRF note")
    blocked: list[dict] = []
    # 只有 class 键（单 token）时该笔记被挡：
    assert pb.lookup_playbook_multi([("class", "Weblogic")], limit=2, out_blocked=blocked) == []
    assert [b["slug"] for b in blocked] == ["weblogic-note"]
    # 加上带实测特征的 target 键后，同一笔记以 ≥2 重叠通过：
    rows = pb.lookup_playbook_multi(
        [("target", "http://direct-ctf2.dasctf.com:27532 Weblogic ssrf"), ("class", "Weblogic")],
        limit=2,
    )
    assert [r["slug"] for r in rows] == ["weblogic-note"]
    assert rows[0]["query_kind"] == "target"
    assert rows[0]["overlap_tokens"] >= 2


def test_the_raw_single_key_lookup_primitive_is_not_gated(store):
    """模型自己调的 `lookup_playbook` 保持全量召回（门槛只在 multi 合并处生效）。"""
    _write("weblogic-note", "Weblogic ssrf uddiexplorer")
    rows = pb.lookup_playbook("Weblogic", limit=3)
    assert rows and rows[0]["slug"] == "weblogic-note"
    assert rows[0]["overlap_tokens"] == 1


# ── 重叠算在"笔记声明的身份"上，不只算 fingerprint ────────────────────────
#
# 这条是实测踩出来的：手工笔记的 fingerprint 常是**目标形状**的
# （"Weblogic 10.3.6 - /wls-wsat/CoordinatorPortType returns 'Web Services WSAT10Service'
# listing; /console/ redirects to login ..."），而真正有判别力的名字在 `name` 里
# （"Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil via bea_wls_internal
# docRoot"）。只数 fingerprint 时，查询 `Weblogic CVE-2017-10271` 与该笔记只重叠 1 个
# token，于是**它自己那道题**都被挡住。278 道真实题面（练习场 2de971ac 全量）实测：
#
#   只数 fingerprint :  手工笔记注入 0/278（Weblogic 笔记在 11 道兄弟题上全部被挡，
#                       ThinkPHP 笔记在 14 道上全部被挡 → 跨题迁移被整体清零）
#   连 name/slug 一起数: 手工笔记注入 16/278，`[Weblogic]SSRF` 仍被正确挡住
#
# 同一个函数里的漏洞类判别早就写明"身份要从 name/slug 读，因为 fingerprint 常只是目标串"
# —— 一条规则不能一边读名字、另一边只读同一个笔记的 fingerprint。

def test_the_overlap_counts_the_name_not_only_the_fingerprint(store):
    """真实形状：fingerprint 是目标串，判别性信息在 name 里。"""
    _write(
        "weblogic-note",
        "Weblogic 10.3.6 - /wls-wsat/CoordinatorPortType returns 'Web Services "
        "WSAT10Service' listing; /console/ redirects to login",
        name="Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil",
    )
    rows = pb.lookup_playbook_multi([("class", "Weblogic CVE-2017-10271")], limit=2)
    assert [r["slug"] for r in rows] == ["weblogic-note"], (
        "the note's own challenge must inject it: name carries weblogic+cve"
    )
    assert rows[0]["overlap_tokens"] >= 2


def test_counting_the_name_does_not_let_a_bare_framework_token_through(store):
    """放开到 name 之后，单 token 查询依然过不了门（原始退化情形没被放回来）。"""
    _write(
        "weblogic-deser",
        "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal",
        name="Weblogic CVE-2017-10271 (wls-wsat XMLDecoder RCE) flag exfil",
    )
    blocked: list[dict] = []
    rows = pb.lookup_playbook_multi([("class", "Weblogic")], limit=2, out_blocked=blocked)
    assert rows == [], "a bare framework token still needs a second declared token"
    assert [b["slug"] for b in blocked] == ["weblogic-deser"]
    assert blocked[0]["overlap_tokens"] == 1


def test_the_overlap_surface_is_the_declared_identity(store):
    """`identity_tokens` = fingerprint + name + slug，是一条可测的公开语义。"""
    _write("weblogic-ssrf-note", "Weblogic uddiexplorer", name="Weblogic SSRF operator portlet")
    note = pb.list_playbooks()[0]
    assert note.tokens() == pb._tokenize("Weblogic uddiexplorer")
    assert "ssrf" in note.identity_tokens(), "the name must contribute"
    assert "note" in note.identity_tokens(), "the slug must contribute"
    assert note.identity_tokens() >= note.tokens()


# ── 被挡条目必须可见 ──────────────────────────────────────────────────────

def test_blocked_rows_are_reported_to_the_caller(store):
    _write("weblogic-deser", "Weblogic CVE-2017-10271 wls-wsat XMLDecoder bea_wls_internal")
    blocked: list[dict] = []
    rows = pb.lookup_playbook_multi([("class", "Weblogic")], limit=2, out_blocked=blocked)
    assert rows == []
    assert [b["slug"] for b in blocked] == ["weblogic-deser"]
    assert blocked[0]["overlap_tokens"] == 1
    assert blocked[0]["query_kind"] == "class"
    assert "name" in blocked[0] and "score" in blocked[0], "日志要能说清被挡的是谁"


def test_a_row_blocked_by_one_key_is_reported_once(store):
    _write("weblogic-deser", "Weblogic CVE-2017-10271 wls-wsat XMLDecoder")
    blocked: list[dict] = []
    pb.lookup_playbook_multi(
        [("class", "Weblogic"), ("target", "Weblogic")], limit=2, out_blocked=blocked
    )
    assert len(blocked) == 1, f"the same note must not be reported twice: {blocked}"


def test_nothing_is_reported_when_nothing_is_blocked(store):
    _write("weblogic-ssrf", "Weblogic ssrf uddiexplorer portlet")
    blocked: list[dict] = []
    rows = pb.lookup_playbook_multi([("class", "Weblogic ssrf")], limit=2, out_blocked=blocked)
    assert rows and blocked == []


# ── 交接文档 §5.7 的两个自伤 bug：回归用例 ────────────────────────────────
#
# 改 `lookup_playbook_multi` / `_reserve_curated_representation` 之前先把这两条写上，
# 它们描述的是已经真实发生过、且很容易在重构里重新引入的失败。

def test_regression_per_key_truncation_must_not_drop_the_curated_note(store):
    """bug 1：逐键查询时就按 `limit` 截断，手工笔记在预约规则看到它之前就被丢掉。

    现场：两条自动笔记在 class 键上都是 1.0，真正有用的手工笔记 0.5 —— 逐键取
    `limit=2` 时手工笔记根本进不了候选，预约规则无从施救。
    """
    query = "Weblogic CVE-2018-2628 Real Easy"
    _write("auto-a", query, name="AutoNotes a", source=pb.SOURCE_AUTO)
    _write("auto-b", query, name="AutoNotes b", source=pb.SOURCE_AUTO)
    _write(
        "curated",
        "Weblogic CVE-2017-10271 wls-wsat XMLDecoder docroot bea_wls_internal",
        name="Weblogic technique note",
        source=pb.SOURCE_CURATED,
    )
    rows = pb.lookup_playbook_multi([("class", query)], limit=2)
    slugs = [r["slug"] for r in rows]
    assert "curated" in slugs, f"per-key truncation dropped the curated note again: {slugs}"
    assert len(rows) == 2


def test_regression_an_all_auto_store_still_respects_limit(store):
    """bug 2：预约规则在"库里只有自动笔记"时返回了未截断的全表（limit=2 回了 3 条）。"""
    query = "Weblogic CVE-2018-2628 Real Easy"
    for slug in ("auto-a", "auto-b", "auto-c"):
        _write(slug, query, name=f"AutoNotes {slug}", source=pb.SOURCE_AUTO)
    for limit in (1, 2, 3):
        rows = pb.lookup_playbook_multi([("class", query)], limit=limit)
        assert len(rows) <= limit, f"limit={limit} returned {len(rows)} rows"


def test_regression_the_gate_never_grows_a_result_set(store):
    """门槛只能让结果集变小（或不变），且始终遵守 limit。"""
    query = "Weblogic CVE-2018-2628 Real Easy"
    for slug in ("a", "b", "c", "d"):
        _write(slug, query, name=f"note {slug}")
    for limit in (1, 2, 3):
        rows = pb.lookup_playbook_multi([("class", query)], limit=limit)
        assert len(rows) <= limit
