"""单站点失败不等于网络封锁 —— 这条提示必须留在系统提示里。

实测（2026-10-19，荷兰宽带数据泄露）：模型需要 RouterPassView，去
`www.nirsoft.net` 下载超时（该主机从本网络确实不可达），于是在黑板上记下
"outbound egress is blocked"，据此交还 run 并要求操作者给 flag。

同一时刻 GitHub 返回 200。单个主机的失败是关于那个主机的事实，不是关于网络的；
把它推广会一次性取消所有剩余路径。

提示本身是给模型的措辞约束（无法用行为断言），所以这里钉两件事：措辞还在，
且它明确要求"至少再试一个不同来源"。
"""

from __future__ import annotations

import re
from pathlib import Path

import vulnclaw.agent.solver as solver

SOURCE = Path(solver.__file__).read_text(encoding="utf-8")
# The rule is written as adjacent string literals, so the raw file has a quote, a
# newline and indentation between fragments. Collapse all whitespace runs so the
# assertions read the SENTENCE regardless of how it was wrapped.
# Strip the Python string-literal punctuation between adjacent fragments, then
# collapse whitespace: what remains is the sentence as the model will read it.
JOINED = " ".join(re.sub(r'"\s*"', "", SOURCE).split())


class TestThePromptDistinguishesHostFromNetwork:
    def test_the_rule_is_present(self):
        assert "A failed connection is a fact about that HOST" in JOINED

    def test_it_demands_a_second_unrelated_source(self):
        assert "at least one unrelated source" in JOINED

    def test_it_forbids_generalising_without_a_second_host(self):
        assert "without a second host" in JOINED

    def test_it_points_at_alternatives_to_a_dead_vendor_site(self):
        """A dead vendor page must not mean "this tool is unobtainable"."""
        for word in ("mirror", "GitHub reimplementation", "specification"):
            assert word in JOINED, word

    def test_reading_a_writeup_is_allowed_for_the_method(self):
        """操作者纠正（2026-10-19）：比赛里看别人怎么解是正常做法，该禁的是照抄结果。

        平台多数按实例重生成 flag，抄来的值本来就提交不了 —— 所以"禁看题解"既拦
        错了东西（方法），又和完成门重复（抄来的值过不了证据门）。
        """
        low = JOINED.lower()
        assert "reading how others solved this challenge is also allowed" in low
        assert "regenerate flags per instance" in low
        assert "is still giving up on derivation" not in low
