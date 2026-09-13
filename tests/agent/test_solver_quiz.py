"""Knowledge-quiz (竞赛理论题) support in the solve engine.

Quiz answers come from model knowledge rather than from a captured flag, so
the completion gate must not demand a flag or quoted evidence terms — that
would loop forever on "答案: A". The gate only requires that the questions
were fetched into evidence, and that any claimed flag is still grounded.
"""

from types import SimpleNamespace

from vulnclaw.agent.agent_state import AgentState
from vulnclaw.agent.solver import (
    _ask_user_rejection_reason,
    _completion_gate,
    _implicit_flag_completion,
    _looks_like_quiz,
    _quiz_questions_inline,
    _system_prompt,
)

QUIZ_GOAL = (
    "CTF 比赛知识竞赛答题：1. 下列属于对称加密算法的是（ ）A. RSA B. AES "
    "C. ECC D. DSA 2. （单选）《网络安全法》的施行时间"
)
INLINE_PAPER_GOAL = (
    "知识竞赛，题目如下：1. 下列属于哈希算法的是（ ）A. AES B. MD5 C. RSA D. SM4"
)
FLAG_QUIZ_GOAL = "CTF 比赛知识竞赛答题并拿flag：1. 对称加密算法 A. RSA B. AES C. SM4 D. DES"


def _make_state(goal: str, evidence_text=None) -> AgentState:
    st = AgentState(goal=goal)
    if evidence_text is not None:
        st.evidence = [
            type(
                "Ev",
                (),
                {"content": evidence_text, "id": "e001", "evidence_id": "e001"},
            )()
        ]
    return st


class TestLooksLikeQuiz:
    def test_chinese_keywords(self):
        assert _looks_like_quiz("知识竞赛：以下说法正确的是")
        assert _looks_like_quiz("（判断题）HTTPS 默认使用 443 端口")
        assert _looks_like_quiz("第2题（多选）下列属于国密算法的")

    def test_english_keywords(self):
        assert _looks_like_quiz("Answer the security awareness quiz")
        assert _looks_like_quiz("Multiple choice: which is a symmetric cipher?")

    def test_option_markers_imply_choice_question(self):
        assert _looks_like_quiz("1. A. RSA B. AES C. ECC")
        assert not _looks_like_quiz("Annex B. references appendix A. notes")

    def test_pentest_goal_is_not_quiz(self):
        assert not _looks_like_quiz("对 http://target 进行渗透测试，找出flag")
        assert not _looks_like_quiz("scan the target and exploit the sqli")


class TestCompletionGateQuiz:
    def test_quiz_without_evidence_rejected(self):
        """Pure guessing without fetching the questions stays rejected — this
        goal has NO inline questions (URL-based), so evidence is required."""
        url_quiz_goal = "知识竞赛入口在 http://127.0.0.1:8000/quiz，答题拿分"
        st = _make_state(url_quiz_goal, None)
        ok, reason, _ = _completion_gate(st, "FINAL: 1.B 2.2017年6月1日")
        assert not ok
        assert "quiz" in reason

    def test_inline_pasted_paper_completes_without_evidence(self):
        """R2: questions pasted in the goal need no fetched evidence."""
        assert _quiz_questions_inline(INLINE_PAPER_GOAL) is True
        assert _quiz_questions_inline(QUIZ_GOAL) is True
        # A bare type keyword must NOT count as inline (would skip reading).
        assert _quiz_questions_inline("入口在 http://x/quiz，20道单选题") is False
        st = _make_state(INLINE_PAPER_GOAL, None)
        ok, reason, _ = _completion_gate(st, "FINAL: 1.B（MD5 是哈希）")
        assert ok, reason

    def test_quiz_answers_accepted_without_flag_or_citations(self):
        """Goal mentions CTF (flag-wanting) but knowledge answers must pass."""
        st = _make_state(QUIZ_GOAL, "第1题 下列属于对称加密算法的是… 第2题 网络安全法施行时间")
        ok, reason, _ = _completion_gate(st, "FINAL: 1.B 2.2017年6月1日")
        assert ok, reason

    def test_flag_demanding_quiz_still_requires_grounded_flag(self):
        """R1: '答题拿flag' must not ride the quiz shortcut to a flagless FINAL."""
        assert _looks_like_quiz(FLAG_QUIZ_GOAL) is True
        st = _make_state(FLAG_QUIZ_GOAL, "答题页已读，全部答对")
        ok, reason, _ = _completion_gate(st, "FINAL: 1.B 2.A 答题完成")
        assert not ok  # no flag in FINAL → premature

        st2 = _make_state(FLAG_QUIZ_GOAL, "答对全部题目，发放 flag{quiz_prize}")
        ok, reason, _ = _completion_gate(st2, "FINAL: 完成，flag{quiz_prize}")
        assert ok, reason

    def test_judge_style_paper_is_inline_even_without_option_markers(self):
        """N2 residual: marker-less judge stems still count as inline."""
        goal = "（判断题）HTTPS 默认使用 443 端口。（对/错）"
        assert _quiz_questions_inline(goal) is True
        # Numbered stems + question marks count as pasted question content,
        # including single-line pasted papers (audit round-5 #5 regression)…
        assert _quiz_questions_inline("知识竞赛答题：1. 网安法何时施行？ 2. 等保核心是什么") is True
        assert _quiz_questions_inline("知识竞赛答题：\n1. 网安法何时施行？\n2. 等保核心是什么") is True
        # …but a question mark on an INSTRUCTION does not (audit A1)…
        assert _quiz_questions_inline("知识竞赛？开始答题") is False
        assert _quiz_questions_inline("开始答题") is False
        # …and numbered RULE LISTS without question marks are not questions
        # (audit F1: rules list must not bypass the read-first gate)…
        assert _quiz_questions_inline("知识竞赛规则：\n1. 不得扫描靶机\n2. 限时30分钟") is False
        # …and a URL-based prompt keeps the read-first requirement.
        assert _quiz_questions_inline("入口在 http://x/quiz，20道单选题") is False

    def test_answer_system_pentest_goal_is_not_quiz(self):
        """'答题' alone must not flip a pentest task into quiz semantics."""
        goal = "对 http://target 答题系统做渗透测试"
        assert _looks_like_quiz(goal) is False

    def test_ask_user_guard_does_not_block_quiz_handoff(self):
        """N3: the premature-ASK_USER guard must not block the designed
        beyond-knowledge hand-off — quiz page evidence always trips near-miss."""
        goal = "知识竞赛入口在 http://127.0.0.1:8000/quiz，答题拿分"
        st = _make_state(
            goal,
            "<form method=\"POST\" action=\"/submit\"><input type=\"radio\" name=\"q1\">",
        )
        question = (
            "ASK_USER: 🔴 超纲题汇总，请作答（附资料线索，可自行搜索资料）："
            "5. 本届比赛主题是（ ）A... B..."
        )
        assert _ask_user_rejection_reason(st, question) == ""

    def test_implicit_completion_ignored_for_quiz_goal_without_flag_demand(self):
        """N4: a flag-shaped string in page evidence must not complete a quiz
        goal that never asked for a flag."""
        st = _make_state(QUIZ_GOAL, "页面公告: 示例 flag{deadbeefdeadbeef} 仅为装饰")
        ok, _, _ = _implicit_flag_completion(st, "题目里提到 flag{deadbeefdeadbeef}")
        assert not ok

    def test_implicit_completion_still_works_for_flag_demanding_goal(self):
        goal = "知识竞赛答题拿flag：1.（ ）A. x B. y C. z"
        st = _make_state(goal, "交卷成功，发放 flag{realprize01}")
        ok, reason, _ = _implicit_flag_completion(st, "拿到 flag{realprize01}")
        assert ok, reason

    def test_quiz_claimed_flag_must_still_be_grounded(self):
        st = _make_state(QUIZ_GOAL, "交卷成功，获得 flag{quiz_master}")
        ok, _, _ = _completion_gate(st, "FINAL: 全部答对，获得 flag{quiz_master}")
        assert ok

        st2 = _make_state(QUIZ_GOAL, "交卷成功，无 flag 返回")
        ok, reason, _ = _completion_gate(st2, "FINAL: 答对！flag{hallucinated}")
        assert not ok
        assert "not present in tool evidence" in reason


class TestSystemPromptQuiz:
    def test_quiz_goal_gets_quiz_instruction(self):
        prompt = _system_prompt(SimpleNamespace(), AgentState(goal=QUIZ_GOAL))
        assert "Knowledge Quiz Mode" in prompt

    def test_quiz_instruction_carries_beyond_knowledge_flagging(self):
        """Beyond-knowledge (current-events) questions must be flagged (red
        marker + reference leads), held back from submission, and asked of the
        user before the single final submission."""
        prompt = _system_prompt(SimpleNamespace(), AgentState(goal=QUIZ_GOAL))
        assert "do NOT guess" in prompt
        assert "🔴 超纲题汇总" in prompt
        assert "Do NOT submit while beyond-knowledge questions remain" in prompt
        assert "ONE single final submission" in prompt

    def test_pentest_goal_has_no_quiz_instruction(self):
        prompt = _system_prompt(
            SimpleNamespace(), AgentState(goal="渗透测试 http://target 并找出flag")
        )
        assert "Knowledge Quiz Mode" not in prompt
