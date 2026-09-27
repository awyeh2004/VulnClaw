

class TestRecordAnswer:
    """blackboard_record_answer: the answer-sheet double write (mock exams 1-3)."""

    def _agent(self, tmp_path):
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard

        findings = []
        state = SimpleNamespace(add_finding=lambda f, skip_dedup=False: findings.append(f) or True)
        bb = Blackboard()
        agent = SimpleNamespace(
            runtime=SimpleNamespace(blackboard=bb),
            context=SimpleNamespace(state=state),
            session_state=SimpleNamespace(target="127.0.0.1:2224"),
        )
        agent._findings = findings
        return agent

    async def test_double_writes_board_fact_and_finding(self):
        import asyncio

        from vulnclaw.agent.blackboard import dispatch_blackboard_tool

        agent = self._agent(None)
        result = await dispatch_blackboard_tool(
            agent,
            "blackboard_record_answer",
            {
                "question": "Q1: 攻击者 IP 是什么？",
                "answer": "203.0.113.77",
                "evidence": "Accepted password for admin from 203.0.113.77 port 51028",
            },
        )
        assert "[answer-sheet] finding recorded" in result
        # board side: a fact carrying the Q<n> card
        facts = list(agent.runtime.blackboard._nodes.values())
        assert any("Q1" in n.description and "203.0.113.77" in n.description for n in facts)
        # findings side: VulnerabilityFinding with the answer and evidence
        assert len(agent._findings) == 1
        f = agent._findings[0]
        assert f.title.startswith("Q1")
        assert f.description == "203.0.113.77"
        assert "203.0.113.77" in f.evidence

    async def test_missing_answer_refuses(self):
        import asyncio

        from vulnclaw.agent.blackboard import dispatch_blackboard_tool

        agent = self._agent(None)
        result = await dispatch_blackboard_tool(agent, "blackboard_record_answer", {"question": "Q1"})
        assert "requires" in result
        assert agent._findings == []
