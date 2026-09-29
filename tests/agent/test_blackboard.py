

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


    async def test_evidence_ref_path_writes_finding(self):
        """Round-8 of the mock-exam series: the evidence_ref branch used to die
        with NameError (_evidence_content was a dispatch-local closure), so the
        board half survived and the findings half silently vanished."""
        import asyncio
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool

        findings = []
        evidence_store = [
            SimpleNamespace(
                id="e007",
                content="Accepted password for admin from 203.0.113.77 port 51028 ssh2",
            )
        ]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
            agent_state=SimpleNamespace(evidence=evidence_store),
            findings=findings,
        )
        agent = SimpleNamespace(
            runtime=SimpleNamespace(blackboard=Blackboard()),
            context=SimpleNamespace(state=state),
            session_state=SimpleNamespace(target="127.0.0.1:2224"),
        )
        result = await dispatch_blackboard_tool(
            agent,
            "blackboard_record_answer",
            {
                "question": "Q1: 攻击者 IP 是什么？",
                "answer": "203.0.113.77",
                "evidence": "Accepted password ... port 51028",
                "evidence_ref": "e007",
            },
        )
        assert "finding recorded" in result, result
        assert "工具执行错误" not in result
        assert len(findings) == 1
        assert findings[0].title.startswith("Q1")

    async def test_same_question_with_different_spacing_is_idempotent(self):
        """Round-10 #4: the model writes the same question with/without spaces; the
        previous exact ``title == question`` match created a second card, and the
        evidence merge mutated the card without reaching a checkpoint."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool

        findings = []
        notifications = []
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
            findings=findings,
            _notify_checkpoint=lambda reason: notifications.append(reason),
        )
        agent = SimpleNamespace(
            runtime=SimpleNamespace(blackboard=Blackboard()),
            context=SimpleNamespace(state=state),
            session_state=SimpleNamespace(target="127.0.0.1:2224"),
        )
        first = await dispatch_blackboard_tool(
            agent,
            "blackboard_record_answer",
            {
                "question": "Q1: 攻击者 IP 是什么？",
                "answer": "203.0.113.77",
                "evidence": "ev-1",
            },
        )
        assert "finding recorded" in first
        # Identical question once whitespace is folded away.
        second = await dispatch_blackboard_tool(
            agent,
            "blackboard_record_answer",
            {
                "question": "Q1:攻击者IP是什么？",
                "answer": "203.0.113.77",
                "evidence": "ev-2",
            },
        )
        assert "already recorded" in second, second
        assert len(findings) == 1
        assert "ev-2" in findings[0].evidence
        assert "finding_updated" in notifications, "the evidence merge did not checkpoint"
