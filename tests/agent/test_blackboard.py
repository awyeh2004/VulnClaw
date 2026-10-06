

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


    async def test_fullwidth_punctuation_stays_one_card(self):
        """Round-11 finding #3: NFKC folding must catch the width variants
        ('Q1：攻击者IP？' vs 'Q1:攻击者IP') or the duplicate channel reopens."""
        import asyncio
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool

        findings = []
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
            findings=findings,
        )
        agent = SimpleNamespace(
            runtime=SimpleNamespace(blackboard=Blackboard()),
            context=SimpleNamespace(state=state),
            session_state=SimpleNamespace(target="127.0.0.1:2224"),
        )
        half = await dispatch_blackboard_tool(
            agent, "blackboard_record_answer",
            {"question": "Q1: 攻击者 IP 是什么？", "answer": "203.0.113.77"},
        )
        full = await dispatch_blackboard_tool(
            agent, "blackboard_record_answer",
            {"question": "Ｑ１：攻击者ＩＰ是什么？", "answer": "203.0.113.77"},
        )
        assert "already recorded" in full, full
        assert len(findings) == 1

    async def test_same_number_with_drifted_wording_is_idempotent(self):
        """round13 F5: the idempotency matcher was text-only, so a same-number
        re-record with drifting wording ("Q1:攻击者IP" vs "Q1:攻击者的IP")
        opened a second card within one session. Identity must use the same
        double key as merge_session_state: question NUMBER first."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool
        from vulnclaw.config.domain_models import (
            ANSWER_CARD_VULN_TYPE,
            VulnerabilityFinding,
        )

        existing = VulnerabilityFinding(
            title="Q1: 攻击者IP",
            description="203.0.113.77",
            evidence="first evidence",
            vuln_type=ANSWER_CARD_VULN_TYPE,
        )
        findings = [existing]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
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
                # Same number, drifted wording — must dedup onto the first card.
                "question": "Q1: 攻击者的IP是啥",
                "answer": "203.0.113.77",
                "evidence": "second evidence",
            },
        )
        assert "answer already recorded" in result, result
        assert len(findings) == 1
        assert "second evidence" in existing.evidence

    async def test_different_question_with_same_number_still_dedups_by_design(self):
        """Documented trade-off from round-12 F1: a competition sheet has
        exactly one Q1, so same-number is always the same question re-recorded.
        The number leg must win over the wording difference here too."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool
        from vulnclaw.config.domain_models import (
            ANSWER_CARD_VULN_TYPE,
            VulnerabilityFinding,
        )

        existing = VulnerabilityFinding(
            title="Q1: 攻击者IP",
            description="203.0.113.77",
            evidence="",
            vuln_type=ANSWER_CARD_VULN_TYPE,
        )
        findings = [existing]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
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
                "question": "Q1: webshell 密码是什么",  # same number, different question
                "answer": "cmd2026",
                "evidence": "",
            },
        )
        assert "answer already recorded" in result, result
        assert len(findings) == 1

    async def test_numbered_rerecord_folds_unnumbered_card(self):
        """round14 F-C: the marker is part of the stored title, so a numbered
        re-record of an unnumbered card ("Q1: 攻击者IP" onto "攻击者IP")
        matched neither the number leg (old card has no number) nor the text
        leg (the marker rides inside the text) and opened a second card. The
        number-stripped fallback leg must fold it back with the evidence."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool
        from vulnclaw.config.domain_models import (
            ANSWER_CARD_VULN_TYPE,
            VulnerabilityFinding,
        )

        existing = VulnerabilityFinding(
            title="攻击者IP",
            description="203.0.113.77",
            evidence="first evidence",
            vuln_type=ANSWER_CARD_VULN_TYPE,
        )
        findings = [existing]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
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
                "question": "Q1: 攻击者IP",  # numbered re-record of an unnumbered card
                "answer": "203.0.113.77",
                "evidence": "second evidence",
            },
        )
        assert "answer already recorded" in result, result
        assert len(findings) == 1
        assert "second evidence" in existing.evidence

    async def test_unnumbered_rerecord_folds_numbered_card(self):
        """round14 F-C, reverse direction: an unnumbered re-record of a
        numbered card must fold onto the numbered card via the stripped key."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool
        from vulnclaw.config.domain_models import (
            ANSWER_CARD_VULN_TYPE,
            VulnerabilityFinding,
        )

        existing = VulnerabilityFinding(
            title="Q1: 攻击者IP",
            description="203.0.113.77",
            evidence="first evidence",
            vuln_type=ANSWER_CARD_VULN_TYPE,
        )
        findings = [existing]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
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
                "question": "攻击者IP",  # same question, marker dropped
                "answer": "203.0.113.77",
                "evidence": "second evidence",
            },
        )
        assert "answer already recorded" in result, result
        assert len(findings) == 1
        assert "second evidence" in existing.evidence

    async def test_same_text_under_different_numbers_are_distinct(self):
        """round14 F-C sibling axiom: on a competition sheet the NUMBER is the
        row identity, so identical wording under different numbers ("Q1: 问题"
        then "Q2: 问题") is two rows, not a re-record — the number leg wins
        and no fallback may fold them. Mirrors the merge-side pin
        test_merge_session_state_keeps_adjacent_answer_cards."""
        from types import SimpleNamespace

        from vulnclaw.agent.blackboard import Blackboard, dispatch_blackboard_tool
        from vulnclaw.config.domain_models import (
            ANSWER_CARD_VULN_TYPE,
            VulnerabilityFinding,
        )

        existing = VulnerabilityFinding(
            title="Q1: 问题",
            description="answer-1",
            evidence="first evidence",
            vuln_type=ANSWER_CARD_VULN_TYPE,
        )
        findings = [existing]
        state = SimpleNamespace(
            add_finding=lambda f, skip_dedup=False: findings.append(f) or True,
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
                "question": "Q2: 问题",  # same wording, different row
                "answer": "answer-2",
                "evidence": "second evidence",
            },
        )
        assert "finding recorded" in result, result
        assert len(findings) == 2
