"""``--target`` must put the named host in scope on EVERY command.

Measured 2026-10-27: ``build_task_constraints`` never looked at
``additional_targets``, so naming a second host left ``allowed_hosts`` at the
primary target only and every request to the extra host came back
``[constraint_violation] ... is outside allowed scope``. The fix landed where
``prepare_task`` builds the scope (``run``/``recon``/``scan``/``exploit``/
``persistent``, the TUI and the Web task API), but ``vulnclaw solve`` derives its
scope from the prompt inside ``AgentCore.solve`` and bypasses that path
entirely -- so the same defect stayed live on the command CTF runs use
(audit 2026-10-30). ``_solve_task_constraints`` closes that gap.
"""

from vulnclaw.cli.commands_run import _solve_task_constraints
from vulnclaw.task_service import (
    TaskCreateRequest,
    TaskOptions,
    build_task_constraints,
)


class TestSolveConstraints:
    def test_extra_host_joins_the_prompt_mined_scope(self):
        constraints = _solve_task_constraints(
            "对 https://app.example.com/ 做一次基线探测",
            ["http://api.example.com/"],
        )
        assert "app.example.com" in constraints.allowed_hosts
        assert "api.example.com" in constraints.allowed_hosts
        assert constraints.strict_mode is True

    def test_extra_host_alone_still_pins_scope(self):
        constraints = _solve_task_constraints("读一下 evidence 里的笔记", ["db.corp"])
        assert constraints.allowed_hosts == ["db.corp"]
        assert constraints.strict_mode is True

    def test_nothing_mined_and_no_extra_keeps_the_old_fallback(self):
        # ``None`` (not an empty TaskConstraints) is what lets a resumed run with
        # a target-less --prompt inherit its stored constraints.
        assert _solve_task_constraints("今天天气怎么样", None) is None

    def test_extra_host_follows_the_same_apex_rule_as_a_primary_target(self):
        constraints = _solve_task_constraints("", ["https://www.blacklake.cn/x"])
        assert constraints.allowed_hosts == ["www.blacklake.cn", "blacklake.cn"]


class TestPrepareTaskConstraints:
    def test_additional_target_reaches_allowed_hosts(self):
        request = TaskCreateRequest(
            command="run",
            target="https://primary.example.com/",
            additional_targets=["http://secondary.example.com/"],
        )
        constraints = build_task_constraints(request)
        assert "primary.example.com" in constraints.allowed_hosts
        assert "secondary.example.com" in constraints.allowed_hosts

    def test_only_host_stays_exact_and_ignores_extras(self):
        request = TaskCreateRequest(
            command="run",
            target="https://primary.example.com/",
            additional_targets=["http://secondary.example.com/"],
            options=TaskOptions(only_host="primary.example.com"),
        )
        constraints = build_task_constraints(request)
        assert constraints.allowed_hosts == ["primary.example.com"]
