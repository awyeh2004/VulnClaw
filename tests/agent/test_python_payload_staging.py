"""生成的载荷脚本必须落在本次运行的 scratch 目录里，而不是系统临时目录。

两个理由，都是实测出来的（2026-09-23 解 Weblogic CVE-2017-10271 期间）：

1. 可审计/可清理：脚本原先落到 ``%TEMP%\\tmpXXXX.py``，跟本次运行的其他产物
   完全脱节，跑完也不会随题清理。
2. 端点杀软：``%TEMP%`` 里的 JSP webshell 脚本被启发式命中并隔离（当场记录到 6 条
   ``HEUR:Backdoor/JSP.WebShell.a``），脚本在"写完"和"要执行"之间被删掉，于是那次
   运行花了好几个回合去自诊断 ``python_execute`` 是不是坏了。落在 scratch 目录后，
   运维只需要在自己的杀软里排除这一条窄路径，而不是排除整个 ``%TEMP%``。
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest

from vulnclaw.agent import builtin_tools as bt


def _agent(solve_work_root: str, run_id: str = "20260923T200000Z-solve-demo"):
    return SimpleNamespace(
        config=SimpleNamespace(session=SimpleNamespace(solve_work_root=solve_work_root)),
        runtime=SimpleNamespace(run_id=run_id),
    )


def test_staging_dir_is_the_run_scratch_dir(tmp_path):
    agent = _agent(str(tmp_path))
    assert bt._payload_script_dir(agent) == str(tmp_path / "20260923T200000Z-solve-demo")


def test_scratch_dir_is_created_and_named_by_run_id(tmp_path):
    agent = _agent(str(tmp_path), run_id='bad:<name>|x')
    staging = bt._payload_script_dir(agent)
    assert staging is not None
    assert Path(staging).is_dir(), "staging dir must exist before tempfile writes into it"
    assert ":" not in Path(staging).name and "|" not in Path(staging).name


def test_no_run_id_falls_back_to_the_manual_subdir(tmp_path):
    """An empty run_id is how interactive runs land in the documented 'manual' dir."""
    assert Path(bt._payload_script_dir(_agent(str(tmp_path), run_id=""))).name == "manual"


@pytest.mark.parametrize("root", ["", "   "])
def test_unconfigured_scratch_root_uses_the_system_temp_dir(root):
    assert bt._payload_script_dir(_agent(root)) is None


def test_unusable_scratch_root_degrades_instead_of_failing(tmp_path):
    """A file where the directory should be: staging must still work."""
    blocked = tmp_path / "not-a-dir"
    blocked.write_text("x", encoding="utf-8")
    assert bt._payload_script_dir(_agent(str(blocked / "nested"))) is None


def test_default_workdir_still_falls_back_to_cwd(monkeypatch):
    """The refactor must not change shell_command's existing default."""
    monkeypatch.chdir(Path.cwd())
    assert bt._default_workdir(_agent("")) == Path.cwd().resolve()
    scratch = bt._default_workdir(_agent(str(Path(tempfile.gettempdir())), run_id="r1"))
    assert scratch.name == "r1"


@pytest.mark.asyncio
async def test_python_execute_stages_into_the_scratch_dir(tmp_path, monkeypatch):
    """End-to-end: the real execute_python path passes dir=<scratch> to tempfile."""
    from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

    class AutoApprove:
        async def request_approval(self, view):  # noqa: ARG002
            return "approve"

    reset_execution_gate()
    get_execution_gate().install_channel(AutoApprove())

    seen: dict = {}
    real = tempfile.NamedTemporaryFile

    def spy(*args, **kwargs):
        seen.update(kwargs)
        return real(*args, **kwargs)

    monkeypatch.setattr(bt.tempfile, "NamedTemporaryFile", spy)

    agent = _agent(str(tmp_path), run_id="run-abc")
    agent.config.safety = SimpleNamespace(
        enable_python_execute=True,
        python_execute_max_lines=50,
        python_execute_mode="trusted-local",
        python_execute_restricted=False,
        python_execute_show_warning=False,
        python_execute_max_output_chars=0,
        python_execute_audit_enabled=False,
    )
    agent.session_state = SimpleNamespace(task_constraints=None)
    agent.context = SimpleNamespace(state=SimpleNamespace(agent_state=None))

    out = await bt.execute_python(agent, {"code": "print(1 + 1)"})
    assert "2" in out, out
    assert seen.get("dir") == str(tmp_path / "run-abc")
    assert seen.get("prefix") == "vulnclaw-payload-"
    assert seen.get("suffix") == ".py"
