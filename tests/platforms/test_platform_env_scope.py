"""平台把靶机交到手上后，靶机域名必须进入本次运行的作用域。

回归守卫，对应一次整轮白跑的实测缺陷（2026-09-23，CTF2 练习场
`[Weblogic]CVE-2017-10271`）：

* 运行的作用域是从任务文本里推出来的，而题面里唯一的 URL 是描述中的 vulhub
  github 链接，于是 allowlist 只有 ``[github.com]``；
* ``platform_start_env`` 随后在平台自己的域名上开出了真靶机，作用域闸把它挡了：

      [constraint_violation] Host direct-ctf2.dasctf.com is outside allowed
      scope [github.com] for target direct-ctf2.dasctf.com

* ``shell_command`` 与 ``python_execute`` 全被挡，agent 拒绝绕过闸门（行为正确），
  于是整整一轮（186 秒、29 次工具调用）都花在"请操作者授权"上，零收获。

修法刻意收窄：**只有本来就在执行约束的运行**才补登记靶机。空约束集意味着什么也没在
拦，补登记反而会开始拦别的 host（例如题面里让人去读的公开 writeup），所以那里不动。
"""

from __future__ import annotations

from types import SimpleNamespace

import pytest

from vulnclaw.agent.builtin_tools import enforce_host_path_constraints
from vulnclaw.agent.context import TaskConstraints
from vulnclaw.platforms import base, bootstrap, registry
from vulnclaw.platforms.tools import dispatch_platform_tool

TARGET_HOST = "direct-ctf2.dasctf.com"
TARGET_PORT = 27420


class EnvAdapter:
    """Adapter whose env goes STARTING -> RUNNING with a real endpoint."""

    name = "envfake"
    capabilities = frozenset({"env"})
    enabled_by_default = True

    def is_configured(self) -> bool:
        return True

    def make_ref(self, *, kind: str, id: str, group: str = ""):
        from vulnclaw.platforms.refs import ChallengeRef

        return ChallengeRef(self.name, kind, group, id)

    def parse_ref(self, tail: str):
        from vulnclaw.platforms.refs import ChallengeRef, parse_fields

        fields = parse_fields(tail)
        if len(fields) == 1:
            return ChallengeRef(self.name, fields[0], "", "")
        if len(fields) == 2:
            return ChallengeRef(self.name, fields[0], fields[1], "")
        return ChallengeRef(self.name, fields[0], fields[1], fields[2])

    async def start_env(self, ref):
        return base.EnvInfo(ref=ref, state=base.STATE_STARTING, complete=False)

    async def read_env(self, ref):
        return base.EnvInfo(
            ref=ref,
            state=base.STATE_RUNNING,
            complete=True,
            endpoints=(
                base.EnvEndpoint(host=TARGET_HOST, port=TARGET_PORT, transport=base.TRANSPORT_TCP),
            ),
        )


@pytest.fixture(autouse=True)
def _registry(monkeypatch):
    registry.clear_adapters()
    bootstrap.reset_bootstrap()
    monkeypatch.setattr(
        "vulnclaw.platforms.bootstrap.ensure_adapters",
        lambda force=False: registry.all_adapters(),
    )
    registry.register_adapter(EnvAdapter())
    yield
    registry.clear_adapters()
    bootstrap.reset_bootstrap()


def _agent(**constraint_kwargs):
    return SimpleNamespace(
        session_state=SimpleNamespace(task_constraints=TaskConstraints(**constraint_kwargs))
    )


REF = "envfake:practice:1:9"


@pytest.mark.asyncio
async def test_read_env_authorises_the_provisioned_endpoint():
    agent = _agent(allowed_hosts=["github.com"])
    out = await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    assert TARGET_HOST in out, "the endpoint must still be rendered to the model"
    hosts = agent.session_state.task_constraints.allowed_hosts
    assert TARGET_HOST in hosts and "github.com" in hosts


@pytest.mark.asyncio
async def test_the_scope_gate_stops_refusing_the_platform_target():
    """The actual defect: this call used to return a constraint_violation."""
    agent = _agent(allowed_hosts=["github.com"])
    before = enforce_host_path_constraints(agent, host=TARGET_HOST)
    assert before is not None and "outside allowed scope" in before, (
        "precondition: without registration the platform target is refused"
    )
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    assert enforce_host_path_constraints(agent, host=TARGET_HOST) is None


@pytest.mark.asyncio
async def test_an_unconstrained_run_does_not_gain_enforcement():
    """Empty constraints = nothing enforced; do not start blocking other hosts."""
    agent = _agent()
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    constraints = agent.session_state.task_constraints
    assert constraints.allowed_hosts == []
    assert constraints.is_empty()


@pytest.mark.asyncio
async def test_port_is_registered_only_when_the_run_constrains_ports():
    strict = _agent(allowed_hosts=["github.com"], allowed_ports=[80])
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=strict)
    assert TARGET_PORT in strict.session_state.task_constraints.allowed_ports

    portless = _agent(allowed_hosts=["github.com"])
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=portless)
    assert portless.session_state.task_constraints.allowed_ports == []


@pytest.mark.asyncio
async def test_starting_state_registers_nothing():
    """An incomplete payload has no endpoint yet, so there is nothing to authorise."""
    agent = _agent(allowed_hosts=["github.com"])
    await dispatch_platform_tool("platform_start_env", {"ref": REF}, agent=agent)
    assert agent.session_state.task_constraints.allowed_hosts == ["github.com"]


@pytest.mark.asyncio
async def test_registration_is_idempotent():
    agent = _agent(allowed_hosts=["github.com"])
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    hosts = agent.session_state.task_constraints.allowed_hosts
    assert hosts.count(TARGET_HOST) == 1


@pytest.mark.asyncio
async def test_missing_agent_and_broken_agent_are_harmless():
    """The pure tool-face call shape must keep working unchanged."""
    assert TARGET_HOST in await dispatch_platform_tool("platform_read_env", {"ref": REF})
    broken = SimpleNamespace(session_state=SimpleNamespace(task_constraints=None))
    assert TARGET_HOST in await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=broken)
    # An object with no session_state at all must not raise either.
    assert TARGET_HOST in await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=object())
