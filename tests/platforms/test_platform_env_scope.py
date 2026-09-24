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

    async def read_challenge(self, ref):
        return base.Challenge(
            ref=ref,
            name="不一样的flag",
            category="REVERSE",
            needs_env=False,
            attachments=(
                base.Attachment(
                    name="challenge.zip", url=f"http://{FILE_HOST}/files/challenge.zip"
                ),
            ),
        )


FILE_HOST = "ctf2-files.dasctf.com"

# The platform's own API/service host. It must NOT come into scope merely because an
# attachment lives on a sibling subdomain (round-8 R8-3/R8-4 are two halves of one thing:
# stop mining scope out of prose, and register the host the platform actually hands over).
API_HOST = "ctf2.dasctf.com"


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


# ── round-8 R8-4: the attachment file host must be registered, not stumbled into ──
#
# The env path above was the ONLY scope-registration point either. The file host was
# therefore reachable purely by accident: it worked when the run's description contained
# no URL (because the scope then fell back to `dasctf.com` -- itself the R8-3 bug: a
# prohibition sentence mined for a domain). As soon as the description carried a URL, the
# scope read `[github.com]` and every fetch of an attachment URL the goal explicitly tells
# the agent to use was refused, while the pre-download is best-effort and can be disabled
# or silently degrade. Registering the host the platform itself published is the fix; it
# follows the same principle as `_register_env_scope`.

READ_REF = "envfake:practice:1:9"


@pytest.mark.asyncio
async def test_read_authorises_the_attachment_file_host():
    agent = _agent(allowed_hosts=["github.com"])
    out = await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    assert FILE_HOST in out, "the attachment URL must still be rendered to the model"
    hosts = agent.session_state.task_constraints.allowed_hosts
    assert FILE_HOST in hosts and "github.com" in hosts


@pytest.mark.asyncio
async def test_the_scope_gate_stops_refusing_the_attachment_host():
    """The defect shape: instructing the agent to fetch a host the gate then refuses."""
    agent = _agent(allowed_hosts=["github.com"])
    before = enforce_host_path_constraints(agent, host=FILE_HOST)
    assert before is not None and "outside allowed scope" in before, (
        "precondition: without registration the attachment host is refused"
    )
    await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    assert enforce_host_path_constraints(agent, host=FILE_HOST) is None


@pytest.mark.asyncio
async def test_the_file_host_does_not_authorise_the_platform_api_host():
    """The two findings must not cancel out: registering the file host is narrow.

    `host_in_scope`'s suffix rule means adding `ctf2-files.dasctf.com` covers that host
    and its subdomains only -- never the sibling API host. This is what makes R8-4
    compatible with R8-3 instead of re-introducing it through the back door.
    """
    agent = _agent(allowed_hosts=["github.com"])
    await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    assert enforce_host_path_constraints(agent, host=FILE_HOST) is None
    refusal = enforce_host_path_constraints(agent, host=API_HOST)
    assert refusal is not None and "outside allowed scope" in refusal


@pytest.mark.asyncio
async def test_reading_does_not_add_enforcement_to_an_unconstrained_run():
    agent = _agent()
    await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    constraints = agent.session_state.task_constraints
    assert constraints.allowed_hosts == []
    assert constraints.is_empty()


@pytest.mark.asyncio
async def test_attachment_registration_is_idempotent():
    agent = _agent(allowed_hosts=["github.com"])
    await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    await dispatch_platform_tool("platform_read", {"ref": READ_REF}, agent=agent)
    hosts = agent.session_state.task_constraints.allowed_hosts
    assert hosts.count(FILE_HOST) == 1


@pytest.mark.asyncio
async def test_reading_without_an_agent_is_harmless():
    """The pure tool-face call shape keeps working, as for the env handlers."""
    assert FILE_HOST in await dispatch_platform_tool("platform_read", {"ref": READ_REF})
    broken = SimpleNamespace(session_state=SimpleNamespace(task_constraints=None))
    assert FILE_HOST in await dispatch_platform_tool(
        "platform_read", {"ref": READ_REF}, agent=broken
    )
    assert FILE_HOST in await dispatch_platform_tool(
        "platform_read", {"ref": READ_REF}, agent=object()
    )


@pytest.mark.parametrize(
    ("url", "expected"),
    [
        ("https://a.example.com/x.zip", ["a.example.com"]),
        ("http://b.example.com:8080/x.zip", ["b.example.com"]),
        ("//c.example.com/x.zip", ["c.example.com"]),
        ("d.example.com/x.zip", ["d.example.com"]),
        ("", []),
        ("not a url at all", []),
    ],
)
def test_attachment_host_extraction_handles_the_url_shapes(url, expected):
    from vulnclaw.platforms.tools import _attachment_hosts

    challenge = base.Challenge(
        ref=base.ChallengeRef("envfake", "practice", "1", "9"),
        name="x",
        attachments=(base.Attachment(name="x.zip", url=url),) if url else (),
    )
    assert _attachment_hosts(challenge) == expected


# ── round8 L10: the handler table and the dispatch rule must agree ────────


def test_the_declared_handler_arity_matches_the_dispatch_rule():
    """Every name in `_AGENT_AWARE` must actually accept an agent, and vice versa.

    The annotation on `_HANDLERS` claimed a single `(args)` shape long after the env
    handlers grew a second parameter. That drift is invisible until the call site raises
    TypeError, so it is checked against the real signatures instead of the annotation.
    """
    import inspect

    from vulnclaw.platforms.tools import _AGENT_AWARE, _HANDLERS

    for name, handler in _HANDLERS.items():
        positional = [
            p
            for p in inspect.signature(handler).parameters.values()
            if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD)
        ]
        if name in _AGENT_AWARE:
            assert len(positional) >= 2, f"{name} is agent-aware but takes {len(positional)}"
        else:
            assert len(positional) == 1, (
                f"{name} takes {len(positional)} positional parameters but is not in "
                f"_AGENT_AWARE, so dispatch would call it with one argument"
            )
    assert set(_AGENT_AWARE) <= set(_HANDLERS)


@pytest.mark.asyncio
async def test_a_case_variant_of_an_authorised_host_is_not_added_twice():
    """Round8 L10: the dedupe compared case-sensitively while the gate does not.

    `host_in_scope` lower-cases both sides, so `Direct-CTF2.dasctf.com` (as a user typed
    it) and `direct-ctf2.dasctf.com` are the SAME authorisation. Registration appended the
    second spelling anyway. The list must keep the operator's spelling and not grow.
    """
    agent = _agent(allowed_hosts=["Direct-CTF2.DASCTF.com"])
    await dispatch_platform_tool("platform_read_env", {"ref": REF}, agent=agent)
    hosts = agent.session_state.task_constraints.allowed_hosts
    assert hosts == ["Direct-CTF2.DASCTF.com"], hosts


def test_a_trailing_dot_variant_is_not_registered_twice():
    """The other normalisation the gate applies and the dedupe did not: the trailing dot.

    `host_in_scope` strips it from both sides, so `dasctf.com.` and `dasctf.com` are one
    authorisation. A direct unit test rather than an adapter override -- registering a
    second adapter under the same name does not reliably replace the first, and a test
    that silently exercises the ordinary path proves nothing.
    """
    from vulnclaw.platforms.tools import _authorise_hosts

    agent = _agent(allowed_hosts=[TARGET_HOST + "."])
    assert _authorise_hosts(agent, [TARGET_HOST]) is False
    assert agent.session_state.task_constraints.allowed_hosts == [TARGET_HOST + "."]
