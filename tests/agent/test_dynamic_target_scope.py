"""Fail-closed scope guard for dynamically built network targets.

Audit item C (2026-10-24): the host/path gate on python_execute and
shell_command only ever saw string-literal URLs. ``requests.get("http://" +
host)``, ``urlopen(os.environ["URL"])``, ``curl $URL`` and
``curl "http://"$(cat f)`` executed unchecked against allowed/blocked hosts.
These tests pin the fail-closed behaviour and -- just as important -- the
shapes that must KEEP working: static constant-built targets, literal URLs
with dynamic headers, and unconstrained local runs.
"""

from __future__ import annotations

import pytest

import vulnclaw.agent.builtin_tools as builtin_tools
from vulnclaw.agent.context import ContextManager, TaskConstraints


class _Runtime:
    run_id = ""


class _Session:
    def __init__(self):
        self.task_constraints = TaskConstraints()


class _Safety:
    def __init__(self):
        self.enable_python_execute = True
        self.python_execute_restricted = False
        self.python_execute_mode = "trusted-local"
        self.python_execute_max_lines = 50
        self.python_execute_show_warning = False
        self.python_execute_max_output_chars = 0
        self.python_execute_audit_enabled = False
        self.denied_hosts = []


class _Config:
    def __init__(self):
        self.safety = _Safety()


class _Agent:
    def __init__(self):
        self.config = _Config()
        self.context = ContextManager()
        self.runtime = _Runtime()
        self.session_state = _Session()
        self.mcp_manager = None


class _AutoApprove:
    def __init__(self):
        self.views = []

    async def request_approval(self, view):
        self.views.append(view)
        return "approve"


@pytest.fixture()
def auto_approve():
    from vulnclaw.agent.exec_gate import get_execution_gate, reset_execution_gate

    reset_execution_gate()
    get_execution_gate().install_channel(_AutoApprove())


@pytest.fixture()
def fake_spawn(monkeypatch):
    monkeypatch.setattr(
        builtin_tools, "_spawn_captured", lambda *a, **k: (0, "ok", "", False)
    )


def _scoped(agent, *, allowed=None, blocked=None, allowed_ports=None):
    constraints = agent.session_state.task_constraints
    if allowed is not None:
        constraints.allowed_hosts = list(allowed)
    if blocked is not None:
        constraints.blocked_hosts = list(blocked)
    if allowed_ports is not None:
        constraints.allowed_ports = list(allowed_ports)
    constraints.strict_mode = True
    return agent


class TestPythonDynamicTarget:
    async def test_concatenated_url_is_refused_under_scope(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": 'import requests\nrequests.get("http://" + host + "/x")'}
        )
        assert "constraint_violation" in result
        assert "dynamically" in result

    async def test_env_var_url_is_refused_under_scope(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent,
            {"code": 'import requests, os\nrequests.get(os.environ["TARGET_URL"])'},
        )
        assert "constraint_violation" in result
        assert "dynamically" in result

    async def test_fstring_url_is_refused_under_scope(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": 'import requests\nrequests.get(f"http://{host}/x")'}
        )
        assert "constraint_violation" in result

    async def test_unbound_name_url_is_refused_under_scope(self, auto_approve, fake_spawn):
        """A name this checker cannot resolve is dynamic: it cannot be proved in scope."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": "import requests\nrequests.get(url)"}
        )
        assert "constraint_violation" in result

    async def test_static_constant_chain_still_passes(self, auto_approve, fake_spawn):
        """``base = "http://…"; url = base + "/x"; get(url)`` is statically known."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent,
            {
                "code": (
                    "import requests\n"
                    'base = "http://allowed.test"\n'
                    'url = base + "/x"\n'
                    "print(requests.get(url))"
                )
            },
        )
        assert "constraint_violation" not in result

    async def test_request_object_wrapper_still_passes(self, auto_approve, fake_spawn):
        """``req = urllib.request.Request(literal); urlopen(req)`` is not dynamic."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent,
            {
                "code": (
                    "import urllib.request\n"
                    'req = urllib.request.Request("http://allowed.test/x")\n'
                    "print(urllib.request.urlopen(req))"
                )
            },
        )
        assert "constraint_violation" not in result

    async def test_without_scope_dynamic_urls_keep_running(self, auto_approve, fake_spawn):
        agent = _Agent()
        result = await builtin_tools.execute_python(
            agent, {"code": 'import requests\nrequests.get("http://" + host + "/x")'}
        )
        assert "constraint_violation" not in result

    async def test_blocked_host_named_anywhere_is_refused(self, auto_approve, fake_spawn):
        """The cheap first pass: naming a blocked host at all, even off-URL."""
        agent = _scoped(_Agent(), allowed=["allowed.test"], blocked=["evil.test"])
        result = await builtin_tools.execute_python(
            agent,
            {"code": 'host = "evil.test"\nprint("plan for", host)'},
        )
        assert "constraint_violation" in result
        assert "evil.test" in result

    async def test_hard_denylist_bites_without_task_scope(self, auto_approve, fake_spawn):
        """safety.denied_hosts is read directly: scope-less runs still refuse."""
        agent = _Agent()
        agent.config.safety.denied_hosts = ["tp.example.com"]
        result = await builtin_tools.execute_python(
            agent, {"code": 'print("target", "tp.example.com")'}
        )
        assert "constraint_violation" in result


class TestShellDynamicTarget:
    async def test_variable_url_is_refused_under_scope(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": 'curl "$URL"'}
        )
        assert "constraint_violation" in result
        assert "scope-checked" in result

    async def test_dynamic_fragment_is_refused(self, auto_approve, fake_spawn):
        """Blocked-only scope: the literal loop cannot judge `$h`, the new rule can.

        Under an allowed_hosts scope the literal loop already refuses the garbage
        host; with only blocked_hosts there is nothing to compare against, which
        is exactly the hole the fragment rule closes.
        """
        agent = _scoped(_Agent(), blocked=["evil.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "curl http://$h/x"}
        )
        assert "constraint_violation" in result
        assert "no literal" in result

    async def test_dynamic_fragment_is_refused_under_allowed_scope_too(
        self, auto_approve, fake_spawn
    ):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "curl http://$h/x"}
        )
        assert "constraint_violation" in result

    async def test_substitution_built_url_is_refused(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": 'curl "http://"$(cat host.txt)"/x"'}
        )
        assert "constraint_violation" in result

    async def test_powershell_variable_uri_is_refused(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "Invoke-WebRequest -Uri $u"}
        )
        assert "constraint_violation" in result

    async def test_literal_url_with_dynamic_header_still_passes(
        self, auto_approve, fake_spawn
    ):
        """`-H "$AUTH"` is a header, not the target: the literal target was checked."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": 'curl -sS http://allowed.test/x -H "$AUTH"'}
        )
        assert "constraint_violation" not in result

    async def test_schemeless_literal_is_scope_checked(self, auto_approve, fake_spawn):
        """`curl evil.test/x` has no scheme for the literal loop; still blocked."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "curl -sS evil.test/x"}
        )
        assert "constraint_violation" in result
        assert "evil.test" in result

    async def test_schemeless_in_scope_target_runs(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "curl -sS allowed.test/x"}
        )
        assert "constraint_violation" not in result

    async def test_blocked_host_named_in_command_is_refused(self, auto_approve, fake_spawn):
        agent = _scoped(_Agent(), allowed=["allowed.test"], blocked=["evil.test"])
        result = await builtin_tools.execute_shell_command(
            agent, {"command": "echo probing evil.test next"}
        )
        assert "constraint_violation" in result

    async def test_without_scope_variable_urls_keep_running(self, auto_approve, fake_spawn):
        agent = _Agent()
        result = await builtin_tools.execute_shell_command(
            agent, {"command": 'curl "$URL"'}
        )
        assert "constraint_violation" not in result


class TestPythonEgressAuditHook:
    """Audit item C2, python side: the staged payload itself refuses out-of-scope
    sockets via sys.addaudithook (installed by the framework, uninstallable by
    the payload). These run the REAL staged subprocess; every violation raises
    before any network I/O, and the one allowed case connects to a closed
    loopback port, so nothing leaves the machine.
    """

    # The host is CONCATENATED so the C-layer text scan cannot see it: this
    # test proves the in-payload hook catches egress the string scanner misses.
    CODE_DNS_BLOCKED = (
        "import socket\n"
        'h = "evil" + ".test"\n'
        "socket.create_connection((h, 80), timeout=2)\n"
    )
    CODE_DNS_OUT_OF_ALLOWED = (
        "import socket\n"
        'socket.create_connection(("other.test", 80), timeout=2)\n'
    )
    CODE_PORT_BLOCKED = (
        "import socket\n"
        'socket.create_connection(("127.0.0.1", 8080), timeout=2)\n'
    )
    CODE_RAW_IP_PASSTHROUGH = (
        "import socket\n"
        "try:\n"
        '    socket.create_connection(("127.0.0.1", 1), timeout=2)\n'
        "except OSError:\n"
        "    print('refused-as-expected')\n"
    )
    CODE_LOCALHOST_ALLOWED = (
        "import socket\n"
        'print(socket.getaddrinfo("localhost", 80)[:1])\n'
    )

    async def test_blocked_host_dns_is_refused(self, auto_approve):
        agent = _scoped(_Agent(), blocked=["evil.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_DNS_BLOCKED, "timeout": 20}
        )
        assert "constraint_violation" in result
        assert "DNS resolution" in result

    async def test_out_of_allowed_dns_is_refused(self, auto_approve):
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_DNS_OUT_OF_ALLOWED, "timeout": 20}
        )
        assert "constraint_violation" in result

    async def test_out_of_scope_port_is_refused(self, auto_approve):
        agent = _scoped(_Agent(), allowed_ports=[80])
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_PORT_BLOCKED, "timeout": 20}
        )
        assert "constraint_violation" in result
        assert "port" in result

    async def test_raw_ip_connect_is_not_falsely_blocked_by_name_scope(
        self, auto_approve
    ):
        """Documented scope: the allowed-NAME list is enforced at DNS; a raw-IP
        connect only enforces blocked lists/ports (an IP cannot be compared
        against a name inside the payload)."""
        agent = _scoped(_Agent(), allowed=["allowed.test"])
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_RAW_IP_PASSTHROUGH, "timeout": 20}
        )
        assert "constraint_violation" not in result
        assert "refused-as-expected" in result

    async def test_localhost_flow_still_works(self, auto_approve):
        """The name→IP handoff (getaddrinfo localhost → connect 127.0.0.1) must
        not false-positive: localhost resolves to an IP the name check never saw."""
        agent = _scoped(_Agent(), allowed=["localhost"])
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_LOCALHOST_ALLOWED, "timeout": 20}
        )
        assert "constraint_violation" not in result

    async def test_no_scope_means_no_hook(self, auto_approve):
        agent = _Agent()
        result = await builtin_tools.execute_python(
            agent, {"code": self.CODE_RAW_IP_PASSTHROUGH, "timeout": 20}
        )
        assert "constraint_violation" not in result
