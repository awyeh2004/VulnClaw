"""round13 F3: URL-path scope matching must resolve dot segments.

The prefix semantics added in 6208773 matched the RAW ``urlparse`` path, so
``/storage/../admin`` passed an allowed ``/storage`` prefix while the server
resolved the request to ``/admin`` — an agent-constructible bypass of the very
constraint that is supposed to fence it in. Percent-encoded dots (``%2e``) are
decoded server-side and must not sneak through either.
"""

from types import SimpleNamespace

from vulnclaw.agent.builtin_tools import (
    _normalize_url_path,
    enforce_host_path_constraints,
)


def _agent(allowed_paths=(), blocked_paths=()):
    constraints = SimpleNamespace(
        allowed_hosts=[],
        blocked_hosts=[],
        allowed_paths=list(allowed_paths),
        blocked_paths=list(blocked_paths),
        allowed_ports=[],
        blocked_ports=[],
        is_empty=lambda: False,
    )
    return SimpleNamespace(session_state=SimpleNamespace(task_constraints=constraints))


class TestNormalizeUrlPath:
    def test_dot_segments_resolved(self):
        assert _normalize_url_path("/storage/../admin") == "/admin"
        assert _normalize_url_path("/storage/./x") == "/storage/x"
        assert _normalize_url_path("/a/b/../../c") == "/c"

    def test_percent_encoded_dots_resolved(self):
        assert _normalize_url_path("/storage/%2e%2e/admin") == "/admin"

    def test_leading_double_slashes_collapsed(self):
        # posixpath.normpath preserves "//x"; scope edges must not be moved by
        # a doubled leading slash.
        assert _normalize_url_path("//storage/x") == "/storage/x"

    def test_plain_paths_unchanged(self):
        assert _normalize_url_path("/storage/{addr}/{slot}") == "/storage/{addr}/{slot}"
        assert _normalize_url_path("/") == "/"


class TestAllowedPathsDotSegmentBypass:
    def test_traversal_out_of_prefix_is_rejected(self):
        agent = _agent(allowed_paths=["/storage"])
        violation = enforce_host_path_constraints(agent, path="/storage/../admin")
        assert violation is not None and "constraint_violation" in violation

    def test_encoded_traversal_out_of_prefix_is_rejected(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/%2e%2e/admin") is not None

    def test_real_subpath_still_allowed(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/{addr}/{slot}") is None

    def test_exact_prefix_still_allowed(self):
        agent = _agent(allowed_paths=["/storage/"])
        assert enforce_host_path_constraints(agent, path="/storage") is None


class TestBlockedPathsNormalization:
    def test_blocked_path_hit_via_traversal(self):
        agent = _agent(allowed_paths=["/"], blocked_paths=["/admin"])
        assert enforce_host_path_constraints(agent, path="/admin/../admin") is not None

    def test_unrelated_path_not_blocked(self):
        agent = _agent(allowed_paths=["/"], blocked_paths=["/admin"])
        assert enforce_host_path_constraints(agent, path="/storage/x") is None
