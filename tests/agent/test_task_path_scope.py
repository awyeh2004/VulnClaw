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


class TestDoubleEncodingAndRawLeg:
    """round14 F-A/F-B: percent-decoding must cover EVERY encoding layer, and
    the allowed check must pass under BOTH the decoded and the raw reading —
    the decoded leg alone is fail-open for servers that keep ``%2F`` literal."""

    def test_double_encoded_dots_resolved(self):
        assert _normalize_url_path("/storage/%252e%252e/admin") == "/admin"

    def test_triple_encoded_dots_resolved(self):
        assert _normalize_url_path("/storage/%25252e%25252e/admin") == "/admin"

    def test_double_encoded_traversal_rejected(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/%252e%252e/admin") is not None

    def test_encoded_slash_literal_rejected(self):
        # Decoding makes this look like /storage/docs, but a server that keeps
        # %2F literal routes it outside /storage/* — the raw leg must reject.
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage%2Fdocs") is not None

    def test_double_encoded_blocked_hit(self):
        agent = _agent(allowed_paths=["/"], blocked_paths=["/admin"])
        assert enforce_host_path_constraints(agent, path="/adm%2569n") is not None

    def test_encoded_space_still_allowed(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/my%20docs") is None

    def test_utf8_encoded_still_allowed(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/%E6%96%87%E6%A1%A3") is None

    def test_exact_prefix_with_trailing_slash_entry_still_allowed(self):
        # The raw leg must not break the round-12 equivalence: entry "/storage/"
        # covers the bare "/storage" request.
        agent = _agent(allowed_paths=["/storage/"])
        assert enforce_host_path_constraints(agent, path="/storage") is None

    def test_request_with_trailing_slash_still_allowed(self):
        agent = _agent(allowed_paths=["/storage"])
        assert enforce_host_path_constraints(agent, path="/storage/") is None

