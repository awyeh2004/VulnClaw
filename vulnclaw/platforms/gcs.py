"""GCS (West Lake Sword / 西湖论剑) adapter.

Wraps :mod:`vulnclaw.gcs_platform.client`; it does not replace it. That client
owns the platform's envelope handling (``{"code": "00000", "data": ...}``) and the
``X-Agent-AccessKey`` auth, neither of which this layer should re-derive.

Structural difference from CTF2, and why it matters here
-------------------------------------------------------

GCS publishes **no separate target endpoint**. CTF2 makes you poll a dedicated
``target`` resource (``get_target``) whose payload changes shape once running.
GCS instead embeds readiness and endpoints in the *challenge detail* itself:

* ``isNeedCheck`` -- still initializing while true
* ``isNeedInit``  -- false means the challenge needs no environment at all
* the target's host/port/user/proxy mappings live in the same payload

So :meth:`GCSAdapter.read_challenge` and :meth:`GCSAdapter.read_env` hit the *same*
upstream call. Forcing them apart would invent a call the platform does not have.

Honesty about evidence
----------------------

**No GCS credential was available while writing this**, so unlike the CTF2 adapter
there are no recorded payloads to normalize against. Field names come from the
GCS tool schema's own documented vocabulary (``exposeIps`` / ports / users / proxy
mappings / ``isNeedCheck`` / ``isNeedInit``) and endpoint discovery is a tolerant
scan. Everything inferred here is labelled ``[inferred]`` in the code, and every
response keeps its raw payload so a wrong guess degrades to "unparsed" rather than
"silently absent".

Transport is deliberately ``unknown``: GCS publishes no TLS flag we have observed,
and guessing ``tcp`` is precisely the mistake that cost 20+ minutes on CTF2.
"""

from __future__ import annotations

from collections.abc import Mapping
from typing import Any

from vulnclaw.platforms import base
from vulnclaw.platforms.base import (
    Attachment,
    Challenge,
    Corpus,
    EnvEndpoint,
    EnvInfo,
    Notice,
    SubmitResult,
)
from vulnclaw.platforms.normalize import (
    READY_KEYS,
    first_present,
    normalize_bool,
    split_host_port,
    state_from_flags,
)
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError, parse_fields
from vulnclaw.platforms.render import TOOL_READ_ENV, TOOL_START_ENV

KIND_EXERCISE = "exercise"
KIND_CATEGORY = "category"
KINDS = frozenset({KIND_EXERCISE, KIND_CATEGORY})

# [inferred] Field names that may carry target endpoints in an exercise payload.
_ENDPOINT_LIST_KEYS = (
    "exposeIps",
    "expose_ips",
    "endpoints",
    "access_urls",
    "targets",
    "ips",
    "hosts",
)
_PORT_KEYS = ("ports", "exposePorts", "expose_ports")
_USER_KEYS = ("users", "user", "username")
_READY_FIELDS = tuple(READY_KEYS) + ("is_need_init",)
_ATTACHMENT_ROW_KEYS = ("files", "attachments", "fileList", "file_list")


class GCSError(RuntimeError):
    """A GCS payload could not be used as asked."""


# ── normalization ─────────────────────────────────────────────────────────


def _walk_strings(value: Any, depth: int = 0, limit: int = 400) -> list[str]:
    """Collect strings from a nested structure, bounded so a huge payload is safe."""
    found: list[str] = []
    if depth > 6 or len(found) > limit:
        return found
    if isinstance(value, str):
        return [value]
    if isinstance(value, Mapping):
        for item in value.values():
            found += _walk_strings(item, depth + 1, limit)
    elif isinstance(value, (list, tuple)):
        for item in value:
            found += _walk_strings(item, depth + 1, limit)
    return found[:limit]


def _looks_like_endpoint(text: str) -> bool:
    candidate = text.strip()
    if not candidate or " " in candidate or len(candidate) > 200:
        return False
    if "://" in candidate:
        return True
    host, port = split_host_port(candidate)
    return bool(host and port)


def extract_endpoints(data: Mapping[str, Any]) -> tuple[EnvEndpoint, ...]:
    """[inferred] Best-effort extraction of target endpoints from an exercise payload.

    Deliberately tolerant and shape-agnostic: with no GCS credential there was no
    payload to measure, so this scans the documented endpoint-bearing keys first
    and then anything URL-shaped, rather than trusting one field name. A miss
    degrades to "no endpoint" (and ``complete=False``), which the renderer reports
    as not-ready -- never as a usable target.
    """
    candidates: list[str] = []

    for key in _ENDPOINT_LIST_KEYS:
        value = data.get(key)
        if isinstance(value, str):
            candidates.append(value)
        elif isinstance(value, (list, tuple)):
            candidates += _walk_strings(value)

    # A host without a port only becomes an endpoint once a port is known.
    host_value = ""
    for key in ("ip", "host", "address", "exposeIp"):
        raw = data.get(key)
        if isinstance(raw, str) and raw.strip():
            host_value = raw.strip()
            break
    ports: list[int] = []
    for key in _PORT_KEYS:
        raw = data.get(key)
        values = raw if isinstance(raw, (list, tuple)) else [raw]
        for item in values:
            if isinstance(item, int) and 0 < item <= 65535:
                ports.append(item)
            elif isinstance(item, str):
                _, port = split_host_port(f"h:{item}")
                if port:
                    ports.append(port)
    if host_value and ports:
        candidates += [f"{host_value}:{port}" for port in ports]

    user = ""
    for key in _USER_KEYS:
        raw = data.get(key)
        if isinstance(raw, str) and raw.strip():
            user = raw.strip()
            break
        if isinstance(raw, (list, tuple)) and raw and isinstance(raw[0], str):
            user = raw[0].strip()
            break

    endpoints: list[EnvEndpoint] = []
    seen: set[str] = set()
    for candidate in candidates:
        if not _looks_like_endpoint(candidate):
            continue
        url = candidate.strip()
        if url in seen:
            continue
        seen.add(url)
        host, port = split_host_port(url)
        endpoints.append(
            EnvEndpoint(
                host=host,
                port=port,
                url="" if url.startswith(host) and "://" not in url else url,
                # GCS publishes no transport flag we have observed; never assume tcp.
                transport=base.TRANSPORT_UNKNOWN,
                user=user,
            )
        )
    return tuple(endpoints)


def normalize_exercise_env(payload: Any, ref: ChallengeRef) -> EnvInfo:
    """Turn a GCS exercise payload into an :class:`EnvInfo`.

    Uses the shared :func:`state_from_flags` because GCS expresses readiness with
    flags rather than a status enum -- keeping that idiom out of the CTF2 adapter
    and out of the renderer.
    """
    raw = payload if isinstance(payload, Mapping) else {"raw": payload}
    data = payload.get("data") if isinstance(payload, Mapping) else None
    data = data if isinstance(data, Mapping) else {}

    if not data:
        return EnvInfo(
            ref=ref,
            state=base.STATE_NONE,
            complete=False,
            guidance=(
                f"Start one with {TOOL_START_ENV}, then poll {TOOL_READ_ENV} until the "
                f"endpoints appear.",
            ),
            raw=raw,
        )

    endpoints = extract_endpoints(data)
    needs_check = first_present(data, tuple(READY_KEYS))
    env_required = normalize_bool(data.get("isNeedInit"))
    state = state_from_flags(
        needs_check=needs_check,
        has_endpoints=bool(endpoints),
        env_required=env_required,
    )

    guidance: list[str] = []
    if state == base.STATE_RUNNING:
        guidance.append(
            "platform note: GCS does not report a transport flag, so the transport "
            "is unknown here -- try plain TCP first; if the handshake succeeds but "
            "the service never responds, try TLS."
        )
    elif state == base.STATE_NOT_REQUIRED:
        guidance.append(
            "platform note: GCS reports isNeedInit=false, so this challenge needs no "
            "environment; attack the published endpoints directly."
        )

    return EnvInfo(
        ref=ref,
        state=state,
        complete=state in (base.STATE_RUNNING, base.STATE_NOT_REQUIRED),
        endpoints=endpoints if state == base.STATE_RUNNING else (),
        guidance=tuple(guidance),
        raw=raw,
    )


def extract_attachments(data: Mapping[str, Any]) -> tuple[Attachment, ...]:
    """[inferred] Attachments from an exercise payload, tolerating field-name drift."""
    rows: list[Any] = []
    for key in _ATTACHMENT_ROW_KEYS:
        value = data.get(key)
        if isinstance(value, list):
            rows = value
            break
    attachments: list[Attachment] = []
    for row in rows:
        if isinstance(row, str):
            attachments.append(Attachment(name=row.rsplit("/", 1)[-1] or "attachment", url=row))
            continue
        if not isinstance(row, Mapping):
            continue
        url = ""
        for key in ("url", "download_url", "fileUrl", "downloadUrl", "path"):
            value = row.get(key)
            if isinstance(value, str) and value:
                url = value
                break
        nested = row.get("file")
        name = ""
        for key in ("name", "filename", "original_name"):
            value = row.get(key)
            if isinstance(value, str) and value:
                name = value
                break
        if not name and isinstance(nested, Mapping):
            inner = nested.get("original_name")
            name = inner if isinstance(inner, str) else ""
        md5 = ""
        for key in ("file_md5", "md5", "hash"):
            value = row.get(key)
            if isinstance(value, str) and value:
                md5 = value
                break
        size = row.get("size")
        if size is None and isinstance(nested, Mapping):
            size = nested.get("size")
        attachments.append(
            Attachment(
                name=name or url.rsplit("/", 1)[-1] or "attachment",
                url=url,
                md5=md5,
                size=size if isinstance(size, int) else None,
            )
        )
    return tuple(attachments)


def row_of(payload: Any) -> Mapping[str, Any]:
    """The exercise detail object inside a GCS envelope response."""
    data = payload.get("data") if isinstance(payload, Mapping) else None
    return data if isinstance(data, Mapping) else {}


def exercise_tree(payload: Any) -> list[tuple[str, list[dict]]]:
    """Flatten ``exercise_list`` into ``[(category_name, [leaf, ...]), ...]``.

    The platform returns a category tree whose leaves are the challenges; the
    leaves are what carry the numeric ``id`` used by every other call.
    """
    data = payload.get("data") if isinstance(payload, Mapping) else payload
    if isinstance(data, Mapping):
        data = data.get("list") or data.get("items") or []
    if not isinstance(data, list):
        return []
    tree: list[tuple[str, list[dict]]] = []
    for category in data:
        if not isinstance(category, Mapping):
            continue
        name = str(category.get("name") or "")
        leaves = category.get("corpus")
        if not isinstance(leaves, list):
            leaves = category.get("challenges") if isinstance(category.get("challenges"), list) else []
        tree.append((name, [leaf for leaf in leaves if isinstance(leaf, Mapping)]))
    return tree


def _leaf_id(leaf: Mapping[str, Any]) -> str:
    for key in ("id", "exerciseId", "exercise_id"):
        value = leaf.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


# ── the adapter ───────────────────────────────────────────────────────────


class GCSAdapter:
    """Platform adapter for the West Lake Sword Competition (西湖论剑).

    ``enabled_by_default = False``: the integration is legacy and the platform
    excludes the agent unless it is switched on deliberately. That default is the
    reason the adapter layer must not treat "not exposed" as "not registered".
    """

    name = "gcs"
    capabilities = frozenset({base.CAP_EVENT_INFO, base.CAP_NOTICES, base.CAP_OVERVIEW})
    enabled_by_default = False

    def __init__(self, client: Any | None = None) -> None:
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            from vulnclaw.gcs_platform import client as _client

            self._client = _client
        return self._client

    # -- addressing --------------------------------------------------------

    def is_configured(self) -> bool:
        try:
            return bool(self.client.is_configured())
        except Exception:
            return False

    def base_url(self) -> str:
        """The API base, so callers can resolve relative attachment paths.

        GCS payloads may carry a root-relative link; a caller with no base would
        have to hardcode the host, which is exactly the platform coupling this
        layer exists to remove.
        """
        try:
            return str(self.client.api_base_url() or "")
        except Exception:
            return ""

    def make_ref(self, *, kind: str, id: str = "", group: str = "") -> ChallengeRef:
        if kind not in KINDS:
            raise RefError(f"unknown GCS kind {kind!r}; expected one of {sorted(KINDS)}")
        return ChallengeRef(self.name, kind, "", id)

    def parse_ref(self, tail: str) -> ChallengeRef:
        """Parse a GCS token tail: ``exercise`` / ``exercise:<id>`` / ``category:<id>``.

        ``gcs:exercise`` is a meaningful corpus (the whole tree), but
        ``gcs:category`` without an index is not -- there is nothing to select --
        so the category form requires its id.
        """
        fields = parse_fields(tail)
        kind = fields[0]
        if kind not in KINDS:
            raise RefError(
                f"unknown GCS ref kind {kind!r}; expected one of {sorted(KINDS)}"
            )
        if len(fields) > 2:
            raise RefError(f"GCS ref takes at most one id: {tail!r}")
        ident = fields[1] if len(fields) > 1 else ""
        if kind == KIND_CATEGORY and not ident:
            raise RefError(f"GCS category ref needs an index: {tail!r}")
        return ChallengeRef(self.name, kind, "", ident)

    @staticmethod
    def _exercise_id(ref: ChallengeRef) -> int:
        if ref.kind != KIND_EXERCISE or not ref.id:
            raise GCSError(
                f"{ref.token()} is not a challenge ref: GCS needs "
                f"gcs:exercise:<exercise_id>"
            )
        try:
            return int(ref.id)
        except ValueError as exc:
            raise GCSError(f"GCS exercise id must be numeric: {ref.id!r}") from exc

    # -- listing -----------------------------------------------------------

    async def list_corpora(self) -> list[Corpus]:
        tree = exercise_tree(await self.client.exercise_list())
        corpora = [
            Corpus(
                ref=CorpusRef(self.name, KIND_CATEGORY, str(index)),
                name=name or f"category {index}",
                count=len(leaves),
            )
            for index, (name, leaves) in enumerate(tree)
        ]
        total = sum(len(leaves) for _, leaves in tree)
        corpora.append(
            Corpus(ref=CorpusRef(self.name, KIND_EXERCISE), name="all exercises", count=total)
        )
        return corpora

    async def list_challenges(self, corpus: CorpusRef) -> list[Challenge]:
        tree = exercise_tree(await self.client.exercise_list())
        if corpus.kind == KIND_EXERCISE:
            leaves = [leaf for _, group in tree for leaf in group]
        elif corpus.kind == KIND_CATEGORY:
            try:
                index = int(corpus.id)
            except (TypeError, ValueError):
                raise GCSError(f"GCS category id must be numeric: {corpus.id!r}") from None
            if index < 0 or index >= len(tree):
                raise GCSError(
                    f"GCS category {corpus.id} is out of range; call platform_list again"
                )
            leaves = tree[index][1]
        else:
            raise GCSError(f"cannot list challenges for GCS corpus kind {corpus.kind!r}")

        return [
            Challenge(
                ref=ChallengeRef(self.name, KIND_EXERCISE, "", _leaf_id(leaf)),
                name=str(leaf.get("name") or _leaf_id(leaf)),
                category=str(leaf.get("category") or ""),
                difficulty=str(leaf.get("difficulty") or ""),
                score=str(leaf.get("score")) if leaf.get("score") is not None else "",
                solved=bool(leaf.get("hasSolved")),
                needs_env=bool(leaf.get("isNeedInit")),
                raw=leaf,
            )
            for leaf in leaves
            if _leaf_id(leaf)
        ]

    # -- reading -----------------------------------------------------------

    async def read_challenge(self, ref: ChallengeRef) -> Challenge:
        exercise_id = self._exercise_id(ref)
        payload = await self.client.exercise(exercise_id)
        data = row_of(payload)
        return Challenge(
            ref=ref,
            name=str(data.get("name") or exercise_id),
            category=str(data.get("category") or ""),
            difficulty=str(data.get("difficulty") or ""),
            score=str(data.get("score") if data.get("score") is not None else ""),
            description=str(data.get("description") or ""),
            solved=bool(data.get("hasSolved")),
            needs_env=bool(data.get("isNeedInit")),
            attachments=extract_attachments(data),
            raw=payload if isinstance(payload, Mapping) else {"raw": payload},
        )

    # -- environment lifecycle ---------------------------------------------

    async def start_env(self, ref: ChallengeRef) -> EnvInfo:
        exercise_id = self._exercise_id(ref)
        payload = await self.client.build_environment(exercise_id)
        info = normalize_exercise_env(payload, ref)
        if info.state == base.STATE_RUNNING:
            return info
        # build-exercise-env is asynchronous by design: the acknowledgement is not
        # the target. Poll instead of treating a partial payload as usable.
        return EnvInfo(
            ref=ref,
            state=base.STATE_STARTING,
            complete=False,
            guidance=(
                f"the environment is being created; poll {TOOL_READ_ENV} until "
                f"isNeedCheck is false and endpoints are published.",
            ),
            raw=info.raw,
        )

    async def read_env(self, ref: ChallengeRef) -> EnvInfo:
        """Same upstream call as :meth:`read_challenge`, by design (see module docstring)."""
        exercise_id = self._exercise_id(ref)
        payload = await self.client.exercise(exercise_id)
        return normalize_exercise_env(payload, ref)

    async def stop_env(self, ref: ChallengeRef) -> None:
        exercise_id = self._exercise_id(ref)
        await self.client.recover_environment(exercise_id)

    # -- submission --------------------------------------------------------

    async def submit_flag(self, ref: ChallengeRef, flag: str) -> SubmitResult:
        exercise_id = self._exercise_id(ref)
        payload = await self.client.submit_answer(exercise_id, flag)
        return SubmitResult(
            accepted=submit_accepted(payload),
            judged=True,
            message=_first_text(payload),
            raw=payload if isinstance(payload, Mapping) else {"raw": payload},
        )

    # -- optional facets ---------------------------------------------------

    async def event_info(self) -> str:
        payload = await self.client.match_info()
        data = row_of(payload)
        note = str(data.get("note") or "")
        rule = str(data.get("rule") or "")
        text = "\n".join(part for part in (note, rule) if part)
        return text or str(payload)

    async def notices(self, notice_id: str | None = None) -> Any:
        """Announcements: the whole list, or one detail.

        The list response wraps a LIST in ``data``, so it must not be forced
        through the Mapping helper the detail path uses -- doing so silently
        turned a populated list into ``{}``.
        """
        if notice_id in (None, ""):
            payload = await self.client.notice_list()
            data = payload.get("data") if isinstance(payload, Mapping) else None
            return data if data is not None else payload
        try:
            numeric = int(str(notice_id))
        except ValueError as exc:
            raise GCSError(f"GCS notice id must be numeric: {notice_id!r}") from exc
        return row_of(await self.client.notice_detail(numeric))

    async def overview(self) -> Mapping[str, Any]:
        return row_of(await self.client.overview())


# ── helpers ───────────────────────────────────────────────────────────────


def submit_accepted(payload: Any) -> bool:
    """Whether an answer payload reports a correct flag (GCS uses ``isCorrect``)."""
    data = payload.get("data") if isinstance(payload, Mapping) else None
    for source in (data, payload):
        if isinstance(source, Mapping):
            for key in ("isCorrect", "correct", "accepted"):
                if key in source:
                    return bool(source[key])
            if "success" in source:
                return bool(source["success"])
    return False


def _first_text(payload: Any) -> str:
    data = payload.get("data") if isinstance(payload, Mapping) else None
    for source in (data, payload):
        if isinstance(source, Mapping):
            for key in ("message", "msg", "detail", "error"):
                value = source.get(key)
                if isinstance(value, str) and value:
                    return value
    return ""


def notice_from_row(row: Mapping[str, Any]) -> Notice:
    """Build a :class:`Notice` from a GCS notice row (used by tests and callers)."""
    return Notice(
        id=str(row.get("id") or ""),
        title=str(row.get("title") or ""),
        content=str(row.get("content") or ""),
    )
