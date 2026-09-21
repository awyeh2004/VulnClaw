"""CTF2 (DASCTF) adapter: normalizes the CTF2 API into the platform vocabulary.

Wraps :mod:`vulnclaw.ctf_platform.client` -- it does not replace it.  That client
holds hard-won knowledge (the Open API vs front-end session API split, the
401-fallback routing) that this layer must not re-derive.

What is *verified* here versus what is best-effort
-------------------------------------------------

The environment lifecycle is normalized against payloads recorded from the real
2026-09-21 run (see ``tests/platforms/ctf2_payloads.py``, which carries the
provenance): ``status=starting`` omits the connection details, ``status=running``
adds ``access_url`` / ``access_urls[]`` / ``nc_ssl``.

Two traps that payload data exposed and that this module encodes explicitly:

1. **``access_type`` is NOT the transport.**  A real running target carries
   ``access_type: "tcp"`` *and* ``nc_ssl: true`` at the same time.  Mapping
   ``access_type`` onto the transport would classify a TLS endpoint as plain TCP
   -- the exact confusion that cost 20+ minutes on the live challenge, since a
   raw socket against TLS completes the handshake and then goes silent.
   Only ``nc_ssl`` (entry-level first, then top-level) decides TLS.
2. **A successful TLS handshake does not mean the target is alive.**  An expired
   instance's proxy answers the handshake and then says
   ``[ TARGET NOT FOUND ] This address has no running target.``  The platform
   payload is the authority on liveness; this symptom is surfaced as guidance.

List endpoints are normalized defensively: the exact envelope of
``list_practice`` / ``list_daily`` was never captured in the recorded runs, so
row extraction tolerates the common shapes and every list response keeps its raw
payload, rather than pretending to a certainty we do not have.

Known gap, deliberately not papered over: the CTF2 routes in the client expose
``practice`` listing, ``daily`` listing, ``competitions`` and
``stage -> challenges``, but **no "list the challenges of a practice ground"**.
:meth:`CTF2Adapter.list_challenges` therefore raises a readable error for that
case instead of inventing a route.
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
    Notice,  # noqa: F401 - re-exported for symmetry with the optional facets
    SubmitResult,
)
from vulnclaw.platforms.normalize import (
    TRANSPORT_KEYS,
    first_present,
    normalize_status,
    normalize_transport,
    split_host_port,
)
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError, parse_fields
from vulnclaw.platforms.render import TOOL_READ_ENV, TOOL_START_ENV

KIND_PRACTICE = "practice"
KIND_DAILY = "daily"
KIND_STAGE = "stage"
KINDS = frozenset({KIND_PRACTICE, KIND_DAILY, KIND_STAGE})


class CTF2Error(RuntimeError):
    """A CTF2 payload could not be used as asked."""


# ``access_type`` is documented here as a field we deliberately ignore; naming it
# keeps the reason visible next to the code that must not use it.
IGNORED_TRANSPORT_FIELD = "access_type"


# ── target payload normalization ──────────────────────────────────────────


def extract_endpoints(data: Mapping[str, Any]) -> tuple[EnvEndpoint, ...]:
    """Build endpoints from a CTF2 target payload's ``data`` object.

    Prefers ``access_urls[]`` (richer: per-entry ``nc_ssl``) and falls back to
    the flat ``access_url``.  Transport resolution order per endpoint:
    the entry's own flag, then the payload's top-level flag, then unknown.
    """
    top_level = first_present(data, TRANSPORT_KEYS)
    endpoints: list[EnvEndpoint] = []

    entries = data.get("access_urls")
    if isinstance(entries, list):
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            url = str(entry.get("url") or entry.get("access_url") or "").strip()
            if not url:
                continue
            marker = first_present(entry, TRANSPORT_KEYS)
            if marker is None:
                marker = top_level
            host, port = split_host_port(url)
            endpoints.append(
                EnvEndpoint(
                    host=host,
                    port=port,
                    url=url,
                    transport=normalize_transport(marker),
                    user=str(entry.get("user") or ""),
                    note=str(entry.get("type") or ""),
                )
            )

    if not endpoints:
        url = str(data.get("access_url") or "").strip()
        if url:
            host, port = split_host_port(url)
            endpoints.append(
                EnvEndpoint(
                    host=host,
                    port=port,
                    url=url,
                    transport=normalize_transport(top_level),
                    note=str(data.get("access_type") or ""),
                )
            )
    return tuple(endpoints)


def normalize_target_payload(payload: Any, ref: ChallengeRef) -> EnvInfo:
    """Turn a CTF2 target payload into an :class:`EnvInfo`.

    ``complete`` is True only when the state is running AND at least one
    endpoint was published -- "running with no endpoint" is still nothing to
    connect to.
    """
    raw = payload if isinstance(payload, Mapping) else {"raw": payload}
    data = payload.get("data") if isinstance(payload, Mapping) else None

    if not isinstance(data, Mapping):
        # No guidance tuple here: the renderer already emits the start->poll
        # instruction for STATE_NONE, and supplying it here printed it twice.
        return EnvInfo(
            ref=ref,
            state=base.STATE_NONE,
            complete=False,
            raw=raw,
        )

    state = normalize_status(data.get("status"))
    endpoints: tuple[EnvEndpoint, ...] = ()
    complete = False

    if state == base.STATE_RUNNING:
        endpoints = extract_endpoints(data)
        complete = bool(endpoints)

    guidance: list[str] = []
    if state == base.STATE_RUNNING and endpoints:
        transports = {ep.transport for ep in endpoints}
        if base.TRANSPORT_TLS in transports:
            guidance.append(
                "platform note: CTF2 reports this endpoint as TLS-wrapped "
                "(field `nc_ssl: true`). The target's `access_type: tcp` is the "
                "connection type, NOT the transport -- it does not mean plain TCP."
            )
        elif base.TRANSPORT_UNKNOWN in transports:
            guidance.append(
                "platform note: CTF2 did not report `nc_ssl` for this endpoint, so "
                "the transport is unknown here -- probe rather than assume."
            )
        guidance.append(
            "platform note: a successful TLS handshake does NOT prove the target is "
            "alive. An expired instance still answers the handshake and then replies "
            "'RANGE KEEPER / [ TARGET NOT FOUND ] This address has no running "
            f"target.' -- if you see that, restart the target with {TOOL_START_ENV} "
            "and re-read the endpoint (the host changes) instead of retrying payloads."
        )

    return EnvInfo(
        ref=ref,
        state=state,
        complete=complete,
        endpoints=endpoints,
        expires_at=str(data.get("expires_at") or ""),
        guidance=tuple(guidance),
        raw=raw,
    )


# ── list payload tolerance ────────────────────────────────────────────────

_ROW_ID_KEYS = ("id", "challenge_id", "challengeId", "practice_id", "practiceId")
# Daily rows WRAP the challenge: {"id": <daily entry id>, "challenge_id": ...,
# "challenge": {...}}. The challenge id must win there, or the ref addresses the
# daily-entry row instead of the challenge.
_CHALLENGE_ROW_ID_KEYS = ("challenge_id", "challengeId")
_ROW_NAME_KEYS = ("name", "title", "challenge_name")
_CHILD_LIST_KEYS = ("challenges", "challenge_list", "corpus", "children", "list")


def extract_rows(payload: Any) -> list[dict]:
    """Best-effort extraction of a list of rows from a CTF2 list response.

    Two envelopes exist and both are measured:

    * Open API lists: ``{"data": {"items": [...], "total": n}}``
    * session-API practice challenge list:
      ``{"data": {"data": [...], "pagination": {...}}}`` -- the rows are nested
      one level deeper, so an ``items``-only reader sees nothing.

    Other keys are tolerated so a future envelope change degrades to an empty list
    rather than a crash.
    """
    data = payload.get("data") if isinstance(payload, Mapping) else payload
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, Mapping):
        for key in ("items", "data", "list", "results", "rows"):
            value = data.get(key)
            if isinstance(value, list):
                return [row for row in value if isinstance(row, dict)]
    return []


def _row_id(row: Mapping[str, Any]) -> str:
    for key in _ROW_ID_KEYS:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def challenge_row_id(row: Mapping[str, Any]) -> str:
    """The challenge id of a list row, preferring the wrapped ``challenge``."""
    for key in _CHALLENGE_ROW_ID_KEYS:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    nested = row.get("challenge")
    if isinstance(nested, Mapping):
        for key in ("id", "challenge_id"):
            value = nested.get(key)
            if value not in (None, ""):
                return str(value)
    return _row_id(row)


def _row_name(row: Mapping[str, Any]) -> str:
    for key in _ROW_NAME_KEYS:
        value = row.get(key)
        if value not in (None, ""):
            return str(value)
    return ""


def _nested_name(row: Mapping[str, Any]) -> str:
    """Names for wrapped rows (daily/submissions nest the challenge object)."""
    nested = row.get("challenge")
    return _row_name(nested) if isinstance(nested, Mapping) else ""


def _embedded_children(row: Mapping[str, Any]) -> list[dict]:
    """Challenge rows embedded inside a corpus row, when the platform nests them."""
    for key in _CHILD_LIST_KEYS:
        value = row.get(key)
        if isinstance(value, list):
            return [child for child in value if isinstance(child, dict)]
    return []


# ── the adapter ───────────────────────────────────────────────────────────


class CTF2Adapter:
    """Platform adapter for CTF2 (DASCTF)."""

    name = "ctf2"
    capabilities = frozenset({base.CAP_SUBMISSIONS})
    enabled_by_default = True

    def __init__(self, client: Any | None = None) -> None:
        # Injectable for tests; the real client is imported lazily so this module
        # stays importable without httpx-adjacent platform state.
        self._client = client

    @property
    def client(self) -> Any:
        if self._client is None:
            from vulnclaw.ctf_platform import client as _client

            self._client = _client
        return self._client

    # -- addressing --------------------------------------------------------

    def is_configured(self) -> bool:
        try:
            return bool(self.client.is_configured())
        except Exception:
            return False

    def make_ref(self, *, kind: str, id: str, group: str = "") -> ChallengeRef:
        if kind not in KINDS:
            raise RefError(f"unknown CTF2 kind {kind!r}; expected one of {sorted(KINDS)}")
        return ChallengeRef(self.name, kind, group, id)

    def parse_ref(self, tail: str) -> ChallengeRef:
        """Parse a CTF2 token tail: ``<kind>[:<group>][:<id>]``."""
        fields = parse_fields(tail)
        kind = fields[0]
        if kind not in KINDS:
            raise RefError(
                f"unknown CTF2 ref kind {kind!r}; expected one of {sorted(KINDS)}"
            )
        rest = fields[1:]
        if kind == KIND_DAILY:
            if len(rest) > 1:
                raise RefError(f"CTF2 daily ref takes at most one id: {tail!r}")
            return ChallengeRef(self.name, kind, "", rest[0] if rest else "")
        if len(rest) > 2:
            raise RefError(f"CTF2 {kind} ref takes at most a group and an id: {tail!r}")
        group = rest[0] if rest else ""
        ident = rest[1] if len(rest) > 1 else ""
        if not group:
            raise RefError(f"CTF2 {kind} ref needs a {kind} id: {tail!r}")
        return ChallengeRef(self.name, kind, group, ident)

    @staticmethod
    def _pair(ref: ChallengeRef) -> tuple[str, str]:
        """The (practice_id, challenge_id) pair the CTF2 API actually takes.

        For ``practice`` refs the group IS the practice id.  For ``stage`` refs
        the platform takes a stage id where the client expects a practice id
        (the routes are shape-identical), which is why this is a named helper --
        it is the one place that mapping is made.
        """
        if not ref.group or not ref.id:
            raise CTF2Error(
                f"{ref.token()} is not a challenge ref: CTF2 needs both a "
                f"{ref.kind} id and a challenge id"
            )
        return ref.group, ref.id

    # -- listing -----------------------------------------------------------

    async def list_corpora(self) -> list[Corpus]:
        corpora: list[Corpus] = []

        for row in extract_rows(await self.client.list_practice(limit=50)):
            practice_id = _row_id(row)
            if not practice_id:
                continue
            children = _embedded_children(row)
            count = row.get("challenge_count")
            corpora.append(
                Corpus(
                    ref=CorpusRef(self.name, KIND_PRACTICE, practice_id),
                    name=_row_name(row) or practice_id,
                    count=count if isinstance(count, int) else (len(children) or None),
                )
            )

        corpora.append(
            Corpus(ref=CorpusRef(self.name, KIND_DAILY), name="daily challenges")
        )

        for row in extract_rows(await self.client.list_competitions(limit=50)):
            for stage in _embedded_children(row):
                stage_id = _row_id(stage)
                if not stage_id:
                    continue
                corpora.append(
                    Corpus(
                        ref=CorpusRef(self.name, KIND_STAGE, stage_id),
                        name=_row_name(stage) or stage_id,
                        note=f"stage of competition {_row_name(row) or '?'}",
                    )
                )
        return corpora

    async def list_challenges(self, corpus: CorpusRef) -> list[Challenge]:
        if corpus.kind == KIND_DAILY:
            rows = extract_rows(await self.client.list_daily(limit=50))
            return [
                Challenge(
                    ref=ChallengeRef(self.name, KIND_DAILY, "", challenge_row_id(row)),
                    name=_row_name(row) or _nested_name(row) or challenge_row_id(row),
                    raw=row,
                )
                for row in rows
                if challenge_row_id(row)
            ]

        if corpus.kind == KIND_STAGE:
            rows = extract_rows(
                await self.client.list_stage_challenges(corpus.id, limit=100)
            )
            return [
                Challenge(
                    ref=ChallengeRef(self.name, KIND_STAGE, corpus.id, _row_id(row)),
                    name=_row_name(row) or _row_id(row),
                    raw=row,
                )
                for row in rows
                if _row_id(row)
            ]

        if corpus.kind == KIND_PRACTICE:
            # The Open API has no challenge-list route for a practice ground
            # (`/api/open/v1/user/practice/<pid>/challenges/` is a hard 404), so
            # this goes through the session API, which does have it. Until that
            # was found, a practice ground's challenges were simply not
            # enumerable -- which is why `platform_list` used to say so.
            payload = await self.client.list_practice_challenges(corpus.id)
            return [
                Challenge(
                    ref=ChallengeRef(self.name, KIND_PRACTICE, corpus.id, _row_id(row)),
                    name=_row_name(row) or _row_id(row),
                    category=str(row.get("category") or ""),
                    difficulty=str(row.get("difficulty") or ""),
                    score=str(row.get("points")) if row.get("points") is not None else "",
                    solved=bool(row.get("is_solved")),
                    needs_env=bool(row.get("has_container")),
                    raw=row,
                )
                for row in extract_rows(payload)
                if _row_id(row)
            ]

        raise CTF2Error(f"cannot list challenges for CTF2 corpus kind {corpus.kind!r}")

    # -- reading -----------------------------------------------------------

    async def read_challenge(self, ref: ChallengeRef) -> Challenge:
        practice_id, challenge_id = self._pair(ref)
        payload = await self.client.read_challenge(practice_id, challenge_id)
        data = payload.get("data") if isinstance(payload, Mapping) else None
        data = data if isinstance(data, Mapping) else {}
        # Field names confirmed against the live platform: `is_solved`, `points`
        # and `has_container`. (`hasSolved` / `score` are GCS's names -- using
        # them here silently produced solved=False and an empty score.)
        return Challenge(
            ref=ref,
            name=str(data.get("name") or challenge_id),
            category=str(data.get("category") or ""),
            difficulty=str(data.get("difficulty") or ""),
            score=str(data.get("points") if data.get("points") is not None else ""),
            description=str(data.get("description") or ""),
            solved=bool(data.get("is_solved")),
            needs_env=bool(data.get("has_container")),
            attachments=extract_attachments(data),
            raw=payload if isinstance(payload, Mapping) else {"raw": payload},
        )

    # -- environment lifecycle ---------------------------------------------

    async def start_env(self, ref: ChallengeRef) -> EnvInfo:
        practice_id, challenge_id = self._pair(ref)
        payload = await self.client.start_environment(practice_id, challenge_id)
        info = normalize_target_payload(payload, ref)
        if info.state in (base.STATE_NONE, base.STATE_STARTING):
            # Either the Open API answered with a queue acknowledgement, or the
            # session API returned 202 + task_id. Both mean: poll read_env.
            return EnvInfo(
                ref=ref,
                state=base.STATE_STARTING,
                complete=False,
                expires_at=info.expires_at,
                guidance=(
                    f"the environment is being created; poll {TOOL_READ_ENV} in ~10s "
                    f"until status={base.STATE_RUNNING} (connection details are NOT in "
                    f"this response).",
                ),
                raw=info.raw,
            )
        return info

    async def read_env(self, ref: ChallengeRef) -> EnvInfo | None:
        practice_id, challenge_id = self._pair(ref)
        if not self.client.session_token():
            raise CTF2Error(
                "CTF2 target lookup needs the front-end session token "
                "(VULNCLAW_CTF2_SESSION_TOKEN, or a logged-in Edge/Chrome profile). "
                "The Open API cannot see target addresses."
            )
        payload = await self.client.get_target(practice_id, challenge_id)
        return normalize_target_payload(payload, ref)

    async def stop_env(self, ref: ChallengeRef) -> None:
        practice_id, challenge_id = self._pair(ref)
        if not self.client.session_token():
            raise CTF2Error(
                "releasing a CTF2 target needs the front-end session token; the "
                "instance still expires on the platform TTL, but its slot stays busy."
            )
        await self.client.stop_target(practice_id, challenge_id)

    # -- submission --------------------------------------------------------

    async def submit_flag(self, ref: ChallengeRef, flag: str) -> SubmitResult:
        practice_id, challenge_id = self._pair(ref)
        payload = await self.client.submit_flag(practice_id, challenge_id, flag)
        return SubmitResult(
            accepted=submit_accepted(payload),
            judged=True,
            message=submit_message(payload),
            raw=payload if isinstance(payload, Mapping) else {"raw": payload},
        )

    async def submissions(self, limit: int = 20) -> list[dict]:
        """Optional facet (CTF2 only): the user's recent submissions."""
        return extract_rows(await self.client.list_submissions(limit=limit))


# ── helpers ───────────────────────────────────────────────────────────────


def extract_attachments(data: Mapping[str, Any]) -> tuple[Attachment, ...]:
    """Pull attachments out of a challenge payload.

    Field names confirmed against the live platform: a row carries
    ``download_url`` / ``file_url`` / ``url``, and the bytes' metadata is nested
    under ``file`` (``original_name``, ``size``, ``mime_type``) -- so a flat
    ``row["name"]`` / ``row["size"]`` lookup silently yields nothing. No md5 is
    published, which is why the download path must verify whatever the platform
    does give rather than assume a hash exists.
    """
    rows = data.get("files") or data.get("attachments") or []
    if not isinstance(rows, list):
        return ()
    attachments: list[Attachment] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        inner = row.get("file") if isinstance(row.get("file"), Mapping) else {}

        url = ""
        for key in ("download_url", "file_url", "url", "downloadUrl"):
            value = row.get(key)
            if isinstance(value, str) and value:
                url = value
                break

        name = ""
        for key in ("original_name", "name", "filename", "file_name"):
            value = inner.get(key) if key == "original_name" else row.get(key)
            if isinstance(value, str) and value:
                name = value
                break
        if not name:
            inner_name = inner.get("original_name")
            if isinstance(inner_name, str):
                name = inner_name

        md5 = ""
        for key in ("file_md5", "md5", "hash"):
            value = row.get(key)
            if isinstance(value, str) and value:
                md5 = value
                break

        size = inner.get("size", row.get("size"))
        attachments.append(
            Attachment(
                name=name or url.rsplit("/", 1)[-1] or "attachment",
                url=url,
                md5=md5,
                size=size if isinstance(size, int) else None,
                note=str(inner.get("mime_type") or ""),
            )
        )
    return tuple(attachments)


def submit_accepted(payload: Any) -> bool:
    """Whether a submit payload reports an accepted flag (tolerant)."""
    data = payload.get("data") if isinstance(payload, Mapping) else None
    for source in (data, payload):
        if isinstance(source, Mapping):
            for key in ("accepted", "isCorrect", "correct"):
                if key in source:
                    return bool(source[key])
            if "success" in source:
                return bool(source["success"])
    return False


def submit_message(payload: Any) -> str:
    """A short human-readable outcome, without hiding the raw payload."""
    data = payload.get("data") if isinstance(payload, Mapping) else None
    for source in (data, payload):
        if isinstance(source, Mapping):
            for key in ("message", "msg", "detail", "error"):
                value = source.get(key)
                if isinstance(value, str) and value:
                    return value
    return ""
