"""CTFd adapter — the platform used by most public and university CTFs.

Why this is a separate module rather than a flag on an existing one: CTF2 and GCS
are *agent-oriented* APIs (an agent token, per-challenge environments, an
`is_solved` field). CTFd is a plain jeopardy board — one flat challenge list, no
environment concept, and a flag submission that answers with a status string.

Field names come from CTFd's own source (`CTFd/api/v1/challenges.py`), not from
guessing at a live response — measured 2026-11-21, the public docs show only
"200 Success" for the attempt endpoint, which is not enough to normalize against.

What actually matters here:

* **The environment concept does not exist.** `read_env` returns ``None`` (the
  protocol's documented "no environment for this ref"), which is a fact about the
  platform rather than a missing feature. Callers then treat the target as static.
* **Submission outcomes are a closed set with one dangerous member.** CTFd answers
  ``correct`` / ``partial`` / ``incorrect`` / ``already_solved`` / ``ratelimited``
  / ``authentication_required``. ``ratelimited`` and ``authentication_required``
  are *not* judgements of the flag, and treating them as wrong answers would burn
  attempts and mislead the run — hence ``SubmitResult.judged``.
* **Auth is a token in a header, and it is easy to leak.** The token is read from
  config and never echoed; a failed auth is reported by name, not by dumping the
  request.
"""

from __future__ import annotations

import json
import logging
import urllib.error
import urllib.parse
import urllib.request
from collections.abc import Mapping
from typing import Any

from vulnclaw.platforms import base
from vulnclaw.platforms.base import (
    Attachment,
    Challenge,
    Corpus,
    EnvInfo,
    SubmitResult,
)
from vulnclaw.platforms.refs import ChallengeRef, CorpusRef, RefError, parse_fields

logger = logging.getLogger(__name__)

NAME = "ctfd"

KIND_CHALLENGE = "challenge"
KIND_CATEGORY = "category"
KINDS = frozenset({KIND_CHALLENGE, KIND_CATEGORY})

#: CTFd's own closed set of attempt outcomes, from ``api/v1/challenges.py``.
STATUS_CORRECT = "correct"
STATUS_PARTIAL = "partial"
STATUS_INCORRECT = "incorrect"
STATUS_ALREADY_SOLVED = "already_solved"
STATUS_RATELIMITED = "ratelimited"
STATUS_AUTH_REQUIRED = "authentication_required"

#: Outcomes that mean "the platform graded this flag". Everything else is a
#: transport or quota problem and must not be counted as a wrong answer.
JUDGED_STATUSES = frozenset(
    {STATUS_CORRECT, STATUS_PARTIAL, STATUS_INCORRECT, STATUS_ALREADY_SOLVED}
)
ACCEPTED_STATUSES = frozenset({STATUS_CORRECT, STATUS_ALREADY_SOLVED})

DEFAULT_TIMEOUT_S = 20.0


class CTFdError(RuntimeError):
    """An upstream call failed in a way the caller should see."""


class CTFdAdapter:
    """Adapter for a CTFd instance (``https://<host>/``).

    Deliberately synchronous at the HTTP layer and wrapped in ``asyncio.to_thread``
    by the async verbs: CTFd is a handful of JSON calls per challenge, and adding
    an async client dependency here would buy nothing over the stdlib.
    """

    name = NAME
    capabilities = frozenset({base.CAP_OVERVIEW})
    #: Off unless asked for. A platform nobody configured must not put its tools
    #: in front of the model — the registry's fail-closed rule, restated here so
    #: reading this file alone tells the truth.
    enabled_by_default = False

    def __init__(self, *, base_url: str = "", token: str = "", timeout_s: float = DEFAULT_TIMEOUT_S) -> None:
        self._base_url = str(base_url or "").strip().rstrip("/")
        self._token = str(token or "").strip()
        self._timeout_s = timeout_s

    # ── config ──────────────────────────────────────────────────────────
    def is_configured(self) -> bool:
        return bool(self._base_url and self._token)

    def make_ref(self, *, kind: str, id: str, group: str = "") -> ChallengeRef:
        if kind not in KINDS:
            raise RefError(f"unknown CTFd kind {kind!r}; expected one of {sorted(KINDS)}")
        return ChallengeRef(self.name, kind, group, id)

    def parse_ref(self, tail: str) -> ChallengeRef:
        """Parse a CTFd token tail: ``<kind>[:<group>][:<id>]``."""
        fields = parse_fields(tail)
        kind = fields[0]
        if kind not in KINDS:
            raise RefError(f"unknown CTFd ref kind {kind!r}; expected one of {sorted(KINDS)}")
        rest = fields[1:]
        if kind == KIND_CATEGORY:
            return ChallengeRef(self.name, kind, rest[0] if rest else "", "")
        if len(rest) < 1:
            raise RefError("CTFd challenge ref needs an id, e.g. ctfd:challenge:<id>")
        return ChallengeRef(self.name, kind, "", rest[0])

    # ── HTTP ────────────────────────────────────────────────────────────
    def _request(self, method: str, path: str, payload: Mapping[str, Any] | None = None) -> Any:
        if not self.is_configured():
            raise CTFdError(
                "CTFd is not configured: set platforms.ctfd.url and platforms.ctfd.token"
            )
        url = f"{self._base_url}{path}"
        data = None
        headers = {
            "Accept": "application/json",
            # CTFd accepts `Authorization: Token <value>`; the docs spell the scheme
            # as "AccessToken" but the implementation matches on the token itself.
            "Authorization": f"Token {self._token}",
            "User-Agent": "vulnclaw-ctfd-adapter",
        }
        if payload is not None:
            data = json.dumps(payload).encode("utf-8")
            headers["Content-Type"] = "application/json"
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self._timeout_s) as response:
                body = response.read()
        except urllib.error.HTTPError as exc:
            # Never include the Authorization header or the token in the message.
            detail = ""
            try:
                detail = exc.read().decode("utf-8", errors="replace")[:200]
            except Exception:  # noqa: BLE001
                detail = ""
            if exc.code in (401, 403):
                raise CTFdError(
                    f"CTFd rejected the token for {method} {path} ({exc.code}); "
                    "check platforms.ctfd.token"
                ) from exc
            raise CTFdError(f"CTFd {method} {path} -> HTTP {exc.code}: {detail}") from exc
        except urllib.error.URLError as exc:
            raise CTFdError(f"CTFd unreachable at {self._base_url}: {exc.reason}") from exc
        if not body:
            return None
        try:
            return json.loads(body.decode("utf-8", errors="replace"))
        except json.JSONDecodeError as exc:
            raise CTFdError(
                f"CTFd {method} {path} returned non-JSON (likely a login redirect; "
                "is the competition open and the token valid?)"
            ) from exc

    # ── mapping ─────────────────────────────────────────────────────────
    def _challenge_from(self, data: Mapping[str, Any], *, category: str = "") -> Challenge:
        """Map one CTFd challenge payload onto the neutral model."""
        cid = str(data.get("id") or "").strip()
        files = data.get("files") or []
        attachments: list[Attachment] = []
        for raw in files:
            # CTFd returns a list of URLs (older) or list of {url,name} (newer).
            if isinstance(raw, str):
                attachments.append(
                    Attachment(name=_basename(raw), url=raw)
                )
            elif isinstance(raw, Mapping):
                url = str(raw.get("url") or raw.get("location") or "")
                if url:
                    attachments.append(
                        Attachment(name=str(raw.get("name") or _basename(url)), url=url)
                    )
        return Challenge(
            ref=self.make_ref(kind=KIND_CHALLENGE, id=cid),
            name=str(data.get("name") or ""),
            category=str(data.get("category") or category or ""),
            difficulty="",
            score=str(data.get("value") or ""),
            description=str(data.get("description") or ""),
            solved=bool(data.get("solved_by_me")),
            needs_env=bool(str(data.get("connection_info") or "").strip()),
            attachments=tuple(attachments),
            raw=dict(data),
        )

    # ── protocol ────────────────────────────────────────────────────────
    async def list_corpora(self) -> list[Corpus]:
        challenges = await self.list_challenges(CorpusRef(self.name, KIND_CATEGORY, ""))
        categories: dict[str, int] = {}
        for challenge in challenges:
            key = challenge.category or "uncategorised"
            categories[key] = categories.get(key, 0) + 1
        return [
            Corpus(
                ref=self.make_ref(kind=KIND_CATEGORY, id=name),
                name=name,
                count=count,
            )
            for name, count in sorted(categories.items())
        ]

    async def list_challenges(self, corpus: CorpusRef) -> list[Challenge]:
        import asyncio

        payload = await asyncio.to_thread(self._request, "GET", "/api/v1/challenges")
        rows = _data_list(payload)
        wanted = (corpus.id or "").strip() if corpus is not None else ""
        challenges = [self._challenge_from(row) for row in rows if isinstance(row, Mapping)]
        if wanted:
            challenges = [c for c in challenges if c.category == wanted]
        return challenges

    async def read_challenge(self, ref: ChallengeRef) -> Challenge:
        import asyncio

        cid = (ref.id or "").strip()
        if not cid:
            raise RefError("CTFd challenge ref has no id")
        payload = await asyncio.to_thread(
            self._request, "GET", f"/api/v1/challenges/{urllib.parse.quote(cid)}"
        )
        data = _data_object(payload)
        if not isinstance(data, Mapping):
            raise CTFdError(f"CTFd did not return challenge {cid}")
        return self._challenge_from(data)

    async def start_env(self, ref: ChallengeRef) -> EnvInfo:
        """CTFd has no environment concept; report that as a fact, not a failure."""
        return EnvInfo(
            ref=ref,
            state=base.STATE_NOT_REQUIRED,
            complete=True,
        )

    async def read_env(self, ref: ChallengeRef) -> EnvInfo | None:
        """None means "this platform has no environment for the ref"."""
        return None

    async def stop_env(self, ref: ChallengeRef) -> None:
        return None

    async def submit_flag(self, ref: ChallengeRef, flag: str) -> SubmitResult:
        """Submit a flag. A wrong flag is a judgement, not an exception."""
        import asyncio

        cid = (ref.id or "").strip()
        if not cid:
            raise RefError("CTFd challenge ref has no id")
        # CTFd compares the challenge id as a number; sending a string works on
        # current releases but sends the wrong type into its type checks.
        numeric: Any = int(cid) if cid.isdigit() else cid
        payload = await asyncio.to_thread(
            self._request,
            "POST",
            "/api/v1/challenges/attempt",
            {"challenge_id": numeric, "submission": str(flag or "")},
        )
        data = payload.get("data") if isinstance(payload, Mapping) else None
        if not isinstance(data, Mapping):
            return SubmitResult(
                accepted=False,
                judged=False,
                message="CTFd returned no attempt result",
                raw=dict(payload) if isinstance(payload, Mapping) else {},
            )
        status = str(data.get("status") or "").strip().lower()
        judged = status in JUDGED_STATUSES
        return SubmitResult(
            accepted=status in ACCEPTED_STATUSES,
            judged=judged,
            message=str(data.get("message") or status or ""),
            raw=dict(data),
        )

    async def overview(self) -> Mapping[str, Any]:
        """Scoreboard summary, best effort — used for a pre-match sanity check."""
        import asyncio

        try:
            payload = await asyncio.to_thread(
                self._request, "GET", "/api/v1/scoreboard/top/10"
            )
        except CTFdError as exc:
            return {"error": str(exc)}
        return payload if isinstance(payload, Mapping) else {}


# ── helpers ───────────────────────────────────────────────────────────


def _basename(url: str) -> str:
    path = urllib.parse.urlparse(str(url or "")).path
    name = path.rsplit("/", 1)[-1]
    return urllib.parse.unquote(name) or "attachment"


def _data_list(payload: Any) -> list[Any]:
    if isinstance(payload, Mapping):
        data = payload.get("data")
        if isinstance(data, list):
            return data
        # CTFd wraps list endpoints as {"data": [...]}; a dict here means an error
        # envelope, which the caller will see as "no challenges".
        return []
    return []


def _data_object(payload: Any) -> Any:
    if isinstance(payload, Mapping):
        return payload.get("data")
    return None


def build_adapter(config: Any) -> CTFdAdapter:
    """Build the adapter from ``platforms.ctfd`` config, or an unconfigured one.

    The token may also come from ``CTFd_TOKEN`` / ``CTFD_TOKEN``, which is the
    safer place for it: ``~/.vulnclaw/config.yaml`` is a file people paste into
    bug reports and screenshots. Config wins over the environment so an operator
    running two instances can pin one explicitly.
    """
    import os

    section = _config_section(config, NAME)
    token = (
        str(_field(section, "token", "api_token") or "").strip()
        or os.environ.get("CTFD_TOKEN", "").strip()
        or os.environ.get("CTFd_TOKEN", "").strip()
    )
    return CTFdAdapter(
        base_url=str(_field(section, "url", "base_url") or os.environ.get("CTFD_URL", "") or ""),
        token=token,
    )


def _config_section(config: Any, name: str) -> Any:
    platforms = getattr(config, "platforms", None)
    if platforms is None:
        return None
    entry = getattr(platforms, name, None)
    if entry is None and isinstance(getattr(platforms, "model_extra", None), dict):
        entry = platforms.model_extra.get(name)
    return entry


def _field(section: Any, *names: str) -> Any:
    if section is None:
        return None
    for name in names:
        value = getattr(section, name, None)
        if value:
            return value
        if isinstance(section, Mapping):
            value = section.get(name)
            if value:
                return value
        extra = getattr(section, "model_extra", None)
        if isinstance(extra, dict) and extra.get(name):
            return extra[name]
    return None