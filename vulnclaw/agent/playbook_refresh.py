"""Re-query the note store with the features the FIRST PROBE actually measured.

Why this exists: the opening query is built from the challenge *name*
(:func:`playbook.challenge_class_signature`), which is nearly information-free --
measured 2026-09-23, the goal written as ``([Weblogic]SSRF)`` yields a two-token
signature and, before the overlap floor existed, made every Weblogic note score 1.0.
The page, however, says much more once it has been fetched: title, ``Server`` /
``X-Powered-By`` headers, the paths it links to, the parameters those links carry.
Until now nothing re-asked the store with that evidence, so the opening recall was
whatever the challenge NAME could guess, for the whole run.

Extraction is deliberately NOT reimplemented here: the five helpers this module calls
are the ones the tool layer already uses for the same purpose
(``builtin_tools._extract_html_title`` / ``_extract_endpoints`` / ``_extract_html_surfaces``
/ ``_http_body_signals``); a second copy of "how to read a page" would drift out of
sync exactly like the flag-prefix copy did. Only the *selection* of what is worth
querying (and the dedupe/cap) is new.

Hard constraints this module respects:

* it never raises for a missing/odd evidence record -- the caller wraps it anyway,
  but a refresh is best-effort by contract;
* it never touches the network or the model: it reads recorded evidence only;
* it only ever RECOMMENDS a replacement; the caller owns the brief and the logging.

Note on what is NOT re-checked: the model's blackboard (LOCK / CONFIRMED facts) is
the other obvious query source the handoff mentions. Deliberately left out for this
change -- the facts are model-authored prose ("the flag is read from the environment
inside the container"), and the probe evidence is the measured, non-speculative
signal. Mixing an unmeasured source into a change whose whole point is "measure,
then re-ask" would make the result unattributable.
"""

from __future__ import annotations

import json
import re
from typing import Any, Iterable, Optional, Sequence

# Tools whose recorded output can contain a real HTTP response. Read from evidence
# rather than from a live call: a refresh must never cost a network round trip.
#
# ``python_execute`` / ``shell_command`` are in here because that is what the model
# ACTUALLY uses on CTF2. Measured 2026-09-24 on a real solve log: 8 x python_execute +
# 5 x shell_command, and ZERO calls to ``http_probe_batch`` / ``fetch`` / ``http_request``
# -- the log contained no ``body:`` marker and no ``response_headers=`` line at all.
# While this set listed only the sanctioned probe tools, ``probe_signature`` returned ""
# for every real run, so the whole re-query was dead code that no unit test could catch
# (the fixtures used the sanctioned format). Reading every tool's text is safe here
# because the parser is not format-bound: it looks for a <title>, for Server /
# X-Powered-By header text and for path-like strings wherever they appear, and anything
# it fails to recognise simply yields no tokens.
HTTP_EVIDENCE_TOOLS = frozenset(
    {
        "http_probe_batch",
        "fetch",
        "http_request",
        "curl",
        "python_execute",
        "shell_command",
    }
)

# Query-length cap. ``Playbook.score`` is the share of the QUERY's tokens found in a
# note, so an ever-growing probe query eventually dilutes every real hit below
# ``min_score`` and the refresh would then empty the brief. Measured on the fixture
# page used by the tests: uncapped, a 40-link page produced 80 query tokens and pushed
# real hits to ~0.02. Capped at 18, the discriminators (title / server / powered-by /
# paths) dominate.
MAX_PROBE_TOKENS = 18

# Path segments that carry no identity: every framework has them, so they only add
# noise to the query (and noise is what the overlap floor is there to remove).
_GENERIC_PATH_SEGMENTS = frozenset(
    {
        "index", "home", "main", "default", "login", "logout", "register", "static",
        "assets", "images", "img", "css", "js", "fonts", "favicon", "favicon.ico",
        "api", "v1", "v2", "public", "www", "html", "php", "asp", "aspx", "jsp",
    }
)

# Query-parameter names that appear on every web app and therefore identify nothing.
_GENERIC_PARAMS = frozenset(
    {
        "id", "page", "lang", "language", "v", "ver", "version", "t", "ts", "time",
        "callback", "format", "type", "action", "method", "redirect", "next", "ref",
        "utm_source", "utm_medium", "utm_campaign", "_", "s", "q", "search",
    }
)

# Where an http_probe_batch body starts inside the recorded raw output.
_BODY_MARKER = "\n    body:\n"

# Words that belong to ERROR PAGES AND HTML MARKUP rather than to a challenge. An
# unauthenticated 404/WAF page ("Error 404--Not Found TITLE Helvetica COLOR black") is
# a real page with a real <title>, so it passes every "is this a page?" check while
# identifying nothing -- the same template is served by every instance of that server.
# A signature made only of these words is therefore treated as no signature at all.
_TEMPLATE_STOP = frozenset(
    {
        "error", "errors", "not", "found", "title", "color", "colors", "helvetica",
        "html", "head", "body", "meta", "font", "style", "center", "table", "tr",
        "td", "div", "span", "br", "hr", "nbsp", "doctype", "public", "envelope",
        "xmlns", "schemas", "xmlsoap", "encoding", "fault", "faultstring", "soap",
        "soapenv", "workcontext", "message", "stacktrace", "frame", "class", "java",
        "void", "string", "array", "method", "status", "result", "output", "command",
        "elapsed", "truncated", "preview", "stored", "chars", "raw", "size",
        "execution", "trusted", "local", "diagnostic", "observed", "directory",
        # colour/font words from server-generated error pages
        "black", "white", "grey", "gray", "red", "blue", "green", "silver", "navy",
        "maroon", "arial", "verdana", "sans", "serif", "monospace", "bold", "size",
    }
)

# A response header line rendered as JSON-ish text by the probe formatter.
_HEADER_RE = re.compile(
    r'"(?P<name>server|x-powered-by)"\s*:\s*"(?P<value>[^"]{1,120})"', re.IGNORECASE
)


def _dedupe_keep_order(items: Iterable[str], limit: int) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for item in items:
        key = item.strip().lower()
        if not key or key in seen:
            continue
        seen.add(key)
        out.append(item.strip())
        if len(out) >= limit:
            break
    return out


def _evidence_texts(evidence: Sequence[Any]) -> list[str]:
    """Raw outputs of the HTTP-ish evidence records, newest last."""
    texts: list[str] = []
    for record in evidence or []:
        if str(getattr(record, "tool", "") or "") not in HTTP_EVIDENCE_TOOLS:
            continue
        content = str(getattr(record, "content", "") or "")
        if content:
            texts.append(content)
    return texts


def _response_body(raw: str) -> str:
    """The response body inside a recorded tool output.

    A sanctioned ``http_probe_batch`` result marks it with an indented ``body:`` line;
    a ``python_execute`` / ``shell_command`` output (what the model actually uses) is
    just the program's stdout, so the whole text IS the candidate body. Returning ""
    for the unmarked case was the second half of the "the re-query never fires" defect:
    even after the tool-name filter was widened, the parser would still have found
    nothing to read.
    """
    text = str(raw or "")
    _, marker, tail = text.partition(_BODY_MARKER)
    if not marker:
        return text
    return "\n".join(line[4:] if line.startswith("    ") else line for line in tail.splitlines())


def _signature_values_from_text(raw: str) -> list[str]:
    """Measured discriminators of ONE recorded HTTP response, in priority order."""
    from vulnclaw.agent.builtin_tools import (
        _extract_endpoints,
        _extract_html_surfaces,
        _extract_html_title,
        _http_body_signals,
    )

    body = _response_body(raw)
    values: list[str] = []
    strong = False
    title = _extract_html_title(body)
    if title:
        values.append(title)
        strong = True
    for match in _HEADER_RE.finditer(raw or ""):
        values.append(f"{match.group('name')} {match.group('value')}")
        strong = True
    # Paths the page itself advertises, plus the parameter names they carry. Both are
    # per-challenge: "/wls-wsat/CoordinatorPortType" or "?uddiexplorer" say far more
    # than the word "weblogic" ever could.
    for endpoint in _extract_endpoints(body):
        path = str(endpoint).split("#", 1)[0]
        path = path.split("?", 1)[0].strip()
        if path:
            signal = _path_signal(path)
            if signal:
                values.append(signal)
                strong = True
        query = str(endpoint).partition("?")[2]
        if query:
            for name in re.findall(r"[?&]([a-z0-9_\-\[\]]{2,40})=", "?" + query, re.IGNORECASE):
                if name.strip("[]").lower() in _GENERIC_PARAMS:
                    continue
                values.append(name.strip("[]"))
                strong = True
    # A path-like string the model printed itself (curl/wget output, an error trace, a
    # payload it just sent). This is the case that matters on CTF2, where the model
    # probes with python_execute rather than with the sanctioned probe tool: the raw
    # stdout is all we get, and "/wls-wsat/CoordinatorPortType" appears in it as plain
    # text. Counted as strong only with a slash, so a bare error word is not enough.
    if not strong:
        for match in re.finditer(r"(?<![\w/])(/[A-Za-z0-9_\-][\w\-./]{2,60})", body):
            signal = _path_signal(match.group(1))
            if signal and "/" in signal:
                values.append(signal)
                strong = True
                if len(values) >= 6:
                    break
    # Form/input markup without repeating the endpoint extraction above.
    for surface in _extract_html_surfaces(body):
        for match in re.finditer(r'(?i)\bname\s*=\s*["\']([^"\']{2,40})["\']', surface):
            values.append(match.group(1))
    # Only the class-defining words out of the body signals. The helper falls back to
    # plain visible text when no marker line exists, and feeding that whole blob in as
    # query tokens would dilute every real hit (the score is a share of the QUERY).
    #
    # These are scored as WEAK on their own. Measured 2026-09-24 by replaying the real
    # tool outputs of a CTF2 run through this parser: the outputs that carry no page and
    # no path produced signatures like "Python execution result trusted-local status
    # elapsed sleep" and "Error 404--Not Found TITLE Helvetica COLOR black" -- pure tool
    # plumbing and error boilerplate. Re-querying the store with those would REPLACE a
    # good brief that was built from the challenge name, which is strictly worse than
    # doing nothing. Hence ``strong``: the probe must show a real page signature
    # (title / response header / path) before anything is asked with it.
    for match in re.finditer(r"[A-Za-z][A-Za-z0-9_\-]{4,30}", _http_body_signals(body, 240) if body else ""):
        word = match.group(0)
        if word.lower() in _GENERIC_PARAMS or word.lower() in _GENERIC_PATH_SEGMENTS:
            continue
        values.append(word)
    return [value for value in values if str(value or "").strip()] if strong else []


def _path_signal(path: str) -> str:
    """A path reduced to its identifying segments.

    Generic segments (``/static/``, ``/api/``, ``/login``) are dropped because they
    are shared by every app, and a shared token is exactly what made the old
    one-token class hits useless.
    """
    parts = [
        part
        for part in re.split(r"[/\\.]+", path)
        if part and part.lower() not in _GENERIC_PATH_SEGMENTS
    ]
    return "/".join(parts[-3:]) if parts else ""


def probe_signature(evidence: Sequence[Any], *, max_tokens: int = MAX_PROBE_TOKENS) -> str:
    """The query built from the measured features of the recorded HTTP evidence.

    Deduped and capped at TOKEN level, not at value level: the discriminators arrive as
    multi-word values (a title, ``Server Weblogic Server 12.2.1.3``), and "Weblogic
    Server" appearing in both the title and the header used to survive as two values
    that tokenize into the same words. The cap is what keeps the query short enough to
    score: ``Playbook.score`` divides by the number of query tokens, so an uncapped
    40-link page pushed the query to 80 tokens and every genuine hit scored ~0.02 --
    below ``min_score``, i.e. the refresh would find nothing precisely on the richest
    pages.

    Returns ``""`` when the evidence holds no usable HTTP response, which the caller
    must read as "nothing new to ask" -- never as "replace the brief with nothing".
    """
    values: list[str] = []
    for raw in _evidence_texts(evidence):
        values.extend(_signature_values_from_text(raw))
    # Split to tokens FIRST, then cap: capping whole values would not bound the query,
    # because one value ("console/login/LoginForm") carries three tokens. Measured on
    # the 40-link fixture: a value-level cap returned 18 values that tokenized into 26.
    tokens = _dedupe_keep_order(
        (
            tok
            for value in values
            for tok in re.split(r"[^A-Za-z0-9_\-]+", value)
        ),
        max_tokens,
    )
    # A signature of template vocabulary only is no signature. Measured 2026-09-24 by
    # replaying a real CTF2 run's outputs: the very first HTTP result the model produced
    # was an unauthenticated error page whose title ("Error 404--Not Found") tokenizes
    # to words that identify no challenge, yet it would have replaced a brief built from
    # the challenge name -- strictly worse than doing nothing. Requiring TWO tokens
    # outside the template vocabulary keeps the refusal cheap and explainable.
    informative = [tok for tok in tokens if tok.lower() not in _TEMPLATE_STOP]
    if len(informative) < 2:
        return ""
    return " ".join(tokens)


def _hit_slugs(rows: Iterable[dict[str, Any]]) -> list[str]:
    return [str(row.get("slug", "")) for row in rows]


def _normalized(signature: str) -> tuple[str, ...]:
    return tuple(sorted({tok for tok in re.split(r"[^a-z0-9]+", (signature or "").lower()) if tok}))


def should_replace(
    previous_rows: Sequence[dict[str, Any]],
    new_rows: Sequence[dict[str, Any]],
) -> tuple[bool, str]:
    """Whether the refresh should replace the brief, plus a short reason for the log.

    The criterion is the hit SET, deliberately and only: same notes with different
    numbers is not a reason to rewrite the system prompt, and a score threshold would
    add a number nobody can calibrate (the probe query is far longer than the class
    signature, so every score moves when it changes). What the operator needs from the
    log is "which notes are in the prompt now", and that changes exactly when the set
    does -- so a mere re-ordering of the same notes also leaves the prompt alone.

    The "no" outcomes matter as much as the "yes": replacing on every probe would make
    the refresh unobservable (an event on every step says nothing about which step
    changed the answer) and would churn the prompt for nothing.
    """
    if not new_rows:
        return False, "the probe query matched no notes (kept the previous brief)"
    if set(_hit_slugs(previous_rows)) != set(_hit_slugs(new_rows)):
        return True, (
            f"hit set changed {_hit_slugs(previous_rows)} -> {_hit_slugs(new_rows)}"
        )
    return False, (
        f"same notes {_hit_slugs(new_rows)} (a re-query that changes nothing must not "
        "rewrite the prompt)"
    )


def new_signature_only(previous_signature: str, signature: str) -> bool:
    """Whether the probe query itself changed, ignoring row ordering."""
    return _normalized(previous_signature) != _normalized(signature)


def blocked_notice_rows(blocked: Sequence[dict[str, Any]], limit: int = 3) -> list[str]:
    """The blocked rows reduced to ``slug=overlap`` strings for the run log."""
    out: list[str] = []
    for row in list(blocked)[:limit]:
        slug = str(row.get("slug", "") or "?")
        out.append(f"{slug}={int(row.get('overlap_tokens', 0) or 0)}")
    return out


def record_signature(*, signature: str, previous: Optional[str]) -> str:
    """The signature to remember as "already asked". Empty stays empty."""
    return signature or (previous or "")
