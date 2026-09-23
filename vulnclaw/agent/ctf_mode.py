"""CTF flag state-machine helpers for AgentCore."""

from __future__ import annotations

import re
from typing import TYPE_CHECKING, Optional

if TYPE_CHECKING:
    from vulnclaw.agent.agent_context import AgentContext


# Flag-shaped literals for the known platforms. SINGLE SOURCE OF TRUTH for "what a
# flag looks like by prefix":
#
#   * detect_flag_claim() matches the whole list to decide whether the model is
#     claiming a flag;
#   * finding_parser imports FLAG_PREFIX_PATTERNS (the prefix subset, WITHOUT the
#     generic catch-all) to spot flag literals in model output and record them as
#     notes.
#
# They used to be maintained separately, and the copy in finding_parser had already
# drifted down to 3 of these 17 prefixes -- so a DASCTF{} / BUUCTF{} / CTFshow{} flag
# mentioned in a response was never recorded as a note.
FLAG_PREFIX_PATTERNS = [
    # Chinese CTF platforms
    r"(DASCTF\{[^}]+\})",
    r"(NSSCTF\{[^}]+\})",
    r"(BUUCTF\{[^}]+\})",
    r"(CTFshow\{[^}]+\})",
    r"(GXCTF\{[^}]+\})",
    r"(D0g3\{[^}]+\})",
    r"(HDCTF\{[^}]+\})",
    r"(ISCTF\{[^}]+\})",
    r"(SCTF\{[^}]+\})",
    r"(HCTF\{[^}]+\})",
    r"(ACTF\{[^}]+\})",
    # International CTF platforms
    r"(CTF\{[^}]+\})",
    r"(FLAG\{[^}]+\})",
    r"(flag\{[^}]+\})",
    r"(Flag\{[^}]+\})",
    # Capitalized variants
    r"(DASctf\{[^}]+\})",
    r"(Nssctf\{[^}]+\})",
]

# Deliberately kept OUT of the prefix list: it matches ANY word{...}, which is
# acceptable as a last-resort detection pattern but far too loose for note extraction.
GENERIC_FLAG_PATTERN = r"(?:^|\s)([A-Za-z0-9_]+\{[^}]+\})(?:\s|$)"

# Comprehensive CTF flag format patterns
# Covers major CTF platforms in China and international competitions
FLAG_PATTERNS = [*FLAG_PREFIX_PATTERNS, GENERIC_FLAG_PATTERN]


def detect_flag_claim(output: str) -> Optional[str]:
    """Detect if the LLM claims to have found a flag."""
    for pattern in FLAG_PATTERNS:
        match = re.search(pattern, output)
        if match:
            return match.group(1)
    return None


# Markers that mean "the flag is verified / the challenge is solved".
#
# SINGLE SOURCE OF TRUTH, and it is a UNION of two lists that used to be maintained
# separately: `detect_verification_success`'s own list, and a second inline list in
# `update_ctf_state` OR-ed with it at its only call site. Measured drift between them:
# "challenge solved" and "got the flag" existed ONLY in the inline list, while
# "the flag is", "captured" and "成功破解" existed ONLY in the function's list. So the
# function's real contribution was just its unique entries, and the two vocabularies
# were silently diverging -- the same failure mode FLAG_PREFIX_PATTERNS had (its copy
# in finding_parser had drifted to 3 of 17 prefixes).
VERIFICATION_CLAIM_MARKERS: tuple[str, ...] = (
    # Chinese
    "验证成功",
    "验证通过",
    "已验证",
    "复现成功",
    "确认flag",
    "flag正确",
    "提交成功",
    "flag 获取成功",
    "flag获取成功",
    "获取成功",
    "找到flag",
    "成功获取",
    "获取了flag",
    "拿到了flag",
    "成功拿到",
    "成功找到",
    "解题完成",
    "解题成功",
    "成功破解",
    "验证flag成功",
    # English
    "verified",
    "confirmed",
    "flag found",
    "flag is",
    "the flag is",
    "captured",
    "flag captured",
    "flag verified",
    "confirms the flag",
    "verification successful",
    "verification passed",
    "flag confirmed",
    "submission successful",
    "flag acquired",
    "successfully obtained",
    "solved the challenge",
    "challenge solved",
    "got the flag",
    "obtained the flag",
)

# Negation cues. A marker match only counts as a success claim when it is NOT negated
# on either side, because a plain substring test gets the meaning EXACTLY backwards on
# text that denies success. Measured false positives before this existed:
#   "无法验证成功"            -> contains "验证成功"
#   "尚未验证成功"            -> contains "验证成功"
#   "not confirmed"          -> contains "confirmed"
#   "the flag is not the correct one" -> contains "the flag is"
# `update_ctf_state` turns this signal into `flag_verified`, which stops the run after
# two post-flag rounds -- so a denial could end a run the model itself said had failed.
_NEGATION_BEFORE = (
    "未",
    "没有",
    "没能",
    "未能",
    "尚未",
    "无法",
    "不能",
    "并非",
    "不是",
    "not ",
    "never ",
    "no ",
    "cannot",
    "can't",
    "couldn't",
    "didn't",
    "wasn't",
    "isn't",
    "unable",
    "failed to",
    "without",
)
_NEGATION_AFTER = (
    "不对",
    "不正确",
    "不是",
    "失败",
    "not ",
    "is not",
    "was not",
    "isn't",
    "wasn't",
    "never",
    "incorrect",
    "wrong",
)
# How far either side to look. Deliberately short: a cue in the NEXT sentence must not
# suppress a real claim, and the cues that matter sit immediately next to the marker.
_LOOK_BEHIND = 24
_LOOK_AHEAD = 12


def _is_negated(text: str, start: int, end: int) -> bool:
    """Whether a marker occurrence at ``text[start:end]`` is negated nearby.

    Case-insensitive, and that is not cosmetic. The cue lists are lowercase and the two
    callers hand over text in DIFFERENT cases: `detect_verification_success` lowercases
    first, while `finding_parser` passes the response verbatim. So on original-case text
    a cue like "NOT " never matched, and `NOT confirmed` read as a success claim -- the
    very inversion this function exists to prevent, in uppercase form.

    Lowercasing the two WINDOWS rather than the whole string keeps the indices valid,
    which matters because `.lower()` can change a string's length for some Unicode.
    """
    before = text[max(0, start - _LOOK_BEHIND):start].lower()
    after = text[end:end + _LOOK_AHEAD].lower()
    return any(cue in before for cue in _NEGATION_BEFORE) or any(
        cue in after for cue in _NEGATION_AFTER
    )


def detect_verification_success(response_text: str) -> bool:
    """Detect if the LLM explicitly claims successful flag verification.

    Negation-aware: a marker inside a denial ("未验证成功", "not confirmed") does not
    count. See ``_NEGATION_BEFORE``/``_NEGATION_AFTER``.
    """
    text = (response_text or "").lower()
    for marker in VERIFICATION_CLAIM_MARKERS:
        start = text.find(marker)
        while start != -1:
            end = start + len(marker)
            if not _is_negated(text, start, end):
                return True
            start = text.find(marker, end)
    return False


def update_ctf_state(agent: AgentContext, response_text: str, result_should_continue: bool) -> bool:
    """Update flag claim/verification state and return should_continue."""
    if agent.runtime.claimed_flag and not agent.runtime.flag_verified:
        # ONE predicate, ONE vocabulary. This used to OR the predicate with a second,
        # separately-maintained inline list of 31 markers -- the two overlapped on 21
        # entries and each held markers the other lacked, so the function's only real
        # contribution was its unique entries and the pair drifted silently. The list
        # now lives in VERIFICATION_CLAIM_MARKERS and this is its single consumer.
        if detect_verification_success(response_text):
            agent.runtime.flag_verified = True

    if agent.runtime.is_ctf_mode and agent.runtime.claimed_flag and not agent.runtime.flag_verified:
        flag_in_notes_count = sum(
            1 for note in agent.context.state.notes if agent.runtime.claimed_flag in note
        )
        if flag_in_notes_count >= 2:
            agent.runtime.flag_verified = True
        elif flag_in_notes_count >= 1 and agent.runtime.claimed_flag in response_text:
            agent.runtime.flag_verified = True

    claimed_flag = detect_flag_claim(response_text)
    if claimed_flag:
        if not agent.runtime.claimed_flag:
            agent.runtime.claimed_flag = claimed_flag
            agent.runtime.flag_verified = False
            result_should_continue = True
        elif agent.runtime.claimed_flag == claimed_flag and not agent.runtime.flag_verified:
            agent.runtime.flag_claim_count += 1
            if agent.runtime.flag_claim_count >= 3:
                agent.runtime.flag_verified = True
            else:
                result_should_continue = True

    if agent.runtime.is_ctf_mode and not result_should_continue:
        if not agent.runtime.flag_verified or not agent.runtime.claimed_flag:
            result_should_continue = True

    if agent.runtime.flag_verified and agent.runtime.claimed_flag:
        agent.runtime.post_flag_rounds += 1
        if agent.runtime.post_flag_rounds >= 2:
            result_should_continue = False
    if agent.runtime.flag_verified and agent.runtime.claimed_flag and result_should_continue:
        if agent.runtime.post_flag_rounds >= 1 and "[done]" not in response_text.lower():
            result_should_continue = False

    return result_should_continue
