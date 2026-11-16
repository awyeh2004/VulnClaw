"""A goal that forbids a path is an instruction, not evidence — and it should say so.

Measured 2026-10-31 on ezphp. Run 1 solved it in 8 minutes via `/flag.php`'s
unfiltered `gopher` scheme; the platform rejected the value it returned. Run 2's
goal then included:

    "The previously obtained flag{...} is a known decoy and was rejected;
     never report or submit it. Do not spend time revalidating /flag.php
     gopher output."

The gopher path *was* the solution — the rejected value was a decoy file reachable
only through it. The prohibition removed the only road, and the run spent 165 tool
calls building an unrelated Nextcloud-crypto attack.

The response is a warning, never a rewrite: an operator who closed a path may have
evidence the run cannot see, so the goal is theirs. What must not happen is the
prohibition passing through silently, because from the outside the run then looks
productive while systematically avoiding the one path that would have worked.
"""

from __future__ import annotations

import pytest

from vulnclaw.agent.input_analysis import (
    extract_goal_prohibitions,
    goal_wording_warning,
)

#: The real goal from the 2026-10-31 ezphp run, trimmed to the decisive part.
_EZPHP_GOAL = (
    "Solve the authorized CTF target and obtain the REAL flag via the intended "
    "shell/code-execution path. The previously obtained flag{You_are_so_smart_8080} "
    "is a known decoy and was rejected; never report or submit it. Do not spend time "
    "revalidating /flag.php gopher output. Target is Nextcloud 34.0.3.2 with PHP 8.5.12."
)


def test_finds_the_prohibition_that_cost_the_ezphp_run():
    sentences = extract_goal_prohibitions(_EZPHP_GOAL)

    joined = " ".join(sentences)
    assert "revalidating /flag.php gopher output" in joined
    assert "never report or submit" in joined


def test_keeps_dotted_paths_intact():
    """Splitting on every period turned "/flag.php gopher" into "/flag." — the
    part naming what was forbidden was exactly what got lost."""
    sentences = extract_goal_prohibitions(_EZPHP_GOAL)

    assert any("/flag.php gopher output" in s for s in sentences)
    assert not any(s.rstrip().endswith("/flag.") for s in sentences)


def test_warning_names_the_prohibition_and_the_consequence():
    warning = goal_wording_warning(_EZPHP_GOAL)

    assert warning.startswith("[!]")
    assert "/flag.php gopher output" in warning
    assert "is not evidence" in warning


def test_clean_goal_produces_no_warning():
    clean = (
        "Solve the authorized CTF target and obtain the flag. Target is "
        "Nextcloud 34.0.3.2 with PHP 8.5.12. Verify the flag from target "
        "evidence before reporting."
    )

    assert extract_goal_prohibitions(clean) == []
    assert goal_wording_warning(clean) == ""


def test_empty_goal_is_silent():
    assert extract_goal_prohibitions("") == []
    assert goal_wording_warning("") == ""


def test_english_prohibitions_are_recognised():
    for goal in (
        "Do not retry the upload vector.",
        "Never submit a flag you cannot source.",
        "Skip the SSRF approach.",
    ):
        assert extract_goal_prohibitions(goal), goal


def test_chinese_prohibitions_are_recognised():
    for goal in (
        "不要再试 gopher 了，换个思路。",
        "已验证该路径无效，禁止重复提交。",
    ):
        assert extract_goal_prohibitions(goal), goal


def test_guidance_is_not_a_prohibition():
    """Warnings that steer without closing a path must stay silent."""
    for goal in (
        "Do not guess the flag.",
        "Don't forget to check robots.txt.",
        "Do not ask the user for permission; proceed.",
    ):
        assert extract_goal_prohibitions(goal) == [], goal


def test_prohibition_citing_a_check_gets_a_softer_note():
    """When the operator names the check, the warning says less.

    It still warns: "we tested it" is not the same as "it cannot work", which is
    the exact confusion that produced the ezphp goal.
    """
    cited = "Do not retry the login form because the platform rejected the flag it produced."

    warning = goal_wording_warning(cited)

    assert warning
    assert "None of these cite a check" not in warning


def test_uncited_prohibition_gets_the_full_note():
    warning = goal_wording_warning("Do not spend time revalidating the gopher path.")

    assert "None of these cite a check" in warning


def test_long_pasted_text_is_not_scanned_line_by_line():
    """A pasted writeup would otherwise light up on every line."""
    pasted = "Do not " + ("x" * 700) + " submit."

    assert extract_goal_prohibitions(pasted) == []


def test_warning_lists_at_most_four_sentences():
    goal = " ".join(f"Do not retry path{i}." for i in range(9))

    warning = goal_wording_warning(goal)

    assert "and 5 more" in warning