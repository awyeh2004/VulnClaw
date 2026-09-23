"""Real CTF2 payloads recorded from the 2026-09-21 live run.

Provenance (verbatim, not reconstructed): the ``content`` fields of the
``ctf2_start_environment`` / ``ctf2_get_target`` tool results in
``.test-tmp/vulnclaw-home/runs/ctf2-stack2/targets/712c3fbe87b27ba4/state/current.json``
(lines ~752 and ~789).  The challenge was CTF2 practice ``stack``
(practice_id ``aa83cd16-0612-461b-a98b-af5ee934ce7d``, challenge_id
``ffb48a20-7742-445c-abf8-07fec1f50ad1``), which was solved for real.

Why these are fixtures rather than hand-written samples: the whole point of the
adapter layer is to normalize the platform's *actual* shapes, and the failure it
guards against (commit f278f16) came from the two shapes differing in ways a
hand-written sample would never reproduce.  In particular the running payload
carries BOTH ``access_type: "tcp"`` and ``nc_ssl: true`` -- treating
``access_type`` as the transport would silently classify a TLS endpoint as plain
TCP, which is exactly the 20-minute miss.
"""

from __future__ import annotations

PRACTICE_ID = "aa83cd16-0612-461b-a98b-af5ee934ce7d"
CHALLENGE_ID = "ffb48a20-7742-445c-abf8-07fec1f50ad1"
SSTI_CHALLENGE_ID = "86df87ab-5daf-46c9-b50b-2ea4efb1e4eb"
HOST = "e031c98d53ce9d75dc5f4feb.tcp-ctf2.dasctf.com"
PORT = 9999
ACCESS_URL = f"{HOST}:{PORT}"
EXPIRES_AT = "2026-09-21T15:57:35.055394+08:00"
TARGET_ID = "e031c98d-ef77-477a-a75d-51a69fe38d9a"

# status=starting: NO access_url, NO access_urls, NO nc_ssl.
STARTING_PAYLOAD: dict = {
    "data": {
        "created_at": "2026-09-21T14:57:35.055669+08:00",
        "description": "stack",
        "expires_at": EXPIRES_AT,
        "friendly_id": "TGT-2026-310885",
        "id": TARGET_ID,
        "name": "practice-stack-d37ad0d4",
        "status": "starting",
        "updated_at": "2026-09-21T14:57:35.055669+08:00",
    },
    "success": True,
}

# status=running: adds access_url, access_urls[] and nc_ssl.
# NOTE access_type == "tcp" while nc_ssl == True: access_type is the connection
# TYPE, not the transport security.  Do not use it to decide TLS.
RUNNING_PAYLOAD: dict = {
    "data": {
        "access_type": "tcp",
        "access_url": ACCESS_URL,
        "access_urls": [{"nc_ssl": True, "type": "tcp", "url": ACCESS_URL}],
        "created_at": "2026-09-21T14:57:35.055669+08:00",
        "description": "stack",
        "expires_at": EXPIRES_AT,
        "friendly_id": "TGT-2026-310885",
        "id": TARGET_ID,
        "name": "practice-stack-d37ad0d4",
        "nc_ssl": True,
        "status": "running",
        "updated_at": "2026-09-21T14:57:39.029449+08:00",
    },
    "success": True,
}

# The expired-instance symptom, measured on the live target: the TLS proxy
# answers the handshake and then reports this at the application layer, so a
# caller must not read "handshake OK" as "target alive".
RANGE_KEEPER_BANNER = (
    "RANGE KEEPER\n[ TARGET NOT FOUND ] This address has no running target."
)

NO_TARGET_PAYLOAD: dict = {"data": None, "success": True}


# ── third provenance block: a WEB target, recorded live on 2026-09-23 ─────
#
# Verbatim from `platform_start_env` on practice challenge "[极客大挑战 2019]BabySQL"
# (practice b9bbb32f-f186-458f-b90b-12440c0f6aea, challenge
# 30c90c3e-2227-4263-8218-9494728f4c38), which was solved for real in the same run.
#
# Why it matters: this is the payload SHAPE the renderer got wrong.  `nc_ssl` is
# null, so the scheme fallback correctly resolves the transport to `tcp` (no TLS
# wrapper needed) -- and the renderer then said "plain TCP is fine", which invites
# a bare socket against a web challenge.  `access_type` is "http", and the URL
# scheme is http:// -- both facts the transport vocabulary cannot express, so the
# renderer must read the scheme.
WEB_TARGET_URL = "http://03ac8797e2ae410f0e8a11dc.http-ctf2.dasctf.com:80"
WEB_TARGET_ID = "03ac8797-e3d4-4613-8a16-649e2cda9dc4"
WEB_EXPIRES_AT = "2026-09-23T09:28:56.045426+08:00"

WEB_RUNNING_PAYLOAD: dict = {
    "data": {
        "access_ready": True,
        "access_type": "http",
        "access_url": WEB_TARGET_URL,
        "access_urls": [{"nc_ssl": None, "type": "http", "url": WEB_TARGET_URL}],
        "created_at": "2026-09-23T08:28:56.045674+08:00",
        "environment_id": WEB_TARGET_ID,
        "expires_at": WEB_EXPIRES_AT,
        "status": "running",
    },
    "success": True,
}


# ── second provenance block: field names confirmed live on 2026-09-21 ─────
#
# Captured by a READ-ONLY probe against the live platform with a
# full-permission personal access token (no environment was started and no flag
# was submitted).  These are key sets and route outcomes, not reconstructions.
#
# The probe corrected four inferred field names in the adapter:
#   hasSolved -> is_solved      (hasSolved is GCS's name, CTF2 uses is_solved)
#   score     -> points         (int)
#   files[].name        -> files[].file.original_name   (nested)
#   files[].size        -> files[].file.size            (nested)
# and it showed that daily rows WRAP the challenge object.

# Every list endpoint uses this envelope (all four confirmed).
LIST_ENVELOPE_KEYS = ("items", "total")

PRACTICE_ROW_KEYS = (
    "allow_writeup_submission", "attack_points", "bot_team_count",
    "challenge_count", "created_at", "defense_points", "description", "end_time",
    "flag_stolen_penalty", "flag_valid_rounds", "friendly_id", "header_image", "id",
    "is_active", "is_public", "name", "round_duration", "service_down_penalty",
    "show_writeups", "sla_points", "sort_order", "start_time", "summary",
    "total_rounds", "type", "updated_at",
)

# Daily rows wrap the challenge -- `id` is the daily ENTRY id, not the challenge.
DAILY_ROW_KEYS = (
    "challenge", "challenge_id", "created_at", "date", "friendly_id", "id",
    "is_visible", "updated_at",
)

# Competition rows carry no stages: verified, so stage refs cannot be discovered
# by listing. (`list_stage_challenges(stage_id)` exists, but nothing enumerates
# stage ids.)
COMPETITION_ROW_KEYS = (
    "allow_self_team_creation", "allow_team_info_edit_after_start",
    "allow_team_join_after_start", "allow_writeup_submission", "created_at",
    "description", "detail_header_image", "end_time", "friendly_id", "header_image",
    "id", "is_hidden", "is_paused", "is_pinned", "is_public", "max_team_size",
    "max_teams", "name", "rules", "show_writeups", "start_time", "updated_at",
)

SUBMISSION_ROW_KEYS = (
    "challenge", "challenge_id", "created_at", "friendly_id", "id", "is_correct",
    "is_first_blood", "points", "stage_id", "team", "team_id", "updated_at",
    "user_id",
)

CHALLENGE_DETAIL_KEYS = (
    "category", "created_at", "description", "difficulty", "files", "friendly_id",
    "has_container", "id", "is_solved", "is_visible", "max_attempts", "name",
    "points", "practice_ground_id", "requires_running_target_for_submit",
    "solve_count", "sort_order", "template_id", "translations", "updated_at",
)

# `files[]` rows nest the bytes' metadata under `file`; there is NO md5 field.
FILE_ROW_KEYS = (
    "created_at", "download_url", "file", "file_url", "id", "is_visible",
    "practice_challenge_id", "updated_at", "url",
)
FILE_INNER_KEYS = ("mime_type", "original_name", "size")

# Verbatim from the live `stack` challenge (practice ..., challenge ffb48a20...).
CHALLENGE_DETAIL_PAYLOAD: dict = {
    "data": {
        "category": "第06章 CTF之PWN篇",
        "description": "stack overflow",
        "difficulty": "Easy",
        "files": [
            {
                "id": "4e0f1c0a-0000-0000-0000-000000000000",
                "download_url": (
                    "https://ctf2-files.dasctf.com/ctf-files/uploads/2026/05/29/"
                    "46531fc3961c7179f6c62ee4d66805ce7ae9f8d3acecf3ff638cf1b564ba3456.so"
                ),
                "file_url": (
                    "https://ctf2-files.dasctf.com/ctf-files/uploads/2026/05/29/"
                    "46531fc3961c7179f6c62ee4d66805ce7ae9f8d3acecf3ff638cf1b564ba3456.so"
                ),
                "file": {
                    "mime_type": "application/octet-stream",
                    "original_name": "libc-2.27.so",
                    "size": 2030544,
                },
                "is_visible": True,
                "practice_challenge_id": CHALLENGE_ID,
            }
        ],
        "friendly_id": "CCHAL-2026-0001",
        "has_container": True,
        "id": CHALLENGE_ID,
        "is_solved": False,
        "is_visible": True,
        "max_attempts": 0,
        "name": "stack",
        "points": 1,
        "practice_ground_id": PRACTICE_ID,
        "requires_running_target_for_submit": False,
    },
    "success": True,
}

DAILY_LIST_PAYLOAD: dict = {
    "data": {
        "items": [
            {
                "id": "1c1f0a00-0000-0000-0000-000000000000",
                "challenge_id": "31fba28e-f924-4f05-9add-da79d0b9e90a",
                "friendly_id": "DAILY-2026-0001",
                "date": "2026-09-21",
                "is_visible": True,
                "challenge": {
                    "id": "31fba28e-f924-4f05-9add-da79d0b9e90a",
                    "name": "vault",
                    "category": "MOBILE",
                    "difficulty": "Hard",
                    "has_container": True,
                    "points": 300,
                    "max_attempts": 0,
                    "files": [],
                    "stage_id": "",
                },
            }
        ],
        "total": 1,
    },
    "success": True,
}

COMPETITION_LIST_PAYLOAD: dict = {
    "data": {
        "items": [
            {
                "id": "c0mpet1t-0000-0000-0000-000000000000",
                "name": "some competition",
                "is_public": True,
                "start_time": "2026-09-01T00:00:00+08:00",
                "end_time": None,
            }
        ],
        "total": 1,
    },
    "success": True,
}

# Closed-form route outcomes, measured with the personal access token only.
OPEN_API_ROUTE_OUTCOMES = {
    "/practice/": 200,
    "/practice/<pid>/challenges/": 404,  # ⭐ no such route -> honest error, not a guess
    "/practice/<pid>/challenges/<cid>/": 200,
    "/practice/<pid>/challenges/<cid>/target/": 404,  # target needs the Bearer session
    "/competitions/": 200,
    "/submissions/": 200,
}


# ── fourth provenance block: the SUBMIT path, recorded live on 2026-09-23 ─────
#
# The one IRREVERSIBLE action had the least recorded evidence of anything in this
# file: its request shape was *inferred* (`{"flag": ..., "confirmation": true}`), and
# the four platform *responses* below had never been captured as fixtures -- they
# existed only as hand-copied dictionaries inside two test files. That is the same
# exposure that produced four wrong field names earlier (hasSolved/is_solved,
# score/points, files[].name, files[].size), so the responses are recorded verbatim
# here and both test files now read from this block instead of keeping copies.
#
# Provenance: `platform_submit` / direct POSTs against
# practice b9bbb32f-f186-458f-b90b-12440c0f6aea. ACCEPTED came from the
# `不一样的flag` solve (challenge 40982610-b3f3-4635-adee-2d4618a97f12); the three
# rejections were measured on `[极客大挑战 2019]BabySQL`
# (30c90c3e-2227-4263-8218-9494728f4c38), whose submission is refused no matter what
# -- including by the platform's own front end.

#: Accepted. Verbatim from platform_submit on `不一样的flag` (+1 point, is_solved).
SUBMIT_ACCEPTED_PAYLOAD: dict = {
    "data": {
        "accepted": True,
        "attempt": 1,
        "earned_points": 1,
        "is_solved": True,
        "points": 1,
        "solved_sub_flag_count": 0,
        "submission_id": "06b08738-1b80-4695-b04f-e8ff6f669828",
        "total_sub_flag_count": 1,
    },
    "success": True,
}

#: Open API 400 as sent BY US (with `confirmation: true`). `params` is null: the
#: request was still invalid for a reason the platform did not name.
SUBMIT_INVALID_REQUEST_PAYLOAD: dict = {
    "error": {
        "code": "INVALID_REQUEST",
        "key": "errors.common.invalid_request",
        "params": None,
    },
    "success": False,
}

#: Same route, same flag, `confirmation` OMITTED -- and the platform names it. This
#: is how the required field was discovered, and it confirms our body is not missing
#: anything the platform is willing to tell us about.
SUBMIT_INVALID_REQUEST_HINT_PAYLOAD: dict = {
    "error": {
        "code": "INVALID_REQUEST",
        "key": "errors.common.invalid_request",
        "params": {"confirmation": True},
    },
    "success": False,
}

#: HTTP 429 from the SESSION API with `risk_action: challenge` -- i.e. a CAPTCHA, a
#: human-verification gate on the scored action. NOTE the body has no top-level
#: `error`, which is why a naive reader reported it as a plain "429 Too Many
#: Requests" (the one reading that invites a retry loop); `_risk_control_note` in
#: ctf_platform/client.py now names it.
#:
#: The image is TRUNCATED ON PURPOSE -- it is a base64 PNG of a captcha, so keeping
#: the full blob in the repository would be pointless bulk. The asserted property is
#: the SHAPE (`data.risk_challenge.image` is a data: URL), not the pixels.
SUBMIT_RISK_CONTROL_PAYLOAD: dict = {
    "data": {
        "risk_action": "challenge",
        "risk_challenge": {
            "id": "7e78d670-24ba-4316-9f66-e33cb90b97f2",
            "image": "data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAALQAAABACAIAAAA8rMpq...<truncated>",
        },
    }
}

#: The session API has no `/challenges/<cid>/submit/` route; the real one is nested
#: under `/practice/<pid>/...`. Recorded so a future "shortcut" route is recognised
#: as a guess rather than treated as a platform change.
SUBMIT_ROUTE_NOT_FOUND_PAYLOAD: dict = {
    "error": {
        "code": "NOT_FOUND",
        "key": "errors.common.not_found",
        "params": {"resource": "route"},
    },
    "success": False,
}

