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
