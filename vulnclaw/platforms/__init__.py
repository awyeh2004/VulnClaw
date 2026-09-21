"""Platform adapter layer: one platform-neutral face over every CTF platform.

Before this package, CTF2 and GCS each had their own tool set (10 + 9 tools) with
near-identical verbs, and the platform an action went to was decided by *which
tool name the model picked*.  That is how an agent solving a CTF2 challenge
reached for ``gcs_submit_flag`` -- the name contained ``submit_flag``.

Here the platform identity lives in a *ref token* instead
(``ctf2:practice:12:345``), so the tool names carry no platform at all and
choosing the wrong one is not expressible.

Layout:

* :mod:`vulnclaw.platforms.refs` -- ref tokens and ``ChallengeRef`` / ``CorpusRef``
* :mod:`vulnclaw.platforms.base` -- the data model the adapters normalize into
* :mod:`vulnclaw.platforms.normalize` -- platform-native value -> vocabulary
* :mod:`vulnclaw.platforms.render` -- ``EnvInfo`` -> agent-facing text
* :mod:`vulnclaw.platforms.registry` -- which platforms exist and are exposed
* :mod:`vulnclaw.platforms.submit_guard` -- flag-submission accounting

This module imports no concrete platform: adapters register themselves
(``vulnclaw.platforms.ctf2`` / ``.gcs``) once they exist.
"""

from __future__ import annotations

from vulnclaw.platforms.base import (
    ALL_CAPABILITIES,
    ALL_STATES,
    ALL_TRANSPORTS,
    CAP_EVENT_INFO,
    CAP_NOTICES,
    CAP_OVERVIEW,
    CAP_SUBMISSIONS,
    INCOMPLETE_STATES,
    STATE_EXPIRED,
    STATE_NONE,
    STATE_NOT_REQUIRED,
    STATE_RUNNING,
    STATE_STARTING,
    STATE_STOPPED,
    STATE_UNKNOWN,
    TRANSPORT_TCP,
    TRANSPORT_TLS,
    TRANSPORT_UNKNOWN,
    USABLE_STATES,
    Attachment,
    Challenge,
    Corpus,
    EnvEndpoint,
    EnvInfo,
    Notice,
    PlatformAdapter,
    SubmitResult,
)
from vulnclaw.platforms.normalize import (
    normalize_bool,
    normalize_status,
    normalize_transport,
    split_host_port,
)
from vulnclaw.platforms.refs import (
    ChallengeRef,
    CorpusRef,
    RefError,
    make_token,
    parse_fields,
    platform_of,
    split_token,
)
from vulnclaw.platforms.registry import (
    PlatformError,
    PlatformNotConfigured,
    UnknownPlatform,
    adapter_for,
    all_adapters,
    capabilities,
    clear_adapters,
    configured_adapters,
    describe,
    is_enabled,
    register_adapter,
    registered_names,
)
from vulnclaw.platforms.render import render_env_info
from vulnclaw.platforms.submit_guard import (
    MigrationReport,
    SubmitGuard,
    get_guard,
    guard_reason_to_message,
    legacy_key_to_token,
    migrate_legacy_state,
    reset_guard,
)

__all__ = [
    "ALL_CAPABILITIES",
    "ALL_STATES",
    "ALL_TRANSPORTS",
    "CAP_EVENT_INFO",
    "CAP_NOTICES",
    "CAP_OVERVIEW",
    "CAP_SUBMISSIONS",
    "INCOMPLETE_STATES",
    "STATE_EXPIRED",
    "STATE_NONE",
    "STATE_NOT_REQUIRED",
    "STATE_RUNNING",
    "STATE_STARTING",
    "STATE_STOPPED",
    "STATE_UNKNOWN",
    "TRANSPORT_TCP",
    "TRANSPORT_TLS",
    "TRANSPORT_UNKNOWN",
    "USABLE_STATES",
    "Attachment",
    "Challenge",
    "ChallengeRef",
    "Corpus",
    "CorpusRef",
    "EnvEndpoint",
    "EnvInfo",
    "MigrationReport",
    "Notice",
    "PlatformAdapter",
    "PlatformError",
    "PlatformNotConfigured",
    "RefError",
    "SubmitGuard",
    "SubmitResult",
    "UnknownPlatform",
    "adapter_for",
    "all_adapters",
    "capabilities",
    "clear_adapters",
    "configured_adapters",
    "describe",
    "get_guard",
    "guard_reason_to_message",
    "is_enabled",
    "legacy_key_to_token",
    "make_token",
    "migrate_legacy_state",
    "normalize_bool",
    "normalize_status",
    "normalize_transport",
    "parse_fields",
    "platform_of",
    "register_adapter",
    "registered_names",
    "render_env_info",
    "reset_guard",
    "split_host_port",
    "split_token",
]
