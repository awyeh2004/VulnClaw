"""``vulnclaw ctf2`` / ``gcs`` / ``competition`` —— 平台交接与竞赛策略命令。

从 :mod:`vulnclaw.cli.main` 拆出（2026-10-12）。按本仓库既有约定（``retest_cmd.py``），
这里定义**普通函数** ``ctf2`` / ``gcs`` / ``competition``，由 ``main.py`` 用
``app.command("ctf2")(ctf2)`` 注册 —— ``app`` 仍只在 main.py，注册顺序不变。

这些命令把挑战交给标准 solve 循环，并读 ``main`` 上的若干名字（``solve``、
``_solve_defaults``、``_adapter_for_ref``、``ctf2_read_challenge``…）。测试会对
``cli.main.<name>`` 打补丁（``test_platform_command_handoff`` / ``test_competition_solve_ref``
/ ``test_predownload_attachments``），所以这些名字一律经 :func:`_from_main` 在调用时解析。
"""

from __future__ import annotations

import asyncio
import os
from typing import Any

import typer

from vulnclaw.cli._helpers import console, err_console
from vulnclaw.cli.repl import _from_main


def ctf2(
    challenge_id: str = typer.Argument(..., help="CTF2 challenge id"),
    practice_id: str = typer.Argument(
        ..., help="CTF2 practice ground id the challenge belongs to"
    ),
    max_steps: int = typer.Option(
        240, "--max-steps", help="Runaway safety budget for autonomous turns"
    ),
    hint: list[str] = typer.Option(
        [],
        "--hint",
        help="Operator hint injected into the run (repeatable). Use it to steer a "
        "stuck run -- e.g. a flag-format hypothesis -- without taking the solve over.",
    ),
) -> None:
    """Solve a CTF2 (DASCTF) challenge directly from its ids.

    Reads the challenge via the CTF2 open API, builds a focused solve goal,
    then hands off to the standard model-led solve loop. Only the two ids are
    needed; attachment download is intentionally out of scope (the open API
    exposes no file endpoint).
    """
    if not _from_main("ctf2_is_configured")():
        err_console.print(
            "[!] CTF2 platform token not configured. Set the VULNCLAW_CTF2_API_KEY "
            "environment variable, then retry."
        )
        raise typer.Exit(1)

    if not _from_main("has_llm_credentials")(_from_main("load_config")().llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    chall_data: dict = {}

    async def _load_challenge():
        payload = await _from_main("ctf2_read_challenge")(practice_id, challenge_id)
        chall_data.update(payload.get("data") or {})

    try:
        asyncio.run(_load_challenge())
    except Exception as exc:  # network or platform errors must not crash
        err_console.print(f"[!] Failed to read challenge from CTF2: {exc}")
        raise typer.Exit(1)

    name = chall_data.get("name")
    if not name:
        err_console.print("[!] Challenge not found for the given ids.")
        raise typer.Exit(1)

    category = chall_data.get("category") or ""
    difficulty = chall_data.get("difficulty") or ""
    description = str(chall_data.get("description") or "").strip()
    requires_env = bool(chall_data.get("has_container"))
    # The platform-neutral ref for this challenge. Code constructs it; the model
    # only ever echoes it back, which is what makes picking the wrong platform
    # inexpressible.
    ref_token = f"ctf2:practice:{practice_id}:{challenge_id}"
    # Match-start insurance, and the reason `competition.predownload_attachments`
    # finally means something. Best effort: on failure the agent still has the URLs.
    from vulnclaw.platforms.ctf2 import extract_attachments as _ctf2_attachments

    _cfg = _from_main("load_config")()
    predownloaded = _from_main("_predownload_challenge_attachments")(
        _cfg, str(name), _ctf2_attachments(chall_data), _from_main("_adapter_for_ref")(ref_token)
    )
    goal = (
        f"Solve CTF2 challenge '{name}' (category {category}, difficulty "
        f"{difficulty}) on practice {practice_id}.\n"
        f"REF: {ref_token}\n"
        f"Pass that exact string as `ref` to the platform_* tools -- the platform "
        f"comes from the ref, so there is no separate platform id to choose. Submit "
        f"the flag with platform_submit once it is known.\n"
        f"Challenge description follows:\n{description}\n"
        # This used to read "Do not attempt to fetch files from or attack
        # ctf2*.dasctf.com hosts", which forbade the ONE network action a RE/rev
        # challenge needs: its attachment is published on
        # ctf2-files.dasctf.com. Measured on "不一样的flag" (an Easy RE whose whole
        # content is an attachment) -- the blanket ban tells the agent not to get
        # the challenge. Attacking the platform is still out of bounds; downloading
        # the challenge's own published files is not.
        f"Downloading this challenge's own published attachments from the platform's "
        f"file host IS expected -- take the URLs from platform_read and fetch them. "
        # Round-8 finding R8-3: this sentence used to name the host outright ("no
        # scanning or probing ctf2*.dasctf.com endpoints"). When the challenge
        # description contains no URL, `detect_target` mined `dasctf.com` out of that
        # glob, `host_in_scope` treats a bare domain as covering every subdomain, and the
        # run's scope was therefore derived from a PROHIBITION -- authorising exactly the
        # platform (ctf2.dasctf.com and friends) the sentence forbade. Naming no host
        # keeps the rule and stops it from being a machine-readable scope source.
        f"What is out of bounds is attacking the platform itself: no scanning or "
        f"probing the platform's own service endpoints, and no guessing at its API. "
        + (
            # Already fetched for the agent, so it does not need the file host at all.
            "These are ALREADY DOWNLOADED to local paths, use them directly:\n"
            + "\n".join(f"  {path}" for path in predownloaded)
            + "\n"
            if predownloaded
            else ""
        )
        + f"Solve from the description and those attachments "
        + (
            "and, if a dynamic target is required, start it with platform_start_env, "
            "poll platform_read_env until it reports the target as usable, and "
            "inspect the authored target before attacking it."
            if requires_env
            else "(this challenge needs no running environment)."
        )
    )
    console.print(
        f"[*] CTF2 challenge [bold]{name}[/] | category [bold]{category}[/] | "
        f"difficulty [bold]{difficulty}[/]"
    )
    # Hand off to the standard solve loop; reuse its full orchestration.
    #
    # Every optional flag has to be passed explicitly (`_solve_defaults`), because
    # `solve()` is a Typer command: calling it from Python leaves its un-passed
    # parameters as truthy OptionInfo sentinels, which crashed this command
    # outright (`TypeError: Value after * must be an iterable, not OptionInfo` in
    # build_targets). `_cli_value` unwraps this command's own defaults, which are
    # sentinels too when `ctf2()` is called from Python.
    _from_main("solve")(
        **_from_main("_solve_defaults")(
            # The REF, not the bare practice id: the origin of a run is what its
            # captured notes are filed under, and the platform's own launches pass
            # the ref here too. With a bare id this entry path wrote its notes under
            # a different identity than the REPL/platform paths, so the same
            # challenge's reuse chain split in two (2026-10-06).
            target=ref_token,
            goal=goal,
            max_steps=_from_main("_cli_value")(max_steps, 240),
            # Same sentinel problem as every other flag here: when `ctf2()` is called
            # from Python the default is a truthy `OptionInfo`, and `list()` on it
            # raises "not iterable". `_cli_value` unwraps it to the real default.
            hint=_from_main("_cli_value")(hint, []),
            resume=False,
        )
    )


def gcs(
    exercise_id: int = typer.Argument(..., help="西湖论剑 challenge (exercise) id"),
    max_steps: int = typer.Option(
        240, "--max-steps", help="Runaway safety budget for autonomous turns"
    ),
) -> None:
    """Solve a West Lake Sword Competition (西湖论剑) challenge by exercise id.

    Reads the challenge via the competition agent API (X-Agent-AccessKey),
    builds a focused solve goal, then hands off to the standard model-led
    solve loop. The agent manages the full environment lifecycle itself:
    build-exercise-env -> poll until ready -> attack endpoints -> submit flag
    -> recover-exercise-env.
    """
    if not _from_main("gcs_is_configured")():
        err_console.print(
            "[!] GCS agent access key not configured. Set the "
            "VULNCLAW_GCS_ACCESS_KEY environment variable, then retry."
        )
        raise typer.Exit(1)

    if not _from_main("has_llm_credentials")(_from_main("load_config")().llm):
        err_console.print("[!] Configure LLM credentials first (api_key or auth_mode).")
        raise typer.Exit(1)

    chall_data: dict = {}

    async def _load_exercise():
        payload = await _from_main("gcs_exercise")(exercise_id)
        chall_data.update(payload.get("data") or payload or {})

    try:
        asyncio.run(_load_exercise())
    except Exception as exc:  # network or platform errors must not crash
        err_console.print(f"[!] Failed to read exercise from GCS: {exc}")
        raise typer.Exit(1)

    name = chall_data.get("name")
    if not name:
        err_console.print("[!] Exercise not found for the given id.")
        raise typer.Exit(1)

    difficulty = chall_data.get("difficulty") or ""
    score = chall_data.get("score") or ""
    description = str(chall_data.get("description") or "").strip()
    has_solved = bool(chall_data.get("hasSolved"))
    needs_init = bool(chall_data.get("isNeedInit"))
    # Platform-neutral ref, built by code so the model only echoes it.
    gcs_ref = f"gcs:exercise:{exercise_id}"
    if has_solved:
        err_console.print(f"[*] Exercise [bold]{name}[/] already solved — skipping.")
        return

    score_text = (str(score).replace(".0", "") if score else "")
    hint = ""
    if exercise_id == 10662:
        hint = (
            "\n[ANALYSIS HINT] This is a glibc 2.27 pwn binary (attachment contains "
            "'pwn' and 'libc.so.6'). The remote target serves the nc binary. "
            "Known libc offsets: system=0x4f420, printf=0x64e40, puts=0x80970, "
            "__free_hook=0x3ed8e8, __malloc_hook=0x3ebc30, main_arena(unsorted leak +0x70). "
            "Menu: 1=browse,2=add(id 1-3),3=remove(index),4=modify review(index),5=view cart. "
            "Vulnerabilities: (1) remove() frees item and item->review but keeps the "
            "dangling pointer in cart->items[index] -> UAF; (2) add_to_cart/remove "
            "allocate/free 0x98-byte chunks (tcache bin 0xa0); (3) modify_review reads "
            "0x9a bytes into the freed review chunk -> allows tcache poisoning. "
            "The intended exploit: leak libc (e.g. via View cart printing review content "
            "after free, exposing main_arena pointer), then tcache-poison __free_hook "
            "with system(), write '/bin/sh' or '/bin/cat /flag' into a freed chunk, and "
            "trigger system(). Do NOT get stuck re-analyzing the binary; write the "
            "exploit and attack the target directly, then submit the flag."
        )
    goal = (
        f"Solve the West Lake Sword Competition challenge '{name}' "
        f"(difficulty {difficulty}; score: {score_text} points).\n"
        f"REF: {gcs_ref}\n"
        f"Pass that exact string as `ref` to the platform_* tools -- the platform "
        f"comes from the ref. Use platform_read for the description and attachment "
        f"links, platform_read_env for the target endpoints, and platform_submit "
        f"once the flag is known.\n"
        f"Challenge description follows:\n{description}\n{hint}\n"
        + (
            "The environment needs initialization: call platform_start_env, poll "
            "platform_read_env until the endpoints are published, attack them, submit "
            "the flag, then call platform_stop_env to release quota. "
            if needs_init
            else "No environment initialization required; attack the provided endpoints directly, then submit the flag. "
        )
        + " Follow the competition rules for the flag format."
    )
    console.print(
        f"[*] GCS exercise [bold]{name}[/] | difficulty [bold]{difficulty}[/] | "
        f"score [bold]{score}[/]"
    )
    # Hand off to the standard solve loop; reuse its full orchestration.
    #
    # `solve` is a typer command: called directly from Python its un-passed
    # parameters keep the typer.Option objects, which read as truthy. The declared
    # defaults come from its signature (`_solve_defaults`) rather than being
    # copied here, so they cannot drift.
    _from_main("solve")(
        **_from_main("_solve_defaults")(
            target=str(exercise_id),
            goal=goal,
            max_steps=_from_main("_cli_value")(max_steps, 240),
            resume=False,
        )
    )


def competition(
    mode: str = typer.Argument(
        ..., help="Action: latency (probe LLM delay) | plan (easy-first order) | solve <eid>"
    ),
    ref: str = typer.Argument(
        None,
        help=(
            "Challenge ref for 'solve' mode, e.g. ctf2:practice:<pid>:<cid> or "
            "gcs:exercise:<id>. A bare numeric id is read as gcs:exercise:<id> "
            "(the old form)."
        ),
    ),
) -> None:
    """Competition-mode strategy helpers (西湖论剑/DASCTF).

    - ``latency``: probe the LLM backend latency and recommend single vs
      multi-agent. A slow shared backend gets worse with more parallel workers,
      so the match strategy should force single-agent when latency is high.
    - ``plan``: fetch the challenge list (if the platform is reachable) and
      print an easy-first order; otherwise summarize local attachments.
    - ``download``: batch-download every challenge attachment at match start
      so a slow/closing backend never blocks local analysis (insurance).
    - ``solve <eid>``: run one challenge with competition strategy (fail-fast on
      stalls, easy-first ordering) instead of the default open-ended solve.
    """
    from vulnclaw.config.llm_utils import probe_llm_latency

    cfg = _from_main("load_config")()

    if mode == "latency":
        _from_main("_competition_latency")(cfg, probe_llm_latency)
        return
    if mode == "plan":
        _from_main("_competition_plan")(cfg)
        return
    if mode == "download":
        _from_main("_competition_download")(cfg)
        return
    if mode == "solve":
        if not ref:
            err_console.print(
                "[!] 'competition solve' requires a challenge ref, e.g. "
                "ctf2:practice:<practice_id>:<challenge_id>"
            )
            raise typer.Exit(1)
        _from_main("_competition_solve")(cfg, str(ref))
        return
    err_console.print(
        f"[!] unknown competition mode: {mode} (use: latency | plan | download | solve <eid>)"
    )
    raise typer.Exit(1)


def _competition_latency(cfg: Any, probe) -> None:
    """Probe LLM latency; recommend single vs multi-agent."""
    llm = cfg.llm
    threshold = float(getattr(cfg.competition, "slow_llm_threshold_s", 5.0))
    console.print(f"[*] Probing LLM backend: {llm.model} @ {llm.base_url}")
    avg, ok = probe(llm)
    if not ok:
        err_console.print(
            "[!] LLM endpoint unreachable/errored — the backend may be overloaded. "
            "Recommendation: force single-agent, reduce retries, avoid parallel workers."
        )
        raise typer.Exit(1)
    console.print(f"    average latency: {avg:.2f}s")
    if avg > threshold:
        console.print(
            f"    [bold red]LATENCY HIGH (> {threshold}s)[/] — backend overloaded. "
            "Use SINGLE agent, low max_rounds, and fail-fast stall detection."
        )
    else:
        console.print(
            f"    [bold green]LATENCY OK (<= {threshold}s)[/] — parallel/multi-agent is viable."
        )


def _platform_challenges() -> list[tuple[str, Any]]:
    """Every challenge the configured platforms expose, as ``(ref token, Challenge)``.

    Goes through the adapter registry rather than a platform client, so:

    * a platform that is not configured contributes nothing instead of raising;
    * a platform that errors contributes a readable note instead of taking the
      whole listing down;
    * supporting another platform needs no change here at all.

    This replaced a hardcoded GCS call. The old code silently fell back to "local
    attachments" whenever GCS was missing or unreachable, which made an
    unconfigured platform indistinguishable from an empty challenge list.
    """
    import asyncio

    from vulnclaw.platforms import registry
    from vulnclaw.platforms.bootstrap import ensure_adapters

    ensure_adapters()
    adapters = registry.configured_adapters()
    if not adapters:
        console.print(
            "[*] No platform is configured; skipping the platform listing. "
            "Set a platform credential (e.g. VULNCLAW_CTF2_API_KEY) to use it."
        )
        return []

    collected: list[tuple[str, Any]] = []
    seen: set[str] = set()
    for adapter in adapters.values():

        async def _list(adapter: Any = adapter) -> list[tuple[str, Any]]:
            rows: list[tuple[str, Any]] = []
            for corpus in await adapter.list_corpora():
                try:
                    challenges = await adapter.list_challenges(corpus.ref)
                except Exception:
                    # An aggregate corpus (GCS's whole-tree entry) or an
                    # unsupported collection: skip it, the others still work.
                    continue
                rows += [(challenge.ref.token(), challenge) for challenge in challenges]
            return rows

        try:
            rows = asyncio.run(_list())
        except Exception as exc:
            console.print(f"[*] {adapter.name}: listing failed ({type(exc).__name__}); skipping")
            continue
        for token, challenge in rows:
            if token in seen:
                continue
            seen.add(token)
            collected.append((token, challenge))
    return collected


def _challenge_sort_key(row: tuple[str, Any]) -> float:
    """Easy/high-score first. Unparseable scores sort last, never crash the sort."""
    try:
        return float(row[1].score or 0)
    except (TypeError, ValueError):
        return 0.0


def _competition_plan(cfg: Any) -> None:
    """Print easy-first challenge ordering (platform or local)."""
    import glob
    import os

    comp = cfg.competition
    if getattr(comp, "easy_first", True):
        console.print("[*] Competition plan: easy-first ordering enabled.")

    challenges = _from_main("_platform_challenges")()
    if challenges:
        console.print(f"[*] {len(challenges)} challenges from the configured platform(s):")
        ordered = sorted(challenges, key=_from_main("_challenge_sort_key"), reverse=True)
        if getattr(comp, "easy_first", True):
            ordered.sort(key=lambda row: str(row[1].difficulty).lower() != "easy")
        for token, challenge in ordered:
            console.print(
                f"    {token}\n        {challenge.name} | score={challenge.score or '-'} "
                f"| diff={challenge.difficulty or '-'}"
                f"{' | SOLVED' if challenge.solved else ''}"
            )
        return
    console.print("[*] No platform challenges available; using local attachments.")

    # Local fallback: list attachments under the work dir.
    work = os.environ.get("VULNCLAW_WORK_DIR", os.path.expandvars(r"%USERPROFILE%\vulnclaw\work"))
    attach = os.path.join(work, "attachments")
    if os.path.isdir(attach):
        files = sorted(glob.glob(os.path.join(attach, "*")))
        if files:
            console.print(f"[*] Local attachments ({len(files)}):")
            for f in files:
                console.print(f"    {os.path.basename(f)}")
            return
    console.print("[*] No challenges or attachments found (platform down + no local work dir).")


def _competition_download(cfg: Any) -> None:
    """Batch-download every configured platform's challenge attachments.

    Attachment discovery now goes through the adapter layer's normalized
    ``Challenge.attachments`` instead of a local field-name guessing loop
    (``attachmentUrl`` / ``fileUrl`` / nested ``file.url`` / ...). Two things this
    fixes:

    * a platform whose payload nests attachment metadata (CTF2 puts the filename
      and size under ``files[].file``) is no longer read as "no download link";
    * a challenge that genuinely publishes nothing says so, instead of the same
      warning meaning both "none published" and "we failed to parse it".

    Note the old version also could not be reused for CTF2 at all, because it was
    written against one platform's shapes.
    """
    import asyncio
    import os

    from vulnclaw.platforms import registry
    from vulnclaw.platforms.bootstrap import ensure_adapters

    ensure_adapters()
    rows = _from_main("_platform_challenges")()
    if not rows:
        err_console.print(
            "[!] No configured platform returned challenges, so there is nothing to "
            "download. Configure a platform credential (e.g. VULNCLAW_CTF2_API_KEY) "
            "and retry."
        )
        raise typer.Exit(1)

    import httpx

    # Same downloader AND the same destination helper the per-challenge pre-download
    # uses (vulnclaw/platforms/attachments.py). Extracted for exactly this reason: the
    # two paths must not drift into "the batch fetches X, the solve fetches Y" -- and
    # the destination used to be a second copy of a Windows-only expression here.
    from vulnclaw.platforms.attachments import attachment_dir, download_attachment

    attach_dir = attachment_dir()
    os.makedirs(attach_dir, exist_ok=True)
    console.print(f"[*] Downloading attachments for {len(rows)} challenges -> {attach_dir}")

    ok = 0
    fail = 0
    # verify=True, deliberately. This used to be `verify=False`, which accepted ANY
    # certificate for a file we then analyse -- and for pwn/RE challenges, execute. The
    # declared size is no defence: an on-path attacker picks the size.
    #
    # Turning it on is safe: the file host serves a valid DigiCert chain, confirmed by
    # fetching a real attachment with verification (the pre-download path, and a plain
    # urllib request, which verifies by default).
    #
    # An operator behind a TLS-inspecting proxy has a legitimate way out that keeps
    # verification ON -- point SSL_CERT_FILE/SSL_CERT_DIR at the interceptor's CA -- and
    # `_describe_download_error` tells them so when a certificate failure happens,
    # instead of leaving a bare SSLError with an in-code bypass as the only option.
    with httpx.Client(timeout=60, verify=True) as client:
        for token, listed in rows:
            try:
                adapter = registry.adapter_for(token)
                challenge = asyncio.run(adapter.read_challenge(listed.ref))
            except Exception as exc:
                fail += 1
                console.print(
                    f"    [fail] {listed.name}: {type(exc).__name__}: {str(exc)[:100]}"
                )
                continue
            if not challenge.attachments:
                console.print(f"    [skip] {challenge.name}: no attachments published")
                continue
            for attachment in challenge.attachments:
                label = f"{challenge.name}/{attachment.name}"
                result = download_attachment(
                    client,
                    attachment,
                    attach_dir,
                    challenge_name=challenge.name,
                    adapter=adapter,
                )
                # NOTE the ordering: a size mismatch sets `error` AND leaves `path`,
                # so `not result.ok` alone would file it as a failure. The original
                # inline version warned and still counted it as ok -- the file was
                # written and is worth keeping for inspection -- and that distinction
                # is preserved here.
                if result.error and not result.path:
                    fail += 1
                    console.print(f"    [fail] {label}: {result.error}")
                    continue
                if result.error:
                    console.print(f"    [warn] {label}: {result.error}")
                ok += 1
                console.print(f"    [ok]   {label} -> {os.path.basename(result.path)}")
    console.print(f"\n[*] Download complete: {ok} ok, {fail} failed/skipped.")
    if fail:
        console.print(
            "[i] Some attachments could not be downloaded; the platform may be "
            "closing or the schema changed. The ones downloaded are already a "
            "local insurance for analysis."
        )


def _adapter_for_ref(ref_token: str) -> Any:
    """The adapter owning a ref token, or None when it cannot be resolved.

    None is a valid answer here: the pre-download is insurance, and a platform that
    cannot be resolved should leave the solve to do what it did before rather than
    failing it.
    """
    try:
        from vulnclaw.platforms import registry
        from vulnclaw.platforms.bootstrap import ensure_adapters

        ensure_adapters()
        return registry.adapter_for(ref_token)
    except Exception:  # noqa: BLE001 - insurance must never break a solve
        return None


def _predownload_challenge_attachments(
    cfg: Any,
    challenge_name: str,
    attachments: Any,
    adapter: Any,
) -> list[str]:
    """Fetch a challenge's attachments before the agent starts. Best effort.

    This is what makes ``competition.predownload_attachments`` real. That field was
    declared, documented as match-start insurance and defaulted to True while nothing
    read it; the capability existed only inside the batch ``competition download``
    command. For a RE/pwn challenge the attachment *is* the challenge, so this is
    worth having: the agent gets a local path instead of depending on the platform's
    file host being reachable at solve time.

    Returns the local paths that are actually usable. Never raises and never aborts a
    solve: a failed pre-download must degrade to "the agent fetches it itself", which
    is the behavior that worked before this existed.
    """
    if not attachments:
        return []
    if not bool(getattr(cfg.competition, "predownload_attachments", False)):
        return []

    import httpx

    from vulnclaw.platforms.attachments import attachment_dir, download_attachment

    dest = attachment_dir()
    paths: list[str] = []
    try:
        # verify stays ON here, unlike the older batch command's client.
        # ctf2-files.dasctf.com serves a real DigiCert chain (confirmed by fetching an
        # attachment with default verification), so disabling it would be gratuitous.
        with httpx.Client(timeout=60.0) as client:
            results = [
                download_attachment(
                    client,
                    attachment,
                    dest,
                    challenge_name=challenge_name,
                    adapter=adapter,
                )
                for attachment in attachments
            ]
    except Exception as exc:  # noqa: BLE001 - insurance must never break a solve
        err_console.print(
            f"[!] attachment pre-download failed ({type(exc).__name__}: {exc}); "
            f"the agent can still fetch it from the platform"
        )
        return []

    for result in results:
        if result.ok:
            paths.append(result.path)
            console.print(f"[*] attachment ready: {os.path.basename(result.path)}")
        else:
            console.print(f"[!] attachment {result.name}: {result.error}")
    return paths


def _competition_solve(cfg: Any, ref: str) -> None:
    """Run one challenge with competition strategy, addressed by platform ref.

    Previously hardcoded to the GCS command with a numeric exercise id, which made
    'competition solve' the one CLI path that only worked for a single platform.
    The platform now comes from the ref (``ctf2:practice:<pid>:<cid>`` /
    ``gcs:exercise:<eid>``), so any configured platform can be driven this way --
    and the goal it hands the agent points at the same neutral ``platform_*`` tools
    every other entry point uses.
    """
    import asyncio

    from vulnclaw.platforms import registry
    from vulnclaw.platforms.bootstrap import ensure_adapters
    from vulnclaw.platforms.refs import split_token

    token = str(ref).strip()
    if token.isdigit():
        # Backward compatibility with the old `competition solve <exercise_id>`.
        token = f"gcs:exercise:{token}"

    ensure_adapters()
    try:
        adapter = registry.adapter_for(token)
        challenge_ref = adapter.parse_ref(split_token(token)[1])
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[!] cannot use ref {token!r}: {exc}")
        raise typer.Exit(1)

    try:
        challenge = asyncio.run(adapter.read_challenge(challenge_ref))
    except Exception as exc:  # noqa: BLE001
        err_console.print(f"[!] failed to read {token}: {type(exc).__name__}: {exc}")
        raise typer.Exit(1)

    comp = cfg.competition
    stall = int(getattr(comp, "stall_turns", 8))
    console.print(
        f"[*] Competition solve: {challenge.name} ({token}) | "
        f"stall guard after {stall} unproductive turns"
    )
    # Same match-start insurance as `vulnclaw ctf2`: see
    # _predownload_challenge_attachments. Presented as local paths so the agent does
    # not need the platform's file host at all.
    predownloaded = _from_main("_predownload_challenge_attachments")(
        cfg, str(challenge.name), challenge.attachments, adapter
    )
    goal = (
        f"Solve {challenge.name} (category {challenge.category or 'unknown'}, "
        f"difficulty {challenge.difficulty or 'unknown'}).\n"
        f"REF: {token}\n"
        f"Pass that exact string as `ref` to every platform_* tool -- the platform "
        f"comes from the ref, so there is no separate platform id to choose. "
        + (
            "This challenge needs a running environment: platform_start_env to "
            "start it, platform_read_env until it reports the target as usable, "
            "then platform_stop_env to release it when done. "
            if challenge.needs_env
            else "This challenge needs no running environment. "
        )
        + "Submit the flag with platform_submit once it is known.\n"
        # The A2 evidence chain needs an explicit nudge. Measured 2026-10-09 on a
        # live Web challenge: with a goal that only said "submit the flag", the
        # model ran 57 tool calls and never once reached for report_finding /
        # traffic_* -- it had no reason to, because nothing told it the report
        # wants findings with bound proof. The tools existing is not the same as
        # the model knowing to use them.
        + (
            "If the target is a live web service and you confirm a vulnerability "
            "(injection / IDOR / upload / credential leak / misconfig), do not stop "
            "at the flag:\n"
            "  1. look at the captured HTTP traffic (traffic_list) and note the "
            "request_id of the exchange that proves it;\n"
            "  2. record the finding with report_finding (title/severity/vuln_type/"
            "description/evidence, verified=true only if you reproduced it);\n"
            "  3. bind the proof with traffic_bind_evidence -- ref that finding and "
            "those request_ids (role=proof for the exploit, role=baseline for the "
            "normal request) so the report carries the raw request/response.\n"
            "Only traffic that went through the capture layer is listable; if "
            "traffic_list is empty, issue the proving request via traffic_repeat or "
            "the browser so the exchange is captured.\n"
            if challenge.needs_env
            else ""
        )
        + (
            "Its attachments are ALREADY DOWNLOADED to local paths, use them directly:\n"
            + "\n".join(f"  {path}" for path in predownloaded)
            + "\n"
            if predownloaded
            else ""
        )
        + f"Challenge description follows:\n{challenge.description}"
    )
    # Every optional flag is passed explicitly: solve() is a Typer command, so a
    # direct Python call leaves un-passed parameters as truthy OptionInfo sentinels.
    _from_main("solve")(
        target=token,
        goal=goal,
        max_steps=max(60, stall * 4),
        resume=False,
        prompt=None,
        max_directions=3,
        max_tool_rounds=6,
        snapshot=None,
        run_name=None,
        resume_run=None,
        runs_dir=None,
        additional_targets=None,
        target_type=None,
        mount=False,
        repair=False,
        force_fresh=False,
        no_import=False,
        stream=False,
        writeup_dir=None,
        model="auto",
    )
