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
    if mode == "solve-all":
        err_console.print(
            "[!] 'solve-all' is its own command, not a competition mode — run "
            "`vulnclaw solve-all --help` (it takes --concurrency / --limit / --dry-run)."
        )
        raise typer.Exit(1)
    err_console.print(
        f"[!] unknown competition mode: {mode} (use: latency | plan | download | "
        f"solve <eid>)"
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


# ── 跨题并发（solve-all） ────────────────────────────────────────────────────
#
# 2026-10-31 强网杯实测：babysilent / 谍影 / CanonicoPWN / dreambound 四题**一次
# 都没跑过**，而题解方四题全解。这不是能力缺口，是排期缺口——当时的做法是手写
# 队列脚本一道道串行跑，前一题烧完时间就没后一题的机会。
#
# 单题内部已经有并行（`run_parallel_pentest` 的表面波 + `run_team_pentest` 的
# 计划波），但对 CTF 单题扇不出多个表面：一个 URL 提不出四个 service。真正缺的
# 并行维度是**跨题**。
#
# 实现上必须用子进程而不是线程/协程：`solve()` 内部是 `asyncio.run(_run())`，
# 同一进程里再跑一次会把事件循环弄坏。锁是**按 target** 分的
# （`solver._solve_lock_path`），不同题不冲突，所以并发是安全的。

#: Upper bound on simultaneous solve processes. The real ceiling is the LLM
#: backend, not the CPU: `competition latency` exists precisely because a slow
#: shared endpoint gets *worse* with more workers. Kept low by default and
#: expected to be raised only after that probe says the backend is fast.
DEFAULT_SOLVE_ALL_CONCURRENCY = 3

#: How often the supervisor re-checks child exit codes. A module constant so
#: tests can pin it instead of sleeping for real.
_SOLVE_ALL_POLL_SECONDS = 0.5


def _solve_target_for(challenge: Any) -> str:
    """The string this challenge would have been recorded under in past runs.

    A run records the *actual* target it was handed — an IP, a host, or a local
    attachment path — never the platform ref: ``run.json`` on 2026-10-31 shows
    ``"canonical": "123.57.159.91:30728"`` for a challenge whose ref was
    ``ctf2:practice:...``. So matching a platform challenge to local history is
    a best-effort name lookup, not an identity check.

    The challenge name is used because it is the one string that survives both
    sides: operators name their runs after the challenge (``qwb-oldsvr``), and
    the name appears in the goal text a run records. A wrong guess here costs an
    unnecessary "already attempted" label that the operator can override with
    ``--include-attempted``, so it is deliberately permissive.
    """
    name = str(getattr(challenge, "name", "") or "").strip()
    if name:
        return name
    ref = getattr(challenge, "ref", None)
    token = getattr(ref, "token", None)
    if callable(token):
        try:
            return str(token())
        except Exception:  # noqa: BLE001
            return ""
    return ""


def solve_all(
    limit: int = typer.Option(
        0, "--limit", help="Only take this many challenges after ordering (0 = all)"
    ),
    concurrency: int = typer.Option(
        DEFAULT_SOLVE_ALL_CONCURRENCY,
        "--concurrency",
        help="How many solve processes to run at once. Raise only after "
        "`vulnclaw competition latency` reports a fast backend.",
    ),
    skip_solved: bool = typer.Option(
        True, "--skip-solved/--include-solved", help="Skip challenges the platform reports SOLVED"
    ),
    dry_run: bool = typer.Option(
        False, "--dry-run", help="Print the launch plan and exit without starting anything"
    ),
    timeout_min: int = typer.Option(
        0,
        "--timeout-min",
        help="Hard wall-clock cap for the whole batch, in minutes (0 = no cap). "
        "A solve that hangs must not hold the other challenges' time.",
    ),
    skip_attempted: bool = typer.Option(
        False,
        "--skip-attempted/--include-attempted",
        help="Skip challenges this machine has already run locally (any outcome). "
        "Off by default: an abandoned attempt may deserve another go, so the "
        "operator decides — see `vulnclaw where` for the effort already spent.",
    ),
    min_effort: int = typer.Option(
        0,
        "--min-effort",
        help="With --skip-attempted, only skip challenges whose previous run used "
        "at least this many tool calls. Lets a cheap abandoned try be retried "
        "while the expensive ones stay parked.",
    ),
) -> None:
    """Run every unsolved challenge concurrently, one subprocess per challenge.

    Why this exists: a sequential run gives the *first* challenge all the time
    and every later one none. On 2026-10-31 that pattern cost four entire
    challenges that were later shown solvable, while the challenges actually
    attempted consumed 1500+ tool calls. Breadth beats depth when the deadline
    is fixed.

    Every child is a normal ``vulnclaw competition solve <ref>`` invocation, so
    this adds no new solving behaviour — it only changes what runs at the same
    time. Output from each child is captured to its own log file so concurrent
    runs do not interleave.
    """
    import subprocess
    import sys
    import time

    cfg = _from_main("load_config")()
    comp = cfg.competition

    challenges = _from_main("_platform_challenges")()
    if not challenges:
        err_console.print(
            "[!] No platform challenges available. Configure a platform, or run "
            "`vulnclaw competition plan` to see the local fallback."
        )
        raise typer.Exit(1)

    ordered = sorted(challenges, key=_from_main("_challenge_sort_key"), reverse=True)
    if getattr(comp, "easy_first", True):
        # Stable partition, not a full re-sort: within a difficulty band the
        # score order computed above must survive.
        ordered.sort(key=lambda row: str(row[1].difficulty).lower() != "easy")

    if skip_solved:
        solved = [row for row in ordered if getattr(row[1], "solved", False)]
        ordered = [row for row in ordered if not getattr(row[1], "solved", False)]
        if solved:
            console.print(f"[*] Skipping {len(solved)} already-solved challenge(s).")

    # Local attempt history. Only consulted when the operator asks, because
    # "attempted" and "should not be retried" are different claims: an abandoned
    # 5-call try is worth another shot, a 300-call one usually is not. The
    # effort figure reported here is what `vulnclaw where` shows in full.
    attempt_index = None
    if skip_attempted:
        from vulnclaw.attempt_index import build_index

        attempt_index = build_index()
        kept: list[Any] = []
        parked: list[tuple[str, Any, int]] = []
        for token, challenge in ordered:
            spent = attempt_index.effort_for(_solve_target_for(challenge))
            if spent >= max(0, int(min_effort or 0)) and attempt_index.was_attempted(
                _solve_target_for(challenge)
            ):
                parked.append((token, challenge, spent))
            else:
                kept.append((token, challenge))
        ordered = kept
        if parked:
            console.print(
                f"[*] Skipping {len(parked)} already-attempted challenge(s) "
                f"(min-effort={min_effort}):"
            )
            for token, challenge, spent in parked:
                console.print(f"    {token}  {challenge.name} (previous effort: {spent} calls)")

    if limit > 0:
        ordered = ordered[:limit]

    if not ordered:
        console.print("[*] Nothing to run.")
        return

    concurrency = max(1, min(int(concurrency or 1), len(ordered)))
    console.print(
        f"[*] solve-all: {len(ordered)} challenge(s), {concurrency} at a time "
        f"(easy-first={'on' if getattr(comp, 'easy_first', True) else 'off'})"
    )
    for token, challenge in ordered:
        console.print(f"    {token}  {challenge.name} ({challenge.difficulty or '-'})")

    if dry_run:
        console.print("[*] --dry-run: nothing started.")
        return

    log_dir = _solve_all_log_dir()
    console.print(f"[*] Per-challenge logs: {log_dir}")

    running: list[tuple[str, subprocess.Popen, Any]] = []
    pending = list(ordered)
    finished: list[tuple[str, int]] = []

    def _launch(token: str, challenge: Any) -> tuple[str, subprocess.Popen, Any]:
        handle = open(log_dir / f"{_safe_log_name(token)}.log", "w", encoding="utf-8")
        # sys.executable, not a bare "vulnclaw": the running interpreter is the
        # one this module was imported from, so a venv or a source checkout is
        # honoured and the child cannot silently resolve to a different install.
        argv = [sys.executable, "-X", "utf8", "-m", "vulnclaw", "competition", "solve", token]
        proc = subprocess.Popen(  # noqa: S603 - argv is built here, not user text
            argv,
            stdout=handle,
            stderr=subprocess.STDOUT,
            cwd=os.getcwd(),
        )
        return token, proc, handle

    try:
        deadline = time.monotonic() + timeout_min * 60 if timeout_min > 0 else None
        while pending or running:
            while pending and len(running) < concurrency:
                token, challenge = pending.pop(0)
                try:
                    running.append(_launch(token, challenge))
                    console.print(f"[+] started {token}")
                except Exception as exc:  # noqa: BLE001 - one bad launch must not stop the batch
                    err_console.print(f"[!] failed to start {token}: {exc}")

            if deadline is not None and time.monotonic() >= deadline:
                err_console.print(
                    f"[!] --timeout-min {timeout_min} reached — stopping "
                    f"{len(running)} running solve(s) and {len(pending)} queued."
                )
                for token, proc, handle in running:
                    proc.terminate()
                    try:
                        proc.wait(timeout=10)
                    except subprocess.TimeoutExpired:
                        proc.kill()
                    handle.close()
                    finished.append((token, -1))
                running = []
                pending = []
                break

            time.sleep(_SOLVE_ALL_POLL_SECONDS)
            still: list[tuple[str, subprocess.Popen, Any]] = []
            for token, proc, handle in running:
                code = proc.poll()
                if code is None:
                    still.append((token, proc, handle))
                    continue
                handle.close()
                finished.append((token, code))
                status = "[green]ok[/]" if code == 0 else f"[red]exit {code}[/]"
                console.print(f"[-] finished {token} ({status})")
            running = still
    except KeyboardInterrupt:
        err_console.print("[!] interrupted — terminating running solves")
        for token, proc, handle in running:
            proc.terminate()
            try:
                proc.wait(timeout=10)
            except subprocess.TimeoutExpired:
                proc.kill()
            handle.close()
        raise typer.Exit(130) from None

    ok = sum(1 for _, code in finished if code == 0)
    console.print(f"[*] solve-all done: {ok}/{len(finished)} exited cleanly.")
    # A non-zero child exit means that challenge's run failed, not that the batch
    # did — report it, but only fail the command when nothing succeeded, so a
    # single broken target does not make an otherwise productive match look red.
    if finished and ok == 0:
        raise typer.Exit(1)


def _solve_all_log_dir() -> Any:
    """Directory for per-challenge child logs, created on demand."""
    from pathlib import Path

    base = os.environ.get("VULNCLAW_WORK_DIR") or os.path.expanduser("~/vulnclaw/work")
    path = Path(base) / "solve-all"
    path.mkdir(parents=True, exist_ok=True)
    return path


def _safe_log_name(token: str) -> str:
    """Collision-free, filesystem-safe log stem derived from a challenge ref.

    The sanitiser maps every non-alphanumeric run to ``_``, so two different refs
    can collapse to one name: ``ctf2:practice:p1:c1`` and ``ctf2/practice/p1/c1``
    both become ``ctf2_practice_p1_c1``. Platform refs happen to use a single
    separator today, which is why this has not bitten — but in ``solve-all`` a
    collision means two children append to one log, and the reviewer then reads a
    merged transcript that belongs to neither challenge.

    A short digest of the *original* token makes the name unique without making it
    unreadable.
    """
    import hashlib
    import re

    text = str(token or "challenge")
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", text).strip("_")[:100] or "challenge"
    digest = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:8]
    return f"{stem}-{digest}"


def where(
    all_targets: bool = typer.Option(
        False, "--all", help="Also list challenges already solved or marked attempted"
    ),
    top: int = typer.Option(
        0, "--top", help="Only show this many challenges (0 = all)", min=0
    ),
) -> None:
    """Show which challenges are untouched, attempted, and how much effort went in.

    This is the answer to a question the platform cannot answer. On 2026-10-31
    four challenges were never started while the ones attempted absorbed 1500+
    tool calls — and nothing on screen made that visible until the writeups came
    in. The platform reports *solved*; only the run history knows *tried*.

    Effort is the number of tool calls the previous run spent. It is the only
    honest way to tell "gave it a real go" from "opened it and got distracted",
    which is exactly the decision `solve-all --skip-attempted --min-effort`
    encodes.
    """
    from vulnclaw.attempt_index import build_index, summarize

    cfg = _from_main("load_config")()
    challenges = _from_main("_platform_challenges")()

    index = build_index()
    counts = summarize(index)
    console.print(
        f"[*] Local history: {counts['runs']} run(s), {counts['attempts']} attempt(s), "
        f"{counts['distinct_targets']} distinct target(s)."
    )

    if not challenges:
        console.print(
            "[!] No platform challenges available. Local history is above; "
            "configure a platform to map it onto a challenge list."
        )
        raise typer.Exit(1)

    ordered = sorted(challenges, key=_from_main("_challenge_sort_key"), reverse=True)
    rows: list[tuple[str, Any, str, int]] = []
    for token, challenge in ordered:
        if getattr(challenge, "solved", False):
            state = "solved"
        else:
            effort = index.effort_for(_solve_target_for(challenge))
            attempted = index.was_attempted(_solve_target_for(challenge))
            if not attempted:
                state = "UNTOUCHED"
            elif effort > 0:
                state = f"attempted ({effort} calls)"
            else:
                state = "attempted (no recorded effort)"
        rows.append((token, challenge, state, index.effort_for(_solve_target_for(challenge))))

    untouched = [r for r in rows if r[2] == "UNTOUCHED"]
    attempted = [r for r in rows if r[2].startswith("attempted")]
    solved = [r for r in rows if r[2] == "solved"]

    def _show(items: list[tuple[str, Any, str, int]], heading: str) -> None:
        if not items:
            return
        console.print(f"\n[bold]{heading}[/] ({len(items)})")
        shown = items[:top] if top > 0 else items
        for token, challenge, state, _effort in shown:
            console.print(
                f"    {state:26} {challenge.name} ({challenge.difficulty or '-'})  {token}"
            )
        if len(shown) < len(items):
            console.print(f"    ... and {len(items) - len(shown)} more")

    if all_targets:
        _show(untouched, "Untouched — never run on this machine")
        _show(attempted, "Attempted — a run exists")
        _show(solved, "Solved")
    else:
        _show(untouched, "Untouched — never run on this machine")
        if attempted:
            console.print(
                f"\n[dim]{len(attempted)} attempted, {len(solved)} solved "
                f"(pass --all to list them)[/]"
            )

    if not untouched:
        console.print(
            "\n[*] Every challenge has been run at least once. Nothing is "
            "unattempted — pick by effort spent, or revisit a solved one."
        )
