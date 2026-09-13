"""Shared self-learning-loop operations for the CLI and the interactive REPL.

Both the top-level ``vulnclaw experience`` / ``learn`` / ``feedback`` commands
and the classic-REPL ``/experience`` / ``/learn`` / ``/feedback`` slash commands
route through here so the two surfaces never drift.

Every function is REPL-safe: it performs the store or run-artifact work and
returns a result for the caller to render, but it never calls ``typer.Exit`` or
otherwise unwinds the process. The typer commands translate a failed
:class:`OpResult` into ``typer.Exit(1)``; the REPL prints it and keeps looping.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Optional

from rich.console import RenderableType
from rich.panel import Panel
from rich.table import Table
from rich.text import Text


@dataclass
class OpResult:
    """Outcome of a self-learning-loop operation.

    ``ok`` reports success; ``renderable`` is the message or rich object the
    caller should print. ``ok=False`` marks a user-facing failure (unknown
    lesson, missing credentials, unfinished run, invalid input).
    """

    ok: bool
    renderable: RenderableType


def _experience_store() -> Any:
    """Create the human-gated lesson store only when a command needs it."""
    from vulnclaw.kb.experience import ExperienceStore

    return ExperienceStore()


def render_pending_lessons() -> OpResult:
    """List lessons awaiting human review as a table (or a friendly note)."""
    from vulnclaw.kb.experience import LessonStatus

    try:
        lessons = _experience_store().list_by_status(LessonStatus.PENDING)
    except OSError as exc:
        return OpResult(False, f"[!] Could not read the experience store: {exc}")
    if not lessons:
        return OpResult(True, "No pending experience lessons.")

    table = Table(title="Pending Experience Lessons", show_lines=False)
    table.add_column("ID", style="cyan", no_wrap=True)
    table.add_column("Scope")
    table.add_column("Signal")
    table.add_column("Confidence", justify="right")
    table.add_column("Context")
    for item in lessons:
        table.add_row(
            Text(item.id),
            Text(item.scope.value),
            Text(item.signal.value),
            f"{item.confidence:.2f}",
            Text(item.context),
        )
    return OpResult(True, table)


def render_lesson(lesson_id: str) -> OpResult:
    """Show full lesson text and evidence provenance for one lesson."""
    try:
        item = _experience_store().get(lesson_id)
    except ValueError:
        # A malformed id (path separators, empty string) must stay REPL-safe.
        return OpResult(False, f"[!] Lesson not found: {lesson_id}")
    except OSError as exc:
        return OpResult(False, f"[!] Could not read the experience store: {exc}")
    if item is None:
        return OpResult(False, f"[!] Lesson not found: {lesson_id}")

    evidence = item.evidence_refs
    tags = item.tags
    source_runs = ", ".join(item.source_runs) or "-"
    details = Text()

    def add_line(label: str, value: str) -> None:
        details.append(f"{label}: ", style="bold")
        details.append(value)
        details.append("\n")

    add_line("ID", item.id)
    add_line("Status", item.status.value)
    add_line("Scope", item.scope.value)
    add_line("Signal", item.signal.value)
    add_line("Confidence", f"{item.confidence:.2f}")
    add_line(
        "Tags",
        f"tech={', '.join(tags.tech) or '-'}, vuln_type={tags.vuln_type or '-'}, "
        f"waf={tags.waf or '-'}, service={tags.service or '-'}",
    )
    add_line("Target key", item.target_key or "-")
    add_line("Context", item.context)
    add_line("Lesson", item.lesson)
    add_line(
        "Evidence",
        f"run_id={evidence.run_id}, finding_id={evidence.finding_id or '-'}, "
        f"path={evidence.path or '-'}",
    )
    add_line("Source runs", source_runs)
    details.append("Created: ", style="bold")
    details.append(item.created_at.isoformat())
    return OpResult(
        True,
        Panel(details, title="Experience Lesson", border_style="cyan"),
    )


def set_lesson_status(lesson_id: str, status: str) -> OpResult:
    """Apply one human review decision (``approved`` or ``rejected``)."""
    try:
        store = _experience_store()
        item = store.approve(lesson_id) if status == "approved" else store.reject(lesson_id)
    except ValueError:
        return OpResult(False, f"[!] Lesson not found: {lesson_id}")
    except OSError as exc:
        # An unwritable or full KB must not unwind the interactive REPL.
        return OpResult(False, f"[!] Could not write the experience store: {exc}")
    if item is None:
        return OpResult(False, f"[!] Lesson not found: {lesson_id}")
    return OpResult(True, f"[+] Lesson {item.id} marked {item.status.value}.")


def edit_lesson(
    lesson_id: str,
    *,
    context: Optional[str] = None,
    lesson: Optional[str] = None,
) -> OpResult:
    """Amend context and/or lesson text without changing provenance or status."""
    if context is None and lesson is None:
        return OpResult(False, "[!] Provide new context and/or lesson text.")
    try:
        item = _experience_store().update(lesson_id, context=context, lesson=lesson)
    except ValueError as exc:
        return OpResult(False, f"[!] Invalid lesson update: {exc}")
    except OSError as exc:
        return OpResult(False, f"[!] Could not write the experience store: {exc}")
    if item is None:
        return OpResult(False, f"[!] Lesson not found: {lesson_id}")
    return OpResult(True, f"[+] Lesson {item.id} updated.")


def distill_run(
    run_name: str,
    *,
    config: Any,
    runs_dir: Optional[str] = None,
) -> OpResult:
    """Distill a completed run into pending lessons (the ``learn`` command)."""
    import json

    from vulnclaw.agent.context import SessionState
    from vulnclaw.agent.distiller import (
        RunArtifacts,
        configured_distiller,
        persist_distilled_lessons,
    )
    from vulnclaw.config.token_provider import has_llm_credentials
    from vulnclaw.feedback import feedback_for_distillation
    from vulnclaw.kb.experience import ExperienceStore
    from vulnclaw.run_context import RunContextError, load_run_context

    if not has_llm_credentials(config.llm):
        return OpResult(False, "[!] Configure LLM credentials first (api_key or auth_mode).")

    run_context = None
    try:
        run_context = load_run_context(run_name, runs_dir=runs_dir, config=config)
        state_data = json.loads(run_context.state_path().read_text(encoding="utf-8"))
        session = SessionState.model_validate(state_data)
        target = run_context.target_manifest()
        artifacts = RunArtifacts.from_session(
            run_context.run_name,
            session,
            target_key=str(target.get("target_id") or ""),
            feedback=feedback_for_distillation(run_context.run_dir),
        )
        lessons = persist_distilled_lessons(
            artifacts,
            configured_distiller(config),
            ExperienceStore(),
        )
        run_context.append_event("distillation_completed", {"lessons": len(lessons), "manual": True})
    except (OSError, ValueError, json.JSONDecodeError, RunContextError) as exc:
        return OpResult(False, f"[!] Could not distill run {run_name}: {exc}")
    except Exception as exc:
        # Keep a run-local audit event, but surface only a concise error type.
        if run_context is not None:
            try:
                run_context.append_event(
                    "distillation_failed", {"error": type(exc).__name__, "manual": True}
                )
            except Exception:
                pass
        return OpResult(False, f"[!] Distillation failed: {type(exc).__name__}")

    return OpResult(
        True,
        f"[+] Distilled {len(lessons)} pending lesson(s) from run {run_context.run_name}.",
    )


def save_run_feedback(
    run: str,
    *,
    rating: int,
    notes: str,
    config: Any,
    runs_dir: Optional[str] = None,
) -> OpResult:
    """Attach or update an operator assessment for a completed run."""
    from vulnclaw.feedback import FeedbackError, save_feedback
    from vulnclaw.run_context import RunContextError, load_run_context

    try:
        run_context = load_run_context(run, runs_dir=runs_dir, config=config)
    except (RunContextError, ValueError, OSError) as exc:
        return OpResult(False, f"[!] Unable to load run '{run}': {exc}")

    status = str(run_context.manifest.get("status") or "")
    if status not in {"completed", "interrupted", "failed"}:
        return OpResult(
            False, f"[!] Run '{run}' is not finished (status: {status or 'unknown'})."
        )
    if not notes.strip():
        return OpResult(False, "[!] Feedback notes must not be empty.")

    try:
        saved = save_feedback(run_context.run_dir, rating=rating, notes=notes)
        # Notes can carry sensitive operational detail; only record the rating.
        run_context.append_event("feedback_updated", {"rating": saved.rating})
    except FeedbackError as exc:
        return OpResult(False, f"[!] Invalid feedback: {exc}")
    except OSError as exc:
        # feedback.json or events.jsonl unwritable: stay REPL-safe.
        return OpResult(False, f"[!] Could not save feedback for '{run}': {exc}")

    return OpResult(True, f"[+] Feedback saved for {run}: rating={saved.rating}/5")
