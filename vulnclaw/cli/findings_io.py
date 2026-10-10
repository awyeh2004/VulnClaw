"""CLI 共用的 ``findings.json`` 读写。

``retest`` 与 ``evidence`` 两个子命令都要「按 finding_id 定位一条已上报的结论、
必要时写回」，规则只写一遍：run 目录 → ``findings.json``；解析失败一律报
:class:`FindingsFileError`（调用方决定退出码），写回走原子写。
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from vulnclaw.config.domain_models import VulnerabilityFinding
from vulnclaw.utils.atomic_write import atomic_write_text


def _atomic_write_json(path: Path, data: Any) -> None:
    """Same bytes as the rest of the repo's JSON writers (``ensure_ascii=False``)."""

    atomic_write_text(path, json.dumps(data, ensure_ascii=False, indent=2))


class FindingsFileError(ValueError):
    """The findings document cannot be located, parsed, or does not hold the id."""


def resolve_findings_file(raw: str | Path) -> Path:
    """Accept either a ``findings.json`` or the run directory that holds one."""

    path = Path(raw)
    if path.is_dir():
        candidate = path / "findings.json"
        if not candidate.exists():
            raise FindingsFileError(f"no findings.json under {path}")
        return candidate
    if not path.exists():
        raise FindingsFileError(f"findings file not found: {path}")
    return path


def load_document(raw: str | Path) -> dict[str, Any]:
    path = resolve_findings_file(raw)
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise FindingsFileError(f"findings file is unreadable: {path}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("findings"), list):
        raise FindingsFileError(f"findings file has no 'findings' list: {path}")
    return document


def find_entry(document: dict[str, Any], finding_id: str) -> dict[str, Any]:
    for entry in document.get("findings") or []:
        if str(entry.get("finding_id", "")) == str(finding_id):
            return entry
    raise FindingsFileError(f"finding {finding_id!r} is not in this findings file")


def load_finding(raw: str | Path, finding_id: str) -> VulnerabilityFinding:
    entry = find_entry(load_document(raw), finding_id)
    try:
        return VulnerabilityFinding.model_validate(entry)
    except Exception as exc:  # pragma: no cover - schema drift on an old artifact
        raise FindingsFileError(f"finding {finding_id!r} is not a valid finding: {exc}") from exc


def save_finding(raw: str | Path, finding: VulnerabilityFinding) -> Path:
    """Replace this finding's entry in the document and write it back atomically.

    Only the one entry is touched: the document's other keys (``summary``,
    ``version``, the sibling findings) are preserved verbatim.

    Fields the model does not know are preserved too. ``VulnerabilityFinding`` is
    a plain ``BaseModel`` (``extra`` defaults to ``ignore``), so a foreign key on
    the entry -- one written by a newer build, or by hand -- is dropped the
    moment the entry is validated. Writing ``model_dump`` back verbatim would
    therefore silently delete it. Overlay the dump on the original entry instead:
    every known field comes from the model (so the edit takes effect), and any
    key the model never saw survives untouched.
    """

    path = resolve_findings_file(raw)
    document = load_document(path)
    payload = finding.model_dump(mode="json")
    for index, entry in enumerate(document["findings"]):
        if str(entry.get("finding_id", "")) == str(finding.finding_id):
            document["findings"][index] = {**entry, **payload}
            break
    else:
        raise FindingsFileError(f"finding {finding.finding_id!r} is not in this findings file")
    _atomic_write_json(path, document)
    return path
