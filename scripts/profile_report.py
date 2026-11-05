#!/usr/bin/env python3
"""Print the resolved run profile and every path this process will write to.

Why it exists: the operator's E: workspace is shared by the CTF checkout and the
production checkout, and the only thing that separates them at runtime is
``VULNCLAW_PROFILE`` + the two root variables. A launcher that forgets one of them
does not fail loudly -- it silently reads the other profile's playbooks or writes
attachments into the CTF work tree. Run this from the launcher (or by hand) to see
what the process actually resolved, and use ``--strict`` in a launcher so a
half-configured environment stops instead of mixing.

    python -X utf8 scripts/profile_report.py
    python -X utf8 scripts/profile_report.py --strict
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent


def _resolve() -> dict[str, object]:
    from vulnclaw.config.profile import current_profile
    from vulnclaw.config.settings import CONFIG_DIR
    from vulnclaw.agent.playbook import PLAYBOOKS_DIR
    from vulnclaw.platforms.attachments import attachment_dir, work_dir

    profile = current_profile()
    work_root = str(work_dir())
    attach = str(attachment_dir())
    playbooks = str(PLAYBOOKS_DIR)
    warnings: list[str] = []
    if profile == "prod":
        # Attachments and playbooks are split automatically; runs/evidence/
        # sessions/targets still live under CONFIG_DIR, so a production process on
        # the default config root shares them with the CTF profile.
        if os.path.normcase(attach) == os.path.normcase(os.path.join(work_root, "attachments")):
            warnings.append(
                "attachments resolve to the CTF directory; set VULNCLAW_ATTACH_DIR "
                "or a separate VULNCLAW_WORK_DIR for the production profile"
            )
        default_config = Path.home() / ".vulnclaw"
        if Path(CONFIG_DIR).resolve() == default_config.resolve():
            warnings.append(
                "config_root is the shared default; runs/, evidence/, sessions/ and "
                "targets/ are shared with the CTF profile -- set VULNCLAW_CONFIG_DIR "
                "to a production-specific root"
            )
    return {
        "profile": profile,
        "config_root": str(CONFIG_DIR),
        "work_root": work_root,
        "attachment_dir": attach,
        "playbook_dir": playbooks,
        "runs_root": str(Path(CONFIG_DIR) / "runs"),
        "warnings": warnings,
    }


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument(
        "--strict",
        action="store_true",
        help="exit non-zero when the environment looks shared between profiles",
    )
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    args = ap.parse_args(argv)

    if str(REPO) not in sys.path:
        sys.path.insert(0, str(REPO))

    info = _resolve()
    if args.json:
        print(json.dumps(info, ensure_ascii=False, indent=2))
    else:
        print(f"profile        : {info['profile']}")
        print(f"config_root    : {info['config_root']}")
        print(f"work_root      : {info['work_root']}")
        print(f"attachment_dir : {info['attachment_dir']}")
        print(f"playbook_dir   : {info['playbook_dir']}")
        print(f"runs_root      : {info['runs_root']}")
        for warning in info["warnings"]:  # type: ignore[index]
            print(f"WARN           : {warning}")

    if args.strict and info["warnings"]:
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
