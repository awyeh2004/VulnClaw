from __future__ import annotations

import argparse
import shutil
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FRONTEND = ROOT / "frontend"


def run_step(name: str, command: list[str], cwd: Path | None = None) -> None:
    print(f"[preflight] {name}: {' '.join(command)}")
    subprocess.run(command, cwd=str(cwd or ROOT), check=True)


def main() -> int:
    parser = argparse.ArgumentParser(description="Run VulnClaw release preflight checks.")
    parser.add_argument("--build", action="store_true", help="Also build dist artifacts after tests and typechecks")
    args = parser.parse_args()

    run_step("version-check", [sys.executable, "-m", "pytest", "-q", "tests/meta/test_release.py"])
    run_step("backend-tests", [sys.executable, "-m", "pytest", "-q"])
    npm_cmd = shutil.which("npm") or shutil.which("npm.cmd")
    if not npm_cmd:
        raise FileNotFoundError("npm was not found in PATH")
    run_step("frontend-types", [npm_cmd, "exec", "--", "tsc", "-b"], cwd=FRONTEND)
    if args.build:
        run_step("build-package", [sys.executable, "-m", "build"])
        run_step("verify-dist", [sys.executable, "scripts/verify_dist_artifacts.py"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
