#!/usr/bin/env python3
"""Invoke the selected BoxFerry runtime installer for repository validation."""

import argparse
import runpy
import subprocess
import sys
from collections.abc import Generator
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
BOOTSTRAP = runpy.run_path(str(ROOT / "scripts/shared-ci.py"))


@contextmanager
def selected_project() -> Generator[Path]:
    config = BOOTSTRAP["load_config"](ROOT)
    with BOOTSTRAP["locked_export"](ROOT):
        project: Path = BOOTSTRAP["prepare_implementation"](ROOT, config["revision"])
        print(
            f"Renovate runtime authority: {config['repository']}@{config['revision']}",
            file=sys.stderr,
        )
        yield project


def installer_command(project: Path, engine: str, destination: Path) -> list[str]:
    return [
        sys.executable,
        "-I",
        str(project / "src/boxferry_ci/renovate_runtime.py"),
        "--engine",
        engine,
        "--pin",
        str(project / "renovate-runtime.json"),
        "--destination",
        str(destination),
    ]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--engine", required=True, choices=("podman", "docker"))
    options = parser.parse_args()
    try:
        with selected_project() as project:
            return subprocess.run(
                installer_command(project, options.engine, ROOT / ".ci-tools/renovate"),
                check=False,
            ).returncode
    except (BOOTSTRAP["BootstrapError"], OSError) as error:
        print(f"Renovate runtime source preparation failed: {error}", file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())
