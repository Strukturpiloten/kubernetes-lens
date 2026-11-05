#!/usr/bin/env python3
"""Compatibility entrypoint for repository-specific shared automation contracts."""

import runpy
from pathlib import Path

if __name__ == "__main__":
    runpy.run_path(str(Path(__file__).with_name("test-shared-automation.py")), run_name="__main__")
