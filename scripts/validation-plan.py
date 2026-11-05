#!/usr/bin/env python3
"""Compatibility entrypoint for the immutable BoxFerry CI launcher."""

import os
import sys
from pathlib import Path

if __name__ == "__main__":
    launcher = Path(__file__).with_name("shared-ci.py")
    os.execv(sys.executable, [sys.executable, str(launcher), *sys.argv[1:]])
