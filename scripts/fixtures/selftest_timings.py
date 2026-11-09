"""Passive, bounded timing for the existing six-module self-test (Python 3.11+)."""

import json
import math
import os
import re
import stat
import sys
import unittest
from time import perf_counter as _counter

ENVIRONMENT = "KUBERNETES_LENS_SELFTEST_TIMINGS"
MAX_CASES = 1024
MAX_BYTES = 512 * 1024
MAX_ID_BYTES = 192
MODULES = (
    "test_kind_runtime",
    "test_owned_qemu",
    "test_owned_host_view",
    "test_owned_guest_stage",
    "test_owned_guest_receiver",
    "test_owned_guest_rootful",
)
_IDENTIFIER = re.compile(r"[A-Za-z_][A-Za-z_0-9]*(?:\.[A-Za-z_][A-Za-z_0-9]*)*\Z")


def _sample():
    try:
        value = _counter()
        return value if type(value) in (int, float) and math.isfinite(value) else None
    except (OSError, RuntimeError, TypeError, ValueError, OverflowError):
        return None


def _elapsed(start):
    end = _sample()
    if start is None or end is None or end < start or not math.isfinite(end - start):
        return None
    return round(end - start, 6)


def _identity(test):
    module = type(test).__module__
    if type(module) is not str or module not in MODULES:
        return None, None
    parts = (module, type(test).__qualname__, getattr(test, "_testMethodName", None))
    if any(
        type(part) is not str
        or len(part) > MAX_ID_BYTES
        or not part.isascii()
        or not _IDENTIFIER.fullmatch(part)
        for part in parts
    ):
        return module, None
    if sum(len(part) for part in parts) + 2 > MAX_ID_BYTES:
        return module, None
    return module, ".".join(parts)


class TimingResult(unittest.TextTestResult):
    """Observe case lifetimes without changing unittest's outcome/fixture callbacks."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.modules = [{"id": name, "cases": 0, "timed": 0, "seconds": 0.0} for name in MODULES]
        self.rows = []
        self.omitted = self.untimed = self.clock_errors = 0
        self.identity_omitted = 0
        self._start = None
        self._skipped = False
        self._current = None

    def startTest(self, test):
        super().startTest(test)
        self._skipped = False
        self._current = test
        self._start = _sample()

    def addSkip(self, test, reason):
        if test is self._current:
            self._skipped = True
        super().addSkip(test, reason)

    def addDuration(self, test, elapsed):
        # 3.11 has no addDuration; newer interpreters must not collect twice.
        pass

    def stopTest(self, test):
        seconds = None if self._skipped else _elapsed(self._start)
        if seconds is None:
            self.untimed += 1
            self.clock_errors += int(not self._skipped)
        module, identity = _identity(test)
        if module in MODULES:
            aggregate = self.modules[MODULES.index(module)]
            aggregate["cases"] += 1
            if seconds is not None:
                aggregate["timed"] += 1
                aggregate["seconds"] += seconds
        if identity is None:
            self.omitted += 1
            self.identity_omitted += 1
        elif len(self.rows) >= MAX_CASES:
            self.omitted += 1
        else:
            self.rows.append([identity, seconds])
        super().stopTest(test)
        self._current = None

    def payload(self, expected, elapsed):
        return {
            "schema": 1,
            "expected": expected,
            "seen": self.testsRun,
            "omitted": self.omitted,
            "untimed": self.untimed,
            "clock_errors": self.clock_errors,
            "elapsed": elapsed,
            "complete": (
                self.omitted == 0
                and self.clock_errors == 0
                and self.testsRun == expected
                and elapsed is not None
            ),
            "modules": self.modules,
            "cases": self.rows,
        }


def write_payload(payload, path):
    """Write only bounded timing data into the caller's pre-created private file."""
    data = json.dumps(payload, separators=(",", ":"), allow_nan=False).encode("ascii")
    if len(data) > MAX_BYTES:
        raise ValueError("timing payload limit")
    descriptor = os.open(path, os.O_WRONLY | os.O_NOFOLLOW)
    with os.fdopen(descriptor, "wb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or stat.S_IMODE(info.st_mode) != 0o600
            or info.st_uid != os.getuid()
            or info.st_nlink != 1
        ):
            raise ValueError("timing payload target")
        stream.truncate(0)
        stream.write(data)


def run_suite(suite):
    """Keep the single runner, original outcomes and native early return."""
    expected = suite.countTestCases()
    started = _sample()
    result = unittest.TextTestRunner(verbosity=1, resultclass=TimingResult).run(suite)
    payload = result.payload(expected, _elapsed(started))
    status = 0 if result.wasSuccessful() else 1
    try:
        target = os.environ.get(ENVIRONMENT)
        if target is not None:
            write_payload(payload, target)
        else:
            # The Rust launcher uses the private file, never these raw captured streams.
            for module in payload["modules"]:
                sys.stderr.write(
                    "self-test timing "
                    + module["id"]
                    + " case_sum_seconds="
                    + format(module["seconds"], ".6e")
                    + "\n"
                )
        fixture_skip = any(not isinstance(test, unittest.TestCase) for test, _ in result.skipped)
        permitted_coverage = (
            payload["omitted"] == result.identity_omitted
            and payload["seen"] <= payload["expected"]
            and (payload["seen"] == payload["expected"] or fixture_skip)
            and payload["clock_errors"] == 0
            and payload["elapsed"] is not None
        )
        if not payload["complete"] and not permitted_coverage:
            raise ValueError("incomplete timing payload")
    except (OSError, ValueError, TypeError):
        sys.stderr.write("self-test timing reporting incomplete\n")
        return status or 2
    return status
