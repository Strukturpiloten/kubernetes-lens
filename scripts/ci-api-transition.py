#!/usr/bin/env python3
"""Exact Kubernetes P5/P6 compatibility into the unchanged canonical gate."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import cast

REPOSITORY = "Strukturpiloten/kubernetes-lens"
POLICY_PATH = "scripts/validation-policy.json"
P5 = "09bb7a6a9dffb8a4cb478901fcdb936fde9e6c78143161a7f66a9d1f64cb250f"
P6 = "571f587e7fa1682fc73bce768eaca2888ea54f52e95e734a977ebfcc23ae4ee7"
LEGACY_JOBS = ("rust", "msrv", "dependencies", "documentation", "lockfile-release-age")
JOBS = ("rust", "api", *LEGACY_JOBS[1:])
RAW_NEEDS = {"validation-plan", *JOBS}
SHA = re.compile(r"[a-f0-9]{40}\Z")
LIMIT = 256 * 1024


class TransitionError(ValueError):
    """Unknown or incomplete evidence cannot authorize aggregate outputs."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise TransitionError(message)


def mapping(value: object, label: str) -> dict[str, object]:
    if not isinstance(value, dict) or not all(isinstance(key, str) for key in value):
        raise TransitionError(f"{label} must be an object")
    return cast(dict[str, object], value)


def unique(pairs: list[tuple[str, object]]) -> dict[str, object]:
    result: dict[str, object] = {}
    for key, value in pairs:
        require(key not in result, "duplicate metadata key")
        result[key] = value
    return result


def metadata(text: str, label: str) -> dict[str, object]:
    require(len(text.encode()) <= LIMIT, f"{label} exceeds its byte bound")
    return mapping(json.loads(text, object_pairs_hook=unique), label)


def git(root: Path, *arguments: str) -> bytes:
    result = subprocess.run(
        ["git", "-C", str(root), *arguments], capture_output=True, check=True, timeout=10
    )
    require(len(result.stdout) <= LIMIT, "trusted policy Git output exceeds its byte bound")
    return result.stdout


def trusted_policy(config: Path, policy_sha: str) -> bool:
    require(SHA.fullmatch(policy_sha) is not None, "invalid trusted policy SHA")
    require(not config.is_symlink(), "trusted policy must be a regular tracked file")
    config = config.resolve(strict=True)
    root = config.parent.parent
    require(config == root / POLICY_PATH, "unexpected trusted policy path")
    require(
        git(root, "rev-parse", "HEAD").decode().strip() == policy_sha,
        "trusted policy checkout does not match the exact event base",
    )
    entry = git(root, "ls-tree", policy_sha, "--", POLICY_PATH).decode().strip()
    require(
        re.fullmatch(r"100644 blob [a-f0-9]{40}\t" + re.escape(POLICY_PATH), entry) is not None,
        "trusted policy is not a tracked regular blob",
    )
    size = git(root, "cat-file", "-s", f"{policy_sha}:{POLICY_PATH}").decode().strip()
    require(
        size.isdecimal() and int(size) <= LIMIT and config.stat().st_size <= LIMIT,
        "trusted policy exceeds its byte bound",
    )
    content = git(root, "show", f"{policy_sha}:{POLICY_PATH}")
    require(config.read_bytes() == content, "trusted policy working bytes differ from its Git blob")
    digest = hashlib.sha256(content).hexdigest()
    require(digest in {P5, P6}, "unknown trusted policy; coordinated review required")
    policy = metadata(content.decode(), "trusted policy")
    require(
        type(policy.get("schema")) is int and policy["schema"] == 2,
        "unsupported trusted policy schema",
    )
    require(policy.get("repository") == REPOSITORY, "trusted policy repository mismatch")
    legacy = digest == P5
    require(
        policy.get("jobs") == list(LEGACY_JOBS if legacy else JOBS),
        "trusted policy inventory mismatch",
    )
    return legacy


def joint_proof(
    plan_json: str, needs_json: str, tested: str, purpose: str, *, legacy: bool
) -> tuple[str, bool]:
    """Validate actual child outcomes before removing only the old policy's extra API row."""
    require(SHA.fullmatch(tested) is not None, "invalid tested candidate")
    require(purpose in {"development", "published"}, "unknown API purpose")
    plan = metadata(plan_json, "validation plan")
    require(
        plan.get("repository") == REPOSITORY and plan.get("tested_sha") == tested,
        "validation plan candidate/repository mismatch",
    )
    jobs = mapping(plan.get("jobs"), "plan jobs")
    require(
        set(jobs) == set(LEGACY_JOBS if legacy else JOBS)
        and all(type(value) is bool for value in jobs.values()),
        "invalid plan selections",
    )
    require(legacy or jobs["api"] == jobs["rust"], "API and quality selections must agree")
    needs = metadata(needs_json, "raw needs")
    require(set(needs) == RAW_NEEDS, "raw aggregate must contain the exact seven dependencies")
    for name, value in needs.items():
        outcome = mapping(value, f"{name} outcome")
        require(set(outcome) == {"result", "outputs"}, f"invalid {name} outcome fields")
        require(
            outcome["result"] in ("success", "failure", "cancelled", "skipped"),
            f"invalid {name} result",
        )
        outputs = mapping(outcome["outputs"], f"{name} outputs")
        require(
            all(isinstance(value, str) for value in outputs.values()),
            f"invalid {name} output types",
        )
    planning = mapping(needs["validation-plan"], "validation-plan outcome")
    require(planning["result"] == "success", "validation plan did not succeed")
    outputs = mapping(planning["outputs"], "validation-plan outputs")
    require(
        set(outputs) <= {"plan", "profile", *("select_" + job.replace("-", "_") for job in JOBS)},
        "unknown validation plan output",
    )
    require(
        outputs.get("plan") == plan_json and outputs.get("profile") == plan.get("profile"),
        "validation plan output bytes/profile mismatch",
    )
    for job, selected in jobs.items():
        require(
            outputs.get("select_" + job.replace("-", "_")) == str(selected).lower(),
            "validation plan selector mismatch",
        )
    if legacy:
        require(outputs.get("select_api", "") == "", "P5 has no independent API selector")
    selected = jobs["rust"] is True
    for name in ("rust", "api"):
        outcome = mapping(needs[name], f"{name} outcome")
        child = mapping(outcome["outputs"], f"{name} outputs")
        allowed = (
            {"candidate_sha", "published_api_candidate_sha"} if name == "api" else {"candidate_sha"}
        )
        require(set(child) <= allowed, f"unknown {name} proof output")
        if selected:
            require(outcome["result"] == "success", f"selected {name} did not succeed")
            require(child.get("candidate_sha") == tested, f"{name} candidate receipt mismatch")
        else:
            require(
                outcome["result"] == "skipped" and all(value == "" for value in child.values()),
                f"unselected {name} must be a planned skip without proof",
            )
    published = mapping(mapping(needs["api"], "api outcome")["outputs"], "api outputs").get(
        "published_api_candidate_sha", ""
    )
    if purpose == "published":
        require(selected and published == tested, "published purpose lacks actual API proof")
    else:
        require(published == "", "development cannot carry published API proof")
    if legacy:
        projected = {name: outcome for name, outcome in needs.items() if name != "api"}
        require(set(projected) == {"validation-plan", *LEGACY_JOBS}, "invalid legacy projection")
        return json.dumps(projected, separators=(",", ":")), purpose == "published"
    return needs_json, purpose == "published"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--repository-root", type=Path, required=True)
    parser.add_argument("--config", type=Path, required=True)
    for name in (
        "event",
        "base-sha",
        "head-sha",
        "tested-sha",
        "policy-sha",
        "automation-sha",
        "plan-json",
        "needs-json",
        "api-purpose",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--github-output", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        legacy = trusted_policy(args.config, args.policy_sha)
        require(
            not legacy or args.event in {"pull_request", "merge_group"},
            "P5 compatibility is only for outstanding exact PR/queue bases",
        )
        require(
            os.environ.get("GITHUB_SHA") == args.tested_sha,
            "tested candidate does not match the actual workflow SHA",
        )
        needs, published = joint_proof(
            args.plan_json, args.needs_json, args.tested_sha, args.api_purpose, legacy=legacy
        )
        command = [
            sys.executable,
            "-m",
            "boxferry_ci",
            "gate",
            "--repository-root",
            str(args.repository_root),
            "--config",
            str(args.config),
        ]
        for name in ("event", "base_sha", "head_sha", "tested_sha", "policy_sha", "automation_sha"):
            command.extend(["--" + name.replace("_", "-"), getattr(args, name)])
        command.extend(["--plan-json", args.plan_json, "--needs-json", needs])
        subprocess.run(command, check=True, timeout=240)
        # Canonical gate independently recomputes the original exact-candidate plan.
        result = f"candidate_sha={args.tested_sha}\n"
        if published:
            result += f"published_api_candidate_sha={args.tested_sha}\n"
        with args.github_output.open("a", encoding="utf-8") as stream:
            stream.write(result)
        return 0
    except (TransitionError, json.JSONDecodeError) as error:
        print(f"API transition refused: {error}", file=sys.stderr)
        return 1
    except (OSError, subprocess.SubprocessError) as error:
        print(
            f"API transition acquisition/validation failed: {type(error).__name__}", file=sys.stderr
        )
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
