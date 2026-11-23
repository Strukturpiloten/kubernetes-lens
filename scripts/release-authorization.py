#!/usr/bin/env python3
"""Refuse publication when the externally managed release review gate is absent."""

from __future__ import annotations

import json
import os
from urllib.request import Request, urlopen


def verify(environment: dict, branch: dict, policies: dict, default_branch: str) -> None:
    rules = environment.get("protection_rules", [])
    review = [rule for rule in rules if rule.get("type") == "required_reviewers"]
    if environment.get("name") != "release" or len(review) != 1 or not review[0].get("reviewers"):
        raise ValueError("release requires an existing required-reviewer environment")
    selection = environment.get("deployment_branch_policy")
    if selection == {"protected_branches": True, "custom_branch_policies": False}:
        if branch.get("protected") is True:
            return
    elif selection == {"protected_branches": False, "custom_branch_policies": True}:
        if any(
            policy.get("name") == default_branch and policy.get("type") == "branch"
            for policy in policies.get("branch_policies", [])
        ):
            return
    raise ValueError("release environment must admit the canonical default branch")


def main() -> None:
    repository = "Strukturpiloten/kubernetes-lens"
    branch = os.environ["DEFAULT_BRANCH"]
    if (
        os.environ.get("GITHUB_REPOSITORY") != repository
        or os.environ.get("GITHUB_EVENT_NAME") != "workflow_dispatch"
        or os.environ.get("GITHUB_REF") != f"refs/heads/{branch}"
    ):
        raise ValueError("publication authorization requires the canonical default branch dispatch")

    def read(path: str) -> dict:
        request = Request(
            f"https://api.github.com/repos/{repository}/{path}",
            headers={
                "Authorization": f"Bearer {os.environ['GH_TOKEN']}",
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2026-03-10",
            },
        )
        with urlopen(request, timeout=30) as response:
            if response.geturl() != request.full_url:
                raise ValueError("unexpected authorization response redirect")
            return json.load(response)

    from urllib.parse import quote

    environment = read("environments/release")
    selection = environment.get("deployment_branch_policy") or {}
    policies = (
        read("environments/release/deployment-branch-policies")
        if selection.get("custom_branch_policies")
        else {}
    )
    verify(environment, read(f"branches/{quote(branch, safe='')}"), policies, branch)


if __name__ == "__main__":
    main()
