#!/usr/bin/env python3
"""Build the credential-free release archive and bind its checksum to API/source proof."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import tomllib
from pathlib import Path


def main() -> None:
    candidate = os.environ["CANDIDATE_SHA"]
    automation = os.environ["AUTOMATION_SHA"]
    published_api = os.environ["PUBLISHED_API_SHA"]
    if not all(re.fullmatch(r"[a-f0-9]{40}", sha) for sha in (candidate, automation)):
        raise ValueError("source identities must be full commit SHAs")
    if published_api != candidate:
        raise ValueError("missing exact published-purpose API receipt")
    head = subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip()
    if head != candidate:
        raise ValueError("held source does not match the candidate")
    manifest = tomllib.loads(Path("Cargo.toml").read_text())["package"]
    version = manifest["version"]
    crate = f"target/package/kubernetes-lens-{version}.crate"
    subprocess.run(["python", "-m", "boxferry_ci.package_crate", crate], check=True)
    digest = hashlib.sha256(Path(crate).read_bytes()).hexdigest()
    proof = {
        "schema": 1,
        "repository": "Strukturpiloten/kubernetes-lens",
        "candidate_sha": candidate,
        "published_api_candidate_sha": published_api,
        "automation_sha": automation,
        "package": "kubernetes-lens",
        "version": version,
        "archive": crate,
        "sha256": digest,
        "native_conformance": "pending; see issue #15 and the compatibility ledger",
        "publication": "not performed by package preparation",
    }
    Path("target/package/release-proof.json").write_text(json.dumps(proof, indent=2) + "\n")


if __name__ == "__main__":
    main()
