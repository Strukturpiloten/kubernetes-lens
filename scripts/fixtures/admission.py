#!/usr/bin/env python3
"""Check frozen source-derived admission expectations; execute no producer/native API.

These checks prevent a fixture plan from treating producer version conditions or
feature-gate defaults as field admission. Their outputs remain pending evidence.
"""

import json

from materialize import OFFICIAL, REPOSITORY, kustomize_closure, load_inventory, require, validate_inventory

STATUS = "source-reviewed-renderer-admission-native-pending"
POINTER = "/spec/template/spec/hostUsers"
PRESERVATION = "preserve-source-with-findings"


def validate_admission_expectations(inventory, expectations, ledger):
    """Verify authored expectations against independent frozen source/field policies."""
    files = validate_inventory(inventory)
    plan = expectations["renderer_admission"]
    require(plan["status"] == STATUS, "invalid-admission-evidence-state")
    entries = [entry for entry in inventory["renderer_entrypoints"] if entry["tool"] == "Kustomize"]
    closures = plan["kustomize_closures"]
    require(len(closures) == len(entries), "incomplete-admission-closures")
    unmatched = list(entries)
    for closure in closures:
        matches = [entry for entry in unmatched if entry["supplied_root"] == closure["supplied_root"]
                   and entry["relative_entrypoint"] == closure["relative_entrypoint"]]
        require(len(matches) == 1, "wrong-admission-root")
        entry = matches[0]
        unmatched.remove(entry)
        actual = kustomize_closure(inventory, entry, files)
        require(all(closure[key] == actual[key] for key in actual), "wrong-admission-closure")
        require(closure["load_restrictions"] == "default-root-only", "unadmitted-load-restrictions")
        require(closure["evidence_status"] == "static-local-closure-renderer-native-api-pending",
                "invalid-admission-evidence-state")
    host = plan["grafana_operator_host_users"]
    pod_spec = ledger["typed_struct_inventory"]["io.k8s.api.core.v1.PodSpec"]
    require("hostUsers" not in pod_spec["proposed_admitted_members"]
            and "hostUsers" in pod_spec["schema_supported_but_unadmitted_members"], "changed-host-users-admission")
    require(host["typed_admission"] == "frozen-unadmitted"
            and host["default_desired_output_policy"] == "deny-unadmitted", "implicit-host-users-admission")
    require(host["preservation_policy"]["id"] == PRESERVATION
            and host["preservation_policy"]["selection"] == "explicit-caller-selection-required",
            "implicit-host-users-preservation")
    require(host["field_pointer"] == POINTER and host["source_condition"] == ">=1.33-0",
            "wrong-host-users-source-condition")
    source = host["source_member"]
    archive = next((asset for asset in inventory["assets"] if asset["id"] == host["archive_id"]), None)
    require(archive is not None and any(all(member.get(key) == value for key, value in source.items())
            for member in archive.get("extracted_files", [])), "wrong-host-users-source-witness")
    require(set(source) == {"path", "bytes", "sha256"} and host["source_lines_one_based_inclusive"] == [40, 42],
            "wrong-host-users-source-witness")
    diagnostic = host["diagnostic"]
    require(set(ledger["diagnostics"]["required_fields"]) <= set(diagnostic)
            and diagnostic["code"] == "unadmitted-field" and diagnostic["severity"] == "error"
            and diagnostic["field_pointer"] == POINTER and diagnostic["actionable_remediation"],
            "incomplete-host-users-diagnostic")
    require(host["gate"] == "UserNamespacesSupport" and host["pending"], "incomplete-host-users-expectations")
    gate = next(record for record in ledger["feature_gate_sources"] if record["gate"] == host["gate"])
    seen = set()
    for case in host["cases"]:
        minor_text = case["kubernetes_minor"]
        require(minor_text in ledger["target_profile_contract"]["kubernetes_minors"], "invalid-case-target")
        minor = int(minor_text.split(".")[1])
        require(case["target_patch"] == minor_text + ".0", "invalid-case-target")
        setting = case["gate_setting"]
        require(setting in ledger["target_profile_contract"]["setting_values"] and type(case["value"]) is bool,
                "invalid-case-profile")
        key = (minor_text, setting, case["value"])
        require(key not in seen, "duplicate-host-users-case")
        seen.add(key)
        stages = [stage for stage in gate["documented_stages"]
                  if int(stage["fromVersion"].split(".")[1]) <= minor
                  <= int(stage.get("toVersion", "1.37").split(".")[1])]
        require(len(stages) == 1, "missing-host-users-gate-source")
        stage = stages[0]
        require(host["gate_documented_defaults"][minor_text] is stage["defaultValue"], "wrong-gate-default-expectation")
        valid = setting == "documented-default" or stage["stage"] != "stable"
        present = minor >= 33
        require(case["source_condition_expectation"] == ("emitted" if present else "omitted")
                and case["evidence_status"] == "source-reviewed-unexecuted", "wrong-host-users-source-expectation")
        expected = case["expected"]
        require(expected["typed_admitted"] is False and expected["profile_valid"] is valid,
                "implicit-host-users-admission")
        require(expected["diagnostic_code"] == ("invalid-target-profile" if not valid else
                "unadmitted-field" if present else None), "wrong-host-users-diagnostic")
        require(expected["desired_output"] == ("denied" if not valid or present else "not-blocked-by-this-field"),
                "implicit-host-users-desired-output")
        require(expected["source_preserving_output"] == ("denied" if not valid else
                "explicit-preserve-source-with-findings-required" if present else "not-required-for-this-field"),
                "implicit-host-users-preservation")
    required = {(minor, setting, value) for minor in host["gate_documented_defaults"]
                for setting in ledger["target_profile_contract"]["setting_values"] for value in (True, False)}
    require(seen == required, "incomplete-host-users-cases")
    require({"1.32", "1.33", "1.34", "1.35", "1.36", "1.37"} <= set(host["gate_documented_defaults"]),
            "missing-host-users-boundary")
    return {"status": STATUS, "kustomize_closures": len(closures), "host_users_expectation_cases": len(seen)}


def main():
    """Trusted repository-only expectation check; success never means native admission."""
    expectations = json.loads((OFFICIAL / "expected.json").read_text())
    ledger = json.loads((REPOSITORY / "schemas/capabilities/kubernetes-1.20-1.37.json").read_text())
    print(json.dumps(validate_admission_expectations(load_inventory(), expectations, ledger), sort_keys=True))


if __name__ == "__main__":
    main()
