//! Original selected disruption, quota, priority, runtime and historical policy checks.
use super::validation::{enumeration, integer, invalid, nodes, number, present, require, sequence, text, unadmitted};
use crate::{
    capability::{FeatureGateId, FeatureGateState, TargetProfile},
    diagnostic::FieldPath,
    syntax::{TreeNode, TreeValue},
    value::{IntOrPercent, dns_label, dns_subdomain, label_key, label_value},
};
use std::collections::BTreeSet;

pub(super) fn namespace(tree: &TreeNode, minor: u8, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["metadata".into(), "labels".into()]);
    let Some(labels) = tree.get_path(&path).and_then(TreeNode::as_mapping) else {
        return;
    };
    for (key, value) in labels {
        if out.exhausted() {
            return;
        }
        let leaf = path.child(key);
        if !label_key(key) || !value.as_str().is_some_and(label_value) {
            invalid(&leaf, out);
        }
        let Some(suffix) = key.strip_prefix("pod-security.kubernetes.io/") else {
            continue;
        };
        if ["enforce", "audit", "warn"].contains(&suffix) {
            if !value
                .as_str()
                .is_some_and(|value| ["privileged", "baseline", "restricted"].contains(&value))
            {
                invalid(&leaf, out);
            }
        } else if ["enforce-version", "audit-version", "warn-version"].contains(&suffix) {
            let known = value.as_str().is_some_and(|value| {
                value == "latest"
                    || value
                        .strip_prefix("v1.")
                        .and_then(|minor| minor.parse::<u8>().ok())
                        .is_some_and(|minor| (20..=37).contains(&minor))
            });
            if !known {
                unadmitted(&leaf, out);
            }
        } else {
            unadmitted(&leaf, out);
        }
        if minor < 25 {
            unadmitted(&leaf, out);
        }
    }
}
fn budget(node: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    if node.value == TreeValue::Null {
        return;
    }
    let valid = if let Some(value) = integer(node) {
        (0..=i64::from(i32::MAX)).contains(&value)
    } else {
        node.as_str()
            .is_some_and(|value| IntOrPercent::parse_percent(value).is_ok())
    };
    if !valid {
        invalid(path, out);
    }
}
pub(super) fn disruption(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["spec".into()]);
    let Some(spec) = tree.get("spec") else { return };
    if present(spec, "minAvailable") && present(spec, "maxUnavailable") {
        invalid(&path, out);
    }
    // Omitting both budgets is legal; do not invent a default or coalesce absence/null with zero.
    for key in ["minAvailable", "maxUnavailable"] {
        if out.exhausted() {
            return;
        }
        if let Some(value) = spec.get(key) {
            budget(value, &path.child(key), out);
        }
    }
    if let Some(selector) = spec.get("selector").filter(|node| node.value != TreeValue::Null) {
        super::validation::selector(selector, &path.child("selector"), out);
    }
    enumeration(
        spec,
        "unhealthyPodEvictionPolicy",
        &["IfHealthyBudget", "AlwaysAllow"],
        &path,
        out,
    );
}
fn overhead(node: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    let Some(entries) = node.as_mapping() else {
        return;
    };
    for (name, node) in entries {
        if !out.charge(name.len().saturating_mul(6).saturating_add(20)) {
            return;
        }
        let leaf = match crate::resources::common::child_path(path, name, out.fields()) {
            Ok(path) => path,
            Err(finding) => {
                out.push(finding);
                return;
            }
        };
        if !super::resource_names::container(name) {
            invalid(&leaf, out);
        }
        let Some(value) = super::quantity_rules::quantity(node, &leaf, out) else {
            if out.exhausted() {
                return;
            }
            continue;
        };
        if value.exact().is_negative() {
            invalid(&leaf, out);
        } else if super::resource_names::integer(name) {
            if !out.charge(40) {
                return;
            }
            if !value.conservative_milli() {
                unadmitted(&leaf, out);
            } else if value.exact().scale() > 0 {
                invalid(&leaf, out);
            }
        }
        // Hugepage size/divisibility and companion-resource admission remain outside this arithmetic profile.
        if name.starts_with("hugepages-") {
            unadmitted(&leaf, out);
        }
    }
}
fn quota_values(node: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    let Some(entries) = node.as_mapping() else {
        return;
    };
    for (name, node) in entries {
        if !out.charge(name.len().saturating_mul(6).saturating_add(20)) {
            return;
        }
        let leaf = match crate::resources::common::child_path(path, name, out.fields()) {
            Ok(path) => path,
            Err(finding) => {
                out.push(finding);
                return;
            }
        };
        if !super::resource_names::quota(name) {
            invalid(&leaf, out);
        }
        let Some(value) = super::quantity_rules::quantity(node, &leaf, out) else {
            if out.exhausted() {
                return;
            }
            continue;
        };
        if value.exact().is_negative() {
            invalid(&leaf, out);
        }
        if super::resource_names::integer(name) && !value.exact().is_negative() {
            if !out.charge(40) {
                return;
            }
            if !value.conservative_milli() {
                unadmitted(&leaf, out);
            } else if value.exact().scale() > 0 {
                invalid(&leaf, out);
            }
        }
    }
}
fn scope_available(
    name: &str,
    target: &TargetProfile,
    path: &FieldPath,
    out: &mut dyn super::validation::AccessSink,
) -> bool {
    if !out.charge(name.len().saturating_add(1)) {
        return false;
    }
    let minor = target.kubernetes.minor();
    let known = matches!(
        name,
        "Terminating" | "NotTerminating" | "BestEffort" | "NotBestEffort" | "PriorityClass"
    ) || name == "CrossNamespacePodAffinity" && minor >= 21
        || name == "VolumeAttributesClass" && minor >= 33;
    if !known {
        invalid(path, out);
        return false;
    }
    if name == "CrossNamespacePodAffinity" && minor < 24 {
        match target
            .feature_gates
            .resolve(FeatureGateId::PodAffinityNamespaceSelector, target.kubernetes)
        {
            Ok(FeatureGateState::Enabled) => {}
            Ok(_) => {
                out.push(
                    crate::Finding::error(
                        crate::FindingCode::FeatureGateRequired,
                        crate::diagnostic::Phase::Validation,
                    )
                    .at_path(path.clone()),
                );
                return false;
            }
            Err(finding) => {
                out.push(finding);
                return false;
            }
        }
    }
    true
}
fn scope_resources(spec: &TreeNode, scope: &str, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    let Some(entries) = spec.get("hard").and_then(TreeNode::as_mapping) else {
        return;
    };
    for (name, _) in entries {
        if !out.charge(name.len().saturating_add(20)) {
            return;
        }
        let standard = super::resource_names::standard_quota(name);
        if !standard {
            continue;
        }
        let allowed = if scope == "VolumeAttributesClass" {
            matches!(name.as_str(), "persistentvolumeclaims" | "requests.storage")
        } else if scope == "BestEffort" {
            name == "pods"
        } else {
            matches!(
                name.as_str(),
                "pods" | "cpu" | "memory" | "requests.cpu" | "requests.memory" | "limits.cpu" | "limits.memory"
            )
        };
        if !allowed {
            invalid(path, out);
        }
    }
}
fn conflict_bit(name: &str) -> u8 {
    match name {
        "BestEffort" => 1,
        "NotBestEffort" => 2,
        "Terminating" => 4,
        "NotTerminating" => 8,
        _ => 0,
    }
}
fn conflicting(bits: u8) -> bool {
    bits & 0b0011 == 0b0011 || bits & 0b1100 == 0b1100
}
fn scope_requirement(
    node: &TreeNode,
    target: &TargetProfile,
    path: &FieldPath,
    out: &mut dyn super::validation::AccessSink,
) -> bool {
    if !out.admit_tree(node) || out.exhausted() {
        return false;
    }
    let Some(name) = text(node, "scopeName") else {
        invalid(&path.child("scopeName"), out);
        return false;
    };
    if !scope_available(name, target, &path.child("scopeName"), out) {
        return false;
    }
    let op = text(node, "operator");
    let count = sequence(node, "values").len();
    let keyed = matches!(name, "PriorityClass" | "VolumeAttributesClass");
    if keyed {
        if !matches!(op, Some("In" | "NotIn" | "Exists" | "DoesNotExist")) {
            invalid(&path.child("operator"), out);
        }
        if matches!(op, Some("In" | "NotIn")) && count == 0
            || matches!(op, Some("Exists" | "DoesNotExist")) && count != 0
        {
            invalid(&path.child("values"), out);
        }
    } else {
        if op != Some("Exists") {
            invalid(&path.child("operator"), out);
        }
        if count != 0 {
            invalid(&path.child("values"), out);
        }
    }
    // Population, observed usage and enforcement remain external controller prerequisites.
    true
}
pub(super) fn quota(tree: &TreeNode, target: &TargetProfile, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) || out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["spec".into()]);
    let Some(spec) = tree.get("spec") else { return };
    if let Some(hard) = spec.get("hard") {
        quota_values(hard, &path.child("hard"), out);
    }
    let mut direct = 0;
    for (leaf, value) in nodes(tree, "/spec/scopes/*", out.fields()) {
        if out.exhausted() {
            return;
        }
        let Some(name) = value.as_str() else {
            invalid(&leaf, out);
            continue;
        };
        if scope_available(name, target, &leaf, out) {
            direct |= conflict_bit(name);
            scope_resources(spec, name, &leaf, out);
        }
    }
    if conflicting(direct) {
        invalid(&path.child("scopes"), out);
    }
    let mut selector = 0;
    for (leaf, value) in nodes(tree, "/spec/scopeSelector/matchExpressions/*", out.fields()) {
        if out.exhausted() {
            return;
        }
        if scope_requirement(value, target, &leaf, out) {
            if let Some(name) = text(value, "scopeName") {
                selector |= conflict_bit(name);
                scope_resources(spec, name, &leaf, out);
            }
        }
    }
    if conflicting(selector) {
        invalid(&path.child("scopeSelector"), out);
    }
}
pub(super) fn limits(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["spec".into(), "limits".into()]);
    let mut seen = BTreeSet::new();
    let mut seen_bytes = 0_usize;
    for (leaf, item) in nodes(tree, "/spec/limits/*", out.fields()) {
        if out.exhausted() {
            return;
        }
        if let Some(kind) = text(item, "type") {
            if !out.charge(
                kind.len()
                    .saturating_add(seen_bytes)
                    .saturating_add(1)
                    .saturating_mul(seen.len().saturating_add(1)),
            ) {
                return;
            }
            if let Err(finding) = out
                .fields()
                .processing
                .payload_array::<String>(1, out.fields().phase)
                .and_then(|()| out.fields().processing.payload(kind.len(), out.fields().phase))
            {
                out.push(finding);
                return;
            }
            if !matches!(kind, "Pod" | "Container" | "PersistentVolumeClaim") {
                if kind.contains('/') && label_key(kind) {
                    unadmitted(&leaf.child("type"), out);
                } else {
                    invalid(&leaf.child("type"), out);
                }
            }
            if !seen.insert(kind.to_owned()) {
                invalid(&leaf.child("type"), out);
            }
            seen_bytes = seen_bytes.saturating_add(kind.len());
        } else {
            invalid(&leaf.child("type"), out);
        }
        for key in ["min", "max", "default", "defaultRequest", "maxLimitRequestRatio"] {
            if out.exhausted() {
                return;
            }
            if let Some(values) = item.get(key) {
                super::quantity_rules::values(
                    values,
                    matches!(text(item, "type"), Some("Pod" | "Container")),
                    &leaf.child(key),
                    out,
                );
            }
        }
        super::quantity_rules::relationships(item, &leaf, out);
    }
    if tree
        .get_path(&path)
        .and_then(TreeNode::as_sequence)
        .is_some_and(<[TreeNode]>::is_empty)
    {
        invalid(&path, out);
    }
}
pub(super) fn priority(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath::default();
    require(tree, "value", &path, out);
    let name = tree.get("metadata").and_then(|meta| text(meta, "name"));
    let value = tree.get("value").and_then(integer);
    let reserved = match name {
        Some("system-node-critical") => Some(2_000_001_000),
        Some("system-cluster-critical") => Some(2_000_000_000),
        _ => None,
    };
    if let Some(expected) = reserved {
        if value != Some(expected)
            || tree
                .get("globalDefault")
                .is_some_and(|value| value.value == TreeValue::Bool(true))
        {
            invalid(&path.child("value"), out);
        }
    } else if name.is_some_and(|name| name.starts_with("system-")) || value.is_some_and(|value| value > 1_000_000_000) {
        invalid(&path.child("value"), out);
    }
    enumeration(tree, "preemptionPolicy", &["Never", "PreemptLowerPriority"], &path, out);
}
fn toleration(node: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    enumeration(node, "operator", &["", "Equal", "Exists"], path, out);
    enumeration(
        node,
        "effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
        path,
        out,
    );
    if text(node, "operator") == Some("Exists") && text(node, "value").is_some_and(|value| !value.is_empty()) {
        invalid(&path.child("value"), out);
    }
    if text(node, "key").is_none_or(str::is_empty) && text(node, "operator") != Some("Exists") {
        invalid(&path.child("key"), out);
    }
    if text(node, "key").is_some_and(|key| !key.is_empty() && !label_key(key)) {
        invalid(&path.child("key"), out);
    }
    if text(node, "value").is_some_and(|value| !label_value(value)) {
        invalid(&path.child("value"), out);
    }
    if present(node, "tolerationSeconds") && text(node, "effect") != Some("NoExecute") {
        invalid(&path.child("tolerationSeconds"), out);
    }
}
pub(super) fn runtime(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath::default();
    if !text(tree, "handler").is_some_and(dns_label) {
        invalid(&path.child("handler"), out);
    }
    for (leaf, map) in nodes(tree, "/overhead/podFixed", out.fields()) {
        if out.exhausted() {
            return;
        }
        overhead(map, &leaf, out);
    }
    for (leaf, map) in nodes(tree, "/scheduling/nodeSelector", out.fields()) {
        if out.exhausted() {
            return;
        }
        if let Some(entries) = map.as_mapping() {
            for (key, value) in entries {
                if out.exhausted() {
                    return;
                }
                if !label_key(key) || !value.as_str().is_some_and(label_value) {
                    invalid(&leaf.child(key), out);
                }
            }
        }
    }
    for (leaf, value) in nodes(tree, "/scheduling/tolerations/*", out.fields()) {
        if out.exhausted() {
            return;
        }
        toleration(value, &leaf, out);
    }
    if let Some(scheduling) = tree.get("scheduling") {
        for (index, value) in sequence(scheduling, "tolerations").iter().enumerate() {
            for previous in &sequence(scheduling, "tolerations")[..index] {
                let mut equal = true;
                for key in ["key", "operator", "value", "effect"] {
                    let left = text(value, key).unwrap_or_default();
                    let right = text(previous, key).unwrap_or_default();
                    if !out.charge(left.len().saturating_add(right.len()).saturating_add(1)) {
                        return;
                    }
                    equal &= left == right;
                }
                // Native uniqueness uses stored operator spelling, and ignores tolerationSeconds.
                if equal {
                    invalid(
                        &path.child("scheduling").child("tolerations").child(index.to_string()),
                        out,
                    );
                }
            }
        }
    }
}
fn strategy(node: &TreeNode, values: &[&str], path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    require(node, "rule", path, out);
    enumeration(node, "rule", values, path, out);
    for (index, range) in sequence(node, "ranges").iter().enumerate() {
        if out.exhausted() {
            return;
        }
        let range_path = path.child("ranges").child(index.to_string());
        number(range, "min", 0, i64::MAX, &range_path, out);
        number(range, "max", 0, i64::MAX, &range_path, out);
        if range
            .get("min")
            .and_then(integer)
            .zip(range.get("max").and_then(integer))
            .is_some_and(|(min, max)| min > max)
        {
            invalid(&range_path, out);
        }
    }
}
fn capability_conflicts(spec: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(spec) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let drops = sequence(spec, "requiredDropCapabilities");
    if !drops.is_empty()
        && sequence(spec, "allowedCapabilities")
            .iter()
            .any(|value| value.as_str() == Some("*"))
    {
        invalid(&path.child("requiredDropCapabilities"), out);
    }
    // Capability spelling is opaque: literal equality alone establishes a conflict.
    for key in ["defaultAddCapabilities", "allowedCapabilities"] {
        if out.exhausted() {
            return;
        }
        for (index, value) in sequence(spec, key).iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let mut conflict = false;
            if let Some(name) = value.as_str() {
                for drop in drops {
                    if !out.charge(
                        name.len()
                            .saturating_add(drop.as_str().map_or(0, str::len))
                            .saturating_add(1),
                    ) {
                        return;
                    }
                    if drop.as_str() == Some(name) {
                        conflict = true;
                        break;
                    }
                }
            }
            if conflict {
                invalid(&path.child(key).child(index.to_string()), out);
            }
        }
    }
}
fn security_lists(spec: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(spec) {
        return;
    }
    if out.exhausted() {
        return;
    }
    for (index, port) in sequence(spec, "hostPorts").iter().enumerate() {
        if out.exhausted() {
            return;
        }
        let leaf = path.child("hostPorts").child(index.to_string());
        number(port, "min", 0, 65535, &leaf, out);
        number(port, "max", 0, 65535, &leaf, out);
        if port
            .get("min")
            .and_then(integer)
            .zip(port.get("max").and_then(integer))
            .is_some_and(|(min, max)| min > max)
        {
            invalid(&leaf, out);
        }
    }
    for (index, prefix) in sequence(spec, "allowedHostPaths").iter().enumerate() {
        if out.exhausted() {
            return;
        }
        if !text(prefix, "pathPrefix")
            .is_some_and(|value| !value.is_empty() && !value.split('/').any(|part| part == ".."))
        {
            invalid(
                &path
                    .child("allowedHostPaths")
                    .child(index.to_string())
                    .child("pathPrefix"),
                out,
            );
        }
    }
    for key in [
        "volumes",
        "allowedUnsafeSysctls",
        "forbiddenSysctls",
        "allowedProcMountTypes",
    ] {
        // The selected strings survive; native restriction/equivalence beyond reviewed helper rules remains explicit.
        if !sequence(spec, key).is_empty() {
            unadmitted(&path.child(key), out);
        }
    }
}
pub(super) fn security(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["spec".into()]);
    require(tree, "spec", &FieldPath::default(), out);
    let Some(spec) = tree.get("spec") else { return };
    if let Some(value) = spec.get("runAsUser") {
        strategy(
            value,
            &["MustRunAs", "MustRunAsNonRoot", "RunAsAny"],
            &path.child("runAsUser"),
            out,
        );
    }
    if present(spec, "runAsGroup") {
        if let Some(value) = spec.get("runAsGroup") {
            let leaf = path.child("runAsGroup");
            strategy(value, &["MustRunAs", "MayRunAs", "RunAsAny"], &leaf, out);
            let ranges_empty = sequence(value, "ranges").is_empty();
            if (text(value, "rule") == Some("RunAsAny") && !ranges_empty)
                || (matches!(text(value, "rule"), Some("MustRunAs" | "MayRunAs")) && ranges_empty)
            {
                invalid(&leaf.child("ranges"), out);
            }
        }
    }
    for key in ["fsGroup", "supplementalGroups"] {
        if out.exhausted() {
            return;
        }
        if let Some(value) = spec.get(key) {
            strategy(value, &["MustRunAs", "MayRunAs", "RunAsAny"], &path.child(key), out);
        }
    }
    if let Some(value) = spec.get("seLinux") {
        require(value, "rule", &path.child("seLinux"), out);
        enumeration(value, "rule", &["MustRunAs", "RunAsAny"], &path.child("seLinux"), out);
    }
    capability_conflicts(spec, &path, out);
    if spec
        .get("defaultAllowPrivilegeEscalation")
        .is_some_and(|value| value.value == TreeValue::Bool(true))
        && spec
            .get("allowPrivilegeEscalation")
            .is_some_and(|value| value.value == TreeValue::Bool(false))
    {
        invalid(&path.child("defaultAllowPrivilegeEscalation"), out);
    }
    security_drivers_and_runtime(spec, &path, out);
    security_lists(spec, &path, out);
}

fn security_drivers_and_runtime(spec: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    for (index, volume) in sequence(spec, "allowedFlexVolumes").iter().enumerate() {
        if text(volume, "driver").is_none_or(str::is_empty) {
            invalid(
                &path
                    .child("allowedFlexVolumes")
                    .child(index.to_string())
                    .child("driver"),
                out,
            );
        }
    }
    for (index, volume) in sequence(spec, "allowedCSIDrivers").iter().enumerate() {
        let leaf = path.child("allowedCSIDrivers").child(index.to_string()).child("name");
        let Some(name) = text(volume, "name") else {
            invalid(&leaf, out);
            continue;
        };
        if !out.charge(name.len().saturating_add(1)) {
            return;
        }
        if let Err(finding) = out.fields().processing.payload(name.len(), out.fields().phase) {
            out.push(finding);
            return;
        }
        if name.len() > 63 || !dns_subdomain(&name.to_ascii_lowercase()) {
            invalid(&leaf, out);
        }
    }
    if let Some(runtime) = spec.get("runtimeClass") {
        let leaf = path.child("runtimeClass");
        let names = sequence(runtime, "allowedRuntimeClassNames");
        for (index, value) in names.iter().enumerate() {
            let Some(name) = value.as_str() else {
                continue;
            };
            if !out.charge(name.len().saturating_add(1)) {
                return;
            }
            if (name != "*" && !dns_subdomain(name)) || (name == "*" && names.len() != 1) {
                invalid(&leaf.child("allowedRuntimeClassNames").child(index.to_string()), out);
            }
            for previous in &names[..index] {
                let other = previous.as_str().unwrap_or_default();
                if !out.charge(name.len().saturating_add(other.len()).saturating_add(1)) {
                    return;
                }
                if name == other {
                    invalid(&leaf.child("allowedRuntimeClassNames").child(index.to_string()), out);
                }
            }
        }
        if let Some(name) = text(runtime, "defaultRuntimeClassName") {
            if !out.charge(name.len().saturating_add(1)) {
                return;
            }
            if !dns_subdomain(name) || name == "*" {
                invalid(&leaf.child("defaultRuntimeClassName"), out);
            }
            let mut admitted = false;
            for value in names {
                let allowed = value.as_str().unwrap_or_default();
                if !out.charge(name.len().saturating_add(allowed.len()).saturating_add(1)) {
                    return;
                }
                admitted |= allowed == name || allowed == "*";
            }
            if !admitted {
                invalid(&leaf.child("defaultRuntimeClassName"), out);
            }
        }
    }
}
