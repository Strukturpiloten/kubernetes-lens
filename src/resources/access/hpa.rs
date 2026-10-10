//! Versioned desired HPA metric unions and behavior; identity is never a scale predicate.
use super::validation::{enumeration, integer, invalid, number, present, require, sequence, text, unadmitted};
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    generation::NativeValidationIntent,
    registry::ValidationContext,
    syntax::{TreeNode, TreeValue},
    value::{Quantity, dns_label},
};

pub(super) fn quantity(node: &TreeNode, positive: bool, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let value = match node.as_str().map(|value| Quantity::parse_in(value, out.fields())) {
        Some(Ok(value)) => Some(value),
        Some(Err(finding)) if finding.code == FindingCode::LimitExceeded => {
            out.push(finding);
            return;
        }
        _ => None,
    };
    if !value.is_some_and(|value| !value.exact().is_negative() && (!positive || !value.exact().is_zero())) {
        invalid(path, out);
    }
}
fn target(node: &TreeNode, source: &str, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    require(node, "type", path, out);
    if !matches!(text(node, "type"), Some("Utilization" | "Value" | "AverageValue")) {
        invalid(&path.child("type"), out);
        return;
    }
    let count = |keys: &[&str]| keys.iter().filter(|key| present(node, key)).count();
    let valid = match source {
        "Object" => count(&["value", "averageValue"]) >= 1,
        "External" => count(&["value", "averageValue"]) == 1,
        "Pods" => present(node, "averageValue"),
        "Resource" | "ContainerResource" => count(&["averageUtilization", "averageValue"]) == 1,
        _ => false,
    };
    if !valid {
        invalid(path, out);
    }
    number(node, "averageUtilization", 1, i64::from(i32::MAX), path, out);
    for key in ["value", "averageValue"] {
        if out.exhausted() {
            return;
        }
        if let Some(value) = node.get(key).filter(|value| value.value != TreeValue::Null) {
            quantity(value, true, &path.child(key), out);
        }
    }
}
fn beta_source(node: &TreeNode, source: &str, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let keys = match source {
        "Pods" => &["targetAverageValue"][..],
        "Object" => &["targetValue", "averageValue"][..],
        "External" => &["targetValue", "targetAverageValue"][..],
        _ => &["targetAverageUtilization", "targetAverageValue"][..],
    };
    if source == "Object" {
        require(node, "targetValue", path, out);
    } else if keys.iter().filter(|key| present(node, key)).count() != 1 {
        invalid(path, out);
    }
    for key in keys {
        if out.exhausted() {
            return;
        }
        if let Some(value) = node.get(key).filter(|node| node.value != TreeValue::Null) {
            if key.ends_with("Utilization") {
                number(node, key, 1, i64::from(i32::MAX), path, out);
            } else {
                quantity(value, true, &path.child(*key), out);
            }
        }
    }
}
fn named_path(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if out.exhausted() {
        return;
    }
    let Some(name) = text(node, key) else {
        invalid(&path.child(key), out);
        return;
    };
    if !out.charge(name.len().saturating_mul(3).saturating_add(1)) {
        return;
    }
    if name.is_empty() || matches!(name, "." | "..") || name.contains(['/', '%']) {
        invalid(&path.child(key), out);
    }
}
fn reference(
    node: &TreeNode,
    context: &ValidationContext<'_>,
    allow_core: bool,
    path: &FieldPath,
    out: &mut dyn super::validation::AccessSink,
) {
    if !out.admit_tree(node) {
        return;
    }
    for key in ["kind", "name"] {
        named_path(node, key, path, out);
    }
    if out.exhausted() || context.target.kubernetes.minor() < 34 {
        return;
    }
    let api = text(node, "apiVersion").unwrap_or_default();
    if !out.charge(api.len().saturating_add(1)) {
        return;
    }
    let grouped = api.split_once('/').is_some_and(|(group, _)| !group.is_empty());
    if api.split('/').count() > 2 || !allow_core && !grouped {
        let leaf = path.child("apiVersion");
        if context.intent == NativeValidationIntent::Create {
            invalid(&leaf, out);
        } else {
            out.push(Finding::warning(FindingCode::NativeContextRequired, Phase::Validation).at_path(leaf));
        }
    }
}
fn metric_identity(
    body: &TreeNode,
    selected: &str,
    api: &str,
    context: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn super::validation::AccessSink,
) {
    if !out.admit_tree(body) {
        return;
    }
    match selected {
        "resource" | "containerResource" => {
            if text(body, "name").is_none_or(str::is_empty) {
                invalid(&path.child("name"), out);
            }
            if selected == "containerResource" {
                if !text(body, "container").is_some_and(dns_label) {
                    invalid(&path.child("container"), out);
                }
                if let Some(name) = text(body, "name") {
                    if !out.charge(name.len().saturating_mul(5).saturating_add(20)) {
                        return;
                    }
                    if !super::resource_names::container(name) {
                        invalid(&path.child("name"), out);
                    }
                }
            }
        }
        _ => {
            if api == "autoscaling/v2beta1" {
                named_path(body, "metricName", path, out);
            } else if let Some(metric) = body.get("metric") {
                named_path(metric, "name", &path.child("metric"), out);
            }
            if selected == "object" {
                let key = if api == "autoscaling/v2beta1" {
                    "target"
                } else {
                    "describedObject"
                };
                if let Some(object) = body.get(key) {
                    reference(object, context, true, &path.child(key), out);
                }
            }
        }
    }
    // Native object admission does not validate selector semantics or establish metrics infrastructure.
}
fn metric(
    node: &TreeNode,
    api: &str,
    context: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn super::validation::AccessSink,
) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let selected = match text(node, "type") {
        Some("Object") => "object",
        Some("Pods") => "pods",
        Some("Resource") => "resource",
        Some("External") => "external",
        Some("ContainerResource") => "containerResource",
        _ => {
            invalid(&path.child("type"), out);
            return;
        }
    };
    for key in ["object", "pods", "resource", "external", "containerResource"] {
        if out.exhausted() {
            return;
        }
        if present(node, key) != (key == selected) {
            invalid(&path.child(key), out);
        }
    }
    let Some(body) = node.get(selected) else { return };
    let body_path = path.child(selected);
    metric_identity(body, selected, api, context, &body_path, out);
    if out.exhausted() {
        return;
    }
    if api == "autoscaling/v2beta1" {
        beta_source(body, text(node, "type").unwrap_or_default(), &body_path, out);
    } else {
        require(body, "target", &body_path, out);
        if let Some(value) = body.get("target") {
            target(
                value,
                text(node, "type").unwrap_or_default(),
                &body_path.child("target"),
                out,
            );
        }
    }
}
fn behavior(node: &TreeNode, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    for direction in ["scaleUp", "scaleDown"] {
        if out.exhausted() {
            return;
        }
        let Some(rules) = node.get(direction).filter(|node| node.value != TreeValue::Null) else {
            continue;
        };
        let rule_path = path.child(direction);
        enumeration(rules, "selectPolicy", &["Max", "Min", "Disabled"], &rule_path, out);
        number(rules, "stabilizationWindowSeconds", 0, 3600, &rule_path, out);
        if present(rules, "policies") && sequence(rules, "policies").is_empty() {
            invalid(&rule_path.child("policies"), out);
        }
        for (index, policy) in sequence(rules, "policies").iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let policy_path = rule_path.child("policies").child(index.to_string());
            enumeration(policy, "type", &["Pods", "Percent"], &policy_path, out);
            number(policy, "value", 1, i64::from(i32::MAX), &policy_path, out);
            number(policy, "periodSeconds", 1, 1800, &policy_path, out);
        }
    }
}
pub(super) fn validate(
    tree: &TreeNode,
    api: &str,
    context: &ValidationContext<'_>,
    out: &mut dyn super::validation::AccessSink,
) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let path = FieldPath(vec!["spec".into()]);
    require(tree, "spec", &FieldPath::default(), out);
    let Some(spec) = tree.get("spec") else { return };
    require(spec, "scaleTargetRef", &path, out);
    require(spec, "maxReplicas", &path, out);
    number(spec, "maxReplicas", 1, i64::from(i32::MAX), &path, out);
    number(spec, "minReplicas", 0, i64::from(i32::MAX), &path, out);
    if let Some(min) = spec.get("minReplicas").and_then(integer) {
        if min == 0 {
            unadmitted(&path.child("minReplicas"), out);
        }
        if spec.get("maxReplicas").and_then(integer).is_some_and(|max| max < min) {
            invalid(&path.child("maxReplicas"), out);
        }
    }
    if let Some(node) = spec.get("scaleTargetRef") {
        reference(
            node,
            context,
            text(node, "kind") == Some("ReplicationController"),
            &path.child("scaleTargetRef"),
            out,
        );
        // Identity resolution cannot establish the target's scale subresource or controller prerequisites.
        unadmitted(&path.child("scaleTargetRef"), out);
    }
    number(
        spec,
        "targetCPUUtilizationPercentage",
        1,
        i64::from(i32::MAX),
        &path,
        out,
    );
    for (index, item) in sequence(spec, "metrics").iter().enumerate() {
        if out.exhausted() {
            return;
        }
        metric(item, api, context, &path.child("metrics").child(index.to_string()), out);
    }
    if let Some(value) = spec.get("behavior") {
        behavior(value, &path.child("behavior"), out);
    }
}
