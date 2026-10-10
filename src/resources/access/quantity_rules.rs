//! Original supplied-field `LimitRange` checks within a conservative native arithmetic domain.
use super::validation::{AccessSink, invalid, text, unadmitted};
use crate::{
    diagnostic::{FieldPath, FindingCode},
    resources::common::child_path,
    syntax::TreeNode,
    value::Quantity,
};
use std::cmp::Ordering;

pub(super) fn quantity(node: &TreeNode, path: &FieldPath, out: &mut dyn AccessSink) -> Option<Quantity> {
    if out.exhausted() {
        return None;
    }
    let Some(lexeme) = node.as_str() else {
        invalid(path, out);
        return None;
    };
    match Quantity::parse_in(lexeme, out.fields()) {
        Ok(value) => Some(value),
        Err(finding) if finding.code == FindingCode::LimitExceeded => {
            out.push(finding);
            None
        }
        Err(_) => {
            invalid(path, out);
            None
        }
    }
}
fn child(parent: &FieldPath, key: &str, out: &mut dyn AccessSink) -> Option<FieldPath> {
    match child_path(parent, key, out.fields()) {
        Ok(path) => Some(path),
        Err(finding) => {
            out.push(finding);
            None
        }
    }
}
/// Parse/sign are separate: native `LimitRange` does not reject every negative supplied quantity.
pub(super) fn values(node: &TreeNode, container: bool, path: &FieldPath, out: &mut dyn AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if let Some(entries) = node.as_mapping() {
        for (key, value) in entries {
            let Some(leaf) = child(path, key, out) else {
                return;
            };
            if !out.charge(key.len().saturating_mul(5).saturating_add(20)) {
                return;
            }
            if !(if container {
                super::resource_names::container(key)
            } else {
                super::resource_names::general(key)
            }) {
                invalid(&leaf, out);
            }
            let Some(value) = quantity(value, &leaf, out) else {
                if out.exhausted() {
                    return;
                }
                continue;
            };
            if !out.charge(20) {
                return;
            }
            if !value.conservative_bytes() {
                unadmitted(&leaf, out);
            }
        }
    }
}
/// Charge every possible key comparison before the underlying mapping lookup.
fn lookup<'a>(map: &'a TreeNode, key: &str, out: &mut dyn AccessSink) -> Option<&'a TreeNode> {
    let entries = map.as_mapping()?;
    for (candidate, _) in entries {
        if !out.charge(candidate.len().saturating_add(key.len()).saturating_add(1)) {
            return None;
        }
    }
    map.get(key)
}
fn compare(left: &TreeNode, right: &TreeNode, leaf: &FieldPath, out: &mut dyn AccessSink) -> Option<Ordering> {
    let left = quantity(left, leaf, out)?;
    let right = quantity(right, leaf, out)?;
    if !out.charge(40) {
        return None;
    }
    if !left.conservative_bytes() || !right.conservative_bytes() {
        unadmitted(leaf, out);
        return None;
    }
    match left.compare_exact(&right, &out.fields().processing, out.fields().phase) {
        Ok(order) => Some(order),
        Err(finding) => {
            out.push(finding);
            None
        }
    }
}
fn relation(item: &TreeNode, low: &str, high: &str, report: &str, path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    let (Some(left), Some(right)) = (item.get(low).and_then(TreeNode::as_mapping), item.get(high)) else {
        return;
    };
    let Some(parent) = child(path, report, out) else {
        return;
    };
    for (key, left) in left {
        if out.exhausted() {
            return;
        }
        let Some(right) = lookup(right, key, out) else {
            continue;
        };
        let Some(leaf) = child(&parent, key, out) else {
            return;
        };
        if compare(left, right, &leaf, out) == Some(Ordering::Greater) {
            invalid(&leaf, out);
        }
    }
}
fn non_overcommit(item: &TreeNode, path: &FieldPath, out: &mut dyn AccessSink) {
    let (Some(defaults), Some(requests)) = (
        item.get("default").and_then(TreeNode::as_mapping),
        item.get("defaultRequest"),
    ) else {
        return;
    };
    let Some(parent) = child(path, "defaultRequest", out) else {
        return;
    };
    for (name, default) in defaults {
        if !out.charge(name.len().saturating_add(1)) {
            return;
        }
        let native = !name.contains('/') || name.contains("kubernetes.io/");
        if native && !name.starts_with("hugepages-") {
            continue;
        }
        let Some(request) = lookup(requests, name, out) else {
            continue;
        };
        let Some(leaf) = child(&parent, name, out) else {
            return;
        };
        if compare(default, request, &leaf, out).is_some_and(|order| order != Ordering::Equal) {
            invalid(&leaf, out);
        }
    }
}
fn ratio(item: &TreeNode, path: &FieldPath, out: &mut dyn AccessSink) {
    let Some(entries) = item.get("maxLimitRequestRatio").and_then(TreeNode::as_mapping) else {
        return;
    };
    let Some(parent) = child(path, "maxLimitRequestRatio", out) else {
        return;
    };
    for (name, node) in entries {
        let Some(leaf) = child(&parent, name, out) else {
            return;
        };
        let Some(value) = quantity(node, &leaf, out) else {
            continue;
        };
        if !out.charge(20) {
            return;
        }
        if !value.conservative_bytes() {
            unadmitted(&leaf, out);
            continue;
        }
        let one = match Quantity::parse_in("1", out.fields()) {
            Ok(one) => one,
            Err(finding) => {
                out.push(finding);
                return;
            }
        };
        match value.compare_exact(&one, &out.fields().processing, out.fields().phase) {
            Ok(Ordering::Less) => invalid(&leaf, out),
            Ok(_) => {}
            Err(finding) => {
                out.push(finding);
                return;
            }
        }
        // Native max/min ratio uses rounded int64 conversions and floating division, not exact supplied order.
        if item.get("min").is_some_and(|map| lookup(map, name, out).is_some())
            && item.get("max").is_some_and(|map| lookup(map, name, out).is_some())
        {
            unadmitted(&leaf, out);
        }
    }
}
pub(super) fn relationships(item: &TreeNode, path: &FieldPath, out: &mut dyn AccessSink) {
    for (low, high, report) in [
        ("min", "max", "min"),
        ("min", "defaultRequest", "defaultRequest"),
        ("defaultRequest", "max", "defaultRequest"),
        ("defaultRequest", "default", "defaultRequest"),
        ("min", "default", "default"),
        ("default", "max", "default"),
    ] {
        relation(item, low, high, report, path, out);
        if out.exhausted() {
            return;
        }
    }
    non_overcommit(item, path, out);
    ratio(item, path, out);
    match text(item, "type") {
        Some("Pod") => {
            for key in ["default", "defaultRequest"] {
                if item
                    .get(key)
                    .and_then(TreeNode::as_mapping)
                    .is_some_and(|entries| !entries.is_empty())
                {
                    let Some(leaf) = child(path, key, out) else {
                        return;
                    };
                    invalid(&leaf, out);
                }
            }
        }
        Some("PersistentVolumeClaim") => {
            let supplied = ["min", "max"]
                .into_iter()
                .any(|key| item.get(key).is_some_and(|map| lookup(map, "storage", out).is_some()));
            if !supplied && !out.exhausted() {
                invalid(path, out);
            }
        }
        _ => {}
    }
}
