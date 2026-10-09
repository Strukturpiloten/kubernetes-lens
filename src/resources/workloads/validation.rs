//! Original bounded semantic checks; no server defaults or runtime lookup.
use super::{
    BTreeMap, CronJobV1, CronJobV1Beta1, DaemonSet, Deployment, EncodeContext, FieldCodec, FieldPath, Finding,
    FindingCode, Job, LabelSelector, Phase, Pod, ReplicaSet, ReplicationController, StatefulSet, TreeNode, gates,
    roots::RootHooks, rules, schedule,
};
use crate::{
    capability::{FeatureGateId, FeatureGateState, MergeStrategy, TargetProfile},
    diagnostic::ResourceId,
    graph::{
        KeyDomain, Reference, ReferencePredicate, ReferenceScope, ReferenceSink, ReferenceTarget, RelationshipKind,
    },
    registry::{FindingSink, ValidationContext},
    syntax::TreeValue,
    value::{IntOrString, Presence, Protected, Quantity},
};
use std::collections::BTreeSet;

pub(super) trait RootProfile: FieldCodec + crate::resources::common::UnknownScopes {
    const API: &'static str;
    const KIND: &'static str;
}
macro_rules! profile {
    ($($name:ident),* $(,)?) => {$(impl RootProfile for $name {
        const API: &'static str = Self::API_VERSION;
        const KIND: &'static str = Self::KIND;
    })*};
}
profile!(
    Pod,
    Deployment,
    StatefulSet,
    DaemonSet,
    ReplicaSet,
    ReplicationController,
    Job,
    CronJobV1,
    CronJobV1Beta1
);

impl<T: RootProfile> RootHooks for T {
    fn references(&self, out: &mut dyn ReferenceSink) {
        if let (Ok(tree), Ok(bindings)) = (
            self.encode(&EncodeContext::new(None), &FieldPath::default()),
            native_bindings::<T>(),
        ) {
            collect_references(&tree, T::KIND, &bindings, out);
        }
    }
    fn protected_paths(&self, out: &mut Vec<FieldPath>) {
        if let (Ok(tree), Ok(bindings)) = (
            self.encode(&EncodeContext::new(None), &FieldPath::default()),
            native_bindings::<T>(),
        ) {
            protected_paths(&tree, &bindings, out);
        }
    }
    fn validate_native(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
        match self.encode(&EncodeContext::new(Some(ctx.target)), &FieldPath::default()) {
            Ok(tree) => {
                let mut opaque = BTreeSet::new();
                self.unknown_scopes(&FieldPath::default(), &mut opaque);
                match native_bindings::<T>() {
                    Ok(bindings) => validate(&tree, T::KIND, T::API, ctx, &opaque, &bindings, out),
                    Err(finding) => out.push(finding),
                }
            }
            Err(finding) => out.push(finding),
        }
    }
}
type NativeBindings = BTreeMap<FieldPath, MergeStrategy>;
fn native_bindings<T: RootProfile>() -> Result<NativeBindings, Finding> {
    let capability = super::capabilities::for_api(crate::model::GroupVersionKind::new(T::API, T::KIND)?)?;
    let mut bindings = capability
        .fields
        .iter()
        .map(|field| Ok((FieldPath::parse(field.path)?, field.merge)))
        .collect::<Result<NativeBindings, Finding>>()?;
    bindings.insert(FieldPath::default(), MergeStrategy::Object);
    Ok(bindings)
}
/// Visit finite native fields only. Free-form maps are leaves: a label, annotation,
/// nodeSelector, CSI attribute or quantity key cannot manufacture a native object.
fn visit_native(
    node: &TreeNode,
    path: &FieldPath,
    pattern: &FieldPath,
    bindings: &NativeBindings,
    visitor: &mut impl FnMut(&TreeNode, &FieldPath, &MergeStrategy),
) {
    let Some(binding) = bindings.get(pattern) else {
        return;
    };
    visitor(node, path, binding);
    match binding {
        MergeStrategy::Object => {
            if let Some(members) = node.as_mapping() {
                for (key, child) in members {
                    visit_native(
                        child,
                        &path.child(key.clone()),
                        &pattern.child(key.clone()),
                        bindings,
                        visitor,
                    );
                }
            }
        }
        MergeStrategy::AtomicList | MergeStrategy::MapList { .. } => {
            if let Some(items) = node.as_sequence() {
                for (index, child) in items.iter().enumerate() {
                    visit_native(
                        child,
                        &path.child(index.to_string()),
                        &pattern.child("*"),
                        bindings,
                        visitor,
                    );
                }
            }
        }
        _ => (),
    }
}
fn invalid(path: &FieldPath, out: &mut dyn FindingSink) {
    out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
}
fn text<'a>(node: &'a TreeNode, key: &str) -> Option<&'a str> {
    node.get(key).and_then(TreeNode::as_str)
}
fn integer(node: &TreeNode) -> Option<i64> {
    if let TreeValue::Number(value) = &node.value {
        value.parse().ok()
    } else {
        None
    }
}
fn number(node: &TreeNode, key: &str) -> Option<i64> {
    node.get(key).and_then(integer)
}
fn items<'a>(node: &'a TreeNode, key: &str) -> &'a [TreeNode] {
    node.get(key).and_then(TreeNode::as_sequence).unwrap_or(&[])
}
fn present(node: &TreeNode, key: &str) -> bool {
    node.get(key).is_some_and(|n| !matches!(n.value, TreeValue::Null))
}
fn one_of(
    node: &TreeNode,
    keys: &[&str],
    required: bool,
    path: &FieldPath,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    let count = keys.iter().filter(|key| present(node, key)).count();
    if count > 1 || required && count == 0 && !opaque.contains(path) {
        invalid(path, out);
    }
}
fn enumeration(node: &TreeNode, key: &str, values: &[&str], path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(value) = text(node, key) {
        if !values.contains(&value) {
            invalid(&path.child(key), out);
        }
    }
}
fn range(node: &TreeNode, key: &str, low: i64, high: i64, path: &FieldPath, out: &mut dyn FindingSink) {
    if number(node, key).is_some_and(|n| n < low || n > high) {
        invalid(&path.child(key), out);
    }
}
fn required(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    if !present(node, key) {
        invalid(&path.child(key), out);
    }
}
fn nonempty(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    if text(node, key).is_some_and(str::is_empty) {
        invalid(&path.child(key), out);
    }
}
fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
}
fn port_name(value: &str) -> bool {
    value.len() <= 15
        && dns_label(value)
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
        && !value.contains("--")
}
fn percentage(node: &TreeNode, key: &str, maximum: Option<u64>, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(n) = node.get(key) {
        match IntOrString::decode(n, &path.child(key))
            .and_then(|v| crate::registry::codec::nonnegative_integer_or_percentage(&v, maximum, &path.child(key)))
        {
            Ok(()) => (),
            Err(e) => out.push(e),
        }
    }
}
fn zero(node: &TreeNode, key: &str) -> bool {
    number(node, key) == Some(0) || text(node, key) == Some("0%")
}
fn port(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(value) = node.get(key) {
        let valid = integer(value).is_some_and(|p| (1..=65535).contains(&p)) || value.as_str().is_some_and(port_name);
        if !valid {
            invalid(&path.child(key), out);
        }
    }
}

fn validate(
    tree: &TreeNode,
    kind: &str,
    api: &str,
    ctx: &ValidationContext<'_>,
    opaque: &BTreeSet<FieldPath>,
    bindings: &NativeBindings,
    out: &mut dyn FindingSink,
) {
    let target = ctx.target;
    let root = FieldPath::default();
    required(tree, "spec", &root, out);
    if let Some(spec) = tree.get("spec") {
        let path = root.child("spec");
        match kind {
            "Pod" => validate_pod(spec, &path, false, target, opaque, out),
            "Job" => validate_job(spec, &path, target, opaque, out),
            "CronJob" => {
                required(spec, "schedule", &path, out);
                required(spec, "jobTemplate", &path, out);
                enumeration(spec, "concurrencyPolicy", &["Allow", "Forbid", "Replace"], &path, out);
                for key in [
                    "startingDeadlineSeconds",
                    "successfulJobsHistoryLimit",
                    "failedJobsHistoryLimit",
                ] {
                    range(spec, key, 0, i64::MAX, &path, out);
                }
                if let Some(schedule) = text(spec, "schedule") {
                    schedule::validate_schedule(
                        schedule,
                        text(spec, "timeZone"),
                        target,
                        ctx.intent,
                        &path.child("schedule"),
                        out,
                    );
                }
                if let Some(zone) = text(spec, "timeZone") {
                    if api == "batch/v1beta1" || target.kubernetes.minor() < 27 {
                        invalid(&path.child("timeZone"), out);
                    }
                    schedule::validate_zone(zone, &path.child("timeZone"), out);
                }
                if let Some(job) = spec.get("jobTemplate").and_then(|n| n.get("spec")) {
                    validate_job(job, &path.child("jobTemplate").child("spec"), target, opaque, out);
                }
            }
            _ => validate_controller(spec, kind, &path, target, opaque, out),
        }
    }
    gates::validate(tree, kind, api, target, out);
    rules::validate(tree, kind, api, target.kubernetes.minor(), out);
    visit_native(tree, &root, &root, bindings, &mut |node, path, binding| {
        validate_bound_node(node, path, binding, target, opaque, out);
    });
}
fn rollout(node: &TreeNode, path: &FieldPath, max_surge: Option<u64>, out: &mut dyn FindingSink) {
    percentage(node, "maxSurge", max_surge, path, out);
    percentage(node, "maxUnavailable", Some(100), path, out);
    if zero(node, "maxSurge") && zero(node, "maxUnavailable") {
        invalid(path, out);
    }
}
fn unique_metadata_names(list: &[TreeNode], path: &FieldPath, out: &mut dyn FindingSink) {
    let mut seen = BTreeSet::new();
    for (i, item) in list.iter().enumerate() {
        let p = path.child(i.to_string()).child("metadata").child("name");
        match item.get("metadata").and_then(|m| text(m, "name")) {
            Some(n) if dns_label(n) && seen.insert(n) => (),
            _ => invalid(&p, out),
        }
    }
}
fn validate_selector_match(
    selector: &TreeNode,
    labels: Option<&TreeNode>,
    kind: &str,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    let map = labels.and_then(TreeNode::as_mapping).map(|entries| {
        entries
            .iter()
            .filter_map(|(k, v)| v.as_str().map(|v| (k.clone(), v.to_owned())))
            .collect::<BTreeMap<_, _>>()
    });
    if kind == "ReplicationController" {
        if selector.as_mapping().is_some_and(<[(String, TreeNode)]>::is_empty) {
            invalid(path, out);
            return;
        }
        if let (Some(selected), Some(labels)) = (selector.as_mapping(), map) {
            if selected
                .iter()
                .any(|(k, v)| v.as_str() != labels.get(k).map(String::as_str))
            {
                invalid(path, out);
            }
        }
    } else {
        match LabelSelector::decode(selector, path) {
            Ok(selected) => {
                let has_terms = selected.match_labels.value().is_some_and(|m| !m.is_empty())
                    || selected.match_expressions.value().is_some_and(|v| !v.is_empty());
                if !has_terms {
                    invalid(path, out);
                }

                if let Err(e) = selected.validate() {
                    out.push(e.at_path(path.clone()));
                }
                if let Some(labels) = map {
                    match selected.matches(&labels) {
                        Ok(true) => (),
                        _ => invalid(path, out),
                    }
                } else if present(selector, "matchLabels") || present(selector, "matchExpressions") {
                    invalid(path, out);
                }
            }
            Err(e) => out.push(e),
        }
    }
}
fn validate_template(
    template: &TreeNode,
    path: &FieldPath,
    job: bool,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    required(template, "spec", path, out);
    if !job {
        if let Some(spec) = template.get("spec") {
            enumeration(spec, "restartPolicy", &["Always"], &path.child("spec"), out);
        }
    }
    if let Some(spec) = template.get("spec") {
        validate_pod(spec, &path.child("spec"), job, target, opaque, out);
    }
}
fn validate_pod(
    spec: &TreeNode,
    path: &FieldPath,
    job: bool,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    required(spec, "containers", path, out);
    if job {
        required(spec, "restartPolicy", path, out);
    }
    if items(spec, "containers").is_empty() {
        invalid(&path.child("containers"), out);
    }
    enumeration(
        spec,
        "restartPolicy",
        if job {
            &["Never", "OnFailure"]
        } else {
            &["Always", "Never", "OnFailure"]
        },
        path,
        out,
    );
    enumeration(
        spec,
        "dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
        path,
        out,
    );
    enumeration(spec, "preemptionPolicy", &["Never", "PreemptLowerPriority"], path, out);
    range(spec, "activeDeadlineSeconds", 1, i64::MAX, path, out);
    range(spec, "terminationGracePeriodSeconds", 0, i64::MAX, path, out);
    if text(spec, "dnsPolicy") == Some("None") && !present(spec, "dnsConfig") {
        invalid(&path.child("dnsConfig"), out);
    }
    let mut volume_names = BTreeSet::new();
    for (i, volume) in items(spec, "volumes").iter().enumerate() {
        let p = path.child("volumes").child(i.to_string());
        match text(volume, "name") {
            Some(n) if dns_label(n) && volume_names.insert(n) => (),
            _ => invalid(&p.child("name"), out),
        }
        let known_sources = crate::resources::common::Volume::NATIVE_FIELDS
            .iter()
            .filter(|name| **name != "name" && present(volume, name))
            .count();
        if known_sources > 1 || known_sources == 0 && !opaque.contains(&p) {
            invalid(&p, out);
        }
    }
    validate_containers(spec, path, &volume_names, target, opaque, out);
}
fn validate_job(
    spec: &TreeNode,
    path: &FieldPath,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    required(spec, "template", path, out);
    for key in [
        "parallelism",
        "completions",
        "backoffLimit",
        "backoffLimitPerIndex",
        "maxFailedIndexes",
        "ttlSecondsAfterFinished",
    ] {
        range(spec, key, 0, i64::MAX, path, out);
    }
    range(spec, "activeDeadlineSeconds", 1, i64::MAX, path, out);
    enumeration(spec, "completionMode", &["NonIndexed", "Indexed"], path, out);
    let indexed = text(spec, "completionMode") == Some("Indexed");
    if indexed && !present(spec, "completions") {
        invalid(&path.child("completions"), out);
    }
    if indexed {
        range(spec, "parallelism", 0, 100_000, path, out);
    }
    let pod = spec.get("template").and_then(|n| n.get("spec"));
    if let Some(template) = spec.get("template") {
        validate_template(template, &path.child("template"), true, target, opaque, out);
    }
    if (present(spec, "podFailurePolicy") || present(spec, "backoffLimitPerIndex"))
        && pod.and_then(|n| text(n, "restartPolicy")) != Some("Never")
    {
        invalid(&path.child("template").child("spec").child("restartPolicy"), out);
    }
    if present(spec, "backoffLimitPerIndex") && !indexed {
        invalid(&path.child("backoffLimitPerIndex"), out);
    }
    if present(spec, "maxFailedIndexes") && !present(spec, "backoffLimitPerIndex") {
        invalid(&path.child("maxFailedIndexes"), out);
    }
    if let (Some(max), Some(count)) = (number(spec, "maxFailedIndexes"), number(spec, "completions")) {
        if max > count {
            invalid(&path.child("maxFailedIndexes"), out);
        }
    }
    if let Some(policy) = spec.get("podFailurePolicy") {
        let rules = items(policy, "rules");
        if rules.is_empty() || rules.len() > 20 {
            invalid(&path.child("podFailurePolicy").child("rules"), out);
        }
        for (i, rule) in rules.iter().enumerate() {
            let p = path.child("podFailurePolicy").child("rules").child(i.to_string());
            one_of(rule, &["onExitCodes", "onPodConditions"], true, &p, opaque, out);
            enumeration(rule, "action", &["FailJob", "FailIndex", "Ignore", "Count"], &p, out);
            if text(rule, "action") == Some("FailIndex") && !present(spec, "backoffLimitPerIndex") {
                invalid(&p.child("action"), out);
            }
            if let Some(exit) = rule.get("onExitCodes") {
                let ep = p.child("onExitCodes");
                enumeration(exit, "operator", &["In", "NotIn"], &ep, out);
                let values = items(exit, "values");
                let mut seen = BTreeSet::new();
                if values.is_empty() || values.len() > 255 {
                    invalid(&ep.child("values"), out);
                }
                for (j, value) in values.iter().enumerate() {
                    if integer(value).is_none_or(|v| {
                        !(0..=255).contains(&v) || text(exit, "operator") == Some("In") && v == 0 || !seen.insert(v)
                    }) {
                        invalid(&ep.child("values").child(j.to_string()), out);
                    }
                }
            }
        }
    }
    if let Some(policy) = spec.get("successPolicy") {
        if !indexed {
            invalid(&path.child("successPolicy"), out);
        }
        let rules = items(policy, "rules");
        if rules.is_empty() || rules.len() > 20 {
            invalid(&path.child("successPolicy").child("rules"), out);
        }
        for (i, rule) in rules.iter().enumerate() {
            let p = path.child("successPolicy").child("rules").child(i.to_string());
            if !present(rule, "succeededCount") && !present(rule, "succeededIndexes") {
                invalid(&p, out);
            }
            range(
                rule,
                "succeededCount",
                1,
                number(spec, "completions").unwrap_or(i64::MAX),
                &p,
                out,
            );
            if let Some(indexes) = text(rule, "succeededIndexes") {
                if !valid_indexes(indexes, number(spec, "completions")) {
                    invalid(&p.child("succeededIndexes"), out);
                }
            }
        }
    }
}
fn valid_indexes(value: &str, completions: Option<i64>) -> bool {
    let mut previous = None;
    for interval in value.split(',') {
        let (a, b) = interval.split_once('-').unwrap_or((interval, interval));
        let parse = |s: &str| {
            if !s.is_empty() && s.bytes().all(|c| c.is_ascii_digit()) {
                s.parse::<i64>().ok()
            } else {
                None
            }
        };
        let (Some(a), Some(b)) = (parse(a), parse(b)) else {
            return false;
        };
        if a > b || previous.is_some_and(|p| a <= p) || completions.is_some_and(|n| b >= n) {
            return false;
        }
        previous = Some(b);
    }
    previous.is_some()
}
fn validate_bound_node(
    node: &TreeNode,
    path: &FieldPath,
    binding: &MergeStrategy,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    let last = path.0.last().map_or("", String::as_str);
    if let Some(map) = node.as_mapping() {
        if matches!(binding, MergeStrategy::Map) {
            if matches!(last, "limits" | "requests" | "overhead") {
                for (key, value) in map {
                    if value
                        .as_str()
                        .is_some_and(|value| Quantity::parse(value).is_ok_and(|q| q.exact().is_negative()))
                    {
                        invalid(&path.child(key.clone()), out);
                    }
                }
            }
            return;
        }
        if !matches!(binding, MergeStrategy::Object) {
            return;
        }
        validate_native_scalars(node, path, out);
        if node.get("optional").is_some_and(|n| matches!(n.value, TreeValue::Null)) {
            invalid(&path.child("optional"), out);
        }
        if present(node, "procMount") {
            enumeration(node, "procMount", &["Default", "Unmasked"], path, out);
        }
        if last == "seccompProfile" {
            required(node, "type", path, out);
            enumeration(node, "type", &["Localhost", "RuntimeDefault", "Unconfined"], path, out);
            if text(node, "type") == Some("Localhost") {
                required(node, "localhostProfile", path, out);
                nonempty(node, "localhostProfile", path, out);
            } else if present(node, "localhostProfile") {
                invalid(&path.child("localhostProfile"), out);
            }
        }
        validate_native_expressions(node, last, path, opaque, out);
        validate_native_items(node, path, target, opaque, out);
    } else if let Some(list) = node.as_sequence() {
        if last == "ports" {
            let mut names = BTreeSet::new();
            for (i, port) in list.iter().enumerate() {
                if let Some(name) = text(port, "name") {
                    if !name.is_empty() && (!port_name(name) || !names.insert(name)) {
                        invalid(&path.child(i.to_string()).child("name"), out);
                    }
                }
            }
        }
        if last == "accessModes" {
            let mut seen = BTreeSet::new();
            for (i, item) in list.iter().enumerate() {
                if item.as_str().is_none_or(|s| {
                    !["ReadWriteOnce", "ReadOnlyMany", "ReadWriteMany", "ReadWriteOncePod"].contains(&s)
                        || !seen.insert(s)
                }) {
                    invalid(&path.child(i.to_string()), out);
                }
            }
        }
    }
}
fn protected_paths(tree: &TreeNode, bindings: &NativeBindings, out: &mut Vec<FieldPath>) {
    let root = FieldPath::default();
    visit_native(tree, &root, &root, bindings, &mut |node, path, binding| {
        if !matches!(binding, MergeStrategy::Object) {
            return;
        }
        if let Some(map) = node.as_mapping() {
            let container = path
                .0
                .iter()
                .rev()
                .nth(1)
                .is_some_and(|p| p == "containers" || p == "initContainers");
            let env = path.0.iter().rev().nth(1).is_some_and(|p| p == "env");
            let header = path.0.iter().rev().nth(1).is_some_and(|p| p == "httpHeaders");
            let exec = path.0.last().is_some_and(|p| p == "exec");
            for (key, _) in map {
                if container && matches!(key.as_str(), "command" | "args")
                    || env && key == "value"
                    || header && key == "value"
                    || exec && key == "command"
                    || key == "gmsaCredentialSpec"
                {
                    out.push(path.child(key.clone()));
                }
            }
        }
    });
}
fn optional(node: &TreeNode) -> Presence<bool> {
    match node.get("optional").map(|n| &n.value) {
        Some(TreeValue::Bool(v)) => Presence::Value(*v),
        Some(TreeValue::Null) => Presence::Null,
        _ => Presence::Absent,
    }
}
fn reference(
    kind: &str,
    name: &str,
    predicate: Option<ReferencePredicate>,
    optional: Presence<bool>,
    relation: RelationshipKind,
    path: &FieldPath,
    out: &mut dyn ReferenceSink,
) {
    let api = if kind == "PriorityClass" {
        "scheduling.k8s.io/v1"
    } else if kind == "RuntimeClass" {
        "node.k8s.io/v1"
    } else {
        "v1"
    };
    if let Ok(gvk) = crate::model::GroupVersionKind::new(api, kind) {
        out.push(Reference {
            from: ResourceId(0),
            path: path.clone(),
            relation,
            target: ReferenceTarget::CheckedObject {
                gvk,
                name: name.to_owned(),
                predicate,
                optional,
            },
            scope: if matches!(kind, "Node" | "RuntimeClass" | "PriorityClass") {
                ReferenceScope::Cluster
            } else {
                ReferenceScope::SameNamespace
            },
        });
    }
}
fn collect_references(tree: &TreeNode, root_kind: &str, bindings: &NativeBindings, out: &mut dyn ReferenceSink) {
    let root = FieldPath::default();
    visit_native(tree, &root, &root, bindings, &mut |node, path, binding| {
        if !matches!(binding, MergeStrategy::Object) {
            return;
        }
        if let Some(map) = node.as_mapping() {
            let last = path.0.last().map_or("", String::as_str);
            collect_object_references(node, root_kind, last, path, out);
            for (key, child) in map {
                if let Some(name) = child.as_str() {
                    let kind = match key.as_str() {
                        "serviceAccountName" => Some("ServiceAccount"),
                        "nodeName" => Some("Node"),
                        "runtimeClassName" => Some("RuntimeClass"),
                        "priorityClassName" => Some("PriorityClass"),
                        _ => None,
                    };
                    if let Some(kind) = kind {
                        reference(
                            kind,
                            name,
                            None,
                            Presence::Absent,
                            RelationshipKind::Identity,
                            &path.child(key.clone()),
                            out,
                        );
                    }
                }
                if key == "imagePullSecrets" {
                    if let Some(list) = child.as_sequence() {
                        for (i, item) in list.iter().enumerate() {
                            if let Some(name) = text(item, "name") {
                                reference(
                                    "Secret",
                                    name,
                                    None,
                                    Presence::Absent,
                                    RelationshipKind::Dependency,
                                    &path.child(key.clone()).child(i.to_string()).child("name"),
                                    out,
                                );
                            }
                        }
                    }
                }
            }
        }
    });
}

fn validate_controller(
    spec: &TreeNode,
    kind: &str,
    path: &FieldPath,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    if kind != "ReplicationController" {
        required(spec, "template", path, out);
        required(spec, "selector", path, out);
    }
    for key in ["replicas", "minReadySeconds", "revisionHistoryLimit"] {
        range(spec, key, 0, i64::MAX, path, out);
    }
    if let Some(template) = spec.get("template") {
        validate_template(template, &path.child("template"), false, target, opaque, out);
        if let Some(selector) = spec.get("selector") {
            let labels = template.get("metadata").and_then(|m| m.get("labels"));
            validate_selector_match(selector, labels, kind, &path.child("selector"), out);
        }
    }
    if kind == "Deployment" {
        range(spec, "progressDeadlineSeconds", 1, i64::MAX, path, out);
        if let (Some(deadline), Some(min_ready)) =
            (number(spec, "progressDeadlineSeconds"), number(spec, "minReadySeconds"))
        {
            if deadline <= min_ready {
                invalid(&path.child("progressDeadlineSeconds"), out);
            }
        }
        if let Some(strategy) = spec.get("strategy") {
            let p = path.child("strategy");
            enumeration(strategy, "type", &["RollingUpdate", "Recreate"], &p, out);
            if text(strategy, "type") == Some("Recreate") && present(strategy, "rollingUpdate") {
                invalid(&p.child("rollingUpdate"), out);
            }
            if let Some(roll) = strategy.get("rollingUpdate") {
                rollout(roll, &p.child("rollingUpdate"), None, out);
            }
        }
    }
    if matches!(kind, "StatefulSet" | "DaemonSet") {
        if let Some(strategy) = spec.get("updateStrategy") {
            let p = path.child("updateStrategy");
            enumeration(strategy, "type", &["RollingUpdate", "OnDelete"], &p, out);
            if text(strategy, "type") == Some("OnDelete") && present(strategy, "rollingUpdate") {
                invalid(&p.child("rollingUpdate"), out);
            }
            if let Some(roll) = strategy.get("rollingUpdate") {
                if kind == "DaemonSet" {
                    rollout(roll, &p.child("rollingUpdate"), Some(100), out);
                } else {
                    range(roll, "partition", 0, i64::MAX, &p.child("rollingUpdate"), out);
                }
            }
        }
    }
    if kind == "StatefulSet" {
        required(spec, "serviceName", path, out);
        nonempty(spec, "serviceName", path, out);
        enumeration(spec, "podManagementPolicy", &["OrderedReady", "Parallel"], path, out);
        if let Some(policy) = spec.get("persistentVolumeClaimRetentionPolicy") {
            for key in ["whenDeleted", "whenScaled"] {
                enumeration(
                    policy,
                    key,
                    &["Retain", "Delete"],
                    &path.child("persistentVolumeClaimRetentionPolicy"),
                    out,
                );
            }
        }
        if let Some(ordinals) = spec.get("ordinals") {
            range(ordinals, "start", 0, i64::MAX, &path.child("ordinals"), out);
        }
        unique_metadata_names(
            items(spec, "volumeClaimTemplates"),
            &path.child("volumeClaimTemplates"),
            out,
        );
    }
}

fn validate_containers(
    spec: &TreeNode,
    path: &FieldPath,
    volume_names: &BTreeSet<&str>,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    let mut names = BTreeSet::new();
    for field in ["containers", "initContainers"] {
        for (i, container) in items(spec, field).iter().enumerate() {
            let p = path.child(field).child(i.to_string());
            match text(container, "name") {
                Some(n) if dns_label(n) && names.insert(n) => (),
                _ => invalid(&p.child("name"), out),
            }
            required(container, "image", &p, out);
            nonempty(container, "image", &p, out);
            enumeration(
                container,
                "imagePullPolicy",
                &["Always", "Never", "IfNotPresent"],
                &p,
                out,
            );
            enumeration(
                container,
                "terminationMessagePolicy",
                &["File", "FallbackToLogsOnError"],
                &p,
                out,
            );
            if present(container, "restartPolicy") {
                let admitted = field == "initContainers"
                    && text(container, "restartPolicy") == Some("Always")
                    && target.kubernetes.minor() >= 28
                    && target
                        .feature_gates
                        .resolve(FeatureGateId::SidecarContainers, target.kubernetes)
                        == Ok(FeatureGateState::Enabled);
                if !admitted {
                    invalid(&p.child("restartPolicy"), out);
                }
            }
            let mut mounts = BTreeSet::new();
            for (j, mount) in items(container, "volumeMounts").iter().enumerate() {
                let mp = p.child("volumeMounts").child(j.to_string());
                if text(mount, "name").is_none_or(|n| !volume_names.contains(n)) {
                    invalid(&mp.child("name"), out);
                }
                one_of(mount, &["subPath", "subPathExpr"], false, &mp, opaque, out);
                if text(mount, "mountPath").is_none_or(|m| m.is_empty() || !mounts.insert(m)) {
                    invalid(&mp.child("mountPath"), out);
                }
            }
            for (j, device) in items(container, "volumeDevices").iter().enumerate() {
                let dp = p.child("volumeDevices").child(j.to_string());
                if text(device, "name").is_none_or(|n| !volume_names.contains(n)) {
                    invalid(&dp.child("name"), out);
                }
                if text(device, "devicePath").is_none_or(|n| !n.starts_with('/')) {
                    invalid(&dp.child("devicePath"), out);
                }
            }
            for key in ["livenessProbe", "readinessProbe", "startupProbe"] {
                if let Some(probe) = container.get(key) {
                    let pp = p.child(key);
                    one_of(probe, &["exec", "httpGet", "tcpSocket"], true, &pp, opaque, out);
                    for member in [
                        "failureThreshold",
                        "successThreshold",
                        "periodSeconds",
                        "timeoutSeconds",
                    ] {
                        range(probe, member, 1, i64::MAX, &pp, out);
                    }
                    range(probe, "initialDelaySeconds", 0, i64::MAX, &pp, out);
                    if key != "readinessProbe" && number(probe, "successThreshold").is_some_and(|v| v != 1) {
                        invalid(&pp.child("successThreshold"), out);
                    }
                }
            }
            if let Some(lifecycle) = container.get("lifecycle") {
                for key in ["postStart", "preStop"] {
                    if let Some(handler) = lifecycle.get(key) {
                        one_of(
                            handler,
                            &["exec", "httpGet", "tcpSocket"],
                            true,
                            &p.child("lifecycle").child(key),
                            opaque,
                            out,
                        );
                    }
                }
            }
        }
    }
}

fn validate_native_expressions(
    node: &TreeNode,
    last: &str,
    path: &FieldPath,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    if matches!(last, "httpGet" | "tcpSocket") {
        required(node, "port", path, out);
    }
    if last == "exec" && items(node, "command").is_empty() {
        invalid(&path.child("command"), out);
    }
    if last == "valueFrom" {
        one_of(
            node,
            &["fieldRef", "resourceFieldRef", "configMapKeyRef", "secretKeyRef"],
            true,
            path,
            opaque,
            out,
        );
    }
    if last == "fieldRef" {
        if text(node, "apiVersion").is_some_and(|s| s != "v1") {
            invalid(&path.child("apiVersion"), out);
        }
        if let Some(field) = text(node, "fieldPath") {
            let allowed = [
                "metadata.name",
                "metadata.namespace",
                "metadata.uid",
                "spec.nodeName",
                "spec.serviceAccountName",
                "status.hostIP",
                "status.hostIPs",
                "status.podIP",
                "status.podIPs",
            ]
            .contains(&field)
                || (path.0.iter().any(|part| part == "downwardAPI")
                    && ["metadata.labels", "metadata.annotations"].contains(&field))
                || ["metadata.labels['", "metadata.annotations['"]
                    .iter()
                    .any(|prefix| field.starts_with(prefix) && field.ends_with("']") && field.len() > prefix.len() + 2);
            if !allowed {
                invalid(&path.child("fieldPath"), out);
            }
        } else {
            invalid(&path.child("fieldPath"), out);
        }
    }
    if last == "resourceFieldRef" {
        if let Some(resource) = text(node, "resource") {
            if ![
                "limits.cpu",
                "limits.memory",
                "limits.ephemeral-storage",
                "requests.cpu",
                "requests.memory",
                "requests.ephemeral-storage",
            ]
            .contains(&resource)
                && !resource.starts_with("limits.hugepages-")
                && !resource.starts_with("requests.hugepages-")
            {
                invalid(&path.child("resource"), out);
            }
        } else {
            invalid(&path.child("resource"), out);
        }
    }
    if matches!(last, "configMapKeyRef" | "secretKeyRef") {
        required(node, "name", path, out);
        required(node, "key", path, out);
        nonempty(node, "name", path, out);
        nonempty(node, "key", path, out);
    }
}

fn validate_environment_name(
    node: &TreeNode,
    key: &str,
    path: &FieldPath,
    target: &TargetProfile,
    out: &mut dyn FindingSink,
) {
    let Some(name) = text(node, key).filter(|name| !name.is_empty()) else {
        return;
    };
    let legacy = !matches!(name, "." | "..")
        && !name.starts_with("..")
        && name
            .as_bytes()
            .first()
            .is_some_and(|byte| byte.is_ascii_alphabetic() || matches!(byte, b'-' | b'.' | b'_'))
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_'));
    if legacy {
        return;
    }
    let relaxed = name.bytes().all(|byte| (b' '..=b'~').contains(&byte) && byte != b'=');
    if !relaxed || target.kubernetes.minor() == 20 {
        invalid(&path.child(key), out);
    } else {
        out.push(Finding::warning(FindingCode::NativeContextRequired, Phase::Validation).at_path(path.child(key)));
    }
}
fn validate_native_items(
    node: &TreeNode,
    path: &FieldPath,
    target: &TargetProfile,
    opaque: &BTreeSet<FieldPath>,
    out: &mut dyn FindingSink,
) {
    if path.0.iter().rev().nth(1).is_some_and(|p| p == "env") {
        required(node, "name", path, out);
        nonempty(node, "name", path, out);
        validate_environment_name(node, "name", path, target, out);
        if present(node, "valueFrom") && text(node, "value").is_some_and(|s| !s.is_empty()) {
            invalid(path, out);
        }
    }
    if path.0.iter().rev().nth(1).is_some_and(|p| p == "envFrom") {
        validate_environment_name(node, "prefix", path, target, out);
        one_of(node, &["configMapRef", "secretRef"], true, path, opaque, out);
    }
    if path.0.iter().rev().nth(1).is_some_and(|p| p == "sources") && path.0.iter().any(|p| p == "projected") {
        one_of(
            node,
            &["secret", "configMap", "downwardAPI", "serviceAccountToken"],
            true,
            path,
            opaque,
            out,
        );
    }
    if path.0.iter().rev().nth(1).is_some_and(|p| p == "tolerations") {
        enumeration(node, "operator", &["Equal", "Exists"], path, out);
        enumeration(
            node,
            "effect",
            &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
            path,
            out,
        );
        if text(node, "operator") == Some("Exists") && text(node, "value").is_some_and(|s| !s.is_empty()) {
            invalid(&path.child("value"), out);
        }
        if text(node, "key") == Some("") && text(node, "operator") != Some("Exists") {
            invalid(&path.child("operator"), out);
        }
        if present(node, "tolerationSeconds") && text(node, "effect") != Some("NoExecute") {
            invalid(&path.child("tolerationSeconds"), out);
        }
    }
    if path
        .0
        .iter()
        .rev()
        .nth(1)
        .is_some_and(|p| p == "matchExpressions" || p == "matchFields")
    {
        let op = text(node, "operator");
        let count = items(node, "values").len();
        enumeration(
            node,
            "operator",
            &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
            path,
            out,
        );
        if matches!(op, Some("In" | "NotIn")) && count == 0
            || matches!(op, Some("Exists" | "DoesNotExist")) && count != 0
            || matches!(op, Some("Gt" | "Lt"))
                && (count != 1
                    || items(node, "values")
                        .first()
                        .and_then(TreeNode::as_str)
                        .is_none_or(|s| s.parse::<i64>().is_err()))
        {
            invalid(&path.child("values"), out);
        }
    }
}

fn collect_azure_file_reference(node: &TreeNode, path: &FieldPath, out: &mut dyn ReferenceSink) {
    if let Some(name) = text(node, "secretName") {
        reference(
            "Secret",
            name,
            None,
            Presence::Absent,
            RelationshipKind::Dependency,
            &path.child("secretName"),
            out,
        );
    }
}
fn collect_object_references(
    node: &TreeNode,
    root_kind: &str,
    last: &str,
    path: &FieldPath,
    out: &mut dyn ReferenceSink,
) {
    if last == "azureFile" {
        collect_azure_file_reference(node, path, out);
    } else if matches!(last, "configMapKeyRef" | "secretKeyRef") {
        if let (Some(name), Some(key)) = (text(node, "name"), text(node, "key")) {
            let domain = if last == "secretKeyRef" {
                KeyDomain::Secret
            } else {
                KeyDomain::ConfigMapText
            };
            reference(
                if last == "secretKeyRef" { "Secret" } else { "ConfigMap" },
                name,
                Some(ReferencePredicate::KeyExists {
                    domain,
                    key: Protected::new(key.to_owned()),
                }),
                optional(node),
                RelationshipKind::Dependency,
                &path.child("key"),
                out,
            );
        }
    } else if matches!(last, "configMapRef" | "secretRef" | "nodePublishSecretRef") {
        if let Some(name) = text(node, "name") {
            reference(
                if last == "configMapRef" { "ConfigMap" } else { "Secret" },
                name,
                None,
                optional(node),
                RelationshipKind::Dependency,
                &path.child("name"),
                out,
            );
        }
    } else if matches!(last, "secret" | "configMap") {
        let kind = if last == "secret" { "Secret" } else { "ConfigMap" };
        let domain = if last == "secret" {
            KeyDomain::Secret
        } else {
            KeyDomain::ConfigMapTextOrBinary
        };
        let key = if text(node, "secretName").is_some() {
            "secretName"
        } else {
            "name"
        };
        if let Some(name) = text(node, key) {
            reference(
                kind,
                name,
                None,
                optional(node),
                RelationshipKind::Dependency,
                &path.child(key),
                out,
            );
            for (i, item) in items(node, "items").iter().enumerate() {
                if let Some(key) = text(item, "key") {
                    reference(
                        kind,
                        name,
                        Some(ReferencePredicate::KeyExists {
                            domain,
                            key: Protected::new(key.to_owned()),
                        }),
                        optional(node),
                        RelationshipKind::Dependency,
                        &path.child("items").child(i.to_string()).child("key"),
                        out,
                    );
                }
            }
        }
    } else if last == "persistentVolumeClaim" {
        if let Some(name) = text(node, "claimName") {
            reference(
                "PersistentVolumeClaim",
                name,
                None,
                Presence::Absent,
                RelationshipKind::Storage,
                &path.child("claimName"),
                out,
            );
        }
    }
    if root_kind == "StatefulSet" && path.0 == ["spec"] {
        if let Some(name) = text(node, "serviceName") {
            reference(
                "Service",
                name,
                Some(ReferencePredicate::HeadlessService),
                Presence::Absent,
                RelationshipKind::Dependency,
                &path.child("serviceName"),
                out,
            );
        }
    }
}

fn validate_native_scalars(node: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    for key in [
        "runAsUser",
        "runAsGroup",
        "fsGroup",
        "initialDelaySeconds",
        "partition",
        "start",
        "tolerationSeconds",
    ] {
        range(node, key, 0, i64::MAX, path, out);
    }
    for key in ["defaultMode", "mode"] {
        range(node, key, 0, 0o777, path, out);
    }
    for key in ["containerPort", "hostPort"] {
        range(node, key, i64::from(key != "hostPort"), 65535, path, out);
    }
    if present(node, "port") {
        port(node, "port", path, out);
    }
    if present(node, "maxSkew") {
        range(node, "maxSkew", 1, i64::MAX, path, out);
    }
    if present(node, "weight") {
        range(node, "weight", 1, 100, path, out);
    }
    if present(node, "scheme") {
        enumeration(node, "scheme", &["HTTP", "HTTPS"], path, out);
    }
    if present(node, "protocol") {
        enumeration(node, "protocol", &["TCP", "UDP", "SCTP"], path, out);
    }
    if present(node, "volumeMode") {
        enumeration(node, "volumeMode", &["Filesystem", "Block"], path, out);
    }
    if present(node, "fsGroupChangePolicy") {
        enumeration(node, "fsGroupChangePolicy", &["Always", "OnRootMismatch"], path, out);
    }
    if present(node, "whenUnsatisfiable") {
        enumeration(
            node,
            "whenUnsatisfiable",
            &["DoNotSchedule", "ScheduleAnyway"],
            path,
            out,
        );
    }
    if present(node, "mountPropagation") {
        enumeration(
            node,
            "mountPropagation",
            &["None", "HostToContainer", "Bidirectional"],
            path,
            out,
        );
    }
}
