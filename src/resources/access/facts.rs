//! Supplied access relationships only; no permission, scale, enforcement or runtime inference.
use super::validation::{Profile, nodes, present, sequence, text};
use crate::{
    capability::KindId,
    diagnostic::{FieldPath, Finding, Phase, ResourceId},
    graph::{
        ExternalRefKind, FactGap, FactState, LabelFacts, LocalSubject, NativeFact, Reference, ReferenceScope,
        ReferenceSink, ReferenceTarget, RelationshipKind, SubjectSelection,
    },
    model::GroupVersionKind,
    registry::{EncodeContext, FieldDecodeContext, ProjectionContext, codec::FieldCodec},
    resources::common::{child_path, copy_path, index_path},
    syntax::{TreeNode, TreeValue},
    value::{LabelSelector, Presence},
};
use std::collections::BTreeMap;

fn path(fields: &FieldDecodeContext, parts: &[&str]) -> Result<FieldPath, Finding> {
    let mut path = FieldPath::default();
    for part in parts {
        path = child_path(&path, part, fields)?;
    }
    Ok(path)
}
fn scan(node: &TreeNode, fields: &FieldDecodeContext) -> Result<(), Finding> {
    fields.processing.work(1, fields.phase)?;
    match &node.value {
        TreeValue::String(value) | TreeValue::Number(value) => fields.processing.work(value.len(), fields.phase)?,
        TreeValue::Sequence(items) => {
            for item in items {
                scan(item, fields)?;
            }
        }
        TreeValue::Mapping(items) => {
            for (key, item) in items {
                fields.processing.work(key.len(), fields.phase)?;
                scan(item, fields)?;
            }
        }
        TreeValue::Tagged(tag, item) => {
            fields.processing.work(tag.len(), fields.phase)?;
            scan(item, fields)?;
        }
        TreeValue::Null | TreeValue::Bool(_) => {}
    }
    Ok(())
}

pub(super) fn native(ctx: &ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    let fields = &ctx.fields;
    if scan(ctx.tree, fields).is_err() {
        return;
    }
    let Ok(path) = path(fields, &["metadata", "labels"]) else {
        return;
    };
    let labels = match ctx.tree.get("metadata") {
        None => Some(&[][..]),
        Some(metadata) if metadata.as_mapping().is_some() => match metadata.get("labels") {
            None => Some(&[][..]),
            Some(labels) => labels.as_mapping(),
        },
        _ => None,
    };
    let mut known = labels.is_some();
    let mut values = BTreeMap::new();
    if let Some(labels) = labels {
        for (key, value) in labels {
            if fields.processing.work(1, fields.phase).is_err() {
                return;
            }
            let Some(value) = value.as_str() else {
                known = false;
                break;
            };
            if fields.processing.work(key.len(), fields.phase).is_err()
                || fields.processing.work(value.len(), fields.phase).is_err()
                || fields
                    .processing
                    .payload_array::<(String, String)>(1, fields.phase)
                    .is_err()
                || fields
                    .processing
                    .payload_sizes([key.len(), value.len()], fields.phase)
                    .is_err()
            {
                return;
            }
            values.insert(key.clone(), value.to_owned());
        }
    }
    let state = if known {
        let Ok(owned_path) = copy_path(&path, fields) else {
            return;
        };
        FactState::Known(LabelFacts {
            values,
            path: owned_path,
        })
    } else {
        FactState::Unknown(FactGap::IncompleteSuppliedEvidence)
    };
    if fields.processing.payload_array::<NativeFact>(1, fields.phase).is_err() {
        return;
    }
    let labels = ctx.state(&path, state);
    ctx.emit_fact(
        NativeFact::SelectorSubject {
            subject: LocalSubject::Object,
            labels,
        },
        out,
    );
}

struct References<'a> {
    fields: FieldDecodeContext,
    out: &'a mut dyn ReferenceSink,
}
impl References<'_> {
    fn charge(&self, units: usize) -> bool {
        !self.out.exhausted() && self.fields.processing.work(units, self.fields.phase).is_ok()
    }
    fn string(&self, value: &str) -> Option<String> {
        if !self.charge(value.len().saturating_add(1))
            || self.fields.processing.payload(value.len(), self.fields.phase).is_err()
        {
            return None;
        }
        Some(value.to_owned())
    }
    fn path(&self, parts: &[&str]) -> Option<FieldPath> {
        if !self.charge(1) {
            return None;
        }
        path(&self.fields, parts).ok()
    }
    fn item(&self, parent: &FieldPath, index: usize) -> Option<FieldPath> {
        if !self.charge(1) {
            return None;
        }
        index_path(parent, index, &self.fields).ok()
    }
    fn emit(&mut self, target: ReferenceTarget, scope: ReferenceScope, relation: RelationshipKind, path: FieldPath) {
        if !self.charge(1)
            || self
                .fields
                .processing
                .payload_array::<Reference>(1, self.fields.phase)
                .is_err()
        {
            return;
        }
        self.out.push(Reference {
            from: ResourceId(0),
            path,
            relation,
            target,
            scope,
        });
    }
    fn named(&mut self, api: &str, kind: &str, name: &str, scope: ReferenceScope, path: FieldPath) {
        if !self.charge(api.len().saturating_add(kind.len()).saturating_add(1))
            || self
                .fields
                .processing
                .payload_array::<String>(3, self.fields.phase)
                .is_err()
            || self
                .fields
                .processing
                .payload_sizes([api.len(), kind.len()], self.fields.phase)
                .is_err()
        {
            return;
        }
        let Some(name) = self.string(name) else {
            return;
        };
        if let Ok(gvk) = GroupVersionKind::new(api, kind) {
            self.emit(
                ReferenceTarget::CheckedObject {
                    gvk,
                    name,
                    predicate: None,
                    optional: Presence::Absent,
                },
                scope,
                RelationshipKind::Identity,
                path,
            );
        }
    }
    fn unsupported(&mut self, name: &str, path: FieldPath) {
        let Some(name) = self.string(name) else {
            return;
        };
        self.emit(
            ReferenceTarget::Exact { gvk: None, name },
            ReferenceScope::Unknown,
            RelationshipKind::Identity,
            path,
        );
    }
    fn external(&mut self, path: FieldPath) {
        self.emit(
            ReferenceTarget::External {
                kind: ExternalRefKind::Other,
            },
            ReferenceScope::Unknown,
            RelationshipKind::Identity,
            path,
        );
    }
    fn namespace(&self, namespace: Option<&str>, fallback: ReferenceScope) -> Option<ReferenceScope> {
        match namespace {
            Some(value) if !value.is_empty() => self
                .string(value)
                .map(|value| ReferenceScope::Namespace(Presence::Value(value))),
            _ => self.charge(1).then_some(fallback),
        }
    }
}
fn binding(tree: &TreeNode, kind: &str, refs: &mut References<'_>) {
    if !refs.charge(1) {
        return;
    }
    if let Some(role) = tree.get("roleRef") {
        let Some(path) = refs.path(&["roleRef"]) else {
            return;
        };
        let name = text(role, "name").unwrap_or_default();
        let role_kind = text(role, "kind");
        if text(role, "apiGroup") == Some("rbac.authorization.k8s.io")
            && matches!(role_kind, Some("Role" | "ClusterRole"))
            && (!kind.starts_with("Cluster") || role_kind == Some("ClusterRole"))
        {
            let role_kind = role_kind.unwrap_or_default();
            refs.named(
                "rbac.authorization.k8s.io/v1",
                role_kind,
                name,
                if role_kind == "ClusterRole" {
                    ReferenceScope::Cluster
                } else {
                    ReferenceScope::SameNamespace
                },
                path,
            );
        } else {
            refs.unsupported(name, path);
        }
    }
    let Some(parent) = refs.path(&["subjects"]) else {
        return;
    };
    for (index, subject) in sequence(tree, "subjects").iter().enumerate() {
        let Some(path) = refs.item(&parent, index) else {
            return;
        };
        match text(subject, "kind") {
            Some("User" | "Group") => refs.external(path),
            Some("ServiceAccount") => {
                if text(subject, "apiGroup").is_some_and(|group| !group.is_empty()) {
                    refs.unsupported(text(subject, "name").unwrap_or_default(), path);
                    continue;
                }
                let fallback = if kind.starts_with("Cluster") {
                    ReferenceScope::Unknown
                } else {
                    ReferenceScope::SameNamespace
                };
                let Some(scope) = refs.namespace(text(subject, "namespace"), fallback) else {
                    return;
                };
                if let Some(name) = text(subject, "name") {
                    refs.named("v1", "ServiceAccount", name, scope, path);
                }
            }
            _ => {}
        }
    }
}
fn selectors(tree: &TreeNode, kind: &str, api: &str, refs: &mut References<'_>) {
    if !refs.charge(1) {
        return;
    }
    let (pointer, kinds, scope, selection) = match kind {
        "ClusterRole" => (
            "/aggregationRule/clusterRoleSelectors/*",
            &[KindId::ClusterRole][..],
            ReferenceScope::Cluster,
            SubjectSelection::Objects,
        ),
        "PodDisruptionBudget" => (
            "/spec/selector",
            &[KindId::Pod][..],
            ReferenceScope::SameNamespace,
            SubjectSelection::PodObjectsOnly,
        ),
        _ => return,
    };
    for (path, node) in nodes(tree, pointer, &refs.fields) {
        if !refs.charge(1) {
            return;
        }
        let Ok(selector) = LabelSelector::decode(node, &refs.fields, &path) else {
            continue;
        };
        let empty = selector.match_labels.value().is_none_or(BTreeMap::is_empty)
            && selector.match_expressions.value().is_none_or(Vec::is_empty);
        let kinds = if kind == "PodDisruptionBudget" && api == "policy/v1beta1" && empty {
            &[][..]
        } else {
            kinds
        };
        refs.emit(
            ReferenceTarget::SubjectSelector {
                kinds,
                selector,
                selection,
            },
            scope.clone(),
            RelationshipKind::Selector,
            path,
        );
    }
}
fn service_account(tree: &TreeNode, refs: &mut References<'_>) {
    for key in ["secrets", "imagePullSecrets"] {
        let Some(parent) = refs.path(&[key]) else {
            return;
        };
        for (index, reference) in sequence(tree, key).iter().enumerate() {
            let Some(mut path) = refs.item(&parent, index) else {
                return;
            };
            if text(reference, "kind").is_some_and(|kind| kind != "Secret")
                || text(reference, "apiVersion").is_some_and(|api| api != "v1")
            {
                refs.external(path);
                continue;
            }
            if let Some(name) = text(reference, "name") {
                let Some(scope) = refs.namespace(text(reference, "namespace"), ReferenceScope::SameNamespace) else {
                    return;
                };
                let Ok(child) = child_path(&path, "name", &refs.fields) else {
                    return;
                };
                path = child;
                refs.named("v1", "Secret", name, scope, path);
            }
        }
    }
}
fn scale_target(tree: &TreeNode, refs: &mut References<'_>) {
    let Some(path) = refs.path(&["spec", "scaleTargetRef"]) else {
        return;
    };
    let Some(reference) = tree.get_path(&path) else {
        return;
    };
    if let (Some(kind), Some(name)) = (text(reference, "kind"), text(reference, "name")) {
        let Some(api) = text(reference, "apiVersion") else {
            refs.external(path);
            return;
        };
        if !refs.charge(api.len().saturating_add(kind.len()).saturating_add(1))
            || refs
                .fields
                .processing
                .payload_array::<String>(3, refs.fields.phase)
                .is_err()
            || refs
                .fields
                .processing
                .payload_sizes([api.len(), kind.len()], refs.fields.phase)
                .is_err()
        {
            return;
        }
        let Ok(gvk) = GroupVersionKind::new(api, kind) else {
            refs.external(path);
            return;
        };
        let Some(name) = refs.string(name) else {
            return;
        };
        refs.emit(
            ReferenceTarget::Exact { gvk: Some(gvk), name },
            ReferenceScope::SameNamespace,
            RelationshipKind::Dependency,
            path,
        );
    }
}
pub(super) fn references<T: Profile>(resource: &T, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
    let mut refs = References {
        fields: ctx.fields(Phase::Analysis),
        out,
    };
    if !refs.charge(1) {
        return;
    }
    let mut encoding = ctx.for_source(ctx.limits);
    encoding.include_unknown = true;
    let Ok(tree) = resource.encode(&encoding, &FieldPath::default()) else {
        return;
    };
    if scan(&tree, &refs.fields).is_err() || !refs.charge(1) {
        return;
    }
    if let Some(namespace) = tree.get("metadata").and_then(|meta| text(meta, "namespace")) {
        let Some(path) = refs.path(&["metadata", "namespace"]) else {
            return;
        };
        refs.named("v1", "Namespace", namespace, ReferenceScope::Cluster, path);
    }
    if !refs.charge(1) {
        return;
    }
    match T::KIND {
        "RoleBinding" | "ClusterRoleBinding" => binding(&tree, T::KIND, &mut refs),
        "ServiceAccount" => service_account(&tree, &mut refs),
        "HorizontalPodAutoscaler" => scale_target(&tree, &mut refs),
        "RuntimeClass" if present(&tree, "handler") => {
            if let Some(path) = refs.path(&["handler"]) {
                refs.external(path);
            }
        }
        "PodSecurityPolicy" => {
            for (path, value) in nodes(&tree, "/spec/runtimeClass/allowedRuntimeClassNames/*", &refs.fields) {
                if !refs.charge(1) {
                    return;
                }
                if let Some(name) = value.as_str() {
                    if name == "*" {
                        refs.external(path);
                    } else {
                        refs.named("node.k8s.io/v1", "RuntimeClass", name, ReferenceScope::Cluster, path);
                    }
                }
            }
        }
        _ => {}
    }
    selectors(&tree, T::KIND, T::API, &mut refs);
}

/// Explicit opaque descendants remain private, including those held by shared selectors.
pub(super) fn protected<T: Profile>(resource: &T, inherited: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
    fn visit(
        tree: &TreeNode,
        path: &FieldPath,
        patterns: &[FieldPath],
        fields: &FieldDecodeContext,
        out: &mut Vec<FieldPath>,
    ) -> Result<(), Finding> {
        fields.processing.work(1, fields.phase)?;
        let mut known = path.0.is_empty() || path.0.len() == 1 && matches!(path.0[0].as_str(), "apiVersion" | "kind");
        if !known {
            for pattern in patterns {
                fields
                    .processing
                    .work(pattern.0.len().saturating_add(1), fields.phase)?;
                if pattern.0.len() != path.0.len() {
                    continue;
                }
                let mut matches = true;
                for (expected, actual) in pattern.0.iter().zip(&path.0) {
                    fields.processing.work(
                        expected.len().saturating_add(actual.len()).saturating_add(1),
                        fields.phase,
                    )?;
                    if expected != "*" && expected != actual {
                        matches = false;
                        break;
                    }
                }
                if matches {
                    known = true;
                    break;
                }
            }
        }
        if !known {
            fields.processing.payload_array::<FieldPath>(1, fields.phase)?;
            out.push(copy_path(path, fields)?);
            return Ok(());
        }
        match &tree.value {
            TreeValue::Mapping(items) => {
                for (key, value) in items {
                    let child = child_path(path, key, fields)?;
                    visit(value, &child, patterns, fields, out)?;
                }
            }
            TreeValue::Sequence(items) => {
                for (index, value) in items.iter().enumerate() {
                    let child = index_path(path, index, fields)?;
                    visit(value, &child, patterns, fields, out)?;
                }
            }
            _ => {}
        }
        Ok(())
    }
    fn collect<T: Profile>(
        resource: &T,
        inherited: &EncodeContext<'_>,
        out: &mut Vec<FieldPath>,
    ) -> Result<(), Finding> {
        let fields = inherited.fields(Phase::Generation);
        fields.processing.work(1, fields.phase)?;
        let mut ctx = EncodeContext::in_operation(
            inherited.target,
            inherited.limits,
            inherited.budget.processing().clone(),
        );
        ctx.include_unknown = true;
        let tree = resource.encode(&ctx, &FieldPath::default())?;
        fields.processing.work(
            T::API.len().saturating_add(T::KIND.len()).saturating_add(1),
            fields.phase,
        )?;
        fields.processing.payload_array::<String>(3, fields.phase)?;
        fields
            .processing
            .payload_sizes([T::API.len(), T::KIND.len()], fields.phase)?;
        let gvk = GroupVersionKind::new(T::API, T::KIND)?;
        let capability = super::capabilities::for_api(gvk)?;
        let mut patterns = Vec::new();
        for field in capability.fields {
            fields
                .processing
                .work(field.path.len().saturating_add(1), fields.phase)?;
            fields.processing.payload(field.path.len(), fields.phase)?;
            fields
                .processing
                .payload_array::<String>(field.path.split('/').count(), fields.phase)?;
            fields.processing.payload_array::<FieldPath>(1, fields.phase)?;
            patterns.push(FieldPath::parse(field.path)?);
        }
        visit(&tree, &FieldPath::default(), &patterns, &fields, out)
    }
    if collect(resource, inherited, out).is_err() {
        // A fixed empty-path privacy sentinel protects the whole resource on failure;
        // it is not ordinary retained path evidence and never exposes a source value.
        out.push(FieldPath::default());
    }
}

#[cfg(test)]
#[path = "processing_tests.rs"]
mod processing_tests;
