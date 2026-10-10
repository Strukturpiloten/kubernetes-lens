//! Effective networking facts and only relationships supported by the frozen core.
use super::validation::{self, Profile};
use crate::{
    capability::KindId,
    diagnostic::{FieldPath, ResourceId},
    graph::{
        FactGap, FactState, LabelFacts, LocalSubject, NativeFact, PeerListPresence, Reference, ReferencePredicate,
        ReferenceScope, ReferenceSink, ReferenceTarget, RelationshipKind, ServicePortSelector, SubjectSelection,
    },
    model::GroupVersionKind,
    registry::{EncodeContext, FieldDecodeContext, ProjectionContext, codec::FieldCodec},
    syntax::{TreeNode, TreeValue},
    value::{LabelSelector, Presence},
};
use std::collections::BTreeMap;

pub(super) fn collect(kind: &str, ctx: &ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    if ctx
        .fields
        .processing
        .payload_array::<String>(8, ctx.fields.phase)
        .is_err()
        || ctx.fields.processing.payload(50, ctx.fields.phase).is_err()
    {
        return;
    }
    let labels_path = FieldPath(vec!["metadata".into(), "labels".into()]);
    if ctx
        .fields
        .processing
        .payload_array::<NativeFact>(3, ctx.fields.phase)
        .is_err()
    {
        return;
    }
    let labels = match ctx.tree.get("metadata") {
        None => Some(BTreeMap::new()),
        Some(metadata) if metadata.as_mapping().is_some() => match metadata.get("labels") {
            None => Some(BTreeMap::new()),
            Some(node) => <BTreeMap<String, String> as FieldCodec>::decode(node, &ctx.fields, &labels_path).ok(),
        },
        Some(_) => None,
    };
    let state = labels.map_or(FactState::Unknown(FactGap::IncompleteSuppliedEvidence), |values| {
        FactState::Known(LabelFacts {
            values,
            path: labels_path.clone(),
        })
    });
    ctx.emit_fact(
        NativeFact::SelectorSubject {
            subject: LocalSubject::Object,
            labels: ctx.state(&labels_path, state),
        },
        out,
    );
    if kind == "Service" {
        let path = FieldPath(vec!["spec".into(), "clusterIP".into()]);
        let state = ctx
            .tree
            .get_path(&path)
            .and_then(TreeNode::as_str)
            .map_or(FactState::Unknown(FactGap::IncompleteSuppliedEvidence), |value| {
                FactState::Known(value == "None")
            });
        ctx.emit_fact(
            NativeFact::ServiceHeadless {
                state: ctx.state(&path, state),
                path,
            },
            out,
        );
        let path = FieldPath(vec!["spec".into(), "ports".into()]);
        ctx.emit_fact(
            NativeFact::ServicePorts {
                state: ctx.state(
                    &path,
                    crate::graph::service_port_declarations(ctx.tree, &path, &ctx.fields),
                ),
                path,
            },
            out,
        );
    }
}
pub(super) fn protected<T: Profile>(value: &T, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
    if let (Ok(tree), Ok(capability)) = (value.encode(ctx, &FieldPath::default()), validation::profile::<T>()) {
        let fields = ctx.fields(crate::diagnostic::Phase::Analysis);
        let _ = validation::walk(&tree, &capability, &fields, &mut |node, path, _| {
            let private_string = matches!(node.value, TreeValue::String(_))
                && !path.0.is_empty()
                && !matches!(path.0[0].as_str(), "apiVersion" | "kind");
            // Map keys remain protected source evidence even when the map is empty.
            let private_map = node.as_mapping().is_some()
                && path.0.last().is_some_and(|part| {
                    matches!(
                        part.as_str(),
                        "selector" | "labels" | "annotations" | "matchLabels" | "topology" | "deprecatedTopology"
                    )
                });
            if (private_string || private_map)
                && validation::charge_path(&fields, path).is_ok()
                && fields.processing.payload_array::<FieldPath>(1, fields.phase).is_ok()
            {
                out.push(path.clone());
            }
        });
    }
}

fn emit(
    target: ReferenceTarget,
    scope: ReferenceScope,
    relation: RelationshipKind,
    path: &FieldPath,
    out: &mut dyn ReferenceSink,
) {
    out.push(Reference {
        from: ResourceId(0),
        path: path.clone(),
        relation,
        target,
        scope,
    });
}
fn checked(api: &str, kind: &str, name: &str, scope: ReferenceScope, path: &FieldPath, out: &mut dyn ReferenceSink) {
    if let Ok(gvk) = GroupVersionKind::new(api, kind) {
        emit(
            ReferenceTarget::CheckedObject {
                gvk,
                name: name.to_owned(),
                predicate: None,
                optional: Presence::Absent,
            },
            scope,
            RelationshipKind::Dependency,
            path,
            out,
        );
    }
}
fn object_reference(node: &TreeNode, path: &FieldPath, out: &mut dyn ReferenceSink) {
    if let (Some(api), Some(kind), Some(name)) = (
        validation::text(node, "apiVersion"),
        validation::text(node, "kind"),
        validation::text(node, "name"),
    ) {
        let scope = match node.get("namespace").map(|node| &node.value) {
            None => match GroupVersionKind::new(api, kind)
                .ok()
                .as_ref()
                .and_then(crate::capability::builtin_scope)
                .and_then(crate::model::ResourceScope::namespaced)
            {
                Some(true) => ReferenceScope::SameNamespace,
                Some(false) => ReferenceScope::Cluster,
                None => ReferenceScope::Unknown,
            },
            Some(TreeValue::Null) => ReferenceScope::Namespace(Presence::Null),
            Some(TreeValue::String(value)) => ReferenceScope::Namespace(Presence::Value(value.clone())),
            _ => ReferenceScope::Unknown,
        };
        if GroupVersionKind::new(api, kind).is_ok() {
            checked(api, kind, name, scope, &path.child("name"), out);
            return;
        }
    }
    if let Some(name) = validation::text(node, "name").filter(|name| !name.is_empty()) {
        // ObjectReference permits an omitted API version. Keep the named
        // dependency visible without manufacturing group, version or scope.
        emit(
            ReferenceTarget::Exact {
                gvk: None,
                name: name.to_owned(),
            },
            ReferenceScope::Unknown,
            RelationshipKind::Dependency,
            path,
            out,
        );
    }
}
fn selector(node: &TreeNode, path: &FieldPath, fields: &FieldDecodeContext, out: &mut dyn ReferenceSink) {
    if let Ok(selector) = LabelSelector::decode(node, fields, path) {
        // Keep decodeable but unsupported selectors as explicit graph edges. The
        // core validates the complete selector before permitting any matches.
        emit(
            ReferenceTarget::SubjectSelector {
                kinds: &[KindId::Pod],
                selector,
                selection: SubjectSelection::PodObjectsAndTemplates,
            },
            ReferenceScope::SameNamespace,
            RelationshipKind::Selector,
            path,
            out,
        );
    }
}
fn service_selector_references(tree: &TreeNode, fields: &FieldDecodeContext, out: &mut dyn ReferenceSink) {
    let path = FieldPath(vec!["spec".into(), "selector".into()]);
    let Some(source) = tree.get_path(&path) else {
        return;
    };
    if fields.processing.tree_copy(source, fields.phase).is_err() {
        return;
    }
    // An explicitly empty Service selector does not select all Pods.
    if let Some(entries) = tree
        .get_path(&path)
        .and_then(TreeNode::as_mapping)
        .filter(|entries| !entries.is_empty())
    {
        if let Some(labels) = entries
            .iter()
            .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
            .collect::<Option<BTreeMap<_, _>>>()
        {
            let selector = LabelSelector::from_match_labels(labels);
            if fields.processing.tree_copy(source, fields.phase).is_err() {
                return;
            }
            emit(
                ReferenceTarget::SubjectSelector {
                    kinds: &[KindId::Pod],
                    selector: selector.clone(),
                    selection: SubjectSelection::PodObjectsAndTemplates,
                },
                ReferenceScope::SameNamespace,
                RelationshipKind::Selector,
                &path,
                out,
            );
            if let Some(ports) = tree
                .get("spec")
                .and_then(|spec| spec.get("ports"))
                .and_then(TreeNode::as_sequence)
            {
                for (index, port) in ports.iter().enumerate() {
                    if out.exhausted()
                        || fields.processing.tree_copy(source, fields.phase).is_err()
                        || fields.processing.tree_copy(port, fields.phase).is_err()
                    {
                        return;
                    }
                    if let Some(name) = validation::text(port, "targetPort").filter(|name| !name.is_empty()) {
                        let leaf = FieldPath(vec![
                            "spec".into(),
                            "ports".into(),
                            index.to_string(),
                            "targetPort".into(),
                        ]);
                        emit(
                            ReferenceTarget::NamedServiceTargetPort {
                                selector: selector.clone(),
                                name: crate::value::Protected::new(name.to_owned()),
                                protocol: string_presence(port, "protocol"),
                            },
                            ReferenceScope::SameNamespace,
                            RelationshipKind::Selector,
                            &leaf,
                            out,
                        );
                    }
                }
            }
        }
    }
}
fn reference_field(kind: &str, last: &str) -> bool {
    matches!(
        last,
        "targetRef"
            | "service"
            | "serviceName"
            | "secretName"
            | "resource"
            | "ingressClassName"
            | "parameters"
            | "podSelector"
            | "ingress"
            | "egress"
    ) || kind == "EndpointSlice" && last == "labels"
}
pub(super) fn references<T: Profile>(value: &T, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
    let mut encoding = ctx.for_source(ctx.limits);
    encoding.include_unknown = true;
    let (Ok(tree), Ok(capability)) = (
        value.encode(&encoding, &FieldPath::default()),
        validation::profile::<T>(),
    ) else {
        return;
    };
    if T::KIND == "Service" {
        service_selector_references(&tree, &ctx.fields(crate::diagnostic::Phase::Analysis), out);
    }
    let fields = ctx.fields(crate::diagnostic::Phase::Analysis);
    let _ = validation::walk(&tree, &capability, &fields, &mut |node, path, pattern| {
        let last = pattern.0.last().map_or("", String::as_str);
        if out.exhausted() || fields.processing.exhausted() {
            return;
        }
        if reference_field(T::KIND, last) && fields.processing.tree_copy(node, fields.phase).is_err() {
            return;
        }
        if T::KIND == "EndpointSlice" && last == "labels" {
            if let Some(name) = validation::text(node, "kubernetes.io/service-name") {
                checked(
                    "v1",
                    "Service",
                    name,
                    ReferenceScope::SameNamespace,
                    &path.child("kubernetes.io/service-name"),
                    out,
                );
            }
        }
        if last == "targetRef" {
            object_reference(node, path, out);
        }
        if T::KIND == "Ingress" {
            if last == "service" {
                if let Some(name) = validation::text(node, "name") {
                    let leaf = path.child("port");
                    ingress_service(name, node.get("port"), &leaf, out);
                }
            }
            if last == "serviceName" {
                if let Some(name) = node.as_str() {
                    let parent = FieldPath(path.0[..path.0.len() - 1].to_vec());
                    let leaf = parent.child("servicePort");
                    ingress_service(name, tree.get_path(&leaf), &leaf, out);
                }
            }
            if last == "resource" && !matches!(node.value, TreeValue::Null) {
                group_reference(node, ReferenceScope::SameNamespace, path, out);
            }
            if last == "secretName" {
                if let Some(name) = node.as_str().filter(|value| !value.is_empty()) {
                    checked("v1", "Secret", name, ReferenceScope::SameNamespace, path, out);
                }
            }
            if last == "ingressClassName" {
                if let Some(name) = node.as_str() {
                    checked(
                        "networking.k8s.io/v1",
                        "IngressClass",
                        name,
                        ReferenceScope::Cluster,
                        path,
                        out,
                    );
                }
            }
        }
        if T::KIND == "IngressClass" && last == "parameters" && !matches!(node.value, TreeValue::Null) {
            let scope = match node.get("scope") {
                None => ReferenceScope::Cluster,
                Some(node) if node.as_str() == Some("Cluster") => ReferenceScope::Cluster,
                Some(scope_node) if scope_node.as_str() == Some("Namespace") => {
                    ReferenceScope::Namespace(string_presence(node, "namespace"))
                }
                _ => ReferenceScope::Unknown,
            };
            group_reference(node, scope, path, out);
        }
        if T::KIND == "NetworkPolicy" && pattern.0 == ["spec", "podSelector"] {
            selector(node, path, &ctx.fields(crate::diagnostic::Phase::Analysis), out);
        }
        if T::KIND == "NetworkPolicy" && pattern.0.len() == 2 && matches!(last, "ingress" | "egress") {
            policy_peers(
                node,
                path,
                if last == "ingress" { "from" } else { "to" },
                &ctx.fields(crate::diagnostic::Phase::Analysis),
                out,
            );
        }
    });
}

fn string_presence(node: &TreeNode, key: &str) -> Presence<String> {
    match node.get(key) {
        None => Presence::Absent,
        Some(value) if value.value == TreeValue::Null => Presence::Null,
        Some(value) => value
            .as_str()
            .map_or(Presence::Null, |value| Presence::Value(value.to_owned())),
    }
}
fn ingress_service(name: &str, port: Option<&TreeNode>, path: &FieldPath, out: &mut dyn ReferenceSink) {
    let selected = port.and_then(|port| match &port.value {
        TreeValue::Number(value) => value.parse().ok().map(ServicePortSelector::Number),
        TreeValue::String(value) => Some(ServicePortSelector::Name(crate::value::Protected::new(value.clone()))),
        TreeValue::Mapping(_) => validation::text(port, "name")
            .filter(|name| !name.is_empty())
            .map(|name| ServicePortSelector::Name(crate::value::Protected::new(name.to_owned())))
            .or_else(|| {
                port.get("number")
                    .and_then(|node| match &node.value {
                        TreeValue::Number(value) => value.parse::<i32>().ok(),
                        _ => None,
                    })
                    .filter(|number| *number != 0)
                    .map(ServicePortSelector::Number)
            }),
        _ => None,
    });
    let selected = selected.unwrap_or(ServicePortSelector::Unavailable(FactGap::IncompleteSuppliedEvidence));
    if let Ok(gvk) = GroupVersionKind::new("v1", "Service") {
        emit(
            ReferenceTarget::CheckedObject {
                gvk,
                name: name.to_owned(),
                predicate: Some(ReferencePredicate::ServicePortExists { port: selected }),
                optional: Presence::Absent,
            },
            ReferenceScope::SameNamespace,
            RelationshipKind::Dependency,
            path,
            out,
        );
    }
}
fn group_reference(node: &TreeNode, scope: ReferenceScope, path: &FieldPath, out: &mut dyn ReferenceSink) {
    emit(
        ReferenceTarget::GroupKindName {
            group: string_presence(node, "apiGroup"),
            kind: validation::text(node, "kind").unwrap_or("").to_owned(),
            name: validation::text(node, "name").unwrap_or("").to_owned(),
        },
        scope,
        RelationshipKind::Dependency,
        path,
        out,
    );
}
fn policy_peers(
    node: &TreeNode,
    path: &FieldPath,
    key: &str,
    fields: &FieldDecodeContext,
    out: &mut dyn ReferenceSink,
) {
    let Some(rules) = node.as_sequence() else { return };
    for (index, rule) in rules.iter().enumerate() {
        if out.exhausted() || fields.processing.work(1, fields.phase).is_err() {
            return;
        }
        let list = path.child(index.to_string()).child(key);
        if rule.as_mapping().is_none() {
            continue;
        }
        let presence = match rule.get(key) {
            None => Some(PeerListPresence::Absent),
            Some(value) if value.value == TreeValue::Null => Some(PeerListPresence::Null),
            Some(value) if value.as_sequence().is_some_and(<[_]>::is_empty) => Some(PeerListPresence::ExplicitEmpty),
            _ => None,
        };
        if let Some(presence) = presence {
            emit(
                ReferenceTarget::NetworkPolicyAllPeers { presence },
                ReferenceScope::SameNamespace,
                RelationshipKind::Selector,
                &list,
                out,
            );
            continue;
        }
        let Some(peers) = rule.get(key).and_then(TreeNode::as_sequence) else {
            continue;
        };
        for (index, peer) in peers.iter().enumerate() {
            if out.exhausted() || fields.processing.work(1, fields.phase).is_err() {
                return;
            }
            let leaf = list.child(index.to_string());
            let selector = |key| match peer.get(key) {
                None => Presence::Absent,
                Some(value) if value.value == TreeValue::Null => Presence::Null,
                Some(value) => {
                    LabelSelector::decode(value, fields, &leaf.child(key)).map_or(Presence::Null, Presence::Value)
                }
            };
            let mut namespace_selector = selector("namespaceSelector");
            let mut pod_selector = selector("podSelector");
            if peer.get("ipBlock").is_some() {
                if namespace_selector.is_absent() && pod_selector.is_absent() {
                    emit(
                        ReferenceTarget::External {
                            kind: crate::graph::ExternalRefKind::Remote,
                        },
                        ReferenceScope::Unknown,
                        RelationshipKind::Selector,
                        &leaf.child("ipBlock"),
                        out,
                    );
                    continue;
                }
                namespace_selector = Presence::Null;
                pod_selector = Presence::Null;
            }
            emit(
                ReferenceTarget::NetworkPolicyPeer {
                    namespace_selector,
                    pod_selector,
                },
                ReferenceScope::SameNamespace,
                RelationshipKind::Selector,
                &leaf,
                out,
            );
        }
    }
}
