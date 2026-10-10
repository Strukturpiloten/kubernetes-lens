mod static_checks;
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::{ExternalRefKind, Reference, ReferenceScope, ReferenceSink, ReferenceTarget, RelationshipKind},
    model::{GroupVersionKind, ResourceScope},
    registry::{FindingSink, ValidationContext},
    source::{ObservationPath, root_observation_paths},
    syntax::TreeNode,
};
pub(super) use static_checks::StaticChecks;

fn error(out: &mut dyn FindingSink, path: &FieldPath) {
    out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
}
fn text<'a>(node: &'a TreeNode, field: &str) -> Option<&'a str> {
    node.get(field).and_then(TreeNode::as_str)
}
fn external(path: FieldPath, relation: RelationshipKind) -> Reference {
    Reference {
        from: crate::diagnostic::ResourceId(0),
        path,
        relation,
        target: ReferenceTarget::External {
            kind: ExternalRefKind::Storage,
        },
        scope: ReferenceScope::Unknown,
    }
}
fn explicit_secret_ref(secret: &TreeNode, path: FieldPath, out: &mut dyn ReferenceSink) {
    let Some(name) = text(secret, "name").filter(|name| !name.is_empty()) else {
        return;
    };
    if secret
        .get("namespace")
        .and_then(TreeNode::as_str)
        .is_some_and(str::is_empty)
    {
        return;
    }
    let Ok(gvk) = GroupVersionKind::new("v1", "Secret") else {
        return;
    };
    out.push(Reference {
        from: crate::diagnostic::ResourceId(0),
        path,
        relation: RelationshipKind::Identity,
        target: ReferenceTarget::CheckedObject {
            gvk,
            name: name.to_owned(),
            predicate: None,
            optional: crate::value::Presence::Absent,
        },
        scope: secret
            .get("namespace")
            .and_then(TreeNode::as_str)
            .map_or(ReferenceScope::Unknown, |namespace| {
                ReferenceScope::Namespace(crate::value::Presence::Value(namespace.to_owned()))
            }),
    });
}
fn storageos_secret_identity_is_supported(secret: &TreeNode) -> bool {
    [("apiVersion", "v1"), ("kind", "Secret")]
        .into_iter()
        .all(|(field, expected)| match secret.get(field) {
            None => true,
            Some(value) => value.as_str() == Some(expected),
        })
}
fn secret_name_ref(name: &str, path: FieldPath, namespace: Option<&str>, out: &mut dyn ReferenceSink) {
    if name.is_empty() || namespace.is_some_and(str::is_empty) {
        return;
    }
    let Ok(gvk) = GroupVersionKind::new("v1", "Secret") else {
        return;
    };
    out.push(Reference {
        from: crate::diagnostic::ResourceId(0),
        path,
        relation: RelationshipKind::Identity,
        target: ReferenceTarget::CheckedObject {
            gvk,
            name: name.to_owned(),
            predicate: None,
            optional: crate::value::Presence::Absent,
        },
        scope: namespace.map_or(ReferenceScope::Unknown, |namespace| {
            ReferenceScope::Namespace(crate::value::Presence::Value(namespace.to_owned()))
        }),
    });
}
pub(super) fn references(kind: &str, tree: &TreeNode, out: &mut dyn ReferenceSink) {
    match kind {
        "PersistentVolumeClaim" => claim_references(tree, out),
        "PersistentVolume" => volume_references(tree, out),
        "StorageClass" if text(tree, "provisioner").is_some_and(|value| !value.is_empty()) => {
            out.push(external(
                FieldPath(vec!["provisioner".into()]),
                RelationshipKind::Storage,
            ));
        }
        _ => {}
    }
}

fn claim_references(tree: &TreeNode, out: &mut dyn ReferenceSink) {
    if let Some(spec) = tree.get("spec") {
        if let Some(name) = text(spec, "volumeName").filter(|name| !name.is_empty()) {
            if let Ok(gvk) = GroupVersionKind::new("v1", "PersistentVolume") {
                out.push(Reference {
                    from: crate::diagnostic::ResourceId(0),
                    path: FieldPath(vec!["spec".into(), "volumeName".into()]),
                    relation: RelationshipKind::Storage,
                    target: ReferenceTarget::CheckedObject {
                        gvk,
                        name: name.to_owned(),
                        predicate: None,
                        optional: crate::value::Presence::Absent,
                    },
                    scope: ReferenceScope::Cluster,
                });
            }
        }
        if let Some(name) = text(spec, "storageClassName").filter(|name| !name.is_empty()) {
            if let Ok(gvk) = GroupVersionKind::new("storage.k8s.io/v1", "StorageClass") {
                out.push(Reference {
                    from: crate::diagnostic::ResourceId(0),
                    path: FieldPath(vec!["spec".into(), "storageClassName".into()]),
                    relation: RelationshipKind::Storage,
                    target: ReferenceTarget::CheckedObject {
                        gvk,
                        name: name.to_owned(),
                        predicate: None,
                        optional: crate::value::Presence::Absent,
                    },
                    scope: ReferenceScope::Cluster,
                });
            }
        }
        if let Some(source) = spec.get("dataSource") {
            if let (Some(target_name), Some(target_kind)) = (text(source, "name"), text(source, "kind")) {
                let api_group = source
                    .get("apiGroup")
                    .and_then(TreeNode::as_str)
                    .filter(|g| !g.is_empty());
                if target_kind == "PersistentVolumeClaim" && api_group.is_none() {
                    if let Ok(gvk) = GroupVersionKind::new("v1", target_kind) {
                        out.push(Reference {
                            from: crate::diagnostic::ResourceId(0),
                            path: FieldPath(vec!["spec".into(), "dataSource".into()]),
                            relation: RelationshipKind::Storage,
                            target: ReferenceTarget::CheckedObject {
                                gvk,
                                name: target_name.to_owned(),
                                predicate: None,
                                optional: crate::value::Presence::Absent,
                            },
                            scope: ReferenceScope::SameNamespace,
                        });
                    }
                } else {
                    out.push(external(
                        FieldPath(vec!["spec".into(), "dataSource".into()]),
                        RelationshipKind::Storage,
                    ));
                }
            }
        }
    }
}

fn volume_references(tree: &TreeNode, out: &mut dyn ReferenceSink) {
    let spec = tree.get("spec");
    if let Some(claim) = spec.and_then(|spec| spec.get("claimRef")) {
        if let (Some(claim_name), Some(namespace)) = (text(claim, "name"), text(claim, "namespace")) {
            if let Ok(gvk) = GroupVersionKind::new("v1", "PersistentVolumeClaim") {
                out.push(Reference {
                    from: crate::diagnostic::ResourceId(0),
                    path: FieldPath(vec!["spec".into(), "claimRef".into()]),
                    relation: RelationshipKind::Storage,
                    target: ReferenceTarget::CheckedObject {
                        gvk,
                        name: claim_name.to_owned(),
                        predicate: None,
                        optional: crate::value::Presence::Absent,
                    },
                    scope: ReferenceScope::Namespace(crate::value::Presence::Value(namespace.to_owned())),
                });
            }
        }
    }
    if let Some(driver) = spec
        .and_then(|spec| spec.get("csi"))
        .and_then(|csi| csi.get("driver"))
        .and_then(TreeNode::as_str)
    {
        if !driver.is_empty() {
            out.push(external(
                FieldPath(vec!["spec".into(), "csi".into(), "driver".into()]),
                RelationshipKind::Storage,
            ));
        }
    }
    if let Some(csi) = spec.and_then(|spec| spec.get("csi")) {
        for field in [
            "controllerExpandSecretRef",
            "controllerPublishSecretRef",
            "nodePublishSecretRef",
            "nodeStageSecretRef",
        ] {
            if let Some(secret) = csi.get(field) {
                explicit_secret_ref(secret, FieldPath(vec!["spec".into(), "csi".into(), field.into()]), out);
            }
        }
    }
    if let Some(spec) = spec {
        for (source, field) in [
            ("azureFile", "secretName"),
            ("cephfs", "secretRef"),
            ("cinder", "secretRef"),
            ("flexVolume", "secretRef"),
            ("iscsi", "secretRef"),
            ("rbd", "secretRef"),
            ("scaleIO", "secretRef"),
        ] {
            if let Some(source_node) = spec.get(source) {
                let path = FieldPath(vec!["spec".into(), source.into(), field.into()]);
                if field == "secretName" {
                    if let Some(name) = text(source_node, field) {
                        let namespace = text(source_node, "secretNamespace");
                        secret_name_ref(name, path, namespace, out);
                    }
                } else if let Some(secret) = source_node.get(field) {
                    explicit_secret_ref(secret, path, out);
                }
            }
        }
        if let Some(secret) = spec
            .get("storageos")
            .and_then(|source| source.get("secretRef"))
            .filter(|secret| storageos_secret_identity_is_supported(secret))
        {
            explicit_secret_ref(
                secret,
                FieldPath(vec!["spec".into(), "storageos".into(), "secretRef".into()]),
                out,
            );
        }
    }
}

pub(super) fn protected_paths(
    kind: &str,
    tree: &TreeNode,
    ctx: &crate::registry::EncodeContext<'_>,
    out: &mut Vec<FieldPath>,
) {
    let fields: &[&str] = match kind {
        "Secret" => &["data", "stringData"],
        "ConfigMap" => &["data", "binaryData"],
        _ => return,
    };
    let fields_context = ctx.fields(Phase::Generation);
    for field in fields {
        let Some(entries) = tree.get(field).and_then(TreeNode::as_mapping) else {
            continue;
        };
        for (key, _) in entries {
            if fields_context
                .processing
                .payload(size_of::<FieldPath>(), Phase::Generation)
                .is_err()
            {
                return;
            }
            let Ok(parent) = crate::resources::common::child_path(&FieldPath::default(), field, &fields_context) else {
                return;
            };
            let Ok(path) = crate::resources::common::child_path(&parent, key, &fields_context) else {
                return;
            };
            out.push(path);
        }
    }
}

pub(super) fn observations(_kind: &str, _tree: &TreeNode, out: &mut Vec<ObservationPath>) {
    out.extend(root_observation_paths());
}

fn validate_metadata(scope: ResourceScope, tree: &TreeNode, out: &mut dyn FindingSink) {
    let name = tree
        .get("metadata")
        .and_then(|m| m.get("name"))
        .and_then(TreeNode::as_str);
    let generated = tree
        .get("metadata")
        .and_then(|m| m.get("generateName"))
        .and_then(TreeNode::as_str);
    if name.is_none_or(str::is_empty) && generated.is_none_or(str::is_empty) {
        error(out, &FieldPath(vec!["metadata".into(), "name".into()]));
    }
    if scope == ResourceScope::Namespaced
        && tree.get("metadata").is_some_and(|m| {
            m.get("namespace")
                .is_some_and(|n| n.as_str().is_some_and(str::is_empty))
        })
    {
        error(out, &FieldPath(vec!["metadata".into(), "namespace".into()]));
    }
}

pub(super) fn validate(
    kind: &str,
    _api: &str,
    scope: ResourceScope,
    tree: &TreeNode,
    ctx: &ValidationContext<'_>,
    out: &mut dyn FindingSink,
) {
    validate_metadata(scope, tree, out);
    match kind {
        "PersistentVolumeClaim" => {
            if let Some(spec) = tree.get("spec") {
                validate_volume_mode(
                    spec.get("volumeMode"),
                    &FieldPath(vec!["spec".into(), "volumeMode".into()]),
                    out,
                );
            }
        }
        "PersistentVolume" => {
            if let Some(spec) = tree.get("spec") {
                validate_volume_mode(
                    spec.get("volumeMode"),
                    &FieldPath(vec!["spec".into(), "volumeMode".into()]),
                    out,
                );
                if text(spec, "persistentVolumeReclaimPolicy")
                    .is_some_and(|v| !matches!(v, "" | "Retain" | "Delete" | "Recycle"))
                {
                    error(
                        out,
                        &FieldPath(vec!["spec".into(), "persistentVolumeReclaimPolicy".into()]),
                    );
                }
            }
        }
        "StorageClass" => {
            if text(tree, "provisioner").is_none_or(str::is_empty) {
                error(out, &FieldPath(vec!["provisioner".into()]));
            }
            if text(tree, "reclaimPolicy").is_some_and(|v| !matches!(v, "Retain" | "Delete")) {
                error(out, &FieldPath(vec!["reclaimPolicy".into()]));
            }
            if text(tree, "volumeBindingMode").is_some_and(|v| !matches!(v, "Immediate" | "WaitForFirstConsumer")) {
                error(out, &FieldPath(vec!["volumeBindingMode".into()]));
            }
        }
        _ => {}
    }
    // Feature/target-specific constraints remain absent unless the selected profile establishes them.
    let _ = ctx;
}

fn validate_volume_mode(value: Option<&TreeNode>, path: &FieldPath, out: &mut dyn FindingSink) {
    if value.is_some_and(|node| {
        !matches!(node.value, crate::syntax::TreeValue::Null) && !matches!(node.as_str(), Some("Filesystem" | "Block"))
    }) {
        error(out, path);
    }
}
