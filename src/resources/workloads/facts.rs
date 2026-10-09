//! Exact supplied workload subjects and symbolic claims, never predicted runtime objects.
use crate::{
    diagnostic::FieldPath,
    graph::{ClaimPatternDraft, FactGap, FactState, LabelFacts, LocalSubject, NativeFact, PortFact, TemplateKind},
    registry::ProjectionContext,
    source::{ObservationPath, ObservationRole, append_metadata_observation_paths},
    syntax::{TreeNode, TreeValue},
    value::{Presence, Protected},
};
use std::collections::BTreeMap;
fn path(parts: &[&str]) -> FieldPath {
    FieldPath(parts.iter().map(|s| (*s).to_owned()).collect())
}
fn string(node: Option<&TreeNode>) -> Presence<Protected<String>> {
    match node.map(|n| &n.value) {
        Some(TreeValue::String(v)) => Presence::Value(Protected::new(v.clone())),
        Some(TreeValue::Null) => Presence::Null,
        _ => Presence::Absent,
    }
}
fn integer(node: Option<&TreeNode>) -> Presence<i32> {
    match node.map(|n| &n.value) {
        Some(TreeValue::Number(v)) => v.parse().map_or(Presence::Absent, Presence::Value),
        Some(TreeValue::Null) => Presence::Null,
        _ => Presence::Absent,
    }
}
fn pod_path(kind: &str) -> FieldPath {
    match kind {
        "Pod" => path(&["spec"]),
        "CronJob" => path(&["spec", "jobTemplate", "spec", "template", "spec"]),
        _ => path(&["spec", "template", "spec"]),
    }
}
/// Optional metadata/labels absence is exact empty evidence only for an existing
/// admitted subject object. Malformed/null maps and missing subjects stay unknown.
fn supplied_labels(tree: &TreeNode, subject_path: &FieldPath, labels_path: &FieldPath) -> FactState<LabelFacts> {
    let unknown = || FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
    let Some(subject) = tree.get_path(subject_path).filter(|node| node.as_mapping().is_some()) else {
        return unknown();
    };
    let values = match subject.get("metadata") {
        None => Some(BTreeMap::new()),
        Some(metadata) if metadata.as_mapping().is_some() => match metadata.get("labels") {
            None => Some(BTreeMap::new()),
            Some(labels) => labels.as_mapping().and_then(|members| {
                members
                    .iter()
                    .map(|(key, value)| value.as_str().map(|v| (key.clone(), v.to_owned())))
                    .collect::<Option<BTreeMap<_, _>>>()
            }),
        },
        Some(_) => None,
    };
    values.map_or_else(unknown, |values| {
        if values
            .iter()
            .any(|(key, value)| !crate::value::label_key(key) || !crate::value::label_value(value))
        {
            unknown()
        } else {
            FactState::Known(LabelFacts {
                values,
                path: labels_path.clone(),
            })
        }
    })
}
fn label_state(ctx: &ProjectionContext<'_>, subject: &LocalSubject, labels_path: &FieldPath) -> FactState<LabelFacts> {
    let root = FieldPath::default();
    let subject_path = match subject {
        LocalSubject::Object => &root,
        LocalSubject::Template { path, .. } => path,
    };
    ctx.state(labels_path, supplied_labels(ctx.tree, subject_path, labels_path))
}
pub(super) fn collect(kind: &str, ctx: &ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    if kind != "Pod" {
        let labels_path = path(&["metadata", "labels"]);
        ctx.emit_fact(
            NativeFact::SelectorSubject {
                subject: LocalSubject::Object,
                labels: label_state(ctx, &LocalSubject::Object, &labels_path),
            },
            out,
        );
    }
    let spec_path = pod_path(kind);
    let (subject, metadata_path) = if kind == "Pod" {
        (LocalSubject::Object, path(&["metadata"]))
    } else {
        let mut template_path = spec_path.clone();
        template_path.0.pop();
        (
            LocalSubject::Template {
                path: template_path.clone(),
                template_kind: TemplateKind::Pod,
            },
            template_path.child("metadata"),
        )
    };
    let labels_path = metadata_path.child("labels");
    ctx.emit_fact(
        NativeFact::SelectorSubject {
            subject: subject.clone(),
            labels: label_state(ctx, &subject, &labels_path),
        },
        out,
    );
    collect_pod_fields(kind, ctx, &spec_path, &subject, out);

    collect_controller_fields(kind, ctx, out);
}

/// Emit only exact workload occurrences from the core's bounded original/effective
/// tree. Core rechecks paths, availability and descriptor budgets before removal.
pub(super) fn observations(kind: &str, tree: &TreeNode, out: &mut Vec<ObservationPath>) {
    let spec = pod_path(kind);
    if kind == "Pod" {
        out.push(ObservationPath {
            path: spec.child("ephemeralContainers"),
            role: ObservationRole::SubresourceOnly,
        });
    } else {
        let mut template = spec.clone();
        template.0.pop();
        if tree.get_path(&template).is_some_and(|node| node.as_mapping().is_some()) {
            append_metadata_observation_paths(&template.child("metadata"), out);
        }
        if kind == "CronJob" {
            let job = path(&["spec", "jobTemplate"]);
            if tree.get_path(&job).is_some_and(|node| node.as_mapping().is_some()) {
                append_metadata_observation_paths(&job.child("metadata"), out);
            }
        }
    }
    let volumes_path = spec.child("volumes");
    if let Some(volumes) = tree.get_path(&volumes_path).and_then(TreeNode::as_sequence) {
        for (index, volume) in volumes.iter().enumerate() {
            if volume
                .get("ephemeral")
                .and_then(|node| node.get("volumeClaimTemplate"))
                .is_some_and(|node| node.as_mapping().is_some())
            {
                let claim = volumes_path
                    .child(index.to_string())
                    .child("ephemeral")
                    .child("volumeClaimTemplate");
                append_metadata_observation_paths(&claim.child("metadata"), out);
            }
        }
    }
    if kind == "StatefulSet" {
        let base = path(&["spec", "volumeClaimTemplates"]);
        if let Some(templates) = tree.get_path(&base).and_then(TreeNode::as_sequence) {
            for (index, template) in templates.iter().enumerate() {
                if template.as_mapping().is_some() {
                    let claim = base.child(index.to_string());
                    out.push(ObservationPath {
                        path: claim.child("status"),
                        role: ObservationRole::ServerOwned,
                    });
                    append_metadata_observation_paths(&claim.child("metadata"), out);
                }
            }
        }
    }
}

fn collect_pod_fields(
    kind: &str,
    ctx: &ProjectionContext<'_>,
    spec_path: &FieldPath,
    subject: &LocalSubject,
    out: &mut Vec<NativeFact>,
) {
    if let Some(spec) = ctx.tree.get_path(spec_path) {
        let containers_path = spec_path.child("containers");
        let mut ports = Vec::new();
        let mut complete = true;
        if let Some(containers) = spec.get("containers").and_then(TreeNode::as_sequence) {
            for (i, container) in containers.iter().enumerate() {
                let ports_path = containers_path.child(i.to_string()).child("ports");
                if let Some(declarations) = container.get("ports").and_then(TreeNode::as_sequence) {
                    for (j, port) in declarations.iter().enumerate() {
                        let p = ports_path.child(j.to_string());
                        let Some(container_port) = port.get("containerPort").and_then(|n| {
                            if let TreeValue::Number(v) = &n.value {
                                v.parse::<i32>().ok()
                            } else {
                                None
                            }
                        }) else {
                            complete = false;
                            continue;
                        };
                        let presence = |key: &str| match port.get(key).map(|n| &n.value) {
                            Some(TreeValue::String(v)) => Presence::Value(v.clone()),
                            Some(TreeValue::Null) => Presence::Null,
                            _ => Presence::Absent,
                        };
                        let fact = PortFact {
                            name: presence("name"),
                            container_port,
                            protocol: presence("protocol"),
                            name_path: p.child("name"),
                            container_port_path: p.child("containerPort"),
                            protocol_path: p.child("protocol"),
                        };
                        if !matches!(
                            ctx.state(&fact.container_port_path, FactState::Known(())),
                            FactState::Known(())
                        ) {
                            complete = false;
                        }
                        ports.push(fact);
                    }
                } else if container.get("ports").is_some() {
                    complete = false;
                }
            }
        } else {
            complete = false;
        }
        let state = if complete {
            FactState::Known(ports)
        } else {
            FactState::Unknown(FactGap::IncompleteSuppliedEvidence)
        };
        ctx.emit_fact(
            NativeFact::ContainerPorts {
                subject: subject.clone(),
                ports: ctx.state(&containers_path, state),
            },
            out,
        );
        if let Some(volumes) = spec.get("volumes").and_then(TreeNode::as_sequence) {
            for (i, volume) in volumes.iter().enumerate() {
                let volume_path = spec_path.child("volumes").child(i.to_string());
                if volume
                    .get("ephemeral")
                    .and_then(|n| n.get("volumeClaimTemplate"))
                    .is_some()
                {
                    let name_path = path(&["metadata", "name"]);
                    let uid_path = path(&["metadata", "uid"]);
                    let pattern = ClaimPatternDraft::PodEphemeral {
                        pod_subject: subject.clone(),
                        volume_path: volume_path.clone(),
                        volume_name: string(volume.get("name")),
                        pod_name: if kind == "Pod" {
                            string(ctx.tree.get_path(&name_path))
                        } else {
                            Presence::Absent
                        },
                        pod_uid: if kind == "Pod" {
                            string(ctx.tree.get_path(&uid_path))
                        } else {
                            Presence::Absent
                        },
                    };
                    ctx.emit_fact(
                        NativeFact::ClaimExpectation {
                            pattern,
                            path: volume_path.child("ephemeral").child("volumeClaimTemplate"),
                        },
                        out,
                    );
                }
            }
        }
    }
}

fn collect_controller_fields(kind: &str, ctx: &ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    if kind == "CronJob" {
        let job_path = path(&["spec", "jobTemplate"]);
        let labels_path = job_path.child("metadata").child("labels");
        let subject = LocalSubject::Template {
            path: job_path,
            template_kind: TemplateKind::Job,
        };
        let labels = label_state(ctx, &subject, &labels_path);
        ctx.emit_fact(NativeFact::SelectorSubject { subject, labels }, out);
    }
    if kind == "StatefulSet" {
        let templates_path = path(&["spec", "volumeClaimTemplates"]);
        if let Some(templates) = ctx.tree.get_path(&templates_path).and_then(TreeNode::as_sequence) {
            for (i, template) in templates.iter().enumerate() {
                let template_path = templates_path.child(i.to_string());
                let pattern = ClaimPatternDraft::StatefulSet {
                    template_path: template_path.clone(),
                    template_name: string(template.get("metadata").and_then(|n| n.get("name"))),
                    controller_name: string(ctx.tree.get_path(&path(&["metadata", "name"]))),
                    replicas: integer(ctx.tree.get_path(&path(&["spec", "replicas"]))),
                    start_ordinal: integer(ctx.tree.get_path(&path(&["spec", "ordinals", "start"]))),
                };
                ctx.emit_fact(
                    NativeFact::ClaimExpectation {
                        pattern,
                        path: template_path,
                    },
                    out,
                );
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        model::GroupVersionKind,
        source::{DocumentFormat, InputOrigin, SourceEvidence, SourceId, SourceInput},
    };

    fn object(key: &str, value: TreeNode) -> TreeNode {
        TreeNode::mapping(vec![(key.to_owned(), value)])
    }
    fn empty() -> TreeNode {
        TreeNode::mapping(Vec::new())
    }
    fn nested(parts: &[&str], mut value: TreeNode) -> TreeNode {
        for part in parts.iter().rev() {
            value = object(part, value);
        }
        value
    }
    fn subjects() -> Vec<FieldPath> {
        vec![
            FieldPath::default(),
            path(&["spec", "template"]),
            path(&["spec", "jobTemplate"]),
            path(&["spec", "jobTemplate", "spec", "template"]),
        ]
    }
    #[test]
    fn optional_metadata_and_labels_absence_are_known_empty_for_each_exact_subject()
    -> Result<(), Box<dyn std::error::Error>> {
        for subject in subjects() {
            let parts = subject.0.iter().map(String::as_str).collect::<Vec<_>>();
            for supplied in [
                empty(),
                object("metadata", empty()),
                object("metadata", object("labels", empty())),
            ] {
                let tree = nested(&parts, supplied);
                let labels_path = subject.child("metadata").child("labels");
                let FactState::Known(labels) = supplied_labels(&tree, &subject, &labels_path) else {
                    return Err("an existing subject with optional metadata/labels absence must be known empty".into());
                };
                assert!(labels.values.is_empty());
                assert_eq!(labels.path, labels_path);
            }
        }
        Ok(())
    }
    #[test]
    fn null_malformed_labels_and_missing_subjects_are_unknown() {
        for subject in subjects() {
            let parts = subject.0.iter().map(String::as_str).collect::<Vec<_>>();
            let labels_path = subject.child("metadata").child("labels");
            let null = || TreeNode::new(TreeValue::Null);
            for supplied in [
                null(),
                TreeNode::string("malformed"),
                object("metadata", null()),
                object("metadata", TreeNode::string("malformed")),
                object("metadata", object("labels", null())),
                object(
                    "metadata",
                    object("labels", TreeNode::new(TreeValue::Sequence(Vec::new()))),
                ),
                object(
                    "metadata",
                    object("labels", object("app", TreeNode::new(TreeValue::Bool(true)))),
                ),
            ] {
                let tree = nested(&parts, supplied);
                assert!(matches!(
                    supplied_labels(&tree, &subject, &labels_path),
                    FactState::Unknown(FactGap::IncompleteSuppliedEvidence)
                ));
            }
            if !subject.0.is_empty() {
                assert!(matches!(
                    supplied_labels(&empty(), &subject, &labels_path),
                    FactState::Unknown(_)
                ));
                assert!(matches!(
                    supplied_labels(&object("spec", null()), &subject, &labels_path),
                    FactState::Unknown(_)
                ));
            }
        }
    }
    #[test]
    fn admitted_string_labels_retain_native_looking_keys_as_data() -> Result<(), Box<dyn std::error::Error>> {
        for subject in subjects() {
            let parts = subject.0.iter().map(String::as_str).collect::<Vec<_>>();
            let labels_path = subject.child("metadata").child("labels");
            let tree = nested(
                &parts,
                object(
                    "metadata",
                    object("labels", object("protocol", TreeNode::string("not-native"))),
                ),
            );
            let FactState::Known(labels) = supplied_labels(&tree, &subject, &labels_path) else {
                return Err("known label map".into());
            };
            assert_eq!(
                labels.values,
                BTreeMap::from([("protocol".to_owned(), "not-native".to_owned())])
            );
            assert_eq!(labels.path, labels_path);
        }
        Ok(())
    }
    #[test]
    fn observation_descriptor_budget_refuses_large_claim_wave_before_collection()
    -> Result<(), Box<dyn std::error::Error>> {
        let gvk = GroupVersionKind::new("apps/v1", "StatefulSet")?;
        let max = crate::source::ParseLimits::default().max_nodes;
        let count = (max - 17) / 9 + 1;
        let tree = object(
            "spec",
            object(
                "volumeClaimTemplates",
                TreeNode::new(TreeValue::Sequence(vec![empty(); count])),
            ),
        );
        let Err(error) = crate::source::check_observation_budget(&tree, &gvk) else {
            return Err("descriptor budget must refuse before collecting".into());
        };
        assert_eq!(error.code, crate::FindingCode::LimitExceeded);
        Ok(())
    }
    #[test]
    fn collectors_keep_root_pod_template_and_job_template_subjects_distinct() -> Result<(), Box<dyn std::error::Error>>
    {
        let source = SourceEvidence::from_input(&SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"{}",
        });
        for (api, kind) in [
            ("v1", "Pod"),
            ("apps/v1", "Deployment"),
            ("apps/v1", "StatefulSet"),
            ("apps/v1", "DaemonSet"),
            ("apps/v1", "ReplicaSet"),
            ("v1", "ReplicationController"),
            ("batch/v1", "Job"),
            ("batch/v1", "CronJob"),
            ("batch/v1beta1", "CronJob"),
        ] {
            let spec_path = pod_path(kind);
            let parts = spec_path.0.iter().map(String::as_str).collect::<Vec<_>>();
            let tree = nested(
                &parts,
                object("containers", TreeNode::new(TreeValue::Sequence(Vec::new()))),
            );
            let gvk = GroupVersionKind::new(api, kind)?;
            let capability = super::super::capabilities::for_api(gvk.clone())?;
            let profile = crate::capability::TargetProfile::documented_defaults(
                crate::capability::KubernetesVersion::new(1, if api == "batch/v1beta1" { 24 } else { 37 })?,
            );
            let ctx = ProjectionContext::new(&tree, &gvk, &source, Some(&profile), &capability);
            let mut facts = Vec::new();
            collect(kind, &ctx, &mut facts);
            let labels = facts
                .iter()
                .filter_map(|fact| {
                    if let NativeFact::SelectorSubject { subject, labels } = fact {
                        Some((subject, labels))
                    } else {
                        None
                    }
                })
                .collect::<Vec<_>>();
            assert_eq!(
                labels.len(),
                if kind == "CronJob" {
                    3
                } else if kind == "Pod" {
                    1
                } else {
                    2
                }
            );
            for (subject, state) in labels {
                let FactState::Known(labels) = state else {
                    return Err("exact optional absence must remain known empty".into());
                };
                assert!(labels.values.is_empty());
                let expected = match subject {
                    LocalSubject::Object => path(&["metadata", "labels"]),
                    LocalSubject::Template { path, .. } => path.child("metadata").child("labels"),
                };
                assert_eq!(labels.path, expected);
            }
        }
        Ok(())
    }
}
