//! Independent regressions for private authoring/projection/merge contracts; no cohort claims.
use super::*;
use crate::{
    model::{AuthoredResource, Metadata},
    registry::codec::FieldCodec,
    source::{AuthoringLimits, EvidenceOrigin, ValueOrigin},
    value::{LabelSelector, Presence},
};
fn path(text: &str) -> TestResult<FieldPath> {
    FieldPath::parse(text).required()
}
fn tree(text: &str) -> TestResult<TreeNode> {
    input(text)?.trees.into_iter().next().required()
}
#[test]
fn shared_presence_unknown_finalizers_and_selector_knowledge() -> TestResult<()> {
    let root = tree(
        "labels: {}\nannotations: null\nfinalizers: []\nownerReferences: [{apiVersion: v1, kind: Pod, name: p, uid: null, extra: private-owner}]\nextra: private-root\n",
    )?;
    let metadata = Metadata::decode(&root, &FieldPath::default()).required()?;
    assert_eq!(metadata.labels, Presence::Value(std::collections::BTreeMap::new()));
    assert_eq!(metadata.annotations, Presence::Null);
    assert_eq!(metadata.finalizers, Presence::Value(Vec::new()));
    let known = metadata
        .encode(&EncodeContext::new(None), &FieldPath::default())
        .required()?;
    assert!(known.get("extra").is_none());
    assert!(
        known
            .get("ownerReferences")
            .and_then(TreeNode::as_sequence)
            .required()?[0]
            .get("extra")
            .is_none()
    );
    let mut authored = EncodeContext::new(None);
    authored.include_unknown = true;
    let full = metadata.encode(&authored, &FieldPath::default()).required()?;
    assert!(full.semantic_eq(&root));
    let selector = LabelSelector::decode(&tree("matchLabels: null\n")?, &FieldPath::default()).required()?;
    assert!(selector.matches(&std::collections::BTreeMap::new()).is_err());
    let selector = LabelSelector::decode(&tree("unknown: private\n")?, &FieldPath::default()).required()?;
    assert_eq!(selector.validate().err().required()?.code, FindingCode::UnadmittedField);
    let selector =
        LabelSelector::decode(&tree("matchLabels: {}\nmatchExpressions: []\n")?, &FieldPath::default()).required()?;
    assert!(selector.matches(&std::collections::BTreeMap::new()).required()?);
    assert!(!format!("{metadata:?}{selector:?}").contains("private-owner"));
    Ok(())
}
#[test]
fn bounded_construction_counts_keys_cumulatively_and_escapes_before_byte_limit() -> TestResult<()> {
    let limits = AuthoringLimits {
        parser: ParseLimits {
            max_nodes: 2,
            ..ParseLimits::default()
        },
        ..AuthoringLimits::default()
    };
    let ctx = EncodeContext {
        target: None,
        include_unknown: true,
        budget: crate::syntax::EncodingBudget::new(limits),
    };
    ctx.key("k", &path("/k")?).required()?;
    ctx.string("v", &path("/k")?).required()?;
    assert_eq!(
        ctx.object(Vec::new(), &FieldPath::default()).err().required()?.code,
        FindingCode::LimitExceeded
    );
    let limits = AuthoringLimits {
        parser: ParseLimits {
            max_scalar_bytes: 1,
            ..ParseLimits::default()
        },
        ..AuthoringLimits::default()
    };
    let ctx = EncodeContext {
        target: None,
        include_unknown: true,
        budget: crate::syntax::EncodingBudget::new(limits),
    };
    assert!(ctx.string("ab", &FieldPath::default()).is_err());
    assert!(ctx.integer(-1, &FieldPath::default()).is_err());
    let limits = AuthoringLimits {
        max_total_snapshot_bytes: 8,
        ..AuthoringLimits::default()
    };
    let budget = crate::syntax::EncodingBudget::new(limits);
    let value = TreeNode::string("\n");
    assert_eq!(budget.snapshot(&value).required()?, b"\"\\u000a\"".to_vec());
    assert_eq!(
        budget.snapshot(&TreeNode::new(TreeValue::Null)).err().required()?.code,
        FindingCode::LimitExceeded
    );
    Ok(())
}
#[test]
fn authored_snapshot_is_generated_positionless_private_and_cumulative() -> TestResult<()> {
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let fixture =
        tree("apiVersion: v1\nkind: Pod\nmetadata: {name: authored, namespace: ns}\nunknownRoot: private-value\n")?;
    let set = ResourceSet::authored_with_registry(
        vec![AuthoredResource::new(Box::new(TestPod { tree: fixture.clone() }))],
        &target,
        &AuthoringLimits::default(),
        &registry()?,
    )
    .required()?;
    let doc = &set.documents()[0];
    assert_eq!(doc.source_evidence().origin, EvidenceOrigin::NativeAuthored);
    assert_eq!(doc.source_evidence().source_version, None);
    assert!(
        doc.field_evidence
            .0
            .values()
            .all(|field| field.origin == ValueOrigin::Generated && field.position.is_none())
    );
    assert!(doc.original.get("unknownRoot").is_some());
    assert!(!format!("{set:?}").contains("private-value"));
    let limits = AuthoringLimits {
        max_resources: 1,
        ..AuthoringLimits::default()
    };
    assert!(
        ResourceSet::authored_with_registry(
            vec![
                AuthoredResource::new(Box::new(TestPod { tree: fixture.clone() })),
                AuthoredResource::new(Box::new(TestPod { tree: fixture }))
            ],
            &target,
            &limits,
            &registry()?
        )
        .is_err()
    );
    Ok(())
}
fn port_fields(pointer: &'static str, key: &'static str) -> &'static [FieldCapability] {
    Box::leak(
        vec![FieldCapability {
            path: pointer,
            since: KubernetesVersion::MIN,
            feature_gate: None,
            removed: None,
            deprecated: None,
            admission: FieldAdmission::Typed,
            merge: MergeStrategy::MapList {
                keys: Box::leak(vec![key, "protocol"].into_boxed_slice()),
            },
            semantic_note: None,
        }]
        .into_boxed_slice(),
    )
}
#[test]
fn comparison_tcp_retains_unknowns_without_materializing_protocol_and_rejects_duplicate_fastpaths() -> TestResult<()> {
    let gvk = GroupVersionKind::new("v1", "Service").required()?;
    let path = path("/spec/ports")?;
    let fields = port_fields("/spec/ports", "port");
    let raw = tree("- {port: 80, targetPort: 8080, unknown: retained}\n")?;
    let before = tree("- {port: 80, targetPort: 8080}\n")?;
    let after = tree("- {port: 80, targetPort: 9090}\n")?;
    let out = crate::generation::merge_native_delta(
        &raw,
        &before,
        &after,
        &path,
        fields,
        &[],
        crate::generation::MergeContext {
            gvk: Some(&gvk),
            target: None,
        },
    )
    .required()?;
    let item = &out.as_sequence().required()?[0];
    assert!(item.get("unknown").is_some());
    assert!(item.get("protocol").is_none());
    let explicit = tree("- {port: 80, targetPort: 8080, protocol: TCP}\n")?;
    let out = crate::generation::merge_native_delta(
        &raw,
        &before,
        &explicit,
        &path,
        fields,
        &[],
        crate::generation::MergeContext {
            gvk: Some(&gvk),
            target: None,
        },
    )
    .required()?;
    assert_eq!(
        out.as_sequence().required()?[0]
            .get("protocol")
            .and_then(TreeNode::as_str),
        Some("TCP")
    );
    let duplicate = tree("- {port: 80}\n- {port: 80, protocol: TCP}\n")?;
    assert!(
        crate::generation::merge_native_delta(
            &duplicate,
            &duplicate,
            &duplicate,
            &path,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: None
            }
        )
        .is_err()
    );
    let rekey = tree("- {port: 81, targetPort: 8080}\n")?;
    assert!(
        crate::generation::merge_native_delta(
            &raw,
            &before,
            &rekey,
            &path,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: None
            }
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn unchanged_malformed_port_keys_preserve_raw_evidence_but_edits_conflict() -> TestResult<()> {
    let gvk = GroupVersionKind::new("v1", "Service").required()?;
    let path = path("/spec/ports")?;
    let fields = port_fields("/spec/ports", "port");
    for invalid in [
        "- {port: 80, protocol: null}",
        "- {port: 0}",
        "- {port: 80, protocol: tcp}",
        "- {protocol: TCP}",
    ] {
        let invalid = tree(invalid)?;
        let out = crate::generation::merge_native_delta(
            &invalid,
            &invalid,
            &invalid,
            &path,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: None,
            },
        )
        .required()?;
        assert!(out.semantic_eq(&invalid));
        let repaired = tree("- {port: 81, protocol: TCP}")?;
        assert!(
            crate::generation::merge_native_delta(
                &invalid,
                &invalid,
                &repaired,
                &path,
                fields,
                &[],
                crate::generation::MergeContext {
                    gvk: Some(&gvk),
                    target: None
                }
            )
            .is_err()
        );
    }
    Ok(())
}

fn real_resources(text: &str, origin: InputOrigin) -> TestResult<ResourceSet> {
    parse_source(
        SourceInput {
            id: SourceId(7),
            format: DocumentFormat::YamlStream,
            origin,
            source_version: Some(KubernetesVersion::MAX),
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()?
    .flatten_resources()
    .required()
}
fn real_options(intent: crate::generation::OutputIntent) -> crate::generation::GenerationOptions {
    crate::generation::GenerationOptions {
        intent,
        json_shape: crate::generation::JsonShape::SingleResource,
        protected_output: crate::generation::ProtectedOutput::Include,
        opaque_fields: crate::generation::OpaqueFieldPolicy::PreserveWithFinding,
        ..crate::generation::GenerationOptions::default()
    }
}
#[test]
fn real_workload_absent_labels_supply_known_empty_selector_subjects() -> TestResult<()> {
    use crate::graph::{
        GraphSubject, Reference, ReferenceScope, ReferenceTarget, RelationshipKind, Resolution, SubjectSelection,
    };
    use crate::value::{SelectorOperator, SelectorRequirement};
    let set = real_resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns}\nspec: {containers: [{name: main, image: example/app:v1}]}\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: ns}\nspec: {template: {metadata: {}, spec: {containers: [{name: main, image: example/app:v1}]}}}\n",
        InputOrigin::Authored,
    )?;
    for selector in [
        LabelSelector::default(),
        LabelSelector::new(
            Presence::Absent,
            Presence::Value(vec![SelectorRequirement::new(
                "absent".into(),
                SelectorOperator::DoesNotExist,
                Presence::Absent,
            )]),
        ),
        LabelSelector::new(
            Presence::Absent,
            Presence::Value(vec![SelectorRequirement::new(
                "absent".into(),
                SelectorOperator::NotIn,
                Presence::Value(vec!["excluded".into()]),
            )]),
        ),
    ] {
        let reference = Reference {
            from: crate::ResourceId(0),
            path: path("/spec")?,
            relation: RelationshipKind::Selector,
            target: ReferenceTarget::SubjectSelector {
                kinds: &[crate::capability::KindId::Pod],
                selector,
                selection: SubjectSelection::PodObjectsAndTemplates,
            },
            scope: ReferenceScope::SameNamespace,
        };
        let graph = crate::graph::resolve_supplied_references_for_target(
            &set,
            &[reference],
            &crate::graph::ReferenceContext::default(),
            &crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX),
        );
        assert!(
            matches!(&graph.edges[0].resolution,Resolution::ResolvedSubjects(subjects) if subjects.len()==2&&matches!(subjects[0],GraphSubject::Object { resource:crate::ResourceId(0) })&&matches!(subjects[1],GraphSubject::Template { resource:crate::ResourceId(1),.. }))
        );
    }
    Ok(())
}
#[test]
fn real_observation_hook_uses_exact_original_tree_and_strips_only_reviewed_paths() -> TestResult<()> {
    use crate::generation::{ExplicitArtifactAccess, OutputFormat, OutputIntent};
    let text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns}\nspec: {containers: [{name: main, image: example/app:v1}], ephemeralContainers: [{name: debug, image: example/debug:v1}]}\nstatus: {ephemeralContainerStatuses: [{name: debug, custom: private-status}]}\n";
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    for (origin, expected) in [
        (InputOrigin::ClusterExport, ValueOrigin::Observed),
        (InputOrigin::Authored, ValueOrigin::Authored),
        (InputOrigin::CallerSupplied, ValueOrigin::CallerSupplied),
        (InputOrigin::HelmRendered, ValueOrigin::CallerSupplied),
    ] {
        let set = real_resources(text, origin)?;
        let doc = &set.documents()[0];
        assert_eq!(
            doc.field_evidence
                .get(&path("/spec/ephemeralContainers/0/name")?)
                .required()?
                .origin,
            expected
        );
        let artifact = crate::generate(
            &set,
            &target,
            OutputFormat::Json,
            &real_options(OutputIntent::AuthoredIntent),
        )
        .required()?;
        let tree = tree(std::str::from_utf8(
            artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
        )?)?;
        assert!(tree.get("status").is_none());
        assert!(tree.get_path(&path("/spec/ephemeralContainers")?).is_none());
        let removed = path("/spec/ephemeralContainers")?;
        assert!(artifact.findings().iter().any(
            |finding| finding.code == FindingCode::ObservedFieldRemoved && finding.path.as_ref() == Some(&removed)
        ));
        assert!(doc.original.get_path(&path("/spec/ephemeralContainers")?).is_some());
    }
    // Pod templates have no status member: an emitter cannot launder this into an observation.
    let set = real_resources(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: d, namespace: ns}\nspec: {template: {metadata: {}, status: {unknown: private}, spec: {containers: [{name: main, image: example/app:v1}]}}}\n",
        InputOrigin::ClusterExport,
    )?;
    let projection = set.documents()[0].project(Some(&target)).required()?;
    let unexpected = path("/spec/template/status")?;
    assert!(
        !projection
            .observations
            .iter()
            .any(|observation| observation.path == unexpected)
    );
    assert_ne!(
        set.documents()[0]
            .field_evidence
            .get(&path("/spec/template/status")?)
            .required()?
            .origin,
        ValueOrigin::Observed
    );
    Ok(())
}

#[test]
fn comparison_tcp_is_finite_across_workload_and_init_container_bindings() -> TestResult<()> {
    let bindings = [
        ("v1", "Pod", "/spec"),
        ("v1", "ReplicationController", "/spec/template/spec"),
        ("apps/v1", "Deployment", "/spec/template/spec"),
        ("apps/v1", "StatefulSet", "/spec/template/spec"),
        ("apps/v1", "DaemonSet", "/spec/template/spec"),
        ("apps/v1", "ReplicaSet", "/spec/template/spec"),
        ("batch/v1", "Job", "/spec/template/spec"),
        ("batch/v1", "CronJob", "/spec/jobTemplate/spec/template/spec"),
        ("batch/v1beta1", "CronJob", "/spec/jobTemplate/spec/template/spec"),
    ];
    for (api, kind, base) in bindings {
        let gvk = GroupVersionKind::new(api, kind).required()?;
        for role in ["containers", "initContainers"] {
            let pointer: &'static str = Box::leak(format!("{base}/{role}/*/ports").into_boxed_str());
            let fields = port_fields(pointer, "containerPort");
            let list_path = path(&format!("{base}/{role}/0/ports"))?;
            let raw = tree("- {containerPort: 80, protocol: TCP, name: old, unknown: retained}\n")?;
            let before = tree("- {containerPort: 80, protocol: TCP, name: old}\n")?;
            let after = tree("- {containerPort: 80, name: new}\n")?;
            let out = crate::generation::merge_native_delta(
                &raw,
                &before,
                &after,
                &list_path,
                fields,
                &[],
                crate::generation::MergeContext {
                    gvk: Some(&gvk),
                    target: None,
                },
            )
            .required()?;
            let item = &out.as_sequence().required()?[0];
            assert_eq!(item.get("name").and_then(TreeNode::as_str), Some("new"));
            assert!(item.get("protocol").is_none());
            assert!(item.get("unknown").is_some());
            let deletion = tree("[]")?;
            assert!(
                crate::generation::merge_native_delta(
                    &raw,
                    &before,
                    &deletion,
                    &list_path,
                    fields,
                    &[],
                    crate::generation::MergeContext {
                        gvk: Some(&gvk),
                        target: None
                    }
                )
                .is_err()
            );
        }
    }
    let gvk = GroupVersionKind::new("batch/v1", "CronJob").required()?;
    let old = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MIN);
    let list_path = path("/spec/jobTemplate/spec/template/spec/containers/0/ports")?;
    let fields = port_fields(
        "/spec/jobTemplate/spec/template/spec/containers/*/ports",
        "containerPort",
    );
    let ports = tree("- {containerPort: 80}")?;
    let edited = tree("- {containerPort: 80, name: changed}")?;
    assert!(
        crate::generation::merge_native_delta(
            &ports,
            &ports,
            &edited,
            &list_path,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: Some(&old)
            }
        )
        .is_err()
    );
    let wrong_path = path("/extension/ports")?;
    let fields = port_fields("/extension/ports", "containerPort");
    assert!(
        crate::generation::merge_native_delta(
            &ports,
            &ports,
            &edited,
            &wrong_path,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: None
            }
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn constructor_scalar_and_key_bytes_share_one_cumulative_boundary() -> TestResult<()> {
    let limits = AuthoringLimits {
        max_total_snapshot_bytes: 4,
        ..AuthoringLimits::default()
    };
    let ctx = EncodeContext {
        target: None,
        include_unknown: true,
        budget: crate::syntax::EncodingBudget::new(limits),
    };
    ctx.key("ab", &path("/ab")?).required()?;
    assert_eq!(
        ctx.string("cde", &path("/ab")?).err().required()?.code,
        FindingCode::LimitExceeded
    );
    assert_eq!(ctx.string("cd", &path("/ab")?).required()?.as_str(), Some("cd"));
    assert_eq!(
        ctx.clone_node(&TreeNode::string("e"), &path("/e")?)
            .err()
            .required()?
            .code,
        FindingCode::LimitExceeded
    );
    Ok(())
}

#[test]
fn malformed_siblings_cannot_hide_later_valid_duplicate_port_keys() -> TestResult<()> {
    let gvk = GroupVersionKind::new("v1", "Service").required()?;
    let fields = port_fields("/spec/ports", "port");
    let ports = tree("- {port: 80, protocol: null, private: retained}\n- {port: 81}\n- {port: 81, protocol: TCP}\n")?;
    assert_eq!(
        crate::generation::merge_native_delta(
            &ports,
            &ports,
            &ports,
            &path("/spec/ports")?,
            fields,
            &[],
            crate::generation::MergeContext {
                gvk: Some(&gvk),
                target: None
            }
        )
        .err()
        .required()?
        .code,
        FindingCode::MergeConflict
    );
    Ok(())
}

#[test]
fn malformed_port_keys_allow_deliberate_field_list_and_removal_repairs() -> TestResult<()> {
    use crate::{
        generation::{MergeContext, merge_native_delta},
        model::FieldEdit,
    };
    let gvk = GroupVersionKind::new("v1", "Service").required()?;
    let context = MergeContext {
        gvk: Some(&gvk),
        target: None,
    };
    let list = path("/spec/ports")?;
    let fields = port_fields("/spec/ports", "port");
    for malformed in [
        "- {port: 80, protocol: null, private: retained}",
        "- {port: 0, private: retained}",
        "- {protocol: TCP, private: retained}",
    ] {
        let ports = tree(malformed)?;
        for repair in [
            FieldEdit::Set {
                path: list.clone(),
                value: tree("- {port: 81, protocol: TCP}")?,
            },
            FieldEdit::Remove { path: list.clone() },
        ] {
            let merged = merge_native_delta(&ports, &ports, &ports, &list, fields, &[repair], context).required()?;
            assert!(merged.semantic_eq(&ports)); // caller edits apply later, original evidence stays immutable.
        }
    }
    let malformed = tree("- {port: 80, protocol: null, private: retained}")?;
    let repair = FieldEdit::Set {
        path: list.child("0").child("protocol"),
        value: TreeNode::string("TCP"),
    };
    assert!(merge_native_delta(&malformed, &malformed, &malformed, &list, fields, &[repair], context).is_ok());
    let duplicates = tree("- {port: 80}\n- {port: 80, protocol: TCP}")?;
    let repair = FieldEdit::Set {
        path: list.child("1").child("port"),
        value: TreeNode::new(TreeValue::Number("81".into())),
    };
    assert!(merge_native_delta(&duplicates, &duplicates, &duplicates, &list, fields, &[repair], context).is_ok());
    let repair = FieldEdit::Remove { path: list.child("1") };
    assert!(merge_native_delta(&duplicates, &duplicates, &duplicates, &list, fields, &[repair], context).is_ok());
    Ok(())
}

#[test]
fn tcp_comparison_rejects_non_numeric_container_indices() -> TestResult<()> {
    let gvk = GroupVersionKind::new("v1", "Pod").required()?;
    let fields = port_fields("/spec/containers/*/ports", "containerPort");
    let ports = tree("- {containerPort: 80, unknown: retained}")?;
    let before = tree("- {containerPort: 80}")?;
    let after = tree("- {containerPort: 80, name: edited}")?;
    for segment in ["bogus", "-", "-1", "1.0"] {
        assert!(
            crate::generation::merge_native_delta(
                &ports,
                &before,
                &after,
                &path(&format!("/spec/containers/{segment}/ports"))?,
                fields,
                &[],
                crate::generation::MergeContext {
                    gvk: Some(&gvk),
                    target: None
                }
            )
            .is_err()
        );
    }
    Ok(())
}

#[test]
fn unrelated_image_edit_preserves_malformed_native_port_evidence_for_validation() -> TestResult<()> {
    use crate::{
        generation::{NativeValidationIntent, validate_for_target_with_intent},
        resources::workloads::Pod,
    };
    let text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns}\nspec: {containers: [{name: main, image: example/old:v1, ports: [{containerPort: 80, protocol: invalid, unknown: private-neighbor}]}]}\n";
    let mut resources = real_resources(text, InputOrigin::Authored)?;
    let Presence::Value(spec) = &mut resources.documents_mut()[0].resource_mut::<Pod>().required()?.spec else {
        return Err("missing Pod spec".into());
    };
    let Presence::Value(containers) = &mut spec.containers else {
        return Err("missing containers".into());
    };
    containers[0].image = Presence::Value("example/new:v2".into());
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let tree = resources.documents()[0].current_tree(Some(&target)).required()?;
    assert_eq!(
        tree.get_path(&path("/spec/containers/0/image")?)
            .and_then(TreeNode::as_str),
        Some("example/new:v2")
    );
    assert_eq!(
        tree.get_path(&path("/spec/containers/0/ports/0/unknown")?)
            .and_then(TreeNode::as_str),
        Some("private-neighbor")
    );
    let protocol_path = path("/spec/containers/0/ports/0/protocol")?;
    for intent in [NativeValidationIntent::Unspecified, NativeValidationIntent::Create] {
        let findings = validate_for_target_with_intent(&resources, &target, intent);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                    && finding.path.as_ref() == Some(&protocol_path))
        );
        assert!(
            findings
                .iter()
                .all(|finding| finding.code != FindingCode::MergeConflict)
        );
        assert!(!format!("{findings:?}").contains("private-neighbor"));
    }
    resources.documents_mut()[0]
        .set_field_from_source(path("/spec/containers/0/ports/0/protocol")?, input("TCP")?)
        .required()?;
    assert!(
        validate_for_target_with_intent(&resources, &target, NativeValidationIntent::Unspecified)
            .iter()
            .all(|finding| finding.path.as_ref() != Some(&protocol_path))
    );
    assert!(
        resources.documents()[0]
            .original
            .get_path(&path("/spec/containers/0/ports/0/unknown")?)
            .is_some()
    );
    Ok(())
}

#[test]
fn removed_beta_cronjob_never_supplies_positive_template_facts() -> TestResult<()> {
    use crate::graph::{Reference, ReferenceScope, ReferenceTarget, RelationshipKind, Resolution, SubjectSelection};
    let resources = real_resources(
        "apiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: c, namespace: ns}\nspec: {schedule: '0 0 * * *', jobTemplate: {spec: {template: {metadata: {labels: {app: match}}, spec: {containers: [{name: main, image: example/app:v1}], restartPolicy: Never}}}}}\n",
        InputOrigin::Authored,
    )?;
    let reference = Reference {
        from: crate::ResourceId(0),
        path: path("/spec")?,
        relation: RelationshipKind::Selector,
        target: ReferenceTarget::SubjectSelector {
            kinds: &[crate::capability::KindId::Pod],
            selector: LabelSelector::default(),
            selection: SubjectSelection::PodObjectsAndTemplates,
        },
        scope: ReferenceScope::SameNamespace,
    };
    for (minor, available) in [(24, true), (25, false), (37, false)] {
        let graph = crate::graph::resolve_supplied_references_for_target(
            &resources,
            std::slice::from_ref(&reference),
            &crate::graph::ReferenceContext::default(),
            &crate::capability::TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?),
        );
        assert_eq!(
            matches!(&graph.edges[0].resolution,Resolution::ResolvedSubjects(subjects) if subjects.len()==1),
            available
        );
        if !available {
            assert!(
                graph
                    .findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::UnavailableApi
                        && finding.resource == Some(crate::ResourceId(0)))
            );
        }
    }
    Ok(())
}
