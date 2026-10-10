//! Genuine sealed unit codecs exercise core contracts independently of delivered cohorts.
use super::*;

#[test]
fn current_role_evidence_binds_each_exact_effective_source() -> TestResult {
    let evidence: serde_json::Value = serde_json::from_slice(include_bytes!("root-status-role-evidence.json"))?;
    let bindings = evidence["current_evaluation_source_sha256"].as_object().required()?;
    let sources: [(&str, &[u8]); 12] = [
        ("src/capability.rs", include_bytes!("../../src/capability.rs")),
        ("src/generation.rs", include_bytes!("../../src/generation.rs")),
        ("src/model.rs", include_bytes!("../../src/model.rs")),
        ("src/registry.rs", include_bytes!("../../src/registry.rs")),
        ("src/syntax.rs", include_bytes!("../../src/syntax.rs")),
        (
            "src/resources/common.rs",
            include_bytes!("../../src/resources/common.rs"),
        ),
        (
            "src/resources/common/native_helpers.rs",
            include_bytes!("../../src/resources/common/native_helpers.rs"),
        ),
        (
            "src/resources/workloads/roots.rs",
            include_bytes!("../../src/resources/workloads/roots.rs"),
        ),
        (
            "src/resources/workloads/validation.rs",
            include_bytes!("../../src/resources/workloads/validation.rs"),
        ),
        ("src/value.rs", include_bytes!("../../src/value.rs")),
        (
            "src/value/access_modes.rs",
            include_bytes!("../../src/value/access_modes.rs"),
        ),
        ("src/source.rs", include_bytes!("../../src/source.rs")),
    ];
    assert_eq!(bindings.len(), sources.len());
    for (name, bytes) in sources {
        let mut actual = String::new();
        for byte in ledger_digest(bytes) {
            use std::fmt::Write as _;
            write!(&mut actual, "{byte:02x}")?;
        }
        assert_eq!(
            bindings[name].as_str().required()?,
            actual,
            "stale current source binding: {name}"
        );
    }
    Ok(())
}
use crate::{
    capability::{FieldAdmission, FieldCapability, KindCapability, KubernetesVersion, MergeStrategy, TargetProfile},
    model::{GroupVersionKind, ResourceScope, ResourceSet},
    registry::{
        DecodeContext, EncodeContext, FindingSink, NativeResource, RegistryBuilder, ResourceRegistration,
        ValidationContext,
    },
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceEvidence, SourceId, SourceInput, ValueOrigin},
    syntax::{SyntaxBuilder, TreeNode, TreeValue},
    value::{Presence, Protected},
};
use std::any::Any;
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
trait Required<T> {
    fn required(self) -> TestResult<T>;
}
impl<T, E: fmt::Debug> Required<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|error| format!("{error:?}").into())
    }
}
impl<T> Required<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| "required fixture evidence".into())
    }
}
fn path(value: &str) -> FieldPath {
    FieldPath(value.split('/').skip(1).map(str::to_owned).collect())
}
fn string_presence(node: Option<&TreeNode>) -> Presence<Protected<String>> {
    match node {
        None => Presence::Absent,
        Some(node) if node.value == TreeValue::Null => Presence::Null,
        Some(node) => node.as_str().map_or(Presence::Null, |value| {
            Presence::Value(Protected::new(value.to_owned()))
        }),
    }
}
fn int_presence(node: Option<&TreeNode>) -> Presence<i32> {
    match node {
        None => Presence::Absent,
        Some(node) if node.value == TreeValue::Null => Presence::Null,
        Some(node) => {
            if let TreeValue::Number(value) = &node.value {
                value.parse().map_or(Presence::Null, Presence::Value)
            } else {
                Presence::Null
            }
        }
    }
}
struct Fixture {
    tree: TreeNode,
    source: SourceId,
}
fn labels(ctx: &registry::ProjectionContext<'_>, base: &FieldPath) -> FactState<LabelFacts> {
    let path = base.child("metadata").child("labels");
    let values = match ctx.tree.get_path(&path) {
        None => BTreeMap::new(),
        Some(node) => match <BTreeMap<String, String> as registry::codec::FieldCodec>::decode(node, &ctx.fields, &path)
        {
            Ok(values) => values,
            Err(_) => return FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
        },
    };
    ctx.state(
        &path,
        FactState::Known(LabelFacts {
            values,
            path: path.clone(),
        }),
    )
}
impl NativeResource for Fixture {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn collect_references(&self, _: &EncodeContext<'_>, _: &mut dyn ReferenceSink) {}
    fn collect_protected_paths(&self, _: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
        out.push(path("/spec/private"));
    }
    fn validate(&self, _: &ValidationContext<'_>, _: &mut dyn FindingSink) {}
    fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding> {
        out.set_root(ctx.clone_node(&self.tree, &FieldPath::default())?);
        Ok(())
    }
    fn collect_observation_paths(&self, tree: &TreeNode, out: &mut Vec<crate::source::ObservationPath>) {
        if tree.get_path(&path("/spec/template")).is_some() {
            crate::source::append_metadata_observation_paths(&path("/spec/template/metadata"), out);
            out.push(crate::source::ObservationPath {
                path: path("/spec/template/status"),
                role: crate::source::ObservationRole::ServerOwned,
            });
        }
        if tree.get_path(&path("/spec/ephemeralContainers")).is_some() {
            out.push(crate::source::ObservationPath {
                path: path("/spec/ephemeralContainers"),
                role: crate::source::ObservationRole::SubresourceOnly,
            });
        }
        if let Some(items) = tree
            .get_path(&path("/spec/volumeClaimTemplates"))
            .and_then(TreeNode::as_sequence)
        {
            for index in 0..items.len() {
                let base = path("/spec/volumeClaimTemplates").child(index.to_string());
                crate::source::append_metadata_observation_paths(&base.child("metadata"), out);
                out.push(crate::source::ObservationPath {
                    path: base.child("status"),
                    role: crate::source::ObservationRole::ServerOwned,
                });
            }
        }
    }
    fn collect_native_facts(&self, ctx: &registry::ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
        assert_eq!(ctx.source.id, self.source);
        ctx.emit_fact(
            NativeFact::SelectorSubject {
                subject: LocalSubject::Object,
                labels: labels(ctx, &FieldPath::default()),
            },
            out,
        );
        if ctx.tree.get_path(&path("/spec/template")).is_some() {
            let base = path("/spec/template");
            ctx.emit_fact(
                NativeFact::SelectorSubject {
                    subject: LocalSubject::Template {
                        path: base.clone(),
                        template_kind: TemplateKind::Pod,
                    },
                    labels: labels(ctx, &base),
                },
                out,
            );
        }
        emit_key_facts(ctx, out);
        if ctx.gvk.kind == "Service" {
            let ports_path = path("/spec/ports");
            ctx.emit_fact(
                NativeFact::ServicePorts {
                    state: service_port_declarations(ctx.tree, &ports_path, &ctx.fields),
                    path: ports_path,
                },
                out,
            );

            let path = path("/spec/clusterIP");
            let state = match ctx.tree.get_path(&path).and_then(TreeNode::as_str) {
                Some("None") => FactState::Known(true),
                Some(value) if value.parse::<std::net::IpAddr>().is_ok() => FactState::Known(false),
                _ => FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
            };
            ctx.emit_fact(
                NativeFact::ServiceHeadless {
                    state: ctx.state(&path, state),
                    path,
                },
                out,
            );
        }
        emit_claim_facts(ctx, out);
    }
}
fn emit_key_facts(ctx: &registry::ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    if ctx.gvk.kind == "ConfigMap" || ctx.gvk.kind == "Secret" {
        let domains = if ctx.gvk.kind == "Secret" {
            vec![(KeyDomain::Secret, vec!["data", "stringData"])]
        } else {
            vec![
                (KeyDomain::ConfigMapText, vec!["data"]),
                (KeyDomain::ConfigMapTextOrBinary, vec!["data", "binaryData"]),
            ]
        };
        for (domain, maps) in domains {
            let mut names = BTreeMap::new();
            let mut complete = true;
            for field in maps {
                if let Some(node) = ctx.tree.get(field) {
                    if let Some(entries) = node.as_mapping() {
                        for (key, _) in entries {
                            names.insert(key.clone(), FieldPath(vec![field.into(), key.clone()]));
                        }
                    } else {
                        complete = false;
                    }
                }
            }
            let path = path("/data");
            let state = if complete {
                FactState::Known(KeyNames(names))
            } else {
                FactState::Unknown(FactGap::IncompleteSuppliedEvidence)
            };
            ctx.emit_fact(
                NativeFact::Keys {
                    domain,
                    state: ctx.state(&path, state),
                    path,
                },
                out,
            );
        }
    }
}
fn emit_claim_facts(ctx: &registry::ProjectionContext<'_>, out: &mut Vec<NativeFact>) {
    if ctx.gvk.kind == "StatefulSet" {
        if let Some(items) = ctx
            .tree
            .get_path(&path("/spec/volumeClaimTemplates"))
            .and_then(TreeNode::as_sequence)
        {
            for (index, item) in items.iter().enumerate() {
                let template_path = path("/spec/volumeClaimTemplates").child(index.to_string());
                ctx.emit_fact(
                    NativeFact::ClaimExpectation {
                        path: template_path.clone(),
                        pattern: ClaimPatternDraft::StatefulSet {
                            template_path,
                            template_name: string_presence(item.get_path(&path("/metadata/name"))),
                            controller_name: string_presence(ctx.tree.get_path(&path("/metadata/name"))),
                            replicas: int_presence(ctx.tree.get_path(&path("/spec/replicas"))),
                            start_ordinal: int_presence(ctx.tree.get_path(&path("/spec/ordinals/start"))),
                        },
                    },
                    out,
                );
            }
        }
    }
    let mut subjects = vec![(LocalSubject::Object, FieldPath::default())];
    if ctx.tree.get_path(&path("/spec/template")).is_some() {
        subjects.push((
            LocalSubject::Template {
                path: path("/spec/template"),
                template_kind: TemplateKind::Pod,
            },
            path("/spec/template"),
        ));
    }
    for (subject, base) in subjects {
        if let Some(volumes) = ctx
            .tree
            .get_path(&base.child("spec").child("volumes"))
            .and_then(TreeNode::as_sequence)
        {
            for (index, volume) in volumes.iter().enumerate() {
                if volume.get("ephemeral").is_none() {
                    continue;
                }
                let volume_path = base.child("spec").child("volumes").child(index.to_string());
                let actual = ctx.gvk.kind == "Pod" && matches!(subject, LocalSubject::Object);
                ctx.emit_fact(
                    NativeFact::ClaimExpectation {
                        path: volume_path.child("ephemeral").child("volumeClaimTemplate"),
                        pattern: ClaimPatternDraft::PodEphemeral {
                            pod_subject: subject.clone(),
                            volume_path,
                            volume_name: string_presence(volume.get("name")),
                            pod_name: if actual {
                                string_presence(ctx.tree.get_path(&path("/metadata/name")))
                            } else {
                                Presence::Absent
                            },
                            pod_uid: if actual {
                                string_presence(ctx.tree.get_path(&path("/metadata/uid")))
                            } else {
                                Presence::Absent
                            },
                        },
                    },
                    out,
                );
            }
        }
    }
}
fn decode(
    tree: &TreeNode,
    source: &SourceEvidence,
    ctx: &DecodeContext<'_>,
) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
    for location in [
        "/metadata/labels",
        "/spec/template/metadata/labels",
        "/data",
        "/binaryData",
        "/stringData",
    ] {
        if let Some(node) = tree.get_path(&path(location)) {
            if node.value != TreeValue::Null {
                <BTreeMap<String, String> as registry::codec::FieldCodec>::decode(node, &ctx.fields, &path(location))
                    .map_err(|finding| vec![finding])?;
            }
        }
    }
    Ok(Box::new(Fixture {
        tree: tree.clone(),
        source: source.id,
    }))
}
fn fields() -> &'static [FieldCapability] {
    let pointers = [
        "/apiVersion",
        "/kind",
        "/metadata",
        "/metadata/name",
        "/metadata/namespace",
        "/metadata/uid",
        "/metadata/finalizers",
        "/metadata/finalizers/*",
        "/metadata/labels",
        "/metadata/labels/*",
        "/metadata/ownerReferences",
        "/metadata/ownerReferences/*",
        "/metadata/ownerReferences/*/apiVersion",
        "/metadata/ownerReferences/*/kind",
        "/metadata/ownerReferences/*/name",
        "/metadata/ownerReferences/*/uid",
        "/metadata/ownerReferences/*/controller",
        "/data",
        "/data/*",
        "/binaryData",
        "/binaryData/*",
        "/stringData",
        "/stringData/*",
        "/spec",
        "/spec/clusterIP",
        "/spec/ports",
        "/spec/ports/*",
        "/spec/ports/*/name",
        "/spec/ports/*/port",
        "/spec/ports/*/protocol",
        "/spec/podSelector",
        "/spec/podSelector/matchLabels",
        "/spec/podSelector/matchLabels/*",
        "/spec/ingress",
        "/spec/ingress/*",
        "/spec/ingress/*/from",
        "/spec/ingress/*/from/*",
        "/spec/ingress/*/from/*/namespaceSelector",
        "/spec/ingress/*/from/*/namespaceSelector/matchLabels",
        "/spec/ingress/*/from/*/namespaceSelector/matchLabels/*",
        "/spec/ingress/*/from/*/podSelector",
        "/spec/ingress/*/from/*/podSelector/matchLabels",
        "/spec/ingress/*/from/*/podSelector/matchLabels/*",
        "/spec/defaultBackend",
        "/spec/defaultBackend/resource",
        "/spec/defaultBackend/resource/apiGroup",
        "/spec/defaultBackend/resource/kind",
        "/spec/defaultBackend/resource/name",
        "/spec/template",
        "/spec/template/metadata",
        "/spec/template/metadata/name",
        "/spec/template/metadata/uid",
        "/spec/template/metadata/finalizers",
        "/spec/template/metadata/finalizers/*",
        "/spec/template/metadata/labels",
        "/spec/template/metadata/labels/*",
        "/spec/template/spec",
        "/spec/replicas",
        "/spec/ordinals",
        "/spec/ordinals/start",
        "/spec/volumeClaimTemplates",
        "/spec/volumeClaimTemplates/*",
        "/spec/volumeClaimTemplates/*/metadata",
        "/spec/volumeClaimTemplates/*/metadata/name",
        "/spec/volumeClaimTemplates/*/metadata/uid",
        "/spec/volumeClaimTemplates/*/status",
        "/spec/volumes",
        "/spec/volumes/*",
        "/spec/volumes/*/name",
        "/spec/volumes/*/ephemeral",
        "/spec/volumes/*/ephemeral/volumeClaimTemplate",
        "/spec/template/spec/volumes",
        "/spec/template/spec/volumes/*",
        "/spec/template/spec/volumes/*/name",
        "/spec/template/spec/volumes/*/ephemeral",
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate",
    ];
    Box::leak(
        pointers
            .into_iter()
            .map(|path| FieldCapability {
                path,
                since: if path == "/spec/ordinals" || path == "/spec/ordinals/start" {
                    KubernetesVersion::new(1, 31).unwrap_or(KubernetesVersion::MAX)
                } else {
                    KubernetesVersion::MIN
                },
                feature_gate: None,
                removed: None,
                deprecated: None,
                admission: FieldAdmission::Typed,
                merge: MergeStrategy::AtomicList,
                semantic_note: None,
            })
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}
fn set(text: &str, origin: InputOrigin) -> TestResult<ResourceSet> {
    let mut registry = RegistryBuilder::new();
    let fields = fields();
    for (api, kind) in [
        ("v1", "Pod"),
        ("apps/v1", "Deployment"),
        ("apps/v1", "StatefulSet"),
        ("v1", "ConfigMap"),
        ("v1", "Secret"),
        ("v1", "Service"),
        ("v1", "PersistentVolumeClaim"),
        ("v1", "Namespace"),
        ("networking.k8s.io/v1", "NetworkPolicy"),
        ("networking.k8s.io/v1", "Ingress"),
    ] {
        let gvk = GroupVersionKind::new(api, kind).required()?;
        let scope = crate::capability::builtin_scope(&gvk).unwrap_or(ResourceScope::CrdResolved { namespaced: true });
        registry
            .register(ResourceRegistration {
                gvk: gvk.clone(),
                scope,
                decode,
                capability: KindCapability {
                    gvk,
                    scope,
                    api_since: KubernetesVersion::MIN,
                    api_removed: None,
                    fields,
                },
            })
            .required()?;
    }
    let parsed = crate::parse_source(
        SourceInput {
            id: SourceId(9),
            format: DocumentFormat::YamlStream,
            origin,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()?;
    ResourceSet::with_registry(vec![parsed], &registry).required()
}
fn checked(
    from: u64,
    kind: &str,
    name: &str,
    predicate: Option<ReferencePredicate>,
    optional: Presence<bool>,
) -> TestResult<Reference> {
    Ok(Reference {
        from: ResourceId(from),
        path: path("/spec/ref"),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::CheckedObject {
            gvk: GroupVersionKind::new("v1", kind).required()?,
            name: name.into(),
            predicate,
            optional,
        },
        scope: ReferenceScope::SameNamespace,
    })
}
fn selector(from: u64) -> Reference {
    Reference {
        from: ResourceId(from),
        path: path("/spec/selector"),
        relation: RelationshipKind::Selector,
        target: ReferenceTarget::SubjectSelector {
            kinds: &[KindId::Pod],
            selector: LabelSelector::from_match_labels(BTreeMap::from([("app".into(), "match".into())])),
            selection: SubjectSelection::PodObjectsAndTemplates,
        },
        scope: ReferenceScope::SameNamespace,
    }
}
#[test]
fn malformed_public_checked_references_never_become_missing_or_optional() -> TestResult {
    let resources = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: config, namespace: ns}\ndata: {}\n",
        InputOrigin::Authored,
    )?;
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let mut malformed = Vec::new();
    let mut invalid_identity = Vec::new();
    for optional in [Presence::Absent, Presence::Value(true)] {
        for name in ["", ".bad", "Bad", "bad/name", "bad%name", "bad..name"] {
            let reference = checked(0, "ConfigMap", name, None, optional.clone())?;
            malformed.push(reference);
            invalid_identity.push(true);
        }
        for key in ["", ".", "..", "..hidden", "bad/key", "bad key", "é"] {
            let reference = checked(
                0,
                "ConfigMap",
                "config",
                Some(ReferencePredicate::KeyExists {
                    domain: KeyDomain::ConfigMapText,
                    key: Protected::new(key.to_owned()),
                }),
                optional.clone(),
            )?;
            malformed.push(reference);
            invalid_identity.push(false);
        }
    }
    let graph = resolve_supplied_references_for_target(&resources, &malformed, &ReferenceContext::default(), &target);
    assert_eq!(graph.edges.len(), malformed.len());
    for (edge, identity) in graph.edges.iter().zip(invalid_identity) {
        assert!(matches!(edge.resolution, Resolution::Unsupported(_)));
        if identity {
            assert_eq!(edge.resolution, Resolution::Unsupported(SafeReason::InvalidIdentity));
        }
    }
    let mut valid = Vec::new();
    for key in [".a", "a..", "_KEY", "-", "MiXeD-1"] {
        let reference = checked(
            0,
            "ConfigMap",
            "config",
            Some(ReferencePredicate::KeyExists {
                domain: KeyDomain::ConfigMapText,
                key: Protected::new(key.to_owned()),
            }),
            Presence::Absent,
        )?;
        valid.push(reference);
    }
    let valid_long_component = "a".repeat(64);
    let reference = checked(0, "ConfigMap", &valid_long_component, None, Presence::Absent)?;
    valid.push(reference);
    let graph = resolve_supplied_references_for_target(&resources, &valid, &ReferenceContext::default(), &target);
    assert_eq!(graph.edges.len(), valid.len());
    for (index, edge) in graph.edges.iter().enumerate() {
        if index == 5 {
            assert_eq!(edge.resolution, Resolution::Missing);
        } else {
            assert!(matches!(edge.resolution, Resolution::MissingKey { .. }));
        }
    }
    Ok(())
}

#[test]
fn malformed_labels_cannot_certify_selector_membership() -> TestResult {
    let resources = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: good, namespace: ns, labels: {app: match}}\nspec: {containers: [{name: web, image: example/web:v1}]}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: bad, namespace: ns, labels: {app: match, another: 'bad value'}}\nspec: {containers: [{name: web, image: example/web:v1}]}\n",
        InputOrigin::Authored,
    )?;
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let graph =
        resolve_supplied_references_for_target(&resources, &[selector(0)], &ReferenceContext::default(), &target);
    assert!(
        matches!(&graph.edges[0].resolution, Resolution::PartiallyResolvedSubjects { matched, unavailable }
        if matched == &[GraphSubject::Object { resource: ResourceId(1) }] && unavailable.len() == 1)
    );
    Ok(())
}

#[test]
fn checked_keys_optional_headless_and_exact_supplier_evidence() -> TestResult {
    let set = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: config, namespace: ns}\ndata: {secret-key-marker: private-value-marker}\nbinaryData: {binary: eA==}\n---\napiVersion: v1\nkind: Service\nmetadata: {name: headless, namespace: ns}\nspec: {clusterIP: None}\n",
        InputOrigin::Authored,
    )?;
    let key = ReferencePredicate::KeyExists {
        domain: KeyDomain::ConfigMapText,
        key: Protected::new("secret-key-marker".into()),
    };
    let refs = vec![
        checked(0, "ConfigMap", "config", Some(key), Presence::Absent)?,
        checked(
            0,
            "ConfigMap",
            "config",
            Some(ReferencePredicate::KeyExists {
                domain: KeyDomain::ConfigMapText,
                key: Protected::new("absent".into()),
            }),
            Presence::Value(true),
        )?,
        checked(
            0,
            "Service",
            "headless",
            Some(ReferencePredicate::HeadlessService),
            Presence::Absent,
        )?,
        checked(0, "ConfigMap", "not-supplied", None, Presence::Value(true))?,
    ];
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let graph = resolve_supplied_references_for_target(&set, &refs, &ReferenceContext::default(), &target);
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::ResolvedSubjects(subjects) if matches!(&subjects[0],GraphSubject::Key {resource:ResourceId(1),..}))
    );
    assert!(
        graph.edges[0]
            .evidence
            .iter()
            .any(|field| field.resource == ResourceId(1)
                && field.source.document_index == 1
                && field.path == path("/data/secret-key-marker")
                && field.origin == ValueOrigin::Authored)
    );
    assert!(matches!(
        graph.edges[1].resolution,
        Resolution::OptionalMissing(MissingSubject::Key {
            object: ResourceId(1),
            ..
        })
    ));
    assert!(matches!(graph.edges[2].resolution, Resolution::ResolvedSubjects(_)));
    assert!(matches!(
        graph.edges[3].resolution,
        Resolution::OptionalMissing(MissingSubject::Object)
    ));
    assert!(!format!("{graph:?}").contains("secret-key-marker"));
    assert!(!format!("{graph:?}").contains("private-value-marker"));
    assert!(
        !graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MissingReference)
    );
    Ok(())
}
#[test]
fn patched_template_membership_and_changed_supplier_provenance_are_current() -> TestResult {
    let mut set = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {name: deployment, namespace: ns, labels: {app: object}}\nspec: {template: {metadata: {labels: {app: match}}, spec: {}}}\n",
        InputOrigin::ClusterExport,
    )?;
    let refs = [selector(0)];
    let graph = resolve_supplied_references(&set, &refs, &ReferenceContext::default());
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::ResolvedSubjects(subjects) if matches!(&subjects[0],GraphSubject::Template {resource:ResourceId(1),path:p,..} if *p==path("/spec/template")))
    );
    let parsed = crate::parse_source(
        SourceInput {
            id: SourceId(20),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"{\"app\":\"different\"}",
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[1]
        .set_field_from_source(path("/spec/template/metadata/labels"), parsed)
        .required()?;
    let graph = resolve_supplied_references(&set, &refs, &ReferenceContext::default());
    assert_eq!(graph.edges[0].resolution, Resolution::Missing);
    assert!(
        graph.edges[0]
            .evidence
            .iter()
            .any(|field| field.resource == ResourceId(1)
                && field.origin == ValueOrigin::Generated
                && field.position.is_none())
    );
    Ok(())
}
#[test]
fn future_claim_range_never_allocates_replicas_and_no_target_never_defaults_ordinals() -> TestResult {
    let set = set(
        "apiVersion: apps/v1\nkind: StatefulSet\nmetadata: {name: db, namespace: ns}\nspec: {replicas: 2147483647, ordinals: {start: 2}, volumeClaimTemplates: [{metadata: {name: data}}]}\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: data-db-2, namespace: ns}\n",
        InputOrigin::Authored,
    )?;
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let graph = resolve_references_for_target(&set, &target);
    let claim = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::GeneratedClaims { .. }))
        .required()?;
    assert!(
        matches!(&claim.resolution,Resolution::ExpectedClaims {state:ClaimExpectationState::IdentityRuleEstablished,matching_supplied} if matching_supplied.len()==1&&matching_supplied[0].resource==ResourceId(1)&&matching_supplied[0].ownership==ClaimOwnership::NotRequiredByThisRule)
    );
    assert!(
        !graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MissingReference)
    );
    let graph = resolve_references(&set);
    assert!(graph.edges.iter().any(|edge| matches!(
        edge.resolution,
        Resolution::Unsupported(SafeReason::FactUnknown(FactGap::TargetProfileRequired))
    )));
    Ok(())
}
#[test]
fn ephemeral_owner_absence_is_unknown_even_in_cluster_export_and_explicit_empty_is_incompatible() -> TestResult {
    let text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns, uid: pod-uid}\nspec: {volumes: [{name: scratch, ephemeral: {volumeClaimTemplate: {}}}]}\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: p-scratch, namespace: ns";
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    for (suffix, expected) in [
        ("}\n", ClaimOwnership::Unknown),
        (
            ", ownerReferences: [{apiVersion: v1, kind: Pod, name: p, uid: pod-uid, controller: true}]}\n",
            ClaimOwnership::VerifiedSupplied,
        ),
    ] {
        let set = set(&format!("{text}{suffix}"), InputOrigin::ClusterExport)?;
        let graph = resolve_references_for_target(&set, &target);
        assert!(graph.edges.iter().any(|edge|matches!(&edge.resolution,Resolution::ExpectedClaims {matching_supplied,..} if matching_supplied.len()==1&&matching_supplied[0].ownership==expected)));
    }
    let set = set(&format!("{text}, ownerReferences: []}}\n"), InputOrigin::ClusterExport)?;
    let graph = resolve_references_for_target(&set, &target);
    assert!(graph.edges.iter().any(|edge| matches!(
        edge.resolution,
        Resolution::Incompatible {
            reason: PredicateMismatch::ClaimOwnerMismatch,
            ..
        }
    )));
    Ok(())
}
#[test]
fn witness_keeps_empty_graph_profile_all_gate_origins_and_exact_sha256() -> TestResult {
    let set = ResourceSet::from_inputs(Vec::new()).required()?;
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let first = resolve_references_for_target(&set, &target);
    let witness = first.target_witness().required()?;
    assert_eq!(
        witness.resolved_gates().len(),
        crate::capability::FeatureGateId::ALL.len()
    );
    let mut opposite = target.clone();
    opposite.feature_gates.states.insert(
        crate::capability::FeatureGateId::GenericEphemeralVolume,
        crate::capability::FeatureGateState::Disabled,
    );
    let second = resolve_references_for_target(&set, &opposite);
    assert_ne!(first.target_witness(), second.target_witness());
    assert!(resolve_references(&set).target_witness().is_none());
    assert_eq!(
        ledger_digest(b"abc"),
        [
            0xba, 0x78, 0x16, 0xbf, 0x8f, 0x01, 0xcf, 0xea, 0x41, 0x41, 0x40, 0xde, 0x5d, 0xae, 0x22, 0x23, 0xb0, 0x03,
            0x61, 0xa3, 0x96, 0x17, 0x7a, 0x9c, 0xb4, 0x10, 0xff, 0x61, 0xf2, 0x00, 0x15, 0xad
        ]
    );
    Ok(())
}

#[test]
fn ephemeral_claim_name_composition_collision_has_distinct_suppliers() -> TestResult {
    let set = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p-a, namespace: ns}\nspec: {volumes: [{name: b, ephemeral: {volumeClaimTemplate: {}}}]}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns}\nspec: {volumes: [{name: a-b, ephemeral: {volumeClaimTemplate: {}}}]}\n",
        InputOrigin::Authored,
    )?;
    let graph = resolve_references_for_target(&set, &TargetProfile::documented_defaults(KubernetesVersion::MAX));
    let collisions = graph
        .findings
        .iter()
        .filter(|finding| finding.code == FindingCode::ClaimIdentityCollision)
        .collect::<Vec<_>>();
    assert_eq!(collisions.len(), 2);
    assert_eq!(collisions[0].resource, Some(ResourceId(0)));
    assert_eq!(collisions[1].resource, Some(ResourceId(1)));
    assert!(
        collisions
            .iter()
            .all(|finding| finding.path.as_ref() == Some(&path("/spec/volumes/0")))
    );
    assert!(!format!("{graph:?}").contains("p-a-b"));
    Ok(())
}
#[test]
fn provenance_comparison_budget_failure_never_keeps_a_positive_resolution() -> TestResult {
    let set = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns, labels: {app: match}}\n",
        InputOrigin::Authored,
    )?;
    let document = &set.documents[0];
    let projection = document.project(None).required()?;
    let result = document.effective_evidence(&projection, &path("/metadata/labels"), |_, _| false);
    assert!(result.is_none());
    // A fresh attempt must still charge the comparison; failed work was not cached.
    let result = document
        .effective_evidence(&projection, &path("/metadata/labels"), |_, _| true)
        .required()?;
    assert_eq!(result.origin, ValueOrigin::Authored);
    Ok(())
}

#[test]
fn malformed_effective_labels_cannot_supply_stale_selector_matches() -> TestResult {
    let mut resources = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: supplier, namespace: ns, labels: {app: match}}\n",
        InputOrigin::Authored,
    )?;
    let value = crate::parse_source(
        SourceInput {
            id: SourceId(11),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"5",
        },
        &ParseLimits::default(),
    )
    .required()?;
    resources.documents_mut()[1]
        .set_field_from_source(path("/metadata/labels"), value)
        .required()?;
    let graph = resolve_supplied_references(&resources, &[selector(0)], &ReferenceContext::default());
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::PartiallyResolvedSubjects { matched,unavailable } if matched.is_empty()&&unavailable.iter().any(|gap|gap.resource==ResourceId(1)))
    );
    assert!(
        graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    assert!(
        !graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MissingReference
                || finding.code == FindingCode::SelectorNoMatches)
    );
    Ok(())
}

#[test]
fn failed_pvc_projection_cannot_produce_a_complete_generated_claim_result() -> TestResult {
    let mut resources = set(
        "apiVersion: apps/v1\nkind: StatefulSet\nmetadata: {name: db, namespace: ns}\nspec: {replicas: 1, ordinals: {start: 0}, volumeClaimTemplates: [{metadata: {name: data}}]}\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: data-db-0, namespace: ns, labels: {good: source}}\n",
        InputOrigin::Authored,
    )?;
    let parsed = crate::parse_source(
        SourceInput {
            id: SourceId(22),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"5",
        },
        &ParseLimits::default(),
    )
    .required()?;
    resources.documents_mut()[1]
        .set_field_from_source(path("/metadata/labels"), parsed)
        .required()?;
    let graph = resolve_references_for_target(&resources, &TargetProfile::documented_defaults(KubernetesVersion::MAX));
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::GeneratedClaims { .. }))
        .required()?;
    assert!(matches!(
        edge.resolution,
        Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))
    ));
    assert!(
        graph
            .findings
            .iter()
            .any(|finding| finding.resource == Some(ResourceId(1)))
    );
    Ok(())
}

#[test]
fn ephemeral_claim_ownership_uses_controller_uid_and_keeps_incomplete_records_unknown() -> TestResult {
    let text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns, uid: pod-uid}\nspec: {volumes: [{name: scratch, ephemeral: {volumeClaimTemplate: {}}}]}\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: p-scratch, namespace: ns, ownerReferences: ";
    for (owners, expected) in [
        (
            "[{apiVersion: apps/v1, kind: Deployment, name: other, uid: pod-uid, controller: true}]",
            ClaimOwnership::VerifiedSupplied,
        ),
        (
            "[{apiVersion: v1, kind: Pod, name: p, controller: true}]",
            ClaimOwnership::Unknown,
        ),
        (
            "[{apiVersion: v1, kind: Pod, uid: pod-uid, controller: true}]",
            ClaimOwnership::Unknown,
        ),
        (
            "[{apiVersion: v1, kind: Pod, name: p, uid: null, controller: true}]",
            ClaimOwnership::Unknown,
        ),
        (
            "[{apiVersion: v1, kind: Pod, name: p, uid: pod-uid, controller: null}]",
            ClaimOwnership::Unknown,
        ),
    ] {
        let resources = set(&format!("{text}{owners}}}\n"), InputOrigin::ClusterExport)?;
        let graph =
            resolve_references_for_target(&resources, &TargetProfile::documented_defaults(KubernetesVersion::MAX));
        let edge = graph
            .edges
            .iter()
            .find(|edge| matches!(edge.reference.target, ReferenceTarget::GeneratedClaims { .. }))
            .required()?;
        assert!(
            matches!(&edge.resolution,Resolution::ExpectedClaims {matching_supplied,..} if matching_supplied.len()==1&&matching_supplied[0].ownership==expected),
            "{owners}: {:?}",
            edge.resolution
        );
    }
    Ok(())
}

#[test]
fn root_status_expectations_bind_the_immutable_report_ledger_and_authenticated_witness() -> TestResult {
    let evidence: serde_json::Value = serde_json::from_str(include_str!("root-status-role-evidence.json"))?;
    assert_eq!(
        evidence["report_sha256"],
        "ea9308ea8a4220132c7036b425ee7ebe189cd48e2a05f16679cbbb891f335228"
    );
    assert_eq!(
        evidence["ledger_sha256"],
        "747adc51d5646a1977fd1a6fa0d022414cdab72520d31470696aaf4e5b0d2c08"
    );
    assert_eq!(
        evidence["witness_sha256"],
        "539a6f61f1b6116373f743efc3ac1322020680d1e919f9852bd8a085d5102a44"
    );
    for (key, bytes) in [
        (
            "current_evaluation_ledger_sha256",
            crate::capability::capability_ledger_bytes(),
        ),
        (
            "witness_sha256",
            include_bytes!("../../schemas/capabilities/kubernetes-schema-witnesses.json").as_slice(),
        ),
    ] {
        let expected = evidence[key].as_str().required()?;
        let mut actual = String::new();
        for byte in ledger_digest(bytes) {
            use std::fmt::Write as _;
            write!(&mut actual, "{byte:02x}")?;
        }
        assert_eq!(actual, expected);
    }
    // Independently frozen source facts/role schema projections remain unchanged;
    // current enum evaluation must never rewrite historic observation provenance.
    let ledger: serde_json::Value = serde_json::from_slice(crate::capability::capability_ledger_bytes())?;
    let projection = serde_json::json!({
        "schema_profiles": ledger["schema_profiles"],
        "schema_definition_inventory": ledger["schema_definition_inventory"],
        "restriction_audit": ledger["restriction_audit"],
    });
    let bytes = serde_json::to_vec(&projection)?;
    let mut actual = String::new();
    for byte in ledger_digest(&bytes) {
        use std::fmt::Write as _;
        write!(&mut actual, "{byte:02x}")?;
    }
    assert_eq!(
        actual,
        "c21b5bca4a0765fb22363638cfb165fe86650ea1c264ef0595ee06ea7a249819"
    );
    assert_eq!(evidence["unchanged_source_schema_projection_sha256"], actual);
    let transition = &evidence["observation_basis_transition"];
    assert_eq!(transition["historical_ledger_sha256"], evidence["ledger_sha256"]);
    assert_eq!(
        transition["evaluation_ledger_sha256"],
        evidence["access_candidate_evaluation_ledger_sha256"]
    );
    assert_eq!(
        transition["verification_kind"],
        "schema-observation-basis-equivalence-only"
    );
    let ledger: serde_json::Value = serde_json::from_slice(crate::capability::capability_ledger_bytes())?;
    let mut roots = Vec::new();
    for resource in ledger["resources"].as_array().required()? {
        for profile in resource["proposed_admitted_api_profiles"].as_array().required()? {
            let status = profile["typed_field_pointers"]
                .as_array()
                .required()?
                .iter()
                .filter(|field| field["pointer"] == "/status")
                .cloned()
                .collect::<Vec<_>>();
            roots.push(serde_json::json!({
                "kind": resource["kind"],
                "api_version": profile["api_version"],
                "target_availability_ranges": profile["target_availability_ranges"],
                "root_schema_forms": profile["root_schema_forms"],
                "status_fields": status,
            }));
        }
    }
    for (key, projection) in [
        ("schema_profiles_sha256", ledger["schema_profiles"].clone()),
        ("api_root_status_sha256", serde_json::Value::Array(roots)),
    ] {
        let bytes = serde_json::to_vec(&projection)?;
        let mut actual = String::new();
        for byte in ledger_digest(&bytes) {
            use std::fmt::Write as _;
            write!(&mut actual, "{byte:02x}")?;
        }
        assert_eq!(actual, transition[key].as_str().required()?);
    }
    Ok(())
}

#[test]
fn networking_peer_conjunction_uses_admitted_namespaces_and_retains_partial_candidates() -> TestResult {
    let document = serde_json::json!({"apiVersion":"v1","kind":"List","items":[
        {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"policy","namespace":"b"},"spec":{"podSelector":{},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"a"}},"podSelector":{"matchLabels":{"app":"web"}}}]}]}},
        {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"a","labels":{"team":"a"}}},
        {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"b","labels":{"team":"b"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"intersection","namespace":"a","labels":{"app":"web"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"wrong-namespace","namespace":"b","labels":{"app":"web"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"excluded","namespace":"missing","labels":{"app":"other"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"unknown","namespace":"missing","labels":{"app":"web"}}}
    ]});
    let mut resources = set(&serde_json::to_string(&document)?, InputOrigin::Authored)?;
    let peer = Reference {
        from: ResourceId(0),
        path: path("/spec/ingress/0/from/0"),
        relation: RelationshipKind::Selector,
        target: ReferenceTarget::NetworkPolicyPeer {
            namespace_selector: Presence::Value(LabelSelector::from_match_labels(BTreeMap::from([(
                "team".to_owned(),
                "a".to_owned(),
            )]))),
            pod_selector: Presence::Value(LabelSelector::from_match_labels(BTreeMap::from([(
                "app".to_owned(),
                "web".to_owned(),
            )]))),
        },
        scope: ReferenceScope::SameNamespace,
    };
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let graph = resolve_supplied_references_for_target(
        &resources,
        std::slice::from_ref(&peer),
        &ReferenceContext::default(),
        &target,
    );
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::PartiallyResolvedSubjects{matched,unavailable} if matched==&[GraphSubject::Object{resource:ResourceId(3)}] && unavailable.len()==1 && unavailable[0].resource==ResourceId(6))
    );
    assert!(
        graph.edges[0]
            .evidence
            .iter()
            .any(|field| field.resource == ResourceId(1) && field.path == path("/metadata/labels"))
    );
    let malformed = crate::parse_source(
        SourceInput {
            id: SourceId(99),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"unknown-labels\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    resources.documents_mut()[4].set_field_from_source(path("/metadata/labels"), malformed)?;
    let graph = resolve_supplied_references_for_target(
        &resources,
        std::slice::from_ref(&peer),
        &ReferenceContext::default(),
        &target,
    );
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::PartiallyResolvedSubjects{matched,unavailable} if matched==&[GraphSubject::Object{resource:ResourceId(3)}] && unavailable.len()==1 && unavailable[0].resource==ResourceId(6))
    );
    let mut duplicates = document.clone();
    duplicates["items"]
        .as_array_mut()
        .required()?
        .push(document["items"][1].clone());
    duplicates["items"][7]["metadata"]["name"] = serde_json::json!("distinct");
    let mut resources = set(&serde_json::to_string(&duplicates)?, InputOrigin::Authored)?;
    let fixture = resources.documents_mut()[7].resource_mut::<Fixture>().required()?;
    let metadata = fixture.tree.get_path(&path("/metadata")).required()?.clone();
    let mut metadata = metadata;
    if let TreeValue::Mapping(entries) = &mut metadata.value {
        for (key, value) in entries {
            if key == "name" {
                value.value = TreeValue::String("a".to_owned());
            }
        }
    }
    if let TreeValue::Mapping(entries) = &mut fixture.tree.value {
        for (key, value) in entries {
            if key == "metadata" {
                *value = metadata.clone();
            }
        }
    }
    let graph = resolve_supplied_references_for_target(&resources, &[peer], &ReferenceContext::default(), &target);
    assert!(
        matches!(&graph.edges[0].resolution,Resolution::PartiallyResolvedSubjects{unavailable,..} if unavailable.iter().any(|gap|gap.reason==FactUnavailable::Unknown(FactGap::AmbiguousSuppliedEvidence)))
    );
    for supplier in [ResourceId(1), ResourceId(7)] {
        assert!(
            graph.edges[0]
                .evidence
                .iter()
                .any(|field| field.resource == supplier && field.path == path("/metadata/name"))
        );
    }
    Ok(())
}
#[test]
fn versionless_native_refs_use_group_kind_scope_name_and_never_prefer_served_versions() -> TestResult {
    let mut document = serde_json::json!({"apiVersion":"v1","kind":"List","items":[
        {"apiVersion":"networking.k8s.io/v1","kind":"Ingress","metadata":{"name":"source","namespace":"ns"},"spec":{"defaultBackend":{"resource":{"apiGroup":"example.org","kind":"Backend","name":"backend"}}}},
        {"apiVersion":"example.org/v2","kind":"Backend","metadata":{"name":"backend","namespace":"ns"}},
        {"apiVersion":"other.org/v1","kind":"Backend","metadata":{"name":"backend","namespace":"ns"}},
        {"apiVersion":"example.org/v1","kind":"Other","metadata":{"name":"backend","namespace":"ns"}}
    ]});
    document["items"].as_array_mut().required()?.push(serde_json::json!({
        "apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition",
        "metadata":{"name":"backends.example.org"},
        "spec":{"group":"example.org","names":{"kind":"Backend","plural":"backends"},
            "scope":"Namespaced","versions":[{"name":"v1","served":true},{"name":"v2","served":true}]}
    }));
    let reference = Reference {
        from: ResourceId(0),
        path: path("/spec/defaultBackend/resource"),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::GroupKindName {
            group: Presence::Value("example.org".to_owned()),
            kind: "Backend".to_owned(),
            name: "backend".to_owned(),
        },
        scope: ReferenceScope::SameNamespace,
    };
    let target = TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let resources = set(&serde_json::to_string(&document)?, InputOrigin::Authored)?;
    let graph = resolve_supplied_references_for_target(
        &resources,
        std::slice::from_ref(&reference),
        &ReferenceContext::default(),
        &target,
    );
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: ResourceId(1)
        }])
    );
    document["items"].as_array_mut().required()?.push(serde_json::json!({"apiVersion":"example.org/v1","kind":"Backend","metadata":{"name":"initially-unique","namespace":"ns"}}));
    let mut resources = set(&serde_json::to_string(&document)?, InputOrigin::Authored)?;
    let patch = crate::parse_source(
        SourceInput {
            id: SourceId(83),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"backend\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    resources.documents_mut()[5].set_field_from_source(path("/metadata/name"), patch)?;
    let graph = resolve_supplied_references_for_target(&resources, &[reference], &ReferenceContext::default(), &target);
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::Ambiguous(vec![ResourceId(1), ResourceId(5)])
    );
    Ok(())
}

#[test]
fn policy_separate_entries_select_a_union_and_keep_templates_distinct() -> TestResult {
    let document = serde_json::json!({"apiVersion":"v1","kind":"List","items":[
        {"apiVersion":"networking.k8s.io/v1","kind":"NetworkPolicy","metadata":{"name":"policy","namespace":"b"},"spec":{"podSelector":{},"ingress":[{"from":[{"namespaceSelector":{"matchLabels":{"team":"a"}}},{"podSelector":{"matchLabels":{"app":"web"}}}]}]}},
        {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"a","labels":{"team":"a"}}},
        {"apiVersion":"v1","kind":"Namespace","metadata":{"name":"b","labels":{"team":"b"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"by-namespace","namespace":"a","labels":{"app":"other"}}},
        {"apiVersion":"v1","kind":"Pod","metadata":{"name":"by-pod","namespace":"b","labels":{"app":"web"}}},
        {"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"template","namespace":"b"},"spec":{"template":{"metadata":{"labels":{"app":"web"}}}}}
    ]});
    let resources = set(&serde_json::to_string(&document)?, InputOrigin::Authored)?;
    let references = [
        Reference {
            from: ResourceId(0),
            path: path("/spec/ingress/0/from/0"),
            relation: RelationshipKind::Selector,
            target: ReferenceTarget::NetworkPolicyPeer {
                namespace_selector: Presence::Value(LabelSelector::from_match_labels(BTreeMap::from([(
                    "team".to_owned(),
                    "a".to_owned(),
                )]))),
                pod_selector: Presence::Absent,
            },
            scope: ReferenceScope::SameNamespace,
        },
        Reference {
            from: ResourceId(0),
            path: path("/spec/ingress/0/from/1"),
            relation: RelationshipKind::Selector,
            target: ReferenceTarget::NetworkPolicyPeer {
                namespace_selector: Presence::Absent,
                pod_selector: Presence::Value(LabelSelector::from_match_labels(BTreeMap::from([(
                    "app".to_owned(),
                    "web".to_owned(),
                )]))),
            },
            scope: ReferenceScope::SameNamespace,
        },
    ];
    let graph = resolve_supplied_references_for_target(
        &resources,
        &references,
        &ReferenceContext::default(),
        &TargetProfile::documented_defaults(KubernetesVersion::MAX),
    );
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: ResourceId(3)
        }])
    );
    assert_eq!(
        graph.edges[1].resolution,
        Resolution::ResolvedSubjects(vec![
            GraphSubject::Object {
                resource: ResourceId(4)
            },
            GraphSubject::Template {
                resource: ResourceId(5),
                path: path("/spec/template"),
                template_kind: TemplateKind::Pod
            }
        ])
    );
    Ok(())
}
