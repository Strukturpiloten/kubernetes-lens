//! A genuine test-only codec proves core deltas without pretending a delivered cohort exists.
use crate::{
    capability::{FieldAdmission, FieldCapability, KindCapability, KubernetesVersion, MergeStrategy},
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::ReferenceSink,
    model::{GroupVersionKind, ResourceScope, ResourceSet},
    parse_source,
    registry::{
        DecodeContext, EncodeContext, FindingSink, NativeResource, RegistryBuilder, ResourceRegistration,
        ValidationContext,
    },
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceEvidence, SourceId, SourceInput},
    syntax::{SyntaxBuilder, TreeNode, TreeValue, UnknownFields},
};
use std::any::Any;
struct TestPod {
    tree: TreeNode,
}
impl NativeResource for TestPod {
    fn as_any(&self) -> &dyn Any {
        self
    }
    fn as_any_mut(&mut self) -> &mut dyn Any {
        self
    }
    fn collect_references(&self, out: &mut dyn ReferenceSink) {
        if let Some(name) = self
            .tree
            .get("metadata")
            .and_then(|m| m.get("name"))
            .and_then(TreeNode::as_str)
        {
            if let Ok(gvk) = GroupVersionKind::new("v1", "Pod") {
                out.push(crate::graph::Reference {
                    from: crate::ResourceId(0),
                    path: FieldPath::default(),
                    relation: crate::graph::RelationshipKind::Dependency,
                    target: crate::graph::ReferenceTarget::Exact {
                        gvk: Some(gvk),
                        name: name.to_owned(),
                    },
                    scope: crate::graph::ReferenceScope::SameNamespace,
                });
            }
        }
    }
    fn collect_protected_paths(&self, out: &mut Vec<FieldPath>) {
        out.push(FieldPath(vec!["spec".into(), "protectedValue".into()]));
    }
    fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
        if ctx.target.kubernetes.minor() < 20 {
            out.push(Finding::error(FindingCode::InvalidTargetProfile, Phase::Validation));
        }
    }
    fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding> {
        let _ = ctx.target;
        out.set_root(self.tree.clone());
        Ok(())
    }
}
fn decode(
    node: &TreeNode,
    _: &SourceEvidence,
    ctx: &DecodeContext<'_>,
) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
    if ctx.gvk.kind != "Pod" || ctx.scope != ResourceScope::Namespaced {
        return Err(vec![Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding)]);
    }
    let mut tree = node.clone();
    remove(&mut tree);
    Ok(Box::new(TestPod { tree }))
}
fn remove(node: &mut TreeNode) {
    match &mut node.value {
        TreeValue::Mapping(entries) => {
            entries.retain(|(key, _)| !matches!(key.as_str(), "unknownRoot" | "unknownChild"));
            for (_, n) in entries {
                remove(n);
            }
        }
        TreeValue::Sequence(items) => {
            for n in items {
                remove(n);
            }
        }
        _ => {}
    }
}

fn fields() -> &'static [FieldCapability] {
    Box::leak(
        vec![FieldCapability {
            path: "/spec/containers",
            since: KubernetesVersion::MIN,
            feature_gate: None,
            removed: None,
            deprecated: None,
            admission: FieldAdmission::Typed,
            merge: MergeStrategy::MapList { keys: &["name"] },
            semantic_note: None,
        }]
        .into_boxed_slice(),
    )
}
fn entry() -> TestResult<ResourceRegistration> {
    let gvk = GroupVersionKind::new("v1", "Pod")?;
    Ok(ResourceRegistration {
        gvk: gvk.clone(),
        scope: ResourceScope::Namespaced,
        decode,
        capability: KindCapability {
            gvk,
            scope: ResourceScope::Namespaced,
            api_since: KubernetesVersion::MIN,
            api_removed: None,
            fields: fields(),
        },
    })
}
fn registry() -> TestResult<RegistryBuilder> {
    let mut registry = RegistryBuilder::new();
    registry.register(entry()?)?;
    Ok(registry)
}
fn input(text: &str) -> TestResult<crate::ParsedInput> {
    parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()
}
fn set_field(name: &str, node: &mut TreeNode, value: TreeNode) -> TestResult<()> {
    let TreeValue::Mapping(entries) = &mut node.value else {
        return Err("expected fixture map".into());
    };
    entries.iter_mut().find(|(key, _)| key == name).required()?.1 = value;
    Ok(())
}
#[test]
fn downcast_delta_retains_unknown_children_null_and_reordered_keyed_items() -> TestResult<()> {
    let mut resources=ResourceSet::with_registry(vec![input("apiVersion: v1\nkind: Pod\nmetadata: {name: one, namespace: ns}\nunknownRoot: retained\nspec: {nullable: null, containers: [{name: first, image: old, unknownChild: private}, {name: second, image: same}]}\n")?],&registry()?).required()?;
    let doc = &mut resources.documents_mut()[0];
    let typed = doc.resource_mut::<TestPod>().required()?;
    let TreeValue::Mapping(root) = &mut typed.tree.value else {
        return Err("expected fixture shape".into());
    };
    let spec = &mut root.iter_mut().find(|(key, _)| key == "spec").required()?.1;
    let TreeValue::Mapping(spec) = &mut spec.value else {
        return Err("expected fixture shape".into());
    };
    let containers = &mut spec.iter_mut().find(|(key, _)| key == "containers").required()?.1;
    let TreeValue::Sequence(items) = &mut containers.value else {
        return Err("expected fixture shape".into());
    };
    set_field("image", &mut items[0], TreeNode::string("new"))?;
    items.swap(0, 1);
    let current = doc.current_tree(None).required()?;
    let mut text = String::new();
    crate::generation::json(&current, &mut text).required()?;
    for value in ["private", "retained", "new", "\"nullable\":null"] {
        assert!(text.contains(value));
    }
    assert!(!text.contains("old"));
    assert!(doc.resource::<TestPod>().is_some());
    Ok(())
}
#[test]
fn atomic_unknown_loss_blocks_and_explicit_patch_resolves() -> TestResult<()> {
    let raw = input("[{name: one, value: before, unknownChild: private}]")?
        .trees
        .remove(0);
    let before = input("[{name: one, value: before}]")?.trees.remove(0);
    let after = input("[{name: one, value: after}]")?.trees.remove(0);
    let path = FieldPath::parse("/spec/atomic").required()?;
    let error = crate::generation::merge_delta(&raw, &before, &after, &path, &[], &[])
        .err()
        .required()?;
    assert_eq!(error.code, FindingCode::MergeConflict);
    assert_eq!(error.path, Some(path.clone()));
    let explicit = crate::model::FieldEdit::Set {
        path: path.clone(),
        value: after.clone(),
    };
    assert!(crate::generation::merge_delta(&raw, &before, &after, &path, &[], &[explicit]).is_ok());
    Ok(())
}
#[test]
fn absent_known_null_and_recursive_unknown_capture() -> TestResult<()> {
    let raw = input("{nullable: null, known: before, unknown: {nested: private}}")?
        .trees
        .remove(0);
    let before = input("{known: before}")?.trees.remove(0);
    let after = input("{known: after}")?.trees.remove(0);
    let out = crate::generation::merge_delta(&raw, &before, &after, &FieldPath::default(), &[], &[]).required()?;
    assert!(out.get("nullable").is_some());
    assert_eq!(out.get("known").and_then(TreeNode::as_str), Some("after"));
    let unknown = UnknownFields::capture(&out, &["known", "nullable"]);
    assert_eq!(unknown.len(), 1);
    assert!(!format!("{unknown:?}").contains("private"));
    let mut entries = Vec::new();
    unknown.append_to(&mut entries);
    assert_eq!(entries.len(), 1);
    Ok(())
}
#[test]
fn duplicate_registry_and_live_codec_gvk_divergence_fail() -> TestResult<()> {
    let mut registry = registry()?;
    assert!(registry.register(entry()?).is_err());
    let mut resources = ResourceSet::with_registry(
        vec![input(
            "apiVersion: v1\nkind: Pod\nmetadata: {name: one, namespace: ns}",
        )?],
        &registry,
    )
    .required()?;
    let doc = &mut resources.documents_mut()[0];
    set_field(
        "kind",
        &mut doc.resource_mut::<TestPod>().required()?.tree,
        TreeNode::string("Secret"),
    )?;
    assert_eq!(
        doc.identity().err().required()?.code,
        FindingCode::CodecIdentityMismatch
    );
    Ok(())
}

type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
trait Require<T> {
    fn required(self) -> TestResult<T>;
}
impl<T> Require<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| "missing fixture condition".into())
    }
}
impl<T, E: std::fmt::Debug> Require<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|error| format!("{error:?}").into())
    }
}

#[test]
fn codec_declared_non_secret_private_field_requires_explicit_native_output() -> TestResult<()> {
    let resources=ResourceSet::with_registry(vec![input("apiVersion: v1\nkind: Pod\nmetadata: {name: private, namespace: ns}\nspec: {protectedValue: ACTUAL_PRIVATE_VALUE}\n")?],&registry()?).required()?;
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let options = crate::generation::GenerationOptions {
        opaque_fields: crate::generation::OpaqueFieldPolicy::PreserveWithFinding,
        ..Default::default()
    };
    let errors = crate::generate(&resources, &target, crate::generation::OutputFormat::Json, &options)
        .err()
        .required()?;
    assert!(
        errors
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    let options = crate::generation::GenerationOptions {
        protected_output: crate::generation::ProtectedOutput::Include,
        ..options
    };
    let artifact = crate::generate(&resources, &target, crate::generation::OutputFormat::Json, &options).required()?;
    let text = std::str::from_utf8(
        artifact.reveal_bytes(&crate::generation::ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
    )?;
    assert!(text.contains("ACTUAL_PRIVATE_VALUE"));
    assert!(!format!("{artifact:?}").contains("ACTUAL_PRIVATE_VALUE"));
    Ok(())
}

#[test]
fn review_empty_unknown_containers_block_but_exact_known_containers_are_admitted() -> TestResult<()> {
    let mut entry = entry()?;
    let fields = [
        "/metadata",
        "/metadata/name",
        "/metadata/namespace",
        "/spec",
        "/spec/knownEmptyMap",
        "/spec/knownEmptyList",
    ]
    .into_iter()
    .map(|path| FieldCapability {
        path,
        since: KubernetesVersion::MIN,
        feature_gate: None,
        removed: None,
        deprecated: None,
        admission: FieldAdmission::Typed,
        merge: MergeStrategy::AtomicList,
        semantic_note: None,
    })
    .collect::<Vec<_>>();
    entry.capability.fields = Box::leak(fields.into_boxed_slice());
    let mut registry = RegistryBuilder::new();
    registry.register(entry)?;
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    for value in ["{}", "[]"] {
        let source = format!(
            "apiVersion: v1\nkind: Pod\nmetadata: {{name: child, namespace: demo}}\nspec: {{knownEmptyMap: {{}}, knownEmptyList: [], unknownRoot: {value}}}\n"
        );
        let resources = ResourceSet::with_registry(vec![input(&source)?], &registry).required()?;
        let errors = crate::generate(
            &resources,
            &target,
            crate::generation::OutputFormat::Yaml,
            &crate::generation::GenerationOptions::default(),
        )
        .err()
        .required()?;
        assert!(
            errors
                .iter()
                .any(|finding| finding.code == FindingCode::OpaqueOutputDenied)
        );
    }
    let resources = ResourceSet::with_registry(vec![input("apiVersion: v1\nkind: Pod\nmetadata: {name: child, namespace: demo}\nspec: {knownEmptyMap: {}, knownEmptyList: []}\n")?], &registry).required()?;
    assert!(
        crate::generate(
            &resources,
            &target,
            crate::generation::OutputFormat::Yaml,
            &crate::generation::GenerationOptions::default()
        )
        .is_ok()
    );
    Ok(())
}
#[test]
fn review_internal_duplicate_provenance_cannot_overwrite_generation_or_graph() -> TestResult<()> {
    let mut resources = ResourceSet::with_registry(vec![input("apiVersion: v1\nkind: Pod\nmetadata: {name: first, namespace: demo}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: second, namespace: demo}\n")?], &registry()?).required()?;
    resources.documents[1].id = resources.documents[0].id;
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    let options = crate::generation::GenerationOptions {
        opaque_fields: crate::generation::OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: crate::generation::ProtectedOutput::Include,
        ..Default::default()
    };
    assert!(
        crate::generate(&resources, &target, crate::generation::OutputFormat::Json, &options)
            .err()
            .required()?
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidIdentity)
    );
    assert!(
        crate::graph::resolve_references(&resources)
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidIdentity)
    );
    Ok(())
}
#[test]
fn review_empty_typed_list_checks_removed_api_and_wrapper_policies() -> TestResult<()> {
    let mut registry = RegistryBuilder::new();
    registry.register_list(crate::registry::TypedListRegistration {
        gvk: GroupVersionKind::new("batch/v1beta1", "CronJobList")?,
        item_gvk: GroupVersionKind::new("batch/v1beta1", "CronJob")?,
    })?;
    let resources = ResourceSet::with_registry(vec![input("apiVersion: batch/v1beta1\nkind: CronJobList\nmetadata: {resourceVersion: '42'}\nunknownRoot: private-value\nitems: []\n")?], &registry).required()?;
    for collections in [
        crate::generation::CollectionOutput::PreserveWrappers,
        crate::generation::CollectionOutput::Flatten,
    ] {
        for format in [
            crate::generation::OutputFormat::Yaml,
            crate::generation::OutputFormat::Json,
        ] {
            let options = crate::generation::GenerationOptions {
                collections,
                ..Default::default()
            };
            let available = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::new(1, 24)?);
            let explicit = crate::generation::GenerationOptions {
                opaque_fields: crate::generation::OpaqueFieldPolicy::PreserveWithFinding,
                protected_output: crate::generation::ProtectedOutput::Include,
                ..options.clone()
            };
            assert!(crate::generate(&resources, &available, format, &explicit).is_ok());
            let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::new(1, 25)?);
            let errors = crate::generate(&resources, &target, format, &options)
                .err()
                .required()?;
            for code in [
                FindingCode::UnavailableApi,
                FindingCode::OpaqueOutputDenied,
                FindingCode::ProtectedOutputDenied,
            ] {
                assert!(
                    errors
                        .iter()
                        .any(|finding| finding.code == code && finding.wrapper.is_some())
                );
            }
        }
    }
    Ok(())
}

#[test]
fn review_internal_duplicate_wrapper_ids_cannot_overwrite_reconstruction() -> TestResult<()> {
    let mut resources = ResourceSet::with_registry(
        vec![input(
            "apiVersion: v1\nkind: List\nitems: []\n---\napiVersion: v1\nkind: List\nitems: []\n",
        )?],
        &registry()?,
    )
    .required()?;
    assert_eq!(resources.lists()[0].id(), crate::model::ListId(0));
    assert!(resources.lists()[0].item_ids().is_empty());
    assert_eq!(resources.lists()[0].source().source, SourceId(0));
    assert!(resources.lists()[0].collection().is_none());
    resources.lists[1].id = resources.lists[0].id;
    let target = crate::capability::TargetProfile::documented_defaults(KubernetesVersion::MAX);
    assert!(
        crate::generate(
            &resources,
            &target,
            crate::generation::OutputFormat::Yaml,
            &crate::generation::GenerationOptions::default()
        )
        .err()
        .required()?
        .iter()
        .any(|finding| finding.code == FindingCode::InvalidIdentity)
    );
    let finding = resources
        .identity_findings()
        .into_iter()
        .find(|finding| finding.code == FindingCode::InvalidIdentity)
        .required()?;
    let subject = finding.wrapper.required()?;
    assert_eq!(subject.source.source, SourceId(0));
    assert_eq!(subject.source.document_index, 1);
    assert_eq!(subject.list, crate::model::ListId(0));
    Ok(())
}

#[path = "core.rs"]
mod core_tests;

#[path = "root_status.rs"]
mod root_status;
