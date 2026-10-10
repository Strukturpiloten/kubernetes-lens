//! Public foundation behavior, independent from native/runtime compatibility evidence.
use kubernetes_lens::{
    FieldPath,
    capability::{FeatureGateId, FeatureGateState, KubernetesVersion, TargetProfile},
    diagnostic::{FindingCode, Phase},
    generate,
    generation::{
        CollectionOutput, ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat,
        ProtectedOutput,
    },
    graph::{
        Reference, ReferenceContext, ReferenceScope, ReferenceTarget, RelationshipKind, Resolution,
        resolve_supplied_references,
    },
    model::{GroupVersionKind, ResourceSet},
    parse_source,
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::{IntOrPercent, IntOrString, LabelSelector, Presence, Protected, Quantity},
};
fn parsed(bytes: &[u8], format: DocumentFormat) -> TestResult<kubernetes_lens::ParsedInput> {
    parse_source(
        SourceInput {
            id: SourceId(4),
            format,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes,
        },
        &ParseLimits::default(),
    )
    .required()
}
fn resources(text: &str) -> TestResult<ResourceSet> {
    parsed(text.as_bytes(), DocumentFormat::YamlStream)?
        .flatten_resources()
        .required()
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn preserve() -> GenerationOptions {
    GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    }
}
fn bytes(artifact: &kubernetes_lens::generation::GeneratedArtifact) -> &[u8] {
    artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact())
}
#[test]
fn strict_json_duplicate_escape_keys_and_redaction() -> TestResult<()> {
    let findings = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: br#"{"private-key":1,"private\u002dkey":2}"#,
        },
        &ParseLimits::default(),
    )
    .err()
    .required()?;
    assert_eq!(findings[0].code, FindingCode::DuplicateKey);
    assert_eq!(findings[0].source.required()?.byte_offset, 17);
    assert!(!format!("{findings:?}").contains("private"));
    assert!(!findings[0].to_string().contains("private-key"));
    Ok(())
}
#[test]
fn yaml_duplicate_unicode_positions_after_block_scalar() -> TestResult<()> {
    for text in [
        "x: café\nx: other\n",
        "x: \"café\"\nx: other\n",
        "x: |\n  café😀\nx: other\n",
    ] {
        let errors = parse_source(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &ParseLimits::default(),
        )
        .err()
        .required()?;
        let point = errors[0].source.required()?;
        assert_eq!(errors[0].code, FindingCode::DuplicateKey);
        assert_eq!(usize::try_from(point.byte_offset)?, text.rfind("x:").required()?);
        assert_eq!(point.column, 1);
    }
    Ok(())
}
#[test]
fn malformed_json_unicode_point_is_byte_offset() -> TestResult<()> {
    let text = "{\"café\":\"😀\",\"next\": }";
    let errors = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .err()
    .required()?;
    let point = errors[0].source.required()?;
    assert_eq!(usize::try_from(point.byte_offset)?, text.len() - 1);
    assert_eq!(point.column as usize, text.chars().count());
    Ok(())
}
#[test]
fn reject_alias_cycles_merge_keys_and_ambiguous_scalars() -> TestResult<()> {
    for (text, code) in [
        ("x: &a [*a]", FindingCode::InvalidAlias),
        ("x: &a {v: 1}\ny: {<<: *a}", FindingCode::UnsupportedMergeKey),
        ("x: 0x10", FindingCode::UnsupportedScalar),
        ("x: +1", FindingCode::UnsupportedScalar),
        ("x: .inf", FindingCode::UnsupportedScalar),
        ("true: 1", FindingCode::InvalidMappingKey),
    ] {
        let errors = parse_source(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &ParseLimits::default(),
        )
        .err()
        .required()?;
        assert_eq!(errors[0].code, code, "{text}");
    }
    Ok(())
}
#[test]
fn budgets_are_independent_and_alias_expansion_bounded() -> TestResult<()> {
    let source = "x: &a [one,two]\ny: *a\n---\nx: three\n";
    let defaults = ParseLimits::default();
    let policies = [
        ParseLimits {
            max_input_bytes: 3,
            ..defaults
        },
        ParseLimits {
            max_documents: 1,
            ..defaults
        },
        ParseLimits {
            max_events: 1,
            ..defaults
        },
        ParseLimits {
            max_nodes: 1,
            ..defaults
        },
        ParseLimits {
            max_depth: 1,
            ..defaults
        },
        ParseLimits {
            max_scalar_bytes: 1,
            ..defaults
        },
        ParseLimits {
            max_aliases: 0,
            ..defaults
        },
        ParseLimits {
            max_alias_visits: 1,
            ..defaults
        },
    ];
    for limits in policies {
        let errors = parse_source(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: source.as_bytes(),
            },
            &limits,
        )
        .err()
        .required()?;
        assert_eq!(errors[0].code, FindingCode::LimitExceeded);
    }
    let valid = parsed(source.as_bytes(), DocumentFormat::YamlStream)?;
    assert_eq!(valid.document_count(), 2);
    Ok(())
}
#[test]
fn source_evidence_is_immutable_and_private() -> TestResult<()> {
    let text = "apiVersion: v1\nkind: Secret\nmetadata: {name: private-name}\nstringData: {password: PRIVATE_TOKEN}\n";
    let parsed = parsed(text.as_bytes(), DocumentFormat::YamlStream)?;
    assert!(!format!("{parsed:?}").contains("PRIVATE_TOKEN"));
    assert_eq!(
        parsed
            .source()
            .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    let set = parsed.flatten_resources().required()?;
    assert!(!format!("{set:?}").contains("private-name"));
    assert!(!format!("{set:?}").contains("PRIVATE_TOKEN"));
    let errors = generate(&set, &target(37)?, OutputFormat::Yaml, &GenerationOptions::default())
        .err()
        .required()?;
    assert!(errors.iter().any(|f| f.code == FindingCode::ProtectedOutputDenied));
    let artifact = generate(&set, &target(37)?, OutputFormat::Yaml, &preserve()).required()?;
    assert!(String::from_utf8_lossy(bytes(&artifact)).contains("PRIVATE_TOKEN"));
    assert!(!format!("{artifact:?}").contains("PRIVATE_TOKEN"));
    Ok(())
}
#[test]
fn collisions_ignore_served_version_without_inventing_namespace() -> TestResult<()> {
    let text = "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: same, namespace: supplied}\n---\napiVersion: batch/v1beta1\nkind: CronJob\nmetadata: {name: same, namespace: supplied}\n";
    let findings = parsed(text.as_bytes(), DocumentFormat::YamlStream)?
        .flatten_resources()
        .err()
        .required()?;
    assert!(findings.iter().any(|f| f.code == FindingCode::DuplicateIdentity));
    let unnamed = resources("apiVersion: v1\nkind: Pod\nmetadata: {generateName: prefix-}\n")?;
    assert!(unnamed.documents()[0].identity().required()?.collision_key().is_none());
    let missing_namespace = resources("apiVersion: v1\nkind: Pod\nmetadata: {name: same}\n")?;
    assert_eq!(
        missing_namespace.documents()[0].identity().required()?.namespace,
        Presence::Absent
    );
    Ok(())
}
#[test]
fn lists_rewrap_nested_metadata_and_typed_list_gvk() -> TestResult<()> {
    let text = "apiVersion: v1\nkind: List\nmetadata: {resourceVersion: original}\nitems:\n- apiVersion: v1\n  kind: PodList\n  metadata: {continue: marker}\n  items:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: one, namespace: ns}\n    spec: {containers: [{name: main, image: example/app:v1}]}\n";
    let set = resources(text)?;
    assert_eq!(set.documents().len(), 1);
    assert_eq!(set.lists().len(), 2);
    assert_eq!(set.documents()[0].collection().required()?.items.len(), 2);
    let artifact = generate(&set, &target(37)?, OutputFormat::Yaml, &preserve()).required()?;
    let again = resources(std::str::from_utf8(bytes(&artifact)).required()?)?;
    assert_eq!(again.lists().len(), 2);
    let output = String::from_utf8_lossy(bytes(&artifact));
    assert!(output.contains("original"));
    assert!(output.contains("marker"));
    let mut options = preserve();
    options.collections = CollectionOutput::Flatten;
    let flat = generate(&set, &target(37)?, OutputFormat::Yaml, &options).required()?;
    assert_eq!(
        resources(std::str::from_utf8(bytes(&flat)).required()?)?.lists().len(),
        0
    );
    assert!(
        parsed(
            b"apiVersion: v1\nkind: PodList\nitems: [{apiVersion: v1, kind: Secret, metadata: {name: wrong}}]",
            DocumentFormat::YamlStream
        )?
        .flatten_resources()
        .is_err()
    );
    Ok(())
}
#[test]
fn target_api_boundaries_and_finite_gate_settings() -> TestResult<()> {
    assert!(KubernetesVersion::new(1, 19).is_err());
    assert!(KubernetesVersion::new(1, 38).is_err());
    assert!(KubernetesVersion::new(2, 20).is_err());
    assert_eq!(FeatureGateId::ALL.len(), 51);
    assert_eq!(kubernetes_lens::capability::KindId::ALL.len(), 35);
    let set = resources("apiVersion: policy/v1beta1\nkind: PodSecurityPolicy\nmetadata: {name: legacy}\n")?;
    assert!(generate(&set, &target(24)?, OutputFormat::Yaml, &preserve()).is_ok());
    let errors = generate(&set, &target(25)?, OutputFormat::Yaml, &preserve())
        .err()
        .required()?;
    assert!(errors.iter().any(|f| f.code == FindingCode::UnavailableApi));
    let mut t = target(37)?;
    t.feature_gates
        .states
        .insert(FeatureGateId::GenericEphemeralVolume, FeatureGateState::Disabled);
    assert!(!t.findings().is_empty());
    let mut t = target(20)?;
    t.feature_gates
        .states
        .insert(FeatureGateId::ProcMountType, FeatureGateState::Unknown);
    assert!(!t.findings().is_empty());
    Ok(())
}
#[test]
fn effective_edits_recheck_identity_and_do_not_overlay_stale_values() -> TestResult<()> {
    let mut set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: before, namespace: ns}\nspec: {containers: [{name: main, image: example/app:v1}], field: old, nullValue: null, privateExtension: {nested: retained}}\n",
    )?;
    set.documents_mut()[0]
        .set_field_from_source(
            FieldPath::parse("/metadata/name").required()?,
            parsed(b"\"after\"", DocumentFormat::Json)?,
        )
        .required()?;
    set.documents_mut()[0]
        .set_field_from_source(
            FieldPath::parse("/spec/field").required()?,
            parsed(b"\"new\"", DocumentFormat::Json)?,
        )
        .required()?;
    set.documents_mut()[0].set_null(FieldPath::parse("/spec/nullValue").required()?);
    let id = set.documents()[0].identity().required()?;
    assert_eq!(id.name, Presence::Value("after".into()));
    let first = generate(&set, &target(37)?, OutputFormat::Json, &preserve()).required()?;
    let second = generate(&set, &target(37)?, OutputFormat::Json, &preserve()).required()?;
    assert_eq!(bytes(&first), bytes(&second));
    let output = String::from_utf8_lossy(bytes(&first));
    assert!(output.contains("retained"));
    assert!(output.contains("new"));
    assert!(!output.contains("before"));
    assert!(
        String::from_utf8_lossy(
            set.documents()[0]
                .source_evidence()
                .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source())
        )
        .contains("before")
    );
    set.documents_mut()[0]
        .set_field_from_source(
            FieldPath::parse("/apiVersion").required()?,
            parsed(b"\"v2\"", DocumentFormat::Json)?,
        )
        .required()?;
    assert!(set.documents()[0].identity().is_err());
    Ok(())
}
fn reference(from: u64, name: &str) -> TestResult<Reference> {
    Ok(Reference {
        from: kubernetes_lens::ResourceId(from),
        path: FieldPath::parse("/spec/target")?,
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::Exact {
            gvk: Some(GroupVersionKind::new("v1", "Pod")?),
            name: name.into(),
        },
        scope: ReferenceScope::SameNamespace,
    })
}
#[test]
fn supplied_graph_namespace_context_selectors_missing_external_and_cycles() -> TestResult<()> {
    let set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: one, labels: {app: match}}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: two}\n",
    )?;
    let refs = vec![reference(0, "two")?, reference(1, "one")?];
    let graph = resolve_supplied_references(&set, &refs, &ReferenceContext::default());
    assert!(matches!(graph.edges[0].resolution, Resolution::Unsupported(_)));
    let context = ReferenceContext {
        default_namespace: Some("explicit".into()),
        ..ReferenceContext::default()
    };
    let graph = resolve_supplied_references(&set, &refs, &context);
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::Resolved(vec![kubernetes_lens::ResourceId(1)])
    );
    assert!(graph.findings.iter().any(|f| f.code == FindingCode::ReferenceCycle));
    assert_eq!(set.documents()[0].identity().required()?.namespace, Presence::Absent);
    let mut selector = LabelSelector::default();
    selector.match_labels = Presence::Value(std::collections::BTreeMap::from([("app".into(), "match".into())]));
    let mut r = reference(0, "none")?;
    r.target = ReferenceTarget::LabelSelector {
        kinds: &[kubernetes_lens::capability::KindId::Pod],
        selector,
    };
    let graph = resolve_supplied_references(&set, &[r], &context);
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::Resolved(vec![kubernetes_lens::ResourceId(0)])
    );
    let graph = resolve_supplied_references(&set, &[reference(0, "missing")?], &context);
    assert_eq!(graph.edges[0].resolution, Resolution::Missing);
    let mut r = reference(0, "none")?;
    r.target = ReferenceTarget::External {
        kind: kubernetes_lens::graph::ExternalRefKind::Remote,
    };
    assert!(matches!(
        resolve_supplied_references(&set, &[r], &context).edges[0].resolution,
        Resolution::External(_)
    ));
    Ok(())
}
#[test]
fn crd_scope_comes_only_from_supplied_served_version_evidence() -> TestResult<()> {
    let set = resources(
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.example.test}\nspec: {group: example.test, scope: Namespaced, names: {kind: Widget}, versions: [{name: v1, served: true}, {name: v2, served: false}]}\n---\napiVersion: example.test/v1\nkind: Widget\nmetadata: {name: one, namespace: ns}\n---\napiVersion: example.test/v2\nkind: Widget\nmetadata: {name: two, namespace: ns}\n",
    )?;
    assert_eq!(
        set.documents()[1].identity().required()?.scope,
        kubernetes_lens::model::ResourceScope::CrdResolved { namespaced: true }
    );
    assert_eq!(
        set.documents()[2].identity().required()?.scope,
        kubernetes_lens::model::ResourceScope::Unknown
    );
    Ok(())
}
#[test]
fn exact_quantities_and_general_named_ports_do_not_round() -> TestResult<()> {
    let a = Quantity::parse("9007199254740993").required()?;
    let b = Quantity::parse("9007199254740993000m").required()?;
    assert!(a.equivalent_to(&b));
    assert!(
        Quantity::parse("1Ki")
            .required()?
            .equivalent_to(&Quantity::parse("1024").required()?)
    );
    assert!(Quantity::parse("1e2147483648").is_err());
    assert!(IntOrPercent::parse_percent("101%").is_err());
    assert!(IntOrPercent::parse_percent("http").is_err());
    assert!(!format!("{:?}", IntOrString::String("PRIVATE".into())).contains("PRIVATE"));
    assert!(!format!("{:?}", Protected::new("PRIVATE")).contains("PRIVATE"));
    Ok(())
}
#[test]
fn json_single_resource_requires_one_document() -> TestResult<()> {
    let set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: one}\nspec: {containers: [{name: main, image: example/app:v1}]}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: two}\nspec: {containers: [{name: main, image: example/app:v1}]}\n",
    )?;
    let mut options = preserve();
    options.json_shape = JsonShape::SingleResource;
    let errors = generate(&set, &target(37)?, OutputFormat::Json, &options)
        .err()
        .required()?;
    assert!(
        errors
            .iter()
            .any(|f| f.code == FindingCode::MalformedDocument && f.phase == Phase::Generation)
    );
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn acquisition_bounds_extensions_symlinks_duplicate_files_and_deterministic_order() -> TestResult<()> {
    use kubernetes_lens::acquisition::{AcquisitionOptions, acquire};
    use std::{fs, os::unix::fs::symlink};
    let directory = std::env::temp_dir().join(format!("kubernetes-foundation-acquire-{}", std::process::id()));
    let _ = fs::remove_dir_all(&directory);
    fs::create_dir(&directory).required()?;
    fs::write(
        directory.join("b.yaml"),
        "apiVersion: v1\nkind: Pod\nmetadata: {name: b}\n",
    )
    .required()?;
    fs::write(
        directory.join("a.json"),
        r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"a"}}"#,
    )
    .required()?;
    let options = AcquisitionOptions::default();
    let input = acquire(&directory, &options).required()?;
    assert_eq!(input.inputs().len(), 2);
    assert_eq!(input.inputs()[0].source().format, DocumentFormat::Json);
    assert!(!format!("{input:?}").contains("a.json"));
    assert!(
        acquire(
            &directory,
            &AcquisitionOptions {
                max_files: 1,
                ..options.clone()
            }
        )
        .is_err()
    );
    assert!(
        acquire(
            &directory,
            &AcquisitionOptions {
                max_total_bytes: 5,
                ..options.clone()
            }
        )
        .is_err()
    );
    symlink(directory.join("a.json"), directory.join("escape.json")).required()?;
    assert!(acquire(&directory, &options).is_err());
    fs::remove_file(directory.join("escape.json")).required()?;
    fs::hard_link(directory.join("a.json"), directory.join("copy.json")).required()?;
    assert!(acquire(&directory, &options).is_err());
    fs::remove_file(directory.join("copy.json")).required()?;
    fs::write(directory.join("other.txt"), "private").required()?;
    assert!(acquire(&directory, &options).is_err());
    fs::remove_dir_all(directory).required()?;
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
        self.map_err(|error| format!("fixture operation failed: {error:?}").into())
    }
}

#[test]
fn target_field_and_gate_checks_cover_selected_families_and_nested_templates() -> TestResult<()> {
    let set = resources(
        "apiVersion: v1\nkind: Service\nmetadata: {name: modern, namespace: ns}\nspec: {trafficDistribution: PreferClose}\n",
    )?;
    let findings = kubernetes_lens::validate_for_target(&set, &target(20)?);
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::UnavailableField)
    );
    assert!(generate(&set, &target(20)?, OutputFormat::Yaml, &preserve()).is_err());
    let set = resources(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: gated, namespace: ns}\nspec: {template: {spec: {volumes: [{name: temp, ephemeral: {volumeClaimTemplate: {metadata: {name: generated}, spec: {}}}}]}}}\n",
    )?;
    assert!(
        kubernetes_lens::validate_for_target(&set, &target(20)?)
            .iter()
            .any(|finding| finding.code == FindingCode::FeatureGateRequired)
    );
    assert!(
        !kubernetes_lens::validate_for_target(&set, &target(23)?)
            .iter()
            .any(|finding| finding.code == FindingCode::FeatureGateRequired)
    );
    Ok(())
}
#[test]
fn strict_scalar_lexemes_and_yaml_quantity_strings_are_preserved() -> TestResult<()> {
    let set=parsed(br#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"number","namespace":"ns"},"spec":{"containers":[{"name":"main","image":"example/app:v1"}],"exact":9007199254740993,"exponent":1.2300e+03}}"#,DocumentFormat::Json)?.flatten_resources().required()?;
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &preserve()).required()?;
    let text = std::str::from_utf8(bytes(&artifact))?;
    assert!(text.contains("9007199254740993"));
    assert!(text.contains("1.2300e+03"));
    let set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: quantities, namespace: ns}\nspec: {containers: [{name: main, image: example/app:v1, resources: {requests: {cpu: 100m, memory: 1Gi}}}]}\n",
    )?;
    assert!(generate(&set, &target(37)?, OutputFormat::Yaml, &preserve()).is_ok());
    Ok(())
}
#[test]
fn served_version_reference_resolution_and_edit_collisions() -> TestResult<()> {
    let mut set = resources(
        "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: target, namespace: ns}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: source, namespace: ns}\n",
    )?;
    let mut reference = reference(1, "target")?;
    reference.target = ReferenceTarget::Exact {
        gvk: Some(GroupVersionKind::new("batch/v1beta1", "CronJob")?),
        name: "target".into(),
    };
    let graph = resolve_supplied_references(&set, &[reference], &ReferenceContext::default());
    assert_eq!(
        graph.edges[0].resolution,
        Resolution::Resolved(vec![kubernetes_lens::ResourceId(0)])
    );
    set.documents_mut()[0].set_field_from_source(
        FieldPath::parse("/metadata/name")?,
        parsed(b"\"renamed\"", DocumentFormat::Json)?,
    )?;
    assert_eq!(set.documents()[0].identity()?.name, Presence::Value("renamed".into()));
    let mut pods = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: one, namespace: ns}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: two, namespace: ns}\n",
    )?;
    pods.documents_mut()[1].set_field_from_source(
        FieldPath::parse("/metadata/name")?,
        parsed(b"\"one\"", DocumentFormat::Json)?,
    )?;
    assert!(
        pods.identity_findings()
            .iter()
            .any(|finding| finding.code == FindingCode::DuplicateIdentity)
    );
    assert!(generate(&pods, &target(37)?, OutputFormat::Yaml, &preserve()).is_err());
    Ok(())
}

#[test]
fn unavailable_builtin_versions_and_crd_scope_edits_cannot_emit() -> TestResult<()> {
    let set =
        resources("apiVersion: apps/v99\nkind: Deployment\nmetadata: {name: unknown-served-version, namespace: ns}\n")?;
    assert_eq!(
        set.documents()[0].identity()?.scope,
        kubernetes_lens::model::ResourceScope::Namespaced
    );
    let errors = generate(&set, &target(37)?, OutputFormat::Yaml, &preserve())
        .err()
        .required()?;
    assert!(errors.iter().any(|f| f.code == FindingCode::UnavailableApi));
    let mut crd = resources(
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.example.test}\nspec: {group: example.test, scope: Namespaced, names: {kind: Widget}, versions: [{name: v1, served: true}]}\n",
    )?;
    crd.documents_mut()[0].set_field_from_source(
        FieldPath::parse("/spec/scope")?,
        parsed(b"\"Cluster\"", DocumentFormat::Json)?,
    )?;
    assert_eq!(
        crd.documents()[0].identity().err().required()?.code,
        FindingCode::UnsupportedSemanticConversion
    );
    assert!(IntOrPercent::Percent(101).validate().is_err());
    Ok(())
}

#[test]
fn deeply_nested_yaml_stops_before_recursive_loader_and_alias_budgets_span_documents() -> TestResult<()> {
    let text = format!("{}0{}", "[".repeat(20_000), "]".repeat(20_000));
    let errors = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .err()
    .required()?;
    assert!(matches!(
        errors[0].code,
        FindingCode::LimitExceeded | FindingCode::MalformedDocument
    ));
    let text = "x: &a value\ny: *a\n---\nx: &a value\ny: *a\n";
    let limits = ParseLimits {
        max_alias_visits: 1,
        ..Default::default()
    };
    let errors = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &limits,
    )
    .err()
    .required()?;
    assert_eq!(errors[0].code, FindingCode::LimitExceeded);
    let text = "x: &a value\n---\ny: *a\n";
    assert!(
        parse_source(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: text.as_bytes()
            },
            &ParseLimits::default()
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn review_identity_requires_value_and_cluster_collision_ignores_namespace_presence() -> TestResult<()> {
    for metadata in [
        "{}",
        "{name: null}",
        "{generateName: null}",
        "{name: null, generateName: null}",
    ] {
        let input = parsed(
            format!("apiVersion: v1\nkind: Pod\nmetadata: {metadata}\n").as_bytes(),
            DocumentFormat::YamlStream,
        )?;
        assert!(input.flatten_resources().is_err());
    }
    let set = resources("apiVersion: v1\nkind: Pod\nmetadata: {name: null, generateName: child-}\n")?;
    assert_eq!(
        set.documents()[0].identity()?.generate_name.value().map(String::as_str),
        Some("child-")
    );
    let a = resources("apiVersion: v1\nkind: Namespace\nmetadata: {name: same}\n")?;
    let b = resources("apiVersion: v1\nkind: Namespace\nmetadata: {name: same, namespace: null}\n")?;
    assert_eq!(
        a.documents()[0].identity()?.collision_key(),
        b.documents()[0].identity()?.collision_key()
    );
    assert!(a.documents()[0].original_identity().namespace.is_absent());
    assert!(matches!(b.documents()[0].original_identity().namespace, Presence::Null));
    let input = parsed(b"apiVersion: v1\nkind: Namespace\nmetadata: {name: same}\n---\napiVersion: v1\nkind: Namespace\nmetadata: {name: same, namespace: null}\n", DocumentFormat::YamlStream)?;
    assert!(input.flatten_resources().is_err());
    Ok(())
}
#[test]
fn review_owner_uses_supplied_cluster_crd_scope_and_reports_unknown_scope() -> TestResult<()> {
    let set = resources(concat!(
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.review.invalid}\n",
        "spec: {group: review.invalid, names: {kind: Widget}, scope: Cluster, versions: [{name: v1, served: true}]}\n",
        "---\napiVersion: review.invalid/v1\nkind: Widget\nmetadata: {name: owner, uid: owner-uid}\n",
        "---\napiVersion: v1\nkind: Pod\nmetadata: {name: child, namespace: demo, ownerReferences: [{apiVersion: review.invalid/v1, kind: Widget, name: owner, uid: owner-uid}]}\n",
    ))?;
    let graph = kubernetes_lens::graph::resolve_references(&set);
    assert_eq!(graph.edges.len(), 1);
    assert!(matches!(&graph.edges[0].resolution, Resolution::Resolved(ids) if ids == &[set.documents()[1].id()]));
    let set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: child, namespace: demo, ownerReferences: [{apiVersion: review.invalid/v1, kind: Widget, name: missing}]}\n",
    )?;
    let graph = kubernetes_lens::graph::resolve_references(&set);
    assert!(matches!(
        graph.edges[0].resolution,
        Resolution::Unsupported(kubernetes_lens::graph::SafeReason::ScopeUnknown)
    ));
    assert!(
        graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::ScopeUnknown)
    );
    Ok(())
}
#[test]
fn review_owner_malformed_values_and_unknown_fields_retain_safe_evidence() -> TestResult<()> {
    for owner in [
        "{}",
        "[private-marker]",
        "[{kind: Pod, name: parent}]",
        "[{apiVersion: v1, name: parent}]",
        "[{apiVersion: v1, kind: Pod}]",
        "[{apiVersion: bad/group/version, kind: Pod, name: parent}]",
        "[{apiVersion: v1, kind: Pod, name: parent, uid: 123}]",
        "[{apiVersion: v1, kind: Pod, name: parent, controller: private-marker}]",
    ] {
        let text = format!(
            "apiVersion: v1\nkind: Pod\nmetadata: {{name: child, namespace: demo, ownerReferences: {owner}}}\n"
        );
        let findings = match parsed(text.as_bytes(), DocumentFormat::YamlStream)?.flatten_resources() {
            Ok(set) => {
                let graph = kubernetes_lens::graph::resolve_references(&set);
                assert!(graph.edges.is_empty());
                graph.findings
            }
            Err(findings) => findings,
        };
        let finding = findings
            .iter()
            .find(|finding| finding.code == FindingCode::NativeFieldInvalid)
            .required()?;
        assert_eq!(finding.resource, Some(kubernetes_lens::ResourceId(0)));
        assert!(
            finding
                .path
                .as_ref()
                .required()?
                .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                .starts_with("/metadata/ownerReferences")
        );
        assert!(finding.source.is_some());
        assert!(!format!("{finding:?}").contains("private-marker"));
    }
    let set = resources(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: child, namespace: demo, ownerReferences: [{apiVersion: v1, kind: Pod, name: parent, private-marker: private-marker}]}\n",
    )?;
    let graph = kubernetes_lens::graph::resolve_references(&set);
    assert_eq!(graph.edges.len(), 1);
    let finding = graph
        .findings
        .iter()
        .find(|finding| finding.code == FindingCode::UnadmittedField)
        .required()?;
    assert!(finding.source.is_some());
    assert!(!format!("{finding:?}").contains("private-marker"));
    Ok(())
}
#[test]
fn review_wrappers_obey_admission_and_privacy_on_every_output_route() -> TestResult<()> {
    for source in [
        "apiVersion: v1\nkind: List\nprivate-wrapper-field: PRIVATE_MARKER\nitems: []\n",
        "apiVersion: v1\nkind: List\nitems: [{apiVersion: v1, kind: List, private-wrapper-field: PRIVATE_MARKER, items: []}]\n",
        "apiVersion: v1\nkind: List\nmetadata: {annotations: {private: PRIVATE_MARKER}}\nitems: []\n",
    ] {
        let set = resources(source)?;
        for format in [OutputFormat::Yaml, OutputFormat::Json] {
            for collections in [CollectionOutput::PreserveWrappers, CollectionOutput::Flatten] {
                let options = GenerationOptions {
                    collections,
                    ..Default::default()
                };
                let errors = generate(&set, &target(30)?, format, &options).err().required()?;
                assert!(
                    errors
                        .iter()
                        .any(|finding| finding.code == FindingCode::OpaqueOutputDenied)
                );
                assert!(
                    errors
                        .iter()
                        .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
                );
                assert!(!format!("{errors:?}").contains("PRIVATE_MARKER"));
                let options = GenerationOptions {
                    opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
                    ..options
                };
                assert!(
                    generate(&set, &target(30)?, format, &options)
                        .err()
                        .required()?
                        .iter()
                        .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
                );
                let options = GenerationOptions {
                    protected_output: ProtectedOutput::Include,
                    ..options
                };
                let artifact = generate(&set, &target(30)?, format, &options).required()?;
                assert!(
                    artifact
                        .findings()
                        .iter()
                        .any(|finding| finding.code == FindingCode::UnadmittedField
                            && finding.path.is_some()
                            && finding.source.is_some())
                );
                if collections == CollectionOutput::Flatten {
                    assert!(
                        artifact
                            .findings()
                            .iter()
                            .any(|finding| finding.code == FindingCode::CollectionFieldRemoved)
                    );
                } else {
                    assert!(std::str::from_utf8(bytes(&artifact))?.contains("PRIVATE_MARKER"));
                }
            }
        }
    }
    Ok(())
}
#[test]
fn review_wrapper_observations_json_retention_and_flatten_losses_are_explicit() -> TestResult<()> {
    let set = resources(
        "apiVersion: v1\nkind: List\nmetadata: {resourceVersion: '42', selfLink: /private, remainingItemCount: 0}\nitems: [{apiVersion: v1, kind: List, metadata: {resourceVersion: '43'}, items: []}]\n",
    )?;
    for format in [OutputFormat::Yaml, OutputFormat::Json] {
        let artifact = generate(&set, &target(30)?, format, &GenerationOptions::default()).required()?;
        assert!(std::str::from_utf8(bytes(&artifact))?.contains("42"));
        assert!(std::str::from_utf8(bytes(&artifact))?.contains("43"));
        let options = GenerationOptions {
            intent: kubernetes_lens::generation::OutputIntent::AuthoredIntent,
            ..Default::default()
        };
        let artifact = generate(&set, &target(30)?, format, &options).required()?;
        assert!(!std::str::from_utf8(bytes(&artifact))?.contains("resourceVersion"));
        assert_eq!(
            artifact
                .findings()
                .iter()
                .filter(|finding| finding.code == FindingCode::ObservedFieldRemoved)
                .count(),
            4
        );
        let options = GenerationOptions {
            collections: CollectionOutput::Flatten,
            ..Default::default()
        };
        let artifact = generate(&set, &target(30)?, format, &options).required()?;
        assert_eq!(
            artifact
                .findings()
                .iter()
                .filter(|finding| finding.code == FindingCode::CollectionFieldRemoved)
                .count(),
            2
        );
    }
    Ok(())
}

#[test]
fn review_known_wrapper_metadata_cannot_hide_malformed_private_containers() -> TestResult<()> {
    for metadata in [
        "{resourceVersion: {private: value}}",
        "{continue: [private]}",
        "{remainingItemCount: -1}",
        "private",
    ] {
        let set = resources(&format!(
            "apiVersion: v1\nkind: List\nmetadata: {metadata}\nitems: []\n"
        ))?;
        for format in [OutputFormat::Yaml, OutputFormat::Json] {
            let errors = generate(&set, &target(30)?, format, &preserve()).err().required()?;
            assert!(
                errors
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.source.is_some()
                        && finding.path.is_some())
            );
        }
    }
    let set = parsed(
        br#"{"apiVersion":"v1","kind":"List","metadata":{"continue":"private-token"},"items":[]}"#,
        DocumentFormat::Json,
    )?
    .flatten_resources()
    .required()?;
    let errors = generate(&set, &target(30)?, OutputFormat::Json, &GenerationOptions::default())
        .err()
        .required()?;
    assert!(
        errors
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    let options = GenerationOptions {
        protected_output: ProtectedOutput::Include,
        json_shape: JsonShape::SingleResource,
        ..Default::default()
    };
    let artifact = generate(&set, &target(30)?, OutputFormat::Json, &options).required()?;
    assert!(std::str::from_utf8(bytes(&artifact))?.contains("private-token"));
    let options = GenerationOptions {
        intent: kubernetes_lens::generation::OutputIntent::AuthoredIntent,
        ..options
    };
    let artifact = generate(&set, &target(30)?, OutputFormat::Json, &options).required()?;
    assert!(!std::str::from_utf8(bytes(&artifact))?.contains("private-token"));
    assert!(
        artifact
            .findings()
            .iter()
            .any(|finding| finding.code == FindingCode::ObservedFieldRemoved)
    );
    Ok(())
}
#[test]
fn review_owner_missing_known_scope_and_live_duplicate_targets_stay_distinct() -> TestResult<()> {
    let mut set = resources(concat!(
        "apiVersion: apiextensions.k8s.io/v1\nkind: CustomResourceDefinition\nmetadata: {name: widgets.review.invalid}\n",
        "spec: {group: review.invalid, names: {kind: Widget}, scope: Cluster, versions: [{name: v1, served: true}]}\n",
        "---\napiVersion: review.invalid/v1\nkind: Widget\nmetadata: {name: first}\n",
        "---\napiVersion: review.invalid/v1\nkind: Widget\nmetadata: {name: second}\n",
        "---\napiVersion: v1\nkind: Pod\nmetadata: {name: child, namespace: demo, ownerReferences: [{apiVersion: review.invalid/v1, kind: Widget, name: missing}]}\n",
    ))?;
    assert!(matches!(
        kubernetes_lens::graph::resolve_references(&set).edges[0].resolution,
        Resolution::Missing
    ));
    let value = parsed(b"first", DocumentFormat::YamlStream)?;
    set.documents_mut()[2].set_field_from_source(FieldPath::parse("/metadata/name")?, value)?;
    let value = parsed(b"first", DocumentFormat::YamlStream)?;
    set.documents_mut()[3].set_field_from_source(FieldPath::parse("/metadata/ownerReferences/0/name")?, value)?;
    let graph = kubernetes_lens::graph::resolve_references(&set);
    assert!(matches!(&graph.edges[0].resolution, Resolution::Ambiguous(ids) if ids.len() == 2));
    Ok(())
}

fn wrapper_input(source_id: u64, text: &str) -> TestResult<kubernetes_lens::ParsedInput> {
    parse_source(
        SourceInput {
            id: SourceId(source_id),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()
}
#[test]
fn wrapper_findings_disambiguate_equal_positions_in_distinct_sources() -> TestResult<()> {
    let source = "apiVersion: v1\nkind: List\nprivate-wrapper-field: PRIVATE_MARKER\nmetadata: {resourceVersion: '42'}\nitems: []\n";
    let set = ResourceSet::from_inputs(vec![wrapper_input(11, source)?, wrapper_input(22, source)?]).required()?;
    let errors = generate(&set, &target(30)?, OutputFormat::Yaml, &GenerationOptions::default())
        .err()
        .required()?;
    let errors = errors
        .iter()
        .filter(|finding| finding.code == FindingCode::OpaqueOutputDenied)
        .collect::<Vec<_>>();
    assert_eq!(errors.len(), 2);
    assert_eq!(errors[0].source, errors[1].source);
    assert_ne!(errors[0], errors[1]);
    assert_eq!(errors[0].wrapper.required()?.source.source, SourceId(11));
    assert_eq!(errors[1].wrapper.required()?.source.source, SourceId(22));
    for format in [OutputFormat::Yaml, OutputFormat::Json] {
        let options = GenerationOptions {
            collections: CollectionOutput::Flatten,
            intent: kubernetes_lens::generation::OutputIntent::AuthoredIntent,
            ..preserve()
        };
        let artifact = generate(&set, &target(30)?, format, &options).required()?;
        for code in [
            FindingCode::UnadmittedField,
            FindingCode::ObservedFieldRemoved,
            FindingCode::CollectionFieldRemoved,
        ] {
            let findings = artifact
                .findings()
                .iter()
                .filter(|finding| finding.code == code)
                .collect::<Vec<_>>();
            assert!(!findings.is_empty());
            for finding in findings {
                let subject = finding.wrapper.required()?;
                assert!(matches!(subject.source.source, SourceId(11 | 22)));
                assert_eq!(subject.source.document_index, 0);
                assert!(finding.resource.is_none());
                assert!(finding.source.is_some());
                assert!(!format!("{finding:?}").contains("PRIVATE_MARKER"));
            }
        }
    }
    Ok(())
}
#[test]
fn nested_wrapper_subjects_retain_document_and_list_coordinates() -> TestResult<()> {
    let source = "apiVersion: v1\nkind: List\nprivate-wrapper-field: root-private\nitems: [{apiVersion: v1, kind: List, private-wrapper-field: nested-private, items: []}]\n---\napiVersion: v1\nkind: List\nprivate-wrapper-field: second-private\nitems: []\n";
    let set = ResourceSet::from_inputs(vec![wrapper_input(11, source)?]).required()?;
    let errors = generate(&set, &target(30)?, OutputFormat::Yaml, &GenerationOptions::default())
        .err()
        .required()?;
    let subjects = errors
        .iter()
        .filter(|finding| finding.code == FindingCode::OpaqueOutputDenied)
        .map(|finding| finding.wrapper)
        .collect::<Vec<_>>();
    assert_eq!(subjects.len(), 3);
    for (subject, list) in subjects.iter().zip(set.lists()) {
        let subject = subject.required()?;
        assert_eq!(subject.list, list.id());
        assert_eq!(subject.source, list.source());
        assert_eq!(subject.source.source, SourceId(11));
    }
    assert_ne!(subjects[0].required()?.list, subjects[1].required()?.list);
    assert_eq!(subjects[0].required()?.source.document_index, 0);
    assert_eq!(subjects[1].required()?.source.document_index, 0);
    assert_eq!(subjects[2].required()?.source.document_index, 1);
    Ok(())
}
#[test]
fn malformed_wrapper_decode_findings_keep_attempted_and_nested_subjects() -> TestResult<()> {
    let source = "apiVersion: v1\nkind: List\nitems: PRIVATE_MARKER\n";
    let mut findings = Vec::new();
    for source_id in [11, 22] {
        let errors = ResourceSet::from_inputs(vec![wrapper_input(source_id, source)?])
            .err()
            .required()?;
        let finding = errors.into_iter().next().required()?;
        let subject = finding.wrapper.required()?;
        assert_eq!(subject.source.source, SourceId(source_id));
        assert_eq!(subject.source.document_index, 0);
        assert_eq!(subject.list, kubernetes_lens::model::ListId(0));
        assert!(finding.source.is_some());
        assert!(finding.path.is_some());
        assert!(!format!("{finding:?}").contains("PRIVATE_MARKER"));
        findings.push(finding);
    }
    assert_eq!(findings[0].source, findings[1].source);
    assert_ne!(findings[0], findings[1]);
    let nested = "apiVersion: v1\nkind: List\nitems: [{apiVersion: v1, kind: List, items: PRIVATE_MARKER}]\n";
    let errors = ResourceSet::from_inputs(vec![wrapper_input(22, nested)?])
        .err()
        .required()?;
    let subject = errors[0].wrapper.required()?;
    assert_eq!(subject.source.source, SourceId(22));
    assert_eq!(subject.list, kubernetes_lens::model::ListId(1));
    Ok(())
}
