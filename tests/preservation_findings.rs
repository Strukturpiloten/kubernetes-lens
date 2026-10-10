//! Independent preservation warnings; no server admission or runtime claims.
use kubernetes_lens::{
    FieldPath, Finding, FindingCode, ResourceId,
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::{Phase, Severity, WrapperSubject},
    generate,
    generation::{
        CollectionOutput, ExplicitArtifactAccess, GeneratedArtifact, GenerationOptions, JsonShape, OpaqueFieldPolicy,
        OutputFormat, ProtectedOutput,
    },
    model::{ListId, ResourceSet, SourceRef},
    parse_source,
    processing::NativeProcessingLimits,
    resources::workloads::Pod,
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::Presence,
};

type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
const ROOT: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings}\nvendor: {token: source-private}\n";
fn input(text: &str, id: u64, limits: &ParseLimits) -> TestResult<kubernetes_lens::ParsedInput> {
    parse_source(
        SourceInput {
            id: SourceId(id),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: text.as_bytes(),
        },
        limits,
    )
    .map_err(|_| "parse failed".into())
}
fn set(text: &str) -> TestResult<ResourceSet> {
    input(text, 9, &ParseLimits::default())?
        .flatten_resources()
        .map_err(|_| "flatten failed".into())
}
fn target() -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, 37)?))
}
fn preserve() -> GenerationOptions {
    GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        json_shape: JsonShape::SingleResource,
        ..GenerationOptions::default()
    }
}
fn artifact(set: &ResourceSet, options: &GenerationOptions) -> TestResult<GeneratedArtifact> {
    generate(set, &target()?, OutputFormat::Yaml, options)
        .map_err(|findings| format!("generation failed: {findings:?}").into())
}
fn unadmitted(artifact: &GeneratedArtifact) -> Vec<&Finding> {
    artifact
        .findings()
        .iter()
        .filter(|f| f.code == FindingCode::UnadmittedField)
        .collect()
}
fn pointer(finding: &Finding) -> TestResult<String> {
    Ok(finding
        .path
        .as_ref()
        .ok_or("missing private path")?
        .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()))
}

#[test]
fn root_preservation_warns_with_private_actionable_evidence_and_preserves_bytes() -> TestResult {
    let resources = set(ROOT)?;
    let blocked = generate(
        &resources,
        &target()?,
        OutputFormat::Yaml,
        &GenerationOptions::default(),
    )
    .err()
    .ok_or("default output unexpectedly allowed")?;
    assert!(blocked.iter().any(|f| f.code == FindingCode::OpaqueOutputDenied));
    let denied = GenerationOptions {
        protected_output: ProtectedOutput::Deny,
        ..preserve()
    };
    let protected = set(&format!("{ROOT}data: {{key: protected-value}}\n"))?;
    assert!(generate(&protected, &target()?, OutputFormat::Yaml, &denied).is_err());
    for format in [OutputFormat::Yaml, OutputFormat::Json] {
        let generated = generate(&resources, &target()?, format, &preserve()).map_err(|_| "preservation failed")?;
        let warnings = unadmitted(&generated);
        assert_eq!(warnings.len(), 1);
        let warning = warnings[0];
        assert_eq!(warning.code, FindingCode::UnadmittedField);
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.phase, Phase::Generation);
        assert_eq!(warning.resource, Some(ResourceId(0)));
        assert_eq!(pointer(warning)?, "/vendor");
        assert_eq!(warning.wrapper, None);
        let position = warning.source.ok_or("original position missing")?;
        assert_eq!((position.line, position.column), (4, 9));
        assert_eq!(
            position.byte_offset,
            u64::try_from(ROOT.find("{token").ok_or("fixture token missing")?)?
        );
        assert!(!warning.remediation().is_empty());
        let bytes = generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
        assert!(std::str::from_utf8(bytes)?.contains("source-private"));
        let debug = format!("{generated:?} {warning:?} {warning}");
        for private in ["vendor", "token", "source-private"] {
            assert!(!debug.contains(private));
        }
        if format == OutputFormat::Json {
            let output: serde_json::Value = serde_json::from_slice(bytes)?;
            assert_eq!(output["vendor"]["token"], "source-private");
        }
    }
    Ok(())
}

#[test]
fn nested_and_empty_unknown_boundaries_have_exact_escaped_paths() -> TestResult {
    let resources = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: p, private~/key: {nested: private-value}}\nspec:\n  containers: [{name: c, image: image, private-field: []}]\n  private-empty: {}\n",
    )?;
    let generated = artifact(&resources, &preserve())?;
    let paths = unadmitted(&generated)
        .into_iter()
        .map(pointer)
        .collect::<TestResult<Vec<_>>>()?;
    assert_eq!(
        paths,
        [
            "/metadata/private~0~1key",
            "/spec/containers/0/private-field",
            "/spec/private-empty"
        ]
    );
    assert!(unadmitted(&generated).iter().all(|f| f.source.is_some()));
    assert!(!format!("{generated:?}").contains("private"));
    Ok(())
}

#[test]
fn multiple_documents_and_nested_lists_retain_exact_source_subjects_on_each_route() -> TestResult {
    let list = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: first}\nvendor: first-private\n---\napiVersion: v1\nkind: List\nitems:\n- apiVersion: v1\n  kind: Secret\n  metadata: {name: second}\n  vendor: second-private\n- apiVersion: v1\n  kind: List\n  items:\n  - apiVersion: v1\n    kind: Pod\n    metadata: {name: third}\n    vendor: third-private\n    spec:\n      containers: [{name: c, image: image}]\n      vendor: nested-private\n";
    let fourth = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: fourth}\nvendor: fourth-private\n";
    let resources = ResourceSet::from_inputs(vec![
        input(list, 9, &ParseLimits::default())?,
        input(fourth, 10, &ParseLimits::default())?,
    ])
    .map_err(|_| "aggregate failed")?;
    let root_wrapper = WrapperSubject {
        source: SourceRef {
            source: SourceId(9),
            document_index: 1,
        },
        list: ListId(0),
    };
    let nested_wrapper = WrapperSubject {
        list: ListId(1),
        ..root_wrapper
    };
    for collections in [CollectionOutput::PreserveWrappers, CollectionOutput::Flatten] {
        let generated = artifact(
            &resources,
            &GenerationOptions {
                collections,
                ..preserve()
            },
        )?;
        let warnings = unadmitted(&generated);
        assert_eq!(warnings.len(), 5);
        let expected = [
            (ResourceId(0), "/vendor", None, 4),
            (ResourceId(1), "/items/0/vendor", Some(root_wrapper), 12),
            (ResourceId(2), "/items/1/items/0/vendor", Some(nested_wrapper), 19),
            (ResourceId(2), "/items/1/items/0/spec/vendor", Some(nested_wrapper), 22),
            (ResourceId(3), "/vendor", None, 4),
        ];
        for (warning, (resource, path, wrapper, line)) in warnings.into_iter().zip(expected) {
            assert_eq!(warning.resource, Some(resource));
            assert_eq!(pointer(warning)?, path);
            assert_eq!(warning.wrapper, wrapper);
            assert_eq!(warning.source.ok_or("source position missing")?.line, line);
        }
        assert_eq!(
            resources.documents()[3].source(),
            SourceRef {
                source: SourceId(10),
                document_index: 0
            }
        );
        let output =
            std::str::from_utf8(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        for value in [
            "first-private",
            "second-private",
            "third-private",
            "nested-private",
            "fourth-private",
        ] {
            assert!(output.contains(value));
            assert!(!format!("{generated:?}").contains(value));
        }
    }
    Ok(())
}

#[test]
fn admitted_free_form_maps_do_not_become_unknown_configuration() -> TestResult {
    let resources = set(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: config, labels: {vendor: custom}, annotations: {vendor: custom}}\ndata: {vendor: source-private}\nbinaryData: {vendor-binary: AQID}\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: secret}\ndata: {vendor: AQID}\nstringData: {vendor: secret-private}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: pod}\nspec:\n  containers:\n  - name: c\n    image: image\n    resources:\n      requests: {example.test/vendor: '1', cpu: '1'}\n      limits: {example.test/vendor: '1', cpu: '2'}\n",
    )?;
    let generated = artifact(&resources, &preserve())?;
    assert!(unadmitted(&generated).is_empty());
    let strict = GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::Block,
        ..preserve()
    };
    assert!(generate(&resources, &target()?, OutputFormat::Yaml, &strict).is_ok());
    Ok(())
}

#[test]
fn existing_unsupported_value_findings_survive_without_duplicate_admission() -> TestResult {
    let resources = set(
        "apiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: claim}\nspec:\n  accessModes: [ReadWriteOncePod]\n  resources: {requests: {storage: 1Gi}}\nvendor: source-private\n",
    )?;
    let generated = artifact(&resources, &preserve())?;
    let warnings = unadmitted(&generated);
    assert_eq!(warnings.len(), 2);
    let existing = warnings
        .iter()
        .find(|f| f.phase == Phase::Validation)
        .ok_or("existing native finding missing")?;
    assert_eq!(pointer(existing)?, "/spec/accessModes/0");
    assert_eq!(existing.severity, Severity::Warning);
    let new = warnings
        .iter()
        .find(|f| f.phase == Phase::Generation)
        .ok_or("preservation finding missing")?;
    assert_eq!(pointer(new)?, "/vendor");
    Ok(())
}

#[test]
fn edited_and_reordered_occurrences_never_claim_original_positions() -> TestResult {
    let mut edited = set(ROOT)?;
    edited.documents_mut()[0].set_field_from_source(
        FieldPath::parse("/vendor")?,
        input("replacement-private", 23, &ParseLimits::default())?,
    )?;
    let generated = artifact(&edited, &preserve())?;
    let warnings = unadmitted(&generated);
    assert_eq!(warnings.len(), 1);
    assert_eq!(pointer(warnings[0])?, "/vendor");
    assert_eq!(warnings[0].source, None);
    assert_eq!(
        edited.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        ROOT.as_bytes()
    );
    assert!(
        std::str::from_utf8(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?
            .contains("replacement-private")
    );

    let mut reordered = set(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: pod}\nspec:\n  containers:\n  - {name: first, image: image, vendor: first-private}\n  - {name: second, image: image, vendor: second-private}\n",
    )?;
    let pod = reordered.documents_mut()[0]
        .resource_mut::<Pod>()
        .ok_or("typed Pod missing")?;
    let Presence::Value(spec) = &mut pod.spec else {
        return Err("Pod spec missing".into());
    };
    let Presence::Value(containers) = &mut spec.containers else {
        return Err("Pod containers missing".into());
    };
    containers.swap(0, 1);
    let generated =
        generate(&reordered, &target()?, OutputFormat::Json, &preserve()).map_err(|_| "reordered generation failed")?;
    let warnings = unadmitted(&generated);
    assert_eq!(warnings.len(), 2);
    assert_eq!(pointer(warnings[0])?, "/spec/containers/0/vendor");
    assert_eq!(pointer(warnings[1])?, "/spec/containers/1/vendor");
    assert!(warnings.iter().all(|warning| warning.source.is_none()));
    let output: serde_json::Value =
        serde_json::from_slice(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(output["spec"]["containers"][0]["name"], "second");
    assert_eq!(output["spec"]["containers"][0]["vendor"], "second-private");
    assert_eq!(output["spec"]["containers"][1]["name"], "first");
    assert_eq!(output["spec"]["containers"][1]["vendor"], "first-private");
    assert!(!format!("{generated:?}").contains("private"));
    Ok(())
}

#[test]
fn exhausted_shared_report_and_work_budgets_fail_closed_without_private_terminal_evidence() -> TestResult {
    let two = format!("{ROOT}---\n{}", ROOT.replace("name: settings", "name: second"));
    let limits = ParseLimits {
        processing: NativeProcessingLimits {
            max_report_entries: 1,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    };
    let resources = input(&two, 9, &limits)?
        .flatten_resources()
        .map_err(|_| "flatten failed")?;
    // A larger caller ceiling cannot raise the retained per-source ceiling or reset it per resource.
    let options = GenerationOptions {
        processing: Some(NativeProcessingLimits::default()),
        ..preserve()
    };
    let errors = generate(&resources, &target()?, OutputFormat::Yaml, &options)
        .err()
        .ok_or("exhausted output allowed")?;
    assert_eq!(
        errors.iter().filter(|f| f.code == FindingCode::UnadmittedField).count(),
        1
    );
    assert_private_terminal(&errors);
    for lowered in [
        NativeProcessingLimits {
            max_processing_units: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_report_bytes: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_report_entries: 0,
            ..NativeProcessingLimits::default()
        },
    ] {
        let options = GenerationOptions {
            processing: Some(lowered),
            ..preserve()
        };
        let errors = generate(&set(ROOT)?, &target()?, OutputFormat::Yaml, &options)
            .err()
            .ok_or("exhausted output allowed")?;
        assert_private_terminal(&errors);
    }
    Ok(())
}
fn assert_private_terminal(errors: &[Finding]) {
    let terminal = errors
        .iter()
        .filter(|f| f.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].severity, Severity::Error);
    assert_eq!(terminal[0].path, None);
    assert_eq!(terminal[0].source, None);
    assert_eq!(terminal[0].resource, None);
    assert_eq!(terminal[0].wrapper, None);
    assert!(!format!("{errors:?}").contains("source-private"));
}

fn extension_target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}

fn crd(schema: &serde_json::Value, beta: bool, legacy: bool) -> serde_json::Value {
    let mut document = serde_json::json!({
        "apiVersion": if beta { "apiextensions.k8s.io/v1beta1" } else { "apiextensions.k8s.io/v1" },
        "kind": "CustomResourceDefinition",
        "metadata": {"name": "widgets.example.test"},
        "spec": {
            "group": "example.test", "scope": "Namespaced",
            "names": {"plural": "widgets", "kind": "Widget"},
            "versions": [{"name": "v1", "served": true, "storage": true}]
        }
    });
    if legacy {
        document["spec"]["version"] = serde_json::json!("v1");
        document["spec"]["validation"] = serde_json::json!({"openAPIV3Schema": schema});
    } else {
        document["spec"]["versions"][0]["schema"] = serde_json::json!({"openAPIV3Schema": schema});
    }
    document
}

fn output_json(generated: &GeneratedArtifact) -> TestResult<serde_json::Value> {
    Ok(serde_json::from_slice(generated.reveal_bytes(
        &ExplicitArtifactAccess::explicitly_allow_raw_artifact(),
    ))?)
}

#[test]
fn recursive_typed_crd_schemas_are_admitted_beyond_static_depth_for_each_layout() -> TestResult {
    let mut deep = serde_json::json!({"type": "string", "pattern": "^selected$", "format": "hostname"});
    for index in (0..18).rev() {
        deep = serde_json::json!({"properties": {format!("p{index}"): deep}});
    }
    let schema = serde_json::json!({
        "properties": {"array": {"items": {"additionalProperties": {
            "allOf": [{"dependencies": {"needs": {"oneOf": [{
                "definitions": {"named": {"patternProperties": {"^item": {
                    "properties": {"deep": deep}
                }}}}
            }]}}}]
        }}}}
    });
    for (beta, legacy, minor) in [(false, false, 30), (true, false, 21), (true, true, 21)] {
        let document = crd(&schema, beta, legacy);
        let resources = set(&document.to_string())?;
        for opaque_fields in [OpaqueFieldPolicy::PreserveWithFinding, OpaqueFieldPolicy::Block] {
            let generated = generate(
                &resources,
                &extension_target(minor)?,
                OutputFormat::Json,
                &GenerationOptions {
                    opaque_fields,
                    ..preserve()
                },
            )
            .map_err(|findings| format!("recursive typed CRD was blocked: {findings:?}"))?;
            assert!(unadmitted(&generated).is_empty());
            assert_eq!(output_json(&generated)?, document);
        }
        if beta {
            assert!(generate(&resources, &extension_target(22)?, OutputFormat::Json, &preserve()).is_err());
        }
    }
    Ok(())
}

#[test]
fn unknown_schema_default_warns_once_at_nested_list_source_boundary() -> TestResult {
    let payload = serde_json::json!({"secret~/key": [{"token": "schema-default-private"}], "empty": {}});
    let document = crd(&serde_json::json!({"type": "object", "default": payload}), false, false);
    let source = serde_json::json!({
        "apiVersion": "v1", "kind": "List", "items": [{
            "apiVersion": "v1", "kind": "List", "items": [document]
        }]
    });
    let resources = set(&source.to_string())?;
    let blocked = generate(
        &resources,
        &extension_target(30)?,
        OutputFormat::Json,
        &GenerationOptions {
            opaque_fields: OpaqueFieldPolicy::Block,
            ..preserve()
        },
    )
    .err()
    .ok_or("unknown schema default was admitted under Block")?;
    assert!(
        blocked
            .iter()
            .any(|finding| finding.code == FindingCode::OpaqueOutputDenied)
    );
    for collections in [CollectionOutput::PreserveWrappers, CollectionOutput::Flatten] {
        let generated = generate(
            &resources,
            &extension_target(30)?,
            OutputFormat::Json,
            &GenerationOptions {
                collections,
                ..preserve()
            },
        )
        .map_err(|findings| format!("unknown schema preservation failed: {findings:?}"))?;
        let warnings = unadmitted(&generated);
        assert_eq!(warnings.len(), 1);
        let warning = warnings[0];
        assert_eq!(warning.resource, Some(ResourceId(0)));
        assert_eq!(warning.severity, Severity::Warning);
        assert_eq!(warning.phase, Phase::Generation);
        assert_eq!(
            pointer(warning)?,
            "/items/0/items/0/spec/versions/0/schema/openAPIV3Schema/default"
        );
        assert_eq!(
            warning.wrapper,
            Some(WrapperSubject {
                source: SourceRef {
                    source: SourceId(9),
                    document_index: 0
                },
                list: ListId(1)
            })
        );
        assert!(warning.source.is_some());
        let output = output_json(&generated)?;
        let selected = if collections == CollectionOutput::PreserveWrappers {
            &output["items"][0]["items"][0]
        } else {
            &output
        };
        assert_eq!(
            selected["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["default"],
            payload
        );
        let debug = format!("{generated:?} {warning:?} {warning}");
        for private in ["secret~/key", "schema-default-private", "openAPIV3Schema"] {
            assert!(!debug.contains(private));
        }
    }
    Ok(())
}

#[test]
fn protected_schema_enum_and_example_are_admitted_only_with_explicit_include() -> TestResult {
    let schema = serde_json::json!({
        "type": "object",
        "enum": [null, {"private~/key": ["enum-private", {}]}],
        "example": {"private-example": {"token": "example-private", "empty": []}}
    });
    for (beta, legacy, minor) in [(false, false, 30), (true, false, 21), (true, true, 21)] {
        let document = crd(&schema, beta, legacy);
        let resources = set(&document.to_string())?;
        let denied = generate(
            &resources,
            &extension_target(minor)?,
            OutputFormat::Json,
            &GenerationOptions {
                protected_output: ProtectedOutput::Deny,
                ..preserve()
            },
        )
        .err()
        .ok_or("protected schema payload unexpectedly allowed")?;
        assert!(
            denied
                .iter()
                .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
        );
        assert!(!format!("{denied:?}").contains("example-private"));
        for opaque_fields in [OpaqueFieldPolicy::PreserveWithFinding, OpaqueFieldPolicy::Block] {
            let generated = generate(
                &resources,
                &extension_target(minor)?,
                OutputFormat::Json,
                &GenerationOptions {
                    opaque_fields,
                    ..preserve()
                },
            )
            .map_err(|findings| format!("protected schema Include failed: {findings:?}"))?;
            assert!(unadmitted(&generated).is_empty());
            assert_eq!(output_json(&generated)?, document);
            let debug = format!("{generated:?}");
            for private in ["private~/key", "enum-private", "example-private", "private-example"] {
                assert!(!debug.contains(private));
            }
        }
    }
    Ok(())
}

#[test]
fn recursive_schema_admission_keeps_each_unknown_boundary_and_protected_descendant() -> TestResult {
    let schema = serde_json::json!({
        "type": "object",
        "properties": {"private~/雪": {
            "type": "object",
            "example": {"protected-private": [{"token": "example-marker"}, {}]},
            "default": {"unknown-private": [{"token": "default-marker"}, {}]},
            "x-unknown": {"properties": {"otherwise-known": {"type": "string"}}}
        }}
    });
    for (beta, legacy, minor) in [(false, false, 30), (true, false, 21), (true, true, 21)] {
        let document = crd(&schema, beta, legacy);
        let resources = set(&document.to_string())?;
        let generated = generate(&resources, &extension_target(minor)?, OutputFormat::Json, &preserve())
            .map_err(|findings| format!("recursive schema preservation failed: {findings:?}"))?;
        assert_eq!(output_json(&generated)?, document);
        let prefix = if legacy {
            "/spec/validation/openAPIV3Schema/properties/private~0~1雪"
        } else {
            "/spec/versions/0/schema/openAPIV3Schema/properties/private~0~1雪"
        };
        let warnings = unadmitted(&generated);
        let mut paths = warnings
            .iter()
            .map(|finding| pointer(finding))
            .collect::<TestResult<Vec<_>>>()?;
        paths.sort();
        assert_eq!(paths, vec![format!("{prefix}/default"), format!("{prefix}/x-unknown")]);
        for finding in warnings {
            assert_eq!(finding.resource, Some(ResourceId(0)));
            assert_eq!(finding.severity, Severity::Warning);
            assert_eq!(finding.phase, Phase::Generation);
            assert!(finding.source.is_some());
        }
        let blocked = generate(
            &resources,
            &extension_target(minor)?,
            OutputFormat::Json,
            &GenerationOptions {
                opaque_fields: OpaqueFieldPolicy::Block,
                ..preserve()
            },
        )
        .err()
        .ok_or("unknown children of admitted schema parent were allowed under Block")?;
        assert!(
            blocked
                .iter()
                .any(|finding| finding.code == FindingCode::OpaqueOutputDenied)
        );
        let protected = generate(
            &resources,
            &extension_target(minor)?,
            OutputFormat::Json,
            &GenerationOptions {
                protected_output: ProtectedOutput::Deny,
                ..preserve()
            },
        )
        .err()
        .ok_or("protected child of admitted schema parent was allowed under Deny")?;
        assert!(
            protected
                .iter()
                .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
        );
        let debug = format!("{generated:?} {blocked:?} {protected:?}");
        for private in [
            "private~/雪",
            "protected-private",
            "example-marker",
            "unknown-private",
            "default-marker",
        ] {
            assert!(!debug.contains(private));
        }
    }
    Ok(())
}
