//! Independent replay, completeness, beta public contract, and exact private provenance regressions.
use kubernetes_lens::{
    FindingCode,
    capability::{FeatureGateResolution, KubernetesVersion, TargetProfile},
    diagnostic::{FieldPath, Severity},
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, NativeValidationIntent, OpaqueFieldPolicy, OutputFormat,
        ProtectedOutput, validate_for_target_with_intent,
    },
    graph::{
        ExternalRefKind, Reference, ReferenceContext, ReferenceScope, ReferenceTarget, RelationshipKind, Resolution,
        resolve_references_for_target, resolve_supplied_references_for_target,
    },
    model::ResourceSet,
    parse_source,
    processing::NativeProcessingLimits,
    resources::extensions::{
        BetaSchemaFieldsView, CustomDocumentCheck, CustomResourceDefinitionV1, ExternalDocumentationCrdV1beta1,
        JSONCrdV1beta1, JSONSchemaPropsOrArrayCrdV1beta1, JSONSchemaPropsOrBoolCrdV1beta1,
        JSONSchemaPropsOrStringArrayCrdV1beta1, SchemaBuilder, SchemaFields, SchemaFieldsBeta,
    },
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::Presence,
};
use std::collections::BTreeMap;
type TestResult = Result<(), String>;
const INPUT: &str = r#"{"apiVersion":"v1","kind":"List","items":[{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","description":"annotation"}}}]}},{"apiVersion":"example.test/v1","kind":"Widget","metadata":{"name":"one","namespace":"dev"}}]}"#;
fn target(minor: u8) -> Result<TargetProfile, String> {
    Ok(TargetProfile::documented_defaults(
        KubernetesVersion::new(1, minor).map_err(|_| "target")?,
    ))
}
fn parse(text: &str, id: u64, format: DocumentFormat) -> Result<ResourceSet, String> {
    parse_source(
        SourceInput {
            id: SourceId(id),
            format,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "parse")?
    .flatten_resources()
    .map_err(|_| "flatten".into())
}
fn sealed_edge(set: &ResourceSet, target: &TargetProfile) -> Result<Reference, String> {
    let checks = set
        .check_custom_documents(target, NativeProcessingLimits::default())
        .map_err(|_| "check")?;
    let descriptor = checks
        .first()
        .and_then(|r| r.binding())
        .ok_or("binding")?
        .supplied_descriptor()
        .clone();
    Ok(Reference {
        from: set.documents()[1].id(),
        path: FieldPath::default(),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::SuppliedCustomResourceVersion { descriptor },
        scope: ReferenceScope::Cluster,
    })
}
fn replay_resolves(set: &ResourceSet, edge: &Reference, target: &TargetProfile) -> bool {
    let graph =
        resolve_supplied_references_for_target(set, std::slice::from_ref(edge), &ReferenceContext::default(), target);
    graph
        .edges
        .last()
        .is_some_and(|edge| matches!(edge.resolution, Resolution::Resolved(_)))
}

fn webhook_fixture(api: &str, kind: &str, side_effects: &str, client: &serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "apiVersion":api,"kind":kind,"metadata":{"name":"policy"},
        "webhooks":[{"name":"hook.example.test","sideEffects":side_effects,
            "admissionReviewVersions":["v1"],"clientConfig":client}]
    })
}
fn endpoint_fixtures(client: &serde_json::Value) -> Result<Vec<(serde_json::Value, u8, &'static str)>, String> {
    let mut cases = Vec::new();
    for (api, minor) in [
        ("admissionregistration.k8s.io/v1", 37),
        ("admissionregistration.k8s.io/v1beta1", 21),
    ] {
        for kind in ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"] {
            cases.push((
                webhook_fixture(api, kind, "None", client),
                minor,
                "/webhooks/0/clientConfig",
            ));
        }
    }
    let original: serde_json::Value = serde_json::from_str(INPUT).map_err(|_| "CRD fixture")?;
    for (api, minor, base) in [
        ("apiextensions.k8s.io/v1", 37, "/spec/conversion/webhook/clientConfig"),
        (
            "apiextensions.k8s.io/v1beta1",
            21,
            "/spec/conversion/webhookClientConfig",
        ),
    ] {
        let mut crd = original["items"][0].clone();
        crd["apiVersion"] = api.into();
        crd["spec"]["conversion"] = if api.ends_with("/v1beta1") {
            serde_json::json!({"strategy":"Webhook","webhookClientConfig":client,"conversionReviewVersions":["v1beta1"]})
        } else {
            serde_json::json!({"strategy":"Webhook","webhook":{"clientConfig":client,"conversionReviewVersions":["v1"]}})
        };
        cases.push((crd, minor, base));
    }
    Ok(cases)
}
fn explicit_output(intent: NativeValidationIntent) -> GenerationOptions {
    GenerationOptions {
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        json_shape: JsonShape::SingleResource,
        validation_intent: intent,
        ..GenerationOptions::default()
    }
}

#[test]
fn webhook_side_effects_create_checks_use_the_exact_api_family_and_beta_boundary() -> TestResult {
    let expected_path = FieldPath::parse("/webhooks/0/sideEffects").map_err(|_| "side effects path")?;
    for kind in ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"] {
        for (api, minors) in [
            ("admissionregistration.k8s.io/v1", [20, 37]),
            ("admissionregistration.k8s.io/v1beta1", [20, 21]),
        ] {
            for side_effects in ["None", "NoneOnDryRun", "Some", "Unknown", "PRIVATE_INVALID_ENUM"] {
                let fixture = webhook_fixture(
                    api,
                    kind,
                    side_effects,
                    &serde_json::json!({"url":"https://private-endpoint.example.test/"}),
                );
                let set = parse(&fixture.to_string(), 91, DocumentFormat::Json)?;
                let permitted = matches!(side_effects, "None" | "NoneOnDryRun")
                    || api.ends_with("/v1beta1") && matches!(side_effects, "Some" | "Unknown");
                for minor in minors {
                    let target = target(minor)?;
                    let findings = validate_for_target_with_intent(&set, &target, NativeValidationIntent::Create);
                    let invalid = findings.iter().find(|finding| {
                        finding.code == FindingCode::NativeFieldInvalid && finding.path.as_ref() == Some(&expected_path)
                    });
                    assert_eq!(invalid.is_none(), permitted, "{api} {kind} {minor} {side_effects}");
                    if let Some(finding) = invalid {
                        assert_eq!(finding.severity, Severity::Error);
                        assert_eq!(finding.resource, Some(set.documents()[0].id()));
                    }
                    assert!(!format!("{findings:?}").contains("PRIVATE_INVALID_ENUM"));
                    assert!(!format!("{findings:?}").contains("private-endpoint"));
                    let generated = kubernetes_lens::generate(
                        &set,
                        &target,
                        OutputFormat::Json,
                        &explicit_output(NativeValidationIntent::Create),
                    );
                    assert_eq!(
                        generated.is_ok(),
                        permitted,
                        "{api} {kind} {minor} {side_effects}: {:?}",
                        generated.as_ref().err()
                    );
                }
            }
            if api.ends_with("/v1beta1") {
                let fixture = webhook_fixture(
                    api,
                    kind,
                    "Some",
                    &serde_json::json!({"url":"https://hooks.example.test/"}),
                );
                let set = parse(&fixture.to_string(), 92, DocumentFormat::Json)?;
                let findings = validate_for_target_with_intent(&set, &target(22)?, NativeValidationIntent::Create);
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::UnavailableApi)
                );
                assert!(
                    kubernetes_lens::generate(
                        &set,
                        &target(22)?,
                        OutputFormat::Json,
                        &explicit_output(NativeValidationIntent::Create)
                    )
                    .is_err()
                );
            }
        }
    }
    Ok(())
}

#[test]
fn legacy_stable_side_effects_require_context_and_preserve_original_documents() -> TestResult {
    let expected_path = FieldPath::parse("/webhooks/0/sideEffects").map_err(|_| "legacy path")?;
    let source_access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let artifact_access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    for kind in ["MutatingWebhookConfiguration", "ValidatingWebhookConfiguration"] {
        for side_effects in ["Some", "Unknown"] {
            let fixture = webhook_fixture(
                "admissionregistration.k8s.io/v1",
                kind,
                side_effects,
                &serde_json::json!({"url":"https://user:PRIVATE_LEGACY_ENDPOINT@hooks.example.test/"}),
            );
            let text = fixture.to_string();
            let set = parse(&text, 93, DocumentFormat::Json)?;
            for minor in [20, 37] {
                let target = target(minor)?;
                let findings = validate_for_target_with_intent(&set, &target, NativeValidationIntent::Unspecified);
                let context = findings
                    .iter()
                    .find(|finding| {
                        finding.code == FindingCode::NativeContextRequired
                            && finding.path.as_ref() == Some(&expected_path)
                    })
                    .ok_or("legacy context uncertainty omitted")?;
                assert_eq!(context.severity, Severity::Warning);
                assert_eq!(context.resource, Some(set.documents()[0].id()));
                assert!(
                    !findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
                );
                let artifact = kubernetes_lens::generate(
                    &set,
                    &target,
                    OutputFormat::Json,
                    &explicit_output(NativeValidationIntent::Unspecified),
                )
                .map_err(|error| format!("legacy source preservation refused: {error:?}"))?;
                let output: serde_json::Value = serde_json::from_slice(artifact.reveal_bytes(&artifact_access))
                    .map_err(|_| "legacy output JSON")?;
                assert_eq!(output["webhooks"][0]["sideEffects"], side_effects);
                assert!(
                    artifact
                        .findings()
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeContextRequired
                            && finding.path.as_ref() == Some(&expected_path))
                );
                assert!(!format!("{artifact:?}{findings:?}").contains("PRIVATE_LEGACY_ENDPOINT"));
            }
            assert_eq!(set.sources()[0].reveal_raw(&source_access), text.as_bytes());
        }
    }
    Ok(())
}

#[test]
fn explicit_null_service_keeps_admission_and_conversion_remote_url_prerequisites() -> TestResult {
    let client = serde_json::json!({"service":null,"url":"https://user:PRIVATE_REMOTE_ENDPOINT@hooks.example.test/"});
    let source_access = ExplicitSourceAccess::explicitly_allow_raw_source();
    for (fixture, minor, base) in endpoint_fixtures(&client)? {
        let text = fixture.to_string();
        let set = parse(&text, 94, DocumentFormat::Json)?;
        let graph = resolve_references_for_target(&set, &target(minor)?);
        let expected_path = FieldPath::parse(&format!("{base}/url")).map_err(|_| "remote endpoint path")?;
        let remote = graph
            .edges
            .iter()
            .filter(|edge| edge.reference.path == expected_path)
            .collect::<Vec<_>>();
        assert_eq!(remote.len(), 1, "{base}");
        let edge = remote[0];
        assert_eq!(edge.reference.from, set.documents()[0].id());
        assert_eq!(edge.reference.relation, RelationshipKind::Dependency);
        assert!(matches!(
            edge.reference.target,
            ReferenceTarget::External {
                kind: ExternalRefKind::Remote
            }
        ));
        assert!(matches!(edge.reference.scope, ReferenceScope::Unknown));
        assert_eq!(edge.resolution, Resolution::External(ExternalRefKind::Remote));
        assert!(
            graph
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::ExternalPrerequisite)
        );
        assert!(
            !graph
                .edges
                .iter()
                .any(|edge| matches!(edge.reference.target, ReferenceTarget::CheckedObject { .. }))
        );
        assert!(!format!("{graph:?}").contains("PRIVATE_REMOTE_ENDPOINT"));
        assert_eq!(set.sources()[0].reveal_raw(&source_access), text.as_bytes());
    }
    Ok(())
}

#[test]
fn null_url_and_null_service_do_not_invent_or_hide_service_prerequisites() -> TestResult {
    for (client, service) in [
        (serde_json::json!({"service":null,"url":null}), false),
        (
            serde_json::json!({"service":{"name":"webhook","namespace":"system"},"url":null}),
            true,
        ),
    ] {
        for (fixture, minor, base) in endpoint_fixtures(&client)? {
            let set = parse(&fixture.to_string(), 95, DocumentFormat::Json)?;
            let graph = resolve_references_for_target(&set, &target(minor)?);
            assert!(!graph.edges.iter().any(|edge| matches!(
                edge.reference.target,
                ReferenceTarget::External {
                    kind: ExternalRefKind::Remote
                }
            )));
            let expected_path =
                FieldPath::parse(&format!("{base}/service/name")).map_err(|_| "service endpoint path")?;
            let present = graph.edges.iter().any(|edge| {
                edge.reference.path == expected_path
                    && matches!(edge.reference.target, ReferenceTarget::CheckedObject { .. })
            });
            assert_eq!(present, service, "{base}");
        }
    }
    Ok(())
}
#[test]
fn sealed_descriptors_reject_other_sets_and_targets() -> TestResult {
    let set = parse(INPUT, 77, DocumentFormat::Json)?;
    let selected = target(30)?;
    let edge = sealed_edge(&set, &selected)?;
    assert!(replay_resolves(&set, &edge, &selected));
    for id in [77, 78] {
        for text in [INPUT.to_owned(), INPUT.replace("\"served\":true", "\"served\":false")] {
            let other = parse(&text, id, DocumentFormat::Json)?;
            assert!(!replay_resolves(&other, &edge, &selected));
        }
    }
    assert!(!replay_resolves(&set, &edge, &target(31)?));
    let mut incomplete = selected.clone();
    incomplete.feature_gates.resolution = FeatureGateResolution::RequireExplicit;
    assert!(!replay_resolves(&set, &edge, &incomplete));
    Ok(())
}
#[test]
fn sealed_descriptors_reject_current_crd_edits() -> TestResult {
    let selected = target(30)?;
    for change in 0..7 {
        let mut set = parse(INPUT, 77, DocumentFormat::Json)?;
        let edge = sealed_edge(&set, &selected)?;
        let crd = set.documents_mut()[0]
            .resource_mut::<CustomResourceDefinitionV1>()
            .ok_or("typed CRD")?;
        let Presence::Value(spec) = &mut crd.spec else {
            return Err("spec".into());
        };
        match change {
            0 => spec.group = Presence::Value("other.test".into()),
            1 => {
                if let Presence::Value(names) = &mut spec.names {
                    names.kind = Presence::Value("Other".into());
                }
            }
            2 => spec.scope = Presence::Value("Cluster".into()),
            _ => {
                let version = match &mut spec.versions {
                    Presence::Value(versions) => versions.first_mut().ok_or("version")?,
                    _ => return Err("versions".into()),
                };
                match change {
                    3 => version.served = Presence::Value(false),
                    4 => version.storage = Presence::Value(false),
                    5 => version.name = Presence::Value("v2".into()),
                    _ => {
                        let mut builder = SchemaBuilder::stable(&ParseLimits::default()).map_err(|_| "builder")?;
                        let root = builder
                            .add(SchemaFields {
                                type_name: Presence::Value("object".into()),
                                description: Presence::Value("edited annotation".into()),
                                ..SchemaFields::default()
                            })
                            .map_err(|_| "node")?;
                        let schema = builder.finish_stable(&root).map_err(|_| "seal")?;
                        if let Presence::Value(validation) = &mut version.schema {
                            validation.open_api_v3_schema = Presence::Value(schema);
                        }
                    }
                }
            }
        }
        assert!(!replay_resolves(&set, &edge, &selected), "edit {change}");
    }
    Ok(())
}
#[test]
fn exhausted_custom_pass_never_succeeds_with_a_missing_tail() -> TestResult {
    let text = "apiVersion: example.test/v1\nkind: Widget\nmetadata: {name: one}\nprivate: abcdefghijklmnopqrstuvwxyz\n---\napiVersion: example.test/v1\nkind: Widget\nmetadata: {name: two}\nprivate: abcdefghijklmnopqrstuvwxyz\n---\napiVersion: example.test/v1\nkind: Widget\nmetadata: {name: three}\nprivate: abcdefghijklmnopqrstuvwxyz\n";
    let set = parse(text, 0, DocumentFormat::YamlStream)?;
    let selected = target(30)?;
    for units in [0, 357, 358, 359, 400, 500, 700, 1000, 10000] {
        match set.check_custom_documents(
            &selected,
            NativeProcessingLimits {
                max_processing_units: units,
                ..NativeProcessingLimits::default()
            },
        ) {
            Ok(results) => assert_eq!(results.len(), 3, "ceiling {units}"),
            Err(finding) => assert_eq!(finding.code, FindingCode::LimitExceeded),
        }
    }
    Ok(())
}
// These signatures are an external-caller compile contract, independently matching the beta inventory.
fn beta_enum<'a>(view: &BetaSchemaFieldsView<'a>) -> &'a Presence<Vec<JSONCrdV1beta1>> {
    view.enum_values()
}
fn beta_example<'a>(view: &BetaSchemaFieldsView<'a>) -> &'a Presence<JSONCrdV1beta1> {
    view.example()
}
fn beta_items<'a>(view: &BetaSchemaFieldsView<'a>) -> &'a Presence<JSONSchemaPropsOrArrayCrdV1beta1> {
    view.items()
}
fn beta_extra<'a>(
    view: &BetaSchemaFieldsView<'a>,
) -> (
    &'a Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
    &'a Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
) {
    (view.additional_items(), view.additional_properties())
}
fn beta_dependencies<'a>(
    view: &BetaSchemaFieldsView<'a>,
) -> &'a Presence<BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1beta1>> {
    view.dependencies()
}
fn beta_docs<'a>(view: &BetaSchemaFieldsView<'a>) -> &'a Presence<ExternalDocumentationCrdV1beta1> {
    view.external_docs()
}
#[test]
fn beta_views_rebuild_beta_drafts_with_protected_payloads() -> TestResult {
    let beta = INPUT.replace("apiextensions.k8s.io/v1", "apiextensions.k8s.io/v1beta1").replace("\"description\":\"annotation\"", "\"enum\":[null,\"private-enum\"],\"example\":\"private-example\",\"items\":{\"type\":\"string\"},\"additionalItems\":false,\"additionalProperties\":true,\"dependencies\":{\"private-dependency\":[\"name\"]},\"externalDocs\":{\"url\":\"private-url\"}");
    let set = parse(&beta, 77, DocumentFormat::Json)?;
    let crd = set.documents()[0]
        .resource::<kubernetes_lens::resources::extensions::CustomResourceDefinitionV1beta1>()
        .ok_or("beta root")?;
    let schema = crd
        .spec
        .value()
        .and_then(|s| s.versions.value())
        .and_then(|v| v.first())
        .and_then(|v| v.schema.value())
        .and_then(|s| s.open_api_v3_schema.value())
        .ok_or("beta schema")?;
    let fields = schema.root_view().fields();
    assert!(fields.item_schema(0).is_some());
    let mut foreign = SchemaBuilder::beta(&ParseLimits::default()).map_err(|_| "foreign builder")?;
    assert!(
        foreign
            .add_beta(SchemaFieldsBeta {
                items: beta_items(&fields).clone(),
                ..SchemaFieldsBeta::default()
            })
            .is_err_and(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    let mut stable = SchemaBuilder::stable(&ParseLimits::default()).map_err(|_| "stable builder")?;
    assert!(
        stable
            .add_beta(SchemaFieldsBeta::default())
            .is_err_and(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );

    let (additional_items, additional_properties) = beta_extra(&fields);
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let example = beta_example(&fields).value().ok_or("example")?;
    assert_eq!(
        example.to_json(&access, &ParseLimits::default()).map_err(|_| "JSON")?,
        br#""private-example""#
    );
    assert!(!format!("{example:?}").contains("private-example"));
    let mut builder = SchemaBuilder::beta(&ParseLimits::default()).map_err(|_| "beta builder")?;
    let child = builder
        .add_beta(SchemaFieldsBeta {
            type_name: Presence::Value("string".into()),
            ..SchemaFieldsBeta::default()
        })
        .map_err(|_| "child")?;
    let root = builder
        .add_beta(SchemaFieldsBeta {
            enum_values: beta_enum(&fields).clone(),
            example: beta_example(&fields).clone(),
            dependencies: beta_dependencies(&fields).clone(),
            external_docs: beta_docs(&fields).clone(),
            additional_items: additional_items.clone(),
            additional_properties: additional_properties.clone(),
            items: Presence::Value(JSONSchemaPropsOrArrayCrdV1beta1::Schema(child)),
            ..SchemaFieldsBeta::default()
        })
        .map_err(|_| "beta draft")?;
    let rebuilt = builder.finish_beta(&root).map_err(|_| "beta seal")?;
    assert!(matches!(
        beta_items(&rebuilt.root_view().fields()),
        Presence::Value(JSONSchemaPropsOrArrayCrdV1beta1::Schema(_))
    ));
    assert!(rebuilt.root_view().fields().item_schema(0).is_some());
    Ok(())
}
#[test]
fn unsupported_keyword_paths_are_exact_distinct_and_private_inside_lists() -> TestResult {
    let text = INPUT.replace("\"description\":\"annotation\"", "\"pattern\":\"private-pattern\",\"format\":\"private-format\",\"private-unknown-one\":1,\"private-unknown-two\":2,\"properties\":{\"absent\":{\"type\":\"string\",\"pattern\":\"private-nested-pattern\"}}");
    let set = parse(&text, 77, DocumentFormat::Json)?;
    let checks = set
        .check_custom_documents(&target(30)?, NativeProcessingLimits::default())
        .map_err(|_| "check")?;
    let CustomDocumentCheck::UnsupportedSchema(report) = checks[0].check() else {
        return Err("unsupported schema".into());
    };
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let paths: Vec<_> = (0..report.unsupported_count())
        .filter_map(|index| report.unsupported_path(index, &access))
        .collect();
    for suffix in [
        "pattern",
        "format",
        "private-unknown-one",
        "private-unknown-two",
        "properties/absent/pattern",
    ] {
        assert!(
            paths.contains(&format!("/items/0/spec/versions/0/schema/openAPIV3Schema/{suffix}")),
            "missing {suffix}"
        );
    }
    let debug = format!("{:?}", checks[0]);
    for private in [
        "private-pattern",
        "private-format",
        "private-unknown-one",
        "private-unknown-two",
        "private-nested-pattern",
    ] {
        assert!(!debug.contains(private));
    }
    Ok(())
}
