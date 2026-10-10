//! Independent boundary and privacy checks for admitted extension resources.
use kubernetes_lens::{
    FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::FieldPath,
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
    },
    graph::{ExternalRefKind, ReferenceTarget, RelationshipKind, Resolution, resolve_references_for_target},
    model::{AuthoredResource, ResourceSet},
    parse_source,
    processing::NativeProcessingLimits,
    resources::extensions::custom_documents::CustomDocumentGraphStatus,
    resources::extensions::{
        CustomResourceDefinitionV1, CustomResourceDefinitionV1beta1, JSONCrdV1, JSONSchemaPropsOrArrayCrdV1,
        SchemaBuilder, SchemaFields, SchemaFieldsBeta,
    },
    source::{
        AuthoringLimits, DocumentFormat, EvidenceOrigin, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId,
        SourceInput,
    },
    validate_for_target,
    value::{Presence, ProtectedJsonValue},
};
type TestResult<T = ()> = Result<T, String>;
fn parsed(text: &str) -> TestResult<ResourceSet> {
    parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "extension source parsing failed")?
    .flatten_resources()
    .map_err(|findings| {
        findings
            .iter()
            .map(|finding| {
                format!(
                    "{} {:?} path-depth={}",
                    finding.code.as_str(),
                    finding.phase,
                    finding.path.as_ref().map_or(0, FieldPath::depth)
                )
            })
            .collect::<Vec<_>>()
            .join(", ")
    })
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(
        KubernetesVersion::new(1, minor).map_err(|_| "bad target version")?,
    ))
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    }
}
fn block_options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    }
}
fn artifact(set: &ResourceSet, minor: u8) -> TestResult<serde_json::Value> {
    let profile = target(minor)?;
    let generated =
        generate(set, &profile, OutputFormat::Json, &options()).map_err(|_| "extension generation failed")?;
    serde_json::from_slice(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
        .map_err(|_| "generated extension artifact was invalid JSON".into())
}

#[test]
fn stable_and_beta_schema_values_have_distinct_types_and_redacted_debug() -> TestResult {
    let marker = "private-schema-enum-value";
    let stable = parsed(&format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"widgets.example.test"}},"spec":{{"group":"example.test","scope":"Namespaced","names":{{"plural":"widgets","singular":"widget","kind":"Widget"}},"versions":[{{"name":"v1","served":true,"storage":true,"schema":{{"openAPIV3Schema":{{"type":"string","enum":["{marker}"],"example":"{marker}","dependencies":{{"a":["b"],"b":{{"type":"string"}}}}}}}}}}]}}}}"#
    ))?;
    let beta = parsed(&format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{{"name":"widgets.example.test"}},"spec":{{"group":"example.test","version":"v1","scope":"Namespaced","names":{{"plural":"widgets","singular":"widget","kind":"Widget"}},"validation":{{"openAPIV3Schema":{{"type":"string","enum":["{marker}"],"example":"{marker}"}}}}}}}}"#
    ))?;
    assert!(!format!("{stable:?}").contains(marker));
    assert!(!format!("{beta:?}").contains(marker));
    let stable_output = artifact(&stable, 30)?;
    let beta_output = artifact(&beta, 21)?;
    assert_eq!(
        stable_output["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["enum"][0],
        marker
    );
    assert_eq!(
        stable_output["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["dependencies"]["a"][0],
        "b"
    );
    assert_eq!(
        stable_output["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["dependencies"]["b"]["type"],
        "string"
    );
    assert_eq!(beta_output["spec"]["validation"]["openAPIV3Schema"]["enum"][0], marker);
    Ok(())
}

#[test]
fn minimal_stable_and_beta_known_schema_fields_generate_under_block_policy() -> TestResult {
    let stable = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","singular":"widget","kind":"Widget","categories":["sample"]},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"name":{"type":"string"}}}}}]}}"#,
    )?;
    let beta = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","version":"v1","scope":"Namespaced","names":{"plural":"widgets","singular":"widget","kind":"Widget","listKind":"WidgetList","shortNames":["wdg"],"categories":["sample"]},"validation":{"openAPIV3Schema":{"type":"object","properties":{"name":{"type":"string"}}}}}}"#,
    )?;
    let stable_profile = target(30)?;
    let beta_profile = target(21)?;
    let stable_output = generate(&stable, &stable_profile, OutputFormat::Json, &block_options())
        .map_err(|_| "stable known schema generation was blocked")?;
    let beta_output = generate(&beta, &beta_profile, OutputFormat::Json, &block_options())
        .map_err(|_| "beta known schema generation was blocked")?;
    let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    let stable_json: serde_json::Value =
        serde_json::from_slice(stable_output.reveal_bytes(&access)).map_err(|_| "stable generated JSON was invalid")?;
    let beta_json: serde_json::Value =
        serde_json::from_slice(beta_output.reveal_bytes(&access)).map_err(|_| "beta generated JSON was invalid")?;
    assert_eq!(
        stable_json["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["type"],
        "object"
    );
    assert_eq!(beta_json["spec"]["validation"]["openAPIV3Schema"]["type"], "object");
    let with_unknown_descendant = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","x-private-unknown":true}}}]}}"#,
    )?;
    assert!(
        generate(
            &with_unknown_descendant,
            &stable_profile,
            OutputFormat::Json,
            &block_options(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn schema_builder_accepts_prior_nodes_and_rejects_foreign_family_handles() -> TestResult {
    let limits = ParseLimits::default();
    let mut stable = SchemaBuilder::stable(&limits).map_err(|_| "stable schema builder failed")?;
    let child = stable
        .add(SchemaFields::default())
        .map_err(|_| "stable schema child failed")?;
    let root = stable
        .add(SchemaFields {
            items: Presence::Value(JSONSchemaPropsOrArrayCrdV1::Schema(child)),
            ..SchemaFields::default()
        })
        .map_err(|_| "stable schema root rejected a prior same-family node")?;
    stable
        .finish_stable(&root)
        .map_err(|_| "stable schema could not be sealed")?;

    let mut beta = SchemaBuilder::beta(&limits).map_err(|_| "beta schema builder failed")?;
    let beta_child = beta
        .add(SchemaFields::default())
        .map_err(|_| "beta schema child failed")?;
    let mut stable_again = SchemaBuilder::stable(&limits).map_err(|_| "stable schema builder failed")?;
    let rejected = stable_again.add(SchemaFields {
        items: Presence::Value(JSONSchemaPropsOrArrayCrdV1::Schema(beta_child)),
        ..SchemaFields::default()
    });
    assert!(rejected.is_err());
    Ok(())
}

#[test]
fn decoded_stable_and_beta_schema_views_traverse_typed_nodes_and_keep_family_drafts() -> TestResult {
    let stable = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"count":{"type":"integer","minimum":2}}}}}]}}"#,
    )?;
    let beta = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","version":"v1","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"validation":{"openAPIV3Schema":{"type":"object","properties":{"name":{"type":"string","minLength":2}}}}}}"#,
    )?;
    let stable_crd = stable.documents()[0]
        .resource::<CustomResourceDefinitionV1>()
        .ok_or("stable typed CRD was absent")?;
    let stable_schema = stable_crd
        .spec
        .value()
        .and_then(|spec| spec.versions.value())
        .and_then(|versions| versions.first())
        .and_then(|version| version.schema.value())
        .and_then(|schema| schema.open_api_v3_schema.value())
        .ok_or("stable typed schema was absent")?;
    assert_eq!(
        stable_schema.root_view().fields().type_name(),
        &Presence::Value("object".into())
    );
    let stable_child = stable_schema
        .root_view()
        .fields()
        .property("count")
        .ok_or("stable child schema was not traversable")?;
    assert_eq!(stable_child.fields().type_name(), &Presence::Value("integer".into()));
    assert_eq!(
        stable_child
            .fields()
            .minimum()
            .value()
            .map(|value| value.lexeme(&ExplicitSourceAccess::explicitly_allow_raw_source())),
        Some("2")
    );

    let beta_crd = beta.documents()[0]
        .resource::<CustomResourceDefinitionV1beta1>()
        .ok_or("beta typed CRD was absent")?;
    let beta_schema = beta_crd
        .spec
        .value()
        .and_then(|spec| spec.validation.value())
        .and_then(|validation| validation.open_api_v3_schema.value())
        .ok_or("beta typed schema was absent")?;
    assert_eq!(
        beta_schema.root_view().fields().type_name(),
        &Presence::Value("object".into())
    );
    let beta_child = beta_schema
        .root_view()
        .fields()
        .property("name")
        .ok_or("beta child schema was not traversable")?;
    assert_eq!(beta_child.fields().type_name(), &Presence::Value("string".into()));
    assert_eq!(beta_child.fields().minimum(), &Presence::Absent);

    let limits = ParseLimits::default();
    let mut beta_builder = SchemaBuilder::beta(&limits).map_err(|_| "beta builder failed")?;
    let child = beta_builder
        .add_beta(SchemaFieldsBeta {
            type_name: Presence::Value("string".into()),
            ..SchemaFieldsBeta::default()
        })
        .map_err(|_| "beta draft node failed")?;
    let root = beta_builder
        .add_beta(SchemaFieldsBeta {
            properties: Presence::Value(std::collections::BTreeMap::from([("name".into(), child)])),
            ..SchemaFieldsBeta::default()
        })
        .map_err(|_| "beta draft root failed")?;
    let authored = beta_builder.finish_beta(&root).map_err(|_| "beta draft did not seal")?;
    assert_eq!(
        authored
            .root_view()
            .fields()
            .property("name")
            .ok_or("authored property missing")?
            .fields()
            .type_name(),
        &Presence::Value("string".into())
    );

    let mut foreign_builder = SchemaBuilder::beta(&limits).map_err(|_| "foreign beta builder failed")?;
    let foreign = foreign_builder
        .add_beta(SchemaFieldsBeta::default())
        .map_err(|_| "foreign beta node failed")?;
    assert!(authored.node_view(&foreign).is_none());
    Ok(())
}

#[test]
fn stable_and_beta_schema_views_preserve_every_selected_member_and_recursive_union() -> TestResult {
    let stable_text = format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{{"name":"widgets.example.test"}},"spec":{{"group":"example.test","scope":"Namespaced","names":{{"plural":"widgets","kind":"Widget"}},"versions":[{{"name":"v1","served":true,"storage":true,"schema":{{"openAPIV3Schema":{EVERY_SCHEMA_MEMBER}}}}}]}}}}"#
    );
    let stable = parsed(&stable_text)?;
    let stable_crd = stable.documents()[0]
        .resource::<CustomResourceDefinitionV1>()
        .ok_or("stable CRD missing")?;
    let stable_schema = stable_crd
        .spec
        .value()
        .and_then(|spec| spec.versions.value())
        .and_then(|versions| versions.first())
        .and_then(|version| version.schema.value())
        .and_then(|schema| schema.open_api_v3_schema.value())
        .ok_or("stable schema missing")?;
    let fields = stable_schema.root_view().fields();
    assert!(
        [
            fields.description().value().is_some(),
            fields.title().value().is_some(),
            fields.format().value().is_some(),
            fields.id().value().is_some(),
            fields.pattern().value().is_some(),
            fields.required().value().is_some(),
            fields.minimum().value().is_some(),
            fields.maximum().value().is_some(),
            fields.exclusive_minimum().value().is_some(),
            fields.exclusive_maximum().value().is_some(),
            fields.multiple_of().value().is_some(),
            fields.min_length().value().is_some(),
            fields.max_length().value().is_some(),
            fields.min_items().value().is_some(),
            fields.max_items().value().is_some(),
            fields.min_properties().value().is_some(),
            fields.max_properties().value().is_some(),
            fields.unique_items().value().is_some(),
            fields.nullable().value().is_some(),
            fields.enum_values().value().is_some(),
            fields.example().value().is_some(),
            fields.properties().value().is_some(),
            fields.definitions().value().is_some(),
            fields.pattern_properties().value().is_some(),
            fields.dependencies().value().is_some(),
            fields.items().value().is_some(),
            fields.additional_items().value().is_some(),
            fields.additional_properties().value().is_some(),
            fields.all_of().value().is_some(),
            fields.any_of().value().is_some(),
            fields.one_of().value().is_some(),
            fields.not().value().is_some(),
            fields.external_docs().value().is_some(),
            fields.x_kubernetes_embedded_resource().value().is_some(),
            fields.x_kubernetes_int_or_string().value().is_some(),
            fields.x_kubernetes_list_map_keys().value().is_some(),
            fields.x_kubernetes_list_type().value().is_some(),
            fields.x_kubernetes_map_type().value().is_some(),
            fields.x_kubernetes_preserve_unknown_fields().value().is_some(),
        ]
        .into_iter()
        .all(|present| present)
    );
    assert!(fields.property("prop").is_some());
    assert_eq!(
        fields.property("prop").ok_or("property missing")?.fields().example(),
        &Presence::Null
    );
    assert!(fields.definition("def").is_some());
    assert!(fields.pattern_property("^x").is_some());
    assert!(fields.dependency_schema("schema").is_some());
    assert!(fields.item_schema(0).is_some());
    assert!(fields.additional_properties_schema().is_some());
    assert!(fields.all_of_schema(0).is_some());
    assert!(fields.any_of_schema(0).is_some());
    assert!(fields.one_of_schema(0).is_some());
    assert!(fields.not_schema().is_some());
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(
        fields.enum_values().value().ok_or("enum missing")?[0]
            .to_json(&access, &ParseLimits::default())
            .map_err(|_| "enum JSON")?,
        b"null"
    );
    assert!(
        String::from_utf8(
            fields
                .example()
                .value()
                .ok_or("example missing")?
                .to_json(&access, &ParseLimits::default())
                .map_err(|_| "example JSON")?
        )
        .map_err(|_| "example UTF-8")?
        .contains("private")
    );

    Ok(())
}

const EVERY_SCHEMA_MEMBER: &str = r#"{"type":"object","description":"d","title":"t","format":"fmt","id":"id","pattern":"p","required":["prop"],"minimum":1,"maximum":9,"exclusiveMinimum":true,"exclusiveMaximum":false,"multipleOf":2,"minLength":1,"maxLength":9,"minItems":1,"maxItems":9,"minProperties":1,"maxProperties":9,"uniqueItems":true,"nullable":true,"enum":[null,1],"example":{"x":"private"},"properties":{"prop":{"type":"string","example":null}},"definitions":{"def":{"type":"string"}},"patternProperties":{"^x":{"type":"string"}},"dependencies":{"schema":{"type":"string"},"required":["prop"]},"items":[{"type":"string"}],"additionalItems":false,"additionalProperties":{"type":"string"},"allOf":[{"type":"string"}],"anyOf":[{"type":"string"}],"oneOf":[{"type":"string"}],"not":{"type":"string"},"externalDocs":{"description":"docs","url":"https://docs.example.test"},"x-kubernetes-embedded-resource":true,"x-kubernetes-int-or-string":true,"x-kubernetes-list-map-keys":["prop"],"x-kubernetes-list-type":"map","x-kubernetes-map-type":"granular","x-kubernetes-preserve-unknown-fields":true}"#;

#[test]
fn beta_schema_views_preserve_every_selected_member_and_recursive_union() -> TestResult {
    let beta_text = format!(
        r#"{{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{{"name":"widgets.example.test"}},"spec":{{"group":"example.test","version":"v1","scope":"Namespaced","names":{{"plural":"widgets","kind":"Widget"}},"validation":{{"openAPIV3Schema":{EVERY_SCHEMA_MEMBER}}}}}}}"#
    );
    let beta = parsed(&beta_text)?;
    let beta_crd = beta.documents()[0]
        .resource::<CustomResourceDefinitionV1beta1>()
        .ok_or("beta CRD missing")?;
    let beta_schema = beta_crd
        .spec
        .value()
        .and_then(|spec| spec.validation.value())
        .and_then(|validation| validation.open_api_v3_schema.value())
        .ok_or("beta schema missing")?;
    let fields = beta_schema.root_view().fields();
    assert!(
        [
            fields.description().value().is_some(),
            fields.title().value().is_some(),
            fields.format().value().is_some(),
            fields.id().value().is_some(),
            fields.pattern().value().is_some(),
            fields.required().value().is_some(),
            fields.minimum().value().is_some(),
            fields.maximum().value().is_some(),
            fields.exclusive_minimum().value().is_some(),
            fields.exclusive_maximum().value().is_some(),
            fields.multiple_of().value().is_some(),
            fields.min_length().value().is_some(),
            fields.max_length().value().is_some(),
            fields.min_items().value().is_some(),
            fields.max_items().value().is_some(),
            fields.min_properties().value().is_some(),
            fields.max_properties().value().is_some(),
            fields.unique_items().value().is_some(),
            fields.nullable().value().is_some(),
            fields.enum_values().value().is_some(),
            fields.example().value().is_some(),
            fields.properties().value().is_some(),
            fields.definitions().value().is_some(),
            fields.pattern_properties().value().is_some(),
            fields.dependencies().value().is_some(),
            fields.items().value().is_some(),
            fields.additional_items().value().is_some(),
            fields.additional_properties().value().is_some(),
            fields.all_of().value().is_some(),
            fields.any_of().value().is_some(),
            fields.one_of().value().is_some(),
            fields.not().value().is_some(),
            fields.external_docs().value().is_some(),
            fields.x_kubernetes_embedded_resource().value().is_some(),
            fields.x_kubernetes_int_or_string().value().is_some(),
            fields.x_kubernetes_list_map_keys().value().is_some(),
            fields.x_kubernetes_list_type().value().is_some(),
            fields.x_kubernetes_map_type().value().is_some(),
            fields.x_kubernetes_preserve_unknown_fields().value().is_some(),
        ]
        .into_iter()
        .all(|present| present)
    );
    assert!(fields.property("prop").is_some());
    assert_eq!(
        fields.property("prop").ok_or("property missing")?.fields().example(),
        &Presence::Null
    );
    assert!(fields.definition("def").is_some());
    assert!(fields.pattern_property("^x").is_some());
    assert!(fields.dependency_schema("schema").is_some());
    assert!(fields.item_schema(0).is_some());
    assert!(fields.additional_properties_schema().is_some());
    assert!(fields.all_of_schema(0).is_some());
    assert!(fields.any_of_schema(0).is_some());
    assert!(fields.one_of_schema(0).is_some());
    assert!(fields.not_schema().is_some());
    Ok(())
}

fn stable_crd_with_schema(schema: &serde_json::Value) -> TestResult<ResourceSet> {
    parsed(
        &serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1",
            "kind": "CustomResourceDefinition",
            "metadata": {"name": "widgets.example.test"},
            "spec": {
                "group": "example.test",
                "scope": "Namespaced",
                "names": {"plural": "widgets", "kind": "Widget"},
                "versions": [{
                    "name": "v1", "served": true, "storage": true,
                    "schema": {"openAPIV3Schema": schema}
                }]
            }
        })
        .to_string(),
    )
}

#[test]
fn selected_schema_recursion_admits_mixed_paths_and_property_depth_seventeen() -> TestResult {
    let mut deep = serde_json::json!({"type": "string"});
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
    let set = stable_crd_with_schema(&schema)?;
    let generated = generate(&set, &target(30)?, OutputFormat::Json, &block_options())
        .map_err(|_| "selected mixed recursive/deep schema paths were blocked")?;
    let output: serde_json::Value =
        serde_json::from_slice(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
            .map_err(|_| "generated recursive schema JSON was invalid")?;
    let mut selected = &output["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["array"]["items"]["additionalProperties"]
        ["allOf"][0]["dependencies"]["needs"]["oneOf"][0]["definitions"]["named"]["patternProperties"]["^item"]["properties"]
        ["deep"];
    for index in 0..18 {
        selected = &selected["properties"][format!("p{index}")];
    }
    assert_eq!(selected["type"], "string");
    Ok(())
}

#[test]
fn selected_protected_schema_payload_needs_include_and_unknown_default_stays_blocked() -> TestResult {
    let selected = stable_crd_with_schema(&serde_json::json!({
        "type": "string",
        "enum": [null, {"nested": ["private"]}],
        "example": {"nested": {"secret": "private"}}
    }))?;
    let denied = GenerationOptions {
        protected_output: ProtectedOutput::Deny,
        ..options()
    };
    assert!(generate(&selected, &target(30)?, OutputFormat::Json, &denied).is_err());
    let included = generate(&selected, &target(30)?, OutputFormat::Json, &options())
        .map_err(|_| "explicitly included selected enum/example payload was blocked")?;
    let included: serde_json::Value =
        serde_json::from_slice(included.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
            .map_err(|_| "generated protected schema JSON was invalid")?;
    assert_eq!(
        included["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["enum"][0],
        serde_json::Value::Null
    );

    let unknown = stable_crd_with_schema(&serde_json::json!({
        "type": "object",
        "default": {"nested": ["must remain blocked"]}
    }))?;
    assert!(generate(&unknown, &target(30)?, OutputFormat::Json, &block_options()).is_err());
    Ok(())
}

#[test]
fn beta_per_version_schema_and_nonempty_webhook_rules_generate_under_block_policy() -> TestResult {
    let beta = parsed(
        r#"{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","version":"v1","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","properties":{"name":{"type":"string"}}}}}]}}"#,
    )?;
    generate(&beta, &target(21)?, OutputFormat::Json, &block_options())
        .map_err(|_| "selected beta per-version schema path was blocked")?;
    let webhooks = parsed(
        r#"{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"policy"},"webhooks":[{"name":"hook.example.test","clientConfig":{"url":"https://hooks.example.test/"},"rules":[{"apiGroups":["example.test"],"apiVersions":["v1"],"operations":["CREATE","UPDATE"],"resources":["widgets"],"scope":"Namespaced"}]}]}"#,
    )?;
    generate(&webhooks, &target(30)?, OutputFormat::Json, &block_options())
        .map_err(|_| "selected nonempty webhook rule paths were blocked")?;
    Ok(())
}

#[test]
fn graph_binds_custom_document_to_actual_crd_version_and_retains_controller_prerequisite() -> TestResult {
    let set = parsed(
        &serde_json::json!({
            "apiVersion": "v1", "kind": "List",
            "items": [
                {
                    "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                    "metadata": {"name": "widgets.example.test"},
                    "spec": {
                        "group": "example.test", "scope": "Namespaced",
                        "names": {"plural": "widgets", "kind": "Widget"},
                        "versions": [{"name": "v1", "served": true, "storage": true,
                            "schema": {"openAPIV3Schema": {"type": "object"}}}]
                    }
                },
                {"apiVersion": "example.test/v1", "kind": "Widget",
                    "metadata": {"name": "sample", "namespace": "dev"}}
            ]
        })
        .to_string(),
    )?;
    let graph = resolve_references_for_target(&set, &target(30)?);
    assert_eq!(graph.custom_documents.len(), 1);
    let record = &graph.custom_documents[0];
    assert_eq!(record.resource_id().0, 1);
    assert_eq!(record.status(), CustomDocumentGraphStatus::Bound);
    let descriptor = record.descriptor().ok_or("bound graph record omitted descriptor")?;
    assert_eq!(descriptor.resource_id().0, 0);
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(record.pointer(&access), "/items/1");
    assert_eq!(descriptor.crd_pointer(&access), "/items/0");
    assert_eq!(descriptor.version_pointer(&access), "/items/0/spec/versions/0");
    assert_eq!(
        descriptor.schema_pointer(&access),
        "/items/0/spec/versions/0/schema/openAPIV3Schema"
    );

    let binding_edge = graph
        .edges
        .iter()
        .find(|edge| {
            matches!(
                edge.reference.target,
                ReferenceTarget::SuppliedCustomResourceVersion { .. }
            )
        })
        .ok_or("graph omitted supplied CRD version dependency")?;
    assert_eq!(binding_edge.reference.from.0, 1);
    assert_eq!(binding_edge.reference.relation, RelationshipKind::Dependency);
    assert_eq!(
        binding_edge.resolution,
        Resolution::Resolved(vec![kubernetes_lens::diagnostic::ResourceId(0)])
    );
    assert!(binding_edge.evidence.iter().any(|item| item.resource.0 == 0));
    let version_path = FieldPath::parse("/spec/versions/0").map_err(|_| "bad version path")?;
    let schema_path = FieldPath::parse("/spec/versions/0/schema/openAPIV3Schema").map_err(|_| "bad schema path")?;
    assert!(
        binding_edge
            .evidence
            .iter()
            .any(|item| { item.resource.0 == 0 && item.path == version_path })
    );
    assert!(
        binding_edge
            .evidence
            .iter()
            .any(|item| { item.resource.0 == 0 && item.path == schema_path })
    );

    let controller = graph
        .edges
        .iter()
        .find(|edge| {
            matches!(
                edge.reference.target,
                ReferenceTarget::External {
                    kind: ExternalRefKind::Operator
                }
            )
        })
        .ok_or("graph omitted the external controller prerequisite")?;
    assert_eq!(controller.resolution, Resolution::External(ExternalRefKind::Operator));
    Ok(())
}

#[test]
fn custom_document_graph_keeps_missing_and_targetless_bindings_non_positive() -> TestResult {
    let custom =
        parsed(r#"{"apiVersion":"example.test/v1","kind":"Widget","metadata":{"name":"sample","namespace":"dev"}}"#)?;
    let missing = resolve_references_for_target(&custom, &target(30)?);
    assert_eq!(
        missing.custom_documents[0].status(),
        CustomDocumentGraphStatus::MissingCrd
    );
    assert!(missing.edges.iter().all(|edge| {
        !matches!(
            edge.reference.target,
            ReferenceTarget::SuppliedCustomResourceVersion { .. }
        )
    }));
    assert!(
        missing
            .edges
            .iter()
            .any(|edge| edge.resolution == Resolution::External(ExternalRefKind::Operator))
    );

    let with_crd = parsed(
        &serde_json::json!({
            "apiVersion": "v1", "kind": "List",
            "items": [
                {
                    "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                    "metadata": {"name": "widgets.example.test"},
                    "spec": {
                        "group": "example.test", "scope": "Namespaced",
                        "names": {"plural": "widgets", "kind": "Widget"},
                        "versions": [{"name": "v1", "served": true, "storage": true,
                            "schema": {"openAPIV3Schema": {"type": "object"}}}]
                    }
                },
                {"apiVersion": "example.test/v1", "kind": "Widget",
                    "metadata": {"name": "sample", "namespace": "dev"}}
            ]
        })
        .to_string(),
    )?;
    let targetless = kubernetes_lens::graph::resolve_references(&with_crd);
    assert_eq!(
        targetless.custom_documents[0].status(),
        CustomDocumentGraphStatus::TargetProfileRequired
    );
    assert!(targetless.custom_documents[0].descriptor().is_none());
    assert!(targetless.edges.iter().all(|edge| {
        !matches!(
            edge.reference.target,
            ReferenceTarget::SuppliedCustomResourceVersion { .. }
        )
    }));
    Ok(())
}

#[test]
fn custom_document_graph_keeps_failed_bindings_non_positive() -> TestResult {
    let make_crd = |name: &str, scope: &str, served: bool, schema: serde_json::Value| {
        serde_json::json!({
            "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
            "metadata": {"name": name},
            "spec": {
                "group": "example.test", "scope": scope,
                "names": {"plural": "widgets", "kind": "Widget"},
                "versions": [{"name": "v1", "served": served, "storage": true,
                    "schema": {"openAPIV3Schema": schema}}]
            }
        })
    };
    let make_set = |crds: Vec<serde_json::Value>| -> TestResult<ResourceSet> {
        let mut items = crds;
        items.push(serde_json::json!({
            "apiVersion": "example.test/v1", "kind": "Widget",
            "metadata": {"name": "sample", "namespace": "dev"}
        }));
        parsed(&serde_json::json!({"apiVersion": "v1", "kind": "List", "items": items}).to_string())
    };
    let cases = [
        (
            vec![make_crd(
                "widgets.example.test",
                "Namespaced",
                false,
                serde_json::json!({"type": "object"}),
            )],
            CustomDocumentGraphStatus::VersionNotServed,
        ),
        (
            vec![
                make_crd(
                    "widgets.example.test",
                    "Namespaced",
                    true,
                    serde_json::json!({"type": "object"}),
                ),
                make_crd(
                    "widgets-alt.example.test",
                    "Namespaced",
                    true,
                    serde_json::json!({"type": "object"}),
                ),
            ],
            CustomDocumentGraphStatus::AmbiguousCrd,
        ),
        (
            vec![make_crd(
                "widgets.example.test",
                "Invalid",
                true,
                serde_json::json!({"type": "object"}),
            )],
            CustomDocumentGraphStatus::InvalidBinding,
        ),
        (
            vec![make_crd(
                "widgets.example.test",
                "Namespaced",
                true,
                serde_json::json!({"type": "object", "default": {"private": true}}),
            )],
            CustomDocumentGraphStatus::UnsupportedSchema,
        ),
        (
            vec![make_crd(
                "widgets.example.test",
                "Namespaced",
                true,
                serde_json::json!({"type": "object", "required": ["name"]}),
            )],
            CustomDocumentGraphStatus::SchemaViolations,
        ),
    ];
    for (crds, expected) in cases {
        let graph = resolve_references_for_target(&make_set(crds)?, &target(30)?);
        assert_eq!(graph.custom_documents[0].status(), expected);
        assert!(graph.custom_documents[0].descriptor().is_none());
        assert!(graph.edges.iter().all(|edge| {
            !matches!(
                edge.reference.target,
                ReferenceTarget::SuppliedCustomResourceVersion { .. }
            )
        }));
    }
    Ok(())
}

#[test]
fn crd_conversion_webhook_adds_the_explicit_service_dependency() -> TestResult {
    let set = parsed(
        &serde_json::json!({
            "apiVersion": "v1", "kind": "List",
            "items": [
                {
                    "apiVersion": "apiextensions.k8s.io/v1", "kind": "CustomResourceDefinition",
                    "metadata": {"name": "widgets.example.test"},
                    "spec": {
                        "group": "example.test", "scope": "Namespaced",
                        "names": {"plural": "widgets", "kind": "Widget"},
                        "versions": [{"name": "v1", "served": true, "storage": true}],
                        "conversion": {"strategy": "Webhook", "webhook": {
                            "clientConfig": {"service": {"name": "converter", "namespace": "system", "port": 443}},
                            "conversionReviewVersions": ["v1"]
                        }}
                    }
                },
                {"apiVersion": "v1", "kind": "Service",
                    "metadata": {"name": "converter", "namespace": "system"}}
            ]
        })
        .to_string(),
    )?;
    let graph = resolve_references_for_target(&set, &target(30)?);
    let conversion_path = FieldPath::parse("/spec/conversion/webhook/clientConfig/service/name")
        .map_err(|_| "bad expected conversion path")?;
    let conversion = graph
        .edges
        .iter()
        .find(|edge| edge.reference.path == conversion_path)
        .ok_or("graph omitted the CRD conversion Service dependency")?;
    assert_eq!(conversion.reference.from.0, 0);
    assert_eq!(conversion.reference.relation, RelationshipKind::Dependency);
    assert!(matches!(
        conversion.reference.target,
        ReferenceTarget::CheckedObject { .. }
    ));
    assert!(matches!(
        conversion.resolution,
        Resolution::ResolvedSubjects(_) | Resolution::Resolved(_)
    ));
    Ok(())
}

#[test]
fn schema_builder_rejects_value_null_example_alias() -> TestResult {
    let null = JSONCrdV1::parse_json(b"null", &ParseLimits::default())
        .map_err(|_| "protected null JSON value failed to parse")?;
    let mut builder = SchemaBuilder::stable(&ParseLimits::default()).map_err(|_| "stable schema builder failed")?;
    let result = builder.add(SchemaFields {
        example: Presence::Value(null),
        ..SchemaFields::default()
    });
    assert!(result.is_err());
    Ok(())
}

#[test]
fn beta_webhook_is_served_only_before_its_removal_boundary() -> TestResult {
    let beta = parsed(
        r#"{"apiVersion":"admissionregistration.k8s.io/v1beta1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"policy"},"webhooks":[]}"#,
    )?;
    assert_eq!(
        artifact(&beta, 21)?["apiVersion"],
        "admissionregistration.k8s.io/v1beta1"
    );
    let failure = generate(
        &beta,
        &target(22).map_err(|_| "bad target")?,
        OutputFormat::Json,
        &options(),
    )
    .err()
    .ok_or_else(|| "removed beta API was accepted".to_owned())?;
    assert!(
        failure
            .iter()
            .any(|finding| finding.code == FindingCode::UnavailableApi)
    );
    Ok(())
}

#[test]
fn stable_webhook_configuration_preserves_url_and_certificate_but_does_not_reveal_them_in_debug() -> TestResult {
    let marker = "secret-webhook-payload";
    let ca_bundle = "c2VjcmV0LXdlYmhvb2stcGF5bG9hZA==";
    let set = parsed(&format!(
        r#"{{"apiVersion":"admissionregistration.k8s.io/v1","kind":"MutatingWebhookConfiguration","metadata":{{"name":"policy"}},"webhooks":[{{"name":"hook.example.test","clientConfig":{{"url":"https://user:{marker}@hooks.example.test/","caBundle":"{ca_bundle}"}}}}]}}"#
    ))?;
    let generated = artifact(&set, 30)?;
    assert_eq!(
        generated["webhooks"][0]["clientConfig"]["url"],
        format!("https://user:{marker}@hooks.example.test/")
    );
    assert_eq!(generated["webhooks"][0]["clientConfig"]["caBundle"], ca_bundle);
    assert!(!format!("{set:?}").contains(marker));
    Ok(())
}

#[test]
fn selected_webhook_selector_members_generate_under_block_policy() -> TestResult {
    let set = parsed(
        r#"{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"policy"},"webhooks":[{"name":"hook.example.test","clientConfig":{"url":"https://hooks.example.test/"},"namespaceSelector":{"matchLabels":{"team":"payments"},"matchExpressions":[{"key":"environment","operator":"In","values":["production"]}]},"objectSelector":{"matchLabels":{"tier":"backend"}}}]}"#,
    )?;
    let generated = generate(&set, &target(30)?, OutputFormat::Json, &block_options())
        .map_err(|_| "selected webhook selectors were blocked")?;
    let output: serde_json::Value =
        serde_json::from_slice(generated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
            .map_err(|_| "generated webhook JSON was invalid")?;
    assert_eq!(
        output["webhooks"][0]["namespaceSelector"]["matchExpressions"][0]["key"],
        "environment"
    );
    Ok(())
}

#[test]
fn authored_custom_object_retains_source_bound_protected_body_and_checks_offline() -> TestResult {
    let body = ProtectedJsonValue::parse_json(
        br#"{"apiVersion":"example.test/v1","kind":"Widget","metadata":{"name":"sample","namespace":"dev"},"password":"private"}"#,
        &ParseLimits::default(),
    )
    .map_err(|_| "custom JSON body failed to parse")?;
    let authored = AuthoredResource::custom_object("example.test/v1", "Widget", body)
        .map_err(|_| "custom object identity failed")?;
    let target = target(30)?;
    let set = ResourceSet::from_authored(vec![authored], &target, &AuthoringLimits::default())
        .map_err(|_| "custom object authoring failed")?;
    assert_eq!(set.sources()[0].origin, EvidenceOrigin::NativeAuthored);

    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let snapshot = set.sources()[0].reveal_raw(&access);
    let snapshot_value: serde_json::Value = serde_json::from_slice(snapshot).map_err(|_| "bad authored snapshot")?;
    assert_eq!(snapshot_value["apiVersion"], "example.test/v1");
    assert_eq!(snapshot_value["password"], "private");
    let checks = set
        .check_custom_documents(&target, NativeProcessingLimits::default())
        .map_err(|_| "public supplied-CRD check failed")?;
    let result = checks.first().ok_or("custom object result missing")?;
    assert!(matches!(
        result.check(),
        kubernetes_lens::resources::extensions::CustomDocumentCheck::MissingCrd
    ));
    assert_eq!(
        result.resource().identity().scope,
        kubernetes_lens::model::ResourceScope::Unknown
    );
    assert!(result.resource().body().is_some());
    assert!(!format!("{result:?}").contains("private"));
    let limited = set.check_custom_documents(
        &target,
        NativeProcessingLimits {
            max_processing_units: 0,
            ..NativeProcessingLimits::default()
        },
    );
    assert!(limited.is_err_and(|finding| finding.code == FindingCode::LimitExceeded));

    let generated = generate(&set, &target, OutputFormat::Json, &options()).map_err(|_| "custom generation failed")?;
    let output_access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    let output: serde_json::Value =
        serde_json::from_slice(generated.reveal_bytes(&output_access)).map_err(|_| "bad generated JSON")?;
    assert_eq!(output, snapshot_value);
    Ok(())
}

#[test]
fn public_custom_check_keeps_list_prefixed_schema_and_document_provenance() -> TestResult {
    let text = concat!(
        "apiVersion: v1\nkind: List\nitems:\n",
        "- apiVersion: apiextensions.k8s.io/v1\n  kind: CustomResourceDefinition\n",
        "  metadata:\n    name: widgets.example.test\n",
        "  spec:\n    group: example.test\n    scope: Namespaced\n",
        "    names:\n      plural: widgets\n      kind: Widget\n",
        "    versions:\n    - name: v1\n      served: true\n      storage: true\n",
        "      schema:\n        openAPIV3Schema:\n          type: object\n",
        "          x-kubernetes-preserve-unknown-fields: true\n",
        "- apiVersion: example.test/v1\n  kind: Widget\n",
        "  metadata:\n    name: sample\n    namespace: dev\n",
    );
    let set = parse_source(
        SourceInput {
            id: SourceId(7),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "List source failed to parse")?
    .flatten_resources()
    .map_err(|_| "List resources failed to decode")?;
    let results = set
        .check_custom_documents(&target(30)?, NativeProcessingLimits::default())
        .map_err(|_| "public List custom check failed")?;
    let result = results.first().ok_or("custom resource was not checked")?;
    let binding = result.binding().ok_or("supplied CRD binding missing")?;
    assert_eq!(result.source().source, SourceId(7));
    assert_eq!(result.source().document_index, 0);
    assert_eq!(binding.crd().document_index, 0);
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(result.pointer(&access), "/items/1");
    assert_eq!(binding.crd_pointer(&access), "/items/0");
    assert_eq!(
        binding.schema_pointer(&access),
        "/items/0/spec/versions/0/schema/openAPIV3Schema"
    );
    let kubernetes_lens::resources::extensions::CustomDocumentCheck::UnsupportedSchema(report) = result.check() else {
        return Err("expected a local unsupported-schema report".into());
    };
    assert_eq!(
        report.unsupported_path(0, &access).as_deref(),
        Some("/items/0/spec/versions/0/schema/openAPIV3Schema/x-kubernetes-preserve-unknown-fields")
    );
    Ok(())
}

#[test]
fn webhook_timeout_local_check_reports_the_native_member_path() -> TestResult {
    let set = parsed(
        r#"{"apiVersion":"admissionregistration.k8s.io/v1","kind":"ValidatingWebhookConfiguration","metadata":{"name":"policy"},"webhooks":[{"name":"hook.example.test","timeoutSeconds":31,"clientConfig":{"url":"https://hooks.example.test/"}}]}"#,
    )?;
    let findings = validate_for_target(&set, &target(30)?);
    assert!(findings.iter().any(|finding| {
        finding.code == FindingCode::NativeFieldInvalid
            && finding.path.as_ref().is_some_and(|path| {
                path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == "/webhooks/0/timeoutSeconds"
            })
    }));
    Ok(())
}
