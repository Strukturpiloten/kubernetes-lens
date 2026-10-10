//! Independent custom-resource, unsupported-schema, provenance and privacy contracts.
#[path = "../examples/official_custom_probe.rs"]
mod probe;
use kubernetes_lens::{
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::{FindingCode, Phase},
    parse_source,
    processing::NativeProcessingLimits,
    resources::extensions::CustomResourceDefinitionV1,
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::Presence,
};
use serde_json::{Value, json};
type TestResult = Result<(), String>;

fn source() -> Value {
    json!({"apiVersion":"v1","kind":"List","metadata":{"annotations":{"private":"private-wrapper-marker"}},"items":[
        {"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","required":["spec"],"properties":{"spec":{"type":"object","required":["value"],"properties":{"value":{"type":"integer","minimum":1},"optional":{"type":"string"}}}}}}}] }},
        {"apiVersion":"example.test/v1","kind":"Widget","metadata":{"name":"private-resource-name","namespace":"fixture-native"},"spec":{"value":3},"token":"private-body-marker"}
    ]})
}
fn assertion() -> Value {
    json!({"resource_index":1,"source_id":0,"source_document":0,"source_pointer":"/items/1",
        "identity":{"group":"example.test","kind":"Widget","version":"v1"},"check":"Bound","positive_dependency":true,
        "unsupported_categories":[],"supported_subset_satisfied":true,"issue_count":0,
        "binding":{"crd_index":0,"source_id":0,"source_document":0,"crd_api_version":"apiextensions.k8s.io/v1","crd_pointer":"/items/0","version_pointer":"/items/0/spec/versions/0","schema_pointer":"/items/0/spec/versions/0/schema/openAPIV3Schema","namespaced":true,"served":true,"storage":true,"schema_family":"v1"}})
}
fn request(body: &Value) -> Value {
    json!({"schema_version":1,"binding":"a".repeat(64),"invocation_nonce":"0".repeat(32),"target_minor":37,"documented_gate_defaults":true,
        "namespace":"fixture-native","preserve_unknown":true,"include_protected":true,"max_input_bytes":8*1024*1024,
        "sources":[{"format":"json","content":body.to_string()}],"assertions":[{"resource_index":1,"pointer":"/spec/value","equals":3}],
        "graph_assertions":[],"wrapper_assertions":[{"wrapper_index":0,"pointer":"/metadata/annotations/private","equals":"private-wrapper-marker"}],
        "custom_assertions":[assertion()]})
}
fn expect_check(mut request: Value, name: &str) -> Value {
    request["custom_assertions"][0]["check"] = json!(name);
    request["custom_assertions"][0]["positive_dependency"] = json!(false);
    request["custom_assertions"][0]["binding"] = Value::Null;
    if let Some(a) = request["custom_assertions"][0].as_object_mut() {
        a.remove("issue_count");
        a.remove("supported_subset_satisfied");
    }
    request
}
fn evaluate(request: &Value) -> Result<Value, String> {
    probe::evaluate(request).map_err(str::to_owned)
}

#[test]
fn supported_subset_control_binds_exact_actual_crd_and_preserves_private_lists() -> TestResult {
    for minor in [20, 37] {
        let mut input = request(&source());
        input["target_minor"] = json!(minor);
        let receipt = evaluate(&input)?;
        assert_eq!(receipt["state"], "static-assertions-passed");
        assert_eq!(receipt["custom"]["records"][0]["state"], "Bound");
        assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 1);
        assert_eq!(receipt["custom"]["records"][0]["operator_prerequisites"], 1);
        assert_eq!(receipt["custom_reprojection"], "checked");
        for marker in [
            "private-wrapper-marker",
            "private-resource-name",
            "private-body-marker",
            "/items/0",
        ] {
            assert!(!receipt.to_string().contains(marker));
        }
    }
    Ok(())
}
#[test]
fn unsupported_optional_schema_is_nonpositive_even_when_supported_subset_succeeds() -> TestResult {
    let mut body = source();
    body["items"][0]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["optional"]
        ["pattern"] = json!("private-pattern-marker");
    let mut input = request(&body);
    input["custom_assertions"][0]["check"] = json!("UnsupportedSchema");
    input["custom_assertions"][0]["positive_dependency"] = json!(false);
    input["custom_assertions"][0]["unsupported_categories"] = json!(["Pattern"]);
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "static-assertions-passed");
    assert_eq!(receipt["custom"]["records"][0]["unsupported_categories"]["Pattern"], 1);
    assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 0);
    assert_eq!(receipt["custom"]["records"][0]["supported_subset_satisfied"], true);
    assert!(!receipt.to_string().contains("private-pattern-marker"));
    Ok(())
}
#[test]
fn unsupported_schema_retains_supported_constraint_violations() -> TestResult {
    let mut body = source();
    let properties =
        &mut body["items"][0]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"];
    properties["optional"]["pattern"] = json!("private-pattern");
    properties["value"]["minimum"] = json!(4);
    let mut input = request(&body);
    let assertion = &mut input["custom_assertions"][0];
    assertion["check"] = json!("UnsupportedSchema");
    assertion["positive_dependency"] = json!(false);
    assertion["unsupported_categories"] = json!(["Pattern"]);
    assertion["issue_count"] = json!(1);
    assertion["supported_subset_satisfied"] = json!(false);
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "static-assertions-passed");
    assert_eq!(receipt["custom"]["records"][0]["issue_count"], 1);
    assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 0);
    Ok(())
}
#[test]
fn missing_and_mismatched_crds_are_explicit_and_never_positive() -> TestResult {
    let mut absent = source();
    absent["items"].as_array_mut().ok_or("items")?.remove(0);
    let mut input = expect_check(request(&absent), "MissingCrd");
    input["assertions"][0]["resource_index"] = json!(0);
    input["custom_assertions"][0]["resource_index"] = json!(0);
    input["custom_assertions"][0]["source_pointer"] = json!("/items/0");
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["custom"]["records"][0]["state"], "MissingCrd");
    assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 0);
    let mut wrong = source();
    wrong["items"][0]["spec"]["names"]["kind"] = json!("Other");
    let receipt = evaluate(&expect_check(request(&wrong), "MissingCrd"))?;
    assert_eq!(receipt["custom"]["records"][0]["state"], "MissingCrd");
    assert_eq!(receipt["custom"]["records"][0]["graph_match"], true);
    Ok(())
}
#[test]
fn ambiguous_supplied_crds_stay_distinct_from_missing() -> TestResult {
    let mut body = source();
    let mut another = body["items"][0].clone();
    another["metadata"]["name"] = json!("alternatewidgets.example.test");
    another["spec"]["names"]["plural"] = json!("alternatewidgets");
    body["items"].as_array_mut().ok_or("items")?.push(another);
    let receipt = evaluate(&expect_check(request(&body), "AmbiguousCrd"))?;
    assert_eq!(receipt["custom"]["records"][0]["state"], "AmbiguousCrd");
    assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 0);
    Ok(())
}
#[test]
fn unserved_missing_version_and_missing_schema_have_separate_outcomes() -> TestResult {
    for (change, state) in [(0, "VersionNotServed"), (1, "VersionNotListed"), (2, "MissingSchema")] {
        let mut body = source();
        match change {
            0 => body["items"][0]["spec"]["versions"][0]["served"] = json!(false),
            1 => body["items"][1]["apiVersion"] = json!("example.test/v2"),
            _ => {
                body["items"][0]["spec"]["versions"][0]
                    .as_object_mut()
                    .ok_or("version")?
                    .remove("schema");
            }
        }
        let mut input = expect_check(request(&body), state);
        if change == 1 {
            input["custom_assertions"][0]["identity"]["version"] = json!("v2");
        }
        let receipt = evaluate(&input)?;
        assert_eq!(receipt["custom"]["records"][0]["state"], state);
        assert_eq!(receipt["custom"]["records"][0]["positive_dependencies"], 0);
    }
    Ok(())
}
#[test]
fn supported_schema_violation_is_separate_from_unsupported() -> TestResult {
    let mut body = source();
    body["items"][0]["spec"]["versions"][0]["schema"]["openAPIV3Schema"]["properties"]["spec"]["properties"]["value"]
        ["minimum"] = json!(4);
    let mut input = request(&body);
    input["custom_assertions"][0]["check"] = json!("SchemaViolations");
    input["custom_assertions"][0]["positive_dependency"] = json!(false);
    input["custom_assertions"][0]["issue_count"] = json!(1);
    input["custom_assertions"][0]["supported_subset_satisfied"] = json!(false);
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "static-assertions-passed");
    assert_eq!(receipt["custom"]["records"][0]["unsupported_categories"], json!({}));
    Ok(())
}
#[test]
fn exact_source_and_version_binding_expectations_fail_independently() -> TestResult {
    for field in ["source_document", "crd_index"] {
        let mut input = request(&source());
        input["custom_assertions"][0]["binding"][field] = json!(1);
        let receipt = evaluate(&input)?;
        assert_eq!(receipt["state"], "static-assertions-failed");
        assert_eq!(receipt["custom"]["records"][0]["binding_match"], false);
    }
    let mut input = request(&source());
    input["custom_assertions"][0]["binding"]["schema_pointer"] =
        json!("/items/0/spec/versions/1/schema/openAPIV3Schema");
    assert_eq!(evaluate(&input)?["state"], "static-assertions-failed");
    Ok(())
}
#[test]
fn protected_consent_and_zero_custom_budget_never_become_success() -> TestResult {
    let mut input = request(&source());
    input["include_protected"] = json!(false);
    let denied = evaluate(&input)?;
    assert_eq!(denied["state"], "generation-refused");
    assert_eq!(denied["custom_reprojection"], "not-executed-native-refusal");
    assert!(!denied.to_string().contains("private-body-marker"));
    input["include_protected"] = json!(true);
    input["custom_processing_units"] = json!(0);
    let exhausted = evaluate(&input)?;
    assert_eq!(exhausted["state"], "processing-refused");
    assert_eq!(exhausted["custom"]["findings"]["limit-exceeded"], 1);
    Ok(())
}
#[test]
fn source_stream_coordinates_are_distinct_from_list_coordinates() -> TestResult {
    let body = source();
    let mut input = request(&body);
    input["sources"] = json!([{"format":"json","content":body["items"][0].to_string()},{"format":"json","content":body["items"][1].to_string()}]);
    input["wrapper_assertions"] = json!([]);
    let assertion = &mut input["custom_assertions"][0];
    assertion["source_id"] = json!(1);
    assertion["source_pointer"] = json!("");
    assertion["binding"]["crd_pointer"] = json!("");
    assertion["binding"]["version_pointer"] = json!("/spec/versions/0");
    assertion["binding"]["schema_pointer"] = json!("/spec/versions/0/schema/openAPIV3Schema");
    assert_eq!(evaluate(&input)?["state"], "static-assertions-passed");
    Ok(())
}
#[test]
fn current_typed_scope_edit_is_refused_before_original_binding_can_be_reused() -> TestResult {
    let bytes = source().to_string();
    let mut set = parse_source(
        SourceInput {
            id: SourceId(8),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: bytes.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "parse")?
    .flatten_resources()
    .map_err(|_| "flatten")?;
    let crd = set.documents_mut()[0]
        .resource_mut::<CustomResourceDefinitionV1>()
        .ok_or("CRD")?;
    let Presence::Value(spec) = &mut crd.spec else {
        return Err("spec".into());
    };
    spec.scope = Presence::Value("Cluster".into());
    let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37).map_err(|_| "target")?);
    let Err(refusal) = set.check_custom_documents(&target, NativeProcessingLimits::default()) else {
        return Err("edited-scope-binding-reused".into());
    };
    assert_eq!(refusal.code, FindingCode::UnsupportedSemanticConversion);
    assert_eq!(refusal.phase, Phase::Generation);
    Ok(())
}
#[test]
fn malformed_and_duplicate_assertion_requests_are_refused_without_payload() -> TestResult {
    let mut input = request(&source());
    input["custom_assertions"]
        .as_array_mut()
        .ok_or("assertions")?
        .push(assertion());
    assert_eq!(probe::evaluate(&input), Err("duplicate-custom-assertion"));
    input["custom_assertions"] = json!([]);
    assert_eq!(probe::evaluate(&input), Err("custom-assertion-budget"));
    input = request(&source());
    input["sources"][0]["content"] = json!("not-json private-marker");
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "parse-refused");
    assert!(!receipt.to_string().contains("private-marker"));
    Ok(())
}
#[cfg(target_os = "linux")]
#[test]
fn original_custom_driver_pure_contracts_are_part_of_the_gate() -> TestResult {
    let output = std::process::Command::new("/usr/bin/python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/fixtures/custom_acceptance.py"
        ))
        .arg("--self-test")
        .env_clear()
        .env("PATH", "/usr/bin:/bin")
        .env("LANG", "C.UTF-8")
        .output()
        .map_err(|_| "Python self-test unavailable")?;
    assert!(output.status.success(), "custom-driver self-test failed");
    Ok(())
}
