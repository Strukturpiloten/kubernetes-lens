//! Independent positive/refusal contracts for the bounded official-source driver.
#[path = "../examples/official_native_probe.rs"]
mod probe;
use serde_json::{Value, json};

type TestResult = Result<(), Box<dyn std::error::Error>>;
fn request(content: &str) -> Value {
    json!({"schema_version":1,"binding":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        "target_minor":37,"documented_gate_defaults":true,"namespace":"fixture-native",
        "preserve_unknown":true,"include_protected":true,"max_input_bytes":8_388_608,
        "sources":[{"format":"yaml","content":content}],
        "assertions":[{"resource_index":0,"pointer":"/metadata/name","equals":"settings","selected_builtin_codec":true}],
        "graph_assertions":[], "wrapper_assertions":[]})
}
fn evaluate(request: &Value) -> Result<Value, Box<dyn std::error::Error>> {
    probe::evaluate(request).map_err(|code| std::io::Error::other(code).into())
}
const CONFIG: &str = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings}\ndata: {mode: native}\n";
#[test]
fn native_json_yaml_determinism_and_typed_fields() -> TestResult {
    let mut input = request(CONFIG);
    input["assertions"] =
        json!([{"resource_index":0,"pointer":"/data/mode","equals":"native","selected_builtin_codec":true}]);
    for minor in [20, 37] {
        input["target_minor"] = json!(minor);
        let receipt = evaluate(&input)?;
        assert_eq!(receipt["state"], "static-assertions-passed");
        assert_eq!(receipt["selected_builtin_codecs"], 1);
        assert_eq!(receipt["reprojection_failures"], 0);
        assert_eq!(receipt["api"], "pending");
        assert_eq!(receipt["runtime"], "pending");
    }
    Ok(())
}
#[test]
fn native_json_list_and_unknown_wrapper_payload_are_retained() -> TestResult {
    let mut input = request("");
    input["sources"][0] = json!({"format":"json","content":r#"{"apiVersion":"v1","kind":"List","metadata":{"resourceVersion":"99"},"vendorWrapper":{"marker":"private-wrapper"},"items":[{"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings"},"vendor":{"exact":"private-unknown"}}]}"#});
    input["assertions"] = json!([{"resource_index":0,"pointer":"/vendor/exact","equals":"private-unknown"}]);
    input["wrapper_assertions"] = json!([{"wrapper_index":0,"pointer":"/vendorWrapper/marker","equals":"private-wrapper"}, {"wrapper_index":0,"pointer":"/metadata/resourceVersion","equals":"99"}]);
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "static-assertions-passed");
    assert_eq!(receipt["default_generation"]["state"], "refused");
    assert!(
        receipt["generation_findings"]["unadmitted-field"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(!receipt.to_string().contains("private-wrapper"));
    assert!(!receipt.to_string().contains("private-unknown"));
    Ok(())
}
#[test]
fn unknown_fields_require_selected_preservation_and_keep_findings() -> TestResult {
    let text = "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings}\nvendor: {token: source-private}\n";
    let mut input = request(text);
    input["assertions"] = json!([{"resource_index":0,"pointer":"/vendor/token","equals":"source-private"}]);
    input["preserve_unknown"] = json!(false);
    let denied = evaluate(&input)?;
    assert_eq!(denied["state"], "generation-refused");
    input["preserve_unknown"] = json!(true);
    let preserved = evaluate(&input)?;
    assert_eq!(preserved["state"], "static-assertions-passed");
    assert_eq!(preserved["opaque_preservation"], "selected-unadmitted-source");
    assert!(
        preserved["default_generation"]["findings"]["opaque-output-denied"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    assert!(!preserved.to_string().contains("source-private"));
    Ok(())
}
#[test]
fn protected_output_requires_separate_consent() -> TestResult {
    let mut input = request(
        "apiVersion: v1\nkind: Secret\nmetadata: {name: settings}\nstringData: {password: private-secret-marker}\n",
    );
    input["assertions"] = json!([{"resource_index":0,"pointer":"/stringData/password","equals":"private-secret-marker","selected_builtin_codec":true}]);
    input["include_protected"] = json!(false);
    let denied = evaluate(&input)?;
    assert_eq!(denied["state"], "generation-refused");
    assert!(
        denied["generation_findings"]["protected-output-denied"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    input["include_protected"] = json!(true);
    let included = evaluate(&input)?;
    assert_eq!(included["state"], "static-assertions-passed");
    assert_eq!(included["default_generation"]["state"], "refused");
    assert!(!included.to_string().contains("private-secret-marker"));
    Ok(())
}
#[test]
fn independent_field_expectations_fail_even_when_roundtrip_succeeds() -> TestResult {
    let mut input = request(CONFIG);
    input["assertions"][0]["equals"] = json!("incorrect-independent-name");
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "static-assertions-failed");
    assert_eq!(receipt["field_failures"], 1);
    assert_eq!(receipt["reprojection_failures"], 0);
    Ok(())
}
#[test]
fn source_indices_are_reconciled_with_sorted_generated_identities() -> TestResult {
    let mut input = request(
        "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: z-last}\ndata: {order: first-source}\n---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: a-first}\ndata: {order: second-source}\n",
    );
    input["assertions"] = json!([{"resource_index":0,"pointer":"/data/order","equals":"first-source"},{"resource_index":1,"pointer":"/data/order","equals":"second-source"}]);
    assert_eq!(evaluate(&input)?["state"], "static-assertions-passed");
    Ok(())
}
#[test]
fn supplied_graph_expectation_checks_actual_edge_and_missing_target() -> TestResult {
    let mut input = request(
        "apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: supplied}\n---\napiVersion: v1\nkind: Pod\nmetadata: {name: settings}\nspec: {serviceAccountName: supplied, containers: [{name: app, image: example.invalid/app:v1}]}\n",
    );
    input["assertions"] =
        json!([{"resource_index":1,"pointer":"/metadata/name","equals":"settings","selected_builtin_codec":true}]);
    input["graph_assertions"] = json!([{"resource_index":1,"path":"/spec/serviceAccountName","resolution":"resolved-subjects","count":1,"target_indices":[0],"subject_kind":"object"}]);
    let positive = evaluate(&input)?;
    assert_eq!(positive["state"], "static-assertions-passed");
    input["graph_assertions"][0]["count"] = json!(2);
    let wrong = evaluate(&input)?;
    assert_eq!(wrong["state"], "static-assertions-failed");
    assert_eq!(wrong["graph_failures"], 1);
    input["sources"][0]["content"] = json!(
        "apiVersion: v1\nkind: Pod\nmetadata: {name: settings}\nspec: {serviceAccountName: absent, containers: [{name: app, image: example.invalid/app:v1}]}\n"
    );
    input["assertions"][0]["resource_index"] = json!(0);
    input["graph_assertions"][0] = json!({"resource_index":0,"path":"/spec/serviceAccountName","resolution":"missing"});
    assert_eq!(evaluate(&input)?["state"], "static-assertions-passed");
    Ok(())
}
#[test]
fn unavailable_api_is_never_relabelled_or_reported_as_success() -> TestResult {
    let mut input = request(
        "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: settings}\nspec: {schedule: '0 * * * *', jobTemplate: {spec: {template: {spec: {restartPolicy: Never, containers: [{name: app, image: example.invalid/app:v1}]}}}}}\n",
    );
    input["target_minor"] = json!(20);
    let receipt = evaluate(&input)?;
    assert_eq!(receipt["state"], "generation-refused");
    assert!(
        receipt["generation_findings"]["unavailable-api"]
            .as_u64()
            .is_some_and(|count| count > 0)
    );
    Ok(())
}
#[test]
fn malformed_duplicate_and_budget_inputs_do_not_become_skips() -> TestResult {
    for content in [
        "metadata: [",
        "apiVersion: v1\nkind: ConfigMap\nkind: Secret\nmetadata: {name: settings}\n",
    ] {
        let receipt = evaluate(&request(content))?;
        assert_eq!(receipt["state"], "parse-refused");
        assert!(receipt.get("field_failures").is_none());
    }
    let mut input = request(CONFIG);
    input["max_input_bytes"] = json!(1);
    assert_eq!(probe::evaluate(&input).err(), Some("request-budget"));
    input["max_input_bytes"] = json!(8_388_609);
    assert_eq!(probe::evaluate(&input).err(), Some("invalid-budget"));
    Ok(())
}
#[test]
fn profiles_and_explicit_options_are_finite() {
    for minor in [19, 38, 256] {
        let mut input = request(CONFIG);
        input["target_minor"] = json!(minor);
        assert_eq!(probe::evaluate(&input).err(), Some("invalid-target"));
    }
    for key in [
        "namespace",
        "preserve_unknown",
        "include_protected",
        "max_input_bytes",
        "documented_gate_defaults",
    ] {
        let mut input = request(CONFIG);
        if let Some(object) = input.as_object_mut() {
            object.remove(key);
        }
        assert!(probe::evaluate(&input).is_err());
    }
    let mut input = request(CONFIG);
    input["documented_gate_defaults"] = json!(false);
    assert_eq!(probe::evaluate(&input).err(), Some("explicit-gate-profile-required"));
}

#[test]
fn namespace_context_is_explicit_and_never_copied_into_source_metadata() -> TestResult {
    let mut input = request("apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: supplied, namespace: alpha}\n");
    input["sources"] = json!([
        {"format":"yaml","content":"apiVersion: v1\nkind: ServiceAccount\nmetadata: {name: supplied, namespace: alpha}\n"},
        {"format":"json","content":r#"{"apiVersion":"v1","kind":"Pod","metadata":{"name":"settings"},"spec":{"serviceAccountName":"supplied","containers":[{"name":"app","image":"example.invalid/app:v1"}]}}"#}
    ]);
    input["namespace"] = json!("alpha");
    input["assertions"] = json!([{"resource_index":1,"pointer":"/metadata/name","equals":"settings"}]);
    input["graph_assertions"] = json!([{"resource_index":1,"path":"/spec/serviceAccountName","resolution":"resolved-subjects","count":1,"target_indices":[0],"subject_kind":"object"}]);
    assert_eq!(evaluate(&input)?["state"], "static-assertions-passed");
    input["namespace"] = json!("beta");
    assert_eq!(evaluate(&input)?["state"], "static-assertions-failed");
    input["graph_assertions"] = json!([{"resource_index":1,"path":"/spec/serviceAccountName","resolution":"missing"}]);
    assert_eq!(evaluate(&input)?["state"], "static-assertions-passed");
    Ok(())
}

// The fixture harness requires Linux memfd/procfs and is unavailable on other platforms.
// This guard does not constitute a skipped native compatibility success.
#[cfg(target_os = "linux")]
#[test]
fn original_python_driver_pure_contracts_are_part_of_the_gate() -> TestResult {
    let output = std::process::Command::new("/usr/bin/python3")
        .arg(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/scripts/fixtures/native_acceptance.py"
        ))
        .arg("--self-test")
        .env_clear()
        .env("LANG", "C")
        .env("LC_ALL", "C")
        .env("TZ", "UTC")
        .env("PYTHONDONTWRITEBYTECODE", "1")
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()?;
    if !output.status.success() {
        return Err(std::io::Error::other("original Python driver pure contracts failed").into());
    }
    Ok(())
}
