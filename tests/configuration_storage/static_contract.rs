//! Independent static expectations from the authenticated specification; no native execution.
use super::{TestResult, set, target};
use kubernetes_lens::{
    Finding, FindingCode, NativeValidationIntent as Intent,
    diagnostic::Severity,
    generate,
    generation::{ExplicitArtifactAccess, GenerationOptions, OutputFormat, ProtectedOutput},
    model::{AuthoredResource, ResourceSet},
    parse_source,
    processing::NativeProcessingLimits,
    resources::configuration_storage::{ConfigMap, PersistentVolumeClaim, Secret, StorageClass},
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    validate_for_target_with_intent, validate_for_target_with_limits,
};
use serde_json::{Value, json};

fn document(kind: &str) -> Value {
    json!({"apiVersion":if kind=="StorageClass" {"storage.k8s.io/v1"} else {"v1"},"kind":kind,
        "metadata":if kind=="StorageClass" {json!({"name":"sample"})} else {json!({"name":"sample","namespace":"app"})}})
}
fn claim() -> Value {
    let mut value = document("PersistentVolumeClaim");
    value["spec"] = json!({"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}});
    value
}
fn class() -> Value {
    let mut value = document("StorageClass");
    value["provisioner"] = json!("Example.COM/DRIVER");
    value
}
fn findings(value: &Value, minor: u8, intent: Intent) -> TestResult<Vec<Finding>> {
    let text = serde_json::to_string(value)?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(101),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "parse static fixture")?;
    Ok(match parsed.flatten_resources() {
        Ok(resources) => validate_for_target_with_intent(&resources, &target(minor)?, intent),
        Err(findings) => findings,
    })
}
fn accepted(value: &Value, minor: u8, intent: Intent) -> TestResult<bool> {
    Ok(!findings(value, minor, intent)?
        .iter()
        .any(|finding| finding.severity == Severity::Error))
}
fn assert_invalid(value: &Value, minor: u8, path: &str) -> TestResult<()> {
    assert!(findings(value, minor, Intent::Create)?.iter().any(|finding| {
        finding.code == FindingCode::NativeFieldInvalid
            && finding
                .path
                .as_ref()
                .is_some_and(|field| field.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == path)
    }));
    Ok(())
}
#[test]
fn configmap_key_intersection_length_and_case_are_native_checks() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = document("ConfigMap");
        value["data"] = json!({".UPPER":"","Key":"a"});
        value["binaryData"] = json!({"key":""});
        assert!(accepted(&value, minor, Intent::Create)?);
        value["binaryData"]["Key"] = json!("");
        assert_invalid(&value, minor, "/data/Key")?;
        value["binaryData"].as_object_mut().ok_or("map")?.remove("Key");
        for (count, valid) in [(253, true), (254, false)] {
            value["data"] = json!({"A".repeat(count):""});
            assert_eq!(accepted(&value, minor, Intent::Create)?, valid);
        }
    }
    Ok(())
}
#[test]
fn configmap_body_counts_utf8_and_decoded_binary_only_at_one_mib() -> TestResult<()> {
    let mut value = document("ConfigMap");
    value["data"] = json!({"long-key-does-not-count":"é".repeat(524_286)});
    value["binaryData"] = json!({"binary":"AQIDBA=="});
    for minor in [20, 37] {
        assert!(accepted(&value, minor, Intent::Create)?);
    }
    value["data"]["extra"] = json!("x");
    for minor in [20, 37] {
        assert_invalid(&value, minor, "")?;
    }
    Ok(())
}
#[test]
fn secret_effective_overlay_size_counts_each_key_once_and_retains_both_maps() -> TestResult<()> {
    let mut value = document("Secret");
    value["data"] = json!({"same":"eA=="});
    value["stringData"] = json!({"same":"","pad":"é".repeat(524_288)});
    for minor in [20, 37] {
        assert!(accepted(&value, minor, Intent::Create)?);
    }
    let resources = set(&serde_json::to_string(&value)?)?;
    let secret = resources.documents()[0].resource::<Secret>().ok_or("secret")?;
    assert_eq!(secret.data.value().ok_or("data")?.len(), 1);
    assert_eq!(secret.string_data.value().ok_or("stringData")?.len(), 2);
    value["stringData"]["extra"] = json!("x");
    for minor in [20, 37] {
        assert_invalid(&value, minor, "/data")?;
    }
    Ok(())
}
#[test]
fn secret_basic_tls_ssh_and_service_account_required_members_match_effective_data() -> TestResult<()> {
    for minor in [20, 37] {
        for kind in [
            "kubernetes.io/basic-auth",
            "kubernetes.io/tls",
            "kubernetes.io/ssh-auth",
            "kubernetes.io/service-account-token",
        ] {
            let mut value = document("Secret");
            value["type"] = json!(kind);
            assert!(!accepted(&value, minor, Intent::Create)?);
            match kind {
                "kubernetes.io/basic-auth" => {
                    for key in ["username", "password"] {
                        value["stringData"] = json!({key:""});
                        assert!(accepted(&value, minor, Intent::Create)?);
                    }
                }
                "kubernetes.io/tls" => {
                    value["stringData"] = json!({"tls.crt":"","tls.key":""});
                    assert!(accepted(&value, minor, Intent::Create)?);
                    value["stringData"].as_object_mut().ok_or("map")?.remove("tls.key");
                    assert!(!accepted(&value, minor, Intent::Create)?);
                }
                "kubernetes.io/ssh-auth" => {
                    value["data"] = json!({"ssh-privatekey":"eA=="});
                    assert!(accepted(&value, minor, Intent::Create)?);
                    value["stringData"] = json!({"ssh-privatekey":""});
                    assert_invalid(&value, minor, "/data/ssh-privatekey")?;
                }
                _ => {
                    value["metadata"]["annotations"] = json!({"kubernetes.io/service-account.name":""});
                    assert!(!accepted(&value, minor, Intent::Create)?);
                    value["metadata"]["annotations"]["kubernetes.io/service-account.name"] = json!("service");
                    assert!(accepted(&value, minor, Intent::Create)?);
                }
            }
        }
        for kind in ["", "Opaque", "custom/private", "bootstrap.kubernetes.io/token"] {
            let mut value = document("Secret");
            value["type"] = json!(kind);
            assert!(accepted(&value, minor, Intent::Create)?);
        }
    }
    Ok(())
}
#[test]
fn secret_docker_private_json_shape_and_override_have_value_free_findings() -> TestResult<()> {
    for minor in [20, 37] {
        for (kind, key) in [
            ("kubernetes.io/dockercfg", ".dockercfg"),
            ("kubernetes.io/dockerconfigjson", ".dockerconfigjson"),
        ] {
            for (text, valid) in [
                ("{}", true),
                ("null", true),
                ("[]", false),
                ("1", false),
                ("true", false),
                ("\"text\"", false),
                ("private-invalid-json", false),
                ("", false),
            ] {
                let mut value = document("Secret");
                value["type"] = json!(kind);
                value["stringData"] = json!({key:text});
                let checked = findings(&value, minor, Intent::Create)?;
                assert_eq!(
                    !checked.iter().any(|finding| finding.severity == Severity::Error),
                    valid
                );
                assert!(!format!("{checked:?}").contains("private-invalid-json"));
                let resources = set(&serde_json::to_string(&value)?)?;
                assert!(
                    !format!("{:?}", resources.documents()[0].resource::<Secret>()).contains("private-invalid-json")
                );
            }
            let mut value = document("Secret");
            value["type"] = json!(kind);
            value["data"] = json!({key:"W10="});
            value["stringData"] = json!({key:"{}"});
            assert!(accepted(&value, minor, Intent::Create)?);
        }
    }
    Ok(())
}
#[test]
fn pvc_create_requires_selected_modes_and_positive_storage_without_pod_resource_rules() -> TestResult<()> {
    for minor in [20, 37] {
        for storage in ["1Gi", "0.1", "1e-9"] {
            let mut value = claim();
            value["spec"]["resources"] =
                json!({"requests":{"storage":storage,"unrelated":"-1"},"limits":{"storage":"0.001"}});
            value["spec"]["accessModes"] = json!(["ReadWriteOnce", "ReadWriteOnce"]);
            assert!(accepted(&value, minor, Intent::Create)?);
        }
        for storage in [json!("0"), json!("-1"), Value::Null] {
            let mut value = claim();
            value["spec"]["resources"]["requests"]["storage"] = storage;
            assert_invalid(&value, minor, "/spec/resources/requests/storage")?;
        }
        let mut value = claim();
        value["spec"]["resources"] = json!({});
        assert_invalid(&value, minor, "/spec/resources/requests/storage")?;
        value = claim();
        value["spec"]["accessModes"] = json!([]);
        assert_invalid(&value, minor, "/spec/accessModes")?;
    }
    Ok(())
}
#[test]
fn pvc_class_selector_and_data_source_create_checks_have_exact_context_and_version_boundary() -> TestResult<()> {
    for minor in [20, 28, 29, 37] {
        for name in ["", "fast", "a".repeat(70).as_str()] {
            let mut value = claim();
            value["spec"]["storageClassName"] = json!(name);
            assert!(accepted(&value, minor, Intent::Create)?);
        }
        let mut value = claim();
        value["spec"]["storageClassName"] = json!("Bad_Name");
        assert_invalid(&value, minor, "/spec/storageClassName")?;
        value = claim();
        value["spec"]["selector"] = json!({});
        assert!(accepted(&value, minor, Intent::Create)?);
        value["spec"]["selector"] = json!({"matchLabels":{"qualified.example/Key":"value"},"matchExpressions":[{"key":"tier","operator":"In","values":["gold"]}]});
        assert!(accepted(&value, minor, Intent::Create)?);
        for selector in [
            json!({"matchLabels":{"bad key":"ok"}}),
            json!({"matchLabels":{"key":"bad value"}}),
            json!({"matchExpressions":[{"key":"key","operator":"Exists","values":["x"]}]}),
            json!({"matchExpressions":[{"key":"key","operator":"In","values":[]}]}),
        ] {
            value["spec"]["selector"] = selector;
            assert_invalid(&value, minor, "/spec/selector")?;
        }
        value = claim();
        value["spec"]["dataSource"] = json!({"name":"source","kind":"Custom","apiGroup":"Bad_Group"});
        assert_eq!(accepted(&value, minor, Intent::Create)?, minor < 29);
        let uncertain = findings(&value, minor, Intent::Unspecified)?;
        assert!(uncertain.iter().any(|f| f.code == FindingCode::NativeContextRequired));
        assert!(!uncertain.iter().any(|f| f.code == FindingCode::NativeFieldInvalid));
        value["spec"]["dataSource"] = json!({"name":"source","kind":"Custom","apiGroup":"custom.example"});
        assert!(accepted(&value, minor, Intent::Create)?);
        value["spec"]["dataSource"] = json!({"name":"source","kind":"Wrong"});
        assert_invalid(&value, minor, "/spec/dataSource/kind")?;
        value["spec"]["dataSource"] = json!({"name":"","kind":"PersistentVolumeClaim"});
        assert_invalid(&value, minor, "/spec/dataSource/name")?;
    }
    Ok(())
}
#[test]
fn storage_class_provisioner_and_parameter_boundaries_preserve_native_spelling() -> TestResult<()> {
    for minor in [20, 37] {
        for provisioner in ["Example.COM/DRIVER", "DRIVER", "example.com/name"] {
            let mut value = class();
            value["provisioner"] = json!(provisioner);
            assert!(accepted(&value, minor, Intent::Create)?);
        }
        let mut value = class();
        value["provisioner"] = json!("bad/name/extra");
        assert_invalid(&value, minor, "/provisioner")?;
        for (count, valid) in [(0, true), (512, true), (513, false)] {
            value = class();
            value["parameters"] = Value::Object((0..count).map(|index| (format!("key-{index}"), json!(""))).collect());
            assert_eq!(accepted(&value, minor, Intent::Create)?, valid);
        }
        value = class();
        value["parameters"] = json!({"not a qualified/key!":""});
        assert!(accepted(&value, minor, Intent::Create)?);
        value["parameters"] = json!({"":""});
        assert_invalid(&value, minor, "/parameters/")?;
        for (length, valid) in [(262_143, true), (262_144, false)] {
            value = class();
            value["parameters"] = json!({"k":"x".repeat(length)});
            assert_eq!(accepted(&value, minor, Intent::Create)?, valid);
        }
    }
    Ok(())
}
#[test]
fn storage_topology_semantics_ignore_term_and_value_order_without_label_value_restrictions() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = class();
        value["allowedTopologies"] = json!([]);
        assert!(accepted(&value, minor, Intent::Create)?);
        let one = json!({"matchLabelExpressions":[{"key":"zone","values":["arbitrary value!","other"]},{"key":"disk","values":[""]}]});
        value["allowedTopologies"] = json!([one]);
        assert!(accepted(&value, minor, Intent::Create)?);
        let duplicate = json!({"matchLabelExpressions":[{"key":"disk","values":[""]},{"key":"zone","values":["other","arbitrary value!"]}]});
        let first = value["allowedTopologies"][0].clone();
        value["allowedTopologies"] = json!([first, duplicate]);
        assert_invalid(&value, minor, "/allowedTopologies/1")?;
        for expressions in [
            json!([]),
            json!([{"key":"zone","values":[]}]),
            json!([{"key":"zone","values":["x","x"]}]),
            json!([{"key":"zone","values":["x"]},{"key":"zone","values":["y"]}]),
            json!([{"key":"bad key","values":["x"]}]),
        ] {
            value["allowedTopologies"] = json!([{"matchLabelExpressions":expressions}]);
            assert!(!accepted(&value, minor, Intent::Create)?);
        }
    }
    Ok(())
}
fn authored(resources: &ResourceSet) -> TestResult<AuthoredResource> {
    let doc = &resources.documents()[0];
    if let Some(root) = doc.resource::<ConfigMap>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<Secret>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<PersistentVolumeClaim>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<StorageClass>() {
        return Ok(root.clone().into());
    }
    Err("unexpected static kind".into())
}
#[test]
fn static_checks_apply_to_source_free_authoring_reparse_and_generation_fixed_points() -> TestResult<()> {
    let mut config = document("ConfigMap");
    config["data"] = json!({"mode":"safe"});
    config["binaryData"] = json!({"bytes":"AQID"});
    let mut secret = document("Secret");
    secret["type"] = json!("kubernetes.io/basic-auth");
    secret["stringData"] = json!({"username":""});
    for value in [config, secret, claim(), class()] {
        let supplied = set(&serde_json::to_string(&value)?)?;
        let fresh = ResourceSet::from_authored(vec![authored(&supplied)?], &target(37)?, &AuthoringLimits::default())
            .map_err(|_| "static authoring")?;
        for resources in [&supplied, &fresh] {
            for minor in [20, 37] {
                assert!(
                    !validate_for_target_with_intent(resources, &target(minor)?, Intent::Create)
                        .iter()
                        .any(|f| f.severity == Severity::Error)
                );
                let options = GenerationOptions {
                    validation_intent: Intent::Create,
                    protected_output: ProtectedOutput::Include,
                    ..GenerationOptions::default()
                };
                let artifact = generate(resources, &target(minor)?, OutputFormat::Yaml, &options)
                    .map_err(|_| "static generation")?;
                let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
                let reparsed = set(std::str::from_utf8(artifact.reveal_bytes(&access))?)?;
                let again = generate(&reparsed, &target(minor)?, OutputFormat::Yaml, &options)
                    .map_err(|_| "static regenerated")?;
                assert_eq!(artifact.reveal_bytes(&access), again.reveal_bytes(&access));
            }
        }
    }
    Ok(())
}
#[test]
fn static_checks_share_zero_and_tight_processing_limits_without_private_echo() -> TestResult<()> {
    let mut secret = document("Secret");
    secret["type"] = json!("kubernetes.io/dockerconfigjson");
    secret["stringData"] = json!({".dockerconfigjson":"{\"private-fixture\":{\"nested\":[]}}"});
    for value in [secret, class(), claim()] {
        let resources = set(&serde_json::to_string(&value)?)?;
        for limits in [
            NativeProcessingLimits {
                max_processing_units: 0,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_payload_bytes: 0,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_report_entries: 0,
                ..NativeProcessingLimits::default()
            },
        ] {
            let checked = validate_for_target_with_limits(&resources, &target(37)?, Intent::Create, &limits);
            // A report budget matters only if an ordinary finding is required.
            if limits.max_report_entries == 0 && checked.is_empty() {
                continue;
            }
            assert!(
                checked
                    .iter()
                    .any(|f| f.code == FindingCode::LimitExceeded && f.path.is_none())
            );
            assert!(!format!("{checked:?}").contains("private-fixture"));
        }
    }
    Ok(())
}

#[test]
fn invalid_static_fields_refuse_authoring_or_explicit_create_generation() -> TestResult<()> {
    let mut config = document("ConfigMap");
    config["data"] = json!({"same":""});
    config["binaryData"] = json!({"same":""});
    let mut secret = document("Secret");
    secret["type"] = json!("kubernetes.io/ssh-auth");
    secret["stringData"] = json!({"ssh-privatekey":""});
    let mut pvc = claim();
    pvc["spec"]["resources"]["requests"]["storage"] = json!("0");
    let mut storage = class();
    storage["allowedTopologies"] = json!([{}]);
    for value in [config, secret, pvc, storage] {
        let supplied = set(&serde_json::to_string(&value)?)?;
        let fresh =
            match ResourceSet::from_authored(vec![authored(&supplied)?], &target(37)?, &AuthoringLimits::default()) {
                Ok(resources) => {
                    // Construction has Unspecified intent, so PVC Create checks run below.
                    assert_eq!(value["kind"], json!("PersistentVolumeClaim"));
                    Some(resources)
                }
                Err(findings) => {
                    assert_ne!(value["kind"], json!("PersistentVolumeClaim"));
                    assert!(findings.iter().any(|f| f.code == FindingCode::NativeFieldInvalid));
                    None
                }
            };
        for resources in std::iter::once(&supplied).chain(fresh.as_ref()) {
            for minor in [20, 37] {
                assert!(
                    validate_for_target_with_intent(resources, &target(minor)?, Intent::Create)
                        .iter()
                        .any(|f| f.code == FindingCode::NativeFieldInvalid)
                );
                let options = GenerationOptions {
                    validation_intent: Intent::Create,
                    protected_output: ProtectedOutput::Include,
                    ..GenerationOptions::default()
                };
                assert!(generate(resources, &target(minor)?, OutputFormat::Yaml, &options).is_err());
            }
        }
    }
    Ok(())
}
#[test]
fn pvc_absent_null_and_unknown_neighbors_do_not_hide_known_create_errors() -> TestResult<()> {
    for minor in [20, 37] {
        for source in [
            json!({}),
            json!({"name":"source"}),
            json!({"kind":"PersistentVolumeClaim"}),
            json!({"name":null,"kind":null}),
        ] {
            let mut value = claim();
            value["spec"]["dataSource"] = source;
            assert!(!accepted(&value, minor, Intent::Create)?);
        }
        for class_name in [Value::Null, json!("")] {
            let mut value = claim();
            value["spec"]["storageClassName"] = class_name;
            assert!(accepted(&value, minor, Intent::Create)?);
        }
        let mut value = claim();
        value["spec"]["selector"] = json!({"futureSelector":{"payload":"preserved"}});
        value["spec"]["resources"]["requests"]["storage"] = json!("0");
        assert_invalid(&value, minor, "/spec/resources/requests/storage")?;
        value["spec"] = Value::Null;
        assert_invalid(&value, minor, "/spec")?;
    }
    Ok(())
}
