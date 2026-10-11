//! Independently authored finite boundary controls; no server/runtime conformance claim.
use kubernetes_lens::{
    FindingCode,
    capability::{FeatureGateId, FeatureGateState, KubernetesVersion, TargetProfile},
    diagnostic::{Finding, Phase, Severity},
    generation::{self, GenerationOptions, NativeValidationIntent, OutputFormat},
    model::ResourceSet,
    parse_source,
    resources::networking::Service,
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::{IntOrString, Presence},
};
use serde_json::{Value, json};
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn target(minor: u8) -> Result<TargetProfile, Box<dyn std::error::Error>> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn set(value: &Value) -> Result<ResourceSet, Box<dyn std::error::Error>> {
    let bytes = serde_json::to_vec(value)?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(9),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "finite source parsing failed")?;
    parsed
        .flatten_resources()
        .map_err(|_| "finite native decoding failed".into())
}
fn pod() -> Value {
    json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"finite","namespace":"ns"},"spec":{"containers":[{"name":"main","image":"image"}]}})
}
fn service(port: &Value) -> Value {
    json!({"apiVersion":"v1","kind":"Service","metadata":{"name":"finite","namespace":"ns"},"spec":{"ports":[{"port":80,"targetPort":port}]}})
}
fn records(value: &Value, minor: u8) -> Result<Vec<Finding>, Box<dyn std::error::Error>> {
    Ok(generation::validate_for_target(&set(value)?, &target(minor)?))
}
fn has(findings: &[Finding], code: FindingCode, path: &str, severity: Severity, phase: Phase) -> bool {
    findings.iter().any(|finding| {
        finding.code == code
            && finding.severity == severity
            && finding.phase == phase
            && finding
                .path
                .as_ref()
                .is_some_and(|actual| actual.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == path)
    })
}
fn invalid(findings: &[Finding], path: &str) -> bool {
    has(
        findings,
        FindingCode::NativeFieldInvalid,
        path,
        Severity::Error,
        Phase::Validation,
    )
}
fn context(findings: &[Finding], path: &str) -> bool {
    has(
        findings,
        FindingCode::NativeContextRequired,
        path,
        Severity::Warning,
        Phase::Validation,
    )
}

fn assert_int_or_string_wire_failures() -> TestResult {
    for bad in [
        json!(2_147_483_648i64),
        json!(-2_147_483_649i64),
        json!(true),
        json!(null),
        json!(1.5),
        json!({}),
    ] {
        let bytes = serde_json::to_vec(&service(&bad))?;
        let parsed = parse_source(
            SourceInput {
                id: SourceId(9),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: &bytes,
            },
            &ParseLimits::default(),
        )
        .map_err(|_| "parse")?;
        let errors = parsed.flatten_resources().err().ok_or("shape accepted")?;
        assert!(has(
            &errors,
            FindingCode::MalformedDocument,
            "/spec/ports/0/targetPort",
            Severity::Error,
            Phase::Decoding
        ));
        let text = std::str::from_utf8(&bytes)?;
        let value_start = text.find("\"targetPort\":").ok_or("targetPort token")? + "\"targetPort\":".len();
        assert!(errors.iter().any(|finding| {
            finding.code == FindingCode::MalformedDocument
                && finding
                    .source
                    .is_some_and(|position| position.byte_offset == value_start as u64)
        }));
    }
    Ok(())
}

#[test]
fn int_or_string_wire_and_authored_boundaries_preserve_discriminants() -> TestResult {
    assert_int_or_string_wire_failures()?;
    for value in [i64::from(i32::MIN), i64::from(i32::MAX)] {
        let resources = set(&service(&json!(value)))?;
        let native = resources.documents()[0]
            .resource::<Service>()
            .ok_or("service extrema")?;
        let port = native
            .spec
            .value()
            .and_then(|spec| spec.ports.value())
            .and_then(|ports| ports.first())
            .ok_or("port extrema")?;
        assert!(matches!(port.target_port.value(),Some(IntOrString::Int(actual)) if *actual == value));
        assert!(invalid(
            &generation::validate_for_target(&resources, &target(37)?),
            "/spec/ports/0/targetPort"
        ));
    }
    assert!(
        !records(&service(&json!(8080)), 37)?
            .iter()
            .any(|finding| finding.severity == Severity::Error)
    );
    let named = set(&service(&json!("8080")))?;
    let native = named.documents()[0].resource::<Service>().ok_or("service")?;
    let port = native
        .spec
        .value()
        .and_then(|spec| spec.ports.value())
        .and_then(|ports| ports.first())
        .ok_or("port")?;
    assert!(matches!(port.target_port.value(), Some(IntOrString::String(value)) if value == "8080"));
    assert!(invalid(
        &generation::validate_for_target(&named, &target(37)?),
        "/spec/ports/0/targetPort"
    ));
    let mut resources = set(&service(&json!(8080)))?;
    let native = resources.documents_mut()[0]
        .resource_mut::<Service>()
        .ok_or("service")?;
    let Presence::Value(spec) = &mut native.spec else {
        return Err("spec".into());
    };
    let Presence::Value(ports) = &mut spec.ports else {
        return Err("ports".into());
    };
    ports[0].target_port = Presence::Value(IntOrString::Int(2_147_483_648));
    let authored = native.clone();
    assert!(invalid(
        &generation::validate_for_target(&resources, &target(37)?),
        "/spec/ports/0/targetPort"
    ));
    assert!(
        generation::generate(
            &resources,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions::default()
        )
        .is_err()
    );
    let errors = ResourceSet::from_authored(vec![authored.into()], &target(37)?, &AuthoringLimits::default())
        .err()
        .ok_or("authored accepted")?;
    assert!(has(
        &errors,
        FindingCode::NativeFieldInvalid,
        "/spec/ports/0/targetPort",
        Severity::Error,
        Phase::Generation
    ));
    assert!(
        errors
            .iter()
            .all(|finding| finding.source.is_none() && finding.phase != Phase::Decoding)
    );
    Ok(())
}

#[test]
fn container_run_as_group_uses_its_own_gate_and_exact_version_context() -> TestResult {
    let mut value = pod();
    value["spec"]["containers"][0]["securityContext"] = json!({"runAsGroup":0});
    let resources = set(&value)?;
    for minor in [20, 21, 22, 23, 37] {
        assert!(
            !generation::validate_for_target(&resources, &target(minor)?)
                .iter()
                .any(|finding| finding.code == FindingCode::FeatureGateRequired)
        );
    }
    let mut disabled = target(20)?;
    disabled
        .feature_gates
        .states
        .insert(FeatureGateId::RunAsGroup, FeatureGateState::Disabled);
    let findings = generation::validate_for_target(&resources, &disabled);
    assert!(has(
        &findings,
        FindingCode::FeatureGateRequired,
        "/spec/containers/0/securityContext/runAsGroup",
        Severity::Error,
        Phase::Validation
    ));
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.code == FindingCode::FeatureGateRequired)
            .count(),
        1
    );
    let record = findings
        .iter()
        .find(|finding| finding.code == FindingCode::FeatureGateRequired)
        .ok_or("gate record")?;
    assert_eq!(record.resource, Some(resources.documents()[0].id()));
    assert!(record.wrapper.is_none() && record.source.is_none());
    let mut unresolved = target(20)?;
    unresolved
        .feature_gates
        .states
        .insert(FeatureGateId::RunAsGroup, FeatureGateState::Unknown);
    assert!(has(
        &generation::validate_for_target(&resources, &unresolved),
        FindingCode::FeatureGateRequired,
        "/spec/containers/0/securityContext/runAsGroup",
        Severity::Error,
        Phase::Validation
    ));
    let mut removed = target(23)?;
    removed
        .feature_gates
        .states
        .insert(FeatureGateId::RunAsGroup, FeatureGateState::Enabled);
    assert!(
        generation::validate_for_target(&resources, &removed)
            .iter()
            .any(|finding| finding.code == FindingCode::InvalidTargetProfile)
    );
    Ok(())
}

#[test]
fn metadata_bytes_security_groups_and_static_nonroot_do_not_infer_runtime() -> TestResult {
    let mut value = pod();
    value["metadata"]["annotations"] = json!({"a":format!("{}x","é".repeat(131_071))});
    assert!(!invalid(&records(&value, 37)?, "/metadata/annotations/a"));
    value["metadata"]["annotations"]["a"] = json!(format!("{}xx", "é".repeat(131_071)));
    assert!(invalid(&records(&value, 37)?, "/metadata/annotations/a"));
    value["metadata"]["annotations"] = json!({"example.org/note":"arbitrary annotation text"});
    value["metadata"]["labels"] = json!({"bad key":"value"});
    assert!(invalid(&records(&value, 37)?, "/metadata/labels/bad key"));
    value["metadata"]["labels"] = json!({"valid":"ok"});
    value["spec"]["securityContext"] = json!({"runAsUser":-1,"supplementalGroups":[0,-1,i64::MAX]});
    value["spec"]["containers"][0]["securityContext"] = json!({"runAsUser":0,"runAsNonRoot":true});
    let findings = records(&value, 37)?;
    assert!(invalid(&findings, "/spec/securityContext/runAsUser"));
    assert!(invalid(&findings, "/spec/securityContext/supplementalGroups/1"));
    value["spec"]["securityContext"]["runAsUser"] = json!(1);
    value["spec"]["securityContext"]["supplementalGroups"] = json!([0, i64::MAX]);
    assert!(!records(&value, 37)?.iter().any(|finding| matches!(
        finding.code,
        FindingCode::NativeFieldInvalid | FindingCode::NativeContextRequired
    )));
    Ok(())
}

#[test]
fn exact_container_quantity_ordering_and_domains_are_separate() -> TestResult {
    let mut value = pod();
    for (request, limit) in [("100m", "0.1"), ("9223372036854775807", "9223372036854775807")] {
        value["spec"]["containers"][0]["resources"] =
            json!({"requests":{"cpu":request,"memory":"100Mi"},"limits":{"cpu":limit,"memory":"200Mi"}});
        assert!(!records(&value, 37)?.iter().any(|finding| matches!(
            finding.code,
            FindingCode::NativeFieldInvalid | FindingCode::NativeContextRequired
        )));
    }
    value["spec"]["containers"][0]["resources"] = json!({"requests":{"cpu":"200m"},"limits":{"cpu":"100m"}});
    let findings = records(&value, 37)?;
    assert!(invalid(&findings, "/spec/containers/0/resources/requests/cpu"));
    assert!(
        generation::generate(
            &set(&value)?,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions::default()
        )
        .is_err()
    );
    for quantity in ["0.0001", "9223372036854775808", "1n"] {
        value["spec"]["containers"][0]["resources"] = json!({"requests":{"cpu":quantity}});
        assert!(context(
            &records(&value, 37)?,
            "/spec/containers/0/resources/requests/cpu"
        ));
    }
    value["spec"]["containers"][0]["resources"] = json!({"requests":{"cpu":"200m"}});
    assert!(!invalid(
        &records(&value, 37)?,
        "/spec/containers/0/resources/requests/cpu"
    ));
    Ok(())
}

#[test]
fn every_admitted_container_port_name_is_unique_in_its_pod() -> TestResult {
    let mut value = pod();
    value["spec"]["containers"][0]["ports"] = json!([{"name":"http","containerPort":8080}]);
    value["spec"]["initContainers"] =
        json!([{"name":"init-a","image":"image","ports":[{"name":"http","containerPort":8081}]}]);
    assert!(invalid(&records(&value, 37)?, "/spec/initContainers/0/ports/0/name"));
    value["spec"]["containers"][0]["ports"] = json!([]);
    value["spec"]["initContainers"] = json!([
        {"name":"init-a","image":"image","ports":[{"name":"http","containerPort":8081}]},
        {"name":"init-b","image":"image","ports":[{"name":"http","containerPort":8082}]}
    ]);
    assert!(invalid(&records(&value, 37)?, "/spec/initContainers/1/ports/0/name"));
    let mut other = value.clone();
    other["metadata"]["name"] = json!("other");
    value["spec"]["initContainers"] = json!([]);
    other["spec"]["initContainers"] = json!([]);
    value["spec"]["containers"][0]["ports"] = json!([{"name":"http","containerPort":8080}]);
    other["spec"]["containers"][0]["ports"] = json!([{"name":"http","containerPort":8080}]);
    let findings = records(&json!({"apiVersion":"v1","kind":"List","items":[value,other]}), 37)?;
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}

#[test]
fn native_duplicate_predicates_survive_separate_projection_refusals() -> TestResult {
    let mut containers = pod();
    containers["spec"]["containers"] = json!([{"name":"same","image":"image"},{"name":"same","image":"image"}]);
    assert!(invalid(&records(&containers, 37)?, "/spec/containers/1/name"));
    let mut volumes = pod();
    volumes["spec"]["volumes"] = json!([{"name":"same","emptyDir":{}},{"name":"same","emptyDir":{}}]);
    assert!(invalid(&records(&volumes, 37)?, "/spec/volumes/1/name"));
    let mut ports = pod();
    ports["spec"]["containers"][0]["ports"] =
        json!([{"name":"http","containerPort":8080},{"name":"http","containerPort":8080}]);
    assert!(invalid(&records(&ports, 37)?, "/spec/containers/0/ports/1/name"));
    let mut mounts = pod();
    mounts["spec"]["volumes"] = json!([{"name":"data","emptyDir":{}}]);
    mounts["spec"]["containers"][0]["volumeMounts"] =
        json!([{"name":"data","mountPath":"/data"},{"name":"data","mountPath":"/data"}]);
    let resources = set(&mounts)?;
    let findings = generation::validate_for_target(&resources, &target(37)?);
    assert!(invalid(&findings, "/spec/containers/0/volumeMounts/1/mountPath"));
    assert!(
        findings
            .iter()
            .filter(|finding| finding.code == FindingCode::NativeFieldInvalid)
            .all(|finding| finding.resource == Some(resources.documents()[0].id()) && finding.source.is_none())
    );
    mounts["spec"]["containers"][0]["volumeMounts"][1]["mountPath"] = json!("/other");
    assert!(
        !records(&mounts, 37)?
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    let mut svc = service(&json!(8080));
    svc["spec"]["ports"] =
        json!([{"name":"one","port":80,"targetPort":8080},{"name":"two","port":80,"protocol":"TCP","targetPort":8081}]);
    let findings = records(&svc, 37)?;
    assert!(has(
        &findings,
        FindingCode::MergeConflict,
        "/spec/ports",
        Severity::Error,
        Phase::Generation
    ));
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}

#[test]
fn admitted_templates_share_finite_rules_but_keep_separate_port_domains() -> TestResult {
    let mut template = pod();
    template["metadata"] = json!({"labels":{"app":"finite"}});
    template["spec"]["containers"][0]["ports"] = json!([{"name":"http","containerPort":8080}]);
    template["spec"]["initContainers"] = json!([{"name":"init","image":"image","ports":[{"name":"http","containerPort":8081}],"securityContext":{"runAsGroup":0}}]);
    let deployment = json!({"apiVersion":"apps/v1","kind":"Deployment","metadata":{"name":"one","namespace":"ns"},
        "spec":{"selector":{"matchLabels":{"app":"finite"}},"template":{"metadata":template["metadata"],"spec":template["spec"]}}});
    assert!(invalid(
        &records(&deployment, 37)?,
        "/spec/template/spec/initContainers/0/ports/0/name"
    ));
    let mut disabled = target(20)?;
    disabled
        .feature_gates
        .states
        .insert(FeatureGateId::RunAsGroup, FeatureGateState::Disabled);
    assert!(has(
        &generation::validate_for_target(&set(&deployment)?, &disabled),
        FindingCode::FeatureGateRequired,
        "/spec/template/spec/initContainers/0/securityContext/runAsGroup",
        Severity::Error,
        Phase::Validation
    ));
    let cron = json!({"apiVersion":"batch/v1","kind":"CronJob","metadata":{"name":"cron","namespace":"ns"},
        "spec":{"schedule":"0 * * * *","jobTemplate":{"spec":{"template":{"metadata":template["metadata"],"spec":template["spec"]}}}}});
    assert!(invalid(
        &records(&cron, 37)?,
        "/spec/jobTemplate/spec/template/spec/initContainers/0/ports/0/name"
    ));
    let mut first = deployment.clone();
    first["spec"]["template"]["spec"]["initContainers"] = json!([]);
    let mut second = first.clone();
    second["metadata"]["name"] = json!("two");
    assert!(
        !records(&json!({"apiVersion":"v1","kind":"List","items":[first,second]}), 37)?
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}

#[test]
fn empty_unadmitted_boundaries_are_warnings_and_do_not_authorize_default_output() -> TestResult {
    for boundary in [json!({}), json!([]), json!({"nested":{"private":"marker"}})] {
        let mut value = pod();
        value["spec"]["vendorFuture"] = boundary;
        let resources = set(&value)?;
        let findings = generation::validate_for_target(&resources, &target(37)?);
        assert!(has(
            &findings,
            FindingCode::UnadmittedField,
            "/spec/vendorFuture",
            Severity::Warning,
            Phase::Validation
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.path.as_ref().is_some_and(|path| path.depth() > 2))
        );
        let errors = generation::generate(
            &resources,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions::default(),
        )
        .err()
        .ok_or("default opaque output accepted")?;
        assert!(
            errors
                .iter()
                .any(|finding| finding.code == FindingCode::OpaqueOutputDenied && finding.phase == Phase::Generation)
        );
    }
    let mut admitted = pod();
    admitted["metadata"]["labels"] = json!({"example.org/app":"finite"});
    admitted["metadata"]["annotations"] = json!({"example.org/note":"arbitrary"});
    assert!(
        !records(&admitted, 37)?
            .iter()
            .any(|finding| finding.code == FindingCode::UnadmittedField)
    );
    let mut nested = pod();
    nested["spec"]["vendorFuture"] = json!({});
    let findings = records(&json!({"apiVersion":"v1","kind":"List","items":[nested]}), 37)?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::UnadmittedField
                && finding.resource.is_some()
                && finding.wrapper.is_some()
                && finding.source.is_none())
    );
    Ok(())
}

#[test]
fn drop_lists_mount_versions_env_ambiguity_and_configmap_corners_remain_distinct() -> TestResult {
    let mut value = pod();
    value["spec"]["containers"][0]["securityContext"] = json!({"capabilities":{"drop":["ALL","ALL"]}});
    assert!(!context(
        &records(&value, 37)?,
        "/spec/containers/0/securityContext/capabilities/drop/1"
    ));
    value["spec"]["containers"][0]["securityContext"]["capabilities"]["drop"] = json!(["", "UNREVIEWED"]);
    assert!(context(
        &records(&value, 37)?,
        "/spec/containers/0/securityContext/capabilities/drop/0"
    ));
    value["spec"]["volumes"] = json!([{"name":"data","emptyDir":{}}]);
    value["spec"]["containers"][0]["volumeMounts"] = json!([{"name":"data","mountPath":"/a:b"}]);
    assert!(invalid(
        &records(&value, 20)?,
        "/spec/containers/0/volumeMounts/0/mountPath"
    ));
    assert!(context(
        &records(&value, 37)?,
        "/spec/containers/0/volumeMounts/0/mountPath"
    ));
    let mut env = pod();
    env["spec"]["containers"][0]["env"] =
        json!([{"name":"MODE","value":"private-finite-marker"},{"name":"MODE","value":"same"}]);
    let findings = records(&env, 37)?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::MergeConflict)
    );
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    assert!(!format!("{findings:?}").contains("private-finite-marker"));
    for key in [".", "..", "..prefix"] {
        let cm = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"finite"},"data":{key:"private-finite-marker"}});
        assert!(context(&records(&cm, 37)?, &format!("/data/{key}")));
    }
    let cm = json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"finite"},"data":{".UPPER":"value"}});
    assert!(!context(&records(&cm, 37)?, "/data/.UPPER"));
    Ok(())
}

#[test]
fn identity_groups_and_budget_refusal_keep_complete_native_facets() -> TestResult {
    let value = pod();
    let mut second = pod();
    second["metadata"]["name"] = json!("second");
    let mut third = pod();
    third["metadata"]["name"] = json!("third");
    let mut resources = set(&json!({"apiVersion":"v1","kind":"List","items":[value,second,third]}))?;
    for document in resources.documents_mut() {
        let native = document
            .resource_mut::<kubernetes_lens::resources::workloads::Pod>()
            .ok_or("pod")?;
        let Presence::Value(metadata) = &mut native.metadata else {
            return Err("metadata".into());
        };
        metadata.name = Presence::Value("same".to_owned());
    }
    let findings = generation::validate_for_target(&resources, &target(37)?);
    for document in resources.documents() {
        assert_eq!(
            findings
                .iter()
                .filter(
                    |finding| finding.code == FindingCode::DuplicateIdentity && finding.resource == Some(document.id())
                )
                .count(),
            1
        );
    }
    assert!(has(
        &findings,
        FindingCode::DuplicateIdentity,
        "/metadata",
        Severity::Error,
        Phase::Validation
    ));
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_processing_units: 1,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(37)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
    );
    let mut invalid_name = pod();
    invalid_name["metadata"]["name"] = json!("INVALID");
    assert!(has(
        &records(&invalid_name, 37)?,
        FindingCode::InvalidIdentity,
        "/metadata/name",
        Severity::Error,
        Phase::Validation
    ));
    Ok(())
}

#[test]
fn first_duplicate_identity_keeps_target_facets_when_report_slots_exhaust() -> TestResult {
    let first = pod();
    let mut second = pod();
    second["metadata"]["name"] = json!("second");
    let mut resources = set(&json!({"apiVersion":"v1","kind":"List","items":[first,second]}))?;
    for document in resources.documents_mut() {
        let native = document
            .resource_mut::<kubernetes_lens::resources::workloads::Pod>()
            .ok_or("pod")?;
        let Presence::Value(metadata) = &mut native.metadata else {
            return Err("metadata".into());
        };
        metadata.name = Presence::Value("same".to_owned());
    }
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_report_entries: 1,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(37)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert_eq!(findings.len(), 2);
    let duplicate = findings
        .iter()
        .find(|finding| finding.code == FindingCode::DuplicateIdentity)
        .ok_or("retained duplicate")?;
    assert_eq!(duplicate.severity, Severity::Error);
    assert_eq!(duplicate.phase, Phase::Validation);
    assert_eq!(duplicate.resource, Some(resources.documents()[0].id()));
    assert!(duplicate.source.is_none() && duplicate.wrapper.is_none());
    assert_eq!(
        duplicate
            .path
            .as_ref()
            .ok_or("metadata path")?
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "/metadata"
    );
    let terminal = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].phase, Phase::Validation);
    assert_eq!(terminal[0].severity, Severity::Error);
    assert!(
        terminal[0].path.is_none()
            && terminal[0].resource.is_none()
            && terminal[0].wrapper.is_none()
            && terminal[0].source.is_none()
    );
    let analysis = resources.identity_findings();
    assert_eq!(analysis.len(), 2);
    assert!(
        analysis
            .iter()
            .all(|finding| finding.code == FindingCode::DuplicateIdentity
                && finding.phase == Phase::Analysis
                && finding.path.is_none())
    );
    Ok(())
}

#[test]
fn retained_wrapper_validation_has_no_position_when_report_slots_exhaust() -> TestResult {
    let resources = set(&json!({"apiVersion":"v1","kind":"List","items":[
        {"apiVersion":"batch/v1","kind":"CronJobList","items":[]},
        {"apiVersion":"batch/v1","kind":"CronJobList","items":[]}
    ]}))?;
    let first = resources.lists().get(1).ok_or("first typed wrapper")?;
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_report_entries: 1,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(20)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert_eq!(findings.len(), 2);
    let unavailable = findings
        .iter()
        .find(|finding| finding.code == FindingCode::UnavailableApi)
        .ok_or("retained wrapper finding")?;
    assert_eq!(unavailable.phase, Phase::Validation);
    assert_eq!(unavailable.severity, Severity::Error);
    assert!(unavailable.resource.is_none() && unavailable.source.is_none());
    let wrapper = unavailable.wrapper.ok_or("wrapper association")?;
    assert_eq!(wrapper.list, first.id());
    assert_eq!(wrapper.source, first.source());
    assert_eq!(unavailable.path.as_ref().ok_or("root wrapper path")?.depth(), 0);
    let terminal = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].phase, Phase::Validation);
    assert!(
        terminal[0].path.is_none()
            && terminal[0].source.is_none()
            && terminal[0].wrapper.is_none()
            && terminal[0].resource.is_none()
    );
    Ok(())
}

#[test]
fn retained_wrapper_field_validation_has_no_position_when_report_slots_exhaust() -> TestResult {
    let resources = set(&json!({"apiVersion":"v1","kind":"List","items":[
        {"apiVersion":"batch/v1","kind":"CronJobList","metadata":{"generateName":"cron-"},"items":[]},
        {"apiVersion":"batch/v1","kind":"CronJobList","items":[]}
    ]}))?;
    let first = resources.lists().get(1).ok_or("first typed wrapper")?;
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_report_entries: 2,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(20)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert_eq!(findings.len(), 3);
    let unavailable = findings
        .iter()
        .find(|finding| finding.code == FindingCode::UnavailableField)
        .ok_or("retained wrapper field finding")?;
    assert_eq!(unavailable.phase, Phase::Validation);
    assert_eq!(unavailable.severity, Severity::Error);
    assert!(unavailable.resource.is_none() && unavailable.source.is_none());
    let wrapper = unavailable.wrapper.ok_or("wrapper association")?;
    assert_eq!(wrapper.list, first.id());
    assert_eq!(wrapper.source, first.source());
    assert_eq!(
        unavailable
            .path
            .as_ref()
            .ok_or("wrapper field path")?
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "/metadata/generateName"
    );
    let terminal = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].phase, Phase::Validation);
    assert!(
        terminal[0].path.is_none()
            && terminal[0].source.is_none()
            && terminal[0].wrapper.is_none()
            && terminal[0].resource.is_none()
    );
    Ok(())
}

#[test]
fn retained_unadmitted_name_keeps_warning_when_report_slots_exhaust() -> TestResult {
    let mut first = service(&json!(80));
    first["metadata"]["name"] = json!("1svc");
    let mut second = service(&json!(80));
    second["metadata"]["name"] = json!("2svc");
    let resources = set(&json!({"apiVersion":"v1","kind":"List","items":[first,second]}))?;
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_report_entries: 1,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(37)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert_eq!(findings.len(), 2);
    let unadmitted = findings
        .iter()
        .find(|finding| finding.code == FindingCode::UnadmittedField)
        .ok_or("retained relaxed Service name finding")?;
    assert_eq!(unadmitted.phase, Phase::Validation);
    assert_eq!(unadmitted.severity, Severity::Warning);
    assert_eq!(unadmitted.resource, Some(resources.documents()[0].id()));
    assert!(unadmitted.source.is_none() && unadmitted.wrapper.is_none());
    assert_eq!(
        unadmitted
            .path
            .as_ref()
            .ok_or("name path")?
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "/metadata/name"
    );
    let terminal = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].phase, Phase::Validation);
    assert_eq!(terminal[0].severity, Severity::Error);
    assert!(
        terminal[0].path.is_none()
            && terminal[0].resource.is_none()
            && terminal[0].wrapper.is_none()
            && terminal[0].source.is_none()
    );
    Ok(())
}

#[test]
fn retained_workload_unknown_boundaries_are_warnings_when_report_slots_exhaust() -> TestResult {
    let first = json!({
        "apiVersion":"apps/v1","kind":"Deployment",
        "metadata":{"name":"first","namespace":"ns"},
        "spec":{
            "selector":{"matchLabels":{"app":"finite"},"vendorFuture":{}},
            "template":{
                "metadata":{"labels":{"app":"finite"}},
                "spec":{"containers":[{"name":"main","image":"image"}]}
            }
        }
    });
    let mut second = first.clone();
    second["metadata"]["name"] = json!("second");
    let mut third = first.clone();
    third["metadata"]["name"] = json!("third");
    let resources = set(&json!({"apiVersion":"v1","kind":"List","items":[first,second,third]}))?;
    let wrapper = resources.lists().first().ok_or("root List")?;
    let limits = kubernetes_lens::processing::NativeProcessingLimits {
        max_report_entries: 2,
        ..Default::default()
    };
    let findings = generation::validate_for_target_with_limits(
        &resources,
        &target(37)?,
        NativeValidationIntent::Unspecified,
        &limits,
    );
    assert_eq!(
        findings.len(),
        3,
        "safe finding facets: {:?}",
        findings
            .iter()
            .map(|finding| (
                finding.code,
                finding.severity,
                finding.phase,
                finding.resource,
                finding.wrapper,
                finding.source.is_some()
            ))
            .collect::<Vec<_>>()
    );
    let retained = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::UnadmittedField)
        .collect::<Vec<_>>();
    assert_eq!(retained.len(), 2);
    for (finding, resource) in retained.iter().zip(&resources.documents()[..2]) {
        assert_eq!(finding.phase, Phase::Validation);
        assert_eq!(finding.severity, Severity::Warning);
        assert_eq!(finding.resource, Some(resource.id()));
        assert!(finding.source.is_none());
        let association = finding.wrapper.ok_or("genuine root List association")?;
        assert_eq!(association.list, wrapper.id());
        assert_eq!(association.source, wrapper.source());
        assert_eq!(
            finding
                .path
                .as_ref()
                .ok_or("unknown selector member path")?
                .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            "/spec/selector/vendorFuture"
        );
    }
    let terminal = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminal.len(), 1);
    assert_eq!(terminal[0].phase, Phase::Validation);
    assert_eq!(terminal[0].severity, Severity::Error);
    assert!(
        terminal[0].path.is_none()
            && terminal[0].resource.is_none()
            && terminal[0].wrapper.is_none()
            && terminal[0].source.is_none()
    );
    Ok(())
}

#[test]
fn malformed_labels_keep_native_errors_outside_int_or_string_wire_contract() -> TestResult {
    for (labels, path) in [
        (json!(5), "/metadata/labels"),
        (json!({"app":5}), "/metadata/labels/app"),
    ] {
        let mut value = pod();
        value["metadata"]["labels"] = labels;
        let bytes = serde_json::to_vec(&value)?;
        let parsed = parse_source(
            SourceInput {
                id: SourceId(9),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: &bytes,
            },
            &ParseLimits::default(),
        )
        .map_err(|_| "malformed label source parsing failed")?;
        let errors = parsed.flatten_resources().err().ok_or("malformed labels accepted")?;
        assert!(has(
            &errors,
            FindingCode::NativeFieldInvalid,
            path,
            Severity::Error,
            Phase::Decoding
        ));
        assert!(
            !errors
                .iter()
                .any(|finding| finding.code == FindingCode::MalformedDocument)
        );
    }
    Ok(())
}

#[test]
fn reviewed_value_ports_reject_wire_null_with_actual_positions() -> TestResult {
    let mut http = pod();
    http["spec"]["containers"][0]["livenessProbe"] = json!({"httpGet":{"port":null}});
    let mut tcp = pod();
    tcp["spec"]["containers"][0]["livenessProbe"] = json!({"tcpSocket":{"port":null}});
    for (value, path, token) in [
        (service(&Value::Null), "/spec/ports/0/targetPort", "\"targetPort\":null"),
        (http, "/spec/containers/0/livenessProbe/httpGet/port", "\"port\":null"),
        (tcp, "/spec/containers/0/livenessProbe/tcpSocket/port", "\"port\":null"),
    ] {
        let bytes = serde_json::to_vec(&value)?;
        let parsed = parse_source(
            SourceInput {
                id: SourceId(9),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: &bytes,
            },
            &ParseLimits::default(),
        )
        .map_err(|_| "port null parsing failed")?;
        let errors = parsed.flatten_resources().err().ok_or("value-port null accepted")?;
        assert!(has(
            &errors,
            FindingCode::MalformedDocument,
            path,
            Severity::Error,
            Phase::Decoding
        ));
        let text = std::str::from_utf8(&bytes)?;
        let offset = text.find(token).ok_or("actual null token")? + token.len() - "null".len();
        assert!(errors.iter().any(|finding| {
            finding.code == FindingCode::MalformedDocument
                && finding
                    .source
                    .is_some_and(|position| position.byte_offset == offset as u64)
        }));
    }
    Ok(())
}

fn authored_null_value_port(
    tcp: Option<bool>,
) -> Result<(ResourceSet, kubernetes_lens::model::AuthoredResource, &'static str), Box<dyn std::error::Error>> {
    use kubernetes_lens::resources::workloads::{HTTPGetAction, Pod, Probe, TCPSocketAction};
    if let Some(tcp) = tcp {
        let mut resources = set(&pod())?;
        let native = resources.documents_mut()[0].resource_mut::<Pod>().ok_or("Pod")?;
        let Presence::Value(spec) = &mut native.spec else {
            return Err("Pod spec".into());
        };
        let Presence::Value(containers) = &mut spec.containers else {
            return Err("containers".into());
        };
        let mut probe = Probe::default();
        if tcp {
            let mut action = TCPSocketAction::default();
            action.port = Presence::Null;
            probe.tcp_socket = Presence::Value(action);
        } else {
            let mut action = HTTPGetAction::default();
            action.port = Presence::Null;
            probe.http_get = Presence::Value(action);
        }
        containers.first_mut().ok_or("first container")?.liveness_probe = Presence::Value(probe);
        let authored = native.clone().into();
        let path = if tcp {
            "/spec/containers/0/livenessProbe/tcpSocket/port"
        } else {
            "/spec/containers/0/livenessProbe/httpGet/port"
        };
        Ok((resources, authored, path))
    } else {
        let mut resources = set(&service(&json!(8080)))?;
        let native = resources.documents_mut()[0]
            .resource_mut::<Service>()
            .ok_or("Service")?;
        let Presence::Value(spec) = &mut native.spec else {
            return Err("Service spec".into());
        };
        let Presence::Value(ports) = &mut spec.ports else {
            return Err("Service ports".into());
        };
        ports.first_mut().ok_or("first Service port")?.target_port = Presence::Null;
        let authored = native.clone().into();
        Ok((resources, authored, "/spec/ports/0/targetPort"))
    }
}

#[test]
fn reviewed_value_port_nulls_keep_actual_authored_and_target_phases() -> TestResult {
    for tcp in [None, Some(false), Some(true)] {
        let (resources, authored, path) = authored_null_value_port(tcp)?;
        let findings = generation::validate_for_target(&resources, &target(37)?);
        assert!(has(
            &findings,
            FindingCode::NativeFieldInvalid,
            path,
            Severity::Error,
            Phase::Validation
        ));
        let errors = generation::generate(
            &resources,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions::default(),
        )
        .err()
        .ok_or("mutated null port generated")?;
        assert!(has(
            &errors,
            FindingCode::NativeFieldInvalid,
            path,
            Severity::Error,
            Phase::Validation
        ));
        let errors = ResourceSet::from_authored(vec![authored], &target(37)?, &AuthoringLimits::default())
            .err()
            .ok_or("authored null port accepted")?;
        assert!(has(
            &errors,
            FindingCode::NativeFieldInvalid,
            path,
            Severity::Error,
            Phase::Generation
        ));
        assert!(
            findings
                .iter()
                .chain(&errors)
                .all(|finding| finding.source.is_none() && finding.phase != Phase::Decoding)
        );
    }
    Ok(())
}

#[test]
fn optional_pdb_budget_nulls_survive_parsing_and_generation() -> TestResult {
    use kubernetes_lens::resources::access::{PodDisruptionBudgetV1, PodDisruptionBudgetV1Beta1};
    for (api, minor) in [("policy/v1", 37), ("policy/v1beta1", 24)] {
        let value = json!({"apiVersion":api,"kind":"PodDisruptionBudget","metadata":{"name":"finite","namespace":"ns"},
            "spec":{"minAvailable":null,"maxUnavailable":null}});
        let resources = set(&value)?;
        if api == "policy/v1" {
            let native = resources.documents()[0]
                .resource::<PodDisruptionBudgetV1>()
                .ok_or("PDB v1")?;
            let spec = native.spec.value().ok_or("PDB v1 spec")?;
            assert!(matches!(spec.min_available, Presence::Null) && matches!(spec.max_unavailable, Presence::Null));
        } else {
            let native = resources.documents()[0]
                .resource::<PodDisruptionBudgetV1Beta1>()
                .ok_or("PDB v1beta1")?;
            let spec = native.spec.value().ok_or("PDB v1beta1 spec")?;
            assert!(matches!(spec.min_available, Presence::Null) && matches!(spec.max_unavailable, Presence::Null));
        }
        assert!(
            !generation::validate_for_target(&resources, &target(minor)?)
                .iter()
                .any(|finding| finding.severity == Severity::Error)
        );
        let artifact = generation::generate(
            &resources,
            &target(minor)?,
            OutputFormat::Json,
            &GenerationOptions {
                json_shape: generation::JsonShape::SingleResource,
                ..GenerationOptions::default()
            },
        )
        .map_err(|_| "optional PDB null generation refused")?;
        let generated: Value = serde_json::from_slice(
            artifact.reveal_bytes(&generation::ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
        )?;
        for path in ["/spec/minAvailable", "/spec/maxUnavailable"] {
            assert!(generated.pointer(path).is_some_and(Value::is_null));
        }
    }
    Ok(())
}

#[test]
fn projection_conflict_keeps_root_annotation_validation() -> TestResult {
    for annotations in [json!({"bad/key/again":"x"}), json!({"size":"x".repeat(262_145)})] {
        let mut value = service(&json!(8080));
        value["spec"]["ports"] = json!([
            {"name":"first","port":80,"targetPort":8080},
            {"name":"second","port":80,"targetPort":8081}
        ]);
        value["metadata"]["annotations"] = annotations;
        let resources = set(&value)?;
        let findings = generation::validate_for_target(&resources, &target(37)?);
        assert!(has(
            &findings,
            FindingCode::MergeConflict,
            "/spec/ports",
            Severity::Error,
            Phase::Generation
        ));
        let path = if value["metadata"]["annotations"].get("size").is_some() {
            "/metadata/annotations/size"
        } else {
            "/metadata/annotations/bad~1key~1again"
        };
        assert!(invalid(&findings, path));
        assert!(
            findings
                .iter()
                .filter(|finding| finding.code == FindingCode::NativeFieldInvalid)
                .all(|finding| { finding.resource == Some(resources.documents()[0].id()) && finding.source.is_none() })
        );
    }
    Ok(())
}

#[test]
fn denied_access_mode_preservation_retains_validation_and_generation_contexts() -> TestResult {
    use kubernetes_lens::{
        generation::{OpaqueFieldPolicy, ProtectedOutput},
        resources::workloads::StatefulSet,
    };
    let value = json!({"apiVersion":"apps/v1","kind":"StatefulSet","metadata":{"name":"app","namespace":"ns"},
        "spec":{"serviceName":"headless","selector":{"matchLabels":{"app":"web"}},
        "template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"image"}]}},
        "volumeClaimTemplates":[{"metadata":{"name":"claim"},"spec":{"accessModes":["ReadWriteOncePod"],"resources":{"requests":{"storage":"1Gi"}}}}]}});
    let mut resources = set(&value)?;
    let foreign = set(&value)?;
    let donor = foreign.documents()[0]
        .resource::<StatefulSet>()
        .ok_or("foreign StatefulSet")?
        .spec
        .value()
        .and_then(|spec| spec.volume_claim_templates.value())
        .and_then(|claims| claims.first())
        .ok_or("foreign claim")?
        .clone();
    let native = resources.documents_mut()[0]
        .resource_mut::<StatefulSet>()
        .ok_or("StatefulSet")?;
    let Presence::Value(spec) = &mut native.spec else {
        return Err("StatefulSet spec".into());
    };
    let Presence::Value(claims) = &mut spec.volume_claim_templates else {
        return Err("claims".into());
    };
    *claims.first_mut().ok_or("claim")? = donor;
    let path = "/spec/volumeClaimTemplates/0/spec/accessModes/0";
    let validation = generation::validate_for_target(&resources, &target(37)?);
    assert!(has(
        &validation,
        FindingCode::UnadmittedField,
        path,
        Severity::Warning,
        Phase::Validation
    ));
    let options = GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    };
    let refused = generation::generate(&resources, &target(37)?, OutputFormat::Json, &options)
        .err()
        .ok_or("foreign access-mode occurrence emitted")?;
    assert!(has(
        &refused,
        FindingCode::UnadmittedField,
        path,
        Severity::Warning,
        Phase::Validation
    ));
    assert!(has(
        &refused,
        FindingCode::UnadmittedField,
        path,
        Severity::Error,
        Phase::Generation
    ));
    assert!(
        refused
            .iter()
            .filter(|finding| finding.code == FindingCode::UnadmittedField)
            .all(|finding| { finding.resource == Some(resources.documents()[0].id()) && finding.source.is_none() })
    );
    Ok(())
}
