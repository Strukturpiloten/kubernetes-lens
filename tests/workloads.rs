//! Independent expected native semantics; these offline checks are not API-server conformance.
use kubernetes_lens::source::AuthoringLimits;
use kubernetes_lens::{
    FindingCode,
    capability::{FeatureGateId, FeatureGateState, KubernetesVersion, TargetProfile},
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
    },
    model::{AuthoredResource, Metadata, ResourceSet},
    parse_source,
    resources::workloads::*,
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    validate_for_target,
    value::{Presence, Protected},
};
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
trait Require<T> {
    fn required(self) -> TestResult<T>;
}
impl<T> Require<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| "missing expected workload fixture".into())
    }
}
impl<T, E> Require<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|_| "workload fixture operation failed".into())
    }
}
fn resources(text: &str) -> TestResult<ResourceSet> {
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
    .required()?
    .flatten_resources()
    .required()
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    }
}
fn json(set: &ResourceSet, minor: u8) -> TestResult<serde_json::Value> {
    let artifact = generate(set, &target(minor)?, OutputFormat::Json, &options()).required()?;
    Ok(serde_json::from_slice(artifact.reveal_bytes(
        &ExplicitArtifactAccess::explicitly_allow_raw_artifact(),
    ))?)
}
fn deployment(extra: &str) -> String {
    format!(
        "apiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: app, namespace: ns}}\nspec:\n  selector: {{matchLabels: {{app: web}}}}\n  template:\n    metadata: {{labels: {{app: web}}}}\n    spec:\n      containers: [{{name: web, image: example/web:v1}}]\n{extra}"
    )
}
fn pod(spec: &str) -> String {
    format!("apiVersion: v1\nkind: Pod\nmetadata: {{name: app, namespace: ns}}\nspec:\n{spec}")
}

fn all_pod_bindings(spec: &serde_json::Value) -> TestResult<Vec<(ResourceSet, String, u8)>> {
    use serde_json::json;
    let mut cases = Vec::new();
    for (api, kind, minor) in [
        ("v1", "Pod", 20),
        ("apps/v1", "Deployment", 20),
        ("apps/v1", "StatefulSet", 20),
        ("apps/v1", "DaemonSet", 20),
        ("apps/v1", "ReplicaSet", 20),
        ("v1", "ReplicationController", 20),
        ("batch/v1", "Job", 20),
        ("batch/v1beta1", "CronJob", 20),
        ("batch/v1", "CronJob", 37),
    ] {
        let mut pod_spec = spec.clone();
        pod_spec["restartPolicy"] = json!(if matches!(kind, "Job" | "CronJob") {
            "OnFailure"
        } else {
            "Always"
        });
        let template = json!({"metadata": {"labels": {"app": "web"}}, "spec": pod_spec});
        let (body, pointer) = match kind {
            "Pod" => (pod_spec, "/spec"),
            "CronJob" => (
                json!({"schedule": "0 * * * *", "jobTemplate": {"spec": {"template": template}}}),
                "/spec/jobTemplate/spec/template/spec",
            ),
            "Job" => (json!({"template": template}), "/spec/template/spec"),
            "ReplicationController" => (
                json!({"selector": {"app": "web"}, "template": template}),
                "/spec/template/spec",
            ),
            "StatefulSet" => (
                json!({"serviceName": "headless", "selector": {"matchLabels": {"app": "web"}}, "template": template}),
                "/spec/template/spec",
            ),
            _ => (
                json!({"selector": {"matchLabels": {"app": "web"}}, "template": template}),
                "/spec/template/spec",
            ),
        };
        let document =
            json!({"apiVersion": api, "kind": kind, "metadata": {"name": "app", "namespace": "ns"}, "spec": body});
        cases.push((
            resources(&serde_json::to_string(&document)?)?,
            pointer.to_owned(),
            minor,
        ));
    }
    Ok(cases)
}

#[test]
fn named_ports_follow_native_grammar_in_every_pod_binding() -> TestResult<()> {
    use serde_json::json;
    for name in [
        "http",
        "http-2",
        "a1",
        "",
        "a--b",
        "-http",
        "http-",
        "123",
        "HTTP",
        "abcdefghijklmnop",
    ] {
        let valid_declared = matches!(name, "http" | "http-2" | "a1" | "");
        let valid_probe = matches!(name, "http" | "http-2" | "a1");
        let spec = json!({"containers": [{"name": "web", "image": "example/web:v1", "ports": [{"name": name, "containerPort": 80}], "readinessProbe": {"tcpSocket": {"port": name}}}]});
        for (set, pointer, minor) in all_pod_bindings(&spec)? {
            let findings = validate_for_target(&set, &target(minor)?);
            for (suffix, valid) in [
                ("/containers/0/ports/0/name", valid_declared),
                ("/containers/0/readinessProbe/tcpSocket/port", valid_probe),
            ] {
                let expected = format!("{pointer}{suffix}");
                let invalid = findings.iter().any(|finding| {
                    finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref().is_some_and(|path| {
                            path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == expected
                        })
                });
                assert_eq!(invalid, !valid);
            }
        }
    }
    Ok(())
}

#[test]
fn relaxed_environment_forms_require_evidence_and_floor_uses_legacy_grammar() -> TestResult<()> {
    use serde_json::json;
    for name in [
        "TOKEN",
        "-",
        "_",
        ".a",
        "a..",
        "1TOKEN",
        ".",
        "..",
        "..x",
        "with space",
        "A=B",
        "A\nB",
        "é",
        "\u{7f}",
    ] {
        let legacy = matches!(name, "TOKEN" | "-" | "_" | ".a" | "a..");
        let relaxed_only = matches!(name, "1TOKEN" | "." | ".." | "..x" | "with space");
        let spec = json!({"containers": [{"name": "web", "image": "example/web:v1", "env": [{"name": name, "value": "value"}], "envFrom": [{"prefix": name, "configMapRef": {"name": "settings"}}]}]});
        for (set, pointer, minor) in all_pod_bindings(&spec)? {
            let findings = validate_for_target(&set, &target(minor)?);
            for suffix in ["/containers/0/env/0/name", "/containers/0/envFrom/0/prefix"] {
                let expected = format!("{pointer}{suffix}");
                let at_field = |code| {
                    findings.iter().any(|finding| {
                        finding.code == code
                            && finding.path.as_ref().is_some_and(|path| {
                                path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == expected
                            })
                    })
                };
                assert_eq!(
                    at_field(FindingCode::NativeFieldInvalid),
                    !legacy && (!relaxed_only || minor == 20)
                );
                assert_eq!(
                    at_field(FindingCode::NativeContextRequired),
                    relaxed_only && minor != 20
                );
            }
            if relaxed_only && minor != 20 {
                let artifact = generate(&set, &target(minor)?, OutputFormat::Json, &options()).required()?;
                assert!(
                    artifact
                        .findings()
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeContextRequired)
                );
            }
        }
    }
    Ok(())
}

#[test]
fn environment_equals_is_invalid_for_names_and_prefixes_across_templates() -> TestResult<()> {
    use serde_json::json;
    for name in ["TOKEN", "A=B"] {
        let spec = json!({"containers": [{"name": "web", "image": "example/web:v1", "env": [{"name": name, "value": "value"}], "envFrom": [{"prefix": name, "configMapRef": {"name": "settings"}}]}], "initContainers": [{"name": "init", "image": "example/init:v1", "env": [{"name": name, "value": "value"}]}]});
        for (set, pointer, minor) in all_pod_bindings(&spec)? {
            let findings = validate_for_target(&set, &target(minor)?);
            for suffix in [
                "/containers/0/env/0/name",
                "/containers/0/envFrom/0/prefix",
                "/initContainers/0/env/0/name",
            ] {
                let expected = format!("{pointer}{suffix}");
                assert_eq!(
                    findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                            && finding
                                .path
                                .as_ref()
                                .is_some_and(|path| path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                                    == expected)),
                    name == "A=B"
                );
            }
        }
    }
    Ok(())
}

#[test]
fn unknown_volume_neighbors_do_not_hide_known_source_contradictions() -> TestResult<()> {
    use serde_json::json;
    for contradictory in [false, true] {
        let mut volume = json!({"name": "data", "emptyDir": {}, "futureField": true});
        if contradictory {
            volume["hostPath"] = json!({"path": "/tmp"});
        }
        let spec = json!({"containers": [{"name": "web", "image": "example/web:v1"}], "volumes": [volume]});
        for (set, pointer, minor) in all_pod_bindings(&spec)? {
            let findings = validate_for_target(&set, &target(minor)?);
            let expected = format!("{pointer}/volumes/0");
            assert_eq!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref().is_some_and(|path| path
                            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                            == expected)),
                contradictory
            );
            if contradictory {
                assert!(generate(&set, &target(minor)?, OutputFormat::Json, &options()).is_err());
            } else {
                assert_eq!(
                    json(&set, minor)?.pointer(&format!("{pointer}/volumes/0/futureField")),
                    Some(&json!(true))
                );
            }
        }
    }
    Ok(())
}

#[test]
fn azure_file_secret_dependency_is_explicit_and_namespaced_in_every_binding() -> TestResult<()> {
    use kubernetes_lens::graph::{ReferenceScope, ReferenceTarget, Resolution, resolve_references_for_target};
    use serde_json::json;
    let spec = json!({"containers": [{"name": "web", "image": "example/web:v1"}], "volumes": [{"name": "data", "azureFile": {"secretName": "account", "shareName": "share"}}]});
    for (set, pointer, minor) in all_pod_bindings(&spec)? {
        let graph = resolve_references_for_target(&set, &target(minor)?);
        let expected = format!("{pointer}/volumes/0/azureFile/secretName");
        let edges = graph
            .edges
            .iter()
            .filter(|edge| {
                edge.reference
                    .path
                    .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                    == expected
            })
            .collect::<Vec<_>>();
        assert_eq!(edges.len(), 1);
        assert!(matches!(edges[0].reference.scope, ReferenceScope::SameNamespace));
        assert!(
            matches!(&edges[0].reference.target, ReferenceTarget::CheckedObject { gvk, name, optional: Presence::Absent, predicate: None } if gvk.api_version() == "v1" && gvk.kind == "Secret" && name == "account")
        );
        assert_eq!(edges[0].resolution, Resolution::Missing);
    }
    Ok(())
}
#[test]
fn concrete_roots_have_fixed_served_api_identity() -> TestResult<()> {
    let set = resources(&pod("  containers: [{name: web, image: example/web:v1}]\n"))?;
    assert!(set.documents()[0].resource::<Pod>().is_some());
    let set = resources(&deployment(""))?;
    assert!(set.documents()[0].resource::<Deployment>().is_some());
    for (kind, api) in [
        ("StatefulSet", "apps/v1"),
        ("DaemonSet", "apps/v1"),
        ("ReplicaSet", "apps/v1"),
        ("ReplicationController", "v1"),
        ("Job", "batch/v1"),
        ("CronJob", "batch/v1"),
        ("CronJob", "batch/v1beta1"),
    ] {
        let set = resources(&format!(
            "apiVersion: {api}\nkind: {kind}\nmetadata: {{name: typed, namespace: ns}}\nspec: {{}}\n"
        ))?;
        let doc = &set.documents()[0];
        let typed = match (kind, api) {
            ("StatefulSet", _) => doc.resource::<StatefulSet>().is_some(),
            ("DaemonSet", _) => doc.resource::<DaemonSet>().is_some(),
            ("ReplicaSet", _) => doc.resource::<ReplicaSet>().is_some(),
            ("ReplicationController", _) => doc.resource::<ReplicationController>().is_some(),
            ("Job", _) => doc.resource::<Job>().is_some(),
            ("CronJob", "batch/v1") => doc.resource::<CronJobV1>().is_some(),
            _ => doc.resource::<CronJobV1Beta1>().is_some(),
        };
        assert!(typed);
    }
    Ok(())
}
#[test]
fn omitted_null_and_zero_replicas_stay_distinct() -> TestResult<()> {
    for (extra, expected) in [
        ("", None),
        ("  replicas: null\n", Some(serde_json::Value::Null)),
        ("  replicas: 0\n", Some(serde_json::json!(0))),
    ] {
        let set = resources(&deployment(extra))?;
        let generated = json(&set, 37)?;
        assert_eq!(generated["spec"].get("replicas"), expected.as_ref());
    }
    Ok(())
}
#[test]
fn surge_above_one_hundred_is_valid_but_unavailability_is_not() -> TestResult<()> {
    let set = resources(&deployment(
        "  strategy: {type: RollingUpdate, rollingUpdate: {maxSurge: '150%', maxUnavailable: '25%'}}\n",
    ))?;
    assert!(
        !validate_for_target(&set, &target(37)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    assert_eq!(json(&set, 37)?["spec"]["strategy"]["rollingUpdate"]["maxSurge"], "150%");
    for extra in [
        "  strategy: {rollingUpdate: {maxUnavailable: '150%'}}\n",
        "  strategy: {rollingUpdate: {maxSurge: 0, maxUnavailable: '0%'}}\n",
        "  strategy: {type: Recreate, rollingUpdate: {maxSurge: 1}}\n",
    ] {
        let set = resources(&deployment(extra))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}
#[test]
fn nested_unknown_member_survives_a_typed_image_edit() -> TestResult<()> {
    let mut set = resources(&pod(
        "  containers: [{name: web, image: example/web:v1, futureField: {private: retained}}]\n",
    ))?;
    let value = set.documents_mut()[0].resource_mut::<Pod>().required()?;
    let Presence::Value(spec) = &mut value.spec else {
        return Err("missing native pod spec".into());
    };
    let Presence::Value(containers) = &mut spec.containers else {
        return Err("missing native containers".into());
    };
    assert_eq!(containers[0].unknown_fields().len(), 1);
    containers[0].image = Presence::Value("example/web:v2".into());
    let generated = json(&set, 37)?;
    assert_eq!(generated["spec"]["containers"][0]["image"], "example/web:v2");
    assert_eq!(generated["spec"]["containers"][0]["futureField"]["private"], "retained");
    assert!(generate(&set, &target(37)?, OutputFormat::Yaml, &GenerationOptions::default()).is_err());
    Ok(())
}
#[test]
fn protected_native_payloads_are_redacted_and_output_requires_permission() -> TestResult<()> {
    let set = resources(&pod(
        "  containers:\n  - name: web\n    image: example/web:v1\n    command: [private-command]\n    args: [private-argument]\n    env: [{name: TOKEN, value: private-token}]\n    livenessProbe: {httpGet: {port: 8080, httpHeaders: [{name: Authorization, value: private-header}]}}\n",
    ))?;
    let native = set.documents()[0].resource::<Pod>().required()?;
    let debug = format!("{native:?}");
    for marker in ["private-command", "private-argument", "private-token", "private-header"] {
        assert!(!debug.contains(marker));
    }
    let denied = generate(&set, &target(37)?, OutputFormat::Json, &GenerationOptions::default())
        .err()
        .required()?;
    assert!(denied.iter().any(|f| f.code == FindingCode::ProtectedOutputDenied));
    let value = json(&set, 37)?;
    assert_eq!(value["spec"]["containers"][0]["env"][0]["value"], "private-token");
    assert_eq!(value["spec"]["containers"][0]["command"][0], "private-command");
    Ok(())
}
#[test]
fn independent_invalid_native_pod_cases_have_path_findings() -> TestResult<()> {
    for spec in [
        "  containers: [{name: same, image: i}, {name: same, image: i}]\n",
        "  containers: [{name: web, image: i}]\n  volumes: [{name: both, emptyDir: {}, hostPath: {path: /tmp}}]\n",
        "  containers: [{name: web, image: i, volumeMounts: [{name: missing, mountPath: /data}]}]\n",
        "  containers: [{name: web, image: i, livenessProbe: {exec: {command: [/bin/true]}, httpGet: {port: 80}}}]\n",
        "  containers: [{name: web, image: i, ports: [{containerPort: 65536}]}]\n",
        "  containers: [{name: web, image: i, env: [{name: TOKEN, value: literal, valueFrom: {secretKeyRef: {name: s, key: token}}}]}]\n",
        "  containers: [{name: web, image: i, securityContext: {runAsUser: -1}}]\n",
        "  containers: [{name: web, image: i, volumeMounts: [{name: data, mountPath: /data, subPath: a, subPathExpr: b}]}]\n  volumes: [{name: data, emptyDir: {}}]\n",
    ] {
        let set = resources(&pod(spec))?;
        let findings = validate_for_target(&set, &target(37)?);
        assert!(
            findings
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid && f.path.is_some())
        );
        assert!(generate(&set, &target(37)?, OutputFormat::Yaml, &options()).is_err());
    }
    Ok(())
}
#[test]
fn sidecars_need_init_role_and_an_enabled_stage() -> TestResult<()> {
    let set = resources(&pod(
        "  containers: [{name: web, image: i}]\n  initContainers: [{name: sidecar, image: i, restartPolicy: Always}]\n",
    ))?;
    let mut enabled = target(28)?;
    enabled
        .feature_gates
        .states
        .insert(FeatureGateId::SidecarContainers, FeatureGateState::Enabled);
    assert!(
        !validate_for_target(&set, &enabled)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    let mut disabled = enabled.clone();
    disabled
        .feature_gates
        .states
        .insert(FeatureGateId::SidecarContainers, FeatureGateState::Disabled);
    assert!(validate_for_target(&set, &disabled).iter().any(|f| matches!(
        f.code,
        FindingCode::FeatureGateRequired | FindingCode::NativeFieldInvalid
    )));
    let regular = resources(&pod("  containers: [{name: web, image: i, restartPolicy: Always}]\n"))?;
    assert!(
        validate_for_target(&regular, &target(37)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}
fn cron(api: &str, schedule: &str, extra: &str) -> String {
    format!(
        "apiVersion: {api}\nkind: CronJob\nmetadata: {{name: timer, namespace: ns}}\nspec:\n  schedule: '{schedule}'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers: [{{name: task, image: i}}]\n{extra}"
    )
}
#[test]
fn cron_served_api_and_stable_timezone_boundaries_are_explicit() -> TestResult<()> {
    let beta = resources(&cron("batch/v1beta1", "0 * * * *", ""))?;
    assert!(
        !validate_for_target(&beta, &target(20)?)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableApi)
    );
    assert!(
        validate_for_target(&beta, &target(25)?)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableApi)
    );
    let stable = resources(&cron("batch/v1", "0 * * * *", ""))?;
    assert!(
        validate_for_target(&stable, &target(20)?)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableApi)
    );
    assert!(
        !validate_for_target(&stable, &target(21)?)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableApi)
    );
    let timezone = resources(&cron("batch/v1", "0 * * * *", "  timeZone: Europe/Berlin\n"))?;
    assert!(validate_for_target(&timezone, &target(26)?).iter().any(|f| matches!(
        f.code,
        FindingCode::FeatureGateRequired | FindingCode::UnavailableField | FindingCode::NativeFieldInvalid
    )));
    assert!(
        !validate_for_target(&timezone, &target(27)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    let beta_timezone = resources(&cron("batch/v1beta1", "0 * * * *", "  timeZone: Europe/Berlin\n"))?;
    let native = beta_timezone.documents()[0].resource::<CronJobV1Beta1>().required()?;
    assert_eq!(native.spec.value().required()?.unknown_fields().len(), 1);
    Ok(())
}
#[test]
fn cron_dialect_accepts_native_forms_and_rejects_extensions() -> TestResult<()> {
    for schedule in ["*/5 0-23 * JAN,MAR MON-FRI", "0 12 ? * SUN", "@hourly", "@every 1h30m"] {
        let set = resources(&cron("batch/v1", schedule, ""))?;
        assert!(
            !validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    for schedule in [
        "0 0 0 * * *",
        "0 0 * * 7",
        "0 0 L * *",
        "0 0 * * MON#2",
        "*/0 * * * *",
        "@every nonsense",
    ] {
        let set = resources(&cron("batch/v1", schedule, ""))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}
#[test]
fn timestamp_lexeme_retains_long_precision_and_checks_calendar() -> TestResult<()> {
    let value = "2024-02-29T23:59:59.123456789012345678901234567890Z";
    let time = NativeTime::parse(value)?;
    assert_eq!(time.lexeme(&ExplicitSourceAccess::explicitly_allow_raw_source()), value);
    assert!(!format!("{time:?}").contains("2024"));
    for bad in [
        "2023-02-29T00:00:00Z",
        "2024-04-31T00:00:00Z",
        "2024-01-01T24:00:00Z",
        "2024-01-01T00:00:00+24:00",
    ] {
        assert!(NativeTime::parse(bad).is_err());
    }
    Ok(())
}
#[test]
fn author_fresh_native_values_without_any_source_manifest() -> TestResult<()> {
    let mut pod = Pod::default();
    let metadata = Metadata {
        name: Presence::Value("fresh".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    };
    pod.metadata = Presence::Value(metadata);
    let mut spec = PodSpec::default();
    let mut container = Container::default();
    container.name = Presence::Value("web".into());
    container.image = Presence::Value("example/web:v1".into());
    container.args = Presence::Value(Protected::new(vec!["private-argument".into()]));
    spec.containers = Presence::Value(vec![container]);
    pod.spec = Presence::Value(spec);
    let set = ResourceSet::from_authored(
        vec![AuthoredResource::from(pod)],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .required()?;
    let generated = json(&set, 37)?;
    assert_eq!(generated["apiVersion"], "v1");
    assert_eq!(generated["kind"], "Pod");
    assert_eq!(generated["metadata"]["name"], "fresh");
    assert_eq!(generated["spec"]["containers"][0]["args"][0], "private-argument");
    assert!(generated["spec"].get("restartPolicy").is_none());
    let artifact = generate(&set, &target(37)?, OutputFormat::Yaml, &options()).required()?;
    let generated =
        std::str::from_utf8(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    let reparsed = resources(generated)?;
    assert!(reparsed.documents()[0].resource::<Pod>().is_some());
    Ok(())
}
#[test]
fn explicit_selector_mismatch_is_invalid() -> TestResult<()> {
    let text = deployment("").replace("metadata: {labels: {app: web}}", "metadata: {labels: {app: different}}");
    let set = resources(&text)?;
    assert!(
        validate_for_target(&set, &target(37)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}
#[test]
fn portworx_parent_stays_unadmitted() -> TestResult<()> {
    let set = resources(&pod(
        "  containers: [{name: web, image: i}]\n  volumes: [{name: data, portworxVolume: {volumeID: private-volume}}]\n",
    ))?;
    let native = set.documents()[0].resource::<Pod>().required()?;
    assert_eq!(
        native.spec.value().required()?.volumes.value().required()?[0]
            .unknown_fields()
            .len(),
        1
    );
    assert!(generate(&set, &target(37)?, OutputFormat::Yaml, &GenerationOptions::default()).is_err());
    Ok(())
}
fn authored_pod(name: &str, image: &str) -> Pod {
    let mut pod = Pod::default();
    let metadata = Metadata {
        name: Presence::Value(name.into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    };
    pod.metadata = Presence::Value(metadata);
    let mut spec = PodSpec::default();
    let mut container = Container::default();
    container.name = Presence::Value("web".into());
    container.image = Presence::Value(image.into());
    spec.containers = Presence::Value(vec![container]);
    pod.spec = Presence::Value(spec);
    pod
}
#[test]
fn authored_source_evidence_is_generated_and_positionless() -> TestResult<()> {
    use kubernetes_lens::{
        FieldPath,
        source::{EvidenceOrigin, ValueOrigin},
    };
    let set = ResourceSet::from_authored(
        vec![authored_pod("fresh", "image").into()],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .required()?;
    let doc = &set.documents()[0];
    assert_eq!(doc.source_evidence().origin, EvidenceOrigin::NativeAuthored);
    assert_eq!(doc.source_evidence().source_version, None);
    for pointer in ["/apiVersion", "/kind", "/metadata/name", "/spec/containers/0/image"] {
        let evidence = doc.field_evidence().get(&FieldPath::parse(pointer)?).required()?;
        assert_eq!(evidence.origin, ValueOrigin::Generated);
        assert!(evidence.position.is_none());
    }
    Ok(())
}
#[test]
fn authoring_scalar_resource_node_depth_and_cumulative_byte_boundaries() -> TestResult<()> {
    let profile = target(37)?;
    let image = "i".repeat(32);
    let mut limits = AuthoringLimits::default();
    limits.parser.max_scalar_bytes = 32;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", &image).into()], &profile, &limits).is_ok());
    limits.parser.max_scalar_bytes = 31;
    let errors = ResourceSet::from_authored(vec![authored_pod("fresh", &image).into()], &profile, &limits)
        .err()
        .required()?;
    assert!(errors.iter().any(|f| f.code == FindingCode::LimitExceeded));
    let limits = AuthoringLimits {
        max_resources: 1,
        ..AuthoringLimits::default()
    };
    assert!(ResourceSet::from_authored(vec![authored_pod("first", "image").into()], &profile, &limits).is_ok());
    assert!(
        ResourceSet::from_authored(
            vec![
                authored_pod("first", "image").into(),
                authored_pod("second", "image").into()
            ],
            &profile,
            &limits
        )
        .is_err()
    );
    // Eleven values/containers plus nine object keys consume twenty construction nodes.
    let mut limits = AuthoringLimits::default();
    limits.parser.max_nodes = 20;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_ok());
    limits.parser.max_nodes = 19;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_err());
    let mut limits = AuthoringLimits::default();
    limits.parser.max_depth = 4;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_ok());
    limits.parser.max_depth = 3;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_err());
    let baseline = ResourceSet::from_authored(
        vec![authored_pod("fresh", "image").into()],
        &profile,
        &AuthoringLimits::default(),
    )
    .required()?;
    let size = baseline.documents()[0].source_evidence().byte_len();
    let mut limits = AuthoringLimits {
        max_total_snapshot_bytes: size,
        ..AuthoringLimits::default()
    };
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_ok());
    limits.max_total_snapshot_bytes = size - 1;
    assert!(ResourceSet::from_authored(vec![authored_pod("fresh", "image").into()], &profile, &limits).is_err());
    Ok(())
}
#[test]
fn native_enum_action_and_optional_reference_shapes_are_checked() -> TestResult<()> {
    for spec in [
        "  containers: [{name: web, image: i, imagePullPolicy: Sometimes}]\n",
        "  containers: [{name: web, image: i, lifecycle: {preStop: {exec: {command: []}}}}]\n",
        "  containers: [{name: web, image: i, readinessProbe: {httpGet: {path: /health}}}]\n",
        "  containers: [{name: web, image: i, env: [{name: TOKEN, valueFrom: {secretKeyRef: {name: s, key: token, optional: null}}}]}]\n",
        "  containers: [{name: web, image: i, securityContext: {seccompProfile: {type: Arbitrary}}}]\n",
        "  containers: [{name: web, image: i}]\n  affinity: {nodeAffinity: {preferredDuringSchedulingIgnoredDuringExecution: [{preference: {matchExpressions: [{key: env, operator: In, values: [prod]}]}}]}}\n",
    ] {
        let set = resources(&pod(spec))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}
#[test]
fn emitted_key_references_keep_object_key_optional_and_private_evidence_distinct() -> TestResult<()> {
    use kubernetes_lens::{
        graph::{KeyDomain, ReferencePredicate, ReferenceTarget, resolve_references},
        source::ExplicitSourceAccess,
    };
    let set = resources(&pod(
        "  containers: [{name: web, image: i, env: [{name: TOKEN, valueFrom: {secretKeyRef: {name: credentials, key: private-key, optional: true}}}]}]\n",
    ))?;
    let graph = resolve_references(&set);
    assert_eq!(graph.edges.len(), 1);
    let reference = &graph.edges[0].reference;
    match &reference.target {
        ReferenceTarget::CheckedObject {
            gvk,
            name,
            predicate: Some(ReferencePredicate::KeyExists { domain, key }),
            optional,
        } => {
            assert_eq!(gvk.kind, "Secret");
            assert_eq!(name, "credentials");
            assert_eq!(*domain, KeyDomain::Secret);
            assert_eq!(
                key.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
                "private-key"
            );
            assert_eq!(*optional, Presence::Value(true));
        }
        _ => return Err("expected native key reference".into()),
    }
    assert!(!format!("{graph:?}").contains("private-key"));
    assert!(!format!("{graph:?}").contains("credentials"));
    Ok(())
}
#[test]
fn job_indexed_policies_validate_restart_counts_and_intervals() -> TestResult<()> {
    fn job(extra: &str) -> String {
        format!(
            "apiVersion: batch/v1\nkind: Job\nmetadata: {{name: task, namespace: ns}}\nspec:\n  completionMode: Indexed\n  completions: 10\n  template:\n    spec:\n      restartPolicy: Never\n      containers: [{{name: task, image: i}}]\n{extra}"
        )
    }
    let set = resources(&job(
        "  backoffLimitPerIndex: 1\n  maxFailedIndexes: 2\n  successPolicy: {rules: [{succeededIndexes: '0-2,4,6-8', succeededCount: 5}]}\n",
    ))?;
    assert!(
        !validate_for_target(&set, &target(37)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    assert!(
        validate_for_target(&set, &target(32)?)
            .iter()
            .any(|f| matches!(f.code, FindingCode::UnavailableField | FindingCode::FeatureGateRequired))
    );
    for extra in [
        "  successPolicy: {rules: [{succeededIndexes: '0-2,2-3'}]}\n",
        "  successPolicy: {rules: [{succeededIndexes: '10'}]}\n",
        "  backoffLimitPerIndex: 1\n  maxFailedIndexes: 11\n",
        "  podFailurePolicy: {rules: [{action: FailJob, onExitCodes: {operator: In, values: [0]}}]}\n",
    ] {
        let set = resources(&job(extra))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}
#[test]
fn timezone_recognition_is_exact_and_inline_tz_rejection_is_versioned() -> TestResult<()> {
    for zone in ["Local", "local", "../UTC", "Europe//Berlin", "Europe/berlin"] {
        let set = resources(&cron("batch/v1", "0 * * * *", &format!("  timeZone: {zone}\n")))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| matches!(f.code, FindingCode::NativeFieldInvalid | FindingCode::UnadmittedField))
        );
    }
    let set = resources(&cron("batch/v1", "TZ=UTC 0 * * * *", ""))?;
    assert!(
        !validate_for_target(&set, &target(36)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    assert!(
        kubernetes_lens::validate_for_target_with_intent(
            &set,
            &target(37)?,
            kubernetes_lens::NativeValidationIntent::Create
        )
        .iter()
        .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    let set = resources(&cron("batch/v1", "TZ=UTC 0 * * * *", "  timeZone: UTC\n"))?;
    assert!(
        validate_for_target(&set, &target(27)?)
            .iter()
            .any(|f| f.code == FindingCode::NativeFieldInvalid)
    );
    for schedule in ["@every 2562047h47m16.854775807s", "@every -2562047h47m16.854775808s"] {
        let set = resources(&cron("batch/v1", schedule, ""))?;
        assert!(
            !validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    for schedule in ["@every 2562047h47m16.854775808s", "@every 999999999999999999999h"] {
        let set = resources(&cron("batch/v1", schedule, ""))?;
        assert!(
            validate_for_target(&set, &target(37)?)
                .iter()
                .any(|f| f.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}
#[test]
fn sidecar_role_and_gate_checks_propagate_through_every_served_template() -> TestResult<()> {
    let pod_spec = "restartPolicy: Always, containers: [{name: app, image: i}], initContainers: [{name: side, image: i, restartPolicy: Always}]";
    // Independent full manifests bind the same PodSpec to each distinct native path.
    let mut documents = Vec::new();
    documents.push(pod(
        "  containers: [{name: app, image: i}]\n  initContainers: [{name: side, image: i, restartPolicy: Always}]\n",
    ));
    for kind in ["Deployment", "StatefulSet", "DaemonSet", "ReplicaSet"] {
        let service = if kind == "StatefulSet" {
            "serviceName: headless, "
        } else {
            ""
        };
        documents.push(format!("apiVersion: apps/v1\nkind: {kind}\nmetadata: {{name: app, namespace: ns}}\nspec: {{{service}selector: {{matchLabels: {{app: web}}}}, template: {{metadata: {{labels: {{app: web}}}}, spec: {{{pod_spec}}}}}}}\n"));
    }
    documents.push(format!("apiVersion: v1\nkind: ReplicationController\nmetadata: {{name: app, namespace: ns}}\nspec: {{selector: {{app: web}}, template: {{metadata: {{labels: {{app: web}}}}, spec: {{{pod_spec}}}}}}}\n"));
    documents.push("apiVersion: batch/v1\nkind: Job\nmetadata: {name: app, namespace: ns}\nspec: {template: {spec: {restartPolicy: Never, containers: [{name: app, image: i}], initContainers: [{name: side, image: i, restartPolicy: Always}]}}}\n".into());
    documents.push(cron("batch/v1","0 * * * *","").replace("containers: [{name: task, image: i}]","containers: [{name: task, image: i}]\n          initContainers: [{name: side, image: i, restartPolicy: Always}]"));
    let mut enabled = target(28)?;
    enabled
        .feature_gates
        .states
        .insert(FeatureGateId::SidecarContainers, FeatureGateState::Enabled);
    let mut disabled = enabled.clone();
    disabled
        .feature_gates
        .states
        .insert(FeatureGateId::SidecarContainers, FeatureGateState::Disabled);
    for document in documents {
        let set = resources(&document)?;
        assert!(!validate_for_target(&set, &enabled).iter().any(|f| matches!(
            f.code,
            FindingCode::NativeFieldInvalid | FindingCode::UnavailableField | FindingCode::FeatureGateRequired
        )));
        assert!(validate_for_target(&set, &disabled).iter().any(|f| matches!(
            f.code,
            FindingCode::NativeFieldInvalid | FindingCode::FeatureGateRequired
        )));
    }
    Ok(())
}
#[test]
fn explicit_gate_enable_cannot_bypass_a_stable_only_field_boundary() -> TestResult<()> {
    let mut old = target(34)?;
    old.feature_gates
        .states
        .insert(FeatureGateId::InPlacePodVerticalScaling, FeatureGateState::Enabled);
    let set = resources(&pod(
        "  containers: [{name: app, image: i, resizePolicy: [{resourceName: cpu, restartPolicy: NotRequired}]}]\n",
    ))?;
    assert!(
        validate_for_target(&set, &old)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableField)
    );
    assert!(
        !validate_for_target(&set, &target(35)?)
            .iter()
            .any(|f| matches!(f.code, FindingCode::UnavailableField | FindingCode::NativeFieldInvalid))
    );
    let mut old = target(26)?;
    old.feature_gates
        .states
        .insert(FeatureGateId::CronJobTimeZone, FeatureGateState::Enabled);
    let set = resources(&cron("batch/v1", "0 * * * *", "  timeZone: UTC\n"))?;
    assert!(
        validate_for_target(&set, &old)
            .iter()
            .any(|f| f.code == FindingCode::UnavailableField)
    );
    let set = resources(&pod(
        "  containers: [{name: app, image: i, securityContext: {procMount: Default}}]\n",
    ))?;
    assert!(
        !validate_for_target(&set, &target(20)?)
            .iter()
            .any(|f| matches!(f.code, FindingCode::UnavailableField | FindingCode::NativeFieldInvalid))
    );
    let set = resources(&pod(
        "  containers: [{name: app, image: i, securityContext: {procMount: Unmasked}}]\n",
    ))?;
    assert!(
        validate_for_target(&set, &target(37)?)
            .iter()
            .any(|f| f.code == FindingCode::UnadmittedField)
    );
    Ok(())
}
#[test]
fn heterogeneous_source_free_collection_and_duplicates_use_native_identity() -> TestResult<()> {
    use kubernetes_lens::value::LabelSelector;
    use std::collections::BTreeMap;
    let mut deployment = Deployment::default();
    deployment.metadata = Presence::Value(Metadata {
        name: Presence::Value("controller".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    });
    let mut spec = DeploymentSpec::default();
    let labels = BTreeMap::from([("app".to_owned(), "web".to_owned())]);
    spec.selector = Presence::Value(LabelSelector::from_match_labels(labels.clone()));
    let mut template = PodTemplateSpec::default();
    template.metadata = Presence::Value(Metadata {
        labels: Presence::Value(labels),
        ..Metadata::default()
    });
    template.spec = authored_pod("template", "image").spec;
    spec.template = Presence::Value(template);
    deployment.spec = Presence::Value(spec);
    let set = ResourceSet::from_authored(
        vec![authored_pod("supplied", "image").into(), deployment.into()],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .required()?;
    assert_eq!(set.documents().len(), 2);
    assert!(set.documents()[0].resource::<Pod>().is_some());
    assert!(set.documents()[1].resource::<Deployment>().is_some());
    let opts = GenerationOptions {
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    };
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let value: serde_json::Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(value["kind"], "List");
    assert_eq!(value["items"].as_array().required()?.len(), 2);
    let errors = ResourceSet::from_authored(
        vec![
            authored_pod("same", "image").into(),
            authored_pod("same", "image").into(),
        ],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .err()
    .required()?;
    assert!(errors.iter().any(|f| f.code == FindingCode::DuplicateIdentity));
    let mut value = authored_pod("namespace-absent", "image");
    let Presence::Value(metadata) = &mut value.metadata else {
        return Err("missing native metadata".into());
    };
    metadata.namespace = Presence::Absent;
    let set = ResourceSet::from_authored(vec![value.into()], &target(37)?, &AuthoringLimits::default()).required()?;
    assert!(json(&set, 37)?["metadata"].get("namespace").is_none());
    Ok(())
}

#[test]
fn native_looking_free_form_keys_are_data_not_validation_references_or_protection() -> TestResult<()> {
    use kubernetes_lens::graph::resolve_references;
    let keys = "{protocol: not-native, scheme: not-native, optional: not-native, serviceAccountName: not-native, nodeName: not-native, runtimeClassName: not-native, priorityClassName: not-native, gmsaCredentialSpec: not-native, command: not-native, limits: not-native, requests: not-native}";
    let text = pod(&format!(
        "  containers: [{{name: web, image: i, resources: {{requests: {{protocol: '1', scheme: '1'}}}}}}]\n  nodeSelector: {keys}\n  volumes: [{{name: data, csi: {{driver: fixture.example, volumeAttributes: {keys}}}}}]\n"
    )).replace("metadata: {name: app, namespace: ns}",
        &format!("metadata: {{name: app, namespace: ns, labels: {keys}, annotations: {keys}}}"));
    let set = resources(&text)?;
    let findings = validate_for_target(&set, &target(37)?);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid),
        "{findings:?}"
    );
    assert!(resolve_references(&set).edges.is_empty());
    let output_options = GenerationOptions {
        json_shape: JsonShape::SingleResource,
        ..GenerationOptions::default()
    };
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &output_options).required()?;
    let value: serde_json::Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(value["metadata"]["labels"]["protocol"], "not-native");
    assert_eq!(value["metadata"]["annotations"]["gmsaCredentialSpec"], "not-native");
    assert_eq!(value["spec"]["nodeSelector"]["serviceAccountName"], "not-native");
    assert_eq!(
        value["spec"]["volumes"][0]["csi"]["volumeAttributes"]["runtimeClassName"],
        "not-native"
    );
    assert_eq!(value["spec"]["containers"][0]["resources"]["requests"]["protocol"], "1");
    Ok(())
}

#[test]
fn actual_native_protocol_references_and_protected_fields_keep_their_bindings() -> TestResult<()> {
    use kubernetes_lens::graph::resolve_references;
    let set = resources(&pod(
        "  serviceAccountName: fixture-sa\n  containers: [{name: web, image: i, ports: [{containerPort: 8080, protocol: INVALID}]}]\n",
    ))?;
    let protocol_path = kubernetes_lens::FieldPath::parse("/spec/containers/0/ports/0/protocol")?;
    let findings = validate_for_target(&set, &target(37)?);
    assert!(
        findings.iter().any(|finding| {
            finding.code == FindingCode::NativeFieldInvalid && finding.path.as_ref() == Some(&protocol_path)
        }),
        "protocol findings: {:?}",
        findings
            .iter()
            .map(|finding| (
                finding.code,
                finding
                    .path
                    .as_ref()
                    .map(|path| path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()))
            ))
            .collect::<Vec<_>>()
    );
    assert_eq!(resolve_references(&set).edges.len(), 1);
    let set = resources(&pod(
        "  containers: [{name: web, image: i, ports: [{containerPort: 8080, protocol: TCP}], command: [private-command]}]\n",
    ))?;
    assert!(
        generate(&set, &target(37)?, OutputFormat::Json, &GenerationOptions::default())
            .err()
            .required()?
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    Ok(())
}

fn resources_with_origin(text: &str, origin: InputOrigin, minor: u8) -> TestResult<ResourceSet> {
    parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin,
            source_version: Some(KubernetesVersion::new(1, minor)?),
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()?
    .flatten_resources()
    .required()
}
fn require_schedule_finding(
    findings: &[kubernetes_lens::Finding],
    code: FindingCode,
    severity: kubernetes_lens::diagnostic::Severity,
) -> TestResult<()> {
    let path = kubernetes_lens::FieldPath::parse("/spec/schedule")?;
    assert!(
        findings.iter().any(|finding| finding.code == code
            && finding.severity == severity
            && finding.path.as_ref() == Some(&path)),
        "{findings:?}"
    );
    Ok(())
}
#[test]
fn inline_timezone_requires_explicit_creation_context_in_validation_and_generation() -> TestResult<()> {
    use kubernetes_lens::{NativeValidationIntent, diagnostic::Severity, validate_for_target_with_intent};
    for prefix in ["TZ=", "CRON_TZ="] {
        let source = cron("batch/v1", &format!("{prefix}UTC 0 * * * *"), "");
        let set = resources_with_origin(&source, InputOrigin::ClusterExport, 36)?;
        assert_eq!(
            set.documents()[0]
                .source_evidence()
                .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            source.as_bytes()
        );
        for intent in [NativeValidationIntent::Unspecified, NativeValidationIntent::Create] {
            let before = validate_for_target_with_intent(&set, &target(36)?, intent);
            assert!(!before.iter().any(|finding| matches!(
                finding.code,
                FindingCode::NativeFieldInvalid | FindingCode::NativeContextRequired
            )));
            let findings = validate_for_target_with_intent(&set, &target(37)?, intent);
            let (code, severity) = if intent == NativeValidationIntent::Create {
                (FindingCode::NativeFieldInvalid, Severity::Error)
            } else {
                (FindingCode::NativeContextRequired, Severity::Warning)
            };
            require_schedule_finding(&findings, code, severity)?;
            let mut opts = options();
            opts.validation_intent = intent;
            if intent == NativeValidationIntent::Create {
                require_schedule_finding(
                    &generate(&set, &target(37)?, OutputFormat::Json, &opts)
                        .err()
                        .required()?,
                    code,
                    severity,
                )?;
            } else {
                let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
                require_schedule_finding(artifact.findings(), code, severity)?;
                let value: serde_json::Value = serde_json::from_slice(
                    artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                )?;
                assert_eq!(value["spec"]["schedule"], format!("{prefix}UTC 0 * * * *"));
            }
        }
    }
    Ok(())
}
#[test]
fn typed_and_explicit_schedule_edits_do_not_infer_creation_or_update() -> TestResult<()> {
    use kubernetes_lens::{FieldPath, NativeValidationIntent, diagnostic::Severity, validate_for_target_with_intent};
    let original = cron("batch/v1", "0 * * * *", "");
    let mut set = resources_with_origin(&original, InputOrigin::ClusterExport, 36)?;
    let Presence::Value(spec) = &mut set.documents_mut()[0].resource_mut::<CronJobV1>().required()?.spec else {
        return Err("missing cron spec".into());
    };
    spec.schedule = Presence::Value("TZ=UTC 1 * * * *".into());
    require_schedule_finding(
        &validate_for_target(&set, &target(37)?),
        FindingCode::NativeContextRequired,
        Severity::Warning,
    )?;
    require_schedule_finding(
        &validate_for_target_with_intent(&set, &target(37)?, NativeValidationIntent::Create),
        FindingCode::NativeFieldInvalid,
        Severity::Error,
    )?;
    let schedule_path = FieldPath::parse("/spec/schedule")?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"CRON_TZ=UTC 2 * * * *\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(schedule_path.clone(), parsed)?;
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &options()).required()?;
    require_schedule_finding(
        artifact.findings(),
        FindingCode::NativeContextRequired,
        Severity::Warning,
    )?;
    assert_eq!(
        set.documents()[0]
            .source_evidence()
            .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        original.as_bytes()
    );
    set.documents_mut()[0].remove_field(schedule_path);
    let findings = validate_for_target(&set, &target(37)?);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeContextRequired)
    );
    require_schedule_finding(&findings, FindingCode::NativeFieldInvalid, Severity::Error)?;
    Ok(())
}
#[test]
fn malformed_inline_syntax_and_timezone_conflicts_remain_errors_under_both_intents() -> TestResult<()> {
    use kubernetes_lens::{NativeValidationIntent, diagnostic::Severity, validate_for_target_with_intent};
    for schedule in [
        "TZ=UTC",
        "TZ=../UTC 0 * * * *",
        "TZ=UTC 0 0 0 * * *",
        "CRON_TZ=UTC @every nonsense",
        "TZ=Europe/berlin 0 * * * *",
    ] {
        let set = resources(&cron("batch/v1", schedule, ""))?;
        for intent in [NativeValidationIntent::Unspecified, NativeValidationIntent::Create] {
            let findings = validate_for_target_with_intent(&set, &target(37)?, intent);
            assert!(findings.iter().any(|finding| finding.severity == Severity::Error));
            assert!(
                !findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeContextRequired)
            );
        }
    }
    for minor in [36, 37] {
        for intent in [NativeValidationIntent::Unspecified, NativeValidationIntent::Create] {
            let set = resources(&cron("batch/v1", "TZ=UTC 0 * * * *", "  timeZone: UTC\n"))?;
            require_schedule_finding(
                &validate_for_target_with_intent(&set, &target(minor)?, intent),
                FindingCode::NativeFieldInvalid,
                Severity::Error,
            )?;
            let ordinary = resources(&cron("batch/v1", "0 * * * *", ""))?;
            assert!(
                !validate_for_target_with_intent(&ordinary, &target(minor)?, intent)
                    .iter()
                    .any(|finding| matches!(
                        finding.code,
                        FindingCode::NativeFieldInvalid | FindingCode::NativeContextRequired
                    ))
            );
        }
    }
    Ok(())
}
fn observed_workload(api: &str, kind: &str) -> (String, String) {
    let pod_spec = "{containers: [{name: web, image: i}], volumes: [{name: scratch, ephemeral: {volumeClaimTemplate: {metadata: {uid: observed-claim, labels: {keep: authored}, futureNeighbor: retained}, spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}}}}]}";
    let pod_spec = if matches!(kind, "Job" | "CronJob") {
        pod_spec.replace("{containers:", "{restartPolicy: Never, containers:")
    } else {
        pod_spec.to_owned()
    };
    let root = format!("apiVersion: {api}\nkind: {kind}\nmetadata: {{name: observed, namespace: ns}}\n");
    if kind == "Pod" {
        return (format!("{root}spec: {pod_spec}\n"), "/spec".into());
    }
    let template = format!("{{metadata: {{uid: observed-template, labels: {{app: web}}}}, spec: {pod_spec}}}");
    if kind == "CronJob" {
        (
            format!(
                "{root}spec: {{schedule: '0 * * * *', jobTemplate: {{metadata: {{uid: observed-job}}, spec: {{template: {template}}}}}}}\n"
            ),
            "/spec/jobTemplate/spec/template/spec".into(),
        )
    } else {
        let selector = if kind == "Job" {
            ""
        } else if kind == "ReplicationController" {
            "selector: {app: web}, "
        } else {
            "selector: {matchLabels: {app: web}}, "
        };
        let service = if kind == "StatefulSet" {
            "serviceName: headless, "
        } else {
            ""
        };
        (
            format!("{root}spec: {{{selector}{service}template: {template}}}\n"),
            "/spec/template/spec".into(),
        )
    }
}
#[test]
fn exact_template_and_ephemeral_claim_observations_preserve_neighbors_across_all_bindings() -> TestResult<()> {
    use kubernetes_lens::{FieldPath, generation::OutputIntent, source::ValueOrigin};
    for (api, kind) in [
        ("v1", "Pod"),
        ("apps/v1", "Deployment"),
        ("apps/v1", "StatefulSet"),
        ("apps/v1", "DaemonSet"),
        ("apps/v1", "ReplicaSet"),
        ("v1", "ReplicationController"),
        ("batch/v1", "Job"),
        ("batch/v1", "CronJob"),
        ("batch/v1beta1", "CronJob"),
    ] {
        let minor = if api == "batch/v1beta1" { 24 } else { 37 };
        let (source, spec) = observed_workload(api, kind);
        let set = resources_with_origin(&source, InputOrigin::ClusterExport, minor)?;
        let claim = format!("{spec}/volumes/0/ephemeral/volumeClaimTemplate");
        assert_eq!(
            set.documents()[0]
                .field_evidence()
                .get(&FieldPath::parse(&format!("{claim}/metadata/uid"))?)
                .required()?
                .origin,
            ValueOrigin::Observed
        );
        let mut opts = options();
        opts.intent = OutputIntent::AuthoredIntent;
        let artifact = generate(&set, &target(minor)?, OutputFormat::Json, &opts)
            .map_err(|errors| format!("{kind} observation generation: {errors:?}"))?;
        let value: serde_json::Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert!(value.pointer(&format!("{claim}/metadata/uid")).is_none());
        assert_eq!(
            value.pointer(&format!("{claim}/metadata/labels/keep")).required()?,
            "authored"
        );
        assert_eq!(
            value.pointer(&format!("{claim}/metadata/futureNeighbor")).required()?,
            "retained"
        );
        let expected_uid_path = FieldPath::parse(&format!("{claim}/metadata/uid"))?;
        assert!(
            artifact
                .findings()
                .iter()
                .any(|finding| finding.code == FindingCode::ObservedFieldRemoved
                    && finding.path.as_ref() == Some(&expected_uid_path))
        );
        opts.intent = OutputIntent::PreserveObservation;
        let artifact = generate(&set, &target(minor)?, OutputFormat::Json, &opts)
            .map_err(|errors| format!("{kind} observation generation: {errors:?}"))?;
        let value: serde_json::Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert_eq!(
            value.pointer(&format!("{claim}/metadata/uid")).required()?,
            "observed-claim"
        );
    }
    Ok(())
}
#[test]
fn standalone_ephemeral_containers_use_original_and_effective_tree_at_the_stable_boundary() -> TestResult<()> {
    use kubernetes_lens::{FieldPath, generation::OutputIntent, source::ValueOrigin};
    let source = pod(
        "  containers: [{name: web, image: i}]\n  ephemeralContainers: [{name: debug, image: i, command: [protected-observed-marker]}]\n",
    );
    let pointer = FieldPath::parse("/spec/ephemeralContainers")?;
    for minor in [24, 25, 37] {
        let mut set = resources_with_origin(&source, InputOrigin::ClusterExport, minor)?;
        let observed = set.documents()[0].field_evidence().get(&pointer).required()?.origin == ValueOrigin::Observed;
        assert_eq!(observed, minor >= 25);
        let mut opts = options();
        opts.intent = OutputIntent::AuthoredIntent;
        let result = generate(&set, &target(minor)?, OutputFormat::Json, &opts);
        if minor >= 25 {
            let artifact = result.required()?;
            let value: serde_json::Value = serde_json::from_slice(
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            )?;
            assert!(value["spec"].get("ephemeralContainers").is_none());
            assert!(
                artifact
                    .findings()
                    .iter()
                    .any(|finding| finding.code == FindingCode::ObservedFieldRemoved
                        && finding.path.as_ref() == Some(&pointer))
            );
        } else {
            let artifact = result.required()?;
            let value: serde_json::Value = serde_json::from_slice(
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            )?;
            assert_eq!(value["spec"]["ephemeralContainers"][0]["name"], "debug");
            assert!(
                !artifact
                    .findings()
                    .iter()
                    .any(|finding| finding.code == FindingCode::ObservedFieldRemoved
                        && finding.path.as_ref() == Some(&pointer))
            );
        }
        opts.intent = OutputIntent::PreserveObservation;
        let preserved = generate(&set, &target(minor)?, OutputFormat::Json, &opts).required()?;
        let value: serde_json::Value =
            serde_json::from_slice(preserved.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert_eq!(
            value["spec"]["ephemeralContainers"][0]["command"][0],
            "protected-observed-marker"
        );
        assert!(!format!("{preserved:?}").contains("protected-observed-marker"));
        set.documents_mut()[0].remove_field(pointer.clone());
        assert!(generate(&set, &target(minor)?, OutputFormat::Json, &opts).is_ok());
    }
    Ok(())
}
#[test]
fn unsupported_template_status_and_ephemeral_containers_are_not_stripped() -> TestResult<()> {
    use kubernetes_lens::generation::OutputIntent;
    let source = deployment("")
        .replace(
            "metadata: {labels: {app: web}}",
            "metadata: {uid: observed-template, labels: {app: web}}",
        )
        .replace("    spec:\n", "    status: {unexpected: retained}\n    spec:\n")
        .replace(
            "      containers:",
            "      ephemeralContainers: [{name: debug, image: i}]\n      containers:",
        );
    let set = resources_with_origin(&source, InputOrigin::ClusterExport, 37)?;
    let mut opts = options();
    opts.intent = OutputIntent::AuthoredIntent;
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let value: serde_json::Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert!(value["spec"]["template"]["metadata"].get("uid").is_none());
    assert_eq!(value["spec"]["template"]["status"]["unexpected"], "retained");
    assert_eq!(
        value["spec"]["template"]["spec"]["ephemeralContainers"][0]["name"],
        "debug"
    );
    Ok(())
}
#[test]
fn external_common_consumer_uses_single_helper_identity_and_private_source_free_output() -> TestResult<()> {
    use kubernetes_lens::resources::common::{
        CSIVolumeSource, Container as CommonContainer, NativeTime as CommonTime,
        ObjectFieldSelector as CommonFieldSelector, PersistentVolumeClaimSpec,
        PersistentVolumeClaimTemplate as CommonClaimTemplate, PodSpec as CommonPodSpec,
        ResourceFieldSelector as CommonResourceSelector, ResourceRequirements,
        StatefulSetClaimTemplate as CommonFullClaim, Volume as CommonVolume,
    };
    use kubernetes_lens::value::{LabelSelector, Quantity};
    use std::collections::BTreeMap;
    let mut requests = ResourceRequirements::default();
    requests.requests = Presence::Value(BTreeMap::from([("storage".into(), Quantity::parse("1Gi")?)]));
    let mut claim = PersistentVolumeClaimSpec::default();
    claim.resources = Presence::Value(requests);
    claim.selector = Presence::Value(LabelSelector::default());
    let mut template = CommonClaimTemplate::default();
    template.spec = Presence::Value(claim.clone());
    let prior_template: PersistentVolumeClaimTemplate = template;
    let mut full = CommonFullClaim::default();
    full.spec = Presence::Value(claim);
    let prior_full: StatefulSetClaimTemplate = full;
    assert!(prior_template.spec.value().is_some());
    assert!(prior_full.spec.value().is_some());
    let time: NativeTime = CommonTime::parse("2024-02-29T00:00:00Z")?;
    assert!(!format!("{time:?}").contains("2024"));
    let _: ObjectFieldSelector = CommonFieldSelector::default();
    let _: ResourceFieldSelector = CommonResourceSelector::default();
    let mut volume = CommonVolume::default();
    volume.csi = Presence::Value(CSIVolumeSource::default());
    let _: Volume = volume;
    let mut native = authored_pod("consumer", "i");
    let mut container = CommonContainer::default();
    container.name = Presence::Value("web".into());
    container.image = Presence::Value("i".into());
    container.command = Presence::Value(Protected::new(vec!["private-common-command".into()]));
    let prior_container: Container = container;
    let mut spec = CommonPodSpec::default();
    spec.containers = Presence::Value(vec![prior_container]);
    native.spec = Presence::Value(spec);
    let set = ResourceSet::from_authored(vec![native.into()], &target(37)?, &AuthoringLimits::default()).required()?;
    assert!(
        generate(&set, &target(37)?, OutputFormat::Json, &GenerationOptions::default())
            .err()
            .required()?
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    assert_eq!(
        json(&set, 37)?["spec"]["containers"][0]["command"][0],
        "private-common-command"
    );
    Ok(())
}

#[test]
fn full_claim_status_and_metadata_follow_reordered_effective_tree_and_explicit_patches() -> TestResult<()> {
    use kubernetes_lens::{FieldPath, generation::OutputIntent, source::ValueOrigin};
    let source = "apiVersion: apps/v1\nkind: StatefulSet\nmetadata: {name: claims, namespace: ns}\nspec:\n  serviceName: headless\n  selector: {matchLabels: {app: web}}\n  template: {metadata: {labels: {app: web}}, spec: {containers: [{name: web, image: i}]}}\n  volumeClaimTemplates:\n  - apiVersion: v1\n    kind: PersistentVolumeClaim\n    metadata: {name: alpha, uid: alpha-observed, labels: {keep: alpha}}\n    spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 1Gi}}}\n    status: {phase: Bound}\n    futureNeighbor: retained-alpha\n  - apiVersion: v1\n    kind: PersistentVolumeClaim\n    metadata: {name: beta, uid: beta-observed, labels: {keep: beta}}\n    spec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 2Gi}}}\n    status: {phase: Pending}\n    futureNeighbor: retained-beta\n";
    let mut set = resources_with_origin(source, InputOrigin::ClusterExport, 37)?;
    let original_uid = FieldPath::parse("/spec/volumeClaimTemplates/0/metadata/uid")?;
    let original_status = FieldPath::parse("/spec/volumeClaimTemplates/0/status/phase")?;
    for path in [&original_uid, &original_status] {
        assert_eq!(
            set.documents()[0].field_evidence().get(path).required()?.origin,
            ValueOrigin::Observed
        );
    }
    let Presence::Value(spec) = &mut set.documents_mut()[0].resource_mut::<StatefulSet>().required()?.spec else {
        return Err("missing stateful spec".into());
    };
    let Presence::Value(claims) = &mut spec.volume_claim_templates else {
        return Err("missing native claims".into());
    };
    claims.swap(0, 1);
    let list_path = FieldPath::parse("/spec/volumeClaimTemplates")?;
    assert!(
        generate(&set, &target(37)?, OutputFormat::Json, &options())
            .err()
            .required()?
            .iter()
            .any(|finding| finding.code == FindingCode::MergeConflict && finding.path.as_ref() == Some(&list_path))
    );
    // Atomic-list edits with private neighbors require explicit replacement authorization.
    let original = resources_with_origin(source, InputOrigin::ClusterExport, 37)?;
    let mut replaced = json(&original, 37)?["spec"]["volumeClaimTemplates"]
        .as_array()
        .required()?
        .clone();
    replaced.swap(0, 1);
    let replacement = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &serde_json::to_vec(&replaced)?,
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(list_path, replacement)?;
    let edited_path = FieldPath::parse("/spec/volumeClaimTemplates/1/metadata/uid")?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"explicit-new-uid\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(edited_path.clone(), parsed)?;
    let mut opts = options();
    opts.intent = OutputIntent::PreserveObservation;
    let retained = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let value: serde_json::Value =
        serde_json::from_slice(retained.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(value["spec"]["volumeClaimTemplates"][0]["metadata"]["name"], "beta");
    assert_eq!(
        value["spec"]["volumeClaimTemplates"][0]["metadata"]["uid"],
        "beta-observed"
    );
    assert_eq!(
        value["spec"]["volumeClaimTemplates"][1]["metadata"]["uid"],
        "explicit-new-uid"
    );
    opts.intent = OutputIntent::AuthoredIntent;
    let stripped = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let value: serde_json::Value =
        serde_json::from_slice(stripped.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    for (index, name) in [(0, "beta"), (1, "alpha")] {
        assert!(value["spec"]["volumeClaimTemplates"][index].get("status").is_none());
        assert!(
            value["spec"]["volumeClaimTemplates"][index]["metadata"]
                .get("uid")
                .is_none()
        );
        assert_eq!(
            value["spec"]["volumeClaimTemplates"][index]["metadata"]["labels"]["keep"],
            name
        );
        assert_eq!(
            value["spec"]["volumeClaimTemplates"][index]["futureNeighbor"],
            format!("retained-{name}")
        );
    }
    assert!(stripped.findings().iter().any(
        |finding| finding.code == FindingCode::ObservedFieldRemoved && finding.path.as_ref() == Some(&edited_path)
    ));
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(
        set.documents()[0].source_evidence().reveal_raw(&access),
        source.as_bytes()
    );
    Ok(())
}

#[test]
fn qualified_label_prefixes_keep_native_selector_facts_known() -> TestResult<()> {
    use kubernetes_lens::graph::{
        GraphSubject, Reference, ReferenceContext, ReferenceScope, ReferenceTarget, RelationshipKind, Resolution,
        SubjectSelection, TemplateKind, resolve_supplied_references_for_target,
    };
    use kubernetes_lens::value::LabelSelector;
    use kubernetes_lens::{FieldPath, ResourceId, capability::KindId};
    use std::collections::BTreeMap;
    // Native qualified-label grammar caps the complete prefix at 253 bytes;
    // it does not impose a 63-byte limit on each DNS component.
    for (prefix, valid) in [
        ("a".repeat(64), true),
        ("a".repeat(253), true),
        ("a".repeat(254), false),
        (format!("{}.{}", "a".repeat(64), "b".repeat(188)), true),
        ("a..b".into(), false),
        ("Upper".into(), false),
        ("-bad".into(), false),
    ] {
        let key = format!("{prefix}/app");
        let source = format!(
            "apiVersion: v1\nkind: Pod\nmetadata: {{name: source, namespace: ns}}\nspec: {{containers: [{{name: web, image: i}}]}}\n---\napiVersion: v1\nkind: Pod\nmetadata: {{name: supplier, namespace: ns, labels: {{app: match, '{key}': match}}}}\nspec: {{containers: [{{name: web, image: i}}]}}\n---\napiVersion: apps/v1\nkind: Deployment\nmetadata: {{name: owner, namespace: ns}}\nspec: {{selector: {{matchLabels: {{app: match}}}}, template: {{metadata: {{labels: {{app: match, '{key}': match}}}}, spec: {{containers: [{{name: web, image: i}}]}}}}}}\n"
        );
        let set = resources(&source)?;
        for minor in [20, 37] {
            let selector = LabelSelector::from_match_labels(BTreeMap::from([(
                if valid { key.clone() } else { "app".into() },
                "match".into(),
            )]));
            let reference = Reference {
                from: ResourceId(0),
                path: FieldPath::parse("/spec/selector")?,
                relation: RelationshipKind::Selector,
                target: ReferenceTarget::SubjectSelector {
                    kinds: &[KindId::Pod],
                    selector,
                    selection: SubjectSelection::PodObjectsAndTemplates,
                },
                scope: ReferenceScope::SameNamespace,
            };
            let graph = resolve_supplied_references_for_target(
                &set,
                &[reference],
                &ReferenceContext::default(),
                &target(minor)?,
            );
            if valid {
                assert!(
                    matches!(&graph.edges[0].resolution,
                    Resolution::ResolvedSubjects(matched) if matched == &[
                        GraphSubject::Object { resource: ResourceId(1) },
                        GraphSubject::Template { resource: ResourceId(2),
                            path: FieldPath::parse("/spec/template")?, template_kind: TemplateKind::Pod },
                    ]),
                    "prefix length {} at 1.{minor}",
                    prefix.len()
                );
                assert!(
                    !graph
                        .findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
                );
            } else {
                assert!(matches!(&graph.edges[0].resolution,
                    Resolution::PartiallyResolvedSubjects { matched, unavailable }
                    if matched.is_empty() && unavailable.len() == 2));
            }
        }
    }
    Ok(())
}
