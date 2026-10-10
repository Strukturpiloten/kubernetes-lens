//! Independent native access expectations; no server, permission, scale or enforcement proof.
use kubernetes_lens::{
    capability::{FeatureGateId, FeatureGateState, KubernetesVersion, TargetProfile},
    diagnostic::{FieldPath, Finding, FindingCode, ResourceId},
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, OutputIntent,
        ProtectedOutput,
    },
    graph::{GraphSubject, ReferenceTarget, Resolution, resolve_references_for_target},
    model::ResourceSet,
    parse_source,
    resources::access::{
        ClusterRole, ClusterRoleBinding, HorizontalPodAutoscalerV1, HorizontalPodAutoscalerV2,
        HorizontalPodAutoscalerV2Beta1, HorizontalPodAutoscalerV2Beta2, LimitRange, Namespace, PodDisruptionBudgetV1,
        PodDisruptionBudgetV1Beta1, PodSecurityPolicy, PriorityClass, ResourceQuota, Role, RoleBinding, RuntimeClassV1,
        RuntimeClassV1Beta1, ServiceAccount,
    },
    source::{
        AuthoringLimits, DocumentFormat, EvidenceOrigin, InputOrigin, ParseLimits, SourceId, SourceInput, ValueOrigin,
    },
    validate_for_target,
    value::Presence,
};
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
trait Required<T> {
    fn required(self) -> TestResult<T>;
}
impl<T> Required<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| "missing independent access fixture evidence".into())
    }
}
impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|error| format!("{error:?}").into())
    }
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn path(pointer: &str) -> TestResult<FieldPath> {
    Ok(FieldPath::parse(pointer)?)
}
fn parsed(value: &Value, origin: InputOrigin) -> TestResult<kubernetes_lens::ParsedInput> {
    let bytes = serde_json::to_vec(value)?;
    parse_source(
        SourceInput {
            id: SourceId(73),
            format: DocumentFormat::Json,
            origin,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .required()
}
fn resources(value: &Value) -> TestResult<ResourceSet> {
    parsed(value, InputOrigin::Authored)?.flatten_resources().required()
}
fn document(api: &str, kind: &str, body: Value) -> Value {
    let mut value = json!({"apiVersion":api,"kind":kind,"metadata":{"name":"native"}});
    if [
        "ServiceAccount",
        "Role",
        "RoleBinding",
        "HorizontalPodAutoscaler",
        "PodDisruptionBudget",
        "ResourceQuota",
        "LimitRange",
    ]
    .contains(&kind)
    {
        value["metadata"]["namespace"] = json!("ns");
    }
    if let Value::Object(entries) = body {
        for (key, member) in entries {
            value[key] = member;
        }
    }
    value
}
fn role(kind: &str) -> Value {
    document(
        "rbac.authorization.k8s.io/v1",
        kind,
        json!({"rules":[{"apiGroups":[""],"resources":["pods"],"verbs":["get"],"resourceNames":["p"]}]}),
    )
}
fn binding(kind: &str) -> Value {
    document(
        "rbac.authorization.k8s.io/v1",
        kind,
        json!({"roleRef":{"apiGroup":"rbac.authorization.k8s.io","kind":if kind=="RoleBinding" {"Role"} else {"ClusterRole"},"name":"native"},"subjects":[{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"alice"}]}),
    )
}
fn hpa(api: &str) -> Value {
    let mut body = json!({"spec":{"scaleTargetRef":{"apiVersion":"apps/v1","kind":"Deployment","name":"d"},"minReplicas":1,"maxReplicas":4}});
    if api == "autoscaling/v1" {
        body["spec"]["targetCPUUtilizationPercentage"] = json!(80);
    } else {
        let source = if api == "autoscaling/v2beta1" {
            json!({"name":"cpu","targetAverageUtilization":60})
        } else {
            json!({"name":"cpu","target":{"type":"Utilization","averageUtilization":60}})
        };
        body["spec"]["metrics"] = json!([{"type":"Resource","resource":source}]);
    }
    document(api, "HorizontalPodAutoscaler", body)
}
fn pdb(api: &str) -> Value {
    document(
        api,
        "PodDisruptionBudget",
        json!({"spec":{"minAvailable":"30%","selector":{"matchLabels":{"app":"web"}}}}),
    )
}
fn psp() -> Value {
    document(
        "policy/v1beta1",
        "PodSecurityPolicy",
        json!({"spec":{"runAsUser":{"rule":"RunAsAny"},"seLinux":{"rule":"RunAsAny"},"supplementalGroups":{"rule":"RunAsAny"},"fsGroup":{"rule":"RunAsAny"},"privileged":false,"allowedHostPaths":[{"pathPrefix":"/srv/data","readOnly":true}]}}),
    )
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    }
}
fn output(set: &ResourceSet, minor: u8) -> TestResult<Value> {
    let artifact = generate(set, &target(minor)?, OutputFormat::Json, &options()).required()?;
    Ok(serde_json::from_slice(artifact.reveal_bytes(
        &ExplicitArtifactAccess::explicitly_allow_raw_artifact(),
    ))?)
}
fn has(findings: &[Finding], code: FindingCode) -> bool {
    findings.iter().any(|finding| finding.code == code)
}

#[test]
fn every_concrete_root_has_native_authoring_lists_fixed_points_and_api_boundaries() -> TestResult {
    macro_rules! root_case {($ty:ty,$value:expr,$first:expr,$last:expr)=>{{
        let value=$value;let set=resources(&value)?;
        let native=set.documents()[0].resource::<$ty>().required()?.clone();
        assert!(!format!("{native:?}").contains("native"));
        let authored=ResourceSet::from_authored(vec![native.into()],&target($first)?,&AuthoringLimits::default()).map_err(|findings| format!("{} {}: {:?}",value["apiVersion"],value["kind"],findings.iter().map(|finding| (finding.code,finding.path.as_ref().map(|path| path.reveal(&kubernetes_lens::source::ExplicitSourceAccess::explicitly_allow_raw_source())))).collect::<Vec<_>>()))?;
        assert_eq!(authored.documents()[0].source_evidence().origin,EvidenceOrigin::NativeAuthored);
        let field=authored.documents()[0].field_evidence().get(&path("/metadata/name")?).required()?;
        assert_eq!(field.origin,ValueOrigin::Generated);assert!(field.position.is_none());
        let first=output(&set,$first)?;assert_eq!(first,output(&resources(&first)?,$first)?);
        assert_eq!(first,output(&authored,$first)?);
        assert_eq!(value["apiVersion"],output(&set,$last)?["apiVersion"]);
        let list=json!({"apiVersion":value["apiVersion"],"kind":format!("{}List",value["kind"].as_str().required()?),"items":[value]});
        assert_eq!(resources(&list)?.documents().len(),1);
        if $first>20 {assert!(has(&validate_for_target(&set,&target($first-1)?),FindingCode::UnavailableApi));}
        if $last<37 {assert!(has(&validate_for_target(&set,&target($last+1)?),FindingCode::UnavailableApi));}
    }};}
    root_case!(Namespace, document("v1", "Namespace", json!({})), 20, 37);
    root_case!(
        ServiceAccount,
        document(
            "v1",
            "ServiceAccount",
            json!({"automountServiceAccountToken":false,"imagePullSecrets":[{"name":"pull"}],"secrets":[{"name":"token"}]})
        ),
        20,
        37
    );
    root_case!(Role, role("Role"), 20, 37);
    root_case!(ClusterRole, role("ClusterRole"), 20, 37);
    root_case!(RoleBinding, binding("RoleBinding"), 20, 37);
    root_case!(ClusterRoleBinding, binding("ClusterRoleBinding"), 20, 37);
    root_case!(HorizontalPodAutoscalerV1, hpa("autoscaling/v1"), 20, 37);
    root_case!(HorizontalPodAutoscalerV2, hpa("autoscaling/v2"), 23, 37);
    root_case!(HorizontalPodAutoscalerV2Beta1, hpa("autoscaling/v2beta1"), 20, 24);
    root_case!(HorizontalPodAutoscalerV2Beta2, hpa("autoscaling/v2beta2"), 20, 25);
    root_case!(PodDisruptionBudgetV1, pdb("policy/v1"), 21, 37);
    root_case!(PodDisruptionBudgetV1Beta1, pdb("policy/v1beta1"), 20, 24);
    root_case!(
        ResourceQuota,
        document(
            "v1",
            "ResourceQuota",
            json!({"spec":{"hard":{"requests.cpu":"2","count/pods":"8"}}})
        ),
        20,
        37
    );
    root_case!(
        LimitRange,
        document(
            "v1",
            "LimitRange",
            json!({"spec":{"limits":[{"type":"Container","min":{"cpu":"100m"},"max":{"cpu":"2"}}]}})
        ),
        20,
        37
    );
    root_case!(
        PriorityClass,
        document(
            "scheduling.k8s.io/v1",
            "PriorityClass",
            json!({"value":-10,"globalDefault":false})
        ),
        20,
        37
    );
    root_case!(
        RuntimeClassV1,
        document(
            "node.k8s.io/v1",
            "RuntimeClass",
            json!({"handler":"runc","scheduling":{"nodeSelector":{"arch":"amd64"}}})
        ),
        20,
        37
    );
    root_case!(
        RuntimeClassV1Beta1,
        document("node.k8s.io/v1beta1", "RuntimeClass", json!({"handler":"runc"})),
        20,
        24
    );
    root_case!(PodSecurityPolicy, psp(), 20, 24);
    Ok(())
}
#[test]
fn private_unknowns_survive_typed_edits_and_protected_output_requires_explicit_access() -> TestResult {
    let mut value = hpa("autoscaling/v2");
    value["spec"]["scaleTargetRef"]["privateFuture"] = json!("access-private-value");
    let mut set = resources(&value)?;
    let Presence::Value(spec) = &mut set.documents_mut()[0]
        .resource_mut::<HorizontalPodAutoscalerV2>()
        .required()?
        .spec
    else {
        return Err("missing HPA native spec".into());
    };
    spec.max_replicas = Presence::Value(7);
    let generated = output(&set, 37)?;
    assert_eq!(generated["spec"]["maxReplicas"], 7);
    assert_eq!(
        generated["spec"]["scaleTargetRef"]["privateFuture"],
        "access-private-value"
    );
    assert!(!format!("{set:?}").contains("access-private-value"));
    let denied = GenerationOptions {
        protected_output: ProtectedOutput::Deny,
        ..options()
    };
    assert!(has(
        &generate(&set, &target(37)?, OutputFormat::Json, &denied)
            .err()
            .required()?,
        FindingCode::ProtectedOutputDenied
    ));
    Ok(())
}
#[test]
fn rbac_scope_subjects_and_aggregation_are_distinct_supplied_relationships() -> TestResult {
    let mut bound = binding("RoleBinding");
    bound["subjects"] = json!([{"kind":"User","apiGroup":"rbac.authorization.k8s.io","name":"private-user"},{"kind":"ServiceAccount","name":"sa","namespace":"ns"}]);
    let mut sa = document("v1", "ServiceAccount", json!({}));
    sa["metadata"]["name"] = json!("sa");
    let mut selected = role("ClusterRole");
    selected["metadata"]["name"] = json!("selected");
    selected["metadata"]["labels"] = json!({"aggregate":"yes"});
    let mut aggregate = role("ClusterRole");
    aggregate["aggregationRule"] = json!({"clusterRoleSelectors":[{"matchLabels":{"aggregate":"yes"}}]});
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[role("Role"),bound,sa,selected,aggregate]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| edge.reference.from == ResourceId(1) && matches!(edge.resolution, Resolution::External(_)))
    );
    assert!(graph.edges.iter().any(|edge|edge.reference.from==ResourceId(1)&&matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if subjects==&[GraphSubject::Object {resource:ResourceId(2)}])));
    assert!(graph.edges.iter().any(|edge|edge.reference.from==ResourceId(4)&&matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if subjects==&[GraphSubject::Object {resource:ResourceId(3)}])));
    assert!(!format!("{graph:?}").contains("private-user"));
    let mut invalid = role("Role");
    invalid["rules"] = json!([{"verbs":["get"],"nonResourceURLs":["/healthz"]}]);
    assert!(has(
        &validate_for_target(&resources(&invalid)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    let mut invalid = binding("ClusterRoleBinding");
    invalid["roleRef"]["kind"] = json!("Role");
    invalid["subjects"] = json!([{"kind":"ServiceAccount","name":"sa"}]);
    let findings = validate_for_target(&resources(&invalid)?, &target(37)?);
    assert!(has(&findings, FindingCode::NativeFieldInvalid));
    Ok(())
}

#[test]
fn pdb_budgets_and_source_api_empty_selector_semantics_remain_distinct() -> TestResult {
    let mut pod = document(
        "v1",
        "Pod",
        json!({"spec":{"containers":[{"name":"main","image":"example/app:v1"}]}}),
    );
    pod["metadata"]["namespace"] = json!("ns");
    for (api, matches_all) in [("policy/v1", true), ("policy/v1beta1", false)] {
        for selector in [None, Some(Value::Null), Some(json!({}))] {
            let mut value = pdb(api);
            value["spec"]["minAvailable"] = Value::Null;
            value["spec"].as_object_mut().required()?.remove("selector");
            if let Some(selector) = selector.clone() {
                value["spec"]["selector"] = selector;
            }
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,pod]}))?;
            let graph = resolve_references_for_target(&set, &target(24)?);
            let selector_edges = graph
                .edges
                .iter()
                .filter(|edge| matches!(edge.reference.target, ReferenceTarget::SubjectSelector { .. }))
                .collect::<Vec<_>>();
            if selector.as_ref() == Some(&json!({})) {
                assert_eq!(selector_edges.len(), 1);
                assert_eq!(
                    matches!(&selector_edges[0].resolution,Resolution::ResolvedSubjects(subjects) if subjects==&[GraphSubject::Object {resource:ResourceId(1)}]),
                    matches_all
                );
            } else {
                assert!(selector_edges.is_empty());
            }
        }
    }
    for invalid in [
        json!({"minAvailable":1,"maxUnavailable":1}),
        json!({"minAvailable":-1}),
        json!({"minAvailable":"101%"}),
        json!({"maxUnavailable":"garbage"}),
    ] {
        let value = document("policy/v1", "PodDisruptionBudget", json!({"spec":invalid}));
        assert!(has(
            &validate_for_target(&resources(&value)?, &target(37)?),
            FindingCode::NativeFieldInvalid
        ));
    }
    let neither = document("policy/v1", "PodDisruptionBudget", json!({"spec":{}}));
    assert!(!has(
        &validate_for_target(&resources(&neither)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}
#[test]
fn pdb_selectors_keep_incomplete_pod_evidence_partial_and_recheck_effective_edits() -> TestResult {
    let policy = pdb("policy/v1");
    let mut pod = document(
        "v1",
        "Pod",
        json!({"spec":{"containers":[{"name":"main","image":"example/app:v1"}]}}),
    );
    pod["metadata"]["namespace"] = json!("ns");
    pod["metadata"]["labels"] = Value::Null;
    let mut set = resources(&json!({"apiVersion":"v1","kind":"List","items":[policy,pod]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(graph.edges.iter().any(|edge|matches!(&edge.resolution,Resolution::PartiallyResolvedSubjects {matched,unavailable} if matched.is_empty()&&unavailable.iter().any(|gap|gap.resource==ResourceId(1)))));
    set.documents_mut()[1]
        .set_field_from_source(
            path("/metadata/labels")?,
            parsed(&json!({"app":"web"}), InputOrigin::Authored)?,
        )
        .required()?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(graph.edges.iter().any(|edge|matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if subjects==&[GraphSubject::Object {resource:ResourceId(1)}])));
    Ok(())
}
#[test]
fn hpa_unions_replica_bounds_and_missing_scale_predicates_are_visible() -> TestResult {
    for (field, value) in [("minReplicas", json!(5)), ("maxReplicas", json!(0))] {
        let mut invalid = hpa("autoscaling/v2");
        invalid["spec"][field] = value;
        assert!(has(
            &validate_for_target(&resources(&invalid)?, &target(37)?),
            FindingCode::NativeFieldInvalid
        ));
    }
    let mut invalid = hpa("autoscaling/v2");
    invalid["spec"]["metrics"][0]["pods"] =
        json!({"metric":{"name":"throughput"},"target":{"type":"AverageValue","averageValue":"5"}});
    assert!(has(
        &validate_for_target(&resources(&invalid)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    invalid["spec"]["metrics"][0].as_object_mut().required()?.remove("pods");
    invalid["spec"]["metrics"][0]["resource"]["target"]["averageValue"] = json!("2");
    assert!(has(
        &validate_for_target(&resources(&invalid)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    let mut omitted = hpa("autoscaling/v1");
    omitted["spec"]["scaleTargetRef"]
        .as_object_mut()
        .required()?
        .remove("apiVersion");
    let set = resources(&omitted)?;
    let findings = validate_for_target(&set, &target(37)?);
    assert!(has(&findings, FindingCode::UnadmittedField));
    assert!(!has(&findings, FindingCode::NativeFieldInvalid));
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| matches!(edge.reference.target, ReferenceTarget::External { .. })
                && matches!(edge.resolution, Resolution::External(_) | Resolution::Unsupported(_)))
    );
    // Naming an existing supplied object still does not establish the scale subresource.
    let mut nonscalable = hpa("autoscaling/v1");
    nonscalable["spec"]["scaleTargetRef"] = json!({"apiVersion":"v1","kind":"ServiceAccount","name":"native"});
    let set = resources(
        &json!({"apiVersion":"v1","kind":"List","items":[nonscalable,document("v1","ServiceAccount",json!({}))]}),
    )?;
    assert!(has(
        &validate_for_target(&set, &target(37)?),
        FindingCode::UnadmittedField
    ));
    Ok(())
}
#[test]
fn gate_and_version_boundaries_win_over_optional_hpa_and_policy_values() -> TestResult {
    let mut value = hpa("autoscaling/v2");
    value["spec"]["minReplicas"] = json!(0);
    let findings = validate_for_target(&resources(&value)?, &target(37)?);
    let minimum = path("/spec/minReplicas")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::UnadmittedField && finding.path.as_ref() == Some(&minimum))
    );
    value["spec"]["minReplicas"] = json!(1);
    value["spec"]["metrics"] = json!([{"type":"ContainerResource","containerResource":{"name":"cpu","container":"main","target":{"type":"Utilization","averageUtilization":60}}}]);
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(29)?),
        FindingCode::FeatureGateRequired
    ));
    assert!(!has(
        &validate_for_target(&resources(&value)?, &target(30)?),
        FindingCode::FeatureGateRequired
    ));
    let mut value = pdb("policy/v1");
    value["spec"]["unhealthyPodEvictionPolicy"] = json!("AlwaysAllow");
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(25)?),
        FindingCode::UnavailableField
    ));
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(30)?),
        FindingCode::FeatureGateRequired
    ));
    assert!(!has(
        &validate_for_target(&resources(&value)?, &target(31)?),
        FindingCode::FeatureGateRequired
    ));
    let value = psp();
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(25)?),
        FindingCode::UnavailableApi
    ));
    Ok(())
}
#[test]
fn hpa_metric_gate_selects_container_resource_without_gating_ordinary_metrics() -> TestResult {
    let ordinary = [
        json!({"type":"Resource","resource":{"name":"cpu","target":{"type":"Utilization","averageUtilization":60}}}),
        json!({"type":"Object","object":{"describedObject":{"apiVersion":"v1","kind":"Service","name":"svc"},"metric":{"name":"requests"},"target":{"type":"Value","value":"10"}}}),
    ];
    for minor in [23, 29] {
        for metric in &ordinary {
            let mut value = hpa("autoscaling/v2");
            value["spec"]["metrics"] = json!([metric]);
            for setting in [None, Some(FeatureGateState::Disabled)] {
                let mut profile = target(minor)?;
                if let Some(setting) = setting {
                    profile
                        .feature_gates
                        .states
                        .insert(FeatureGateId::HPAContainerMetrics, setting);
                }
                let set = resources(&value)?;
                let findings = validate_for_target(&set, &profile);
                assert!(
                    !has(&findings, FindingCode::FeatureGateRequired),
                    "ordinary metric {minor}: {findings:?}"
                );
                assert!(!has(&findings, FindingCode::NativeFieldInvalid));
                generate(&set, &profile, OutputFormat::Json, &options()).required()?;
            }
        }
    }
    let mut value = hpa("autoscaling/v2");
    value["spec"]["metrics"] = json!([{"type":"ContainerResource","containerResource":{"name":"cpu","container":"main","target":{"type":"Utilization","averageUtilization":60}}}]);
    let set = resources(&value)?;
    for setting in [None, Some(FeatureGateState::Enabled), Some(FeatureGateState::Disabled)] {
        let mut profile = target(29)?;
        if let Some(setting) = setting {
            profile
                .feature_gates
                .states
                .insert(FeatureGateId::HPAContainerMetrics, setting);
        }
        let findings = validate_for_target(&set, &profile);
        for pointer in ["/spec/metrics/0/type", "/spec/metrics/0/containerResource"] {
            let expected = path(pointer)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::FeatureGateRequired
                        && finding.path.as_ref() == Some(&expected))
            );
        }
        assert!(has(
            &generate(&set, &profile, OutputFormat::Json, &options())
                .err()
                .required()?,
            FindingCode::FeatureGateRequired
        ));
    }
    for minor in [30, 32] {
        let findings = validate_for_target(&set, &target(minor)?);
        assert!(!has(&findings, FindingCode::FeatureGateRequired));
        assert!(!has(&findings, FindingCode::NativeFieldInvalid));
        assert_eq!(output(&set, minor)?["spec"]["metrics"][0]["type"], "ContainerResource");
    }
    value["spec"]["metrics"][0]["type"] = json!("UnknownMetric");
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(32)?),
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}
#[test]
fn both_pdb_policy_values_follow_field_availability_and_stable_only_admission() -> TestResult {
    let expected = path("/spec/unhealthyPodEvictionPolicy")?;
    for policy in ["IfHealthyBudget", "AlwaysAllow"] {
        let mut value = pdb("policy/v1");
        value["spec"]["unhealthyPodEvictionPolicy"] = json!(policy);
        let set = resources(&value)?;
        assert!(has(
            &validate_for_target(&set, &target(25)?),
            FindingCode::UnavailableField
        ));
        for setting in [None, Some(FeatureGateState::Enabled), Some(FeatureGateState::Disabled)] {
            let mut profile = target(30)?;
            if let Some(setting) = setting {
                profile
                    .feature_gates
                    .states
                    .insert(FeatureGateId::PDBUnhealthyPodEvictionPolicy, setting);
            }
            let findings = validate_for_target(&set, &profile);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::FeatureGateRequired
                        && finding.path.as_ref() == Some(&expected))
            );
            assert!(has(
                &generate(&set, &profile, OutputFormat::Json, &options())
                    .err()
                    .required()?,
                FindingCode::FeatureGateRequired
            ));
        }
        for minor in [31, 33] {
            let findings = validate_for_target(&set, &target(minor)?);
            assert!(!has(&findings, FindingCode::FeatureGateRequired));
            assert!(!has(&findings, FindingCode::NativeFieldInvalid));
            assert_eq!(output(&set, minor)?["spec"]["unhealthyPodEvictionPolicy"], policy);
        }
    }
    let mut invalid = pdb("policy/v1");
    invalid["spec"]["unhealthyPodEvictionPolicy"] = json!("UnknownPolicy");
    assert!(has(
        &validate_for_target(&resources(&invalid)?, &target(33)?),
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}
#[test]
fn scale_to_zero_gate_matches_numeric_zero_without_coercing_strings() -> TestResult {
    let expected = path("/spec/minReplicas")?;
    for (api, minor) in [
        ("autoscaling/v1", 20),
        ("autoscaling/v2beta1", 20),
        ("autoscaling/v2beta2", 20),
        ("autoscaling/v2", 29),
    ] {
        let mut value = hpa(api);
        value["spec"]["minReplicas"] = json!(0);
        let findings = validate_for_target(&resources(&value)?, &target(minor)?);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::FeatureGateRequired
                    && finding.path.as_ref() == Some(&expected)),
            "{api} {minor}"
        );
        value["spec"]["minReplicas"] = json!("0");
        let findings = parsed(&value, InputOrigin::Authored)?
            .flatten_resources()
            .err()
            .required()?;
        assert!(has(&findings, FindingCode::NativeFieldInvalid));
        assert!(!findings.iter().any(
            |finding| finding.code == FindingCode::FeatureGateRequired && finding.path.as_ref() == Some(&expected)
        ));
    }
    Ok(())
}
#[test]
fn fail_index_action_retains_its_value_predicate_gate() -> TestResult {
    let expected = path("/spec/podFailurePolicy/rules/0/action")?;
    let mut value = document(
        "batch/v1",
        "Job",
        json!({"spec":{"template":{"spec":{"restartPolicy":"Never","containers":[{"name":"main","image":"example/app:v1"}]}},"podFailurePolicy":{"rules":[{"action":"Count","onPodConditions":[{"type":"DisruptionTarget","status":"True"}]}]}}}),
    );
    for minor in [32, 33] {
        let findings = validate_for_target(&resources(&value)?, &target(minor)?);
        assert!(!findings.iter().any(
            |finding| finding.code == FindingCode::FeatureGateRequired && finding.path.as_ref() == Some(&expected)
        ));
    }
    value["spec"]["podFailurePolicy"]["rules"][0]["action"] = json!("FailIndex");
    let findings = validate_for_target(&resources(&value)?, &target(32)?);
    assert!(findings.iter().any(|finding| finding.code == FindingCode::FeatureGateRequired && finding.path.as_ref() == Some(&expected)));
    let findings = validate_for_target(&resources(&value)?, &target(33)?);
    assert!(!findings.iter().any(|finding| finding.code == FindingCode::FeatureGateRequired && finding.path.as_ref() == Some(&expected)));
    assert!(has(&findings, FindingCode::NativeFieldInvalid));
    Ok(())
}
#[test]
fn hpa_utilization_preserves_positive_int32_targets_above_one_hundred() -> TestResult {
    for (api, first) in [("autoscaling/v2beta2", 20), ("autoscaling/v2", 23)] {
        for minor in [first, if api.ends_with("v2beta2") { 25 } else { 37 }] {
            for utilization in [101, 200, i32::MAX] {
                let mut value = hpa(api);
                value["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"] = json!(utilization);
                let set = resources(&value)?;
                assert!(!has(
                    &validate_for_target(&set, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
                let generated = output(&set, minor)?;
                assert_eq!(
                    generated["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"],
                    utilization
                );
                assert!(!has(
                    &validate_for_target(&resources(&generated)?, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
            }
            for utilization in [0, -1] {
                let mut invalid = hpa(api);
                invalid["spec"]["metrics"][0]["resource"]["target"]["averageUtilization"] = json!(utilization);
                assert!(has(
                    &validate_for_target(&resources(&invalid)?, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
            }
        }
    }
    Ok(())
}
#[test]
fn rbac_external_subject_namespace_is_preserved_without_namespaced_user_resolution() -> TestResult {
    for kind in ["RoleBinding", "ClusterRoleBinding"] {
        for subject in ["User", "Group"] {
            let mut value = binding(kind);
            if kind == "ClusterRoleBinding" {
                value["roleRef"]["kind"] = json!("ClusterRole");
            }
            value["subjects"] = json!([{"kind":subject,"apiGroup":"rbac.authorization.k8s.io","name":"external-subject","namespace":"supplied-subject-namespace"}]);
            let set = resources(&value)?;
            for minor in [20, 37] {
                assert!(!has(
                    &validate_for_target(&set, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
                let generated = output(&set, minor)?;
                assert_eq!(generated["subjects"][0]["namespace"], "supplied-subject-namespace");
                assert!(!has(
                    &validate_for_target(&resources(&generated)?, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
                let graph = resolve_references_for_target(&set, &target(minor)?);
                let expected = path("/subjects/0")?;
                assert!(
                    graph
                        .edges
                        .iter()
                        .any(|edge| edge.reference.path == expected
                            && matches!(edge.resolution, Resolution::External(_)))
                );
            }
            value["subjects"][0]["apiGroup"] = json!("wrong.example");
            assert!(has(
                &validate_for_target(&resources(&value)?, &target(37)?),
                FindingCode::NativeFieldInvalid
            ));
        }
    }
    Ok(())
}
#[test]
fn hpa_missing_or_malformed_api_never_becomes_a_kindless_same_name_lookup() -> TestResult {
    let expected = path("/spec/scaleTargetRef")?;
    for api in [None, Some(""), Some("apps/v1/extra")] {
        let mut value = hpa("autoscaling/v1");
        value["spec"]["scaleTargetRef"] = json!({"kind":"Deployment","name":"shared"});
        if let Some(api) = api {
            value["spec"]["scaleTargetRef"]["apiVersion"] = json!(api);
        }
        let mut pod = document(
            "v1",
            "Pod",
            json!({"spec":{"containers":[{"name":"main","image":"example/app:v1"}]}}),
        );
        pod["metadata"]["name"] = json!("shared");
        pod["metadata"]["namespace"] = json!("ns");
        let mut deployment = document(
            "apps/v1",
            "Deployment",
            json!({"spec":{"selector":{"matchLabels":{"app":"web"}},"template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"main","image":"example/app:v1"}]}}}}),
        );
        deployment["metadata"]["name"] = json!("shared");
        deployment["metadata"]["namespace"] = json!("ns");
        for items in [json!([value, pod]), json!([value, pod, deployment])] {
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":items}))?;
            let graph = resolve_references_for_target(&set, &target(37)?);
            let edge = graph
                .edges
                .iter()
                .find(|edge| edge.reference.from == ResourceId(0) && edge.reference.path == expected)
                .required()?;
            assert!(matches!(edge.reference.target, ReferenceTarget::External { .. }));
            assert!(matches!(
                edge.resolution,
                Resolution::External(_) | Resolution::Unsupported(_)
            ));
        }
    }
    Ok(())
}
#[test]
fn historical_host_path_prefixes_preserve_spelling_and_reject_parent_components() -> TestResult {
    let expected = path("/spec/allowedHostPaths/0/pathPrefix")?;
    for prefix in [
        "var/data",
        "/var/data",
        "./var/./data",
        "var//data",
        "var/.../data",
        "/",
    ] {
        let mut value = psp();
        value["spec"]["allowedHostPaths"][0]["pathPrefix"] = json!(prefix);
        let set = resources(&value)?;
        for minor in [20, 24] {
            assert!(!has(
                &validate_for_target(&set, &target(minor)?),
                FindingCode::NativeFieldInvalid
            ));
            let generated = output(&set, minor)?;
            assert_eq!(generated["spec"]["allowedHostPaths"][0]["pathPrefix"], prefix);
            assert!(!has(
                &validate_for_target(&resources(&generated)?, &target(minor)?),
                FindingCode::NativeFieldInvalid
            ));
        }
        assert!(has(
            &validate_for_target(&set, &target(25)?),
            FindingCode::UnavailableApi
        ));
    }
    for prefix in ["", "..", "../var", "var/../data", "/var/../etc", "var/.."] {
        let mut value = psp();
        value["spec"]["allowedHostPaths"][0]["pathPrefix"] = json!(prefix);
        let set = resources(&value)?;
        for minor in [20, 24] {
            let findings = validate_for_target(&set, &target(minor)?);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref() == Some(&expected))
            );
            assert!(has(
                &generate(&set, &target(minor)?, OutputFormat::Json, &options())
                    .err()
                    .required()?,
                FindingCode::NativeFieldInvalid
            ));
        }
    }
    Ok(())
}
#[test]
fn runtime_tolerations_preserve_empty_defaults_and_require_exists_for_empty_keys() -> TestResult {
    for (api, last) in [("node.k8s.io/v1beta1", 24), ("node.k8s.io/v1", 37)] {
        for toleration in [
            json!({"key":"example.org/node","operator":"","effect":"","value":"selected"}),
            json!({"key":"example.org/node","effect":""}),
            json!({"key":"","operator":"Exists","effect":""}),
            json!({"operator":"Exists"}),
        ] {
            let value = document(
                api,
                "RuntimeClass",
                json!({"handler":"runc","scheduling":{"tolerations":[toleration]}}),
            );
            let set = resources(&value)?;
            for minor in [20, last] {
                assert!(!has(
                    &validate_for_target(&set, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
                let generated = output(&set, minor)?;
                assert_eq!(generated["scheduling"]["tolerations"][0], toleration);
                assert!(!has(
                    &validate_for_target(&resources(&generated)?, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
            }
        }
        for toleration in [
            json!({}),
            json!({"operator":"Equal"}),
            json!({"key":""}),
            json!({"key":"","operator":"Equal"}),
            json!({"key":"bad/key/extra","operator":"Exists"}),
            json!({"key":"node","value":"bad value"}),
        ] {
            let value = document(
                api,
                "RuntimeClass",
                json!({"handler":"runc","scheduling":{"tolerations":[toleration]}}),
            );
            let set = resources(&value)?;
            for minor in [20, last] {
                assert!(has(
                    &validate_for_target(&set, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
                assert!(has(
                    &generate(&set, &target(minor)?, OutputFormat::Json, &options())
                        .err()
                        .required()?,
                    FindingCode::NativeFieldInvalid
                ));
            }
        }
    }
    Ok(())
}
#[test]
fn service_account_reference_values_are_preserved_without_invented_admission_errors() -> TestResult {
    for length in [64, 253] {
        let name = "a".repeat(length);
        let value = document(
            "v1",
            "ServiceAccount",
            json!({"secrets":[{"name":name,"kind":"ConfigMap","apiVersion":"custom.example/v2","namespace":"elsewhere"}],"imagePullSecrets":[{"name":name}]}),
        );
        let set = resources(&value)?;
        for minor in [20, 37] {
            let findings = validate_for_target(&set, &target(minor)?);
            assert!(!has(&findings, FindingCode::NativeFieldInvalid));
            assert!(has(&findings, FindingCode::UnadmittedField));
            let generated = output(&set, minor)?;
            assert_eq!(generated["secrets"], value["secrets"]);
            assert_eq!(generated["imagePullSecrets"], value["imagePullSecrets"]);
            assert!(!has(
                &validate_for_target(&resources(&generated)?, &target(minor)?),
                FindingCode::NativeFieldInvalid
            ));
            let graph = resolve_references_for_target(&set, &target(minor)?);
            let expected = path("/secrets/0")?;
            assert!(graph.edges.iter().any(|edge| edge.reference.path == expected
                && matches!(edge.resolution, Resolution::External(_) | Resolution::Unsupported(_))));
        }
    }
    Ok(())
}
#[test]
fn rbac_service_account_subject_names_use_the_total_subdomain_envelope() -> TestResult {
    let expected = path("/subjects/0/name")?;
    for kind in ["RoleBinding", "ClusterRoleBinding"] {
        for (name, valid) in [
            ("a".repeat(64), true),
            ("a".repeat(253), true),
            ("a".repeat(254), false),
            ("Bad_Name".into(), false),
            ("bad..name".into(), false),
        ] {
            let mut value = binding(kind);
            if kind == "ClusterRoleBinding" {
                value["roleRef"]["kind"] = json!("ClusterRole");
            }
            value["subjects"] = json!([{"kind":"ServiceAccount","apiGroup":"","name":name,"namespace":"ns"}]);
            let set = resources(&value)?;
            for minor in [20, 37] {
                let findings = validate_for_target(&set, &target(minor)?);
                assert_eq!(
                    findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                            && finding.path.as_ref() == Some(&expected)),
                    !valid
                );
                if valid {
                    let generated = output(&set, minor)?;
                    assert_eq!(generated["subjects"][0]["name"], name);
                    assert!(!has(
                        &validate_for_target(&resources(&generated)?, &target(minor)?),
                        FindingCode::NativeFieldInvalid
                    ));
                } else {
                    assert!(has(
                        &generate(&set, &target(minor)?, OutputFormat::Json, &options())
                            .err()
                            .required()?,
                        FindingCode::NativeFieldInvalid
                    ));
                }
            }
        }
    }
    Ok(())
}
#[test]
fn policy_rule_strings_are_retained_separately_from_native_array_and_scope_rules() -> TestResult {
    for rules in [
        json!([{"verbs":[""],"nonResourceURLs":["metrics","/a*b",""]}]),
        json!([{"verbs":[""],"apiGroups":[""],"resources":[""],"resourceNames":[""]}]),
    ] {
        let value = document("rbac.authorization.k8s.io/v1", "ClusterRole", json!({"rules":rules}));
        let set = resources(&value)?;
        for minor in [20, 37] {
            assert!(!has(
                &validate_for_target(&set, &target(minor)?),
                FindingCode::NativeFieldInvalid
            ));
            let generated = output(&set, minor)?;
            assert_eq!(generated["rules"], rules);
            assert!(!has(
                &validate_for_target(&resources(&generated)?, &target(minor)?),
                FindingCode::NativeFieldInvalid
            ));
        }
    }
    for (kind, rules) in [
        (
            "ClusterRole",
            json!([{"verbs":[],"apiGroups":[""],"resources":["pods"]}]),
        ),
        (
            "ClusterRole",
            json!([{"verbs":["get"],"nonResourceURLs":["/healthz"],"resources":["pods"],"apiGroups":[""]}]),
        ),
        ("Role", json!([{"verbs":["get"],"nonResourceURLs":["/healthz"]}])),
    ] {
        let value = document("rbac.authorization.k8s.io/v1", kind, json!({"rules":rules}));
        assert!(has(
            &validate_for_target(&resources(&value)?, &target(37)?),
            FindingCode::NativeFieldInvalid
        ));
    }
    Ok(())
}
fn assert_invalid_generation(set: &ResourceSet, minor: u8) -> TestResult {
    assert!(has(
        &generate(set, &target(minor)?, OutputFormat::Json, &options())
            .err()
            .required()?,
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}

#[test]
fn hpa_target_types_preserve_native_permissive_leaves_and_actual_source_requirements() -> TestResult {
    let cases = [
        (
            "Object",
            json!({"describedObject":{"apiVersion":"v1","kind":"Service","name":"svc"},"metric":{"name":"requests"}}),
            json!({"type":"Value","value":"1","averageValue":"2","averageUtilization":200}),
            true,
        ),
        (
            "Pods",
            json!({"metric":{"name":"requests"}}),
            json!({"type":"Value","averageValue":"2","value":"1","averageUtilization":200}),
            true,
        ),
        (
            "Resource",
            json!({"name":"cpu"}),
            json!({"type":"Value","averageUtilization":200,"value":"1"}),
            true,
        ),
        (
            "External",
            json!({"metric":{"name":"requests"}}),
            json!({"type":"Utilization","averageValue":"2","averageUtilization":200}),
            true,
        ),
        (
            "Object",
            json!({"describedObject":{"apiVersion":"v1","kind":"Service","name":"svc"},"metric":{"name":"requests"}}),
            json!({"type":"Value","averageUtilization":200}),
            false,
        ),
        (
            "Pods",
            json!({"metric":{"name":"requests"}}),
            json!({"type":"Value","value":"1"}),
            false,
        ),
        (
            "Resource",
            json!({"name":"cpu"}),
            json!({"type":"Utilization","averageUtilization":200,"averageValue":"2"}),
            false,
        ),
        (
            "External",
            json!({"metric":{"name":"requests"}}),
            json!({"type":"Value","value":"1","averageValue":"2"}),
            false,
        ),
        (
            "Pods",
            json!({"metric":{"name":"requests"}}),
            json!({"type":"Value","averageValue":"0"}),
            false,
        ),
        (
            "Resource",
            json!({"name":"cpu"}),
            json!({"type":"Utilization","averageUtilization":0}),
            false,
        ),
    ];
    for (api, minors) in [("autoscaling/v2beta2", [20, 25]), ("autoscaling/v2", [23, 37])] {
        for (kind, source, metric_target, valid) in &cases {
            let member = kind.to_ascii_lowercase();
            let mut body = source.clone();
            body["target"] = metric_target.clone();
            let mut metric = json!({"type":kind});
            metric[member.as_str()] = body;
            let mut value = hpa(api);
            value["spec"]["metrics"] = json!([metric]);
            let set = resources(&value)?;
            for minor in minors {
                let findings = validate_for_target(&set, &target(minor)?);
                assert_eq!(
                    has(&findings, FindingCode::NativeFieldInvalid),
                    !valid,
                    "{api} {kind} {minor}: {findings:?}"
                );
                if *valid {
                    let generated = output(&set, minor)?;
                    assert_eq!(
                        generated["spec"]["metrics"][0][member.as_str()]["target"],
                        *metric_target
                    );
                    assert!(!has(
                        &validate_for_target(&resources(&generated)?, &target(minor)?),
                        FindingCode::NativeFieldInvalid
                    ));
                } else {
                    assert_invalid_generation(&set, minor)?;
                }
            }
        }
    }
    Ok(())
}
#[test]
fn beta1_object_conversion_retains_both_values_and_requires_positive_target_value() -> TestResult {
    for (values, valid) in [
        (json!({"targetValue":"1"}), true),
        (json!({"targetValue":"1","averageValue":"2"}), true),
        (json!({"targetValue":"1","averageValue":null}), true),
        (json!({"averageValue":"2"}), false),
        (json!({"targetValue":null,"averageValue":"2"}), false),
        (json!({"targetValue":"0","averageValue":"2"}), false),
        (json!({"targetValue":"-1","averageValue":"2"}), false),
        (json!({"targetValue":"1","averageValue":"0"}), false),
        (json!({"targetValue":"1","averageValue":"-1"}), false),
    ] {
        let mut source = json!({"target":{"apiVersion":"v1","kind":"Service","name":"svc"},"metricName":"requests"});
        for (key, value) in values.as_object().required()? {
            source[key] = value.clone();
        }
        let mut value = hpa("autoscaling/v2beta1");
        value["spec"]["metrics"] = json!([{"type":"Object","object":source}]);
        let set = resources(&value)?;
        for minor in [20, 24] {
            let findings = validate_for_target(&set, &target(minor)?);
            assert_eq!(
                has(&findings, FindingCode::NativeFieldInvalid),
                !valid,
                "{minor}: {findings:?}"
            );
            if valid {
                let generated = output(&set, minor)?;
                assert_eq!(generated["spec"]["metrics"][0]["object"], source);
                assert!(!has(
                    &validate_for_target(&resources(&generated)?, &target(minor)?),
                    FindingCode::NativeFieldInvalid
                ));
            } else {
                assert!(has(
                    &generate(&set, &target(minor)?, OutputFormat::Json, &options())
                        .err()
                        .required()?,
                    FindingCode::NativeFieldInvalid
                ));
            }
        }
    }
    Ok(())
}
#[test]
fn signed_priority_reserved_values_and_runtime_handler_have_independent_rules() -> TestResult {
    let value = document(
        "scheduling.k8s.io/v1",
        "PriorityClass",
        json!({"value":-2_147_483_648,"preemptionPolicy":"Never"}),
    );
    assert!(!has(
        &validate_for_target(&resources(&value)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    for (name, value) in [
        ("system-unknown", 5),
        ("system-node-critical", 1),
        ("native", 1_000_000_001),
    ] {
        let mut value = document("scheduling.k8s.io/v1", "PriorityClass", json!({"value":value}));
        value["metadata"]["name"] = json!(name);
        assert!(has(
            &validate_for_target(&resources(&value)?, &target(37)?),
            FindingCode::NativeFieldInvalid
        ));
    }
    let mut builtin = document("scheduling.k8s.io/v1", "PriorityClass", json!({"value":2_000_001_000}));
    builtin["metadata"]["name"] = json!("system-node-critical");
    assert!(!has(
        &validate_for_target(&resources(&builtin)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    let value = document("node.k8s.io/v1", "RuntimeClass", json!({"handler":"Bad_Handler"}));
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    let value = document("node.k8s.io/v1", "RuntimeClass", json!({"handler":"runc"}));
    let graph = resolve_references_for_target(&resources(&value)?, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::External(_)))
    );
    Ok(())
}
#[test]
fn quota_limit_selected_arithmetic_and_historical_policy_boundaries_are_distinct() -> TestResult {
    let quota = document(
        "v1",
        "ResourceQuota",
        json!({"spec":{"hard":{"requests.memory":"1Gi"},"scopeSelector":{"matchExpressions":[{"scopeName":"PriorityClass","operator":"In","values":["high"]}]}}}),
    );
    let set = resources(&quota)?;
    let findings = validate_for_target(&set, &target(37)?);
    assert!(!has(&findings, FindingCode::UnadmittedField));
    assert!(!has(&findings, FindingCode::NativeFieldInvalid));
    assert_eq!(output(&set, 37)?["spec"]["hard"]["requests.memory"], "1Gi");
    let limits = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container","min":{"memory":"2Gi"},"max":{"memory":"1Gi"},"maxLimitRequestRatio":{"cpu":"2"}}]}}),
    );
    assert!(has(
        &validate_for_target(&resources(&limits)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    let mut unverified = limits;
    unverified["spec"]["limits"][0]["min"]["memory"] = json!("-1Gi");
    let findings = validate_for_target(&resources(&unverified)?, &target(37)?);
    assert!(has(&findings, FindingCode::UnadmittedField));
    assert!(!has(&findings, FindingCode::NativeFieldInvalid));
    let mut historical = psp();
    historical["spec"]["allowedCapabilities"] = json!(["CHOWN"]);
    historical["spec"]["volumes"] = json!(["configMap"]);
    let set = resources(&historical)?;
    assert!(has(
        &validate_for_target(&set, &target(24)?),
        FindingCode::UnadmittedField
    ));
    assert_eq!(output(&set, 24)?["spec"]["allowedCapabilities"], json!(["CHOWN"]));
    historical["spec"]["hostPorts"] = json!([{"min":70000,"max":70001}]);
    assert!(has(
        &validate_for_target(&resources(&historical)?, &target(24)?),
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}
#[test]
fn exact_root_observations_preserve_lifecycle_and_aggregated_rules() -> TestResult {
    for (kind, body) in [
        ("Namespace", json!({"spec":{"finalizers":["private-lifecycle"]}})),
        ("ResourceQuota", json!({"spec":{"hard":{"pods":"8"}}})),
    ] {
        let mut value = document("v1", kind, body);
        value["status"] = json!({"phase":"Active","privateObserved":"secret-observation"});
        let set = parsed(&value, InputOrigin::ClusterExport)?
            .flatten_resources()
            .required()?;
        let options = GenerationOptions {
            intent: OutputIntent::AuthoredIntent,
            ..options()
        };
        let artifact = generate(&set, &target(37)?, OutputFormat::Json, &options).required()?;
        let result: Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert!(result.get("status").is_none());
        if kind == "Namespace" {
            assert_eq!(result["spec"]["finalizers"], json!(["private-lifecycle"]));
        }
    }
    let mut value = role("ClusterRole");
    value["status"] = json!({"private":"retained-status"});
    value["aggregationRule"] = json!({"clusterRoleSelectors":[{}]});
    let set = parsed(&value, InputOrigin::ClusterExport)?
        .flatten_resources()
        .required()?;
    let opts = GenerationOptions {
        intent: OutputIntent::AuthoredIntent,
        ..options()
    };
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let result: Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(result["status"]["private"], "retained-status");
    assert_eq!(result["rules"], value["rules"]);
    Ok(())
}
#[test]
fn source_free_budgets_and_native_failures_keep_exact_resource_attribution() -> TestResult {
    let mut value = hpa("autoscaling/v2");
    value["spec"]["maxReplicas"] = json!(0);
    let set = resources(&value)?;
    let findings = validate_for_target(&set, &target(37)?);
    let max_path = path("/spec/maxReplicas")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                && finding.path.as_ref() == Some(&max_path)
                && finding.resource == Some(ResourceId(0)))
    );
    let native = set.documents()[0]
        .resource::<HorizontalPodAutoscalerV2>()
        .required()?
        .clone();
    let limits = AuthoringLimits {
        max_resources: 0,
        ..AuthoringLimits::default()
    };
    assert!(ResourceSet::from_authored(vec![native.into()], &target(37)?, &limits).is_err());
    Ok(())
}

fn processing_terminal(findings: &[Finding]) {
    let terminals = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(terminals.len(), 1);
    assert!(terminals[0].path.is_none());
}

#[test]
fn actual_namespace_and_service_account_obey_lower_public_operation_limits() -> TestResult {
    use kubernetes_lens::{
        NativeValidationIntent,
        graph::{ReferenceContext, resolve_references_with_context_for_target},
        processing::NativeProcessingLimits,
        validate_for_target_with_limits,
    };
    let labels = (0..256)
        .map(|index| (format!("private-{index}"), json!("access-private-payload")))
        .collect::<serde_json::Map<_, _>>();
    let secrets = (0..256)
        .map(|index| json!({"name":format!("access-private-payload-{index}")}))
        .collect::<Vec<_>>();
    let target = target(37)?;
    for value in [
        json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"ns","labels":labels}}),
        document("v1", "ServiceAccount", json!({"secrets":secrets})),
    ] {
        let set = resources(&value)?;
        assert!(validate_for_target(&set, &target).is_empty());
        let ceiling = NativeProcessingLimits {
            max_payload_bytes: 512,
            ..NativeProcessingLimits::default()
        };
        let findings = validate_for_target_with_limits(&set, &target, NativeValidationIntent::Unspecified, &ceiling);
        processing_terminal(&findings);
        assert!(!format!("{findings:?}").contains("access-private-payload"));
        let errors = generate(
            &set,
            &target,
            OutputFormat::Json,
            &GenerationOptions {
                processing: Some(ceiling),
                ..options()
            },
        )
        .err()
        .required()?;
        processing_terminal(&errors);
        assert!(!format!("{errors:?}").contains("access-private-payload"));
        assert_eq!(output(&set, 37)?, value);
        for limits in [
            NativeProcessingLimits {
                max_processing_units: 0,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_processing_units: 1,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_payload_bytes: 0,
                ..NativeProcessingLimits::default()
            },
        ] {
            let graph = resolve_references_with_context_for_target(
                &set,
                &ReferenceContext {
                    processing: Some(limits),
                    ..ReferenceContext::default()
                },
                &target,
            );
            processing_terminal(&graph.findings);
            assert!(graph.edges.is_empty());
            assert!(!format!("{graph:?}").contains("access-private-payload"));
        }
    }
    Ok(())
}

#[test]
fn actual_service_account_unknown_reports_stop_at_the_inherited_report_limit() -> TestResult {
    use kubernetes_lens::{
        NativeValidationIntent, processing::NativeProcessingLimits, validate_for_target_with_limits,
    };
    let items = (0..100)
        .map(|index| json!({"name":format!("s{index}"),"privateFuture":"access-private-scope"}))
        .collect::<Vec<_>>();
    let set = resources(&document("v1", "ServiceAccount", json!({"secrets":items})))?;
    let target = target(37)?;
    let ordinary = validate_for_target(&set, &target);
    assert_eq!(
        ordinary
            .iter()
            .filter(|finding| finding.code == FindingCode::UnadmittedField)
            .count(),
        100
    );
    for entries in [0, 1] {
        let findings = validate_for_target_with_limits(
            &set,
            &target,
            NativeValidationIntent::Unspecified,
            &NativeProcessingLimits {
                max_report_entries: entries,
                ..NativeProcessingLimits::default()
            },
        );
        processing_terminal(&findings);
        assert_eq!(findings.len(), entries + 1);
        if entries == 1 {
            assert_eq!(findings[0].code, FindingCode::UnadmittedField);
            assert_eq!(findings[0].path, Some(path("/secrets/0")?));
        }
        assert!(!format!("{findings:?}").contains("access-private-scope"));
    }
    Ok(())
}

#[test]
fn historical_policy_strategy_rules_and_ranges_follow_the_reviewed_floor() -> TestResult {
    let accepted = [
        ("seLinux", json!({"rule":"MustRunAs"})),
        ("runAsUser", json!({"rule":"MustRunAs"})),
        (
            "runAsUser",
            json!({"rule":"MustRunAsNonRoot","ranges":[{"min":0,"max":0}]}),
        ),
        ("runAsGroup", Value::Null),
        ("runAsGroup", json!({"rule":"RunAsAny"})),
        (
            "runAsGroup",
            json!({"rule":"MayRunAs","ranges":[{"min":0,"max":9_223_372_036_854_775_807_i64}]}),
        ),
        ("runAsGroup", json!({"rule":"MustRunAs","ranges":[{"min":0,"max":0}]})),
        ("fsGroup", json!({"rule":"MustRunAs"})),
        ("fsGroup", json!({"rule":"MayRunAs"})),
        ("supplementalGroups", json!({"rule":"MustRunAs"})),
        ("supplementalGroups", json!({"rule":"MayRunAs"})),
    ];
    for (key, strategy) in accepted {
        let mut value = psp();
        value["spec"][key] = strategy;
        let findings = validate_for_target(&resources(&value)?, &target(24)?);
        assert!(
            !has(&findings, FindingCode::NativeFieldInvalid),
            "accepted {key}: {:?}",
            findings
                .iter()
                .map(|finding| (
                    finding.code,
                    finding.path.as_ref().map(|path| path
                        .reveal(&kubernetes_lens::source::ExplicitSourceAccess::explicitly_allow_raw_source()))
                ))
                .collect::<Vec<_>>()
        );
    }
    let rejected = [
        ("seLinux", json!({"rule":"MayRunAs"})),
        ("runAsUser", json!({"rule":"MayRunAs"})),
        (
            "runAsGroup",
            json!({"rule":"MustRunAsNonRoot","ranges":[{"min":0,"max":1}]}),
        ),
        ("runAsGroup", json!({"rule":"RunAsAny","ranges":[{"min":0,"max":1}]})),
        ("runAsGroup", json!({"rule":"MustRunAs"})),
        ("runAsGroup", json!({"rule":"MayRunAs"})),
        ("fsGroup", json!({"rule":"MustRunAsNonRoot"})),
        ("supplementalGroups", json!({"rule":"MustRunAsNonRoot"})),
    ];
    for (key, strategy) in rejected {
        let mut value = psp();
        value["spec"][key] = strategy;
        assert!(
            has(
                &validate_for_target(&resources(&value)?, &target(24)?),
                FindingCode::NativeFieldInvalid
            ),
            "rejected {key}"
        );
    }
    for key in ["runAsUser", "runAsGroup", "fsGroup", "supplementalGroups"] {
        for range in [
            json!({"min":-1,"max":1}),
            json!({"min":2,"max":1}),
            json!({"min":0,"max":-1}),
        ] {
            let mut value = psp();
            value["spec"][key] = json!({"rule":"MustRunAs","ranges":[range]});
            assert!(has(
                &validate_for_target(&resources(&value)?, &target(24)?),
                FindingCode::NativeFieldInvalid
            ));
        }
    }
    Ok(())
}
#[test]
fn historical_policy_capabilities_are_literal_conflicts_without_a_whitelist() -> TestResult {
    let accepted = [
        json!({"allowedCapabilities":["ARBITRARY_native","CHOWN"],"requiredDropCapabilities":["chown"]}),
        json!({"allowedCapabilities":["CHOWN"],"requiredDropCapabilities":["ALL"]}),
        json!({"allowedCapabilities":["*"],"requiredDropCapabilities":[]}),
        json!({"defaultAddCapabilities":["NEW_PRIVATE_CAP"],"allowedCapabilities":["NEW_PRIVATE_CAP"]}),
    ];
    for capabilities in accepted {
        let mut value = psp();
        for (key, member) in capabilities.as_object().required()? {
            value["spec"][key] = member.clone();
        }
        let findings = validate_for_target(&resources(&value)?, &target(24)?);
        assert!(!has(&findings, FindingCode::NativeFieldInvalid));
        assert!(!has(&findings, FindingCode::UnadmittedField));
        assert_eq!(output(&resources(&value)?, 24)?["spec"], value["spec"]);
    }
    for (capabilities, expected) in [
        (
            json!({"allowedCapabilities":["*"],"requiredDropCapabilities":["CHOWN"]}),
            "/spec/requiredDropCapabilities",
        ),
        (
            json!({"allowedCapabilities":["CHOWN"],"requiredDropCapabilities":["CHOWN"]}),
            "/spec/allowedCapabilities/0",
        ),
        (
            json!({"defaultAddCapabilities":["CHOWN"],"requiredDropCapabilities":["CHOWN"]}),
            "/spec/defaultAddCapabilities/0",
        ),
    ] {
        let mut value = psp();
        for (key, member) in capabilities.as_object().required()? {
            value["spec"][key] = member.clone();
        }
        let expected = path(expected)?;
        let findings = validate_for_target(&resources(&value)?, &target(24)?);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                    && finding.path.as_ref() == Some(&expected))
        );
    }
    let mut value = psp();
    value["spec"]["volumes"] = json!(["ephemeral", "ARBITRARY"]);
    let findings = validate_for_target(&resources(&value)?, &target(24)?);
    assert!(has(&findings, FindingCode::UnadmittedField));
    assert!(!has(&findings, FindingCode::NativeFieldInvalid));
    Ok(())
}

#[path = "access/native_rules.rs"]
mod native_rules;
