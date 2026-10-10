use super::*;
use kubernetes_lens::{
    resources::networking::*,
    source::ExplicitSourceAccess,
    value::{IntOrString, Presence},
};
#[test]
fn service_unknown_neighbors_follow_typed_nonkey_edit_and_deterministic_generation() -> TestResult<()> {
    let mut value = service();
    value["spec"]["ports"][0]["futurePortField"] = json!("private-neighbor");
    value["futureRoot"] = json!({"port":123});
    let bytes = serde_json::to_vec(&value)?;
    let mut set = resources(&value)?;
    let Presence::Value(spec) = &mut set.documents_mut()[0].resource_mut::<Service>().required()?.spec else {
        return Err("missing service spec".into());
    };
    let Presence::Value(ports) = &mut spec.ports else {
        return Err("missing ports".into());
    };
    ports[0].target_port = Presence::Value(IntOrString::Int(8080));
    let result = output(&set, 37)?;
    assert_eq!(result["spec"]["ports"][0]["futurePortField"], "private-neighbor");
    assert_eq!(result["spec"]["ports"][0]["targetPort"], 8080);
    assert_eq!(result["futureRoot"]["port"], 123);
    assert_eq!(result, output(&set, 37)?);
    assert_eq!(
        set.documents()[0]
            .source_evidence()
            .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        bytes
    );
    Ok(())
}
#[test]
fn omitted_tcp_service_merge_keeps_absence_and_unknown_descendants() -> TestResult<()> {
    let mut value = service();
    value["spec"]["ports"][0].as_object_mut().required()?.remove("protocol");
    value["spec"]["ports"][0]["futurePortField"] = json!("retained");
    let mut set = resources(&value)?;
    let Presence::Value(spec) = &mut set.documents_mut()[0].resource_mut::<Service>().required()?.spec else {
        return Err("missing service spec".into());
    };
    let Presence::Value(ports) = &mut spec.ports else {
        return Err("missing ports".into());
    };
    ports[0].target_port = Presence::Value(IntOrString::Int(8080));
    let result = output(&set, 37)?;
    assert!(
        !result["spec"]["ports"][0]
            .as_object()
            .required()?
            .contains_key("protocol")
    );
    assert_eq!(result["spec"]["ports"][0]["futurePortField"], "retained");
    assert_eq!(result["spec"]["ports"][0]["targetPort"], 8080);
    Ok(())
}
#[test]
fn atomic_endpoint_edits_refuse_unknown_loss_until_explicit_replacement() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["future"] = json!("private-neighbor");
    let mut set = resources(&value)?;
    let Presence::Value(endpoints) = &mut set.documents_mut()[0]
        .resource_mut::<EndpointSliceV1>()
        .required()?
        .endpoints
    else {
        return Err("missing endpoints".into());
    };
    endpoints[0].hostname = Presence::Value("edited".to_owned());
    let findings = generate(&set, &target(37)?, OutputFormat::Json, &options())
        .err()
        .required()?;
    assert!(has(&findings, FindingCode::MergeConflict, "/endpoints")?);
    value["endpoints"][0]["hostname"] = json!("edited");
    let bytes = serde_json::to_vec(&value["endpoints"])?;
    let replacement = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(FieldPath::parse("/endpoints")?, replacement)?;
    let result = output(&set, 37)?;
    assert_eq!(result["endpoints"][0]["future"], "private-neighbor");
    assert_eq!(result["endpoints"][0]["hostname"], "edited");
    Ok(())
}
#[test]
fn unadmitted_endport_hints_and_topology_are_retained_with_findings() -> TestResult<()> {
    let mut policy = policy();
    policy["spec"]["ingress"][0]["ports"] = json!([{"port":80,"endPort":90}]);
    let mut slice = slice("discovery.k8s.io/v1");
    slice["endpoints"][0]["hints"] = json!({"forZones":[{"name":"zone"}]});
    slice["endpoints"][0]["deprecatedTopology"] = json!({"node":"private-topology"});
    for (value, path) in [
        (&policy, "/spec/ingress/0/ports/0/endPort"),
        (&slice, "/endpoints/0/hints"),
        (&slice, "/endpoints/0/deprecatedTopology"),
    ] {
        let set = resources(value)?;
        let findings = validate_for_target(&set, &target(37)?);
        assert!(
            has(&findings, FindingCode::UnadmittedField, path)?,
            "{path}: {findings:?}"
        );
        assert_eq!(&output(&set, 37)?, value);
    }
    Ok(())
}
#[test]
fn unselected_traffic_distribution_is_retained_but_explicit_preservation_cannot_admit_it() -> TestResult<()> {
    use kubernetes_lens::diagnostic::Severity;
    let mut value = service();
    value["spec"]["trafficDistribution"] = json!("PreferSameZone");
    let bytes = serde_json::to_vec(&value)?;
    let set = resources(&value)?;
    let findings = validate_for_target(&set, &target(37)?);
    assert!(has(
        &findings,
        FindingCode::UnadmittedField,
        "/spec/trafficDistribution"
    )?);
    let Presence::Value(spec) = &set.documents()[0].resource::<Service>().required()?.spec else {
        return Err("missing retained Service spec".into());
    };
    assert_eq!(spec.traffic_distribution, Presence::Value("PreferSameZone".to_owned()));
    for policy in [
        GenerationOptions::default(),
        GenerationOptions {
            opaque_fields: OpaqueFieldPolicy::Block,
            ..options()
        },
        options(),
    ] {
        let errors = generate(&set, &target(37)?, OutputFormat::Json, &policy)
            .err()
            .required()?;
        let path = FieldPath::parse("/spec/trafficDistribution")?;
        assert!(errors.iter().any(|finding| finding.code == FindingCode::UnadmittedField
            && finding.severity == Severity::Error
            && finding.path.as_ref() == Some(&path)));
        assert_eq!(
            set.documents()[0]
                .source_evidence()
                .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            bytes
        );
    }
    Ok(())
}
#[test]
fn optional_null_and_absence_do_not_materialize_readiness_protocol_or_selectors() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["conditions"] = json!({"ready":null});
    value["ports"] = json!([{"port":null}]);
    let result = output(&resources(&value)?, 37)?;
    assert_eq!(result["ports"][0]["port"], Value::Null);
    assert!(!result["ports"][0].as_object().required()?.contains_key("protocol"));
    assert_eq!(result["endpoints"][0]["conditions"]["ready"], Value::Null);
    let mut service = service();
    service["spec"]["selector"] = Value::Null;
    let set = resources(&service)?;
    let Presence::Value(spec) = &set.documents()[0].resource::<Service>().required()?.spec else {
        return Err("missing service".into());
    };
    assert!(matches!(spec.selector, Presence::Null));
    Ok(())
}
#[test]
fn freeform_native_looking_keys_do_not_become_semantic_controls() -> TestResult<()> {
    let mut value = service();
    value["metadata"]["labels"] = json!({"protocol":"INVALID","port":"0","scope":"unrelated"});
    value["spec"]["selector"] = json!({"protocol":"INVALID","port":"0"});
    valid(&value, 37)?;
    assert_eq!(
        output(&resources(&value)?, 37)?["spec"]["selector"]["protocol"],
        "INVALID"
    );
    Ok(())
}
#[test]
fn networking_debug_findings_and_default_output_hide_sensitive_markers() -> TestResult<()> {
    let marker = "secret-network-marker";
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["hostname"] = json!(marker);
    value["metadata"]["annotations"] = json!({"note":marker});
    let set = resources(&value)?;
    let doc = &set.documents()[0];
    assert!(!format!("{:?}", doc.resource::<EndpointSliceV1>()).contains(marker));
    assert!(!format!("{:?}", validate_for_target(&set, &target(37)?)).contains(marker));
    let failure = generate(&set, &target(37)?, OutputFormat::Json, &GenerationOptions::default())
        .err()
        .required()?;
    assert!(
        failure
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    assert!(!format!("{failure:?}").contains(marker));
    assert_eq!(output(&set, 37)?["endpoints"][0]["hostname"], marker);
    Ok(())
}

#[test]
fn stable_topology_is_exportable_only_as_unchanged_source_backed_observation() -> TestResult<()> {
    use kubernetes_lens::generation::OutputIntent;
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["deprecatedTopology"] = json!({"node":"private-topology"});
    let mut set = resources(&value)?;
    assert_eq!(
        output(&set, 37)?["endpoints"][0]["deprecatedTopology"],
        value["endpoints"][0]["deprecatedTopology"]
    );
    let desired = GenerationOptions {
        intent: OutputIntent::AuthoredIntent,
        ..options()
    };
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &desired).required()?;
    let result: Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert!(result["endpoints"][0].get("deprecatedTopology").is_none());
    assert!(has(
        artifact.findings(),
        FindingCode::ObservedFieldRemoved,
        "/endpoints/0/deprecatedTopology"
    )?);
    let native = set.documents_mut()[0].resource_mut::<EndpointSliceV1>().required()?;
    let Presence::Value(endpoints) = &mut native.endpoints else {
        return Err("missing endpoints".into());
    };
    let Presence::Value(topology) = &mut endpoints[0].deprecated_topology else {
        return Err("missing topology".into());
    };
    topology.insert("node".to_owned(), "attempted-write".to_owned());
    let findings = generate(&set, &target(37)?, OutputFormat::Json, &options())
        .err()
        .required()?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::UnadmittedField
                && finding.severity == kubernetes_lens::diagnostic::Severity::Error)
    );
    let baseline = resources(&value)?;
    let native = baseline.documents()[0]
        .resource::<EndpointSliceV1>()
        .required()?
        .clone();
    let authored = ResourceSet::from_authored(
        vec![native.into()],
        &target(37)?,
        &kubernetes_lens::source::AuthoringLimits::default(),
    )
    .required()?;
    assert!(generate(&authored, &target(37)?, OutputFormat::Json, &options()).is_err());
    Ok(())
}
