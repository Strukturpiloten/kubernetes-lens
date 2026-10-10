//! Independent static expectations; no native server or oracle execution.
use super::*;
use kubernetes_lens::{NativeValidationIntent as Intent, validate_for_target_with_intent};

fn checks(value: &Value, minor: u8, intent: Intent) -> TestResult<Vec<Finding>> {
    Ok(validate_for_target_with_intent(
        &resources(value)?,
        &target(minor)?,
        intent,
    ))
}
fn accepted(value: &Value, minor: u8) -> TestResult<()> {
    let findings = checks(value, minor, Intent::Create)?;
    assert!(
        !findings.iter().any(|f| f.code == FindingCode::NativeFieldInvalid),
        "{findings:?}"
    );
    Ok(())
}
fn invalid_at(value: &Value, minor: u8, path: &str) -> TestResult<()> {
    assert!(
        has(
            &checks(value, minor, Intent::Create)?,
            FindingCode::NativeFieldInvalid,
            path
        )?,
        "{path}"
    );
    Ok(())
}
#[test]
fn headless_externalname_and_front_port_grammars_match_distinct_native_roles() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = service();
        value["spec"] = json!({"clusterIP":"None"});
        accepted(&value, minor)?;
        value["spec"] = json!({});
        invalid_at(&value, minor, "/spec/ports")?;
        value["spec"] = json!({"type":"ExternalName","externalName":"service.example."});
        accepted(&value, minor)?;
        assert_eq!(
            output(&resources(&value)?, minor)?["spec"]["externalName"],
            json!("service.example.")
        );
        value["spec"]["externalName"] = json!("service.example..");
        invalid_at(&value, minor, "/spec/externalName")?;
        for name in ["123", "abcdefghijklmnop"] {
            value = service();
            value["spec"]["ports"][0]["name"] = json!(name);
            accepted(&value, minor)?;
            value["spec"]["ports"][0]["targetPort"] = json!(name);
            invalid_at(&value, minor, "/spec/ports/0/targetPort")?;
        }
    }
    Ok(())
}
#[test]
fn service_authored_defaults_remain_explicit_with_context_and_round_trip() -> TestResult<()> {
    for target_port in [json!(0), json!("")] {
        let mut value = service();
        value["spec"]["type"] = json!("");
        value["spec"]["sessionAffinity"] = json!("");
        value["spec"]["ports"][0]["protocol"] = json!("");
        value["spec"]["ports"][0]["targetPort"] = target_port;
        value["spec"]["sessionAffinityConfig"] = json!({"clientIP":{"timeoutSeconds":-1}});
        for minor in [20, 37] {
            accepted(&value, minor)?;
            let findings = checks(&value, minor, Intent::Create)?;
            for path in [
                "/spec/type",
                "/spec/sessionAffinity",
                "/spec/ports/0/protocol",
                "/spec/ports/0/targetPort",
                "/spec/sessionAffinityConfig",
            ] {
                assert!(has(&findings, FindingCode::NativeContextRequired, path)?);
            }
            assert_eq!(output(&resources(&value)?, minor)?["spec"], value["spec"]);
        }
    }
    let mut value = service();
    value["spec"]["sessionAffinity"] = json!("ClientIP");
    accepted(&value, 37)?;
    value["spec"]["sessionAffinityConfig"] = json!({"clientIP":{}});
    accepted(&value, 37)?;
    value["spec"]["sessionAffinityConfig"]["clientIP"]["timeoutSeconds"] = json!(0);
    invalid_at(&value, 37, "/spec/sessionAffinityConfig/clientIP/timeoutSeconds")?;
    Ok(())
}
#[test]
fn service_dual_stack_checks_families_without_guessing_clusterip_normalization() -> TestResult<()> {
    let mut value = service();
    value["spec"]["clusterIP"] = json!("10.0.0.1");
    value["spec"]["clusterIPs"] = json!(["10.0.0.1", "10.0.0.2"]);
    invalid_at(&value, 37, "/spec/clusterIPs/1")?;
    value["spec"]["clusterIPs"] = json!(["10.0.0.1", "2001:db8::1"]);
    value["spec"]["ipFamilies"] = json!(["IPv4", "IPv6"]);
    accepted(&value, 37)?;
    value["spec"]["ipFamilies"] = json!(["IPv6", "IPv4"]);
    invalid_at(&value, 37, "/spec/ipFamilies/0")?;
    value["spec"]["ipFamilies"] = json!(["IPv4"]);
    invalid_at(&value, 37, "/spec/ipFamilies")?;
    value["spec"]["ipFamilies"] = json!(["IPv4", "IPv6"]);
    value["spec"].as_object_mut().required()?.remove("clusterIP");
    assert!(has(
        &checks(&value, 37, Intent::Create)?,
        FindingCode::NativeContextRequired,
        "/spec/clusterIPs"
    )?);
    assert!(!has(
        &checks(&value, 37, Intent::Create)?,
        FindingCode::NativeFieldInvalid,
        "/spec/clusterIPs"
    )?);
    for field in ["clusterIPs", "ipFamilies", "ipFamilyPolicy"] {
        value = service();
        value["spec"]["type"] = json!("ExternalName");
        value["spec"]["externalName"] = json!("service.example");
        value["spec"][field] = match field {
            "clusterIPs" => json!(["10.0.0.1"]),
            "ipFamilies" => json!(["IPv4"]),
            _ => json!("SingleStack"),
        };
        invalid_at(&value, 37, &format!("/spec/{field}"))?;
    }
    value["spec"]["ipFamilyPolicy"] = Value::Null;
    accepted(&value, 37)?;
    Ok(())
}
#[test]
fn service_ranges_external_addresses_and_nodeport_keys_have_native_boundaries() -> TestResult<()> {
    let mut value = service();
    value["spec"]["loadBalancerSourceRanges"] = json!(["10.0.0.0/8"]);
    invalid_at(&value, 37, "/spec/loadBalancerSourceRanges")?;
    value["spec"]["type"] = json!("LoadBalancer");
    accepted(&value, 37)?;
    value = service();
    value["spec"]["externalIPs"] = json!(["10.0.0.1", "10.0.0.1", "224.1.2.3", "255.255.255.255"]);
    accepted(&value, 37)?;
    for address in ["127.0.0.1", "0.0.0.0", "169.254.1.1", "224.0.0.1", "ff02::1"] {
        value["spec"]["externalIPs"] = json!([address]);
        invalid_at(&value, 37, "/spec/externalIPs/0")?;
    }
    value = service();
    value["spec"]["type"] = json!("NodePort");
    value["spec"]["ports"] =
        json!([{"name":"one","port":80,"nodePort":30000},{"name":"two","port":81,"nodePort":30000,"protocol":"TCP"}]);
    invalid_at(&value, 37, "/spec/ports/1/nodePort")?;
    value["spec"]["ports"][1]["protocol"] = json!("UDP");
    accepted(&value, 37)?;
    value["spec"]["ports"][0]["protocol"] = json!("");
    value["spec"]["ports"][1]["protocol"] = json!("TCP");
    invalid_at(&value, 37, "/spec/ports/1/nodePort")?;
    Ok(())
}
#[test]
fn loadbalancer_port_10250_has_a_one_33_boundary() -> TestResult<()> {
    let mut value = service();
    value["spec"]["type"] = json!("LoadBalancer");
    value["spec"]["ports"][0]["port"] = json!(10250);
    for minor in [20, 32] {
        invalid_at(&value, minor, "/spec/ports/0/port")?;
    }
    for minor in [33, 37] {
        accepted(&value, minor)?;
    }
    value["spec"]["type"] = json!("ClusterIP");
    accepted(&value, 20)?;
    Ok(())
}
#[test]
fn endpoints_subsets_front_names_and_special_ip_predicate_are_distinct() -> TestResult<()> {
    let mut value = document("v1", "Endpoints", json!({"subsets":[]}));
    accepted(&value, 37)?;
    value["subsets"] = json!([{}]);
    invalid_at(&value, 37, "/subsets/0")?;
    value["subsets"] = json!([{"addresses":[{"ip":"10.0.0.1"}],"ports":[{"port":80},{"port":81}]}]);
    invalid_at(&value, 37, "/subsets/0/ports/0/name")?;
    value["subsets"][0]["ports"] = json!([{"name":"123","port":80},{"name":"abcdefghijklmnop","port":81}]);
    accepted(&value, 37)?;
    for address in ["0.0.0.0", "127.0.0.1", "169.254.1.1", "224.0.0.1"] {
        value["subsets"][0]["addresses"][0]["ip"] = json!(address);
        invalid_at(&value, 20, "/subsets/0/addresses/0/ip")?;
    }
    for address in ["224.1.2.3", "255.255.255.255"] {
        value["subsets"][0]["addresses"][0]["ip"] = json!(address);
        accepted(&value, 37)?;
    }
    Ok(())
}
#[test]
fn endpoint_slice_port_default_names_and_topology_cardinality_are_bounded() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["ports"] = json!([{"port":80}]);
    accepted(&value, 37)?;
    value["ports"] = json!([{"port":80},{"port":81}]);
    invalid_at(&value, 37, "/ports/1/name")?;
    for (count, valid) in [(100, true), (101, false)] {
        value["ports"] = json!(
            (0..count)
                .map(|n| json!({"name":format!("p{n}"),"port":80}))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            !has(
                &checks(&value, 37, Intent::Create)?,
                FindingCode::NativeFieldInvalid,
                "/ports"
            )?,
            valid
        );
    }
    value = slice("discovery.k8s.io/v1beta1");
    for (count, valid) in [(16, true), (17, false)] {
        value["endpoints"][0]["topology"] =
            Value::Object((0..count).map(|n| (format!("key{n}"), json!("x"))).collect());
        assert_eq!(
            !has(
                &checks(&value, 24, Intent::Create)?,
                FindingCode::NativeFieldInvalid,
                "/endpoints/0/topology"
            )?,
            valid
        );
    }
    value["endpoints"][0]["topology"] = json!({"bad key":"x"});
    invalid_at(&value, 24, "/endpoints/0/topology/bad key")?;
    value["endpoints"][0]["topology"] = json!({"key":"bad value"});
    invalid_at(&value, 24, "/endpoints/0/topology/key")?;
    Ok(())
}
#[test]
fn slice_pointer_protocol_defaults_do_not_admit_explicit_empty() -> TestResult<()> {
    for (api, minor) in [("discovery.k8s.io/v1beta1", 20), ("discovery.k8s.io/v1", 37)] {
        let mut value = slice(api);
        value["ports"] = json!([{"port":80}]);
        accepted(&value, minor)?;
        value["ports"][0]["protocol"] = json!("");
        invalid_at(&value, minor, "/ports/0/protocol")?;
        value["ports"][0]["protocol"] = Value::Null;
        accepted(&value, minor)?;
        assert_eq!(output(&resources(&value)?, minor)?["ports"][0]["protocol"], Value::Null);
    }
    let mut value = service();
    value["spec"]["sessionAffinityConfig"] = json!({});
    assert!(has(
        &checks(&value, 37, Intent::Create)?,
        FindingCode::NativeContextRequired,
        "/spec/sessionAffinityConfig"
    )?);
    Ok(())
}
#[test]
fn endpoint_slice_duplicate_addresses_and_patch_sensitive_special_ips_are_explicit() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["addresses"] = json!(["10.0.0.1", "10.0.0.1", "224.1.2.3", "255.255.255.255"]);
    accepted(&value, 37)?;
    assert_eq!(
        output(&resources(&value)?, 37)?["endpoints"][0]["addresses"],
        value["endpoints"][0]["addresses"]
    );
    value["endpoints"][0]["addresses"] = json!(["127.0.0.1"]);
    assert!(has(
        &checks(&value, 21, Intent::Create)?,
        FindingCode::NativeContextRequired,
        "/endpoints/0/addresses/0"
    )?);
    assert!(!has(
        &checks(&value, 21, Intent::Create)?,
        FindingCode::NativeFieldInvalid,
        "/endpoints/0/addresses/0"
    )?);
    for minor in [22, 37] {
        invalid_at(&value, minor, "/endpoints/0/addresses/0")?;
    }
    Ok(())
}
#[test]
fn ingress_resource_and_class_parameter_names_are_path_segments() -> TestResult<()> {
    let mut ingress = ingress("networking.k8s.io/v1");
    ingress["spec"]["defaultBackend"] = json!({"resource":{"kind":"Config_Kind","name":"config_name"}});
    accepted(&ingress, 37)?;
    let mut class = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":{"kind":"Config_Kind","name":"config_name"}}}),
    );
    accepted(&class, 37)?;
    for value in [&ingress, &class] {
        use kubernetes_lens::graph::{ReferenceTarget, Resolution, resolve_references_for_target};
        let set = resources(value)?;
        let graph = resolve_references_for_target(&set, &target(37)?);
        let edge = graph
            .edges
            .iter()
            .find(|edge| matches!(edge.reference.target, ReferenceTarget::GroupKindName { .. }))
            .required()?;
        // A valid path-segment reference with no supplier is missing, not an
        // invalid source identity or a positive claim about a custom supplier.
        assert_eq!(edge.resolution, Resolution::Missing);
        let generated = output(&set, 37)?;
        assert_eq!(generated["spec"], value["spec"]);
    }
    for name in ["", ".", "..", "bad/name", "bad%name"] {
        ingress["spec"]["defaultBackend"]["resource"]["name"] = json!(name);
        invalid_at(&ingress, 37, "/spec/defaultBackend/resource/name")?;
        class["spec"]["parameters"]["kind"] = json!(name);
        invalid_at(&class, 37, "/spec/parameters/kind")?;
    }
    for (value, prefix) in [
        (&mut ingress, "/spec/defaultBackend/resource"),
        (&mut class, "/spec/parameters"),
    ] {
        if prefix.contains("resource") {
            value["spec"]["defaultBackend"]["resource"] = json!({"kind":"Config","name":"config_name","apiGroup":""});
        } else {
            value["spec"]["parameters"] = json!({"kind":"Config","name":"config_name","apiGroup":""});
        }
        invalid_at(value, 37, &format!("{prefix}/apiGroup"))?;
    }
    Ok(())
}
#[test]
fn ingressclass_controller_accepts_http_path_punctuation_with_a_total_limit() -> TestResult<()> {
    let mut value = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/a/~%!$&'()*+,;=:"}}),
    );
    accepted(&value, 37)?;
    for controller in ["Bad_domain/path", "example.org/", "example.org/bad path"] {
        value["spec"]["controller"] = json!(controller);
        invalid_at(&value, 37, "/spec/controller")?;
    }
    for (length, valid) in [(250, true), (251, false)] {
        value["spec"]["controller"] = json!(format!("example.org/{}", "x".repeat(length - 12)));
        assert_eq!(
            !has(
                &checks(&value, 37, Intent::Create)?,
                FindingCode::NativeFieldInvalid,
                "/spec/controller"
            )?,
            valid
        );
    }
    Ok(())
}
#[test]
fn ingress_tls_hosts_and_beta_wildcard_http_compatibility_are_separate() -> TestResult<()> {
    for api in [
        "networking.k8s.io/v1",
        "networking.k8s.io/v1beta1",
        "extensions/v1beta1",
    ] {
        let mut value = ingress(api);
        value["spec"]["tls"] = json!([{"hosts":["127.0.0.1"]}]);
        accepted(&value, 21)?;
        value["spec"]["rules"] = json!([{"host":"127.0.0.1"}]);
        invalid_at(&value, 21, "/spec/rules/0/host")?;
        value["spec"].as_object_mut().required()?.remove("rules");
        value["spec"]["tls"][0]["secretName"] = json!("bad secret name");
        if api == "networking.k8s.io/v1" {
            invalid_at(&value, 21, "/spec/tls/0/secretName")?;
            assert!(has(
                &checks(&value, 21, Intent::Unspecified)?,
                FindingCode::NativeContextRequired,
                "/spec/tls/0/secretName"
            )?);
        } else {
            accepted(&value, 21)?;
        }
        value["spec"].as_object_mut().required()?.remove("tls");
        value["spec"]["rules"] = json!([{"host":"*.example.org","http":{"paths":[]}}]);
        if api == "networking.k8s.io/v1" {
            invalid_at(&value, 21, "/spec/rules/0/http/paths")?;
            assert!(has(
                &checks(&value, 21, Intent::Unspecified)?,
                FindingCode::NativeContextRequired,
                "/spec/rules/0/http"
            )?);
        } else {
            accepted(&value, 21)?;
        }
    }
    Ok(())
}
#[test]
fn ingress_backend_service_names_distinguish_dns1035_and_relaxed_gate_context() -> TestResult<()> {
    let mut value = ingress("networking.k8s.io/v1");
    value["spec"]["defaultBackend"]["service"]["name"] = json!("123-service");
    invalid_at(&value, 33, "/spec/defaultBackend/service/name")?;
    for minor in [34, 35, 36] {
        let checked = checks(&value, minor, Intent::Create)?;
        assert!(has(
            &checked,
            FindingCode::NativeContextRequired,
            "/spec/defaultBackend/service/name"
        )?);
        assert!(!has(
            &checked,
            FindingCode::NativeFieldInvalid,
            "/spec/defaultBackend/service/name"
        )?);
    }
    accepted(&value, 37)?;
    Ok(())
}
#[test]
fn policy_type_defaulting_and_duplicates_do_not_fabricate_native_constraints() -> TestResult<()> {
    let mut value = policy();
    for types in [json!([]), json!(["Ingress", "Ingress"]), json!(["Egress", "Egress"])] {
        value["spec"]["policyTypes"] = types;
        accepted(&value, 37)?;
        assert_eq!(
            output(&resources(&value)?, 37)?["spec"]["policyTypes"],
            value["spec"]["policyTypes"]
        );
    }
    value["spec"]["policyTypes"] = json!(["Ingress", "Egress", "Ingress"]);
    invalid_at(&value, 37, "/spec/policyTypes")?;
    value["spec"]["policyTypes"] = json!(["invalid"]);
    invalid_at(&value, 37, "/spec/policyTypes/0")?;
    Ok(())
}
#[test]
fn noncanonical_ip_cidr_gate_and_old_value_context_is_actionable() -> TestResult<()> {
    for minor in [33, 36, 37] {
        let mut value = policy();
        value["spec"]["ingress"][0]["from"] = json!([{"ipBlock":{"cidr":"010.0.0.1/8"}}]);
        for intent in [Intent::Create, Intent::Unspecified] {
            assert!(has(
                &checks(&value, minor, intent)?,
                FindingCode::NativeContextRequired,
                "/spec/ingress/0/from/0/ipBlock/cidr"
            )?);
        }
        value["spec"]["ingress"][0]["from"][0]["ipBlock"]["cidr"] = json!("10.0.0.1/8");
        assert!(has(
            &checks(&value, minor, Intent::Create)?,
            FindingCode::NativeContextRequired,
            "/spec/ingress/0/from/0/ipBlock/cidr"
        )?);
        value["spec"]["ingress"][0]["from"][0]["ipBlock"]["cidr"] = json!("10.0.0.0/8");
        accepted(&value, minor)?;
        value["spec"]["ingress"][0]["from"][0]["ipBlock"]["except"] = json!(["10.1.0.0/16"]);
        for intent in [Intent::Create, Intent::Unspecified] {
            assert!(
                !checks(&value, minor, intent)?
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeContextRequired)
            );
        }
    }
    Ok(())
}
#[test]
fn empty_service_protocol_compares_as_tcp_without_materializing_a_default() -> TestResult<()> {
    use kubernetes_lens::graph::{GraphSubject, ReferenceTarget, Resolution, resolve_references_for_target};
    let mut supplying = service();
    supplying["spec"]["selector"] = json!({"app":"web"});
    supplying["spec"]["ports"][0]["protocol"] = json!("");
    supplying["spec"]["ports"][0]["targetPort"] = json!("web");
    let pod = document(
        "v1",
        "Pod",
        json!({"metadata":{"name":"pod","namespace":"ns","labels":{"app":"web"}},
        "spec":{"containers":[{"name":"main","image":"image","ports":[{"name":"web","containerPort":8080}]}]}}),
    );
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying.clone(),pod.clone()]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edge = graph
        .edges
        .iter()
        .find(|e| matches!(e.reference.target, ReferenceTarget::NamedServiceTargetPort { .. }))
        .required()?;
    assert_eq!(
        edge.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[1].id()
        }])
    );
    assert_eq!(
        output(&resources(&supplying)?, 37)?["spec"]["ports"][0]["protocol"],
        json!("")
    );
    supplying["spec"]["ports"][0]["targetPort"] = json!("");
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying.clone(),pod]}))?;
    assert!(
        !resolve_references_for_target(&set, &target(37)?)
            .edges
            .iter()
            .any(|e| matches!(e.reference.target, ReferenceTarget::NamedServiceTargetPort { .. }))
    );
    supplying["spec"]["ports"] =
        json!([{"port":80,"name":"first","protocol":""},{"port":80,"name":"second","protocol":"TCP"}]);
    let set = resources(&supplying)?;
    assert!(
        resolve_references_for_target(&set, &target(37)?)
            .findings
            .iter()
            .any(|f| f.code == FindingCode::MergeConflict)
    );
    assert!(generate(&set, &target(37)?, OutputFormat::Json, &options()).is_err());
    Ok(())
}
fn author(set: &ResourceSet) -> TestResult<kubernetes_lens::model::AuthoredResource> {
    use kubernetes_lens::resources::networking::{
        EndpointSliceV1, Endpoints, IngressClassV1, IngressV1, NetworkPolicy, Service,
    };
    let doc = &set.documents()[0];
    if let Some(root) = doc.resource::<Service>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<Endpoints>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<EndpointSliceV1>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<IngressV1>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<IngressClassV1>() {
        return Ok(root.clone().into());
    }
    if let Some(root) = doc.resource::<NetworkPolicy>() {
        return Ok(root.clone().into());
    }
    Err("unexpected authored networking kind".into())
}
#[test]
fn finite_native_corrections_reparse_and_have_source_free_generation_fixed_points() -> TestResult<()> {
    use kubernetes_lens::source::AuthoringLimits;
    let mut headless = service();
    headless["spec"] = json!({"clusterIP":"None"});
    let mut svc = service();
    svc["spec"]["ports"][0]["name"] = json!("123");
    svc["spec"]["ports"][0]["protocol"] = json!("");
    let mut ingress = ingress("networking.k8s.io/v1");
    ingress["spec"]["defaultBackend"] = json!({"resource":{"kind":"Config_Kind","name":"config_name"}});
    let class = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/a/!~%","parameters":{"kind":"Config_Kind","name":"config_name"}}}),
    );
    let mut policy = policy();
    policy["spec"]["policyTypes"] = json!(["Ingress", "Ingress"]);
    for value in [headless, svc, ingress, class, policy] {
        let supplied = resources(&value)?;
        let fresh = ResourceSet::from_authored(vec![author(&supplied)?], &target(37)?, &AuthoringLimits::default())
            .required()?;
        for set in [&supplied, &fresh] {
            for minor in [20, 37] {
                let mut opts = options();
                opts.validation_intent = Intent::Create;
                let artifact = generate(set, &target(minor)?, OutputFormat::Json, &opts).required()?;
                let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
                let parsed: Value = serde_json::from_slice(artifact.reveal_bytes(&access))?;
                let again = generate(&resources(&parsed)?, &target(minor)?, OutputFormat::Json, &opts).required()?;
                assert_eq!(artifact.reveal_bytes(&access), again.reveal_bytes(&access));
            }
        }
    }
    Ok(())
}
#[test]
fn explicit_create_generation_refuses_stable_wildcard_http_errors() -> TestResult<()> {
    let mut value = ingress("networking.k8s.io/v1");
    value["spec"]["rules"] = json!([{"host":"*.example.org","http":{"paths":[]}}]);
    let set = resources(&value)?;
    let mut opts = options();
    opts.validation_intent = Intent::Create;
    let findings = generate(&set, &target(37)?, OutputFormat::Json, &opts)
        .err()
        .required()?;
    assert!(has(
        &findings,
        FindingCode::NativeFieldInvalid,
        "/spec/rules/0/http/paths"
    )?);
    opts.validation_intent = Intent::Unspecified;
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    assert!(
        artifact
            .findings()
            .iter()
            .any(|f| f.code == FindingCode::NativeContextRequired)
    );
    Ok(())
}

#[test]
fn unclassified_native_ip_variants_do_not_become_false_family_or_subnet_rejections() -> TestResult<()> {
    let mut value = policy();
    for cidr in ["0010.0.0.0/8", "::ffff:10.0.0.0/120"] {
        value["spec"]["ingress"][0]["from"] = json!([{"ipBlock":{"cidr":cidr,"except":["10.1.0.0/16"]}}]);
        let checked = checks(&value, 37, Intent::Create)?;
        assert!(has(
            &checked,
            FindingCode::NativeContextRequired,
            "/spec/ingress/0/from/0/ipBlock/cidr"
        )?);
        assert!(
            !checked
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
        );
    }
    Ok(())
}

#[test]
fn preserved_fqdn_addresses_and_legacy_special_ips_keep_distinct_findings() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["addressType"] = json!("FQDN");
    value["endpoints"][0]["addresses"] = json!(["service.example.org"]);
    let checked = checks(&value, 37, Intent::Create)?;
    assert!(has(&checked, FindingCode::UnadmittedField, "/addressType")?);
    assert!(!checked.iter().any(|f| f.code == FindingCode::NativeFieldInvalid));
    value = slice("discovery.k8s.io/v1beta1");
    value["endpoints"][0]["addresses"] = json!(["127.0.0.1"]);
    let checked = checks(&value, 20, Intent::Create)?;
    assert!(has(
        &checked,
        FindingCode::NativeContextRequired,
        "/endpoints/0/addresses/0"
    )?);
    assert!(!checked.iter().any(|f| f.code == FindingCode::NativeFieldInvalid));
    Ok(())
}

#[test]
fn backend_ports_use_effective_union_values_without_changing_authored_spelling() -> TestResult<()> {
    use kubernetes_lens::graph::{
        GraphSubject, ReferencePredicate, ReferenceTarget, Resolution, resolve_references_for_target,
    };
    for minor in [20, 37] {
        let mut supplying = service();
        supplying["spec"]["ports"][0]["name"] = json!("http");
        for port in [json!({"name":"","number":80}), json!({"name":"http","number":0})] {
            let mut value = ingress("networking.k8s.io/v1");
            for occurrence in [
                "/spec/defaultBackend/service/port",
                "/spec/rules/0/http/paths/0/backend/service/port",
            ] {
                if occurrence.contains("rules") {
                    value["spec"] = json!({"rules":[{"http":{"paths":[{"path":"/","pathType":"Prefix","backend":{"service":{"name":"native","port":port}}}]}}]});
                } else {
                    *value.pointer_mut(occurrence).required()? = port.clone();
                }
                accepted(&value, minor)?;
                assert_eq!(
                    output(&resources(&value)?, minor)?.pointer(occurrence).required()?,
                    &port
                );
                let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,supplying]}))?;
                let graph = resolve_references_for_target(&set, &target(minor)?);
                let edge = graph
                    .edges
                    .iter()
                    .find(|edge| {
                        matches!(
                            &edge.reference.target,
                            ReferenceTarget::CheckedObject {
                                predicate: Some(ReferencePredicate::ServicePortExists { .. }),
                                ..
                            }
                        )
                    })
                    .required()?;
                assert_eq!(
                    edge.resolution,
                    Resolution::ResolvedSubjects(vec![GraphSubject::ServicePort {
                        resource: set.documents()[1].id(),
                        path: FieldPath::parse("/spec/ports/0")?
                    }])
                );
            }
        }
        for port in [
            json!({}),
            json!({"name":"","number":0}),
            json!({"name":"http","number":80}),
        ] {
            let mut value = ingress("networking.k8s.io/v1");
            value["spec"]["defaultBackend"]["service"]["port"] = port;
            invalid_at(&value, minor, "/spec/defaultBackend/service/port")?;
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,supplying]}))?;
            let graph = resolve_references_for_target(&set, &target(minor)?);
            let edge = graph
                .edges
                .iter()
                .find(|edge| {
                    matches!(
                        &edge.reference.target,
                        ReferenceTarget::CheckedObject {
                            predicate: Some(ReferencePredicate::ServicePortExists { .. }),
                            ..
                        }
                    )
                })
                .required()?;
            assert!(matches!(edge.resolution, Resolution::Unsupported(_)));
        }
        for port in [json!({"name":"bad/name","number":0}), json!({"name":"","number":65536})] {
            let mut value = ingress("networking.k8s.io/v1");
            value["spec"]["defaultBackend"]["service"]["port"] = port.clone();
            let leaf = if port["name"] == "" { "number" } else { "name" };
            invalid_at(&value, minor, &format!("/spec/defaultBackend/service/port/{leaf}"))?;
        }
    }
    Ok(())
}

#[test]
fn rule_hosts_reject_decimal_ipv4_variants_while_tls_retains_dns_spelling() -> TestResult<()> {
    for minor in [20, 23, 37] {
        for api in if minor == 20 {
            vec![
                "networking.k8s.io/v1",
                "networking.k8s.io/v1beta1",
                "extensions/v1beta1",
            ]
        } else {
            vec!["networking.k8s.io/v1"]
        } {
            let mut value = ingress(api);
            for host in ["127.000.0.1", "010.000.000.001"] {
                value["spec"]["rules"] = json!([{"host":host}]);
                if minor <= 22 {
                    accepted(&value, minor)?;
                    assert!(has(
                        &checks(&value, minor, Intent::Create)?,
                        FindingCode::NativeContextRequired,
                        "/spec/rules/0/host"
                    )?);
                } else {
                    invalid_at(&value, minor, "/spec/rules/0/host")?;
                }
            }
            value["spec"].as_object_mut().required()?.remove("rules");
            value["spec"]["tls"] = json!([{"hosts":["127.000.0.1","010.000.000.001"]}]);
            accepted(&value, minor)?;
            assert_eq!(
                output(&resources(&value)?, minor)?["spec"]["tls"][0]["hosts"][0],
                "127.000.0.1"
            );
        }
    }
    Ok(())
}

#[test]
fn unsupported_policy_selectors_keep_edges_and_private_unknown_evidence() -> TestResult<()> {
    use kubernetes_lens::graph::{ReferenceTarget, Resolution, resolve_references_for_target};
    let private = "networking-private-selector-value";
    for pointer in ["/spec/podSelector", "/spec/ingress/0/from/0/podSelector"] {
        let mut value = policy();
        if pointer.contains("from") {
            value["spec"]["ingress"] = json!([{"from":[{"podSelector":{}}]}]);
        }
        *value.pointer_mut(pointer).required()? = json!({"matchLabels":{"app":"web"},"vendorFuture":private});
        let pod = document(
            "v1",
            "Pod",
            json!({"metadata":{"name":"matching","namespace":"ns","labels":{"app":"web"}},"spec":{"containers":[{"name":"main","image":"image"}]}}),
        );
        let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,pod]}))?;
        let graph = resolve_references_for_target(&set, &target(37)?);
        let path = if pointer.contains("from") {
            "/spec/ingress/0/from/0"
        } else {
            pointer
        };
        let path = FieldPath::parse(path)?;
        let edge = graph
            .edges
            .iter()
            .find(|edge| {
                edge.reference.path == path
                    && matches!(
                        edge.reference.target,
                        ReferenceTarget::SubjectSelector { .. } | ReferenceTarget::NetworkPolicyPeer { .. }
                    )
            })
            .required()?;
        assert!(
            matches!(edge.resolution, Resolution::Unsupported(_)),
            "{:?}",
            edge.resolution
        );
        let findings = validate_for_target(&set, &target(37)?);
        assert!(!format!("{set:?} {graph:?} {findings:?}").contains(private));
        let single = resources(&value)?;
        assert!(generate(&single, &target(37)?, OutputFormat::Json, &GenerationOptions::default()).is_err());
        assert_eq!(
            output(&single, 37)?.pointer(pointer).required()?["vendorFuture"],
            private
        );
    }
    Ok(())
}

#[test]
fn nullable_native_pointers_preserve_exact_parsed_and_source_free_envelopes() -> TestResult<()> {
    use kubernetes_lens::source::AuthoringLimits;
    let mut ing = ingress("networking.k8s.io/v1");
    ing["spec"]["ingressClassName"] = Value::Null;
    ing["spec"]["defaultBackend"]["resource"] = Value::Null;
    let class = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":null}}),
    );
    let mut svc = service();
    svc["spec"]["ports"][0]["appProtocol"] = Value::Null;
    svc["spec"]["internalTrafficPolicy"] = Value::Null;
    let mut sl = slice("discovery.k8s.io/v1");
    sl["ports"] = json!([{"appProtocol":null}]);
    let mut resource = ingress("networking.k8s.io/v1");
    resource["spec"]["defaultBackend"] =
        json!({"service":null,"resource":{"kind":"Config","name":"config_name","apiGroup":null}});
    let parameters = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":{"kind":"Config","name":"config_name","apiGroup":null,"scope":null}}}),
    );
    for value in [ing, class, svc, sl, resource, parameters] {
        let supplied = resources(&value)?;
        let fresh = ResourceSet::from_authored(vec![author(&supplied)?], &target(37)?, &AuthoringLimits::default())
            .required()?;
        for set in [&supplied, &fresh] {
            let findings = validate_for_target_with_intent(set, &target(37)?, Intent::Create);
            assert!(
                !findings.iter().any(|f| f.code == FindingCode::NativeFieldInvalid),
                "{findings:?}"
            );
            let generated = output(set, 37)?;
            let root = if value["kind"] == "EndpointSlice" {
                "ports"
            } else {
                "spec"
            };
            assert_eq!(generated[root], value[root]);
            let again = output(&resources(&generated)?, 37)?;
            assert_eq!(generated, again);
            if value["kind"] == "Service" {
                assert!(has(
                    &findings,
                    FindingCode::NativeContextRequired,
                    "/spec/internalTrafficPolicy"
                )?);
            }
            if value["spec"]["parameters"].is_object() {
                assert!(has(
                    &findings,
                    FindingCode::NativeContextRequired,
                    "/spec/parameters/scope"
                )?);
            }
        }
    }
    let mut required_name = ingress("networking.k8s.io/v1");
    required_name["spec"]["defaultBackend"]["service"]["name"] = Value::Null;
    invalid_at(&required_name, 37, "/spec/defaultBackend/service/name")?;
    let mut nonnil_app = service();
    nonnil_app["spec"]["ports"][0]["appProtocol"] = json!("");
    invalid_at(&nonnil_app, 37, "/spec/ports/0/appProtocol")?;
    Ok(())
}

#[test]
fn present_named_targetref_without_api_witness_remains_explicitly_unsupported() -> TestResult<()> {
    use kubernetes_lens::graph::{ReferenceTarget, Resolution, resolve_references_for_target};
    let pod = document(
        "v1",
        "Pod",
        json!({"metadata":{"name":"private-pod","namespace":"ns"},"spec":{"containers":[{"name":"main","image":"image"}]}}),
    );
    let mut ep = document(
        "v1",
        "Endpoints",
        json!({"subsets":[{"addresses":[{"ip":"10.0.0.1"}]}]}),
    );
    let sl = slice("discovery.k8s.io/v1");
    for (mut value, pointer) in [
        (ep.clone(), "/subsets/0/addresses/0/targetRef"),
        (sl, "/endpoints/0/targetRef"),
    ] {
        let container = pointer.rsplit_once('/').required()?.0;
        for reference in [
            None,
            Some(Value::Null),
            Some(json!({"kind":"Pod","name":"private-pod","namespace":"ns"})),
        ] {
            value
                .pointer_mut(container)
                .required()?
                .as_object_mut()
                .required()?
                .remove("targetRef");
            if let Some(reference) = reference.clone() {
                value.pointer_mut(container).required()?["targetRef"] = reference;
            }
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,pod]}))?;
            let graph = resolve_references_for_target(&set, &target(37)?);
            let path = FieldPath::parse(pointer)?;
            let edges: Vec<_> = graph.edges.iter().filter(|edge| edge.reference.path == path).collect();
            if reference.as_ref().is_some_and(Value::is_object) {
                assert_eq!(edges.len(), 1);
                assert!(matches!(
                    &edges[0].reference.target,
                    ReferenceTarget::Exact { gvk: None, .. }
                ));
                assert!(matches!(edges[0].resolution, Resolution::Unsupported(_)));
                assert_eq!(
                    output(&resources(&value)?, 37)?.pointer(pointer).required()?,
                    reference.as_ref().required()?
                );
            } else {
                assert!(edges.is_empty());
            }
            assert!(!format!("{graph:?}").contains("private-pod"));
        }
    }
    ep["subsets"][0]["addresses"][0]["targetRef"] =
        json!({"apiVersion":"v1","kind":"Pod","name":"private-pod","namespace":"ns"});
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[ep,pod]}))?;
    assert!(
        resolve_references_for_target(&set, &target(37)?)
            .edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::ResolvedSubjects(_)))
    );
    Ok(())
}

#[test]
fn wildcard_hosts_bound_the_full_authored_name_before_removing_the_prefix() -> TestResult<()> {
    for minor in [20, 37] {
        for last_label in [59, 60, 61] {
            let name = format!(
                "*.{}.{}.{}.{}",
                "a".repeat(63),
                "b".repeat(63),
                "c".repeat(63),
                "d".repeat(last_label)
            );
            assert_eq!(name.len(), 194 + last_label);
            let mut value = ingress("networking.k8s.io/v1");
            value["spec"]["rules"] = json!([{"host":name}]);
            value["spec"]["tls"] = json!([{"hosts":[name]}]);
            if name.len() == 253 {
                accepted(&value, minor)?;
                assert_eq!(output(&resources(&value)?, minor)?["spec"]["tls"][0]["hosts"][0], name);
            } else {
                invalid_at(&value, minor, "/spec/rules/0/host")?;
                invalid_at(&value, minor, "/spec/tls/0/hosts/0")?;
            }
        }
        let bare = format!(
            "{}.{}.{}.{}",
            "a".repeat(63),
            "b".repeat(63),
            "c".repeat(63),
            "d".repeat(61)
        );
        assert_eq!(bare.len(), 253);
        let mut value = ingress("networking.k8s.io/v1");
        value["spec"]["rules"] = json!([{"host":bare}]);
        value["spec"]["tls"] = json!([{"hosts":[bare]}]);
        accepted(&value, minor)?;
    }
    Ok(())
}

#[test]
fn empty_endpoints_hostname_differs_from_a_present_empty_slice_pointer() -> TestResult<()> {
    for minor in [20, 37] {
        let value = document(
            "v1",
            "Endpoints",
            json!({"subsets":[{"addresses":[{"ip":"10.0.0.1","hostname":""}]}]}),
        );
        accepted(&value, minor)?;
        assert_eq!(
            output(&resources(&value)?, minor)?["subsets"][0]["addresses"][0]["hostname"],
            ""
        );
        let api = if minor == 20 {
            "discovery.k8s.io/v1beta1"
        } else {
            "discovery.k8s.io/v1"
        };
        let mut sl = slice(api);
        sl["endpoints"][0]["hostname"] = json!("");
        invalid_at(&sl, minor, "/endpoints/0/hostname")?;
    }
    Ok(())
}

#[test]
fn peer_pointer_nulls_do_not_count_as_effective_selectors() -> TestResult<()> {
    use kubernetes_lens::graph::{ReferenceTarget, Resolution, resolve_references_for_target};
    for minor in [20, 37] {
        for (direction, peers) in [("ingress", "from"), ("egress", "to")] {
            for peer in [
                json!({"namespaceSelector":{},"podSelector":null}),
                json!({"namespaceSelector":null,"podSelector":{}}),
            ] {
                let mut value = policy();
                value["spec"][direction] = json!([{peers:[peer]}]);
                accepted(&value, minor)?;
                assert_eq!(
                    output(&resources(&value)?, minor)?["spec"][direction][0][peers][0],
                    peer
                );
                let pod = document(
                    "v1",
                    "Pod",
                    json!({"spec":{"containers":[{"name":"main","image":"image"}]}}),
                );
                let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[value,pod]}))?;
                let graph = resolve_references_for_target(&set, &target(minor)?);
                let edge = graph
                    .edges
                    .iter()
                    .find(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
                    .required()?;
                assert!(matches!(edge.resolution, Resolution::Unsupported(_)));
            }
            for peer in [
                json!({"namespaceSelector":null,"podSelector":null}),
                json!({"namespaceSelector":null}),
                json!({"podSelector":null}),
            ] {
                let mut value = policy();
                value["spec"][direction] = json!([{peers:[peer]}]);
                invalid_at(&value, minor, &format!("/spec/{direction}/0/{peers}/0"))?;
            }
        }
        let mut value = policy();
        value["spec"]["podSelector"] = Value::Null;
        invalid_at(&value, minor, "/spec/podSelector")?;
    }
    Ok(())
}

#[test]
fn service_metadata_uses_native_label_and_prefix_callbacks_at_relaxed_gate_boundaries() -> TestResult<()> {
    use kubernetes_lens::source::AuthoringLimits;
    for minor in [20, 33, 34, 35, 36, 37] {
        let mut dotted = service();
        dotted["metadata"]["name"] = json!("svc.with.dot");
        invalid_at(&dotted, minor, "/metadata/name")?;
        let parsed = resources(&dotted)?;
        assert!(
            ResourceSet::from_authored(vec![author(&parsed)?], &target(minor)?, &AuthoringLimits::default()).is_err()
        );
        let mut numeric = service();
        numeric["metadata"]["name"] = json!("1svc");
        let findings = checks(&numeric, minor, Intent::Create)?;
        let parsed = resources(&numeric)?;
        let fresh = ResourceSet::from_authored(vec![author(&parsed)?], &target(minor)?, &AuthoringLimits::default());
        let code = if minor <= 33 {
            FindingCode::NativeFieldInvalid
        } else {
            FindingCode::UnadmittedField
        };
        assert!(has(&findings, code, "/metadata/name")?);
        assert!(has(&fresh.err().required()?, code, "/metadata/name")?);
        assert_eq!(
            parsed.documents()[0].identity()?.name.value().map(String::as_str),
            Some("1svc")
        );
        let failure = generate(&parsed, &target(minor)?, OutputFormat::Json, &options())
            .err()
            .required()?;
        assert!(has(&failure, code, "/metadata/name")?);
        for prefix in ["svc-".to_owned(), "0-".to_owned(), format!("{}-", "a".repeat(63))] {
            let mut value = service();
            value["metadata"].as_object_mut().required()?.remove("name");
            value["metadata"]["generateName"] = json!(prefix);
            accepted(&value, minor)?;
            let supplied = resources(&value)?;
            let fresh =
                ResourceSet::from_authored(vec![author(&supplied)?], &target(minor)?, &AuthoringLimits::default())
                    .required()?;
            for set in [&supplied, &fresh] {
                let generated = output(set, minor)?;
                assert_eq!(generated["metadata"]["generateName"], prefix);
                assert!(generated["metadata"].get("name").is_none());
            }
        }
        let mut long = service();
        long["metadata"].as_object_mut().required()?.remove("name");
        long["metadata"]["generateName"] = json!(format!("{}-", "a".repeat(64)));
        invalid_at(&long, minor, "/metadata/generateName")?;
        let mut numeric_prefix = service();
        numeric_prefix["metadata"].as_object_mut().required()?.remove("name");
        numeric_prefix["metadata"]["generateName"] = json!("1svc-");
        let findings = checks(&numeric_prefix, minor, Intent::Create)?;
        assert!(has(&findings, code, "/metadata/generateName")?);
        let supplied = resources(&numeric_prefix)?;
        assert_eq!(
            supplied.documents()[0]
                .identity()?
                .generate_name
                .value()
                .map(String::as_str),
            Some("1svc-")
        );
        let failure =
            ResourceSet::from_authored(vec![author(&supplied)?], &target(minor)?, &AuthoringLimits::default())
                .err()
                .required()?;
        assert!(has(&failure, code, "/metadata/generateName")?);
        let failure = generate(&supplied, &target(minor)?, OutputFormat::Json, &options())
            .err()
            .required()?;
        assert!(has(&failure, code, "/metadata/generateName")?);
    }
    Ok(())
}

fn assert_selected_generated_prefix(set: &ResourceSet, prefix: &str, minor: u8) -> TestResult<()> {
    let identity = set.documents()[0].identity()?;
    assert!(identity.name.is_absent());
    assert_eq!(identity.generate_name.value().map(String::as_str), Some(prefix));
    assert!(identity.collision_key().is_none());
    let findings = validate_for_target_with_intent(set, &target(minor)?, Intent::Create);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.severity == kubernetes_lens::diagnostic::Severity::Error)
    );
    assert!(has(
        &findings,
        FindingCode::NativeContextRequired,
        "/metadata/generateName"
    )?);
    let generated = output(set, minor)?;
    assert_eq!(generated["metadata"]["generateName"], prefix);
    assert!(generated["metadata"].get("name").is_none());
    Ok(())
}

#[test]
fn service_prefix_envelope_delegation_preserves_other_native_identity_checks() -> TestResult<()> {
    use kubernetes_lens::source::AuthoringLimits;
    for prefix in ["A-", "_-", "$-", "a.-"] {
        for minor in [20, 37] {
            for kind in ["Service", "Namespace", "Pod"] {
                let mut value = match kind {
                    "Service" => service(),
                    "Namespace" => json!({"apiVersion":"v1","kind":"Namespace","metadata":{}}),
                    _ => document(
                        "v1",
                        "Pod",
                        json!({"spec":{"containers":[{"name":"main","image":"image"}]}}),
                    ),
                };
                value["metadata"].as_object_mut().required()?.remove("name");
                value["metadata"]["generateName"] = json!(prefix);
                let supplied = resources(&value)?;
                assert_eq!(
                    supplied.documents()[0]
                        .original_identity()
                        .generate_name
                        .value()
                        .map(String::as_str),
                    Some(prefix)
                );
                let authored = match kind {
                    "Namespace" => supplied.documents()[0]
                        .resource::<kubernetes_lens::resources::access::Namespace>()
                        .required()?
                        .clone()
                        .into(),
                    "Pod" => supplied.documents()[0]
                        .resource::<kubernetes_lens::resources::workloads::Pod>()
                        .required()?
                        .clone()
                        .into(),
                    _ => author(&supplied)?,
                };
                let fresh = ResourceSet::from_authored(vec![authored], &target(minor)?, &AuthoringLimits::default())
                    .required()?;
                for set in [&supplied, &fresh] {
                    assert_selected_generated_prefix(set, prefix, minor)?;
                }
            }
        }
    }
    Ok(())
}

#[test]
fn service_prefix_hazard_and_unicode_keep_acquisition_separate_from_selected_naming() -> TestResult<()> {
    use kubernetes_lens::{graph::resolve_references_for_target, source::AuthoringLimits};
    for prefix in ["-", "é-"] {
        let mut value = service();
        value["metadata"].as_object_mut().required()?.remove("name");
        value["metadata"]["generateName"] = json!(prefix);
        let supplied = resources(&value)?;
        assert_eq!(
            supplied.documents()[0]
                .identity()?
                .generate_name
                .value()
                .map(String::as_str),
            Some(prefix)
        );
        assert!(supplied.documents()[0].identity()?.collision_key().is_none());
        for minor in [20, 21, 22, 37] {
            let code = if prefix == "-" && minor <= 21 {
                FindingCode::NativeNamingUnverified
            } else {
                FindingCode::NativeFieldInvalid
            };
            let findings = checks(&value, minor, Intent::Create)?;
            assert!(has(&findings, code, "/metadata/generateName")?);
            let authored =
                ResourceSet::from_authored(vec![author(&supplied)?], &target(minor)?, &AuthoringLimits::default());
            if code == FindingCode::NativeNamingUnverified {
                let authored = authored.required()?;
                assert!(has(
                    &validate_for_target(&authored, &target(minor)?),
                    code,
                    "/metadata/generateName"
                )?);
            } else {
                assert!(has(&authored.err().required()?, code, "/metadata/generateName")?);
                let failure = generate(&supplied, &target(minor)?, OutputFormat::Json, &options())
                    .err()
                    .required()?;
                assert!(has(&failure, code, "/metadata/generateName")?);
            }
            let graph = resolve_references_for_target(&supplied, &target(minor)?);
            assert!(has(&graph.findings, code, "/metadata/generateName")?);
            assert!(!graph.edges.iter().any(|edge| matches!(
                edge.resolution,
                kubernetes_lens::graph::Resolution::ResolvedSubjects(_)
                    | kubernetes_lens::graph::Resolution::Resolved(_)
            )));
        }
    }
    Ok(())
}

#[test]
fn native_empty_enum_exception_does_not_admit_other_values_or_cohorts() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = service();
        for (field, path) in [("type", "/spec/type"), ("sessionAffinity", "/spec/sessionAffinity")] {
            value["spec"][field] = json!("INVALID");
            invalid_at(&value, minor, path)?;
            assert!(has(
                &checks(&value, minor, Intent::Create)?,
                FindingCode::UnadmittedField,
                path
            )?);
            value["spec"].as_object_mut().required()?.remove(field);
        }
        value["spec"]["ports"][0]["protocol"] = json!("INVALID");
        invalid_at(&value, minor, "/spec/ports/0/protocol")?;
        assert!(has(
            &checks(&value, minor, Intent::Create)?,
            FindingCode::UnadmittedField,
            "/spec/ports/0/protocol"
        )?);
        let ep = document(
            "v1",
            "Endpoints",
            json!({"subsets":[{"addresses":[{"ip":"10.0.0.1"}],"ports":[{"port":80,"protocol":""}]}]}),
        );
        accepted(&ep, minor)?;
        assert!(has(
            &checks(&ep, minor, Intent::Create)?,
            FindingCode::NativeContextRequired,
            "/subsets/0/ports/0/protocol"
        )?);
        let pod = document(
            "v1",
            "Pod",
            json!({"spec":{"containers":[{"name":"main","image":"image","ports":[{"containerPort":80,"protocol":""}]}]}}),
        );
        let findings = validate_for_target(&resources(&pod)?, &target(minor)?);
        assert!(has(
            &findings,
            FindingCode::UnadmittedField,
            "/spec/containers/0/ports/0/protocol"
        )?);
        let quota = json!({"apiVersion":"v1","kind":"ResourceQuota","metadata":{"name":"quota","namespace":"ns"},"spec":{"scopes":[""]}});
        let findings = validate_for_target(&resources(&quota)?, &target(minor)?);
        assert!(has(&findings, FindingCode::NativeFieldInvalid, "/spec/scopes/0")?);
    }
    Ok(())
}
