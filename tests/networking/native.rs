use super::*;
#[test]
fn service_ports_types_classes_and_cross_fields_fail_at_native_paths() -> TestResult<()> {
    for (member, value, path) in [
        ("ports", json!([]), "/spec/ports"),
        (
            "ports",
            json!([{"port":80,"protocol":"TCP","targetPort":"123"}]),
            "/spec/ports/0/targetPort",
        ),
        (
            "ports",
            json!([{"port":80,"protocol":"TCP","nodePort":30000}]),
            "/spec/ports/0/nodePort",
        ),
        ("type", json!("made-up"), "/spec/type"),
        ("clusterIP", json!("not-an-ip"), "/spec/clusterIP"),
        ("sessionAffinity", json!("invalid"), "/spec/sessionAffinity"),
        (
            "loadBalancerClass",
            json!("example.org/class"),
            "/spec/loadBalancerClass",
        ),
        ("healthCheckNodePort", json!(30000), "/spec/healthCheckNodePort"),
        (
            "allocateLoadBalancerNodePorts",
            json!(false),
            "/spec/allocateLoadBalancerNodePorts",
        ),
    ] {
        let mut body = service();
        body["spec"][member] = value;
        let findings = validate_for_target(&resources(&body)?, &target(37)?);
        assert!(
            has(&findings, FindingCode::NativeFieldInvalid, path)?,
            "{path}: {findings:?}"
        );
    }
    let mut external = service();
    external["spec"]["type"] = json!("ExternalName");
    external["spec"]["externalName"] = json!("api.example.org");
    external["spec"].as_object_mut().required()?.remove("ports");
    valid(&external, 37)?;
    external["spec"]["externalName"] = json!("bad host");
    assert!(has(
        &validate_for_target(&resources(&external)?, &target(37)?),
        FindingCode::NativeFieldInvalid,
        "/spec/externalName"
    )?);
    Ok(())
}
#[test]
fn ingress_backend_union_port_union_paths_and_hosts_are_independent() -> TestResult<()> {
    let mut stable = ingress("networking.k8s.io/v1");
    stable["spec"]["defaultBackend"]["resource"] = json!({"apiGroup":"example.org","kind":"Backend","name":"backend"});
    assert!(has(
        &validate_for_target(&resources(&stable)?, &target(37)?),
        FindingCode::NativeFieldInvalid,
        "/spec/defaultBackend"
    )?);
    for (port, path) in [
        (json!({"name":"http","number":80}), "/spec/defaultBackend/service/port"),
        (json!({"number":65536}), "/spec/defaultBackend/service/port/number"),
        (json!({}), "/spec/defaultBackend/service/port"),
    ] {
        let mut value = ingress("networking.k8s.io/v1");
        value["spec"]["defaultBackend"]["service"]["port"] = port;
        assert!(has(
            &validate_for_target(&resources(&value)?, &target(37)?),
            FindingCode::NativeFieldInvalid,
            path
        )?);
    }
    for api in [
        "networking.k8s.io/v1",
        "networking.k8s.io/v1beta1",
        "extensions/v1beta1",
    ] {
        let backend = if api == "networking.k8s.io/v1" {
            json!({"service":{"name":"native","port":{"number":80}}})
        } else {
            json!({"serviceName":"native","servicePort":80})
        };
        let value = document(
            api,
            "Ingress",
            json!({"spec":{"rules":[{"host":"api.example.org","http":{"paths":[{"path":"/prefix","pathType":"Prefix","backend":backend}]}}]}}),
        );
        valid(&value, 21)?;
        let mut bad = value.clone();
        bad["spec"]["rules"][0]["http"]["paths"][0]["path"] = json!("relative");
        assert!(has(
            &validate_for_target(&resources(&bad)?, &target(21)?),
            FindingCode::NativeFieldInvalid,
            "/spec/rules/0/http/paths/0/path"
        )?);
        if api == "networking.k8s.io/v1" {
            bad = value.clone();
            bad["spec"]["rules"][0]["http"]["paths"][0]
                .as_object_mut()
                .required()?
                .remove("pathType");
            assert!(has(
                &validate_for_target(&resources(&bad)?, &target(21)?),
                FindingCode::NativeFieldInvalid,
                "/spec/rules/0/http/paths/0/pathType"
            )?);
        }
    }
    Ok(())
}
#[test]
fn policy_peer_presence_union_selector_and_cidr_constraints_stay_distinct() -> TestResult<()> {
    for (peer, path) in [
        (json!({}), "/spec/ingress/0/from/0"),
        (
            json!({"ipBlock":{"cidr":"10.0.0.0/8"},"podSelector":{}}),
            "/spec/ingress/0/from/0",
        ),
        (
            json!({"ipBlock":{"cidr":"10.0.0.0/8","except":["192.168.0.0/16"]}}),
            "/spec/ingress/0/from/0/ipBlock/except/0",
        ),
        (
            json!({"ipBlock":{"cidr":"10.0.0.0/8","except":["2001:db8::/64"]}}),
            "/spec/ingress/0/from/0/ipBlock/except/0",
        ),
        (
            json!({"ipBlock":{"cidr":"not-cidr"}}),
            "/spec/ingress/0/from/0/ipBlock/cidr",
        ),
        (json!({"podSelector":null}), "/spec/ingress/0/from/0"),
    ] {
        let mut value = policy();
        value["spec"]["ingress"][0]["from"] = json!([peer]);
        assert!(
            has(
                &validate_for_target(&resources(&value)?, &target(37)?),
                FindingCode::NativeFieldInvalid,
                path
            )?,
            "{path}"
        );
    }
    for peers in [
        Value::Null,
        json!([]),
        json!([{"podSelector":{}}]),
        json!([{"namespaceSelector":{},"podSelector":{"matchLabels":{"app":"web"}}}]),
        json!([{"ipBlock":{"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}}]),
    ] {
        let mut value = policy();
        if !peers.is_null() {
            value["spec"]["ingress"][0]["from"] = peers;
        }
        valid(&value, 37)?;
    }
    let mut named = policy();
    named["spec"]["egress"] = json!([{"ports":[{"port":"https","protocol":"TCP"}]}]);
    valid(&named, 37)?;
    let mut missing = policy();
    missing["spec"].as_object_mut().required()?.remove("podSelector");
    assert!(has(
        &validate_for_target(&resources(&missing)?, &target(33)?),
        FindingCode::NativeFieldInvalid,
        "/spec/podSelector"
    )?);
    Ok(())
}
#[test]
fn addresses_and_condition_presence_validate_without_readiness_defaults() -> TestResult<()> {
    for address in [
        "127.0.0.1",
        "0.0.0.0",
        "224.0.0.1",
        "169.254.1.2",
        "not-ip",
        "2001:db8::1",
    ] {
        let mut value = slice("discovery.k8s.io/v1");
        value["endpoints"][0]["addresses"] = json!([address]);
        assert!(has(
            &validate_for_target(&resources(&value)?, &target(37)?),
            FindingCode::NativeFieldInvalid,
            "/endpoints/0/addresses/0"
        )?);
    }
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["conditions"] = json!({"ready":null,"serving":false,"terminating":false});
    valid(&value, 37)?;
    assert_eq!(
        output(&resources(&value)?, 37)?["endpoints"][0]["conditions"]["ready"],
        Value::Null
    );
    value["endpoints"][0]["addresses"] = json!(["10.0.0.1", "10.0.0.1"]);
    // Native validation does not impose address uniqueness.
    valid(&value, 37)?;
    Ok(())
}
#[test]
fn class_parameter_shape_scope_and_cluster_metadata_remain_explicit() -> TestResult<()> {
    use kubernetes_lens::{
        resources::networking::{IngressClassV1, IngressClassV1Parameters},
        value::Presence,
    };
    let mut value = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":{"apiGroup":"example.org","kind":"Config","name":"p"}}}),
    );
    for minor in [20, 21, 37] {
        valid(&value, minor)?;
        assert!(
            !output(&resources(&value)?, minor)?["spec"]["parameters"]
                .as_object()
                .required()?
                .contains_key("scope")
        );
    }
    let set = resources(&value)?;
    let Presence::Value(spec) = &set.documents()[0].resource::<IngressClassV1>().required()?.spec else {
        return Err("missing class spec".into());
    };
    assert!(matches!(
        spec.parameters,
        Presence::Value(IngressClassV1Parameters::Legacy(_))
    ));
    value["spec"]["parameters"]["scope"] = json!("Namespace");
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(37)?),
        FindingCode::NativeFieldInvalid,
        "/spec/parameters/namespace"
    )?);
    value["spec"]["parameters"]["namespace"] = json!("ns");
    valid(&value, 37)?;
    value["spec"]["parameters"]["scope"] = json!("Cluster");
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(37)?),
        FindingCode::NativeFieldInvalid,
        "/spec/parameters/namespace"
    )?);
    value["metadata"]["namespace"] = json!("ns");
    assert!(resources(&value).is_err());
    Ok(())
}

#[test]
fn malformed_service_map_keys_keep_concrete_native_validation_findings() -> TestResult<()> {
    for (ports, path) in [
        (json!([{"port":0,"protocol":"TCP"}]), "/spec/ports/0/port"),
        (json!([{"port":80,"protocol":"INVALID"}]), "/spec/ports/0/protocol"),
    ] {
        let mut value = service();
        value["spec"]["ports"] = ports;
        let findings = validate_for_target(&resources(&value)?, &target(37)?);
        assert!(
            has(&findings, FindingCode::NativeFieldInvalid, path)?,
            "{path}: {findings:?}"
        );
    }
    Ok(())
}
