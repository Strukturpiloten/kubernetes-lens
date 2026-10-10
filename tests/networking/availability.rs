use super::*;
use kubernetes_lens::{
    capability::{FeatureGateId, FeatureGateState},
    resources::networking::*,
};
#[test]
fn ten_exact_api_roots_decode_and_generate_without_relabeling() -> TestResult<()> {
    for (api, kind, body, minor) in [
        ("v1", "Service", service(), 37),
        (
            "v1",
            "Endpoints",
            document(
                "v1",
                "Endpoints",
                json!({"subsets":[{"addresses":[{"ip":"10.0.0.1"}],"ports":[{"port":80}]}]}),
            ),
            37,
        ),
        ("discovery.k8s.io/v1", "EndpointSlice", slice("discovery.k8s.io/v1"), 37),
        (
            "discovery.k8s.io/v1beta1",
            "EndpointSlice",
            slice("discovery.k8s.io/v1beta1"),
            24,
        ),
        ("networking.k8s.io/v1", "Ingress", ingress("networking.k8s.io/v1"), 37),
        (
            "networking.k8s.io/v1beta1",
            "Ingress",
            ingress("networking.k8s.io/v1beta1"),
            21,
        ),
        ("extensions/v1beta1", "Ingress", ingress("extensions/v1beta1"), 21),
        (
            "networking.k8s.io/v1",
            "IngressClass",
            document(
                "networking.k8s.io/v1",
                "IngressClass",
                json!({"spec":{"controller":"example.org/controller"}}),
            ),
            37,
        ),
        (
            "networking.k8s.io/v1beta1",
            "IngressClass",
            document(
                "networking.k8s.io/v1beta1",
                "IngressClass",
                json!({"spec":{"controller":"example.org/controller"}}),
            ),
            21,
        ),
        ("networking.k8s.io/v1", "NetworkPolicy", policy(), 37),
    ] {
        let set = resources(&body)?;
        let doc = &set.documents()[0];
        assert!(match (kind, api) {
            ("Service", _) => doc.resource::<Service>().is_some(),
            ("Endpoints", _) => doc.resource::<Endpoints>().is_some(),
            ("EndpointSlice", "discovery.k8s.io/v1") => doc.resource::<EndpointSliceV1>().is_some(),
            ("EndpointSlice", _) => doc.resource::<EndpointSliceV1Beta1>().is_some(),
            ("Ingress", "networking.k8s.io/v1") => doc.resource::<IngressV1>().is_some(),
            ("Ingress", "networking.k8s.io/v1beta1") => doc.resource::<IngressV1Beta1>().is_some(),
            ("Ingress", _) => doc.resource::<IngressExtensionsV1Beta1>().is_some(),
            ("IngressClass", "networking.k8s.io/v1") => doc.resource::<IngressClassV1>().is_some(),
            ("IngressClass", _) => doc.resource::<IngressClassV1Beta1>().is_some(),
            ("NetworkPolicy", _) => doc.resource::<NetworkPolicy>().is_some(),
            _ => false,
        });
        valid(&body, minor)?;
        let value = output(&set, minor)?;
        assert_eq!(value["apiVersion"], api);
        assert_eq!(value["kind"], kind);
    }
    Ok(())
}
#[test]
fn served_api_boundaries_do_not_relabel_beta_or_materialize_fields() -> TestResult<()> {
    for (value, before, after) in [
        (slice("discovery.k8s.io/v1beta1"), 24, 25),
        (ingress("networking.k8s.io/v1beta1"), 21, 22),
        (ingress("extensions/v1beta1"), 21, 22),
        (
            document(
                "networking.k8s.io/v1beta1",
                "IngressClass",
                json!({"spec":{"controller":"example.org/controller"}}),
            ),
            21,
            22,
        ),
    ] {
        let set = resources(&value)?;
        output(&set, before)?;
        let findings = validate_for_target(&set, &target(after)?);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnavailableApi)
        );
        assert!(generate(&set, &target(after)?, OutputFormat::Json, &options()).is_err());
    }
    let set = resources(&slice("discovery.k8s.io/v1"))?;
    assert!(
        validate_for_target(&set, &target(20)?)
            .iter()
            .any(|finding| finding.code == FindingCode::UnavailableApi)
    );
    output(&set, 21)?;
    Ok(())
}
#[test]
fn stable_gate_boundaries_reject_explicit_pre_stable_enable() -> TestResult<()> {
    for (gate, boundary, path, body) in [
        (
            FeatureGateId::IPv6DualStack,
            23,
            "/spec/ipFamilyPolicy",
            json!({"ipFamilyPolicy":"SingleStack"}),
        ),
        (
            FeatureGateId::ServiceLBNodePortControl,
            24,
            "/spec/allocateLoadBalancerNodePorts",
            json!({"type":"LoadBalancer","allocateLoadBalancerNodePorts":false}),
        ),
        (
            FeatureGateId::ServiceLoadBalancerClass,
            24,
            "/spec/loadBalancerClass",
            json!({"type":"LoadBalancer","loadBalancerClass":"example.org/class"}),
        ),
        (
            FeatureGateId::ServiceInternalTrafficPolicy,
            26,
            "/spec/internalTrafficPolicy",
            json!({"internalTrafficPolicy":"Cluster"}),
        ),
        (
            FeatureGateId::ServiceTrafficDistribution,
            33,
            "/spec/trafficDistribution",
            json!({"trafficDistribution":"PreferClose"}),
        ),
    ] {
        let mut value = service();
        for (key, member) in body.as_object().required()? {
            value["spec"][key] = member.clone();
        }
        let set = resources(&value)?;
        let findings = validate_for_target(&set, &target(boundary - 1)?);
        assert!(findings.iter().any(|finding| matches!(
            finding.code,
            FindingCode::UnavailableField | FindingCode::FeatureGateRequired | FindingCode::UnadmittedField
        )));
        output(&set, boundary)?;
        let mut profile = target(boundary - 1)?;
        profile.feature_gates.states.insert(gate, FeatureGateState::Enabled);
        let findings = validate_for_target(&set, &profile);
        assert!(
            findings.iter().any(|finding| matches!(
                finding.code,
                FindingCode::InvalidTargetProfile
                    | FindingCode::UnadmittedField
                    | FindingCode::UnavailableField
                    | FindingCode::FeatureGateRequired
            )),
            "{path}"
        );
    }
    Ok(())
}
#[test]
fn endpoint_conditions_node_names_and_class_scopes_keep_each_gate_boundary() -> TestResult<()> {
    let mut beta = slice("discovery.k8s.io/v1beta1");
    beta["endpoints"][0]["nodeName"] = json!("node");
    assert!(
        validate_for_target(&resources(&beta)?, &target(20)?)
            .iter()
            .any(|finding| matches!(
                finding.code,
                FindingCode::UnavailableField | FindingCode::FeatureGateRequired | FindingCode::UnadmittedField
            ))
    );
    output(&resources(&beta)?, 21)?;
    let mut stable = slice("discovery.k8s.io/v1");
    stable["endpoints"][0]["conditions"] = json!({"serving":false,"terminating":true});
    assert!(generate(&resources(&stable)?, &target(25)?, OutputFormat::Json, &options()).is_err());
    output(&resources(&stable)?, 26)?;
    let value = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":{"apiGroup":"example.org","kind":"Config","name":"p","scope":"Namespace","namespace":"ns"}}}),
    );
    assert!(generate(&resources(&value)?, &target(22)?, OutputFormat::Json, &options()).is_err());
    output(&resources(&value)?, 23)?;
    Ok(())
}
#[test]
fn endpoint_slice_required_array_profile_boundary_is_preserved() -> TestResult<()> {
    let value = document("discovery.k8s.io/v1", "EndpointSlice", json!({"addressType":"IPv4"}));
    assert!(has(
        &validate_for_target(&resources(&value)?, &target(35)?),
        FindingCode::NativeFieldInvalid,
        "/endpoints"
    )?);
    assert!(!has(
        &validate_for_target(&resources(&value)?, &target(36)?),
        FindingCode::NativeFieldInvalid,
        "/endpoints"
    )?);
    Ok(())
}
