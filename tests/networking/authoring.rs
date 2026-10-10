use super::*;
use kubernetes_lens::{
    model::{AuthoredResource, Metadata},
    resources::networking::*,
    source::{AuthoringLimits, EvidenceOrigin, ValueOrigin},
    value::Presence,
};
fn metadata(name: &str, namespaced: bool) -> Metadata {
    Metadata {
        name: Presence::Value(name.to_owned()),
        namespace: if namespaced {
            Presence::Value("ns".to_owned())
        } else {
            Presence::Absent
        },
        ..Metadata::default()
    }
}
#[test]
fn source_free_networking_declarations_generate_with_private_positionless_evidence() -> TestResult<()> {
    let mut port = ServicePort::default();
    port.port = Presence::Value(80);
    port.protocol = Presence::Value("TCP".to_owned());
    let mut spec = ServiceSpec::default();
    spec.ports = Presence::Value(vec![port]);
    let mut service = Service::default();
    service.metadata = Presence::Value(metadata("service", true));
    service.spec = Presence::Value(spec);
    let mut endpoint = EndpointDiscoveryV1::default();
    endpoint.addresses = Presence::Value(vec!["10.0.0.1".to_owned()]);
    let mut slice = EndpointSliceV1::default();
    slice.metadata = Presence::Value(metadata("slice", true));
    slice.address_type = Presence::Value("IPv4".to_owned());
    slice.endpoints = Presence::Value(vec![endpoint]);
    let mut class_spec = IngressClassV1Spec::default();
    class_spec.controller = Presence::Value("example.org/controller".to_owned());
    let mut class = IngressClassV1::default();
    class.metadata = Presence::Value(metadata("class", false));
    class.spec = Presence::Value(class_spec);
    let values: Vec<AuthoredResource> = vec![service.into(), slice.into(), class.into()];
    let set = ResourceSet::from_authored(values, &target(37)?, &AuthoringLimits::default()).required()?;
    for doc in set.documents() {
        assert_eq!(doc.source_evidence().origin, EvidenceOrigin::NativeAuthored);
        let evidence = doc
            .field_evidence()
            .get(&FieldPath::parse("/metadata/name")?)
            .required()?;
        assert_eq!(evidence.origin, ValueOrigin::Generated);
        assert!(evidence.position.is_none());
    }
    let mut opts = options();
    opts.json_shape = JsonShape::KubernetesList;
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &opts).required()?;
    let output: Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert_eq!(output["items"][0]["spec"]["ports"][0]["port"], 80);
    assert_eq!(output["items"][1]["endpoints"][0]["addresses"][0], "10.0.0.1");
    assert_eq!(output["items"][2]["spec"]["controller"], "example.org/controller");
    Ok(())
}
#[test]
fn source_free_limits_and_required_fields_are_not_bypassed() -> TestResult<()> {
    let mut value = Service::default();
    value.metadata = Presence::Value(metadata("service", true));
    value.spec = Presence::Value(ServiceSpec::default());
    assert!(ResourceSet::from_authored(vec![value.into()], &target(37)?, &AuthoringLimits::default()).is_err());
    let mut value = Endpoints::default();
    value.metadata = Presence::Value(metadata("endpoints", true));
    let limits = AuthoringLimits {
        max_resources: 0,
        ..AuthoringLimits::default()
    };
    let findings = ResourceSet::from_authored(vec![value.into()], &target(37)?, &limits)
        .err()
        .required()?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded)
    );
    Ok(())
}
#[test]
fn every_beta_and_policy_root_supports_real_source_free_construction() -> TestResult<()> {
    use kubernetes_lens::value::{IntOrString, LabelSelector};
    let mut endpoints = Endpoints::default();
    endpoints.metadata = Presence::Value(metadata("endpoints", true));
    let mut beta_endpoint = EndpointDiscoveryV1beta1::default();
    beta_endpoint.addresses = Presence::Value(vec!["10.0.0.1".to_owned()]);
    let mut slice = EndpointSliceV1Beta1::default();
    slice.metadata = Presence::Value(metadata("slice-beta", true));
    slice.address_type = Presence::Value("IPv4".to_owned());
    slice.endpoints = Presence::Value(vec![beta_endpoint]);
    let mut port = ServiceBackendPortNetworkingV1::default();
    port.number = Presence::Value(80);
    let mut service = IngressServiceBackendNetworkingV1::default();
    service.name = Presence::Value("backend".to_owned());
    service.port = Presence::Value(port);
    let mut backend = IngressBackendNetworkingV1::default();
    backend.service = Presence::Value(service);
    let mut spec = IngressV1Spec::default();
    spec.default_backend = Presence::Value(backend);
    let mut ingress = IngressV1::default();
    ingress.metadata = Presence::Value(metadata("ingress", true));
    ingress.spec = Presence::Value(spec);
    let mut backend = IngressBackendNetworkingV1beta1::default();
    backend.service_name = Presence::Value("backend".to_owned());
    backend.service_port = Presence::Value(IntOrString::Int(80));
    let mut spec = IngressV1Beta1Spec::default();
    spec.backend = Presence::Value(backend);
    let mut beta = IngressV1Beta1::default();
    beta.metadata = Presence::Value(metadata("ingress-beta", true));
    beta.spec = Presence::Value(spec);
    let mut backend = IngressBackendExtensionsV1beta1::default();
    backend.service_name = Presence::Value("backend".to_owned());
    backend.service_port = Presence::Value(IntOrString::Int(80));
    let mut spec = IngressExtensionsV1Beta1Spec::default();
    spec.backend = Presence::Value(backend);
    let mut extensions = IngressExtensionsV1Beta1::default();
    extensions.metadata = Presence::Value(metadata("ingress-extensions", true));
    extensions.spec = Presence::Value(spec);
    let mut spec = IngressClassV1Beta1Spec::default();
    spec.controller = Presence::Value("example.org/controller".to_owned());
    let mut class = IngressClassV1Beta1::default();
    class.metadata = Presence::Value(metadata("class-beta", false));
    class.spec = Presence::Value(spec);
    let mut spec = NetworkPolicySpec::default();
    spec.pod_selector = Presence::Value(LabelSelector::default());
    let mut policy = NetworkPolicy::default();
    policy.metadata = Presence::Value(metadata("policy", true));
    policy.spec = Presence::Value(spec);
    let values: Vec<AuthoredResource> = vec![
        endpoints.into(),
        slice.into(),
        ingress.into(),
        beta.into(),
        extensions.into(),
        class.into(),
        policy.into(),
    ];
    let set = ResourceSet::from_authored(values, &target(21)?, &AuthoringLimits::default()).required()?;
    assert_eq!(set.documents().len(), 7);
    for doc in set.documents() {
        assert_eq!(doc.source_evidence().origin, EvidenceOrigin::NativeAuthored);
    }
    Ok(())
}
