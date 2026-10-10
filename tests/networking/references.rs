use super::*;
use kubernetes_lens::graph::{GraphSubject, Resolution, resolve_references_for_target};
#[test]
fn service_selector_uses_real_pod_subjects_and_tracks_explicit_source_edits() -> TestResult<()> {
    let mut service = service();
    service["spec"]["selector"] = json!({"app":"web"});
    let pod = document(
        "v1",
        "Pod",
        json!({"metadata":{"name":"pod","namespace":"ns","labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"image"}]}}),
    );
    let mut set = resources(&json!({"apiVersion":"v1","kind":"List","items":[service,pod]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(graph.edges.iter().any(|edge|matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if subjects.iter().any(|subject|matches!(subject,GraphSubject::Object{..})))));
    let bytes = b"{\"app\":\"other\"}";
    let patch = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes,
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(FieldPath::parse("/spec/selector")?, patch)?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        !graph
            .edges
            .iter()
            .any(|edge| matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if !subjects.is_empty()))
    );
    Ok(())
}
#[test]
fn slice_service_label_and_ingress_front_port_evidence_do_not_claim_routing() -> TestResult<()> {
    let mut slice = slice("discovery.k8s.io/v1");
    slice["metadata"]["labels"] = json!({"kubernetes.io/service-name":"native"});
    let ingress_doc = ingress("networking.k8s.io/v1");
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[service(),slice,ingress_doc]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .filter(|edge| matches!(edge.resolution, Resolution::ResolvedSubjects(_)))
            .count()
            >= 2
    );
    assert!(graph.target_witness().is_some());
    // A complete supplied Service with no matching front port is a finite missing-port result.
    let mut wrong = ingress("networking.k8s.io/v1");
    wrong["spec"]["defaultBackend"]["service"]["port"]["number"] = json!(8080);
    valid(&wrong, 37)?;
    let wrong_set = resources(&json!({"apiVersion":"v1","kind":"List","items":[service(),wrong]}))?;
    assert!(
        resolve_references_for_target(&wrong_set, &target(37)?)
            .edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::MissingServicePort { .. }))
    );
    Ok(())
}
#[test]
fn absent_service_selector_and_empty_policy_rules_do_not_fabricate_peer_edges() -> TestResult<()> {
    let set = resources(&service())?;
    assert!(resolve_references_for_target(&set, &target(37)?).edges.is_empty());
    let mut empty_selector = service();
    empty_selector["spec"]["selector"] = json!({});
    let pod = document(
        "v1",
        "Pod",
        json!({"spec":{"containers":[{"name":"web","image":"image"}]}}),
    );
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[empty_selector,pod]}))?;
    assert!(resolve_references_for_target(&set, &target(37)?).edges.is_empty());
    let mut policy = policy();
    policy["spec"]["podSelector"] = json!({"matchLabels":{"app":"web"}});
    policy["spec"]["ingress"] = json!([]);
    let graph = resolve_references_for_target(&resources(&policy)?, &target(37)?);
    assert_eq!(graph.edges.len(), 1);
    Ok(())
}

#[test]
fn endpoint_target_reference_uses_declared_cluster_scope_without_a_namespace() -> TestResult<()> {
    let class = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller"}}),
    );
    for kind in ["EndpointSlice", "Endpoints"] {
        let reference = json!({"apiVersion":"networking.k8s.io/v1","kind":"IngressClass","name":"native"});
        let source = if kind == "EndpointSlice" {
            let mut value = slice("discovery.k8s.io/v1");
            value["endpoints"][0]["targetRef"] = reference;
            value
        } else {
            document(
                "v1",
                "Endpoints",
                json!({"subsets":[{"addresses":[{"ip":"10.0.0.1","targetRef":reference}]}]}),
            )
        };
        let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[source,class]}))?;
        let graph = resolve_references_for_target(&set, &target(37)?);
        assert_eq!(graph.edges.len(), 1);
        assert!(matches!(
            &graph.edges[0].resolution,
            Resolution::ResolvedSubjects(subjects)
                if subjects == &[GraphSubject::Object { resource: set.documents()[1].id() }]
        ));
    }
    Ok(())
}

fn supplied_pod(name: &str, namespace: &str, labels: Value, ports: Value) -> Value {
    let mut value = document(
        "v1",
        "Pod",
        json!({"metadata":{"name":name,"namespace":namespace},"spec":{"containers":[{"name":"main","image":"image"}]}}),
    );
    value["metadata"]["labels"] = labels;
    value["spec"]["containers"][0]["ports"] = ports;
    value
}

fn backend_port(
    graph: &kubernetes_lens::graph::ReferenceGraph,
) -> TestResult<&kubernetes_lens::graph::ResolvedReference> {
    graph
        .edges
        .iter()
        .find(|edge| {
            matches!(
                edge.reference.target,
                kubernetes_lens::graph::ReferenceTarget::CheckedObject {
                    predicate: Some(kubernetes_lens::graph::ReferencePredicate::ServicePortExists { .. }),
                    ..
                }
            )
        })
        .required()
}
#[test]
fn ingress_front_ports_never_match_target_or_container_ports_and_keep_beta_forms() -> TestResult<()> {
    let declaration = FieldPath::parse("/spec/ports/0")?;
    let identity_name = FieldPath::parse("/metadata/name")?;
    for (api, minor) in [
        ("networking.k8s.io/v1", 37),
        ("networking.k8s.io/v1beta1", 21),
        ("extensions/v1beta1", 21),
    ] {
        let mut supplying = service();
        supplying["spec"]["ports"][0]["targetPort"] = json!(8080);
        let mut backend = ingress(api);
        for (port, missing) in [(80, false), (8080, true)] {
            if api == "networking.k8s.io/v1" {
                backend["spec"]["defaultBackend"]["service"]["port"] = json!({"number":port});
            } else {
                backend["spec"]["backend"]["servicePort"] = json!(port);
            }
            let pod = supplied_pod("pod", "ns", json!({}), json!([{"containerPort":8080}]));
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,backend,pod]}))?;
            let graph = resolve_references_for_target(&set, &target(minor)?);
            let edge = backend_port(&graph)?;
            if missing {
                assert!(matches!(edge.resolution, Resolution::MissingServicePort { .. }));
            } else {
                assert!(
                    matches!(&edge.resolution,Resolution::ResolvedSubjects(subjects) if matches!(subjects.as_slice(),[GraphSubject::ServicePort{path,..}] if *path==declaration)),
                    "{api}: {:?}",
                    edge.resolution
                );
            }
            assert!(
                edge.evidence
                    .iter()
                    .any(|field| field.path == identity_name && field.resource == set.documents()[0].id())
            );
        }
        supplying["spec"]["ports"][0] = json!({"name":"http","port":80,"targetPort":"web"});
        for (port, missing) in [("http", false), ("web", true)] {
            if api == "networking.k8s.io/v1" {
                backend["spec"]["defaultBackend"]["service"]["port"] = json!({"name":port});
            } else {
                backend["spec"]["backend"]["servicePort"] = json!(port);
            }
            let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,backend]}))?;
            let graph = resolve_references_for_target(&set, &target(minor)?);
            assert_eq!(
                matches!(backend_port(&graph)?.resolution, Resolution::MissingServicePort { .. }),
                missing
            );
        }
    }
    Ok(())
}
#[test]
fn service_identity_port_ambiguity_and_unavailable_evidence_are_distinct() -> TestResult<()> {
    use kubernetes_lens::graph::SafeReason;
    let backend = ingress("networking.k8s.io/v1");
    let set = resources(&backend)?;
    assert!(matches!(
        backend_port(&resolve_references_for_target(&set, &target(37)?))?.resolution,
        Resolution::Missing
    ));
    let ports = json!([{"name":"tcp","port":80,"protocol":"TCP"},{"name":"udp","port":80,"protocol":"UDP"}]);
    let mut supplying = service();
    supplying["spec"]["ports"] = ports;
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,backend]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edge = backend_port(&graph)?;
    assert!(
        matches!(&edge.resolution,Resolution::AmbiguousServicePorts(subjects) if subjects.len()==2),
        "{:?}",
        edge.resolution
    );
    for pointer in [
        "/spec/ports/0/port",
        "/spec/ports/1/port",
        "/spec/ports/0/protocol",
        "/spec/ports/1/protocol",
    ] {
        let expected = FieldPath::parse(pointer)?;
        assert!(edge.evidence.iter().any(|field| field.path == expected));
    }
    let mut second = service();
    second["metadata"]["name"] = json!("initially-unique");
    let mut set = resources(&json!({"apiVersion":"v1","kind":"List","items":[service(),second,backend]}))?;
    let patch = parse_source(
        SourceInput {
            id: SourceId(82),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"native\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[1].set_field_from_source(FieldPath::parse("/metadata/name")?, patch)?;
    assert!(
        matches!(backend_port(&resolve_references_for_target(&set,&target(37)?))?.resolution,Resolution::Ambiguous(ref ids) if ids.len()==2)
    );
    let mut supplying = service();
    supplying["spec"]["ports"] = Value::Null;
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,backend]}))?;
    assert!(matches!(
        backend_port(&resolve_references_for_target(&set, &target(37)?))?.resolution,
        Resolution::Unsupported(SafeReason::FactUnknown(_))
    ));
    let beta = ingress("networking.k8s.io/v1beta1");
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[service(),beta]}))?;
    let graph = resolve_references_for_target(&set, &target(25)?);
    assert!(graph.findings.iter().any(
        |finding| finding.code == FindingCode::UnavailableApi && finding.resource == Some(set.documents()[1].id())
    ));
    assert!(
        !graph
            .edges
            .iter()
            .any(|edge| edge.reference.from == set.documents()[1].id())
    );
    let reference = kubernetes_lens::graph::Reference {
        from: set.documents()[1].id(),
        path: FieldPath::parse("/spec/backend")?,
        relation: kubernetes_lens::graph::RelationshipKind::Dependency,
        target: kubernetes_lens::graph::ReferenceTarget::CheckedObject {
            gvk: kubernetes_lens::model::GroupVersionKind::new("v1", "Service")?,
            name: "native".into(),
            predicate: Some(kubernetes_lens::graph::ReferencePredicate::ServicePortExists {
                port: kubernetes_lens::graph::ServicePortSelector::Number(80),
            }),
            optional: kubernetes_lens::value::Presence::Absent,
        },
        scope: kubernetes_lens::graph::ReferenceScope::SameNamespace,
    };
    let graph = kubernetes_lens::graph::resolve_supplied_references_for_target(
        &set,
        &[reference],
        &kubernetes_lens::graph::ReferenceContext::default(),
        &target(25)?,
    );
    assert_eq!(
        backend_port(&graph)?.resolution,
        Resolution::Unsupported(SafeReason::InvalidIdentity)
    );
    assert!(graph.findings.iter().any(
        |finding| finding.code == FindingCode::UnavailableApi && finding.resource == Some(set.documents()[1].id())
    ));
    Ok(())
}
#[test]
fn named_service_target_ports_combine_selection_protocol_and_complete_port_evidence() -> TestResult<()> {
    use kubernetes_lens::graph::ReferenceTarget;
    let mut supplying = service();
    supplying["spec"]["selector"] = json!({"app":"web"});
    supplying["spec"]["ports"][0]["targetPort"] = json!("web");
    let tcp = supplied_pod(
        "tcp",
        "ns",
        json!({"app":"web"}),
        json!([{"name":"web","containerPort":8080}]),
    );
    let udp = supplied_pod(
        "udp",
        "ns",
        json!({"app":"web"}),
        json!([{"name":"web","containerPort":8081,"protocol":"UDP"}]),
    );
    let unselected = supplied_pod(
        "other",
        "ns",
        json!({"app":"other"}),
        json!([{"name":"web","containerPort":8080}]),
    );
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,tcp,udp,unselected]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NamedServiceTargetPort { .. }))
        .required()?;
    assert_eq!(
        edge.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[1].id()
        }])
    );
    let incomplete = document(
        "apps/v1",
        "Deployment",
        json!({
            "metadata":{"name":"incomplete","namespace":"ns"},
            "spec":{"selector":{"matchLabels":{"app":"web"}},"template":{
                "metadata":{"labels":{"app":"web"}},
                "spec":{"containers":[{"name":"main","image":"image","ports":[{"name":"web","containerPort":8080}]}]}
            }}
        }),
    );
    let mut set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,tcp,incomplete]}))?;
    let invalid = parse_source(
        SourceInput {
            id: SourceId(73),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"\"malformed\"",
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[2].set_field_from_source(
        FieldPath::parse("/spec/template/spec/containers/0/ports/0/containerPort")?,
        invalid,
    )?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NamedServiceTargetPort { .. }))
        .required()?;
    assert!(
        matches!(&edge.resolution,Resolution::PartiallyResolvedSubjects{matched,unavailable} if matched.len()==1 && !unavailable.is_empty())
    );
    let no_port = supplied_pod("none", "ns", json!({"app":"web"}), json!([]));
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,no_port]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .any(|edge| matches!(&edge.resolution,Resolution::MissingContainerPort{selected} if selected.len()==1))
    );
    Ok(())
}
#[test]
fn policy_universal_presence_and_same_entry_unknown_conjunction_are_explicit() -> TestResult<()> {
    use kubernetes_lens::graph::{PeerListPresence, ReferenceTarget};
    for (rule, expected) in [
        (json!({}), PeerListPresence::Absent),
        (json!({"from":[]}), PeerListPresence::ExplicitEmpty),
    ] {
        let mut policy = policy();
        policy["spec"]["ingress"] = json!([rule]);
        let graph = resolve_references_for_target(&resources(&policy)?, &target(37)?);
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| edge.resolution == Resolution::NetworkPolicyAllPeers(expected))
        );
    }
    for rule in [
        json!({"from":null}),
        json!({"from":[{}]}),
        json!({"from":[{"podSelector":null}]}),
        json!({"from":[{"ipBlock":{"cidr":"10.0.0.0/8"},"podSelector":{}}]}),
    ] {
        let mut policy = policy();
        policy["spec"]["ingress"] = json!([rule]);
        let graph = resolve_references_for_target(&resources(&policy)?, &target(37)?);
        assert!(graph.edges.iter().any(|edge| matches!(
            edge.reference.target,
            ReferenceTarget::NetworkPolicyPeer { .. } | ReferenceTarget::NetworkPolicyAllPeers { .. }
        ) && matches!(edge.resolution, Resolution::Unsupported(_))));
    }
    let mut policy = policy();
    policy["spec"]["ingress"] =
        json!([{"from":[{"namespaceSelector":{},"podSelector":{"matchLabels":{"app":"web"}}}]}]);
    let matching = supplied_pod("web", "other", json!({"app":"web"}), json!([]));
    let excluded = supplied_pod("other", "missing", json!({"app":"other"}), json!([]));
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[policy,matching,excluded]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let peer = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .required()?;
    assert_eq!(
        peer.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[1].id()
        }])
    );
    policy["spec"]["ingress"][0]["from"][0]["namespaceSelector"] = json!({"matchLabels":{"team":"a"}});
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[policy,matching,excluded]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let peer = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .required()?;
    assert!(
        matches!(&peer.resolution,Resolution::PartiallyResolvedSubjects{matched,unavailable} if matched.is_empty() && unavailable.len()==1 && unavailable[0].resource==set.documents()[1].id())
    );
    Ok(())
}
#[test]
fn versionless_backend_and_class_parameters_preserve_group_and_scope_presence() -> TestResult<()> {
    use kubernetes_lens::graph::ReferenceTarget;
    let mut backend = ingress("networking.k8s.io/v1");
    backend["spec"]["defaultBackend"] = json!({"resource":{"kind":"Service","name":"native"}});
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[backend,service()]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(graph.edges.iter().any(
        |edge| matches!(edge.reference.target, ReferenceTarget::GroupKindName { .. })
            && matches!(edge.resolution, Resolution::ResolvedSubjects(_))
    ));
    assert!(
        output(&resources(&backend)?, 37)?["spec"]["defaultBackend"]["resource"]
            .get("apiGroup")
            .is_none()
    );
    backend["spec"]["defaultBackend"]["resource"]["apiGroup"] = Value::Null;
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[backend,service()]}))?;
    assert!(
        resolve_references_for_target(&set, &target(37)?)
            .edges
            .iter()
            .any(
                |edge| matches!(edge.reference.target, ReferenceTarget::GroupKindName { .. })
                    && matches!(edge.resolution, Resolution::Unsupported(_))
            )
    );
    let mut class = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"spec":{"controller":"example.org/controller","parameters":{"apiGroup":"networking.k8s.io","kind":"IngressClass","name":"supplier"}}}),
    );
    let supplier = document(
        "networking.k8s.io/v1",
        "IngressClass",
        json!({"metadata":{"name":"supplier"},"spec":{"controller":"example.org/controller"}}),
    );
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[class,supplier]}))?;
    assert!(
        resolve_references_for_target(&set, &target(24)?)
            .edges
            .iter()
            .any(
                |edge| matches!(edge.reference.target, ReferenceTarget::GroupKindName { .. })
                    && matches!(edge.resolution, Resolution::ResolvedSubjects(_))
            )
    );
    assert!(
        output(&resources(&class)?, 24)?["spec"]["parameters"]
            .get("scope")
            .is_none()
    );
    class["spec"]["parameters"] = json!({"kind":"Service","name":"native","scope":"Namespace","namespace":"ns"});
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[class,service()]}))?;
    let graph = resolve_references_for_target(&set, &target(24)?);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::GroupKindName { .. }))
        .required()?;
    assert!(
        matches!(edge.resolution, Resolution::ResolvedSubjects(_)),
        "{:?}",
        edge.resolution
    );
    for pointer in ["/spec/parameters/scope", "/spec/parameters/namespace"] {
        let path = FieldPath::parse(pointer)?;
        assert!(
            edge.evidence
                .iter()
                .any(|field| field.resource == set.documents()[0].id() && field.path == path)
        );
    }
    let mut forged = edge.reference.clone();
    forged.scope = kubernetes_lens::graph::ReferenceScope::Cluster;
    let graph = kubernetes_lens::graph::resolve_supplied_references_for_target(
        &set,
        &[forged],
        &kubernetes_lens::graph::ReferenceContext::default(),
        &target(24)?,
    );
    assert!(matches!(graph.edges[0].resolution, Resolution::Unsupported(_)));
    Ok(())
}

#[test]
fn named_service_target_port_edits_recompute_selection_and_protocol() -> TestResult<()> {
    use kubernetes_lens::{graph::ReferenceTarget, resources::networking::Service, value::Presence};
    let mut supplying = service();
    supplying["spec"]["selector"] = json!({"app":"web"});
    supplying["spec"]["ports"][0]["targetPort"] = json!("web");
    let tcp = supplied_pod(
        "tcp",
        "ns",
        json!({"app":"web"}),
        json!([{"name":"web","containerPort":8080}]),
    );
    let udp = supplied_pod(
        "udp",
        "ns",
        json!({"app":"other"}),
        json!([{"name":"other","containerPort":8081,"protocol":"UDP"}]),
    );
    let mut set = resources(&json!({"apiVersion":"v1","kind":"List","items":[supplying,tcp,udp]}))?;
    let expected = set.documents()[2].id();
    let service = set.documents_mut()[0].resource_mut::<Service>().required()?;
    let Presence::Value(spec) = &mut service.spec else {
        return Err("missing spec".into());
    };
    spec.selector = Presence::Value(std::collections::BTreeMap::from([(
        "app".to_owned(),
        "other".to_owned(),
    )]));
    let Presence::Value(ports) = &mut spec.ports else {
        return Err("missing ports".into());
    };
    ports[0].target_port = Presence::Value(kubernetes_lens::value::IntOrString::String("other".to_owned()));
    ports[0].protocol = Presence::Value("UDP".to_owned());
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NamedServiceTargetPort { .. }))
        .required()?;
    assert_eq!(
        edge.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object { resource: expected }])
    );
    for pointer in ["/spec/selector", "/spec/ports/0/targetPort", "/spec/ports/0/protocol"] {
        let path = FieldPath::parse(pointer)?;
        assert!(
            edge.evidence
                .iter()
                .any(|field| field.resource == set.documents()[0].id()
                    && field.path == path
                    && field.position.is_none())
        );
    }
    Ok(())
}

#[test]
fn policy_absent_namespaces_require_explicit_comparison_context() -> TestResult<()> {
    use kubernetes_lens::graph::{ReferenceContext, ReferenceTarget, resolve_references_with_context_for_target};
    let mut policy = policy();
    policy["metadata"].as_object_mut().required()?.remove("namespace");
    policy["spec"]["ingress"] = json!([{"from":[{"podSelector":{}}]}]);
    let mut pod = supplied_pod("pod", "ns", json!({}), json!([]));
    pod["metadata"].as_object_mut().required()?.remove("namespace");
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[policy,pod]}))?;
    let target = target(37)?;
    let graph = resolve_references_for_target(&set, &target);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .required()?;
    assert!(
        matches!(&edge.resolution,Resolution::PartiallyResolvedSubjects{matched,unavailable} if matched.is_empty() && unavailable.len()==1)
    );
    let context = ReferenceContext {
        default_namespace: Some("explicit".to_owned()),
        ..ReferenceContext::default()
    };
    let graph = resolve_references_with_context_for_target(&set, &context, &target);
    let edge = graph
        .edges
        .iter()
        .find(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .required()?;
    assert_eq!(
        edge.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[1].id()
        }])
    );
    Ok(())
}

#[test]
fn normalized_duplicate_service_ports_fail_closed_until_explicit_repair() -> TestResult<()> {
    use kubernetes_lens::{graph::SafeReason, source::ExplicitSourceAccess};
    let mut supplying = service();
    supplying["spec"]["ports"] = json!([
        {"name":"implicit","port":80,"future":"first-private"},
        {"name":"explicit","port":80,"protocol":"TCP","future":"second-private"}
    ]);
    let document = json!({"apiVersion":"v1","kind":"List","items":[supplying,ingress("networking.k8s.io/v1")]});
    let original = serde_json::to_vec(&document)?;
    let mut set = resources(&document)?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(matches!(
        backend_port(&graph)?.resolution,
        Resolution::Unsupported(SafeReason::FactUnknown(_))
    ));
    let ports_path = FieldPath::parse("/spec/ports")?;
    assert!(
        graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::MergeConflict && finding.path.as_ref() == Some(&ports_path))
    );
    let options = GenerationOptions {
        json_shape: JsonShape::KubernetesList,
        collections: kubernetes_lens::generation::CollectionOutput::Flatten,
        ..options()
    };
    let rejected = generate(&set, &target(37)?, OutputFormat::Json, &options)
        .err()
        .required()?;
    assert!(
        rejected
            .iter()
            .any(|finding| finding.code == FindingCode::MergeConflict)
    );
    let repaired = json!([
        {"name":"implicit","port":80,"future":"first-private"},
        {"name":"explicit","port":81,"protocol":"TCP","future":"second-private"}
    ]);
    let repair_bytes = serde_json::to_vec(&repaired)?;
    let patch = parse_source(
        SourceInput {
            id: SourceId(81),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &repair_bytes,
        },
        &ParseLimits::default(),
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(ports_path, patch)?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert_eq!(
        backend_port(&graph)?.resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::ServicePort {
            resource: set.documents()[0].id(),
            path: FieldPath::parse("/spec/ports/0")?
        }])
    );
    let artifact = generate(&set, &target(37)?, OutputFormat::Json, &options).required()?;
    let generated: Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    let items = generated.get("items").and_then(Value::as_array).required()?;
    assert_eq!(items[0]["spec"]["ports"], repaired);
    assert!(items[0]["spec"]["ports"][0].get("protocol").is_none());
    assert_eq!(
        set.documents()[0]
            .source_evidence()
            .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        original
    );
    Ok(())
}

#[test]
fn ingress_rule_backends_follow_reordered_front_ports_and_source_patches() -> TestResult<()> {
    use kubernetes_lens::{resources::networking::Service, value::Presence};
    for (api, minor) in [
        ("networking.k8s.io/v1", 37),
        ("networking.k8s.io/v1beta1", 21),
        ("extensions/v1beta1", 21),
    ] {
        let mut supplying = service();
        supplying["spec"]["ports"] = json!([
            {"name":"first","port":80,"future":"first-private"},
            {"name":"second","port":81,"future":"second-private"}
        ]);
        let mut backend = ingress(api);
        let root = if api == "networking.k8s.io/v1" {
            "defaultBackend"
        } else {
            "backend"
        };
        let declaration = backend["spec"][root].clone();
        backend["spec"].as_object_mut().required()?.remove(root);
        backend["spec"]["rules"] = json!([{"http":{"paths":[{"path":"/","pathType":"Prefix","backend":declaration}]}}]);
        let document = json!({"apiVersion":"v1","kind":"List","items":[supplying,backend]});
        let mut set = resources(&document)?;
        let native = set.documents_mut()[0].resource_mut::<Service>().required()?;
        let Presence::Value(spec) = &mut native.spec else {
            return Err("missing spec".into());
        };
        let Presence::Value(ports) = &mut spec.ports else {
            return Err("missing ports".into());
        };
        ports.swap(0, 1);
        let graph = resolve_references_for_target(&set, &target(minor)?);
        let edge = backend_port(&graph)?;
        assert_eq!(
            edge.resolution,
            Resolution::ResolvedSubjects(vec![GraphSubject::ServicePort {
                resource: set.documents()[0].id(),
                path: FieldPath::parse("/spec/ports/1")?
            }])
        );
        let current_port = FieldPath::parse("/spec/ports/1/port")?;
        assert!(edge.evidence.iter().any(|field| field.path == current_port
            && field.resource == set.documents()[0].id()
            && field.position.is_none()));
        let (pointer, bytes): (&str, &[u8]) = if api == "networking.k8s.io/v1" {
            ("/spec/rules/0/http/paths/0/backend/service/port", b"{\"number\":81}")
        } else {
            ("/spec/rules/0/http/paths/0/backend/servicePort", b"81")
        };
        let patch = parse_source(
            SourceInput {
                id: SourceId(84),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes,
            },
            &ParseLimits::default(),
        )
        .required()?;
        set.documents_mut()[1].set_field_from_source(FieldPath::parse(pointer)?, patch)?;
        let graph = resolve_references_for_target(&set, &target(minor)?);
        assert_eq!(
            backend_port(&graph)?.resolution,
            Resolution::ResolvedSubjects(vec![GraphSubject::ServicePort {
                resource: set.documents()[0].id(),
                path: FieldPath::parse("/spec/ports/0")?
            }])
        );
    }
    Ok(())
}

/// Uses actual v1 Namespace documents; never substitutes a synthetic graph supplier.
#[test]
fn native_namespace_and_pod_selectors_conjoin_within_each_peer_and_union_across_peers() -> TestResult<()> {
    use kubernetes_lens::graph::ReferenceTarget;
    let mut policy = policy();
    policy["spec"]["ingress"] = json!([{"from":[{
        "namespaceSelector":{"matchLabels":{"team":"a"}},
        "podSelector":{"matchLabels":{"app":"web"}}
    }]}]);
    let namespaces: Vec<Value> = [("team-a", "a"), ("team-b", "b")]
        .into_iter()
        .map(|(name, team)| json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":name,"labels":{"team":team}}}))
        .collect();
    let matching = supplied_pod("both", "team-a", json!({"app":"web"}), json!([]));
    let namespace_only = supplied_pod("namespace-only", "team-a", json!({"app":"other"}), json!([]));
    let pod_only = supplied_pod("pod-only", "team-b", json!({"app":"web"}), json!([]));
    let input = json!({"apiVersion":"v1","kind":"List","items":[
        policy,namespaces[0],namespaces[1],matching,namespace_only,pod_only
    ]});
    let set = resources(&input)?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let peers: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .collect();
    assert_eq!(peers.len(), 1);
    assert_eq!(
        peers[0].resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[3].id()
        }])
    );
    let labels = FieldPath::parse("/metadata/labels")?;
    assert!(
        peers[0]
            .evidence
            .iter()
            .any(|field| field.resource == set.documents()[1].id() && field.path == labels)
    );

    // Separate native peer entries produce independent relations whose union includes
    // the namespace-only Pod and the pod-only Pod in the policy's own namespace.
    let mut separated = input;
    separated["items"][0]["metadata"]["namespace"] = json!("team-b");
    separated["items"][0]["spec"]["ingress"][0]["from"] = json!([
        {"namespaceSelector":{"matchLabels":{"team":"a"}}},
        {"podSelector":{"matchLabels":{"app":"web"}}}
    ]);
    let set = resources(&separated)?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let peers: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| matches!(edge.reference.target, ReferenceTarget::NetworkPolicyPeer { .. }))
        .collect();
    assert_eq!(peers.len(), 2);
    assert_eq!(
        peers[0].resolution,
        Resolution::ResolvedSubjects(vec![
            GraphSubject::Object {
                resource: set.documents()[3].id()
            },
            GraphSubject::Object {
                resource: set.documents()[4].id()
            }
        ])
    );
    assert_eq!(
        peers[1].resolution,
        Resolution::ResolvedSubjects(vec![GraphSubject::Object {
            resource: set.documents()[5].id()
        }])
    );
    Ok(())
}
