//! Independent cumulative-budget regressions for the native networking integration.
use super::*;
use kubernetes_lens::{
    graph::{ReferenceContext, Resolution, resolve_references_with_context_for_target},
    processing::NativeProcessingLimits,
};
fn graph(set: &ResourceSet, ceiling: NativeProcessingLimits) -> TestResult<kubernetes_lens::graph::ReferenceGraph> {
    Ok(resolve_references_with_context_for_target(
        set,
        &ReferenceContext {
            processing: Some(ceiling),
            ..ReferenceContext::default()
        },
        &target(37)?,
    ))
}
fn terminal(findings: &[Finding]) {
    assert_eq!(
        findings
            .iter()
            .filter(|finding| finding.code == FindingCode::LimitExceeded)
            .count(),
        1
    );
    assert!(
        findings
            .iter()
            .find(|finding| finding.code == FindingCode::LimitExceeded)
            .is_some_and(|finding| finding.path.is_none())
    );
}
fn subjects() -> Value {
    let mut selected = service();
    selected["spec"]["selector"] = json!({"app":"web"});
    selected["spec"]["ports"] = json!([{ "port":80, "targetPort":"http", "protocol":"TCP" }, { "port":443, "targetPort":"https", "protocol":"TCP" }]);
    let pod = document(
        "v1",
        "Pod",
        json!({"metadata":{"name":"pod","namespace":"ns","labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"image","ports":[{"name":"http","containerPort":8080,"protocol":"TCP"},{"name":"https","containerPort":8443,"protocol":"TCP"}]}]}}),
    );
    let mut policy = policy();
    policy["spec"]["podSelector"] = json!({"matchLabels":{"app":"web"}});
    policy["spec"]["ingress"] =
        json!([{ "from":[{ "podSelector":{"matchLabels":{"app":"web"}},"namespaceSelector":{} }] }]);
    json!({"apiVersion":"v1","kind":"List","items":[selected,pod,policy,ingress("networking.k8s.io/v1")]})
}
fn minimum(mut succeeds: impl FnMut(usize) -> TestResult<bool>) -> TestResult<usize> {
    let mut low = 0;
    let mut high = NativeProcessingLimits::default().max_processing_units;
    assert!(succeeds(high)?);
    while low < high {
        let middle = low + (high - low) / 2;
        if succeeds(middle)? {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low)
}
#[test]
fn tiny_networking_graph_work_and_payload_ceilings_fail_closed() -> TestResult<()> {
    let set = resources(&subjects())?;
    let good = graph(&set, NativeProcessingLimits::default())?;
    assert!(
        good.edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::ResolvedSubjects(_)))
    );
    for ceiling in [
        NativeProcessingLimits {
            max_processing_units: 1,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_payload_bytes: 1,
            ..NativeProcessingLimits::default()
        },
    ] {
        let bounded = graph(&set, ceiling)?;
        terminal(&bounded.findings);
        assert!(
            bounded
                .edges
                .iter()
                .all(|edge| edge.evidence.is_empty() && matches!(edge.resolution, Resolution::Unsupported(_)))
        );
    }
    Ok(())
}
#[test]
fn late_networking_graph_exhaustion_removes_prior_positive_evidence() -> TestResult<()> {
    let set = resources(&subjects())?;
    let sufficient = minimum(|work| {
        Ok(!graph(
            &set,
            NativeProcessingLimits {
                max_processing_units: work,
                ..NativeProcessingLimits::default()
            },
        )?
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::LimitExceeded))
    })?;
    let bounded = graph(
        &set,
        NativeProcessingLimits {
            max_processing_units: sufficient - 1,
            ..NativeProcessingLimits::default()
        },
    )?;
    // The last charged operation happens after positive relationships have been collected.
    assert!(!bounded.edges.is_empty());
    terminal(&bounded.findings);
    assert!(
        bounded
            .edges
            .iter()
            .all(|edge| edge.evidence.is_empty() && matches!(edge.resolution, Resolution::Unsupported(_)))
    );
    Ok(())
}
#[test]
fn networking_graph_caller_cannot_raise_retained_source_ceiling() -> TestResult<()> {
    let fixture = subjects();
    let ordinary = resources(&fixture)?;
    let sufficient = minimum(|work| {
        Ok(!graph(
            &ordinary,
            NativeProcessingLimits {
                max_processing_units: work,
                ..NativeProcessingLimits::default()
            },
        )?
        .findings
        .iter()
        .any(|finding| finding.code == FindingCode::LimitExceeded))
    })?;
    let bytes = serde_json::to_vec(&fixture)?;
    let retained = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits {
            processing: NativeProcessingLimits {
                max_processing_units: sufficient - 1,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        },
    )
    .required()?
    .flatten_resources()
    .required()?;
    let bounded = graph(
        &retained,
        NativeProcessingLimits {
            max_processing_units: usize::MAX,
            ..NativeProcessingLimits::default()
        },
    )?;
    terminal(&bounded.findings);
    assert!(
        bounded
            .edges
            .iter()
            .all(|edge| edge.evidence.is_empty() && matches!(edge.resolution, Resolution::Unsupported(_)))
    );
    Ok(())
}
#[test]
fn topology_preservation_and_authored_stripping_share_output_budget() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["deprecatedTopology"] = json!({"example.org/zone":"private-retained-value"});
    let set = resources(&value)?;
    for intent in [
        kubernetes_lens::generation::OutputIntent::PreserveObservation,
        kubernetes_lens::generation::OutputIntent::AuthoredIntent,
    ] {
        let make_options = |work| GenerationOptions {
            intent,
            processing: Some(NativeProcessingLimits {
                max_processing_units: work,
                ..NativeProcessingLimits::default()
            }),
            ..options()
        };
        let sufficient =
            minimum(|work| Ok(generate(&set, &target(37)?, OutputFormat::Json, &make_options(work)).is_ok()))?;
        let findings = generate(&set, &target(37)?, OutputFormat::Json, &make_options(sufficient - 1))
            .err()
            .required()?;
        terminal(&findings);
        let artifact = generate(&set, &target(37)?, OutputFormat::Json, &make_options(sufficient)).required()?;
        let output: Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert_eq!(
            output["endpoints"][0].get("deprecatedTopology").is_some(),
            intent != kubernetes_lens::generation::OutputIntent::AuthoredIntent
        );
    }
    Ok(())
}
#[test]
fn stripped_topology_cannot_turn_report_exhaustion_into_success() -> TestResult<()> {
    let mut value = slice("discovery.k8s.io/v1");
    value["endpoints"][0]["deprecatedTopology"] = json!({"example.org/zone":"private-value"});
    let set = resources(&value)?;
    for ceiling in [
        NativeProcessingLimits {
            max_report_entries: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_report_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    ] {
        let findings = generate(
            &set,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions {
                intent: kubernetes_lens::generation::OutputIntent::AuthoredIntent,
                processing: Some(ceiling),
                ..options()
            },
        )
        .err()
        .required()?;
        terminal(&findings);
    }
    Ok(())
}

#[test]
fn networking_graph_and_generation_cannot_raise_retained_edit_ceiling() -> TestResult<()> {
    let mut set = resources(&subjects())?;
    let patch = parse_source(
        SourceInput {
            id: SourceId(19),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: b"null",
        },
        &ParseLimits {
            processing: NativeProcessingLimits {
                max_processing_units: 5,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        },
    )
    .required()?;
    set.documents_mut()[0].set_field_from_source(FieldPath::parse("/spec/selector")?, patch)?;
    let raised = NativeProcessingLimits {
        max_processing_units: usize::MAX,
        ..NativeProcessingLimits::default()
    };
    let bounded = graph(&set, raised)?;
    terminal(&bounded.findings);
    assert!(
        bounded
            .edges
            .iter()
            .all(|edge| edge.evidence.is_empty() && matches!(edge.resolution, Resolution::Unsupported(_)))
    );
    let findings = generate(
        &set,
        &target(37)?,
        OutputFormat::Yaml,
        &GenerationOptions {
            processing: Some(raised),
            ..options()
        },
    )
    .err()
    .required()?;
    terminal(&findings);
    Ok(())
}
