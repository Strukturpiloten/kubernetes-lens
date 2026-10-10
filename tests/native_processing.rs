//! Independent public processing regressions; no API-server or runtime conformance claim.
use kubernetes_lens::{
    FieldPath, FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    generation::{GenerationOptions, OpaqueFieldPolicy, OutputFormat, ProtectedOutput},
    graph::{ReferenceContext, resolve_references_with_context},
    model::ResourceSet,
    processing::NativeProcessingLimits,
    resources::workloads::Pod,
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::{NativeBytes, NativeQuantityDomain, Quantity},
};
use std::{cmp::Ordering, fmt::Write as _};
type TestResult<T = ()> = Result<T, String>;
fn require<T, E>(result: Result<T, E>) -> TestResult<T> {
    result.map_err(|_| "unexpected operation failure".into())
}
fn target() -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(require(KubernetesVersion::new(
        1, 30,
    ))?))
}
fn parsed(text: &str, limits: &ParseLimits) -> Result<kubernetes_lens::ParsedInput, Vec<kubernetes_lens::Finding>> {
    kubernetes_lens::parse_source(
        SourceInput {
            id: SourceId(7),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        limits,
    )
}
fn pod_text(name: &str) -> String {
    format!(
        "apiVersion: v1\nkind: Pod\nmetadata: {{name: {name}}}\nspec:\n  containers:\n  - name: main\n    image: example.invalid/app:v1\n    resources:\n      requests: {{memory: 1Gi}}\n"
    )
}
fn set(text: &str, limits: &ParseLimits) -> Result<ResourceSet, Vec<kubernetes_lens::Finding>> {
    parsed(text, limits)?.flatten_resources()
}
fn work_limits(units: usize) -> ParseLimits {
    ParseLimits {
        processing: NativeProcessingLimits {
            max_processing_units: units,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    }
}
fn minimum(mut succeeds: impl FnMut(usize) -> bool) -> TestResult<usize> {
    let mut low = 0;
    let mut high = 100_000;
    if !succeeds(high) {
        return Err("upper test bound did not succeed".into());
    }
    while low < high {
        let middle = low + (high - low) / 2;
        if succeeds(middle) {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    Ok(low)
}
fn terminal(findings: &[kubernetes_lens::Finding]) {
    let limits = findings
        .iter()
        .filter(|finding| finding.code == FindingCode::LimitExceeded)
        .collect::<Vec<_>>();
    assert_eq!(limits.len(), 1);
    assert!(limits[0].path.is_none());
}
#[test]
fn binary_native_padding_whitespace_tail_bits_and_privacy() -> TestResult {
    let limits = ParseLimits::default();
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    for (text, bytes) in [
        ("", &b""[..]),
        ("AAEC/w==", &b"\0\x01\x02\xff"[..]),
        ("Zg==", &b"f"[..]),
        ("Zh==", &b"f"[..]),
        ("Zm8=", &b"fo"[..]),
        ("Zm9=", &b"fo"[..]),
        ("Z\r\ng==\n", &b"f"[..]),
    ] {
        let native = require(NativeBytes::parse_base64(text, &limits))?;
        assert_eq!(native.bytes(&access), bytes);
        assert_eq!(format!("{native:?}"), "NativeBytes(<private>)");
    }
    for invalid in ["Zg", "Zg=", "Zg===", "Z=g=", "Zg== ", "Zg==\t", "-w==", "_w=="] {
        assert!(NativeBytes::parse_base64(invalid, &limits).is_err());
    }
    let tight = ParseLimits {
        processing: NativeProcessingLimits {
            max_payload_bytes: 13,
            ..NativeProcessingLimits::default()
        },
        ..limits
    };
    assert_eq!(
        NativeBytes::parse_base64("AAEC\r\n/w==", &tight)
            .err()
            .ok_or("missing binary limit")?
            .code,
        FindingCode::LimitExceeded
    );
    let exact = ParseLimits {
        processing: NativeProcessingLimits {
            max_payload_bytes: 14,
            ..tight.processing
        },
        ..tight
    };
    assert_eq!(
        require(NativeBytes::parse_base64("AAEC\r\n/w==", &exact))?.bytes(&access),
        b"\0\x01\x02\xff"
    );
    assert!(
        NativeBytes::try_from_bytes(
            vec![0; 4],
            &ParseLimits {
                max_scalar_bytes: 7,
                ..limits
            }
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn quantities_compare_exactly_and_separate_native_uncertainty() -> TestResult {
    for (left, right, expected) in [
        ("1Gi", "1024Mi", Ordering::Equal),
        ("1Gi", "1G", Ordering::Greater),
        ("1m", ".001", Ordering::Equal),
        ("-2", "-1", Ordering::Less),
        ("1.2", "1.19", Ordering::Greater),
        ("-1.2", "-1.19", Ordering::Less),
        ("-1e-2147483647", "-2e-2147483647", Ordering::Greater),
        ("-0", "+0", Ordering::Equal),
        ("1e2147483647", "1e2147483646", Ordering::Greater),
        ("1e-2147483647", "2e-2147483647", Ordering::Less),
    ] {
        let left = require(Quantity::parse(left))?;
        let right = require(Quantity::parse(right))?;
        let result = require(left.compare_supplied(&right, &NativeProcessingLimits::default()))?;
        assert_eq!(result.ordering, expected);
        assert!(
            left.compare_supplied(
                &right,
                &NativeProcessingLimits {
                    max_processing_units: 532,
                    ..NativeProcessingLimits::default()
                }
            )
            .is_err()
        );
        assert_eq!(
            require(left.compare_supplied(
                &right,
                &NativeProcessingLimits {
                    max_processing_units: 533,
                    ..NativeProcessingLimits::default()
                }
            ))?
            .ordering,
            expected
        );
    }
    for (text, domain) in [
        ("9223372036854775807", NativeQuantityDomain::ConservativeIntegralBytes),
        (
            "9223372036854775807000m",
            NativeQuantityDomain::ConservativeIntegralBytes,
        ),
        ("0", NativeQuantityDomain::ConservativeIntegralBytes),
        ("1Ki", NativeQuantityDomain::ConservativeIntegralBytes),
        ("9223372036854775808", NativeQuantityDomain::NativeSemanticsUnverified),
        ("1m", NativeQuantityDomain::NativeSemanticsUnverified),
        ("-1", NativeQuantityDomain::NativeSemanticsUnverified),
    ] {
        let quantity = require(Quantity::parse(text))?;
        assert_eq!(
            require(quantity.compare_supplied(&quantity, &NativeProcessingLimits::default()))?.native_domain,
            domain
        );
    }
    Ok(())
}
#[test]
fn native_pod_decode_authoring_and_reprojection_are_cumulative() -> TestResult {
    let one = pod_text("a");
    let two = format!("{one}---\n{}", pod_text("b"));
    let decode_minimum = minimum(|units| set(&one, &work_limits(units)).is_ok())?;
    require(set(&one, &work_limits(decode_minimum)))?;
    // Reusing a SourceId in a separate operation does not share its counter identity.
    require(set(&one, &work_limits(decode_minimum)))?;
    terminal(
        &set(&two, &work_limits(decode_minimum))
            .err()
            .ok_or("missing aggregate decode limit")?,
    );
    let first = require(set(&one, &ParseLimits::default()))?;
    let second = require(set(&pod_text("b"), &ParseLimits::default()))?;
    let a = first.documents()[0]
        .resource::<Pod>()
        .ok_or("missing native Pod")?
        .clone();
    let b = second.documents()[0]
        .resource::<Pod>()
        .ok_or("missing native Pod")?
        .clone();
    let target = target()?;
    let author_minimum = minimum(|units| {
        ResourceSet::from_authored(
            vec![a.clone().into()],
            &target,
            &AuthoringLimits {
                parser: work_limits(units),
                ..AuthoringLimits::default()
            },
        )
        .is_ok()
    })?;
    require(ResourceSet::from_authored(
        vec![a.clone().into()],
        &target,
        &AuthoringLimits {
            parser: work_limits(author_minimum),
            ..AuthoringLimits::default()
        },
    ))?;
    terminal(
        &ResourceSet::from_authored(
            vec![a.into(), b.into()],
            &target,
            &AuthoringLimits {
                parser: work_limits(author_minimum),
                ..AuthoringLimits::default()
            },
        )
        .err()
        .ok_or("missing aggregate authoring limit")?,
    );
    let aggregate = require(set(&two, &ParseLimits::default()))?;
    let options = |units| GenerationOptions {
        processing: Some(work_limits(units).processing),
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    };
    let generation_minimum =
        minimum(|units| kubernetes_lens::generate(&first, &target, OutputFormat::Yaml, &options(units)).is_ok())?;
    terminal(
        &kubernetes_lens::generate(&aggregate, &target, OutputFormat::Yaml, &options(generation_minimum))
            .err()
            .ok_or("missing aggregate projection limit")?,
    );
    Ok(())
}
#[test]
fn retained_patch_and_graph_ceilings_cannot_be_raised() -> TestResult {
    let mut resources = require(set(&pod_text("a"), &ParseLimits::default()))?;
    let patch = require(parsed("null", &work_limits(5)))?;
    require(
        resources.documents_mut()[0].set_field_from_source(require(FieldPath::parse("/spec/nodeSelector"))?, patch),
    )?;
    let target = target()?;
    let options = GenerationOptions {
        processing: Some(NativeProcessingLimits {
            max_processing_units: usize::MAX,
            ..NativeProcessingLimits::default()
        }),
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    };
    terminal(
        &kubernetes_lens::generate(&resources, &target, OutputFormat::Json, &options)
            .err()
            .ok_or("patch ceiling was reset")?,
    );
    let graph = resolve_references_with_context(
        &resources,
        &ReferenceContext {
            processing: Some(work_limits(0).processing),
            ..ReferenceContext::default()
        },
    );
    assert!(graph.edges.is_empty());
    terminal(&graph.findings);
    let zero = work_limits(0);
    terminal(&parsed("null", &zero).err().ok_or("zero budget succeeded")?);
    Ok(())
}

#[test]
fn immutable_binary_spelling_and_default_protected_output_remain_separate() -> TestResult {
    let text = "apiVersion: v1\nkind: Secret\nmetadata: {name: example}\ndata: {key: 'Zh=='}\n";
    let resources = require(set(text, &ParseLimits::default()))?;
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    let options = GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    };
    let findings = kubernetes_lens::generate(&resources, &target()?, OutputFormat::Yaml, &options)
        .err()
        .ok_or("private output unexpectedly allowed")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    assert!(!format!("{resources:?}{findings:?}").contains("Zh=="));
    Ok(())
}

fn list_input(text: &str, id: u64, limits: &ParseLimits) -> TestResult<kubernetes_lens::ParsedInput> {
    require(kubernetes_lens::parse_source(
        SourceInput {
            id: SourceId(id),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        limits,
    ))
}
#[test]
fn independently_parsed_empty_lists_share_constructor_and_identity_allowances() -> TestResult {
    let text = "apiVersion: v1\nkind: List\nitems: []\n";
    let limits = work_limits(text.len() + 1);
    require(ResourceSet::from_inputs(vec![list_input(text, 1, &limits)?]))?;
    let inputs = (0..16)
        .map(|id| list_input(text, id, &limits))
        .collect::<TestResult<Vec<_>>>()?;
    terminal(
        &ResourceSet::from_inputs(inputs)
            .err()
            .ok_or("aggregate empty-List work was reset")?,
    );
    let inputs = vec![
        list_input(text, 1, &ParseLimits::default())?,
        list_input(text, 2, &ParseLimits::default())?,
    ];
    let resources = require(ResourceSet::from_inputs(inputs))?;
    let findings = kubernetes_lens::validate_for_target_with_limits(
        &resources,
        &target()?,
        kubernetes_lens::NativeValidationIntent::Unspecified,
        &work_limits(1).processing,
    );
    terminal(&findings);
    Ok(())
}
#[test]
fn opaque_list_wrapper_item_and_id_copies_are_cumulative() -> TestResult {
    let body = "x".repeat(4096);
    let text = |name| {
        format!(
            "apiVersion: v1\nkind: List\nitems:\n- apiVersion: example.invalid/v1\n  kind: Thing\n  metadata: {{name: {name}}}\n  spec: {{payload: {body}}}\n"
        )
    };
    let first = text("a");
    let payload_limits = |bytes| ParseLimits {
        processing: NativeProcessingLimits {
            max_payload_bytes: bytes,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    };
    let boundary = minimum(|bytes| {
        list_input(&first, 1, &payload_limits(bytes)).is_ok_and(|input| ResourceSet::from_inputs(vec![input]).is_ok())
    })?;
    let limits = payload_limits(boundary);
    let resources = require(ResourceSet::from_inputs(vec![list_input(&first, 1, &limits)?]))?;
    assert_eq!(resources.sources()[0].limits().processing.max_payload_bytes, boundary);
    let inputs = vec![list_input(&first, 1, &limits)?, list_input(&text("b"), 2, &limits)?];
    let findings = ResourceSet::from_inputs(inputs)
        .err()
        .ok_or("aggregate opaque-List copy allowance was reset")?;
    terminal(&findings);
    assert!(findings.iter().any(|finding| finding.code == FindingCode::UnknownKind));
    Ok(())
}

#[test]
fn opaque_projection_copy_respects_lower_payload_in_validation_and_generation() -> TestResult {
    let body = "x".repeat(8192);
    let text = format!("apiVersion: v1\nkind: Secret\nmetadata: {{name: opaque}}\nstringData: {{payload: {body}}}\n");
    let resources = require(set(&text, &ParseLimits::default()))?;
    let limits = NativeProcessingLimits {
        max_payload_bytes: 2048,
        ..NativeProcessingLimits::default()
    };
    let findings = kubernetes_lens::validate_for_target_with_limits(
        &resources,
        &target()?,
        kubernetes_lens::NativeValidationIntent::Unspecified,
        &limits,
    );
    terminal(&findings);
    for collections in [
        kubernetes_lens::generation::CollectionOutput::PreserveWrappers,
        kubernetes_lens::generation::CollectionOutput::Flatten,
    ] {
        let options = GenerationOptions {
            processing: Some(limits),
            protected_output: ProtectedOutput::Include,
            opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
            collections,
            ..GenerationOptions::default()
        };
        terminal(
            &kubernetes_lens::generate(&resources, &target()?, OutputFormat::Yaml, &options)
                .err()
                .ok_or("opaque projection copied beyond the lowered payload allowance")?,
        );
    }
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    assert!(!format!("{resources:?}{findings:?}").contains(&body));
    Ok(())
}

#[test]
fn list_wrapper_warning_sink_retains_first_before_report_exhaustion() -> TestResult {
    use std::fmt::Write as _;
    for metadata in [false, true] {
        let mut text = String::from("apiVersion: v1\nkind: List\nitems: []\n");
        if metadata {
            text.push_str("metadata:\n");
        }
        for index in 0..64 {
            require(writeln!(
                text,
                "{}unknown{index}: private-value",
                if metadata { "  " } else { "" }
            ))?;
        }
        let resources = require(set(&text, &ParseLimits::default()))?;
        let options = |entries| GenerationOptions {
            processing: Some(NativeProcessingLimits {
                max_report_entries: entries,
                ..NativeProcessingLimits::default()
            }),
            opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
            protected_output: ProtectedOutput::Include,
            ..GenerationOptions::default()
        };
        let expected = require(FieldPath::parse(if metadata {
            "/metadata/unknown0"
        } else {
            "/unknown0"
        }))?;
        let control = require(kubernetes_lens::generate(
            &resources,
            &target()?,
            OutputFormat::Yaml,
            &options(128),
        ))?;
        assert_eq!(control.findings().len(), 64);
        assert!(
            control
                .findings()
                .iter()
                .all(|finding| finding.code == FindingCode::UnadmittedField)
        );
        let bounded = kubernetes_lens::generate(&resources, &target()?, OutputFormat::Yaml, &options(1))
            .err()
            .ok_or("List warning report exhaustion returned success")?;
        terminal(&bounded);
        assert_eq!(bounded.len(), 2);
        assert_eq!(bounded[0].code, FindingCode::UnadmittedField);
        assert_eq!(bounded[0].path.as_ref(), Some(&expected));
        assert!(bounded[0].wrapper.is_some());
        assert!(bounded[0].source.is_some());
        assert!(!format!("{bounded:?}").contains("private-value"));
        assert_eq!(
            resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            text.as_bytes()
        );
        let work = kubernetes_lens::generate(
            &resources,
            &target()?,
            OutputFormat::Yaml,
            &GenerationOptions {
                processing: Some(work_limits(0).processing),
                ..options(128)
            },
        )
        .err()
        .ok_or("zero traversal budget returned success")?;
        terminal(&work);
    }
    Ok(())
}

#[test]
fn pod_sidecar_capability_sink_preserves_unavailable_evidence_and_stops() -> TestResult {
    use std::fmt::Write as _;
    let mut text = pod_text("sidecars");
    text.push_str("  initContainers:\n");
    for index in 0..32 {
        require(writeln!(
            text,
            "  - name: sidecar{index}\n    image: example.invalid/private:v1\n    restartPolicy: Always"
        ))?;
    }
    let resources = require(set(&text, &ParseLimits::default()))?;
    let target = TargetProfile::documented_defaults(require(KubernetesVersion::new(1, 20))?);
    let findings = |entries| {
        kubernetes_lens::validate_for_target_with_limits(
            &resources,
            &target,
            kubernetes_lens::NativeValidationIntent::Unspecified,
            &NativeProcessingLimits {
                max_report_entries: entries,
                ..NativeProcessingLimits::default()
            },
        )
    };
    let control = findings(1_000);
    assert!(!control.iter().any(|finding| finding.code == FindingCode::LimitExceeded));
    for index in 0..32 {
        let path = require(FieldPath::parse(&format!("/spec/initContainers/{index}/restartPolicy")))?;
        assert!(
            control
                .iter()
                .any(|finding| finding.code == FindingCode::UnavailableField && finding.path.as_ref() == Some(&path))
        );
    }
    let first = require(FieldPath::parse("/spec/initContainers/0/restartPolicy"))?;
    for entries in [0, 1] {
        let bounded = findings(entries);
        terminal(&bounded);
        assert_eq!(bounded.len(), entries + 1);
        if entries == 1 {
            assert_eq!(bounded[0].code, FindingCode::UnavailableField);
            assert_eq!(bounded[0].path.as_ref(), Some(&first));
            assert!(bounded[0].resource.is_some());
        }
        assert!(!format!("{bounded:?}").contains("example.invalid/private"));
        let graph = kubernetes_lens::graph::resolve_references_with_context_for_target(
            &resources,
            &ReferenceContext {
                processing: Some(NativeProcessingLimits {
                    max_report_entries: entries,
                    ..NativeProcessingLimits::default()
                }),
                ..ReferenceContext::default()
            },
            &target,
        );
        terminal(&graph.findings);
        assert!(graph.edges.is_empty());
    }
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    Ok(())
}

#[test]
fn typed_pod_opaque_root_respects_lower_validation_and_generation_ceiling() -> TestResult {
    let private = "private-opaque-root".repeat(2048);
    let text = format!("{}retainedOpaque: {private}\n", pod_text("opaque-merge"));
    let resources = require(set(&text, &ParseLimits::default()))?;
    assert!(resources.documents()[0].resource::<Pod>().is_some());
    let target = target()?;
    let ceiling = NativeProcessingLimits {
        max_payload_bytes: private.len() - 1,
        ..NativeProcessingLimits::default()
    };
    let findings = kubernetes_lens::validate_for_target_with_limits(
        &resources,
        &target,
        kubernetes_lens::NativeValidationIntent::Unspecified,
        &ceiling,
    );
    terminal(&findings);
    let options = GenerationOptions {
        processing: Some(ceiling),
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        json_shape: kubernetes_lens::generation::JsonShape::SingleResource,
        ..GenerationOptions::default()
    };
    let errors = kubernetes_lens::generate(&resources, &target, OutputFormat::Json, &options)
        .err()
        .ok_or("opaque Pod bypassed lower generation ceiling")?;
    terminal(&errors);
    assert!(!format!("{errors:?}").contains("private-opaque-root"));
    let control = require(kubernetes_lens::generate(
        &resources,
        &target,
        OutputFormat::Json,
        &GenerationOptions {
            processing: None,
            ..options
        },
    ))?;
    let bytes =
        control.reveal_bytes(&kubernetes_lens::generation::ExplicitArtifactAccess::explicitly_allow_raw_artifact());
    let tree: serde_json::Value = require(serde_json::from_slice(bytes))?;
    assert_eq!(tree["retainedOpaque"].as_str(), Some(private.as_str()));
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    Ok(())
}

#[test]
fn generic_list_metadata_validation_obeys_lower_work_budget() -> TestResult {
    let mut text = String::from("apiVersion: v1\nkind: List\nmetadata:\n");
    for index in 0..64 {
        writeln!(&mut text, "  private-metadata-{index}: benign").map_err(|_| "test input formatting failed")?;
    }
    text.push_str("items: []\n");
    let resources = require(set(&text, &ParseLimits::default()))?;
    let target = target()?;
    assert!(kubernetes_lens::validate_for_target(&resources, &target).is_empty());
    for units in [0, 1] {
        let findings = kubernetes_lens::validate_for_target_with_limits(
            &resources,
            &target,
            kubernetes_lens::NativeValidationIntent::Unspecified,
            &NativeProcessingLimits {
                max_processing_units: units,
                ..NativeProcessingLimits::default()
            },
        );
        terminal(&findings);
        assert_eq!(findings.len(), 1);
        assert!(!format!("{findings:?}").contains("private-metadata"));
    }
    let no_payload = kubernetes_lens::validate_for_target_with_limits(
        &resources,
        &target,
        kubernetes_lens::NativeValidationIntent::Unspecified,
        &NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    );
    terminal(&no_payload);
    assert_eq!(no_payload.len(), 1);
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes(),
    );
    Ok(())
}

#[test]
fn generic_list_invalid_metadata_stops_on_report_exhaustion() -> TestResult {
    let text = "apiVersion: v1\nkind: List\nmetadata:\n  resourceVersion: {hidden: private-list-value}\n  selfLink: false\n  continue: 42\n  remainingItemCount: -1\nitems: []\n";
    let resources = require(set(text, &ParseLimits::default()))?;
    let target = target()?;
    let control = kubernetes_lens::validate_for_target(&resources, &target);
    assert_eq!(
        control
            .iter()
            .filter(|f| f.code == FindingCode::NativeFieldInvalid)
            .count(),
        4
    );
    for entries in [0, 1] {
        let findings = kubernetes_lens::validate_for_target_with_limits(
            &resources,
            &target,
            kubernetes_lens::NativeValidationIntent::Unspecified,
            &NativeProcessingLimits {
                max_report_entries: entries,
                ..NativeProcessingLimits::default()
            },
        );
        terminal(&findings);
        assert_eq!(findings.len(), entries + 1);
        if entries == 1 {
            assert_eq!(findings[0].code, FindingCode::NativeFieldInvalid);
            assert_eq!(
                findings[0].path,
                Some(require(FieldPath::parse("/metadata/resourceVersion"))?)
            );
            assert!(findings[0].wrapper.is_some());
        }
        assert!(!format!("{findings:?}").contains("private-list-value"));
    }
    assert_eq!(
        resources.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes(),
    );
    Ok(())
}
