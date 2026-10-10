//! Independent JSON-domain semantics and privacy; no schema/server conformance claim.
use kubernetes_lens::{
    Finding, FindingCode,
    processing::NativeProcessingLimits,
    source::{ExplicitSourceAccess, ParseLimits},
    value::{ExactJsonNumber, ProtectedJsonBuilder, ProtectedJsonValue},
};
type TestResult<T = ()> = Result<T, String>;
fn require<T>(result: Result<T, Finding>) -> TestResult<T> {
    result.map_err(|_| "unexpected protected operation failure".into())
}
fn parsed(text: &str) -> TestResult<ProtectedJsonValue> {
    ProtectedJsonValue::parse_json(text.as_bytes(), &ParseLimits::default())
        .map_err(|_| "unexpected JSON parse failure".into())
}
fn failed<T>(result: Result<T, Finding>) -> TestResult<Finding> {
    result.err().ok_or_else(|| "operation unexpectedly succeeded".into())
}
#[test]
fn json_objects_are_unordered_arrays_ordered_and_numbers_exact() -> TestResult {
    let left = parsed(r#"{"second":[null,true,"payload",9007199254740993],"first":{"zero":-0.0,"one":1.00}}"#)?;
    let right = parsed(r#"{"first":{"one":10e-1,"zero":0},"second":[null,true,"payload",9007199254740993]}"#)?;
    assert_eq!(left, right);
    assert!(require(left.equivalent(&right, &ParseLimits::default()))?);
    for different in [
        r#"{"second":[true,null,"payload",9007199254740993],"first":{"zero":0,"one":1}}"#,
        r#"{"second":[null,true,"payload",9007199254740992],"first":{"zero":0,"one":1}}"#,
    ] {
        let different = parsed(different)?;
        assert_ne!(left, different);
        assert!(!require(left.equivalent(&different, &ParseLimits::default()))?);
    }
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let bytes = require(left.to_json(&access, &ParseLimits::default()))?;
    let reparsed = ProtectedJsonValue::parse_json(&bytes, &ParseLimits::default()).map_err(|_| "roundtrip failed")?;
    assert!(require(left.equivalent(&reparsed, &ParseLimits::default()))?);
    Ok(())
}
#[test]
fn authoring_needs_no_source_seed_and_supports_genuine_null_members() -> TestResult {
    let limits = ParseLimits::default();
    let mut builder = require(ProtectedJsonBuilder::new(&limits))?;
    let null = require(builder.null())?;
    let boolean = require(builder.boolean(false))?;
    let number = require(builder.number(require(ExactJsonNumber::parse("1e-2147483648", &limits))?))?;
    let string = require(builder.string("own-value".into()))?;
    let list = require(builder.array(vec![null, boolean, number, string]))?;
    let root = require(builder.object(vec![("owned-key".into(), list)]))?;
    let value = require(builder.finish(&root))?;
    let expected = parsed(r#"{"owned-key":[null,false,1e-2147483648,"own-value"]}"#)?;
    assert_eq!(value, expected);
    assert_eq!(
        require(value.to_json(&ExplicitSourceAccess::explicitly_allow_raw_source(), &limits))?,
        br#"{"owned-key":[null,false,1e-2147483648,"own-value"]}"#
    );
    Ok(())
}
#[test]
fn foreign_handles_and_duplicate_keys_cannot_construct_a_value() -> TestResult {
    let limits = ParseLimits::default();
    let mut first = require(ProtectedJsonBuilder::new(&limits))?;
    let foreign = require(first.null())?;
    let mut second = require(ProtectedJsonBuilder::new(&limits))?;
    let local = require(second.null())?;
    assert_eq!(
        failed(second.array(vec![foreign]))?.code,
        FindingCode::NativeFieldInvalid
    );
    let marker = "PRIVATE-key-do-not-disclose";
    let finding = failed(second.object(vec![(marker.into(), local.clone()), (marker.into(), local)]))?;
    assert_eq!(finding.code, FindingCode::NativeFieldInvalid);
    assert!(finding.path.is_none());
    assert!(!format!("{finding:?}").contains(marker));
    assert!(!format!("{second:?}").contains(marker));
    Ok(())
}
#[test]
fn expanded_dag_nodes_payload_and_depth_have_exact_boundaries() -> TestResult {
    for (nodes, bytes, accepted) in [(7, 4, true), (6, 4, false), (7, 3, false)] {
        let limits = ParseLimits {
            max_nodes: nodes,
            max_input_bytes: bytes,
            ..ParseLimits::default()
        };
        let mut builder = require(ProtectedJsonBuilder::new(&limits))?;
        let leaf = require(builder.string("x".into()))?;
        let child = require(builder.array(vec![leaf.clone(), leaf]))?;
        let result = builder.array(vec![child.clone(), child]);
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            let root = require(result)?;
            require(builder.finish(&root))?;
        } else {
            assert_eq!(failed(result)?.code, FindingCode::LimitExceeded);
            assert_eq!(failed(builder.null())?.code, FindingCode::LimitExceeded);
        }
    }
    for (depth, accepted) in [(1, false), (2, true)] {
        let limits = ParseLimits {
            max_depth: depth,
            ..ParseLimits::default()
        };
        let mut builder = require(ProtectedJsonBuilder::new(&limits))?;
        let leaf = require(builder.null())?;
        let child = require(builder.array(vec![leaf]))?;
        assert_eq!(builder.array(vec![child]).is_ok(), accepted);
    }
    Ok(())
}
#[test]
fn closed_arena_prevents_recursive_drop_and_enforces_hard_depth() -> TestResult {
    let limits = ParseLimits {
        max_depth: 128,
        ..ParseLimits::default()
    };
    let mut builder = require(ProtectedJsonBuilder::new(&limits))?;
    let mut root = require(builder.null())?;
    for _ in 0..128 {
        root = require(builder.array(vec![root]))?;
    }
    let value = require(builder.finish(&root))?;
    drop(value.clone());
    drop(value);
    let invalid = ParseLimits {
        max_depth: 129,
        ..ParseLimits::default()
    };
    assert_eq!(
        failed(ProtectedJsonBuilder::new(&invalid))?.code,
        FindingCode::LimitExceeded
    );
    Ok(())
}
#[test]
fn semantic_comparison_uses_one_cumulative_budget() -> TestResult {
    let left = parsed("[true]")?;
    let right = parsed("[true]")?;
    for (units, accepted) in [(2, false), (3, true)] {
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_processing_units: units,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        let result = left.equivalent(&right, &limits);
        assert_eq!(result.is_ok(), accepted);
        if accepted {
            assert!(require(result)?);
        } else {
            assert_eq!(failed(result)?.code, FindingCode::LimitExceeded);
        }
    }
    let limits = ParseLimits {
        processing: NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    };
    assert_eq!(
        failed(ProtectedJsonBuilder::new(&limits))?.code,
        FindingCode::LimitExceeded
    );
    Ok(())
}
#[test]
fn all_default_failures_and_debug_hide_keys_values_and_number_spelling() -> TestResult {
    const MARKER: &str = "DO-NOT-DISCLOSE-key-or-value";
    for text in [
        format!("{{\"{MARKER}\":null,\"{MARKER}\":true}}"),
        format!("{{\"{MARKER}\":1e2147483648}}"),
        format!("{{\"{MARKER}\":\"unterminated"),
    ] {
        let findings = ProtectedJsonValue::parse_json(text.as_bytes(), &ParseLimits::default())
            .err()
            .ok_or("invalid protected JSON succeeded")?;
        assert!(!format!("{findings:?}").contains(MARKER));
        assert!(findings.iter().all(|finding| finding.path.is_none()));
    }
    let value = parsed(&format!("{{\"{MARKER}\":\"{MARKER}\"}}"))?;
    assert!(!format!("{value:?}").contains(MARKER));
    let limits = ParseLimits {
        max_input_bytes: 8,
        ..ParseLimits::default()
    };
    let finding = failed(value.to_json(&ExplicitSourceAccess::explicitly_allow_raw_source(), &limits))?;
    assert_eq!(finding.code, FindingCode::LimitExceeded);
    assert!(finding.path.is_none());
    assert!(!format!("{finding:?}").contains(MARKER));
    Ok(())
}

#[test]
fn parsed_values_retain_lower_processing_ceilings_when_callers_request_defaults() -> TestResult {
    let limits = ParseLimits {
        processing: NativeProcessingLimits {
            max_processing_units: 512,
            ..NativeProcessingLimits::default()
        },
        ..ParseLimits::default()
    };
    let lower = ProtectedJsonValue::parse_json(b"0", &limits).map_err(|_| "bounded input failed")?;
    let ordinary = parsed("0")?;
    for (left, right) in [(&lower, &ordinary), (&ordinary, &lower)] {
        assert_eq!(
            failed(left.equivalent(right, &ParseLimits::default()))?.code,
            FindingCode::LimitExceeded
        );
    }
    Ok(())
}

#[test]
fn native_source_unknown_number_magnitudes_survive_generation_and_reparse() -> TestResult {
    use kubernetes_lens::{
        capability::{KubernetesVersion, TargetProfile},
        generation::{
            ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
        },
        source::{DocumentFormat, InputOrigin, SourceId, SourceInput},
    };
    let target = TargetProfile::documented_defaults(require(KubernetesVersion::new(1, 37))?);
    let options = GenerationOptions {
        json_shape: JsonShape::SingleResource,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    };
    let resources = |bytes: &[u8]| {
        kubernetes_lens::parse_source(
            SourceInput {
                id: SourceId(924),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes,
            },
            &ParseLimits::default(),
        )
        .and_then(kubernetes_lens::ParsedInput::flatten_resources)
        .map_err(|_| "source-backed resource input failed")
    };
    for spelling in ["1e400", "1e2147483648", "-9007199254740993"] {
        let text = format!(
            r#"{{"apiVersion":"v1","kind":"Pod","metadata":{{"name":"example"}},"spec":{{"containers":[{{"name":"app","image":"example:v1"}}]}},"unknownMagnitude":{spelling}}}"#
        );
        let original = resources(text.as_bytes())?;
        assert_eq!(
            original.sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
            text.as_bytes()
        );
        let artifact = kubernetes_lens::generate(&original, &target, OutputFormat::Json, &options)
            .map_err(|_| "native resource generation failed")?;
        let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
        let output = artifact.reveal_bytes(&access);
        assert!(
            std::str::from_utf8(output)
                .map_err(|_| "invalid UTF-8 output")?
                .contains(spelling)
        );
        let reparsed = resources(output)?;
        let second = kubernetes_lens::generate(&reparsed, &target, OutputFormat::Json, &options)
            .map_err(|_| "native fixed-point generation failed")?;
        assert_eq!(output, second.reveal_bytes(&access));
    }
    Ok(())
}
