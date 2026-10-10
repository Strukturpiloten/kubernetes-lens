use super::*;
use crate::{
    capability::{KubernetesVersion, TargetProfile},
    processing::{NativeOperationBudget, NativeProcessingLimits, ProcessingReport},
    registry::FieldDecodeContext,
    resources::configuration_storage::roots::{TopologySelectorLabelRequirement, TopologySelectorTerm},
    source::ParseLimits,
    value::Presence,
};
use std::error::Error;

type TestResult = Result<(), Box<dyn Error>>;
fn context(target: &TargetProfile, limits: NativeProcessingLimits) -> ValidationContext<'_> {
    ValidationContext {
        intent: NativeValidationIntent::Create,
        target,
        fields: FieldDecodeContext::new(
            ParseLimits::default(),
            NativeOperationBudget::new(limits),
            Phase::Validation,
        ),
    }
}
fn target() -> Result<TargetProfile, Finding> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, 37)?))
}
fn assert_limit(result: Result<(), Finding>) {
    assert!(result.is_err_and(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none()));
}
#[test]
fn private_json_preflight_exhaustion_is_sticky_and_never_a_shape_error() -> TestResult {
    let target = target()?;
    let bytes = b"{\"private-budget-fixture\":[]}";
    for limits in [
        NativeProcessingLimits {
            max_processing_units: bytes.len() * 8 - 1,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_payload_bytes: bytes.len() * 128 - 1,
            ..NativeProcessingLimits::default()
        },
    ] {
        let ctx = context(&target, limits);
        let mut findings = Vec::new();
        let mut check = Check {
            ctx: &ctx,
            out: &mut findings,
        };
        assert_limit(validate_private_map(Some(bytes), ".dockerconfigjson", &mut check));
        assert_limit(validate_private_map(Some(b"{}"), ".dockerconfigjson", &mut check));
        assert!(findings.is_empty());
        assert!(!format!("{findings:?}").contains("private-budget-fixture"));
    }
    Ok(())
}
#[test]
fn private_json_calls_share_the_same_scratch_budget() -> TestResult {
    let target = target()?;
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_payload_bytes: 256,
            ..NativeProcessingLimits::default()
        },
    );
    let mut findings = Vec::new();
    let mut check = Check {
        ctx: &ctx,
        out: &mut findings,
    };
    assert!(validate_private_map(Some(b"{}"), ".dockercfg", &mut check).is_ok());
    assert_eq!(ctx.fields.processing.charged_payload_bytes(), 256);
    assert_limit(validate_private_map(Some(b"null"), ".dockercfg", &mut check));
    assert!(findings.is_empty());
    Ok(())
}
#[test]
fn configmap_size_scan_stops_before_a_native_size_finding() -> TestResult {
    let target = target()?;
    let root = ConfigMap {
        data: Presence::Value(BTreeMap::from([(
            "k".into(),
            crate::value::Protected::new("x".repeat(1_048_577)),
        )])),
        ..ConfigMap::default()
    };
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_processing_units: 100,
            ..NativeProcessingLimits::default()
        },
    );
    let mut findings = Vec::new();
    assert_limit(root.check(&ctx, &mut findings));
    assert!(findings.is_empty());
    assert_eq!(ctx.fields.processing.charged_payload_bytes(), 0);
    Ok(())
}
#[test]
fn topology_scratch_and_comparison_charges_stop_before_invalidity() -> TestResult {
    let target = target()?;
    let term = TopologySelectorTerm {
        match_label_expressions: Presence::Value(vec![TopologySelectorLabelRequirement {
            key: Presence::Value("zone".into()),
            values: Presence::Value(vec!["x".into()]),
            ..TopologySelectorLabelRequirement::default()
        }]),
        ..TopologySelectorTerm::default()
    };
    let class = StorageClass {
        allowed_topologies: Presence::Value(vec![term.clone(), term]),
        ..StorageClass::default()
    };
    for limits in [
        NativeProcessingLimits {
            max_payload_bytes: 20 + size_of::<[usize; 8]>() - 1,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_processing_units: 8,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            // The first signature fits; comparison of the second signature does not.
            max_processing_units: 700,
            ..NativeProcessingLimits::default()
        },
    ] {
        let ctx = context(&target, limits);
        let mut findings = Vec::new();
        assert_limit(topologies(
            &class,
            &mut Check {
                ctx: &ctx,
                out: &mut findings,
            },
        ));
        assert!(findings.is_empty());
    }
    Ok(())
}
#[derive(Default)]
struct StopAfterFinding(Vec<Finding>);
impl FindingSink for StopAfterFinding {
    fn push(&mut self, finding: Finding) {
        self.0.push(finding);
    }
    fn exhausted(&self) -> bool {
        !self.0.is_empty()
    }
}
#[test]
fn sink_refusal_stops_before_the_remaining_body_scan() -> TestResult {
    let target = target()?;
    let root = ConfigMap {
        data: Presence::Value(BTreeMap::from([(
            "bad key".into(),
            crate::value::Protected::new("x".repeat(1024)),
        )])),
        ..ConfigMap::default()
    };
    let ctx = context(&target, NativeProcessingLimits::default());
    let mut sink = StopAfterFinding::default();
    assert_limit(root.check(&ctx, &mut sink));
    assert_eq!(sink.0.len(), 1);
    assert_eq!(sink.0[0].code, FindingCode::NativeFieldInvalid);
    assert!(ctx.fields.processing.exhausted());
    Ok(())
}
#[test]
fn lookup_charges_grow_with_member_count() -> TestResult {
    let target = target()?;
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_processing_units: 64,
            ..NativeProcessingLimits::default()
        },
    );
    let mut findings = Vec::new();
    let check = Check {
        ctx: &ctx,
        out: &mut findings,
    };
    assert!(check.lookup("k", 0).is_ok());
    assert_limit(check.lookup("k", 512));
    assert!(findings.is_empty());
    Ok(())
}

#[test]
fn static_report_exhaustion_retains_only_the_pathless_terminal() -> TestResult {
    let target = target()?;
    let root = ConfigMap {
        data: Presence::Value(BTreeMap::from([(
            "bad key".into(),
            crate::value::Protected::new("x".repeat(1024)),
        )])),
        ..ConfigMap::default()
    };
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_report_entries: 0,
            ..NativeProcessingLimits::default()
        },
    );
    let mut report = ProcessingReport::new(ctx.fields.processing.clone(), Phase::Validation);
    assert_limit(root.check(&ctx, &mut report));
    let findings = report.into_vec();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::LimitExceeded);
    assert!(findings[0].path.is_none());
    Ok(())
}
