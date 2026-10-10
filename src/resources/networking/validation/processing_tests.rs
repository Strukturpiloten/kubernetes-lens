use super::*;
use crate::{
    capability::{KubernetesVersion, TargetProfile},
    generation::NativeValidationIntent,
    processing::{NativeOperationBudget, NativeProcessingLimits, ProcessingReport},
    registry::FieldDecodeContext,
    source::ParseLimits,
};
use serde_json::{Value, json};
type TestResult = Result<(), Finding>;
fn tree(value: Value) -> TreeNode {
    TreeNode::new(match value {
        Value::Null => TreeValue::Null,
        Value::Bool(v) => TreeValue::Bool(v),
        Value::Number(v) => TreeValue::Number(v.to_string()),
        Value::String(v) => TreeValue::String(v),
        Value::Array(v) => TreeValue::Sequence(v.into_iter().map(tree).collect()),
        Value::Object(v) => TreeValue::Mapping(v.into_iter().map(|(k, v)| (k, tree(v))).collect()),
    })
}
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
#[test]
fn direct_port_name_scratch_exhaustion_cannot_turn_into_a_duplicate_error() -> TestResult {
    let target = target()?;
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    );
    let ports = tree(json!([{"name":"same"},{"name":"same"}]));
    let mut findings = Vec::new();
    distinct_port_names(
        ports
            .as_sequence()
            .ok_or_else(|| Finding::error(FindingCode::MalformedDocument, Phase::Validation))?,
        false,
        &ctx,
        &FieldPath::default(),
        &mut findings,
    );
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::LimitExceeded);
    assert!(findings[0].path.is_none());
    Ok(())
}
#[test]
fn direct_cidr_preflight_limit_and_prior_failure_remain_pathless() -> TestResult {
    let target = target()?;
    let value = tree(json!({"cidr":"10.0.0.0/8","except":["10.1.0.0/16"]}));
    for limits in [
        NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits::default(),
    ] {
        let ctx = context(&target, limits);
        if limits.max_payload_bytes != 0 {
            ctx.fields.processing.fail(Phase::Validation);
        }
        let mut findings = Vec::new();
        ip_block(&value, &FieldPath::default(), &ctx, &mut findings);
        assert_eq!(findings.len(), 1);
        assert_eq!(findings[0].code, FindingCode::LimitExceeded);
        assert!(findings[0].path.is_none());
    }
    Ok(())
}
#[test]
fn direct_endpoint_report_refusal_stops_before_later_ports() -> TestResult {
    let target = target()?;
    let ctx = context(
        &target,
        NativeProcessingLimits {
            max_report_entries: 0,
            ..NativeProcessingLimits::default()
        },
    );
    let value = tree(json!({"subsets":[{"ports":[{"port":80},{"port":81}]}]}));
    let mut report = ProcessingReport::new(ctx.fields.processing.clone(), Phase::Validation);
    endpoints(&value, &ctx, &FieldPath::default(), &mut report);
    let findings = report.into_vec();
    assert_eq!(findings.len(), 1);
    assert_eq!(findings[0].code, FindingCode::LimitExceeded);
    assert!(findings[0].path.is_none());
    assert!(ctx.fields.processing.exhausted());
    Ok(())
}
