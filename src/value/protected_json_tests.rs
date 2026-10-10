//! Independent charged-payload invariants, not allocator/RSS measurements.
use super::*;
use crate::processing::NativeProcessingLimits;

type TestResult<T = ()> = Result<T, String>;
fn require<T>(result: Result<T, Finding>) -> TestResult<T> {
    result.map_err(|_| "unexpected protected operation failure".into())
}
fn limited_work(units: usize) -> NativeOperationBudget {
    NativeOperationBudget::new(NativeProcessingLimits {
        max_processing_units: units,
        ..NativeProcessingLimits::default()
    })
}
fn failure<T>(result: Result<T, Finding>) -> TestResult {
    let finding = result.err().ok_or("expected bounded failure")?;
    assert_eq!(finding.code, FindingCode::LimitExceeded);
    Ok(())
}
fn tree(children: usize, object: bool) -> TreeNode {
    if object {
        TreeNode::mapping(
            (0..children)
                .map(|index| (format!("private-{index}"), TreeNode::new(TreeValue::Null)))
                .collect(),
        )
    } else {
        TreeNode::new(TreeValue::Sequence(
            (0..children).map(|_| TreeNode::new(TreeValue::Null)).collect(),
        ))
    }
}

#[test]
fn unavailable_scheduling_work_cannot_retain_payload_proportional_to_unvisited_siblings() -> TestResult {
    for object in [false, true] {
        let mut decode_payloads = Vec::new();
        let mut encode_payloads = Vec::new();
        for children in [1, 1024] {
            let tree = tree(children, object);
            // Builder initialization and the root visit fit; no work remains
            // to schedule even the first child. Sibling count must not affect
            // subsequently retained payload under this same work ceiling.
            let budget = limited_work(2);
            let fields = FieldDecodeContext::new(ParseLimits::default(), budget.clone(), Phase::Decoding);
            failure(ProtectedJsonValue::decode(&tree, &fields, &FieldPath::default()))?;
            decode_payloads.push(budget.charged_payload_bytes());

            let fields = FieldDecodeContext::new(
                ParseLimits::default(),
                NativeOperationBudget::new(NativeProcessingLimits::default()),
                Phase::Decoding,
            );
            let value = require(ProtectedJsonValue::decode(&tree, &fields, &FieldPath::default()))?;
            let budget = limited_work(1);
            let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
            failure(value.encode(&ctx, &FieldPath::default()))?;
            encode_payloads.push(budget.charged_payload_bytes());
        }
        assert_eq!(decode_payloads[0], decode_payloads[1]);
        assert_eq!(encode_payloads[0], encode_payloads[1]);
    }
    Ok(())
}

#[test]
fn decode_and_encode_cannot_restart_prior_shared_work_or_payload_consumption() -> TestResult {
    let tree = TreeNode::new(TreeValue::Null);
    let fields = FieldDecodeContext::new(
        ParseLimits::default(),
        NativeOperationBudget::new(NativeProcessingLimits::default()),
        Phase::Decoding,
    );
    let value = require(ProtectedJsonValue::decode(&tree, &fields, &FieldPath::default()))?;
    for payload in [false, true] {
        for encode in [false, true] {
            let budget = limited_work(128);
            let phase = if encode { Phase::Generation } else { Phase::Decoding };
            if payload {
                require(budget.payload(budget.limits().max_payload_bytes, phase))?;
            } else {
                require(budget.work(127, phase))?;
            }
            assert!(!budget.exhausted());
            if encode {
                let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
                failure(value.encode(&ctx, &FieldPath::default()))?;
            } else {
                let fields = FieldDecodeContext::new(ParseLimits::default(), budget.clone(), phase);
                failure(ProtectedJsonValue::decode(&tree, &fields, &FieldPath::default()))?;
            }
            assert!(budget.exhausted());
            failure(budget.work(0, phase))?;
            failure(budget.payload(0, phase))?;
        }
    }
    Ok(())
}

#[test]
fn inherited_json_sizing_is_cumulative_and_keeps_limit_failure_sticky() -> TestResult {
    let value = ProtectedJsonValue::parse_json(b"1", &ParseLimits::default())
        .map_err(|_| "small protected number failed to parse")?;
    let budget = limited_work(3);
    let fields = FieldDecodeContext::new(ParseLimits::default(), budget.clone(), Phase::Analysis);
    assert_eq!(require(value.retained_json_len_in(&fields))?, 1);
    failure(value.retained_json_len_in(&fields))?;
    assert!(budget.exhausted());
    failure(budget.work(0, Phase::Analysis))?;
    failure(budget.payload(0, Phase::Analysis))?;
    Ok(())
}
