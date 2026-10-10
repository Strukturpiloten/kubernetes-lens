use super::{PersistentVolumeClaimSpec, UnknownScopeVisitor, UnknownScopes};
use crate::{
    diagnostic::{FieldPath, FindingCode, Phase},
    processing::{NativeOperationBudget, NativeProcessingLimits},
    registry::{FieldDecodeContext, codec::FieldCodec},
    source::ParseLimits,
    syntax::{TreeNode, TreeValue, UnknownFields},
};
use std::collections::BTreeSet;

fn fields(limits: NativeProcessingLimits) -> FieldDecodeContext {
    FieldDecodeContext::new(
        ParseLimits::default(),
        NativeOperationBudget::new(limits),
        Phase::Analysis,
    )
}

#[test]
fn capture_admits_work_before_unknown_sibling_copies() -> Result<(), String> {
    let mut charged = Vec::new();
    for count in [1, 1024] {
        let tree = TreeNode::mapping(
            (0..count)
                .map(|index| {
                    (
                        format!("private-{index}"),
                        TreeNode::new(TreeValue::String("private-value".into())),
                    )
                })
                .collect(),
        );
        let ctx = fields(NativeProcessingLimits {
            max_processing_units: 1,
            ..NativeProcessingLimits::default()
        });
        let error = UnknownFields::capture_in(&tree, &["known"], &ctx)
            .err()
            .ok_or("capture exceeded budget")?;
        assert_eq!(error.code, FindingCode::LimitExceeded);
        assert!(ctx.processing.exhausted());
        assert!(!format!("{error:?}").contains("private"));
        charged.push(ctx.processing.charged_payload_bytes());
    }
    assert_eq!(charged[0], charged[1]);
    Ok(())
}

#[test]
fn capture_stops_on_payload_and_prior_sticky_exhaustion() {
    let tree = TreeNode::mapping(vec![(
        "private-key".into(),
        TreeNode::new(TreeValue::String("private-value".into())),
    )]);
    for prior_failure in [false, true] {
        let ctx = fields(NativeProcessingLimits {
            max_payload_bytes: 2 * size_of::<usize>(),
            ..NativeProcessingLimits::default()
        });
        if prior_failure {
            assert!(ctx.processing.payload(usize::MAX, Phase::Analysis).is_err());
        }
        assert!(UnknownFields::capture_in(&tree, &[], &ctx).is_err());
        let charged = ctx.processing.charged_payload_bytes();
        assert!(UnknownFields::capture_in(&tree, &[], &ctx).is_err());
        assert_eq!(ctx.processing.charged_payload_bytes(), charged);
    }
}

fn claim() -> Result<PersistentVolumeClaimSpec, String> {
    let tree = TreeNode::mapping(vec![
        (
            "accessModes".into(),
            TreeNode::new(TreeValue::Sequence(vec![TreeNode::new(TreeValue::String(
                "future-private-mode".into(),
            ))])),
        ),
        ("future-private-field".into(), TreeNode::new(TreeValue::Null)),
    ]);
    PersistentVolumeClaimSpec::decode(&tree, &fields(NativeProcessingLimits::default()), &FieldPath::default())
        .map_err(|_| "claim decode failed".into())
}

#[test]
fn streamed_unknown_scopes_match_native_scopes_and_stop_on_callback_refusal() -> Result<(), String> {
    let claim = claim()?;
    let mut expected = BTreeSet::new();
    claim.unknown_scopes(&FieldPath::default(), &mut expected);
    let ctx = fields(NativeProcessingLimits::default());
    let mut actual = BTreeSet::new();
    assert!(claim.visit_unknown_scopes(
        &FieldPath::default(),
        &mut UnknownScopeVisitor::new(&ctx, &mut |path| {
            actual.insert(path);
            true
        }),
    ));
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 2);
    let mut calls = 0;
    assert!(!claim.visit_unknown_scopes(
        &FieldPath::default(),
        &mut UnknownScopeVisitor::new(&ctx, &mut |_| {
            calls += 1;
            false
        }),
    ));
    assert_eq!(calls, 1);
    Ok(())
}

#[test]
fn streamed_unknown_scopes_refuse_callbacks_after_work_or_payload_exhaustion() -> Result<(), String> {
    let claim = claim()?;
    let path = FieldPath(vec!["spec".into()]);
    for limits in [
        NativeProcessingLimits {
            max_processing_units: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    ] {
        let ctx = fields(limits);
        let mut calls = 0;
        for _ in 0..2 {
            assert!(!claim.visit_unknown_scopes(
                &path,
                &mut UnknownScopeVisitor::new(&ctx, &mut |_| {
                    calls += 1;
                    true
                }),
            ));
        }
        assert_eq!(calls, 0);
        assert!(ctx.processing.exhausted());
    }
    Ok(())
}
