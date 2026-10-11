//! Shared supplied metadata predicates; no namespace/default or protected value is inferred.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    registry::{FieldDecodeContext, FindingSink},
    syntax::TreeNode,
    value::{label_key, label_value},
};

pub(crate) fn validate(
    metadata: &TreeNode,
    path: &FieldPath,
    fields: &FieldDecodeContext,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    for name in ["labels", "annotations"] {
        fields.processing.work(1, Phase::Validation)?;
        let Some(entries) = metadata.get(name).and_then(TreeNode::as_mapping) else {
            continue;
        };
        let parent = super::child_path(path, name, fields)?;
        let mut total = 0usize;
        let mut size_reported = false;
        for (key, node) in entries {
            if out.exhausted() {
                return Ok(());
            }
            let Some(value) = node.as_str() else { continue };
            let bytes = key
                .len()
                .checked_add(value.len())
                .ok_or_else(|| fields.processing.fail(Phase::Validation))?;
            fields.processing.work(bytes.saturating_add(1), Phase::Validation)?;
            total = total
                .checked_add(bytes)
                .ok_or_else(|| fields.processing.fail(Phase::Validation))?;
            let oversized = name == "annotations" && total > 262_144 && !size_reported;
            if !label_key(key) || name == "labels" && !label_value(value) || oversized {
                out.push(
                    Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)
                        .at_path(super::child_path(&parent, key, fields)?),
                );
            }
            size_reported |= oversized;
        }
    }
    Ok(())
}
