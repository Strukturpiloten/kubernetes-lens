//! Original finite PV Create checks from the independent declarative rule contract.
use super::{Check, Finding, FindingCode, NativeValidationIntent, PersistentVolume, Phase};
use crate::{
    diagnostic::FieldPath,
    registry::{FindingSink, ValidationContext, codec::FieldCodec},
    syntax::{TreeNode, TreeValue},
};
mod affinity;
mod sources;

pub(super) fn check(
    volume: &PersistentVolume,
    ctx: &ValidationContext<'_>,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    let mut check = Check { ctx, out };
    check.work(1)?;
    if ctx.intent != NativeValidationIntent::Create {
        return context(&mut check, &["spec"]);
    }
    let Some(spec) = volume.spec.value() else {
        return check.invalid(&["spec"]);
    };
    if spec
        .access_modes
        .value()
        .is_none_or(crate::value::AccessModes::is_empty)
    {
        check.invalid(&["spec", "accessModes"])?;
    }
    let capacity = spec.capacity.value();
    if capacity.is_none_or(|map| map.len() != 1 || !map.contains_key("storage")) {
        check.invalid(&["spec", "capacity"])?;
    }
    if let Some(capacity) = capacity {
        for (key, quantity) in capacity {
            check.text(key)?;
            check.text(quantity.native_lexeme())?;
            if quantity.exact().is_negative() || quantity.exact().is_zero() {
                check.invalid(&["spec", "capacity", key])?;
            } else if !quantity.conservative_bytes() {
                context(&mut check, &["spec", "capacity", key])?;
            }
        }
    }
    if let Some(class) = spec.storage_class_name.value() {
        check.text(class)?;
        if !class.is_empty() && !super::class_name(class) {
            check.invalid(&["spec", "storageClassName"])?;
        }
    }
    if check.out.exhausted() {
        return Ok(());
    }
    let mut encoding = ctx.encoding();
    encoding.include_unknown = true;
    let tree = spec.encode(&encoding, &FieldPath::parse("/spec")?)?;
    sources::check(&tree, volume, &mut check)?;
    affinity::check(&tree, &mut check)
}
fn context(check: &mut Check<'_, '_>, path: &[&str]) -> Result<(), Finding> {
    if !check.out.exhausted() {
        check
            .out
            .push(Finding::warning(FindingCode::NativeContextRequired, Phase::Validation).at_path(check.path(path)?));
    }
    Ok(())
}
fn get<'a>(node: &'a TreeNode, key: &str, check: &Check<'_, '_>) -> Result<Option<&'a TreeNode>, Finding> {
    check.work(
        node.as_mapping()
            .map_or(1, |entries| entries.len().saturating_add(1))
            .saturating_mul(key.len().saturating_add(1)),
    )?;
    Ok(node.get(key).filter(|node| !matches!(node.value, TreeValue::Null)))
}
fn text<'a>(node: &'a TreeNode, key: &str, check: &Check<'_, '_>) -> Result<Option<&'a str>, Finding> {
    let value = get(node, key, check)?.and_then(TreeNode::as_str);
    if let Some(value) = value {
        check.text(value)?;
    }
    Ok(value)
}
fn required(node: &TreeNode, branch: &str, names: &[&str], check: &mut Check<'_, '_>) -> Result<(), Finding> {
    for name in names {
        if text(node, name, check)?.is_none_or(str::is_empty) {
            check.invalid(&["spec", branch, name])?;
        }
    }
    Ok(())
}
fn label(value: &str) -> bool {
    value.len() <= 63 && super::class_name(value) && !value.contains('.')
}
fn bounded_integer(node: &TreeNode, branch: &str, field: &str, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let Some(value) = get(node, field, check)? else {
        return Ok(());
    };
    if !matches!(&value.value, TreeValue::Number(number) if number.parse::<i32>().is_ok_and(|value| (0..=255).contains(&value)))
    {
        check.invalid(&["spec", branch, field])?;
    }
    Ok(())
}
fn nonempty_list(node: &TreeNode, field: &str, check: &Check<'_, '_>) -> Result<bool, Finding> {
    Ok(get(node, field, check)?
        .and_then(TreeNode::as_sequence)
        .is_some_and(|items| !items.is_empty()))
}
