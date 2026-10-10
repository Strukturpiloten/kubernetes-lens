//! Finite selected PV node-affinity syntax, independent of scheduler success.
use super::{Check, Finding, TreeNode, context, get, text};
pub(super) fn check(spec: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let Some(affinity) = get(spec, "nodeAffinity", check)? else {
        if get(spec, "local", check)?.is_some() {
            check.invalid(&["spec", "nodeAffinity"])?;
        }
        return Ok(());
    };
    let Some(required) = get(affinity, "required", check)? else {
        return check.invalid(&["spec", "nodeAffinity", "required"]);
    };
    let Some(terms) = get(required, "nodeSelectorTerms", check)?
        .and_then(TreeNode::as_sequence)
        .filter(|terms| !terms.is_empty())
    else {
        return check.invalid(&["spec", "nodeAffinity", "required", "nodeSelectorTerms"]);
    };
    for (index, term) in terms.iter().enumerate() {
        if check.out.exhausted() {
            return Ok(());
        }
        check.work(1)?;
        check.payload(20)?;
        let index = index.to_string();
        for field in ["matchExpressions", "matchFields"] {
            let Some(requirements) = get(term, field, check)?.and_then(TreeNode::as_sequence) else {
                continue;
            };
            for (item, requirement) in requirements.iter().enumerate() {
                check.work(1)?;
                check.payload(20)?;
                let item = item.to_string();
                let path = [
                    "spec",
                    "nodeAffinity",
                    "required",
                    "nodeSelectorTerms",
                    &index,
                    field,
                    &item,
                ];
                requirement_check(requirement, field, &path, check)?;
            }
        }
    }
    Ok(())
}
fn requirement_check(node: &TreeNode, field: &str, path: &[&str], check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let key = text(node, "key", check)?.unwrap_or("");
    let operator = text(node, "operator", check)?.unwrap_or("");
    let values = get(node, "values", check)?
        .and_then(TreeNode::as_sequence)
        .unwrap_or(&[]);
    let valid = if field == "matchFields" {
        key == "metadata.name" && matches!(operator, "In" | "NotIn") && values.len() == 1
    } else {
        crate::value::label_key(key)
            && match operator {
                "In" | "NotIn" => !values.is_empty(),
                "Exists" | "DoesNotExist" => values.is_empty(),
                "Gt" | "Lt" => values.len() == 1,
                _ => false,
            }
    };
    if !valid {
        check.invalid(path)?;
    }
    for value in values {
        let Some(value) = value.as_str() else {
            check.invalid(path)?;
            continue;
        };
        check.text(value)?;
        if field == "matchFields" && !super::super::class_name(value) {
            check.invalid(path)?;
        } else if field == "matchExpressions"
            && check.ctx.target.kubernetes.minor() >= 33
            && !crate::value::label_value(value)
        {
            context(check, path)?;
        }
    }
    // No current strategy/old-object witness determines the 1.33+ label-value option.
    // Empty terms and nonnumeric Gt/Lt values are not invented native errors.
    Ok(())
}
