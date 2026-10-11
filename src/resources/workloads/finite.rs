//! Reviewed finite supplied predicates. No cluster, image, kernel or filesystem facts.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    registry::{FieldDecodeContext, FindingSink},
    resources::common::{child_path, index_path},
    syntax::TreeNode,
    value::Quantity,
};
use std::{cmp::Ordering, collections::BTreeSet};

pub(super) fn object(
    node: &TreeNode,
    path: &FieldPath,
    fields: &FieldDecodeContext,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    fields.processing.work(1, Phase::Validation)?;
    match path.0.last().map(String::as_str) {
        Some("metadata") => crate::resources::common::finite_metadata::validate(node, path, fields, out)?,
        Some("securityContext") => {
            if let Some(groups) = node.get("supplementalGroups").and_then(TreeNode::as_sequence) {
                let parent = child_path(path, "supplementalGroups", fields)?;
                for (index, group) in groups.iter().enumerate() {
                    fields.processing.work(21, Phase::Validation)?;
                    if super::validation::integer(group).is_some_and(|value| value < 0) {
                        out.push(
                            Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)
                                .at_path(index_path(&parent, index, fields)?),
                        );
                    }
                }
            }
        }
        Some("resources")
            if path
                .0
                .iter()
                .rev()
                .nth(2)
                .is_some_and(|field| matches!(field.as_str(), "containers" | "initContainers")) =>
        {
            resources(node, path, fields, out)?;
        }
        Some("spec") if node.get("containers").is_some() || node.get("initContainers").is_some() => {
            ports(node, path, fields, out)?;
        }
        _ => (),
    }
    Ok(())
}

fn resources(
    node: &TreeNode,
    path: &FieldPath,
    fields: &FieldDecodeContext,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    for member in ["requests", "limits"] {
        let Some(entries) = node.get(member).and_then(TreeNode::as_mapping) else {
            continue;
        };
        let parent = child_path(path, member, fields)?;
        for (name, value) in entries {
            if out.exhausted() {
                return Ok(());
            }
            fields
                .processing
                .work(name.len().saturating_add(1), Phase::Validation)?;
            let Some(lexeme) = value.as_str() else { continue };
            let quantity = Quantity::parse_in(lexeme, fields)?;
            fields.processing.work(533, Phase::Validation)?;
            if quantity.exact().is_negative() {
                continue;
            } // existing exact negative leaf check
            if !quantity.finite_container_domain(name) {
                out.push(
                    Finding::warning(FindingCode::NativeContextRequired, Phase::Validation)
                        .at_path(child_path(&parent, name, fields)?),
                );
            }
        }
    }
    let Some(requests) = node.get("requests").and_then(TreeNode::as_mapping) else {
        return Ok(());
    };
    let Some(limits) = node.get("limits") else {
        return Ok(());
    };
    for (name, value) in requests {
        if out.exhausted() {
            return Ok(());
        }
        fields.processing.work(
            limits
                .as_mapping()
                .map_or(1, |entries| entries.len().saturating_mul(name.len().saturating_add(1))),
            Phase::Validation,
        )?;
        let Some((request, limit)) = value.as_str().zip(limits.get(name).and_then(TreeNode::as_str)) else {
            continue;
        };
        let request = Quantity::parse_in(request, fields)?;
        let limit = Quantity::parse_in(limit, fields)?;
        fields.processing.work(1066, Phase::Validation)?;
        if request.finite_container_domain(name)
            && limit.finite_container_domain(name)
            && request.compare_exact(&limit, &fields.processing, Phase::Validation)? == Ordering::Greater
        {
            let parent = child_path(path, "requests", fields)?;
            out.push(
                Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)
                    .at_path(child_path(&parent, name, fields)?),
            );
        }
    }
    Ok(())
}

fn ports(
    node: &TreeNode,
    path: &FieldPath,
    fields: &FieldDecodeContext,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    let mut names = BTreeSet::new();
    for member in ["containers", "initContainers"] {
        let Some(containers) = node.get(member).and_then(TreeNode::as_sequence) else {
            continue;
        };
        let parent = child_path(path, member, fields)?;
        for (index, container) in containers.iter().enumerate() {
            fields.processing.work(1, Phase::Validation)?;
            let Some(ports) = container.get("ports").and_then(TreeNode::as_sequence) else {
                continue;
            };
            for (port_index, port) in ports.iter().enumerate() {
                if out.exhausted() {
                    return Ok(());
                }
                let Some(name) = port
                    .get("name")
                    .and_then(TreeNode::as_str)
                    .filter(|name| !name.is_empty())
                else {
                    continue;
                };
                let levels = names.len().saturating_add(1).ilog2() as usize + 1;
                fields.processing.work(
                    name.len().saturating_add(1).saturating_mul(levels).saturating_mul(32),
                    Phase::Validation,
                )?;
                fields.processing.payload_array::<&str>(1, Phase::Validation)?;
                if !names.insert(name) {
                    let container_path = index_path(&parent, index, fields)?;
                    let ports_path = child_path(&container_path, "ports", fields)?;
                    let port_path = index_path(&ports_path, port_index, fields)?;
                    out.push(
                        Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)
                            .at_path(child_path(&port_path, "name", fields)?),
                    );
                }
            }
        }
    }
    Ok(())
}

pub(super) fn drops(
    node: &TreeNode,
    path: &FieldPath,
    fields: &FieldDecodeContext,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    let Some(items) = node.as_sequence() else { return Ok(()) };
    for (index, item) in items.iter().enumerate() {
        if out.exhausted() {
            return Ok(());
        }
        let Some(name) = item.as_str() else { continue };
        fields
            .processing
            .work(name.len().saturating_add(1), Phase::Validation)?;
        if name != "ALL" {
            out.push(
                Finding::warning(FindingCode::NativeContextRequired, Phase::Validation)
                    .at_path(index_path(path, index, fields)?),
            );
        }
    }
    Ok(())
}
