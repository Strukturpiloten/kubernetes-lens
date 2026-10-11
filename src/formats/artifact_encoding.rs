//! Original bounded JSON and Go-string serialization for generated projects only.
use super::{FormatError, Result};
use crate::{
    diagnostic::Phase,
    processing::NativeOperationBudget,
    syntax::{TreeNode, TreeValue},
};
use std::collections::BTreeMap;

pub(super) type SelectedFields = BTreeMap<(usize, Vec<String>), String>;
type Selection<'a> = Option<(usize, &'a SelectedFields)>;

pub(super) fn append(out: &mut Vec<u8>, bytes: &[u8], budget: &NativeOperationBudget) -> Result<()> {
    budget
        .payload(bytes.len(), Phase::Generation)
        .and_then(|()| budget.work(bytes.len(), Phase::Generation))
        .map_err(|finding| FormatError::native(vec![finding]))?;
    out.try_reserve(bytes.len())
        .map_err(|_| FormatError::native(vec![budget.fail(Phase::Generation)]))?;
    out.extend_from_slice(bytes);
    Ok(())
}

fn quoted(out: &mut Vec<u8>, value: &str, go: bool, budget: &NativeOperationBudget) -> Result<()> {
    budget
        .work(value.len(), Phase::Generation)
        .map_err(|finding| FormatError::native(vec![finding]))?;
    append(out, b"\"", budget)?;
    for ch in value.chars() {
        match ch {
            '"' => append(out, b"\\\"", budget)?,
            '\\' => append(out, b"\\\\", budget)?,
            '\u{08}' => append(out, b"\\b", budget)?,
            '\u{0c}' => append(out, b"\\f", budget)?,
            '\n' => append(out, b"\\n", budget)?,
            '\r' => append(out, b"\\r", budget)?,
            '\t' => append(out, b"\\t", budget)?,
            '\u{00}'..='\u{1f}' | '\u{7f}' if ch != '\u{7f}' || go => {
                const HEX: &[u8; 16] = b"0123456789abcdef";
                let byte =
                    u8::try_from(u32::from(ch)).map_err(|_| FormatError::new(super::FormatCode::InvalidProject))?;
                append(
                    out,
                    &[
                        b'\\',
                        b'u',
                        b'0',
                        b'0',
                        HEX[usize::from(byte >> 4)],
                        HEX[usize::from(byte & 15)],
                    ],
                    budget,
                )?;
            }
            _ => {
                let mut utf8 = [0; 4];
                append(out, ch.encode_utf8(&mut utf8).as_bytes(), budget)?;
            }
        }
    }
    append(out, b"\"", budget)
}

// A fallible heap sort meters actual key comparisons and stops immediately on exhaustion.
fn ordered<'a>(
    entries: &'a [(String, TreeNode)],
    budget: &NativeOperationBudget,
) -> Result<Vec<&'a (String, TreeNode)>> {
    fn greater(a: &(String, TreeNode), b: &(String, TreeNode), budget: &NativeOperationBudget) -> Result<bool> {
        budget
            .work(a.0.len().min(b.0.len()).saturating_add(1), Phase::Generation)
            .map_err(|finding| FormatError::native(vec![finding]))?;
        Ok(a.0.as_bytes() > b.0.as_bytes())
    }
    fn sift(items: &mut [&(String, TreeNode)], mut root: usize, budget: &NativeOperationBudget) -> Result<()> {
        while let Some(left) = root
            .checked_mul(2)
            .and_then(|n| n.checked_add(1))
            .filter(|n| *n < items.len())
        {
            let mut child = left;
            if left + 1 < items.len() && greater(items[left + 1], items[left], budget)? {
                child += 1;
            }
            if !greater(items[child], items[root], budget)? {
                break;
            }
            items.swap(root, child);
            root = child;
        }
        Ok(())
    }
    budget
        .payload_array::<&(String, TreeNode)>(entries.len(), Phase::Generation)
        .map_err(|finding| FormatError::native(vec![finding]))?;
    let mut result: Vec<_> = entries.iter().collect();
    for root in (0..result.len() / 2).rev() {
        sift(&mut result, root, budget)?;
    }
    for end in (1..result.len()).rev() {
        result.swap(0, end);
        sift(&mut result[..end], 0, budget)?;
    }
    Ok(result)
}

enum Event<'a> {
    Node(&'a TreeNode, Vec<String>),
    Key(&'a str),
    Bytes(&'static [u8]),
}
fn push<'a>(stack: &mut Vec<Event<'a>>, event: Event<'a>, budget: &NativeOperationBudget) -> Result<()> {
    budget
        .payload_array::<Event<'a>>(1, Phase::Generation)
        .and_then(|()| budget.work(1, Phase::Generation))
        .map_err(|finding| FormatError::native(vec![finding]))?;
    stack.push(event);
    Ok(())
}
fn child_path(path: &[String], component: &str, template: bool, budget: &NativeOperationBudget) -> Result<Vec<String>> {
    if !template {
        return Ok(Vec::new());
    }
    budget
        .payload_array::<String>(path.len().saturating_add(1), Phase::Generation)
        .map_err(|finding| FormatError::native(vec![finding]))?;
    for item in path.iter().map(String::as_str).chain(std::iter::once(component)) {
        budget
            .payload(item.len(), Phase::Generation)
            .and_then(|()| budget.work(item.len(), Phase::Generation))
            .map_err(|finding| FormatError::native(vec![finding]))?;
    }
    let mut result = path.to_vec();
    result.push(component.to_owned());
    Ok(result)
}
fn literal(out: &mut Vec<u8>, token: &[u8], budget: &NativeOperationBudget) -> Result<()> {
    append(out, b"{{ print ", budget)?;
    let text = std::str::from_utf8(token).map_err(|_| FormatError::new(super::FormatCode::InvalidProject))?;
    quoted(out, text, true, budget)?;
    append(out, b" }}", budget)
}

pub(super) fn json(tree: &TreeNode, budget: &NativeOperationBudget) -> Result<Vec<u8>> {
    encode(tree, None, budget)
}
pub(super) fn template(
    tree: &TreeNode,
    index: usize,
    selected: &SelectedFields,
    budget: &NativeOperationBudget,
) -> Result<Vec<u8>> {
    encode(tree, Some((index, selected)), budget)
}
fn encode(tree: &TreeNode, selection: Selection<'_>, budget: &NativeOperationBudget) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    let mut stack = Vec::new();
    push(&mut stack, Event::Node(tree, Vec::new()), budget)?;
    while let Some(event) = stack.pop() {
        match event {
            Event::Bytes(bytes) => append(&mut out, bytes, budget)?,
            Event::Key(key) => {
                if selection.is_some() {
                    let mut token = Vec::new();
                    quoted(&mut token, key, false, budget)?;
                    literal(&mut out, &token, budget)?;
                } else {
                    quoted(&mut out, key, false, budget)?;
                }
            }
            Event::Node(node, path) => {
                if let Some((index, selected)) = selection {
                    // The path is consumed as a lookup key; no hidden clone is made.
                    let lookup = (index, path);
                    if let Some(name) = selected.get(&lookup) {
                        append(&mut out, b"{{ toJson (index .Values ", budget)?;
                        quoted(&mut out, name, true, budget)?;
                        append(&mut out, b") }}", budget)?;
                        continue;
                    }
                    expand(
                        node,
                        &lookup.1,
                        true,
                        !selected.is_empty(),
                        &mut stack,
                        &mut out,
                        budget,
                    )?;
                } else {
                    expand(node, &path, false, false, &mut stack, &mut out, budget)?;
                }
            }
        }
    }
    Ok(out)
}
fn expand<'a>(
    node: &'a TreeNode,
    path: &[String],
    template: bool,
    track_paths: bool,
    stack: &mut Vec<Event<'a>>,
    out: &mut Vec<u8>,
    budget: &NativeOperationBudget,
) -> Result<()> {
    match &node.value {
        TreeValue::Mapping(entries) => {
            if entries.is_empty() {
                return append(out, b"{}", budget);
            }
            append(out, if template { b"{ " } else { b"{" }, budget)?;
            push(stack, Event::Bytes(if template { b" }" } else { b"}" }), budget)?;
            for (index, (key, value)) in ordered(entries, budget)?.into_iter().enumerate().rev() {
                let path = child_path(path, key, track_paths, budget)?;
                push(stack, Event::Node(value, path), budget)?;
                push(stack, Event::Bytes(b":"), budget)?;
                push(stack, Event::Key(key), budget)?;
                if index > 0 {
                    push(stack, Event::Bytes(b","), budget)?;
                }
            }
            Ok(())
        }
        TreeValue::Sequence(items) => {
            append(out, b"[", budget)?;
            push(stack, Event::Bytes(b"]"), budget)?;
            for (index, value) in items.iter().enumerate().rev() {
                let digits = if index == 0 {
                    1
                } else {
                    usize::try_from(index.ilog10()).map_err(|_| FormatError::new(super::FormatCode::LimitExceeded))? + 1
                };
                budget
                    .payload(digits, Phase::Generation)
                    .and_then(|()| budget.work(digits, Phase::Generation))
                    .map_err(|finding| FormatError::native(vec![finding]))?;
                let component = index.to_string();
                let path = child_path(path, &component, track_paths, budget)?;
                push(stack, Event::Node(value, path), budget)?;
                if index > 0 {
                    push(stack, Event::Bytes(b","), budget)?;
                }
            }
            Ok(())
        }
        TreeValue::Tagged(..) => Err(FormatError::new(super::FormatCode::InvalidProject)),
        _ => {
            if template {
                let token = json(node, budget)?;
                literal(out, &token, budget)
            } else {
                match &node.value {
                    TreeValue::Null => append(out, b"null", budget),
                    TreeValue::Bool(value) => append(out, if *value { b"true" } else { b"false" }, budget),
                    TreeValue::Number(value) => append(out, value.as_bytes(), budget),
                    TreeValue::String(value) => quoted(out, value, false, budget),
                    _ => Err(FormatError::new(super::FormatCode::InvalidProject)),
                }
            }
        }
    }
}
