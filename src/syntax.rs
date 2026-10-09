//! Crate-private ordered source arena and merge-safe owned syntax.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase, SourcePosition},
    source::{DocumentFormat, ParseLimits, SourceId},
};
use std::{collections::BTreeSet, fmt, sync::Arc};

pub(crate) type NodeId = usize;
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ScalarStyle {
    Plain,
    SingleQuoted,
    DoubleQuoted,
    Literal,
    Folded,
}
#[derive(Clone)]
pub(crate) enum NodeValue {
    Null,
    Bool(bool),
    Number(String),
    String(String, ScalarStyle),
    Sequence(Vec<NodeId>),
    Mapping(Vec<(NodeId, NodeId)>),
    Alias(NodeId),
    Tagged(String, NodeId),
}
#[derive(Clone)]
pub(crate) struct SyntaxNode {
    pub(crate) value: NodeValue,
    pub(crate) start: SourcePosition,
}
#[derive(Clone)]
pub(crate) struct SyntaxDocument {
    pub(crate) root: NodeId,
    pub(crate) format: DocumentFormat,
    pub(crate) source: SourceId,
    pub(crate) document_index: u32,
    pub(crate) nodes: Vec<SyntaxNode>,
}
impl fmt::Debug for SyntaxDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntaxDocument")
            .field("source", &self.source)
            .field("document_index", &self.document_index)
            .field("format", &self.format)
            .field("node_count", &self.nodes.len())
            .finish_non_exhaustive()
    }
}
impl fmt::Debug for SyntaxNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SyntaxNode")
            .field("position", &self.start)
            .finish_non_exhaustive()
    }
}

#[derive(Clone, Eq, PartialEq)]
pub(crate) struct TreeNode {
    pub(crate) value: TreeValue,
    pub(crate) start: Option<SourcePosition>,
}
#[derive(Clone, Eq, PartialEq)]
pub(crate) enum TreeValue {
    Null,
    Bool(bool),
    Number(String),
    String(String),
    Sequence(Vec<TreeNode>),
    Mapping(Vec<(String, TreeNode)>),
    Tagged(String, Box<TreeNode>),
}
impl fmt::Debug for TreeNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("TreeNode")
            .field("position", &self.start)
            .finish_non_exhaustive()
    }
}
impl TreeNode {
    pub(crate) const fn new(value: TreeValue) -> Self {
        Self { value, start: None }
    }
    pub(crate) fn string(value: impl Into<String>) -> Self {
        Self::new(TreeValue::String(value.into()))
    }
    pub(crate) fn mapping(entries: Vec<(String, Self)>) -> Self {
        Self::new(TreeValue::Mapping(entries))
    }
    pub(crate) fn get(&self, key: &str) -> Option<&Self> {
        if let TreeValue::Mapping(entries) = &self.value {
            entries.iter().find_map(|(name, node)| (name == key).then_some(node))
        } else {
            None
        }
    }
    pub(crate) fn as_str(&self) -> Option<&str> {
        if let TreeValue::String(value) = &self.value {
            Some(value)
        } else {
            None
        }
    }
    pub(crate) fn as_mapping(&self) -> Option<&[(String, Self)]> {
        if let TreeValue::Mapping(entries) = &self.value {
            Some(entries)
        } else {
            None
        }
    }
    pub(crate) fn as_sequence(&self) -> Option<&[Self]> {
        if let TreeValue::Sequence(items) = &self.value {
            Some(items)
        } else {
            None
        }
    }
    pub(crate) fn get_path(&self, path: &FieldPath) -> Option<&Self> {
        let mut node = self;
        for segment in &path.0 {
            node = match &node.value {
                TreeValue::Mapping(entries) => entries
                    .iter()
                    .find_map(|(key, value)| (key == segment).then_some(value))?,
                TreeValue::Sequence(items) => items.get(segment.parse::<usize>().ok()?)?,
                _ => return None,
            };
        }
        Some(node)
    }
    pub(crate) fn semantic_eq(&self, other: &Self) -> bool {
        match (&self.value, &other.value) {
            (TreeValue::Mapping(left), TreeValue::Mapping(right)) => {
                left.len() == right.len()
                    && left.iter().all(|(key, value)| {
                        right
                            .iter()
                            .find(|(other, _)| other == key)
                            .is_some_and(|(_, other)| value.semantic_eq(other))
                    })
            }
            (TreeValue::Sequence(left), TreeValue::Sequence(right)) => {
                left.len() == right.len() && left.iter().zip(right).all(|(left, right)| left.semantic_eq(right))
            }
            (TreeValue::Tagged(left_tag, left), TreeValue::Tagged(right_tag, right)) => {
                left_tag == right_tag && left.semantic_eq(right)
            }
            _ => self.value == other.value,
        }
    }
}

impl SyntaxDocument {
    pub(crate) fn materialize(&self, limits: &ParseLimits, alias_visits: &mut usize) -> Result<TreeNode, Finding> {
        let mut stack = BTreeSet::new();
        self.materialize_node(self.root, limits, &mut stack, alias_visits, 0, false)
    }
    fn materialize_node(
        &self,
        id: NodeId,
        limits: &ParseLimits,
        stack: &mut BTreeSet<NodeId>,
        alias_visits: &mut usize,
        depth: usize,
        inside_alias: bool,
    ) -> Result<TreeNode, Finding> {
        let Some(node) = self.nodes.get(id) else {
            return Err(Finding::error(FindingCode::InvalidAlias, Phase::Parsing));
        };
        if depth > limits.max_depth {
            return Err(Finding::error(FindingCode::LimitExceeded, Phase::Parsing).at_source(node.start));
        }
        if inside_alias {
            *alias_visits = alias_visits.saturating_add(1);
            if *alias_visits > limits.max_alias_visits {
                return Err(Finding::error(FindingCode::LimitExceeded, Phase::Parsing).at_source(node.start));
            }
        }
        if !stack.insert(id) {
            return Err(Finding::error(FindingCode::InvalidAlias, Phase::Parsing).at_source(node.start));
        }
        let value = match &node.value {
            NodeValue::Null => TreeValue::Null,
            NodeValue::Bool(value) => TreeValue::Bool(*value),
            NodeValue::Number(value) => TreeValue::Number(value.clone()),
            NodeValue::String(value, style) => match style {
                ScalarStyle::Plain
                | ScalarStyle::SingleQuoted
                | ScalarStyle::DoubleQuoted
                | ScalarStyle::Literal
                | ScalarStyle::Folded => TreeValue::String(value.clone()),
            },
            NodeValue::Sequence(items) => TreeValue::Sequence(
                items
                    .iter()
                    .map(|item| self.materialize_node(*item, limits, stack, alias_visits, depth + 1, inside_alias))
                    .collect::<Result<_, _>>()?,
            ),
            NodeValue::Mapping(entries) => {
                let mut keys = BTreeSet::new();
                let mut values = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let key_node = self.materialize_node(*key, limits, stack, alias_visits, depth + 1, inside_alias)?;
                    let TreeValue::String(key) = key_node.value else {
                        return Err(Finding::error(FindingCode::InvalidMappingKey, Phase::Parsing)
                            .at_source(key_node.start.unwrap_or(node.start)));
                    };
                    if key == "<<" {
                        return Err(Finding::error(FindingCode::UnsupportedMergeKey, Phase::Parsing)
                            .at_source(key_node.start.unwrap_or(node.start)));
                    }
                    if !keys.insert(key.clone()) {
                        return Err(Finding::error(FindingCode::DuplicateKey, Phase::Parsing)
                            .at_source(key_node.start.unwrap_or(node.start)));
                    }
                    values.push((
                        key,
                        self.materialize_node(*value, limits, stack, alias_visits, depth + 1, inside_alias)?,
                    ));
                }
                TreeValue::Mapping(values)
            }
            NodeValue::Alias(target) => {
                let result = self.materialize_node(*target, limits, stack, alias_visits, depth + 1, true)?;
                stack.remove(&id);
                return Ok(TreeNode {
                    start: Some(node.start),
                    ..result
                });
            }
            NodeValue::Tagged(tag, value) => TreeValue::Tagged(
                tag.clone(),
                Box::new(self.materialize_node(*value, limits, stack, alias_visits, depth + 1, inside_alias)?),
            ),
        };
        stack.remove(&id);
        Ok(TreeNode {
            value,
            start: Some(node.start),
        })
    }
}

/// Retained unknown nested syntax. It is not typed capability or serializable by default.
#[derive(Clone, Default)]
pub struct UnknownFields {
    pub(crate) entries: Vec<(String, OpaqueNode)>,
}
impl UnknownFields {
    /// Number of retained unknown immediate fields.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Whether the native object had no unknown fields.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    pub(crate) fn capture(node: &TreeNode, known: &[&str]) -> Self {
        Self {
            entries: node
                .as_mapping()
                .unwrap_or(&[])
                .iter()
                .filter(|(key, _)| !known.contains(&key.as_str()))
                .map(|(key, node)| (key.clone(), OpaqueNode(Arc::new(node.clone()))))
                .collect(),
        }
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    pub(crate) fn append_to(&self, entries: &mut Vec<(String, TreeNode)>) {
        for (key, value) in &self.entries {
            if !entries.iter().any(|(known, _)| known == key) {
                entries.push((key.clone(), (*value.0).clone()));
            }
        }
    }
}
impl fmt::Debug for UnknownFields {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("UnknownFields")
            .field("field_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub(crate) struct OpaqueNode(pub(crate) Arc<TreeNode>);
impl fmt::Debug for OpaqueNode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("OpaqueNode")
            .field("source_position", &self.0.start)
            .finish_non_exhaustive()
    }
}

pub(crate) struct SyntaxBuilder {
    root: Option<TreeNode>,
}
impl SyntaxBuilder {
    pub(crate) const fn new() -> Self {
        Self { root: None }
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    pub(crate) fn set_root(&mut self, root: TreeNode) {
        self.root = Some(root);
    }
    pub(crate) fn finish(self) -> Result<TreeNode, Finding> {
        self.root
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Generation))
    }
}
