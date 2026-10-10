//! Crate-private ordered source arena and merge-safe owned syntax.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase, SourcePosition},
    source::{DocumentFormat, ParseLimits, SourceId},
};
use std::{
    cell::Cell,
    collections::{BTreeMap, BTreeSet},
    fmt,
    rc::Rc,
    sync::Arc,
};

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
                if left.len() != right.len() {
                    return false;
                }
                let index: BTreeMap<_, _> = right.iter().map(|(key, value)| (key, value)).collect();
                left.iter()
                    .all(|(key, value)| index.get(key).is_some_and(|other| value.semantic_eq(other)))
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
impl PartialEq for UnknownFields {
    fn eq(&self, other: &Self) -> bool {
        let right: BTreeMap<_, _> = other.entries.iter().map(|(key, value)| (key, value)).collect();
        self.entries.len() == other.entries.len()
            && self
                .entries
                .iter()
                .all(|(key, node)| right.get(key).is_some_and(|value| node.0.semantic_eq(&value.0)))
    }
}
impl Eq for UnknownFields {}
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
    pub(crate) fn set_root(&mut self, root: TreeNode) {
        self.root = Some(root);
    }
    pub(crate) fn finish(self) -> Result<TreeNode, Finding> {
        self.root
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Generation))
    }
}

/// Shared construction accounting; cloning a context never resets its allowance.
#[derive(Clone)]
pub(crate) struct EncodingBudget(Rc<EncodingCounters>, Phase);
struct EncodingCounters {
    processing: crate::processing::NativeOperationBudget,
    limits: crate::source::AuthoringLimits,
    nodes: Cell<usize>,
    events: Cell<usize>,
    bytes: Cell<usize>,
    scalar_bytes: Cell<usize>,
    verified_scalar_bytes: Cell<usize>,
    verified_nodes: Cell<usize>,
    verified_events: Cell<usize>,
}
impl EncodingBudget {
    #[cfg(test)]
    pub(crate) fn new(limits: crate::source::AuthoringLimits) -> Self {
        Self::in_operation(
            limits,
            crate::processing::NativeOperationBudget::new(limits.parser.processing),
        )
    }
    pub(crate) fn in_operation(
        limits: crate::source::AuthoringLimits,
        processing: crate::processing::NativeOperationBudget,
    ) -> Self {
        Self(
            Rc::new(EncodingCounters {
                processing,
                limits,
                nodes: Cell::new(0),
                events: Cell::new(0),
                bytes: Cell::new(0),
                scalar_bytes: Cell::new(0),
                verified_scalar_bytes: Cell::new(0),
                verified_nodes: Cell::new(0),
                verified_events: Cell::new(0),
            }),
            Phase::Generation,
        )
    }
    pub(crate) fn for_phase(mut self, phase: Phase) -> Self {
        self.1 = phase;
        self
    }
    pub(crate) fn phase(&self) -> Phase {
        self.1
    }
    pub(crate) fn processing(&self) -> &crate::processing::NativeOperationBudget {
        &self.0.processing
    }
    pub(crate) fn check_len(&self, len: usize, path: &FieldPath) -> Result<(), Finding> {
        let limits = self.0.limits.parser;
        if !self.0.limits.valid()
            || len > limits.max_nodes.saturating_sub(self.0.nodes.get())
            || len > limits.max_events.saturating_sub(self.0.events.get())
        {
            return Err(encoding_limit(path));
        }
        Ok(())
    }
    pub(crate) fn scalar(&self, len: usize, path: &FieldPath) -> Result<(), Finding> {
        self.processing().work(len, self.1)?;
        if len > self.0.limits.parser.max_scalar_bytes {
            return Err(encoding_limit(path));
        }
        let total = self
            .0
            .scalar_bytes
            .get()
            .checked_add(len)
            .ok_or_else(|| encoding_limit(path))?;
        if total > self.0.limits.max_total_snapshot_bytes {
            return Err(encoding_limit(path));
        }
        self.node(path)?;
        self.0.scalar_bytes.set(total);
        Ok(())
    }
    pub(crate) fn node(&self, path: &FieldPath) -> Result<(), Finding> {
        self.processing().work(1, self.1)?;
        self.check_len(1, path)?;
        if path.0.len() > self.0.limits.parser.max_depth {
            return Err(encoding_limit(path));
        }
        self.0.nodes.set(self.0.nodes.get() + 1);
        self.0.events.set(self.0.events.get() + 1);
        Ok(())
    }
    pub(crate) fn clone_node(&self, node: &TreeNode, path: &FieldPath) -> Result<TreeNode, Finding> {
        let value = match &node.value {
            TreeValue::Null => {
                self.node(path)?;
                TreeValue::Null
            }
            TreeValue::Bool(value) => {
                self.node(path)?;
                TreeValue::Bool(*value)
            }
            TreeValue::Number(value) => {
                self.processing().payload(value.len(), self.1)?;
                self.scalar(value.len(), path)?;
                TreeValue::Number(value.clone())
            }
            TreeValue::String(value) => {
                self.processing().payload(value.len(), self.1)?;
                self.scalar(value.len(), path)?;
                TreeValue::String(value.clone())
            }
            TreeValue::Sequence(items) => {
                self.node(path)?;
                self.check_len(items.len(), path)?;
                let mut out = Vec::with_capacity(items.len());
                for (index, item) in items.iter().enumerate() {
                    out.push(self.clone_node(item, &path.child(index.to_string()))?);
                }
                TreeValue::Sequence(out)
            }
            TreeValue::Mapping(entries) => {
                self.node(path)?;
                self.check_len(entries.len().checked_mul(2).ok_or_else(|| encoding_limit(path))?, path)?;
                let mut out = Vec::with_capacity(entries.len());
                for (key, value) in entries {
                    let child = path.child(key);
                    self.processing().payload(key.len(), self.1)?;
                    self.scalar(key.len(), &child)?;
                    out.push((key.clone(), self.clone_node(value, &child)?));
                }
                TreeValue::Mapping(out)
            }
            TreeValue::Tagged(..) => {
                return Err(Finding::error(FindingCode::UnsupportedScalar, Phase::Generation).at_path(path.clone()));
            }
        };
        Ok(TreeNode::new(value))
    }
    /// Verify the final shape independently of trusted codec accounting.
    pub(crate) fn verify(&self, node: &TreeNode) -> Result<(), Finding> {
        let check = Self::in_operation(self.0.limits, self.processing().clone()).for_phase(self.1);
        check.0.nodes.set(self.0.verified_nodes.get());
        check.0.events.set(self.0.verified_events.get());
        check.0.scalar_bytes.set(self.0.verified_scalar_bytes.get());
        check.inspect(node, &FieldPath::default())?;
        self.0.verified_nodes.set(check.0.nodes.get());
        self.0.verified_events.set(check.0.events.get());
        self.0.verified_scalar_bytes.set(check.0.scalar_bytes.get());
        Ok(())
    }
    fn inspect(&self, node: &TreeNode, path: &FieldPath) -> Result<(), Finding> {
        match &node.value {
            TreeValue::String(value) | TreeValue::Number(value) => self.scalar(value.len(), path)?,
            TreeValue::Mapping(entries) => {
                self.node(path)?;
                let mut keys = BTreeSet::new();
                for (key, value) in entries {
                    let child = path.child(key);
                    self.scalar(key.len(), &child)?;
                    if !keys.insert(key) {
                        return Err(Finding::error(FindingCode::DuplicateKey, Phase::Generation).at_path(child));
                    }
                    self.inspect(value, &child)?;
                }
            }
            TreeValue::Sequence(items) => {
                self.node(path)?;
                for (index, value) in items.iter().enumerate() {
                    self.inspect(value, &path.child(index.to_string()))?;
                }
            }
            TreeValue::Tagged(..) => {
                return Err(Finding::error(FindingCode::UnsupportedScalar, Phase::Generation).at_path(path.clone()));
            }
            _ => self.node(path)?,
        }
        Ok(())
    }
    /// Stream JSON directly into a checked byte buffer, with no unbounded intermediary.
    pub(crate) fn snapshot(&self, node: &TreeNode) -> Result<Vec<u8>, Finding> {
        self.verify(node)?;
        let mut out = Vec::new();
        self.json(node, &mut out, &FieldPath::default())?;
        self.0.bytes.set(
            self.0
                .bytes
                .get()
                .checked_add(out.len())
                .ok_or_else(|| encoding_limit(&FieldPath::default()))?,
        );
        Ok(out)
    }
    fn append(&self, out: &mut Vec<u8>, bytes: &[u8], path: &FieldPath) -> Result<(), Finding> {
        let next = out.len().checked_add(bytes.len()).ok_or_else(|| encoding_limit(path))?;
        if next > self.0.limits.parser.max_input_bytes
            || next
                > self
                    .0
                    .limits
                    .max_total_snapshot_bytes
                    .saturating_sub(self.0.bytes.get())
        {
            return Err(encoding_limit(path));
        }
        self.processing().payload(bytes.len(), self.1)?;
        self.processing().work(bytes.len(), self.1)?;
        out.extend_from_slice(bytes);
        Ok(())
    }
    fn quoted(&self, value: &str, out: &mut Vec<u8>, path: &FieldPath) -> Result<(), Finding> {
        self.append(out, b"\"", path)?;
        for byte in value.bytes() {
            match byte {
                b'"' => self.append(out, b"\\\"", path)?,
                b'\\' => self.append(out, b"\\\\", path)?,
                0..=31 => {
                    let hex = b"0123456789abcdef";
                    self.append(
                        out,
                        &[
                            b'\\',
                            b'u',
                            b'0',
                            b'0',
                            hex[usize::from(byte >> 4)],
                            hex[usize::from(byte & 15)],
                        ],
                        path,
                    )?;
                }
                _ => self.append(out, &[byte], path)?,
            }
        }
        self.append(out, b"\"", path)
    }
    fn json(&self, node: &TreeNode, out: &mut Vec<u8>, path: &FieldPath) -> Result<(), Finding> {
        match &node.value {
            TreeValue::Null => self.append(out, b"null", path),
            TreeValue::Bool(value) => self.append(out, if *value { b"true" } else { b"false" }, path),
            TreeValue::Number(value) => {
                // The strict parser checks lexemes too; fail safely before writing malformed JSON.
                if serde_json::from_str::<serde_json::Number>(value).is_err() {
                    return Err(
                        Finding::error(FindingCode::NativeFieldInvalid, Phase::Generation).at_path(path.clone())
                    );
                }
                self.append(out, value.as_bytes(), path)
            }
            TreeValue::String(value) => self.quoted(value, out, path),
            TreeValue::Sequence(items) => {
                self.append(out, b"[", path)?;
                for (index, item) in items.iter().enumerate() {
                    if index > 0 {
                        self.append(out, b",", path)?;
                    }
                    self.json(item, out, &path.child(index.to_string()))?;
                }
                self.append(out, b"]", path)
            }
            TreeValue::Mapping(entries) => {
                self.append(out, b"{", path)?;
                // The native codec supplies deterministic field order; maps supply BTreeMap order.
                for (index, (key, item)) in entries.iter().enumerate() {
                    if index > 0 {
                        self.append(out, b",", path)?;
                    }
                    let child = path.child(key);
                    self.quoted(key, out, &child)?;
                    self.append(out, b":", &child)?;
                    self.json(item, out, &child)?;
                }
                self.append(out, b"}", path)
            }
            TreeValue::Tagged(..) => {
                Err(Finding::error(FindingCode::UnsupportedScalar, Phase::Generation).at_path(path.clone()))
            }
        }
    }
}
fn encoding_limit(path: &FieldPath) -> Finding {
    Finding::error(FindingCode::LimitExceeded, Phase::Generation).at_path(path.clone())
}
