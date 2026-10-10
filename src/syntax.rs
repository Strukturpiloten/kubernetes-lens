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

/// Sealed native occurrence candidate, authorized only against immutable document anchors.
#[derive(Clone)]
pub(crate) struct NativeOccurrence(Arc<()>);
impl NativeOccurrence {
    pub(crate) fn new_in(processing: &crate::processing::NativeOperationBudget, phase: Phase) -> Result<Self, Finding> {
        processing.work(1, phase)?;
        // Conservative retained Arc allocation header; this is not an RSS accounting claim.
        processing.payload(2 * size_of::<usize>(), phase)?;
        Ok(Self(Arc::new(())))
    }
    pub(crate) fn same(&self, other: &Self) -> bool {
        Arc::ptr_eq(&self.0, &other.0)
    }
}
/// Private balanced path index. It retains no operation handle: each fallible
/// insertion receives the current inherited budget. Taking the index moves its
/// arena without allocating, comparing paths, or rebuilding another table.
#[derive(Clone, Default)]
pub(crate) struct NativeOccurrences {
    entries: Vec<OccurrenceEntry>,
    root: Option<usize>,
}
#[derive(Clone)]
struct OccurrenceEntry {
    path: FieldPath,
    occurrence: NativeOccurrence,
    left: Option<usize>,
    right: Option<usize>,
    height: usize,
}
impl NativeOccurrences {
    pub(crate) fn new() -> Self {
        Self::default()
    }
    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.entries.len()
    }
    #[cfg(test)]
    pub(crate) fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Read-only reconciliation callers precharge all retained path comparisons
    /// before lookup. That bound also covers this index's visited subset.
    pub(crate) fn get(&self, path: &FieldPath) -> Option<&NativeOccurrence> {
        let mut current = self.root;
        while let Some(index) = current {
            let entry = &self.entries[index];
            match path.cmp(&entry.path) {
                std::cmp::Ordering::Less => current = entry.left,
                std::cmp::Ordering::Greater => current = entry.right,
                std::cmp::Ordering::Equal => return Some(&entry.occurrence),
            }
        }
        None
    }
    pub(crate) fn keys(&self) -> impl Iterator<Item = &FieldPath> {
        self.iter().map(|entry| &entry.path)
    }
    pub(crate) fn values(&self) -> impl Iterator<Item = &NativeOccurrence> {
        self.iter().map(|entry| &entry.occurrence)
    }
    fn iter(&self) -> OccurrenceIter<'_> {
        OccurrenceIter {
            entries: &self.entries,
            current: self.root,
            // AVL height is less than twice log2(n + 1). No representable
            // arena can require more slots; iteration allocates no scratch heap.
            stack: [0; 2 * usize::BITS as usize],
            depth: 0,
        }
    }
    pub(crate) fn insert_in(
        &mut self,
        path: &FieldPath,
        occurrence: &NativeOccurrence,
        processing: &crate::processing::NativeOperationBudget,
        phase: Phase,
    ) -> Result<(), Finding> {
        let root = self.insert_at(self.root, path, occurrence, processing, phase)?;
        self.root = Some(root);
        Ok(())
    }
    fn compare_in(
        left: &FieldPath,
        right: &FieldPath,
        processing: &crate::processing::NativeOperationBudget,
        phase: Phase,
    ) -> Result<std::cmp::Ordering, Finding> {
        processing.work(1, phase)?;
        for (left, right) in left.0.iter().zip(&right.0) {
            processing.work(1, phase)?;
            // Charge the conservative complete byte scan of the actual segment
            // pair BEFORE delegating its comparison, never every table key.
            processing.work(left.len(), phase)?;
            processing.work(right.len(), phase)?;
            let order = left.cmp(right);
            if order != std::cmp::Ordering::Equal {
                return Ok(order);
            }
        }
        Ok(left.0.len().cmp(&right.0.len()))
    }
    fn charge_path_copy(
        path: &FieldPath,
        processing: &crate::processing::NativeOperationBudget,
        phase: Phase,
    ) -> Result<(), Finding> {
        processing.payload_array::<String>(path.0.len(), phase)?;
        for segment in &path.0 {
            processing.payload(segment.len(), phase)?;
            processing.work(segment.len(), phase)?;
        }
        Ok(())
    }
    fn insert_at(
        &mut self,
        current: Option<usize>,
        path: &FieldPath,
        occurrence: &NativeOccurrence,
        processing: &crate::processing::NativeOperationBudget,
        phase: Phase,
    ) -> Result<usize, Finding> {
        processing.work(1, phase)?;
        let Some(index) = current else {
            processing.payload_array::<OccurrenceEntry>(1, phase)?;
            Self::charge_path_copy(path, processing, phase)?;
            if self.entries.len() == self.entries.capacity() {
                // Vec growth can copy the complete retained structural arena;
                // strings/tokens move without copying their private payloads.
                processing.work(
                    self.entries
                        .len()
                        .checked_mul(size_of::<OccurrenceEntry>())
                        .ok_or_else(|| processing.fail(phase))?,
                    phase,
                )?;
            }
            let index = self.entries.len();
            self.entries.push(OccurrenceEntry {
                path: path.clone(),
                occurrence: occurrence.clone(),
                left: None,
                right: None,
                height: 1,
            });
            return Ok(index);
        };
        let order = Self::compare_in(path, &self.entries[index].path, processing, phase)?;
        if order == std::cmp::Ordering::Equal {
            // Diagnostic path retention is also a real private copy. Failure to
            // reserve it returns terminal LimitExceeded, never a partial success.
            Self::charge_path_copy(path, processing, phase)?;
            return Err(Finding::error(FindingCode::MergeConflict, phase).at_path(path.clone()));
        }
        // Fixed local metadata allowance per ACTUALLY visited ancestor: one
        // child update/height check and at most two local rotations (three
        // touched nodes): at most five height updates, six rotation-link accesses,
        // and the child/balance accesses, bounded by 64 structural units.
        // Reserve before descent so failure cannot leave a
        // partially inserted or unbalanced index. This is not a logarithmic guess.
        processing.work(64, phase)?;
        if order == std::cmp::Ordering::Less {
            let child = self.insert_at(self.entries[index].left, path, occurrence, processing, phase)?;
            self.entries[index].left = Some(child);
        } else {
            let child = self.insert_at(self.entries[index].right, path, occurrence, processing, phase)?;
            self.entries[index].right = Some(child);
        }
        Ok(self.balance(index))
    }
    fn height(&self, index: Option<usize>) -> usize {
        index.map_or(0, |index| self.entries[index].height)
    }
    fn update_height(&mut self, index: usize) {
        self.entries[index].height = 1 + self
            .height(self.entries[index].left)
            .max(self.height(self.entries[index].right));
    }
    fn rotate_left(&mut self, index: usize, right: usize) -> usize {
        self.entries[index].right = self.entries[right].left;
        self.entries[right].left = Some(index);
        self.update_height(index);
        self.update_height(right);
        right
    }
    fn rotate_right(&mut self, index: usize, left: usize) -> usize {
        self.entries[index].left = self.entries[left].right;
        self.entries[left].right = Some(index);
        self.update_height(index);
        self.update_height(left);
        left
    }
    fn balance(&mut self, index: usize) -> usize {
        self.update_height(index);
        let left = self.entries[index].left;
        let right = self.entries[index].right;
        if self.height(left) > self.height(right) + 1 {
            if let Some(mut left) = left {
                if self.height(self.entries[left].right) > self.height(self.entries[left].left) {
                    if let Some(right) = self.entries[left].right {
                        left = self.rotate_left(left, right);
                        self.entries[index].left = Some(left);
                    }
                }
                return self.rotate_right(index, left);
            }
        } else if self.height(right) > self.height(left) + 1 {
            if let Some(mut right) = right {
                if self.height(self.entries[right].left) > self.height(self.entries[right].right) {
                    if let Some(left) = self.entries[right].left {
                        right = self.rotate_right(right, left);
                        self.entries[index].right = Some(right);
                    }
                }
                return self.rotate_left(index, right);
            }
        }
        index
    }
}
struct OccurrenceIter<'a> {
    entries: &'a [OccurrenceEntry],
    current: Option<usize>,
    stack: [usize; 2 * usize::BITS as usize],
    depth: usize,
}
impl<'a> Iterator for OccurrenceIter<'a> {
    type Item = &'a OccurrenceEntry;
    fn next(&mut self) -> Option<Self::Item> {
        while let Some(index) = self.current {
            self.stack[self.depth] = index;
            self.depth += 1;
            self.current = self.entries[index].left;
        }
        if self.depth == 0 {
            return None;
        }
        self.depth -= 1;
        let index = self.stack[self.depth];
        self.current = self.entries[index].right;
        Some(&self.entries[index])
    }
}

#[cfg(test)]
mod occurrence_index_tests {
    use super::*;
    use crate::processing::{NativeOperationBudget, NativeProcessingLimits};

    fn check_avl(table: &NativeOccurrences, index: Option<usize>) -> usize {
        let Some(index) = index else {
            return 0;
        };
        let entry = &table.entries[index];
        let left_height = check_avl(table, entry.left);
        let right_height = check_avl(table, entry.right);
        assert!(left_height.abs_diff(right_height) <= 1);
        assert_eq!(entry.height, 1 + left_height.max(right_height));
        if let Some(left) = entry.left {
            assert!(table.entries[left].path < entry.path);
        }
        if let Some(right) = entry.right {
            assert!(table.entries[right].path > entry.path);
        }
        entry.height
    }

    #[test]
    fn insertion_orders_preserve_sorted_paths_and_exact_tokens_without_rebuilding() -> Result<(), Finding> {
        for order in [
            (0..512).collect::<Vec<_>>(),
            (0..512).rev().collect(),
            (0..256).flat_map(|i| [i, 511 - i]).collect(),
        ] {
            let processing = NativeOperationBudget::new(NativeProcessingLimits::default());
            let mut table = NativeOccurrences::new();
            let mut expected = BTreeMap::new();
            for number in order {
                let path = FieldPath(vec!["private/~unicode-λ".into(), format!("field-{number:04}")]);
                let token = NativeOccurrence::new_in(&processing, Phase::Generation)?;
                table.insert_in(&path, &token, &processing, Phase::Generation)?;
                expected.insert(path, token);
                check_avl(&table, table.root);
            }
            assert_eq!(table.keys().collect::<Vec<_>>(), expected.keys().collect::<Vec<_>>());
            for (path, expected_token) in &expected {
                assert!(table.get(path).is_some_and(|token| token.same(expected_token)));
            }
            assert!(
                table
                    .values()
                    .zip(expected.values())
                    .all(|(left, right)| left.same(right))
            );
            // Taking is a constant structural move, not a second charged index build.
            let retained = processing.charged_payload_bytes();
            let moved = std::mem::take(&mut table);
            assert!(table.is_empty());
            assert_eq!(moved.len(), 512);
            assert_eq!(processing.charged_payload_bytes(), retained);
        }
        Ok(())
    }

    #[test]
    fn comparison_charges_only_the_segment_pairs_it_actually_visits() -> Result<(), Finding> {
        let processing = NativeOperationBudget::new(NativeProcessingLimits {
            max_processing_units: 4,
            ..NativeProcessingLimits::default()
        });
        let left = FieldPath(vec!["a".into(), "unvisited-private-tail".repeat(2048)]);
        let right = FieldPath(vec!["b".into(), "unvisited-private-tail".repeat(2048)]);
        assert_eq!(
            NativeOccurrences::compare_in(&left, &right, &processing, Phase::Analysis)?,
            std::cmp::Ordering::Less
        );
        assert!(!processing.exhausted());
        let exhausted = NativeOccurrences::compare_in(&left, &right, &processing, Phase::Analysis)
            .err()
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?;
        assert_eq!(exhausted.code, FindingCode::LimitExceeded);
        assert_eq!(exhausted.phase, Phase::Analysis);
        assert!(exhausted.path.is_none());
        Ok(())
    }

    #[test]
    fn failed_insert_is_atomic_and_uses_the_current_supplied_budget_and_phase() -> Result<(), Finding> {
        let original_budget = NativeOperationBudget::new(NativeProcessingLimits::default());
        let path = FieldPath::parse("/spec/retained/~0~1private")?;
        let token = NativeOccurrence::new_in(&original_budget, Phase::Decoding)?;
        let mut table = NativeOccurrences::new();
        table.insert_in(&path, &token, &original_budget, Phase::Decoding)?;
        let current = NativeOperationBudget::new(NativeProcessingLimits {
            max_processing_units: 0,
            ..NativeProcessingLimits::default()
        });
        let next = FieldPath::parse("/spec/new")?;
        let error = table
            .insert_in(&next, &token, &current, Phase::Analysis)
            .err()
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?;
        assert_eq!(error.code, FindingCode::LimitExceeded);
        assert_eq!(error.phase, Phase::Analysis);
        assert!(error.path.is_none());
        assert!(current.exhausted());
        assert!(!original_budget.exhausted());
        assert_eq!(table.len(), 1);
        assert!(table.get(&path).is_some_and(|saved| saved.same(&token)));
        assert!(table.get(&next).is_none());
        check_avl(&table, table.root);
        Ok(())
    }
}

/// Retained unknown nested syntax. It is not typed capability or serializable by default.
#[derive(Clone, Default)]
pub struct UnknownFields {
    pub(crate) entries: Vec<(String, OpaqueNode)>,
    pub(crate) occurrence: Option<NativeOccurrence>,
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
    #[cfg(test)]
    pub(crate) fn capture(node: &TreeNode, known: &[&str]) -> Self {
        Self::capture_entries(node, known, None)
    }
    pub(crate) fn capture_in(
        node: &TreeNode,
        known: &[&str],
        ctx: &crate::registry::FieldDecodeContext,
    ) -> Result<Self, Finding> {
        let occurrence = NativeOccurrence::new_in(&ctx.processing, ctx.phase)?;
        let mut entries = Vec::new();
        for (key, value) in node.as_mapping().unwrap_or(&[]) {
            let comparisons = key
                .len()
                .checked_add(1)
                .and_then(|units| units.checked_mul(known.len().saturating_add(1)))
                .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
            ctx.processing.work(comparisons, ctx.phase)?;
            if known.contains(&key.as_str()) {
                continue;
            }
            ctx.processing.payload_array::<(String, OpaqueNode)>(1, ctx.phase)?;
            ctx.processing.payload(key.len(), ctx.phase)?;
            ctx.processing.payload(2 * size_of::<usize>(), ctx.phase)?;
            ctx.processing.tree_copy(value, ctx.phase)?;
            entries.push((key.clone(), OpaqueNode(Arc::new(value.clone()))));
        }
        Ok(Self {
            occurrence: Some(occurrence),
            entries,
        })
    }
    #[cfg(test)]
    fn capture_entries(node: &TreeNode, known: &[&str], occurrence: Option<NativeOccurrence>) -> Self {
        Self {
            occurrence,
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
        self.snapshot_in(node).map_err(|mut finding| {
            // Private snapshots may contain payload-bearing keys. Diagnostics keep
            // their code/phase, but never expose a traversal path into those keys.
            finding.path = None;
            finding
        })
    }
    fn snapshot_in(&self, node: &TreeNode) -> Result<Vec<u8>, Finding> {
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
                // Validate grammar using the raw parser: numeric magnitude must not
                // be coerced through serde_json's finite floating-point Number.
                if !value
                    .as_bytes()
                    .first()
                    .is_some_and(|byte| matches!(byte, b'-' | b'0'..=b'9'))
                    || !serde_json::from_str::<&serde_json::value::RawValue>(value).is_ok_and(|raw| raw.get() == value)
                {
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

#[cfg(test)]
mod snapshot_privacy_tests {
    use super::*;
    use crate::source::AuthoringLimits;
    #[test]
    fn raw_numeric_grammar_preserves_magnitude_outside_float_and_typed_number_ranges() -> Result<(), String> {
        for spelling in ["1e400", "1e2147483648", "-9007199254740993"] {
            let tree = TreeNode::mapping(vec![(
                "unknown".into(),
                TreeNode::new(TreeValue::Number(spelling.into())),
            )]);
            let budget = EncodingBudget::new(AuthoringLimits::default());
            let bytes = budget.snapshot(&tree).map_err(|_| "valid raw number rejected")?;
            assert_eq!(bytes, format!("{{\"unknown\":{spelling}}}").as_bytes());
        }
        Ok(())
    }
    #[test]
    fn private_keys_never_escape_snapshot_verification_or_serialization_errors() -> Result<(), String> {
        const MARKER: &str = "PRIVATE-snapshot-key";
        let null = || TreeNode::new(TreeValue::Null);
        let tree = |value| TreeNode::mapping(vec![(MARKER.into(), value)]);
        let cases = [
            (
                TreeNode::mapping(vec![(MARKER.into(), null()), (MARKER.into(), null())]),
                AuthoringLimits::default(),
                FindingCode::DuplicateKey,
            ),
            (
                tree(null()),
                AuthoringLimits {
                    parser: ParseLimits {
                        max_scalar_bytes: 1,
                        ..ParseLimits::default()
                    },
                    ..AuthoringLimits::default()
                },
                FindingCode::LimitExceeded,
            ),
            (
                tree(null()),
                AuthoringLimits {
                    max_total_snapshot_bytes: 4,
                    ..AuthoringLimits::default()
                },
                FindingCode::LimitExceeded,
            ),
            (
                tree(TreeNode::new(TreeValue::Number("1e+".into()))),
                AuthoringLimits::default(),
                FindingCode::NativeFieldInvalid,
            ),
        ];
        for (tree, limits, expected) in cases {
            let budget = EncodingBudget::new(limits);
            let finding = budget.snapshot(&tree).err().ok_or("invalid snapshot succeeded")?;
            assert_eq!(finding.code, expected);
            assert!(finding.path.is_none());
            assert!(!format!("{finding:?}").contains(MARKER));
        }
        Ok(())
    }
}
