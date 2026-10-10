//! Immutable, bounded protected JSON values with a flat, acyclic native arena.
use super::ExactJsonNumber;
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    processing::NativeOperationBudget,
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    syntax::{TreeNode, TreeValue},
};
use std::{fmt, sync::Arc};

#[derive(Clone, Copy)]
struct Shape {
    nodes: usize,
    events: usize,
    depth: usize,
    bytes: usize,
    scalar: usize,
}
pub(crate) enum JsonNode {
    Null,
    Boolean(bool),
    Number(ExactJsonNumber),
    String(String),
    Array(Vec<usize>),
    Object(Vec<(String, usize)>),
}
struct Node {
    value: JsonNode,
    shape: Shape,
}
struct Arena {
    nodes: Vec<Node>,
    root: usize,
    limits: ParseLimits,
}
/// An opaque node handle belonging to exactly one JSON builder.
#[derive(Clone)]
pub struct JsonNodeId {
    identity: Arc<()>,
    index: usize,
}
impl fmt::Debug for JsonNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsonNodeId(<private>)")
    }
}
/// A bounded builder for immutable JSON, without a recursive caller-controlled node type.
/// Child handles must belong to this builder and precede their parent; cycles are impossible.
pub struct ProtectedJsonBuilder {
    nodes: Vec<Node>,
    identity: Arc<()>,
    fields: FieldDecodeContext,
}
impl fmt::Debug for ProtectedJsonBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedJsonBuilder(<private>)")
    }
}
fn bounded(mut limits: ParseLimits) -> ParseLimits {
    let defaults = ParseLimits::default();
    limits.max_input_bytes = limits.max_input_bytes.min(defaults.max_input_bytes);
    limits.max_nodes = limits.max_nodes.min(defaults.max_nodes);
    limits.max_events = limits.max_events.min(defaults.max_events);
    limits.max_scalar_bytes = limits.max_scalar_bytes.min(defaults.max_scalar_bytes);
    limits.processing = limits.processing.bounded();
    limits
}
fn invalid(phase: Phase) -> Finding {
    Finding::error(FindingCode::NativeFieldInvalid, phase)
}
impl ProtectedJsonBuilder {
    /// Start a fresh bounded authoring operation. Caller buffers are consumed, not cloned.
    /// # Errors
    /// Rejects invalid limits or an exhausted processing allowance.
    pub fn new(limits: &ParseLimits) -> Result<Self, Finding> {
        Self::in_operation(FieldDecodeContext::new(
            bounded(*limits),
            NativeOperationBudget::new(limits.processing),
            Phase::Decoding,
        ))
    }
    fn in_operation(mut fields: FieldDecodeContext) -> Result<Self, Finding> {
        fields.limits = bounded(fields.limits);
        fields.processing.work(1, fields.phase)?;
        if !fields.limits.valid() {
            return Err(fields.processing.fail(fields.phase));
        }
        fields
            .processing
            .payload(size_of::<Self>() + size_of::<Arc<()>>(), fields.phase)?;
        Ok(Self {
            nodes: Vec::new(),
            identity: Arc::new(()),
            fields,
        })
    }
    fn shape(&self, node: &JsonNode) -> Result<Shape, Finding> {
        let fields = &self.fields;
        let fail = || fields.processing.fail(fields.phase);
        let mut shape = Shape {
            nodes: 1,
            events: 1,
            depth: 0,
            bytes: 0,
            scalar: 0,
        };
        let include = |shape: &mut Shape, index: usize| -> Result<(), Finding> {
            fields.processing.work(1, fields.phase)?;
            let child = self.nodes.get(index).ok_or_else(|| invalid(fields.phase))?.shape;
            shape.nodes = shape.nodes.checked_add(child.nodes).ok_or_else(fail)?;
            shape.events = shape.events.checked_add(child.events).ok_or_else(fail)?;
            shape.bytes = shape.bytes.checked_add(child.bytes).ok_or_else(fail)?;
            shape.depth = shape.depth.max(child.depth.checked_add(1).ok_or_else(fail)?);
            shape.scalar = shape.scalar.max(child.scalar);
            Ok(())
        };
        match node {
            JsonNode::Null | JsonNode::Boolean(_) => {}
            JsonNode::Number(number) => {
                shape.bytes = number.native_lexeme().len();
                shape.scalar = shape.bytes;
            }
            JsonNode::String(value) => {
                shape.bytes = value.len();
                shape.scalar = value.len();
            }
            JsonNode::Array(items) => {
                for index in items {
                    include(&mut shape, *index)?;
                }
                shape.events = shape.events.checked_add(1).ok_or_else(fail)?;
            }
            JsonNode::Object(items) => {
                for (key, index) in items {
                    include(&mut shape, *index)?;
                    shape.bytes = shape.bytes.checked_add(key.len()).ok_or_else(fail)?;
                    shape.scalar = shape.scalar.max(key.len());
                }
                shape.events = shape
                    .events
                    .checked_add(items.len())
                    .and_then(|n| n.checked_add(1))
                    .ok_or_else(fail)?;
            }
        }
        check_shape(shape, fields)?;
        Ok(shape)
    }
    fn add(&mut self, value: JsonNode) -> Result<JsonNodeId, Finding> {
        self.fields.processing.work(1, self.fields.phase)?;
        if self.nodes.len() >= self.fields.limits.max_nodes {
            return Err(self.fields.processing.fail(self.fields.phase));
        }
        let shape = self.shape(&value)?;
        self.fields.processing.payload_array::<Node>(1, self.fields.phase)?;
        let index = self.nodes.len();
        self.nodes.push(Node { value, shape });
        Ok(JsonNodeId {
            identity: self.identity.clone(),
            index,
        })
    }
    fn index(&self, id: &JsonNodeId) -> Result<usize, Finding> {
        self.fields.processing.work(1, self.fields.phase)?;
        if !Arc::ptr_eq(&self.identity, &id.identity) || id.index >= self.nodes.len() {
            return Err(invalid(self.fields.phase));
        }
        Ok(id.index)
    }
    /// Add genuine JSON null; absence is a separate owning-field concept.
    /// # Errors
    /// Refuses cumulative construction or processing limits.
    pub fn null(&mut self) -> Result<JsonNodeId, Finding> {
        self.add(JsonNode::Null)
    }
    /// Add a JSON boolean without materializing defaults.
    /// # Errors
    /// Refuses cumulative construction or processing limits.
    pub fn boolean(&mut self, value: bool) -> Result<JsonNodeId, Finding> {
        self.add(JsonNode::Boolean(value))
    }
    /// Add an exact number. The original spelling remains private.
    /// # Errors
    /// Refuses scalar, shape or cumulative processing limits.
    pub fn number(&mut self, value: ExactJsonNumber) -> Result<JsonNodeId, Finding> {
        self.fields
            .processing
            .work(value.native_lexeme().len(), self.fields.phase)?;
        self.add(JsonNode::Number(value))
    }
    /// Consume one caller-owned JSON string without copying its payload.
    /// # Errors
    /// Refuses scalar, shape or cumulative processing limits.
    pub fn string(&mut self, value: String) -> Result<JsonNodeId, Finding> {
        self.fields.processing.work(value.len(), self.fields.phase)?;
        self.add(JsonNode::String(value))
    }
    /// Add an ordered array. Repeated children count as expanded occurrences.
    /// # Errors
    /// Rejects foreign handles and excessive depth, expansion or cumulative budgets.
    pub fn array(&mut self, children: Vec<JsonNodeId>) -> Result<JsonNodeId, Finding> {
        self.fields
            .processing
            .payload_array::<usize>(children.len(), self.fields.phase)?;
        let mut indexes = Vec::with_capacity(children.len());
        for child in children {
            indexes.push(self.index(&child)?);
        }
        self.add(JsonNode::Array(indexes))
    }
    /// Consume object entries, rejecting duplicate keys and ignoring insertion order in equality.
    /// # Errors
    /// Rejects foreign handles, duplicates, shape limits and cumulative budgets.
    pub fn object(&mut self, mut children: Vec<(String, JsonNodeId)>) -> Result<JsonNodeId, Finding> {
        let phase = self.fields.phase;
        let processing = &self.fields.processing;
        let mut max_key = 0usize;
        for (key, child) in &children {
            processing.work(key.len().checked_add(1).ok_or_else(|| processing.fail(phase))?, phase)?;
            if key.len() > self.fields.limits.max_scalar_bytes {
                return Err(processing.fail(phase));
            }
            self.index(child)?;
            max_key = max_key.max(key.len());
        }
        // Conservative comparator allowance before sorting any private keys.
        let levels =
            usize::try_from(usize::BITS - children.len().leading_zeros()).map_err(|_| processing.fail(phase))?;
        let comparisons = children
            .len()
            .checked_mul(levels.checked_add(1).ok_or_else(|| processing.fail(phase))?)
            .and_then(|n| n.checked_mul(max_key.checked_add(1)?))
            .and_then(|n| n.checked_mul(4))
            .ok_or_else(|| processing.fail(phase))?;
        processing.work(comparisons, phase)?;
        children.sort_unstable_by(|(left, _), (right, _)| left.cmp(right));
        for pair in children.windows(2) {
            processing.work(max_key.checked_add(1).ok_or_else(|| processing.fail(phase))?, phase)?;
            if pair[0].0 == pair[1].0 {
                return Err(invalid(phase));
            }
        }
        processing.payload_array::<(String, usize)>(children.len(), phase)?;
        let items = children.into_iter().map(|(key, child)| (key, child.index)).collect();
        self.add(JsonNode::Object(items))
    }
    /// Seal an immutable root. Unreachable builder nodes confer no source authority.
    /// # Errors
    /// Rejects a foreign root or exhausted cumulative operation.
    pub fn finish(self, root: &JsonNodeId) -> Result<ProtectedJsonValue, Finding> {
        let index = self.index(root)?;
        self.fields.processing.payload(size_of::<Arena>(), self.fields.phase)?;
        Ok(ProtectedJsonValue(Arc::new(Arena {
            nodes: self.nodes,
            root: index,
            limits: self.fields.limits,
        })))
    }
}
fn check_shape(shape: Shape, fields: &FieldDecodeContext) -> Result<(), Finding> {
    if shape.nodes > fields.limits.max_nodes
        || shape.events > fields.limits.max_events
        || shape.depth > fields.limits.max_depth
        || shape.bytes > fields.limits.max_input_bytes
        || shape.scalar > fields.limits.max_scalar_bytes
    {
        return Err(fields.processing.fail(fields.phase));
    }
    Ok(())
}
/// A protected immutable JSON value. Clone shares a flat arena; no recursive drop occurs.
/// Default Debug and failures expose neither private keys nor payloads.
#[derive(Clone)]
pub struct ProtectedJsonValue(Arc<Arena>);
impl fmt::Debug for ProtectedJsonValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ProtectedJsonValue(<private>)")
    }
}
impl PartialEq for ProtectedJsonValue {
    fn eq(&self, other: &Self) -> bool {
        fn equal(left: &Arena, a: usize, right: &Arena, b: usize) -> bool {
            match (&left.nodes[a].value, &right.nodes[b].value) {
                (JsonNode::Null, JsonNode::Null) => true,
                (JsonNode::Boolean(a), JsonNode::Boolean(b)) => a == b,
                (JsonNode::Number(a), JsonNode::Number(b)) => a == b,
                (JsonNode::String(a), JsonNode::String(b)) => a == b,
                (JsonNode::Array(a), JsonNode::Array(b)) => {
                    a.len() == b.len() && a.iter().zip(b).all(|(a, b)| equal(left, *a, right, *b))
                }
                (JsonNode::Object(a), JsonNode::Object(b)) => {
                    a.len() == b.len()
                        && a.iter()
                            .zip(b)
                            .all(|((ka, a), (kb, b))| ka == kb && equal(left, *a, right, *b))
                }
                _ => false,
            }
        }
        // Safe only because all construction seals depth <=128 and expanded occurrences.
        equal(&self.0, self.0.root, &other.0, other.0.root)
    }
}
impl Eq for ProtectedJsonValue {}
impl ProtectedJsonValue {
    /// Parse one strict JSON value. This creates a value, never supplied resource authority.
    /// # Errors
    /// Rejects duplicates, malformed syntax/numbers and finite cumulative limits privately.
    pub fn parse_json(bytes: &[u8], limits: &ParseLimits) -> Result<Self, Vec<Finding>> {
        let limits = bounded(*limits);
        let processing = NativeOperationBudget::new(limits.processing);
        let parsed = crate::parser::parse_source_in(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::Json,
                origin: InputOrigin::CallerSupplied,
                source_version: None,
                bytes,
            },
            &limits,
            &processing,
        )?;
        let Some(tree) = parsed.trees.first() else {
            return Err(vec![invalid(Phase::Decoding)]);
        };
        let fields = FieldDecodeContext::new(limits, processing.clone(), Phase::Decoding);
        Self::decode(tree, &fields, &FieldPath::default()).map_err(|finding| {
            let mut findings = vec![finding];
            processing.finish_report(&mut findings, fields.phase);
            findings
        })
    }
    /// Serialize private values only after explicit access authorization.
    /// # Errors
    /// Refuses lowered shape/output/processing limits without leaking nested keys.
    pub fn to_json(&self, _access: &ExplicitSourceAccess, limits: &ParseLimits) -> Result<Vec<u8>, Finding> {
        let processing = NativeOperationBudget::new(limits.processing.lowered_by(self.0.limits.processing));
        let ctx = EncodeContext::in_operation(None, bounded(*limits), processing);
        if !ctx.limits.valid() {
            return Err(ctx.budget.processing().fail(ctx.budget.phase()));
        }
        let tree = self.encode(&ctx, &FieldPath::default())?;
        ctx.budget.snapshot(&tree).map_err(private_error)
    }

    /// Count canonical JSON output bytes without serializing or allocating a snapshot.
    /// The caller's existing processing session is charged for every retained occurrence.
    pub(crate) fn retained_json_len_in(&self, ctx: &FieldDecodeContext) -> Result<usize, Finding> {
        fn string_len(value: &str, ctx: &FieldDecodeContext) -> Result<usize, Finding> {
            let mut len = 2usize;
            for byte in value.bytes() {
                ctx.processing.work(1, ctx.phase)?;
                let escaped = match byte {
                    b'"' | b'\\' | b'\x08' | b'\x0c' | b'\n' | b'\r' | b'\t' => 2,
                    0..=0x1f => 6,
                    _ => 1,
                };
                len = len.checked_add(escaped).ok_or_else(|| ctx.processing.fail(ctx.phase))?;
            }
            Ok(len)
        }

        fn count(
            value: &ProtectedJsonValue,
            index: usize,
            depth: usize,
            ctx: &FieldDecodeContext,
        ) -> Result<usize, Finding> {
            if depth > ctx.limits.max_depth {
                return Err(ctx.processing.fail(ctx.phase));
            }
            ctx.processing.work(1, ctx.phase)?;
            let node = value.node(index).ok_or_else(|| ctx.processing.fail(ctx.phase))?;
            match node {
                JsonNode::Null | JsonNode::Boolean(true) => Ok(4),
                JsonNode::Boolean(false) => Ok(5),
                JsonNode::Number(number) => {
                    let len = number.native_lexeme().len();
                    ctx.processing.work(len, ctx.phase)?;
                    Ok(len)
                }
                JsonNode::String(text) => string_len(text, ctx),
                JsonNode::Array(children) => {
                    let separators = children.len().saturating_sub(1);
                    let mut len = 2usize
                        .checked_add(separators)
                        .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
                    for child in children {
                        len = len
                            .checked_add(count(value, *child, depth + 1, ctx)?)
                            .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
                    }
                    Ok(len)
                }
                JsonNode::Object(entries) => {
                    let separators = entries.len().saturating_sub(1);
                    let mut len = 2usize
                        .checked_add(separators)
                        .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
                    for (key, child) in entries {
                        len = len
                            .checked_add(string_len(key, ctx)?)
                            .and_then(|len| len.checked_add(1))
                            .and_then(|len| len.checked_add(count(value, *child, depth + 1, ctx).ok()?))
                            .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
                    }
                    Ok(len)
                }
            }
        }

        let shape = self
            .0
            .nodes
            .get(self.root())
            .ok_or_else(|| ctx.processing.fail(ctx.phase))?
            .shape;
        if shape.nodes > ctx.limits.max_nodes
            || shape.events > ctx.limits.max_events
            || shape.depth > ctx.limits.max_depth
            || shape.bytes > ctx.limits.max_input_bytes
            || shape.scalar > ctx.limits.max_scalar_bytes
        {
            return Err(ctx.processing.fail(ctx.phase));
        }
        count(self, self.root(), 1, ctx)
    }
    /// Compare exact JSON values within retained and caller-lowered processing ceilings.
    /// # Errors
    /// Refuses exhausted cumulative comparison limits; no native-schema parity is implied.
    pub fn equivalent(&self, other: &Self, limits: &ParseLimits) -> Result<bool, Finding> {
        let ceiling = limits
            .processing
            .lowered_by(self.0.limits.processing)
            .lowered_by(other.0.limits.processing);
        let processing = NativeOperationBudget::new(ceiling);
        let fields = FieldDecodeContext::new(bounded(*limits), processing.clone(), Phase::Analysis);
        if !fields.limits.valid() {
            return Err(processing.fail(fields.phase));
        }
        for value in [self, other] {
            check_shape(value.0.nodes[value.root()].shape, &fields)?;
        }
        self.equivalent_in(other, &processing, Phase::Analysis)
    }
    pub(crate) fn root(&self) -> usize {
        self.0.root
    }
    pub(crate) fn node(&self, index: usize) -> Option<&JsonNode> {
        self.0.nodes.get(index).map(|node| &node.value)
    }
    pub(crate) fn equivalent_in(
        &self,
        other: &Self,
        processing: &NativeOperationBudget,
        phase: Phase,
    ) -> Result<bool, Finding> {
        processing.payload_array::<(usize, usize)>(1, phase)?;
        let mut pending = vec![(self.root(), other.root())];
        while let Some((a, b)) = pending.pop() {
            processing.work(1, phase)?;
            match (
                self.node(a).ok_or_else(|| invalid(phase))?,
                other.node(b).ok_or_else(|| invalid(phase))?,
            ) {
                (JsonNode::Null, JsonNode::Null) => {}
                (JsonNode::Boolean(a), JsonNode::Boolean(b)) if a == b => {}
                (JsonNode::Number(a), JsonNode::Number(b)) => {
                    if a.compare_in(b, processing, phase)? != std::cmp::Ordering::Equal {
                        return Ok(false);
                    }
                }
                (JsonNode::String(a), JsonNode::String(b)) => {
                    processing.work(
                        a.len().checked_add(b.len()).ok_or_else(|| processing.fail(phase))?,
                        phase,
                    )?;
                    if a != b {
                        return Ok(false);
                    }
                }
                (JsonNode::Array(a), JsonNode::Array(b)) if a.len() == b.len() => {
                    processing.payload_array::<(usize, usize)>(a.len(), phase)?;
                    processing.work(a.len(), phase)?;
                    pending.extend(a.iter().zip(b).map(|(a, b)| (*a, *b)));
                }
                (JsonNode::Object(a), JsonNode::Object(b)) if a.len() == b.len() => {
                    processing.payload_array::<(usize, usize)>(a.len(), phase)?;
                    for ((ka, a), (kb, b)) in a.iter().zip(b) {
                        processing.work(
                            ka.len()
                                .checked_add(kb.len())
                                .and_then(|n| n.checked_add(1))
                                .ok_or_else(|| processing.fail(phase))?,
                            phase,
                        )?;
                        if ka != kb {
                            return Ok(false);
                        }
                        pending.push((*a, *b));
                    }
                }
                _ => return Ok(false),
            }
        }
        Ok(true)
    }
}
fn private_error(mut finding: Finding) -> Finding {
    finding.path = None;
    finding
}

fn reserve_steps<T>(children: usize, fields: &FieldDecodeContext) -> Result<(), Finding> {
    let count = children
        .checked_add(1)
        .ok_or_else(|| fields.processing.fail(fields.phase))?;
    fields.processing.work(count, fields.phase)?;
    fields.processing.payload_array::<T>(count, fields.phase)
}

impl FieldCodec for ProtectedJsonValue {
    fn decode(tree: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        enum Step<'a> {
            Visit(&'a TreeNode),
            Finish(&'a TreeNode),
        }
        let mut builder = ProtectedJsonBuilder::in_operation(ctx.clone())?;
        ctx.processing.payload_array::<Step<'_>>(1, ctx.phase)?;
        let mut pending = vec![Step::Visit(tree)];
        let mut built: Vec<JsonNodeId> = Vec::new();
        while let Some(step) = pending.pop() {
            ctx.processing.work(1, ctx.phase)?;
            match step {
                Step::Visit(node) => match &node.value {
                    TreeValue::Mapping(items) => {
                        reserve_steps::<Step<'_>>(items.len(), ctx)?;
                        pending.push(Step::Finish(node));
                        pending.extend(items.iter().rev().map(|(_, node)| Step::Visit(node)));
                    }
                    TreeValue::Sequence(items) => {
                        reserve_steps::<Step<'_>>(items.len(), ctx)?;
                        pending.push(Step::Finish(node));
                        pending.extend(items.iter().rev().map(Step::Visit));
                    }
                    _ => {
                        let id = match &node.value {
                            TreeValue::Null => builder.null()?,
                            TreeValue::Bool(value) => builder.boolean(*value)?,
                            TreeValue::Number(value) => builder.number(ExactJsonNumber::parse_in(value, ctx)?)?,
                            TreeValue::String(value) => {
                                ctx.processing.payload(value.len(), ctx.phase)?;
                                builder.string(value.clone())?
                            }
                            _ => return Err(invalid(ctx.phase).at_path(path.clone())),
                        };
                        ctx.processing.payload_array::<JsonNodeId>(1, ctx.phase)?;
                        built.push(id);
                    }
                },
                Step::Finish(node) => {
                    let count = match &node.value {
                        TreeValue::Mapping(items) => items.len(),
                        TreeValue::Sequence(items) => items.len(),
                        _ => return Err(invalid(ctx.phase)),
                    };
                    let start = built.len().checked_sub(count).ok_or_else(|| invalid(ctx.phase))?;
                    ctx.processing.payload_array::<JsonNodeId>(count, ctx.phase)?;
                    let children = built.split_off(start);
                    let id = if let TreeValue::Mapping(items) = &node.value {
                        ctx.processing.payload_array::<(String, JsonNodeId)>(count, ctx.phase)?;
                        let mut entries = Vec::with_capacity(count);
                        for ((key, _), child) in items.iter().zip(children) {
                            ctx.processing.payload(key.len(), ctx.phase)?;
                            ctx.processing.work(key.len(), ctx.phase)?;
                            entries.push((key.clone(), child));
                        }
                        builder.object(entries)?
                    } else {
                        builder.array(children)?
                    };
                    ctx.processing.payload_array::<JsonNodeId>(1, ctx.phase)?;
                    built.push(id);
                }
            }
        }
        let root = built.pop().ok_or_else(|| invalid(ctx.phase))?;
        if !built.is_empty() {
            return Err(invalid(ctx.phase));
        }
        builder.finish(&root).map_err(|finding| {
            if finding.code == FindingCode::LimitExceeded {
                private_error(finding)
            } else {
                private_error(finding).at_path(path.clone())
            }
        })
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        enum Step {
            Visit(usize),
            Finish(usize),
        }
        let fields = ctx.fields(ctx.budget.phase());
        check_shape(self.0.nodes[self.0.root].shape, &fields)?;
        fields.processing.payload_array::<Step>(1, fields.phase)?;
        let mut pending = vec![Step::Visit(self.root())];
        let mut built = Vec::new();
        while let Some(step) = pending.pop() {
            fields.processing.work(1, fields.phase)?;
            match step {
                Step::Visit(index) => match &self.0.nodes[index].value {
                    JsonNode::Array(items) => {
                        reserve_steps::<Step>(items.len(), &fields)?;
                        pending.push(Step::Finish(index));
                        pending.extend(items.iter().rev().map(|index| Step::Visit(*index)));
                    }
                    JsonNode::Object(items) => {
                        reserve_steps::<Step>(items.len(), &fields)?;
                        pending.push(Step::Finish(index));
                        pending.extend(items.iter().rev().map(|(_, index)| Step::Visit(*index)));
                    }
                    value => {
                        let node = match value {
                            JsonNode::Null => ctx.null(path)?,
                            JsonNode::Boolean(value) => ctx.boolean(*value, path)?,
                            JsonNode::Number(value) => value.encode(ctx, path)?,
                            JsonNode::String(value) => ctx.string(value, path)?,
                            _ => return Err(invalid(fields.phase)),
                        };
                        fields.processing.payload_array::<TreeNode>(1, fields.phase)?;
                        built.push(node);
                    }
                },
                Step::Finish(index) => {
                    let count = match &self.0.nodes[index].value {
                        JsonNode::Array(items) => items.len(),
                        JsonNode::Object(items) => items.len(),
                        _ => return Err(invalid(fields.phase)),
                    };
                    let start = built.len().checked_sub(count).ok_or_else(|| invalid(fields.phase))?;
                    fields.processing.payload_array::<TreeNode>(count, fields.phase)?;
                    let children = built.split_off(start);
                    let node = if let JsonNode::Object(items) = &self.0.nodes[index].value {
                        fields
                            .processing
                            .payload_array::<(String, TreeNode)>(count, fields.phase)?;
                        let mut entries = Vec::with_capacity(count);
                        for ((key, _), child) in items.iter().zip(children) {
                            entries.push((ctx.key(key, path)?, child));
                        }
                        ctx.object(entries, path)?
                    } else {
                        ctx.sequence(children, path)?
                    };
                    fields.processing.payload_array::<TreeNode>(1, fields.phase)?;
                    built.push(node);
                }
            }
        }
        let root = built.pop().ok_or_else(|| invalid(fields.phase))?;
        if !built.is_empty() {
            return Err(invalid(fields.phase));
        }
        Ok(root)
    }
}

#[cfg(test)]
#[path = "protected_json_tests.rs"]
mod processing_tests;
