//! Bounded strict syntax parsing with immutable, private source evidence.
use crate::{
    diagnostic::{Finding, FindingCode, Phase, SourcePosition},
    source::{DocumentFormat, ParseLimits, Positions, SourceEvidence, SourceInput},
    syntax::{NodeId, NodeValue, ScalarStyle, SyntaxDocument, SyntaxNode, TreeNode},
};
use serde::de::{Deserializer as _, MapAccess, SeqAccess, Visitor};
use serde_json::value::RawValue;
use std::{collections::BTreeMap, fmt, sync::Arc};
use yaml_rust2::{
    parser::{Event, MarkedEventReceiver, Parser},
    scanner::{Marker, TScalarStyle},
};

/// Parsed syntax and immutable source; native resources are materialized separately.
pub struct ParsedInput {
    pub(crate) documents: Vec<Arc<SyntaxDocument>>,
    pub(crate) trees: Vec<TreeNode>,
    pub(crate) evidence: Arc<SourceEvidence>,
    pub(crate) limits: ParseLimits,
    pub(crate) processing: crate::processing::NativeOperationBudget,
}
impl ParsedInput {
    /// Number of syntax documents, preserving YAML stream boundaries.
    #[must_use]
    pub fn document_count(&self) -> usize {
        self.documents.len()
    }
    /// Finite budgets applied to this input.
    #[must_use]
    pub const fn limits(&self) -> &ParseLimits {
        &self.limits
    }
    /// Private immutable input evidence.
    #[must_use]
    pub fn source(&self) -> &SourceEvidence {
        &self.evidence
    }
    /// Materialize native identities/List wrappers using the delivered registry.
    ///
    /// # Errors
    /// Refuses malformed resource/List identity and duplicate supplied identities.
    pub fn flatten_resources(self) -> Result<crate::model::ResourceSet, Vec<Finding>> {
        let processing = self.processing.clone();
        crate::model::ResourceSet::with_registry_in(vec![self], &crate::resources::registry()?, processing)
    }
}
impl fmt::Debug for ParsedInput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedInput")
            .field("source", &self.evidence)
            .field("document_count", &self.documents.len())
            .finish_non_exhaustive()
    }
}

/// Parse one explicit strict JSON value or bounded YAML document stream.
///
/// # Errors
/// Returns fixed structured findings for malformed syntax, duplicates, invalid keys/aliases,
/// unsupported scalar/merge semantics, or independent finite-budget exhaustion. Parser text is
/// never included in errors; original bytes remain with the caller or private successful evidence.
pub fn parse_source(input: SourceInput<'_>, limits: &ParseLimits) -> Result<ParsedInput, Vec<Finding>> {
    parse_source_in(
        input,
        limits,
        &crate::processing::NativeOperationBudget::new(limits.processing),
    )
}
pub(crate) fn parse_source_in(
    input: SourceInput<'_>,
    limits: &ParseLimits,
    processing: &crate::processing::NativeOperationBudget,
) -> Result<ParsedInput, Vec<Finding>> {
    let result = parse_in(input, limits, processing.clone());
    result.map_err(|mut findings| {
        processing.finish_report(&mut findings, Phase::Parsing);
        findings
    })
}
fn parse_in(
    input: SourceInput<'_>,
    limits: &ParseLimits,
    processing: crate::processing::NativeOperationBudget,
) -> Result<ParsedInput, Vec<Finding>> {
    processing.work(1, Phase::Parsing).map_err(|finding| vec![finding])?;
    processing
        .work(input.bytes.len(), Phase::Parsing)
        .map_err(|finding| vec![finding])?;
    if !limits.valid() || input.bytes.len() > limits.max_input_bytes {
        return Err(vec![limit()]);
    }
    let text = std::str::from_utf8(input.bytes).map_err(|_| vec![malformed()])?;
    let positions = Positions::new(text);
    let documents = match input.format {
        DocumentFormat::Json => vec![parse_json(text, &input, *limits, &positions).map_err(|finding| vec![finding])?],
        DocumentFormat::YamlStream => parse_yaml(text, &input, *limits, &positions).map_err(|finding| vec![finding])?,
    };
    if documents.is_empty() {
        return Err(vec![malformed()]);
    }
    let mut trees = Vec::with_capacity(documents.len());
    let mut alias_visits = 0;
    for document in &documents {
        trees.push(
            document
                .materialize(limits, &mut alias_visits)
                .map_err(|finding| vec![finding])?,
        );
    }
    Ok(ParsedInput {
        documents: documents.into_iter().map(Arc::new).collect(),
        trees,
        evidence: Arc::new(SourceEvidence::from_input_with_limits(&input, *limits)),
        limits: *limits,
        processing,
    })
}
fn malformed() -> Finding {
    Finding::error(FindingCode::MalformedDocument, Phase::Parsing)
}
fn limit() -> Finding {
    Finding::error(FindingCode::LimitExceeded, Phase::Parsing)
}

fn json_preflight(text: &str, limits: ParseLimits) -> Result<(), Finding> {
    let mut depth = 0usize;
    let mut string_start = None;
    let mut escaped = false;
    for (index, byte) in text.bytes().enumerate() {
        if let Some(start) = string_start {
            if index - start > limits.max_scalar_bytes.saturating_mul(6).saturating_add(2) {
                return Err(limit());
            }
            if escaped {
                escaped = false;
            } else if byte == b'\\' {
                escaped = true;
            } else if byte == b'"' {
                string_start = None;
            }
        } else {
            match byte {
                b'"' => string_start = Some(index),
                b'{' | b'[' => {
                    depth = depth.saturating_add(1);
                    if depth > limits.max_depth {
                        return Err(limit());
                    }
                }
                b'}' | b']' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
    }
    Ok(())
}
fn parse_json(
    text: &str,
    input: &SourceInput<'_>,
    limits: ParseLimits,
    positions: &Positions<'_>,
) -> Result<SyntaxDocument, Finding> {
    json_preflight(text, limits)?;
    let raw: &RawValue = serde_json::from_str(text)
        .map_err(|error| malformed().at_source(positions.at_line_column(error.line(), error.column())))?;
    let mut reader = JsonReader {
        text,
        positions,
        nodes: Vec::new(),
        limits,
        events: 0,
        error: None,
    };
    let root = reader
        .value(raw, 0)
        .map_err(|_| reader.error.clone().unwrap_or_else(malformed))?;
    Ok(SyntaxDocument {
        root,
        format: input.format,
        source: input.id,
        document_index: 0,
        nodes: reader.nodes,
    })
}
struct JsonReader<'a, 'p> {
    text: &'a str,
    positions: &'p Positions<'a>,
    nodes: Vec<SyntaxNode>,
    limits: ParseLimits,
    events: usize,
    error: Option<Finding>,
}
impl<'a> JsonReader<'a, '_> {
    fn fail(&mut self, finding: Finding) -> serde_json::Error {
        self.error.get_or_insert(finding);
        serde::de::Error::custom("native-input-rejected")
    }
    fn event(&mut self) -> Result<(), serde_json::Error> {
        self.events = self.events.saturating_add(1);
        if self.events > self.limits.max_events {
            return Err(self.fail(limit()));
        }
        Ok(())
    }
    fn push(&mut self, value: NodeValue, start: SourcePosition) -> Result<NodeId, serde_json::Error> {
        self.event()?;
        if self.nodes.len() >= self.limits.max_nodes {
            return Err(self.fail(limit().at_source(start)));
        }
        let id = self.nodes.len();
        self.nodes.push(SyntaxNode { value, start });
        Ok(id)
    }
    fn offset(&self, raw: &RawValue) -> usize {
        (raw.get().as_ptr() as usize).saturating_sub(self.text.as_ptr() as usize)
    }
    fn value(&mut self, raw: &'a RawValue, depth: usize) -> Result<NodeId, serde_json::Error> {
        let offset = self.offset(raw);
        let start = self.positions.at_byte(offset);
        if depth > self.limits.max_depth {
            return Err(self.fail(limit().at_source(start)));
        }
        let value = raw.get();
        match value.as_bytes().first() {
            Some(b'{') => {
                let id = self.push(NodeValue::Mapping(Vec::new()), start)?;
                let mut de = serde_json::Deserializer::from_str(value);
                let entries = de.deserialize_map(JsonMap {
                    reader: self,
                    raw,
                    depth,
                    cursor: 1,
                })?;
                self.event()?;
                self.nodes[id].value = NodeValue::Mapping(entries);
                Ok(id)
            }
            Some(b'[') => {
                let id = self.push(NodeValue::Sequence(Vec::new()), start)?;
                let mut de = serde_json::Deserializer::from_str(value);
                let items = de.deserialize_seq(JsonSequence { reader: self, depth })?;
                self.event()?;
                self.nodes[id].value = NodeValue::Sequence(items);
                Ok(id)
            }
            Some(b'"') => {
                let decoded: String = serde_json::from_str(value)?;
                if decoded.len() > self.limits.max_scalar_bytes {
                    return Err(self.fail(limit().at_source(start)));
                }
                self.push(NodeValue::String(decoded, ScalarStyle::DoubleQuoted), start)
            }
            _ => {
                if value.len() > self.limits.max_scalar_bytes {
                    return Err(self.fail(limit().at_source(start)));
                }
                let node = match value {
                    "null" => NodeValue::Null,
                    "true" => NodeValue::Bool(true),
                    "false" => NodeValue::Bool(false),
                    _ => NodeValue::Number(value.to_owned()),
                };
                self.push(node, start)
            }
        }
    }
}
struct JsonMap<'a, 'r, 'p> {
    reader: &'r mut JsonReader<'a, 'p>,
    raw: &'a RawValue,
    depth: usize,
    cursor: usize,
}
impl<'de> Visitor<'de> for JsonMap<'de, '_, '_> {
    type Value = Vec<(NodeId, NodeId)>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a native object")
    }
    fn visit_map<M: MapAccess<'de>>(mut self, mut map: M) -> Result<Self::Value, M::Error> {
        let mut names = std::collections::BTreeSet::new();
        let mut entries = Vec::new();
        while let Some(key) = map.next_key::<String>()? {
            let bytes = self.raw.get().as_bytes();
            while bytes
                .get(self.cursor)
                .is_some_and(|byte| byte.is_ascii_whitespace() || *byte == b',')
            {
                self.cursor += 1;
            }
            let position = self
                .reader
                .positions
                .at_byte(self.reader.offset(self.raw) + self.cursor);
            if key.len() > self.reader.limits.max_scalar_bytes {
                self.reader.error.get_or_insert(limit().at_source(position));
                return Err(serde::de::Error::custom("native-input-rejected"));
            }
            if !names.insert(key.clone()) {
                self.reader
                    .error
                    .get_or_insert(Finding::error(FindingCode::DuplicateKey, Phase::Parsing).at_source(position));
                return Err(serde::de::Error::custom("native-input-rejected"));
            }
            let key_id = self
                .reader
                .push(NodeValue::String(key, ScalarStyle::DoubleQuoted), position)
                .map_err(|_| serde::de::Error::custom("native-input-rejected"))?;
            let raw: &'de RawValue = map.next_value()?;
            self.cursor = self.reader.offset(raw).saturating_sub(self.reader.offset(self.raw)) + raw.get().len();
            let value_id = self
                .reader
                .value(raw, self.depth + 1)
                .map_err(|_| serde::de::Error::custom("native-input-rejected"))?;
            entries.push((key_id, value_id));
        }
        Ok(entries)
    }
}
struct JsonSequence<'a, 'r, 'p> {
    reader: &'r mut JsonReader<'a, 'p>,
    depth: usize,
}
impl<'de> Visitor<'de> for JsonSequence<'de, '_, '_> {
    type Value = Vec<NodeId>;
    fn expecting(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("a native sequence")
    }
    fn visit_seq<S: SeqAccess<'de>>(self, mut seq: S) -> Result<Self::Value, S::Error> {
        let mut values = Vec::new();
        while let Some(raw) = seq.next_element::<&'de RawValue>()? {
            values.push(
                self.reader
                    .value(raw, self.depth + 1)
                    .map_err(|_| serde::de::Error::custom("native-input-rejected"))?,
            );
        }
        Ok(values)
    }
}

struct Frame {
    id: NodeId,
    key: Option<NodeId>,
}
struct YamlReader<'a, 'p> {
    positions: &'p Positions<'a>,
    input: &'p SourceInput<'a>,
    limits: ParseLimits,
    documents: Vec<SyntaxDocument>,
    nodes: Vec<SyntaxNode>,
    frames: Vec<Frame>,
    anchors: BTreeMap<usize, NodeId>,
    root: Option<NodeId>,
    events: usize,
    node_count: usize,
    aliases: usize,
    error: Option<Finding>,
}
fn parse_yaml<'a>(
    text: &'a str,
    input: &SourceInput<'a>,
    limits: ParseLimits,
    positions: &Positions<'a>,
) -> Result<Vec<SyntaxDocument>, Finding> {
    let mut reader = YamlReader {
        positions,
        input,
        limits,
        documents: Vec::new(),
        nodes: Vec::new(),
        frames: Vec::new(),
        anchors: BTreeMap::new(),
        root: None,
        events: 0,
        node_count: 0,
        aliases: 0,
        error: None,
    };
    // Pull events iteratively: Parser::load recursively walks nested collections and cannot
    // abort a receiver. Stopping here bounds parser state growth and avoids its recursive loader.
    let mut parser = Parser::new_from_str(text);
    loop {
        let (event, marker) = parser.next_token().map_err(|error| {
            malformed().at_source(positions.at_yaml_marker(error.marker().line(), error.marker().col()))
        })?;
        let end = event == Event::StreamEnd;
        reader.on_event(event, marker);
        if let Some(error) = reader.error.take() {
            return Err(error);
        }
        if end {
            break;
        }
    }
    Ok(reader.documents)
}
impl YamlReader<'_, '_> {
    fn attach(&mut self, id: NodeId) {
        if let Some(frame) = self.frames.last_mut() {
            match &mut self.nodes[frame.id].value {
                NodeValue::Sequence(items) => items.push(id),
                NodeValue::Mapping(entries) => {
                    if let Some(key) = frame.key.take() {
                        entries.push((key, id));
                    } else {
                        frame.key = Some(id);
                    }
                }
                _ => self.error = Some(malformed()),
            }
        } else if self.root.replace(id).is_some() {
            self.error = Some(malformed());
        }
    }
    fn push(
        &mut self,
        value: NodeValue,
        position: SourcePosition,
        anchor: usize,
        tag: Option<String>,
    ) -> Option<NodeId> {
        self.node_count = self.node_count.saturating_add(1 + usize::from(tag.is_some()));
        if self.node_count > self.limits.max_nodes {
            self.error = Some(limit().at_source(position));
            return None;
        }
        let id = self.nodes.len();
        self.nodes.push(SyntaxNode { value, start: position });
        let attached = if let Some(tag) = tag {
            let tagged = self.nodes.len();
            self.nodes.push(SyntaxNode {
                value: NodeValue::Tagged(tag, id),
                start: position,
            });
            tagged
        } else {
            id
        };
        if anchor != 0 {
            self.anchors.insert(anchor, attached);
        }
        self.attach(attached);
        Some(id)
    }
}
impl MarkedEventReceiver for YamlReader<'_, '_> {
    fn on_event(&mut self, event: Event, marker: Marker) {
        if self.error.is_some() {
            return;
        }
        let position = self.positions.at_yaml_marker(marker.line(), marker.col());
        self.events = self.events.saturating_add(1);
        if self.events > self.limits.max_events {
            self.error = Some(limit().at_source(position));
            return;
        }
        let mapping = matches!(&event, Event::MappingStart(_, _));
        match event {
            Event::DocumentStart => {
                if self.documents.len() >= self.limits.max_documents {
                    self.error = Some(limit().at_source(position));
                    return;
                }
                self.nodes.clear();
                self.frames.clear();
                self.anchors.clear();
                self.root = None;
            }
            Event::DocumentEnd => {
                if !self.frames.is_empty() {
                    self.error = Some(malformed().at_source(position));
                    return;
                }
                let Some(root) = self.root.take() else {
                    self.error = Some(malformed().at_source(position));
                    return;
                };
                self.documents.push(SyntaxDocument {
                    root,
                    format: self.input.format,
                    source: self.input.id,
                    document_index: u32::try_from(self.documents.len()).unwrap_or(u32::MAX),
                    nodes: std::mem::take(&mut self.nodes),
                });
            }
            Event::MappingStart(anchor, tag) | Event::SequenceStart(anchor, tag) => {
                if self.frames.len() >= self.limits.max_depth {
                    self.error = Some(limit().at_source(position));
                    return;
                }
                let value = if mapping {
                    NodeValue::Mapping(Vec::new())
                } else {
                    NodeValue::Sequence(Vec::new())
                };
                let tag = tag.map(|tag| format!("{}{}", tag.handle, tag.suffix));
                if let Some(id) = self.push(value, position, anchor, tag) {
                    self.frames.push(Frame { id, key: None });
                }
            }
            Event::MappingEnd | Event::SequenceEnd => {
                let Some(frame) = self.frames.pop() else {
                    self.error = Some(malformed().at_source(position));
                    return;
                };
                if frame.key.is_some() {
                    self.error = Some(malformed().at_source(position));
                }
            }
            Event::Scalar(value, style, anchor, tag) => {
                if value.len() > self.limits.max_scalar_bytes {
                    self.error = Some(limit().at_source(position));
                    return;
                }
                let style = match style {
                    TScalarStyle::Plain => ScalarStyle::Plain,
                    TScalarStyle::SingleQuoted => ScalarStyle::SingleQuoted,
                    TScalarStyle::DoubleQuoted => ScalarStyle::DoubleQuoted,
                    TScalarStyle::Literal => ScalarStyle::Literal,
                    TScalarStyle::Folded => ScalarStyle::Folded,
                };
                let tag_text = tag.map(|tag| format!("{}{}", tag.handle, tag.suffix));
                match yaml_scalar(value, style, tag_text) {
                    Ok((value_node, tag)) => {
                        self.push(value_node, position, anchor, tag);
                    }
                    Err(finding) => {
                        self.error = Some(finding.at_source(position));
                    }
                }
            }
            Event::Alias(anchor) => {
                self.aliases = self.aliases.saturating_add(1);
                if self.aliases > self.limits.max_aliases {
                    self.error = Some(limit().at_source(position));
                    return;
                }
                let Some(target) = self.anchors.get(&anchor).copied() else {
                    self.error = Some(Finding::error(FindingCode::InvalidAlias, Phase::Parsing).at_source(position));
                    return;
                };
                self.push(NodeValue::Alias(target), position, 0, None);
            }
            Event::Nothing | Event::StreamStart | Event::StreamEnd => {}
        }
    }
}
fn is_json_number(value: &str) -> bool {
    if !value
        .as_bytes()
        .first()
        .is_some_and(|byte| byte.is_ascii_digit() || *byte == b'-')
    {
        return false;
    }
    serde_json::from_str::<&RawValue>(value)
        .is_ok_and(|raw| !matches!(raw.get().as_bytes().first(), Some(b'{' | b'[' | b'"')))
}

fn ambiguous_number(value: &str) -> bool {
    let candidate = value.trim_start_matches(['+', '-']);
    if matches!(candidate.to_ascii_lowercase().as_str(), ".inf" | ".nan") {
        return true;
    }
    if candidate
        .strip_prefix("0x")
        .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| b.is_ascii_hexdigit() || b == b'_'))
        || candidate
            .strip_prefix("0o")
            .is_some_and(|digits| !digits.is_empty() && digits.bytes().all(|b| (b'0'..=b'7').contains(&b) || b == b'_'))
    {
        return true;
    }
    let normalized = candidate.replace('_', "");
    if !normalized.is_empty() && normalized.bytes().all(|b| b.is_ascii_digit()) {
        return true;
    }
    let normalized = if normalized.starts_with('.') {
        format!("0{normalized}")
    } else {
        normalized
    };
    is_json_number(&normalized)
}

fn yaml_scalar(
    value: String,
    style: ScalarStyle,
    tag_text: Option<String>,
) -> Result<(NodeValue, Option<String>), Finding> {
    let string_tag = tag_text
        .as_deref()
        .is_some_and(|tag| matches!(tag, "!!str" | "tag:yaml.org,2002:str"));
    let value_node = if string_tag || style != ScalarStyle::Plain {
        NodeValue::String(value, style)
    } else {
        match value.as_str() {
            "null" | "Null" | "NULL" | "~" | "" => NodeValue::Null,
            "true" | "True" | "TRUE" => NodeValue::Bool(true),
            "false" | "False" | "FALSE" => NodeValue::Bool(false),
            _ if is_json_number(&value) => NodeValue::Number(value),
            _ => {
                if ambiguous_number(&value) {
                    return Err(Finding::error(FindingCode::UnsupportedScalar, Phase::Parsing));
                }
                NodeValue::String(value, style)
            }
        }
    };
    Ok((value_node, tag_text.filter(|_| !string_tag)))
}
