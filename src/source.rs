//! Explicit inputs, immutable private evidence, and finite parser budgets.
use crate::{
    capability::KubernetesVersion,
    diagnostic::{FieldPath, SourcePosition},
};
use std::{collections::BTreeMap, fmt, sync::Arc};

/// Input-local source identifier; never a filename or credential.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct SourceId(pub u64);
/// Supported explicit source formats.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DocumentFormat {
    /// YAML 1.2 document stream.
    YamlStream,
    /// One strict JSON value/resource/List.
    Json,
}
/// Caller-declared source origin, independent of field defaulting.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum InputOrigin {
    /// Caller-authored desired-state input.
    Authored,
    /// Caller-supplied cluster export; no live acquisition occurs.
    ClusterExport,
    /// Caller-supplied Helm renderer output.
    HelmRendered,
    /// Source origin was not otherwise established.
    CallerSupplied,
}
/// Caller-supplied byte input; no ambient discovery is performed.
#[derive(Clone, Copy)]
pub struct SourceInput<'a> {
    /// Input-local identifier.
    pub id: SourceId,
    /// Explicit format; no permissive sniffing/fallback.
    pub format: DocumentFormat,
    /// Caller-declared source origin.
    pub origin: InputOrigin,
    /// Optional caller-declared Kubernetes source version, never inferred from apiVersion.
    pub source_version: Option<KubernetesVersion>,
    /// Explicit source bytes; Debug never includes them.
    pub bytes: &'a [u8],
}
impl fmt::Debug for SourceInput<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceInput")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("origin", &self.origin)
            .field("source_version", &self.source_version)
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
/// Finite independent parser budgets, checked before allocation/dereferencing.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ParseLimits {
    /// Maximum original source bytes.
    pub max_input_bytes: usize,
    /// Maximum YAML documents or one JSON root.
    pub max_documents: usize,
    /// Maximum parser events (JSON syntax nodes/keys also consume events).
    pub max_events: usize,
    /// Maximum retained syntax nodes.
    pub max_nodes: usize,
    /// Maximum container/alias traversal depth; cannot exceed the foundation safety ceiling.
    pub max_depth: usize,
    /// Maximum decoded scalar or key byte length.
    pub max_scalar_bytes: usize,
    /// Maximum alias occurrences; zero explicitly forbids aliases.
    pub max_aliases: usize,
    /// Maximum total alias expansion visits; zero explicitly forbids expansion.
    pub max_alias_visits: usize,
}
impl Default for ParseLimits {
    fn default() -> Self {
        Self {
            max_input_bytes: 8 * 1024 * 1024,
            max_documents: 256,
            max_events: 1_000_000,
            max_nodes: 500_000,
            max_depth: 64,
            max_scalar_bytes: 1024 * 1024,
            max_aliases: 1024,
            max_alias_visits: 65_536,
        }
    }
}
impl ParseLimits {
    pub(crate) fn valid(self) -> bool {
        self.max_input_bytes > 0
            && self.max_documents > 0
            && self.max_events > 0
            && self.max_nodes > 0
            && (1..=128).contains(&self.max_depth)
            && self.max_scalar_bytes > 0
    }
}

/// Explicit opt-in token for private original source/native-value access.
#[derive(Clone, Copy, Debug)]
pub struct ExplicitSourceAccess(());
impl ExplicitSourceAccess {
    /// Deliberately authorize original source/native bytes; never invoked implicitly.
    #[must_use]
    pub const fn explicitly_allow_raw_source() -> Self {
        Self(())
    }
}
/// Immutable original input, shared by documents without copying source bodies.
#[derive(Clone)]
pub struct SourceEvidence {
    /// Input-local identifier.
    pub id: SourceId,
    /// Caller-selected format.
    pub format: DocumentFormat,
    /// Caller-declared source origin.
    pub origin: InputOrigin,
    /// Caller-declared source version.
    pub source_version: Option<KubernetesVersion>,
    raw: Arc<[u8]>,
}
impl SourceEvidence {
    pub(crate) fn from_input(input: &SourceInput<'_>) -> Self {
        Self {
            id: input.id,
            format: input.format,
            origin: input.origin,
            source_version: input.source_version,
            raw: Arc::from(input.bytes),
        }
    }
    /// Reveal immutable original bytes only after explicit authorization.
    #[must_use]
    pub fn reveal_raw(&self, _access: &ExplicitSourceAccess) -> &[u8] {
        &self.raw
    }
    /// Original source size, without byte disclosure.
    #[must_use]
    pub fn byte_len(&self) -> usize {
        self.raw.len()
    }
}
impl fmt::Debug for SourceEvidence {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SourceEvidence")
            .field("id", &self.id)
            .field("format", &self.format)
            .field("origin", &self.origin)
            .field("source_version", &self.source_version)
            .field("byte_len", &self.raw.len())
            .finish_non_exhaustive()
    }
}

/// An explicit origin rule, never an inferred cluster default.
#[derive(Clone, Eq, PartialEq)]
pub enum ValueOrigin {
    /// Explicit authored field.
    Authored,
    /// Explicit source observation, not desired-state defaulting.
    Observed,
    /// Explicitly applied versioned rule; absence alone never creates this variant.
    Defaulted {
        /// Stable reviewed rule identifier, private in Debug.
        rule: String,
        /// Version to which the rule applies.
        version: KubernetesVersion,
    },
    /// Caller-generated/edited value.
    Generated,
    /// Caller supplied input without established authorship/observation.
    CallerSupplied,
}
impl fmt::Debug for ValueOrigin {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Authored => "Authored",
            Self::Observed => "Observed",
            Self::Defaulted { .. } => "Defaulted(<private-rule>)",
            Self::Generated => "Generated",
            Self::CallerSupplied => "CallerSupplied",
        })
    }
}
/// Immutable per-field evidence; typed edits do not mutate original provenance.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FieldEvidence {
    /// Original input-local source ID.
    pub source: SourceId,
    /// Original source position, when present.
    pub position: Option<SourcePosition>,
    /// Explicit field-origin classification.
    pub origin: ValueOrigin,
}
/// Path-addressable private-key evidence sidecar.
#[derive(Clone, Default)]
pub struct FieldEvidenceMap(pub(crate) BTreeMap<FieldPath, FieldEvidence>);
impl FieldEvidenceMap {
    /// Borrow evidence for an explicitly selected path.
    #[must_use]
    pub fn get(&self, path: &FieldPath) -> Option<&FieldEvidence> {
        self.0.get(path)
    }
    /// Number of retained fields, without disclosing keys.
    #[must_use]
    pub fn len(&self) -> usize {
        self.0.len()
    }
    /// Whether there are no retained field records.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}
impl fmt::Debug for FieldEvidenceMap {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldEvidenceMap")
            .field("field_count", &self.0.len())
            .finish_non_exhaustive()
    }
}

pub(crate) struct Positions<'a> {
    text: &'a str,
    line_starts: Vec<usize>,
}
impl<'a> Positions<'a> {
    pub(crate) fn new(text: &'a str) -> Self {
        let mut line_starts = vec![0];
        for (offset, byte) in text.bytes().enumerate() {
            if byte == b'\n' {
                line_starts.push(offset + 1);
            }
        }
        Self { text, line_starts }
    }
    pub(crate) fn at_byte(&self, offset: usize) -> SourcePosition {
        let offset = offset.min(self.text.len());
        let line = self
            .line_starts
            .partition_point(|start| *start <= offset)
            .saturating_sub(1);
        let line_start = self.line_starts.get(line).copied().unwrap_or(0);
        let column = self
            .text
            .get(line_start..offset)
            .map_or(0, |slice| slice.chars().count());
        SourcePosition {
            byte_offset: u64::try_from(offset).unwrap_or(u64::MAX),
            line: u32::try_from(line + 1).unwrap_or(u32::MAX),
            column: u32::try_from(column + 1).unwrap_or(u32::MAX),
        }
    }
    pub(crate) fn at_yaml_marker(&self, line: usize, column: usize) -> SourcePosition {
        let start = self
            .line_starts
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(self.text.len());
        let rest = &self.text[start..];
        let offset = rest
            .char_indices()
            .nth(column)
            .map_or(self.text.len(), |(offset, _)| start + offset);
        self.at_byte(offset)
    }
    pub(crate) fn at_line_column(&self, line: usize, byte_column: usize) -> SourcePosition {
        let start = self
            .line_starts
            .get(line.saturating_sub(1))
            .copied()
            .unwrap_or(self.text.len());
        let mut offset = start.saturating_add(byte_column.saturating_sub(1)).min(self.text.len());
        while offset > start && !self.text.is_char_boundary(offset) {
            offset -= 1;
        }
        self.at_byte(offset)
    }
}
