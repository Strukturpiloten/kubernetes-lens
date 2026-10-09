//! Structured findings that never include free-form source values.
use std::fmt;

/// Stable machine-readable finding categories.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum FindingCode {
    /// Invalid YAML/JSON syntax or native document shape.
    MalformedDocument,
    /// Duplicate decoded mapping key.
    DuplicateKey,
    /// A configured finite input budget was exceeded.
    LimitExceeded,
    /// An alias is missing, cyclic, or exceeds its expansion budget.
    InvalidAlias,
    /// Native object keys must be strings.
    InvalidMappingKey,
    /// YAML merge keys require explicit semantics and are not expanded.
    UnsupportedMergeKey,
    /// A scalar/tag cannot be represented without changing its meaning.
    UnsupportedScalar,
    /// Resource identity is incomplete or has invalid names.
    InvalidIdentity,
    /// Two supplied records represent the same object.
    DuplicateIdentity,
    /// Distinct supplied Pod/volume rules predict the same claim identity.
    ClaimIdentityCollision,
    /// A supplied reference resolves to more than one object.
    AmbiguousReference,
    /// A supplied reference has no target.
    MissingReference,
    /// A selector has no supplied matches.
    SelectorNoMatches,
    /// An explicitly declared dependency is external.
    ExternalPrerequisite,
    /// A dependency is controlled by another resource/operator.
    OperatorOwned,
    /// Scope/namespace cannot be established from explicit evidence.
    ScopeUnknown,
    /// Input scope contradicts supplied scope evidence.
    ScopeMismatch,
    /// A known kind has no delivered native codec.
    UnadmittedKind,
    /// An unknown kind is source-preserved, not understood.
    UnknownKind,
    /// A native field is invalid.
    NativeFieldInvalid,
    /// A reviewed native rule requires an explicit operation context.
    NativeContextRequired,
    /// The target API is not served in the selected profile.
    UnavailableApi,
    /// The target field is not available.
    UnavailableField,
    /// Typed admission cannot be established.
    UnadmittedField,
    /// A gate setting is unknown/disabled for the selected field.
    FeatureGateRequired,
    /// Target profiles must use the finite reviewed vocabulary/range.
    InvalidTargetProfile,
    /// API relabeling is not a semantic migration.
    UnsupportedSemanticConversion,
    /// Default output cannot expose protected payloads.
    ProtectedOutputDenied,
    /// An opaque preserved value requires explicit output permission.
    OpaqueOutputDenied,
    /// A structural replacement would discard unknown source evidence.
    MergeConflict,
    /// Server-owned fields were explicitly removed for authored output.
    ObservedFieldRemoved,
    /// Explicit flattening discarded retained List wrapper fields.
    CollectionFieldRemoved,
    /// Typed/encoded identity diverged from its registry contract.
    CodecIdentityMismatch,
    /// Registrations must be unique and valid.
    InvalidRegistration,
    /// Explicit acquisition failed or selected unsafe input.
    AcquisitionFailed,
    /// A selected input extension is outside the acquisition policy.
    UnsupportedInputExtension,
    /// A supplied reference cycle was found.
    ReferenceCycle,
}

impl FindingCode {
    /// Stable kebab-case code, safe for reports.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::MalformedDocument => "malformed-document",
            Self::DuplicateKey => "duplicate-key",
            Self::LimitExceeded => "limit-exceeded",
            Self::InvalidAlias => "invalid-alias",
            Self::InvalidMappingKey => "invalid-mapping-key",
            Self::UnsupportedMergeKey => "unsupported-merge-key",
            Self::UnsupportedScalar => "unsupported-scalar",
            Self::InvalidIdentity => "invalid-identity",
            Self::DuplicateIdentity => "duplicate-identity",
            Self::ClaimIdentityCollision => "claim-identity-collision",
            Self::AmbiguousReference => "ambiguous-reference",
            Self::MissingReference => "unresolved-reference",
            Self::SelectorNoMatches => "selector-no-matches",
            Self::ExternalPrerequisite => "external-prerequisite",
            Self::OperatorOwned => "operator-owned",
            Self::ScopeUnknown => "scope-unknown",
            Self::ScopeMismatch => "scope-mismatch",
            Self::UnadmittedKind => "unadmitted-kind",
            Self::UnknownKind => "unknown-kind",
            Self::NativeFieldInvalid => "native-field-invalid",
            Self::NativeContextRequired => "native-context-required",
            Self::UnavailableApi => "unavailable-api",
            Self::UnavailableField => "unavailable-field",
            Self::UnadmittedField => "unadmitted-field",
            Self::FeatureGateRequired => "feature-gate-required",
            Self::InvalidTargetProfile => "invalid-target-profile",
            Self::UnsupportedSemanticConversion => "unsupported-semantic-conversion",
            Self::ProtectedOutputDenied => "protected-output-denied",
            Self::OpaqueOutputDenied => "opaque-output-denied",
            Self::MergeConflict => "merge-conflict",
            Self::ObservedFieldRemoved => "observed-field-removed",
            Self::CollectionFieldRemoved => "collection-field-removed",
            Self::CodecIdentityMismatch => "codec-identity-mismatch",
            Self::InvalidRegistration => "invalid-registration",
            Self::AcquisitionFailed => "acquisition-failed",
            Self::UnsupportedInputExtension => "unsupported-input-extension",
            Self::ReferenceCycle => "reference-cycle",
        }
    }
}

/// Finding severity; warnings never imply typed/native support.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Severity {
    /// Output/processing must stop.
    Error,
    /// Retained evidence is incomplete or outside typed admission.
    Warning,
    /// An explicit transformation or observation was recorded.
    Information,
}

/// Processing boundary at which a finding was produced.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Explicit read-only acquisition.
    Acquisition,
    /// Syntax parsing.
    Parsing,
    /// Native document/codec decoding.
    Decoding,
    /// Supplied-set graph/reference analysis.
    Analysis,
    /// Explicit target validation.
    Validation,
    /// In-memory output generation.
    Generation,
}

/// A byte offset and one-based Unicode line/column in immutable source input.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct SourcePosition {
    /// UTF-8 byte offset from the beginning of the source.
    pub byte_offset: u64,
    /// One-based line.
    pub line: u32,
    /// One-based Unicode scalar column.
    pub column: u32,
}

/// Input-local resource ID; not a Kubernetes name or UID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ResourceId(pub u64);

/// A JSON-pointer-like edit/evidence path. Debug never prints its segments.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub struct FieldPath(pub(crate) Vec<String>);

impl FieldPath {
    /// Parse a JSON pointer without normalizing user keys.
    ///
    /// # Errors
    /// Rejects invalid escaping and non-pointer syntax with a fixed finding.
    pub fn parse(pointer: &str) -> Result<Self, Finding> {
        if pointer.is_empty() {
            return Ok(Self::default());
        }
        if !pointer.starts_with('/') {
            return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation));
        }
        let mut segments = Vec::new();
        for segment in pointer[1..].split('/') {
            let mut decoded = String::new();
            let mut chars = segment.chars();
            while let Some(ch) = chars.next() {
                if ch == '~' {
                    match chars.next() {
                        Some('0') => decoded.push('~'),
                        Some('1') => decoded.push('/'),
                        _ => return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)),
                    }
                } else {
                    decoded.push(ch);
                }
            }
            segments.push(decoded);
        }
        Ok(Self(segments))
    }

    pub(crate) fn child(&self, key: impl Into<String>) -> Self {
        let mut path = self.0.clone();
        path.push(key.into());
        Self(path)
    }

    /// Number of path segments, with no user-key disclosure.
    #[must_use]
    pub fn depth(&self) -> usize {
        self.0.len()
    }

    /// Reveal the exact path only under explicit source access.
    #[must_use]
    pub fn reveal(&self, _access: &crate::source::ExplicitSourceAccess) -> String {
        let mut pointer = String::new();
        for segment in &self.0 {
            pointer.push('/');
            for ch in segment.chars() {
                match ch {
                    '~' => pointer.push_str("~0"),
                    '/' => pointer.push_str("~1"),
                    _ => pointer.push(ch),
                }
            }
        }
        pointer
    }
}

impl fmt::Debug for FieldPath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("FieldPath")
            .field("depth", &self.0.len())
            .finish_non_exhaustive()
    }
}

/// Immutable wrapper coordinates, containing only safe input-local identifiers.
/// The source ID and document index distinguish equal-position inputs; the List ID
/// distinguishes nested wrappers in the same source document. List IDs are local
/// to one `ResourceSet` and must be interpreted together with these coordinates.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WrapperSubject {
    /// Exact supplied source and YAML/JSON document coordinates.
    pub source: crate::model::SourceRef,
    /// Input-local retained or attempted wrapper ID.
    pub list: crate::model::ListId,
}

/// A finding with fixed-code presentation and private free-form path data.
#[derive(Clone, Eq, PartialEq)]
pub struct Finding {
    /// Stable code.
    pub code: FindingCode,
    /// Whether processing/output must stop.
    pub severity: Severity,
    /// Processing phase.
    pub phase: Phase,
    /// Non-sensitive input-local resource identifier.
    pub resource: Option<ResourceId>,
    /// Retained/attempted List wrapper coordinates, independent of any resource ID.
    pub wrapper: Option<WrapperSubject>,
    /// Redacted by default, exact only under explicit source access.
    pub path: Option<FieldPath>,
    /// Position in original source, if available.
    pub source: Option<SourcePosition>,
}

impl Finding {
    /// Construct a blocking finding with no input text.
    #[must_use]
    pub const fn error(code: FindingCode, phase: Phase) -> Self {
        Self {
            code,
            severity: Severity::Error,
            phase,
            resource: None,
            wrapper: None,
            path: None,
            source: None,
        }
    }
    /// Construct a preserved/unsupported finding with no support claim.
    #[must_use]
    pub const fn warning(code: FindingCode, phase: Phase) -> Self {
        Self {
            code,
            severity: Severity::Warning,
            phase,
            resource: None,
            wrapper: None,
            path: None,
            source: None,
        }
    }
    /// Attach a private path.
    #[must_use]
    pub fn at_path(mut self, path: FieldPath) -> Self {
        self.path = Some(path);
        self
    }
    /// Attach original source position.
    #[must_use]
    pub const fn at_source(mut self, source: SourcePosition) -> Self {
        self.source = Some(source);
        self
    }
    /// Attach a non-sensitive resource ID.
    #[must_use]
    pub const fn for_resource(mut self, resource: ResourceId) -> Self {
        self.resource = Some(resource);
        self
    }
    /// Attach immutable wrapper/source coordinates without changing a resource subject.
    #[must_use]
    pub const fn for_wrapper(mut self, wrapper: WrapperSubject) -> Self {
        self.wrapper = Some(wrapper);
        self
    }
    /// Fixed actionable advice. It contains no parser message or input snippet.
    #[must_use]
    pub const fn remediation(&self) -> &'static str {
        match self.code {
            FindingCode::CollectionFieldRemoved => {
                "Preserve List wrappers to retain their metadata and unknown fields."
            }
            FindingCode::LimitExceeded => "Select smaller explicit inputs or increase the relevant finite budget.",
            FindingCode::ProtectedOutputDenied => {
                "Explicitly authorize private protected output before requesting the original payload."
            }
            FindingCode::OpaqueOutputDenied | FindingCode::UnadmittedKind | FindingCode::UnknownKind => {
                "Select explicit preservation output or supply a delivered native codec; preservation is not typed support."
            }
            FindingCode::UnavailableApi
            | FindingCode::UnavailableField
            | FindingCode::UnsupportedSemanticConversion => {
                "Select an available target or a separately reviewed semantic migration; do not relabel apiVersion."
            }
            FindingCode::FeatureGateRequired | FindingCode::InvalidTargetProfile => {
                "Select an explicit valid versioned feature-gate profile."
            }
            FindingCode::MissingReference
            | FindingCode::AmbiguousReference
            | FindingCode::SelectorNoMatches
            | FindingCode::ScopeUnknown => "Supply an unambiguous target and explicit namespace/scope evidence.",
            FindingCode::MergeConflict => {
                "Resolve unknown-data removal explicitly or edit only the intended leaf/keyed item."
            }
            FindingCode::AcquisitionFailed | FindingCode::UnsupportedInputExtension => {
                "Select bounded regular files/directories with admitted extensions and no symlink traversal."
            }
            _ => "Correct the named structural condition using the retained private source evidence.",
        }
    }
}

impl fmt::Debug for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Finding")
            .field("code", &self.code)
            .field("severity", &self.severity)
            .field("phase", &self.phase)
            .field("resource", &self.resource)
            .field("wrapper", &self.wrapper)
            .field("path", &self.path)
            .field("source", &self.source)
            .finish()
    }
}
impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}: {}", self.code.as_str(), self.remediation())
    }
}
impl std::error::Error for Finding {}

pub(crate) fn has_errors(findings: &[Finding]) -> bool {
    findings.iter().any(|finding| finding.severity == Severity::Error)
}
