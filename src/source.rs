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
/// Immutable evidence origin, distinct from a caller's input declaration.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum EvidenceOrigin {
    /// Caller-supplied source with its declared origin.
    Supplied(InputOrigin),
    /// Library-created canonical snapshot of explicitly supplied typed native values.
    NativeAuthored,
}
/// Finite cumulative native-authoring and parser construction limits.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AuthoringLimits {
    /// Per-snapshot syntax limits; node/event budgets also apply cumulatively to construction.
    pub parser: ParseLimits,
    /// Maximum supplied native values, independently of byte size.
    pub max_resources: usize,
    /// Maximum aggregate canonical snapshot bytes.
    pub max_total_snapshot_bytes: usize,
}
impl Default for AuthoringLimits {
    fn default() -> Self {
        let parser = ParseLimits::default();
        Self {
            max_resources: parser.max_documents,
            max_total_snapshot_bytes: parser.max_input_bytes,
            parser,
        }
    }
}
impl AuthoringLimits {
    pub(crate) fn valid(self) -> bool {
        self.parser.valid() && self.max_resources > 0 && self.max_total_snapshot_bytes > 0
    }
}
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ObservationRole {
    ServerOwned,
    SubresourceOnly,
}
#[derive(Clone, Debug)]
pub(crate) struct ObservationPath {
    pub(crate) path: FieldPath,
    pub(crate) role: ObservationRole,
}
pub(crate) fn append_metadata_observation_paths(base: &FieldPath, out: &mut Vec<ObservationPath>) {
    for key in [
        "uid",
        "resourceVersion",
        "managedFields",
        "creationTimestamp",
        "generation",
        "selfLink",
        "deletionTimestamp",
        "deletionGracePeriodSeconds",
    ] {
        out.push(ObservationPath {
            path: base.child(key),
            role: ObservationRole::ServerOwned,
        });
    }
}
pub(crate) fn root_observation_paths() -> Vec<ObservationPath> {
    let mut out = vec![ObservationPath {
        path: FieldPath(vec!["status".into()]),
        role: ObservationRole::ServerOwned,
    }];
    append_metadata_observation_paths(&FieldPath(vec!["metadata".into()]), &mut out);
    out
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
    /// Exact immutable evidence origin, never inferred from a target.
    pub origin: EvidenceOrigin,
    /// Caller-declared source version.
    pub source_version: Option<KubernetesVersion>,
    raw: Arc<[u8]>,
}
impl SourceEvidence {
    pub(crate) fn from_input(input: &SourceInput<'_>) -> Self {
        Self {
            id: input.id,
            format: input.format,
            origin: EvidenceOrigin::Supplied(input.origin),
            source_version: input.source_version,
            raw: Arc::from(input.bytes),
        }
    }
    pub(crate) fn native_authored(id: SourceId, raw: Vec<u8>) -> Self {
        Self {
            id,
            format: DocumentFormat::Json,
            origin: EvidenceOrigin::NativeAuthored,
            source_version: None,
            raw: Arc::from(raw),
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

// Authenticated finite OpenAPI observations; independent expectations/checksums live in
// tests/foundation/root-status-role-evidence.json. These roles confer no typed admission.
const ROOT_STATUS_ROLES: &[(&str, &str, &str, u8, u8)] = &[
    ("apiextensions.k8s.io", "v1beta1", "CustomResourceDefinition", 20, 21),
    ("apiextensions.k8s.io", "v1", "CustomResourceDefinition", 20, 37),
    ("apps", "v1", "DaemonSet", 20, 37),
    ("apps", "v1", "Deployment", 20, 37),
    ("apps", "v1", "ReplicaSet", 20, 37),
    ("apps", "v1", "StatefulSet", 20, 37),
    ("autoscaling", "v1", "HorizontalPodAutoscaler", 20, 37),
    ("autoscaling", "v2beta1", "HorizontalPodAutoscaler", 20, 24),
    ("autoscaling", "v2beta2", "HorizontalPodAutoscaler", 20, 25),
    ("autoscaling", "v2", "HorizontalPodAutoscaler", 23, 37),
    ("batch", "v1beta1", "CronJob", 20, 24),
    ("batch", "v1", "CronJob", 21, 37),
    ("batch", "v1", "Job", 20, 37),
    ("extensions", "v1beta1", "Ingress", 20, 21),
    ("networking.k8s.io", "v1beta1", "Ingress", 20, 21),
    ("networking.k8s.io", "v1", "Ingress", 20, 37),
    ("networking.k8s.io", "v1", "NetworkPolicy", 24, 27),
    ("policy", "v1beta1", "PodDisruptionBudget", 20, 24),
    ("policy", "v1", "PodDisruptionBudget", 21, 37),
    ("", "v1", "Namespace", 20, 37),
    ("", "v1", "PersistentVolume", 20, 37),
    ("", "v1", "PersistentVolumeClaim", 20, 37),
    ("", "v1", "Pod", 20, 37),
    ("", "v1", "ReplicationController", 20, 37),
    ("", "v1", "ResourceQuota", 20, 37),
    ("", "v1", "Service", 20, 37),
];
pub(crate) fn root_status_role(gvk: &crate::model::GroupVersionKind, version: Option<KubernetesVersion>) -> bool {
    if gvk.group.as_deref() == Some("") {
        return false;
    }
    let Some(api) = crate::capability::declaration(gvk) else {
        return false;
    };
    ROOT_STATUS_ROLES.iter().any(|(group, served, kind, first, last)| {
        gvk.group.as_deref().unwrap_or("") == *group
            && gvk.version == *served
            && gvk.kind == *kind
            && version.map_or(*first == api.first && *last == api.last, |version| {
                (api.first..=api.last).contains(&version.minor()) && (*first..=*last).contains(&version.minor())
            })
    })
}
pub(crate) fn list_observation_paths() -> Vec<ObservationPath> {
    ["resourceVersion", "selfLink", "continue", "remainingItemCount"]
        .into_iter()
        .map(|member| ObservationPath {
            path: FieldPath(vec!["metadata".into(), member.into()]),
            role: ObservationRole::ServerOwned,
        })
        .collect()
}

/// Core recheck of sealed descriptors against the finite native occurrence vocabulary.
pub(crate) fn retain_reviewed_observations(
    tree: &crate::syntax::TreeNode,
    gvk: &crate::model::GroupVersionKind,
    version: Option<KubernetesVersion>,
    observations: &mut Vec<ObservationPath>,
) {
    observations.retain(|observation| {
        if tree.get_path(&observation.path).is_none() {
            return false;
        }
        let path = &observation.path.0;
        let supported = crate::capability::declaration(gvk).is_some_and(|declaration| {
            version.is_none_or(|version| (declaration.first..=declaration.last).contains(&version.minor()))
        });
        if observation.role == ObservationRole::SubresourceOnly {
            return supported
                && gvk.group.is_none()
                && gvk.version == "v1"
                && gvk.kind == "Pod"
                && path == &["spec", "ephemeralContainers"]
                && version.is_some_and(|version| version.minor() >= 25);
        }
        if path == &["status"] {
            return root_status_role(gvk, version);
        }
        let server_member = path.last().is_some_and(|field| {
            matches!(
                field.as_str(),
                "uid"
                    | "resourceVersion"
                    | "managedFields"
                    | "creationTimestamp"
                    | "generation"
                    | "selfLink"
                    | "deletionTimestamp"
                    | "deletionGracePeriodSeconds"
            )
        });
        if path.len() == 2 && path[0] == "metadata" && server_member {
            return true;
        }
        if !supported {
            return false;
        }
        if gvk.group.as_deref() == Some("apps")
            && gvk.version == "v1"
            && gvk.kind == "StatefulSet"
            && path.len() >= 4
            && path[0] == "spec"
            && path[1] == "volumeClaimTemplates"
            && path[2].parse::<usize>().is_ok()
        {
            return path.len() == 4 && path[3] == "status" || path.len() == 5 && path[3] == "metadata" && server_member;
        }
        if !server_member || path.len() < 2 || path[path.len() - 2] != "metadata" {
            return false;
        }
        let metadata_base = &path[..path.len() - 2];
        let pod_spec = match (gvk.group.as_deref(), gvk.version.as_str(), gvk.kind.as_str()) {
            (None, "v1", "Pod") => vec!["spec"],
            (None, "v1", "ReplicationController")
            | (Some("apps"), "v1", "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet")
            | (Some("batch"), "v1", "Job") => {
                if metadata_base == ["spec", "template"] {
                    return true;
                }
                vec!["spec", "template", "spec"]
            }
            (Some("batch"), "v1" | "v1beta1", "CronJob") => {
                if metadata_base == ["spec", "jobTemplate"]
                    || metadata_base == ["spec", "jobTemplate", "spec", "template"]
                {
                    return true;
                }
                vec!["spec", "jobTemplate", "spec", "template", "spec"]
            }
            _ => return false,
        };
        metadata_base.len() == pod_spec.len() + 4
            && metadata_base
                .iter()
                .take(pod_spec.len())
                .map(String::as_str)
                .eq(pod_spec.iter().copied())
            && metadata_base[pod_spec.len()] == "volumes"
            && metadata_base[pod_spec.len() + 1].parse::<usize>().is_ok()
            && metadata_base[pod_spec.len() + 2] == "ephemeral"
            && metadata_base[pod_spec.len() + 3] == "volumeClaimTemplate"
    });
}

/// Refuse a descriptor wave before the sealed collector allocates its output.
pub(crate) fn check_observation_budget(
    tree: &crate::syntax::TreeNode,
    gvk: &crate::model::GroupVersionKind,
) -> Result<(), crate::diagnostic::Finding> {
    let mut descriptors = 9usize;
    let pod_spec = match (gvk.group.as_deref(), gvk.version.as_str(), gvk.kind.as_str()) {
        (None, "v1", "Pod") => FieldPath(vec!["spec".into()]),
        (None, "v1", "ReplicationController")
        | (Some("apps"), "v1", "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet")
        | (Some("batch"), "v1", "Job") => {
            descriptors += 8;
            FieldPath(vec!["spec".into(), "template".into(), "spec".into()])
        }
        (Some("batch"), "v1" | "v1beta1", "CronJob") => {
            descriptors += 16;
            FieldPath(vec![
                "spec".into(),
                "jobTemplate".into(),
                "spec".into(),
                "template".into(),
                "spec".into(),
            ])
        }
        _ => FieldPath::default(),
    };
    if gvk.group.as_deref() == Some("apps") && gvk.kind == "StatefulSet" {
        if let Some(items) = tree
            .get_path(&FieldPath(vec!["spec".into(), "volumeClaimTemplates".into()]))
            .and_then(crate::syntax::TreeNode::as_sequence)
        {
            descriptors = descriptors.saturating_add(items.len().saturating_mul(9));
        }
    }
    if !pod_spec.0.is_empty() {
        if let Some(volumes) = tree
            .get_path(&pod_spec.child("volumes"))
            .and_then(crate::syntax::TreeNode::as_sequence)
        {
            let claims = volumes
                .iter()
                .filter(|volume| {
                    volume
                        .get("ephemeral")
                        .and_then(|node| node.get("volumeClaimTemplate"))
                        .is_some()
                })
                .count();
            descriptors = descriptors.saturating_add(claims.saturating_mul(8));
        }
    }
    if gvk.group.is_none() && gvk.kind == "Pod" {
        descriptors = descriptors.saturating_add(1);
    }
    if descriptors > ParseLimits::default().max_nodes {
        return Err(crate::diagnostic::Finding::error(
            crate::diagnostic::FindingCode::LimitExceeded,
            crate::diagnostic::Phase::Analysis,
        ));
    }
    Ok(())
}
