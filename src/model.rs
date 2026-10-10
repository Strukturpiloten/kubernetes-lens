//! Native identities, shared metadata, immutable evidence, and retained collection wrappers.
use crate::{
    capability::KindCapability,
    diagnostic::{FieldPath, Finding, FindingCode, Phase, ResourceId, WrapperSubject},
    parser::ParsedInput,
    registry::{self, DecodeContext, NativeResource, RegistryBuilder},
    source::{EvidenceOrigin, FieldEvidence, FieldEvidenceMap, InputOrigin, SourceEvidence, SourceId, ValueOrigin},
    syntax::{SyntaxDocument, TreeNode, TreeValue, UnknownFields},
    value::Presence,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
    sync::Arc,
};
/// Exact source GVK, including served version. Debug never discloses free-form strings.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct GroupVersionKind {
    /// `None` means the core API group.
    pub group: Option<String>,
    /// Exact served version.
    pub version: String,
    /// Exact kind.
    pub kind: String,
}
impl GroupVersionKind {
    /// Parse one exact native API spelling and kind.
    /// # Errors
    /// Refuses empty/invalid components rather than normalizing them.
    pub fn new(api_version: &str, kind: &str) -> Result<Self, Finding> {
        let (group, version) = if let Some((group, version)) = api_version.split_once('/') {
            (Some(group.to_owned()), version)
        } else {
            (None, api_version)
        };
        if group
            .as_deref()
            .is_some_and(|group| !crate::value::dns_subdomain(group))
            || version.is_empty()
            || !version.bytes().all(|c| c.is_ascii_alphanumeric())
            || kind.is_empty()
            || !kind.bytes().all(|c| c.is_ascii_alphanumeric())
        {
            return Err(invalid());
        }
        Ok(Self {
            group,
            version: version.to_owned(),
            kind: kind.to_owned(),
        })
    }
    /// Exact API spelling for caller-selected identity work.
    #[must_use]
    pub fn api_version(&self) -> String {
        self.group
            .as_ref()
            .map_or_else(|| self.version.clone(), |g| format!("{g}/{}", self.version))
    }
}
impl fmt::Debug for GroupVersionKind {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("GroupVersionKind(<private>)")
    }
}
/// Scope established only by native declarations or supplied CRDs.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum ResourceScope {
    /// Namespace-scoped built-in.
    Namespaced,
    /// Cluster-scoped built-in.
    Cluster,
    /// Scope established by a supplied CRD, retaining its namespaced bit.
    CrdResolved {
        /// Supplied CRD declares namespaced scope.
        namespaced: bool,
    },
    /// No supplied scope evidence.
    Unknown,
}
impl ResourceScope {
    /// Known namespace requirement, without defaulting authored namespace.
    #[must_use]
    pub const fn namespaced(self) -> Option<bool> {
        match self {
            Self::Namespaced => Some(true),
            Self::Cluster => Some(false),
            Self::CrdResolved { namespaced } => Some(namespaced),
            Self::Unknown => None,
        }
    }
}
/// Effective native identity; all presence values stay distinct.
#[derive(Clone, Eq, PartialEq)]
pub struct ResourceIdentity {
    /// Exact current served GVK.
    pub gvk: GroupVersionKind,
    /// Native/supplied scope.
    pub scope: ResourceScope,
    /// Authored namespace; caller context is stored separately.
    pub namespace: Presence<String>,
    /// Authored name, if present.
    pub name: Presence<String>,
    /// Authored generated-name prefix, if present.
    pub generate_name: Presence<String>,
}
impl fmt::Debug for ResourceIdentity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceIdentity")
            .field("gvk", &self.gvk)
            .field("scope", &self.scope)
            .field("namespace", &self.namespace)
            .field("name", &self.name)
            .field("generate_name", &self.generate_name)
            .finish()
    }
}
/// Duplicate lookup deliberately excludes served API version.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct CollisionKey {
    /// Exact group.
    pub group: Option<String>,
    /// Exact kind.
    pub kind: String,
    /// Known scope.
    pub scope: ResourceScope,
    /// Authored namespace for namespaced objects; cluster keys use `Absent`.
    pub namespace: Presence<String>,
    /// Exact explicit object name.
    pub name: String,
}
impl fmt::Debug for CollisionKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("CollisionKey(<private>)")
    }
}
impl ResourceIdentity {
    /// Derive a resolvable identity, ignoring served version. No namespace is invented.
    #[must_use]
    pub fn collision_key(&self) -> Option<CollisionKey> {
        let name = self.name.value()?.clone();
        let namespaced = self.scope.namespaced()?;
        if namespaced && !matches!(self.namespace, Presence::Value(_)) {
            return None;
        }
        Some(CollisionKey {
            group: self.gvk.group.clone(),
            kind: self.gvk.kind.clone(),
            scope: self.scope,
            namespace: if namespaced {
                self.namespace.clone()
            } else {
                Presence::Absent
            },
            name,
        })
    }
}
/// Shared native owner evidence; arbitrary strings remain private in Debug.
#[derive(Clone)]
pub struct OwnerReference {
    /// Exact owner API.
    pub api_version: String,
    /// Exact owner kind.
    pub kind: String,
    /// Explicit owner name.
    pub name: String,
    /// Explicit UID evidence.
    pub uid: Presence<String>,
    /// Explicit controller flag.
    pub controller: Presence<bool>,
    /// Explicit deletion-block flag.
    pub block_owner_deletion: Presence<bool>,
    /// Unadmitted descendants.
    pub unknown: UnknownFields,
}
impl fmt::Debug for OwnerReference {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("OwnerReference(<private>)")
    }
}
/// Shared editable native metadata. Evidence remains outside this live value.
#[derive(Clone, Default)]
pub struct Metadata {
    /// Explicit name.
    pub name: Presence<String>,
    /// Explicit generated prefix.
    pub generate_name: Presence<String>,
    /// Explicit namespace.
    pub namespace: Presence<String>,
    /// Exact label map.
    pub labels: Presence<BTreeMap<String, String>>,
    /// Exact annotation map.
    pub annotations: Presence<BTreeMap<String, String>>,
    /// Explicit native finalizer names; never inferred or stripped as observations.
    pub finalizers: Presence<Vec<String>>,
    /// Exported UID evidence.
    pub uid: Presence<String>,
    /// Exported version evidence.
    pub resource_version: Presence<String>,
    /// Explicit owner records.
    pub owner_references: Presence<Vec<OwnerReference>>,
    /// All remaining metadata, retained privately.
    pub unknown: UnknownFields,
}
impl fmt::Debug for Metadata {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Metadata(<private>)")
    }
}
/// Input-local collection ID.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub struct ListId(pub u64);
/// Source document coordinates, never an ambient path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SourceRef {
    /// Source ID.
    pub source: SourceId,
    /// Zero-based YAML document index.
    pub document_index: u32,
}
/// Nested wrapper/item coordinates, retaining wrapper order.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CollectionPath {
    /// Ordered enclosing List IDs and item indices.
    pub items: Vec<(ListId, usize)>,
}
/// Original List metadata and order are private, immutable evidence.
/// ```compile_fail
/// fn replace_id(list: &mut kubernetes_lens::model::ListDocument) {
///     list.id = kubernetes_lens::model::ListId(0);
/// }
/// ```
/// ```compile_fail
/// fn replace_source(list: &mut kubernetes_lens::model::ListDocument) {
///     list.source.source = kubernetes_lens::source::SourceId(0);
/// }
/// ```
/// ```compile_fail
/// fn replace_items(list: &mut kubernetes_lens::model::ListDocument) {
///     list.item_ids.clear();
/// }
/// ```
pub struct ListDocument {
    /// Input-local List ID.
    pub(crate) id: ListId,
    /// Source coordinates.
    pub(crate) source: SourceRef,
    /// Ordered contained resource IDs, including nested wrappers.
    pub(crate) item_ids: Vec<ResourceId>,
    pub(crate) original: TreeNode,
    pub(crate) syntax: Arc<SyntaxDocument>,
    pub(crate) collection: Option<CollectionPath>,
}
impl ListDocument {
    /// Stable input-local wrapper ID.
    #[must_use]
    pub const fn id(&self) -> ListId {
        self.id
    }
    /// Original source coordinates.
    #[must_use]
    pub const fn source(&self) -> SourceRef {
        self.source
    }
    /// Original contained resource IDs, including nested Lists, in source order.
    #[must_use]
    pub fn item_ids(&self) -> &[ResourceId] {
        &self.item_ids
    }
    /// Original enclosing wrapper coordinates.
    #[must_use]
    pub const fn collection(&self) -> Option<&CollectionPath> {
        self.collection.as_ref()
    }
}
impl fmt::Debug for ListDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ListDocument")
            .field("id", &self.id)
            .field("source", &self.source)
            .field("item_count", &self.item_ids.len())
            .field("syntax", &self.syntax)
            .finish_non_exhaustive()
    }
}
#[derive(Clone)]
pub(crate) enum FieldEdit {
    Set { path: FieldPath, value: TreeNode },
    Remove { path: FieldPath },
}
/// Retained original native document and optional delivered typed value.
/// Provenance cannot be overwritten, even through `ResourceSet::documents_mut`.
/// ```compile_fail
/// fn replace_id(doc: &mut kubernetes_lens::model::ResourceDocument) {
///     doc.id = kubernetes_lens::ResourceId(0);
/// }
/// ```
/// ```compile_fail
/// fn replace_source(doc: &mut kubernetes_lens::model::ResourceDocument) {
///     doc.source.source = kubernetes_lens::source::SourceId(0);
/// }
/// ```
/// ```compile_fail
/// fn detach_wrapper(doc: &mut kubernetes_lens::model::ResourceDocument) {
///     doc.collection = None;
/// }
/// ```
pub struct ResourceDocument {
    /// Stable input-local ID.
    pub(crate) id: ResourceId,
    /// Immutable source coordinates.
    pub(crate) source: SourceRef,
    /// Enclosing wrappers, preserving order.
    pub(crate) collection: Option<CollectionPath>,
    pub(crate) original_identity: ResourceIdentity,
    pub(crate) original: TreeNode,
    pub(crate) syntax: Arc<SyntaxDocument>,
    pub(crate) evidence: Arc<SourceEvidence>,
    pub(crate) field_evidence: FieldEvidenceMap,
    pub(crate) original_known: Option<TreeNode>,
    /// Sealed anchors captured with `original_known`; callers cannot replace this table.
    pub(crate) original_occurrences: crate::syntax::NativeOccurrences,
    pub(crate) resource: Option<Box<dyn NativeResource>>,
    pub(crate) decode: Option<registry::DecodeFn>,
    pub(crate) capability: Option<KindCapability>,
    pub(crate) edits: Vec<FieldEdit>,
    pub(crate) edit_processing_limits: crate::processing::NativeProcessingLimits,
}
impl fmt::Debug for ResourceDocument {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceDocument")
            .field("id", &self.id)
            .field("source", &self.source)
            .field("typed", &self.resource.is_some())
            .field("syntax", &self.syntax)
            .finish_non_exhaustive()
    }
}
impl ResourceDocument {
    /// Stable input-local ID; caller edits cannot change provenance.
    #[must_use]
    pub const fn id(&self) -> ResourceId {
        self.id
    }
    /// Immutable original source coordinates.
    #[must_use]
    pub const fn source(&self) -> SourceRef {
        self.source
    }
    /// Immutable enclosing wrapper coordinates and order.
    #[must_use]
    pub const fn collection(&self) -> Option<&CollectionPath> {
        self.collection.as_ref()
    }

    /// Current effective identity, recomputed from the live encoded value and explicit edits.
    /// # Errors
    /// Invalid edits or codec GVK/scope divergence are rejected.
    pub fn identity(&self) -> Result<ResourceIdentity, Finding> {
        let tree = self.current_tree(None)?;
        identity(&tree, self.original_identity.scope)
    }
    /// Original immutable identity, retained independently from edits.
    #[must_use]
    pub const fn original_identity(&self) -> &ResourceIdentity {
        &self.original_identity
    }
    /// Borrow a delivered native value without blanket Serialize/Debug requirements.
    #[must_use]
    pub fn resource<T: 'static>(&self) -> Option<&T> {
        self.resource.as_ref()?.as_any().downcast_ref()
    }
    /// Edit a delivered native value. Derived identity/graph views are never cached.
    #[must_use]
    pub fn resource_mut<T: 'static>(&mut self) -> Option<&mut T> {
        self.resource.as_mut()?.as_any_mut().downcast_mut()
    }
    /// Immutable field provenance; typed mutations do not rewrite it.
    #[must_use]
    pub const fn field_evidence(&self) -> &FieldEvidenceMap {
        &self.field_evidence
    }
    /// Immutable private original source.
    #[must_use]
    pub fn source_evidence(&self) -> &SourceEvidence {
        &self.evidence
    }
    /// Explicitly set a null distinct from omission.
    pub fn set_null(&mut self, path: FieldPath) {
        self.edits.push(FieldEdit::Set {
            path,
            value: TreeNode::new(TreeValue::Null),
        });
    }
    /// Explicitly remove a field.
    pub fn remove_field(&mut self, path: FieldPath) {
        self.edits.push(FieldEdit::Remove { path });
    }
    /// Set one field from explicitly parsed bounded syntax, retaining its native value.
    /// # Errors
    /// Requires exactly one syntax document.
    pub fn set_field_from_source(&mut self, path: FieldPath, value: ParsedInput) -> Result<(), Finding> {
        if value.trees.len() != 1 {
            return Err(invalid());
        }
        self.edit_processing_limits = self.edit_processing_limits.lowered_by(value.limits.processing);
        let Some(value) = value.trees.into_iter().next() else {
            return Err(invalid());
        };
        self.edits.push(FieldEdit::Set { path, value });
        Ok(())
    }
    #[cfg(test)]
    pub(crate) fn project(
        &self,
        target: Option<&crate::capability::TargetProfile>,
    ) -> Result<EffectiveProjection, Vec<Finding>> {
        self.project_in(target, None)
    }
    pub(crate) fn project_in(
        &self,
        target: Option<&crate::capability::TargetProfile>,
        ctx: Option<&registry::EncodeContext<'_>>,
    ) -> Result<EffectiveProjection, Vec<Finding>> {
        let standalone;
        let ctx = if let Some(ctx) = ctx {
            ctx
        } else {
            standalone = registry::EncodeContext::in_operation(
                target,
                *self.evidence.limits(),
                crate::processing::NativeOperationBudget::new(
                    self.evidence
                        .limits()
                        .processing
                        .lowered_by(self.edit_processing_limits),
                ),
            );
            &standalone
        };
        let ctx = ctx.for_source(*self.evidence.limits());
        let (tree, occurrences) = self
            .current_tree_with_occurrences_in(target, Some(&ctx), true)
            .map_err(|finding| vec![finding.for_resource(self.id)])?;
        let identity = identity_in(
            &tree,
            self.original_identity.scope,
            ctx.budget.processing(),
            ctx.budget.phase(),
        )
        .map_err(|finding| vec![finding.for_resource(self.id)])?;
        let (resource, findings) = match self
            .decode
            .map(|decode| {
                decode(
                    &tree,
                    &self.evidence,
                    &DecodeContext {
                        gvk: &identity.gvk,
                        scope: identity.scope,
                        fields: ctx.fields(Phase::Decoding),
                    },
                )
            })
            .transpose()
        {
            Ok(resource) => (resource, Vec::new()),
            Err(findings) => (
                None,
                findings
                    .into_iter()
                    .map(|finding| {
                        let mut finding = finding.for_resource(self.id);
                        if self.evidence.origin == EvidenceOrigin::NativeAuthored {
                            finding.source = None;
                        }
                        finding
                    })
                    .collect::<Vec<_>>(),
            ),
        };
        crate::source::check_observation_budget(&tree, &identity.gvk)
            .map_err(|finding| vec![finding.for_resource(self.id)])?;
        let mut observations = crate::source::root_observation_paths();
        if let Some(resource) = &resource {
            resource.collect_observation_paths(&tree, &mut observations);
        }
        crate::source::retain_reviewed_observations(
            &tree,
            &identity.gvk,
            self.evidence
                .source_version
                .or_else(|| target.map(|target| target.kubernetes)),
            &mut observations,
        );
        Ok(EffectiveProjection {
            tree,
            occurrences,
            identity,
            resource,
            observations,
            findings,
            comparisons: std::cell::RefCell::new(BTreeMap::new()),
        })
    }
    pub(crate) fn effective_evidence(
        &self,
        projection: &EffectiveProjection,
        path: &FieldPath,
        mut charge: impl FnMut(&TreeNode, &TreeNode) -> bool,
    ) -> Option<FieldEvidence> {
        let tree = &projection.tree;
        let mut comparisons = projection.comparisons.borrow_mut();
        let mut equal = |path: &FieldPath, before: &TreeNode, after: &TreeNode| -> Option<bool> {
            if let Some(result) = comparisons.get(path) {
                return Some(*result);
            }
            if !charge(before, after) {
                return None;
            }
            let result = before.semantic_eq(after);
            comparisons.insert(path.clone(), result);
            Some(result)
        };
        let generated = FieldEvidence {
            source: self.evidence.id,
            position: None,
            origin: ValueOrigin::Generated,
        };
        if self.evidence.origin == EvidenceOrigin::NativeAuthored {
            return Some(generated);
        }
        for length in 0..path.0.len() {
            let prefix = FieldPath(path.0[..length].to_vec());
            if let (Some(before), Some(after)) = (self.original.get_path(&prefix), tree.get_path(&prefix)) {
                if matches!(before.value, TreeValue::Sequence(_)) && !equal(&prefix, before, after)? {
                    return Some(generated);
                }
            }
        }
        match (self.original.get_path(path), tree.get_path(path)) {
            (Some(before), Some(after)) if equal(path, before, after)? => {
                Some(self.field_evidence.0.get(path).cloned().unwrap_or(generated))
            }
            _ => Some(generated),
        }
    }
    pub(crate) fn current_tree(&self, target: Option<&crate::capability::TargetProfile>) -> Result<TreeNode, Finding> {
        self.current_tree_in(target, None)
    }
    pub(crate) fn current_tree_in(
        &self,
        target: Option<&crate::capability::TargetProfile>,
        ctx: Option<&registry::EncodeContext<'_>>,
    ) -> Result<TreeNode, Finding> {
        self.current_tree_with_occurrences_in(target, ctx, false)
            .map(|(tree, _)| tree)
    }
    fn current_tree_with_occurrences_in(
        &self,
        target: Option<&crate::capability::TargetProfile>,
        ctx: Option<&registry::EncodeContext<'_>>,
        observe: bool,
    ) -> Result<(TreeNode, crate::syntax::NativeOccurrences), Finding> {
        let standalone;
        let ctx = if let Some(ctx) = ctx {
            ctx
        } else {
            standalone = registry::EncodeContext::in_operation(
                target,
                *self.evidence.limits(),
                crate::processing::NativeOperationBudget::new(
                    self.evidence
                        .limits()
                        .processing
                        .lowered_by(self.edit_processing_limits),
                ),
            );
            &standalone
        };
        let observed;
        let ctx = if observe && self.resource.is_some() {
            observed = ctx.observed()?;
            &observed
        } else {
            ctx
        };
        let processing = ctx.budget.processing();
        let phase = ctx.budget.phase();
        let merge_context = crate::generation::BudgetedMergeContext {
            native: crate::generation::MergeContext {
                gvk: Some(&self.original_identity.gvk),
                target,
            },
            processing,
            phase,
        };
        let mut tree = if let (Some(resource), Some(original_known)) = (&self.resource, &self.original_known) {
            let known = registry::encode_in(resource.as_ref(), ctx)?;
            let encoded_identity = identity_in(&known, self.original_identity.scope, processing, phase)?;
            if encoded_identity.gvk != self.original_identity.gvk {
                return Err(Finding::error(FindingCode::CodecIdentityMismatch, Phase::Generation));
            }
            crate::generation::merge_native_delta_in(
                &self.original,
                original_known,
                &known,
                &FieldPath::default(),
                self.capability.as_ref().map_or(&[], |c| c.fields),
                &self.edits,
                merge_context,
            )?
        } else {
            processing.tree_copy(&self.original, phase)?;
            self.original.clone()
        };
        for edit in &self.edits {
            crate::generation::apply_edit_in(&mut tree, edit, processing, phase)?;
        }
        if self.original_identity.gvk.group.as_deref() == Some("apiextensions.k8s.io")
            && self.original_identity.gvk.kind == "CustomResourceDefinition"
        {
            for pointer in [
                "/spec/group",
                "/spec/names/kind",
                "/spec/scope",
                "/spec/versions",
                "/spec/version",
            ] {
                let path = FieldPath::parse(pointer)?;
                let before = self.original.get_path(&path);
                let after = tree.get_path(&path);
                if match (before, after) {
                    (Some(before), Some(after)) => !crate::generation::merge_semantic_eq(before, after, merge_context)?,
                    (None, None) => false,
                    _ => true,
                } {
                    return Err(
                        Finding::error(FindingCode::UnsupportedSemanticConversion, Phase::Generation).at_path(path),
                    );
                }
            }
        }
        let current = identity_in(&tree, self.original_identity.scope, processing, phase)?;
        if current.gvk != self.original_identity.gvk {
            return Err(Finding::error(
                FindingCode::UnsupportedSemanticConversion,
                Phase::Generation,
            ));
        }
        Ok((tree, ctx.take_occurrences()))
    }
}
/// Ordered supplied resources, retained wrappers, and immutable private sources.
pub struct ResourceSet {
    pub(crate) documents: Vec<ResourceDocument>,
    pub(crate) lists: Vec<ListDocument>,
    pub(crate) sources: Vec<Arc<SourceEvidence>>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) processing: crate::processing::NativeOperationBudget,
}
impl fmt::Debug for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceSet")
            .field("resource_count", &self.documents.len())
            .field("list_count", &self.lists.len())
            .field("sources", &self.sources)
            .field("findings", &self.findings)
            .field("processing", &self.processing.limits())
            .finish()
    }
}
impl ResourceSet {
    /// Build bounded canonical evidence from delivered typed native values and an explicit target.
    /// No namespace, API version, name or native default is inferred.
    /// # Errors
    /// Refuses invalid targets, construction budgets, malformed native identity and validation errors.
    pub fn from_authored(
        values: Vec<AuthoredResource>,
        target: &crate::capability::TargetProfile,
        limits: &crate::source::AuthoringLimits,
    ) -> Result<Self, Vec<Finding>> {
        Self::authored_with_registry(values, target, limits, &crate::resources::registry()?)
    }
    pub(crate) fn authored_with_registry(
        values: Vec<AuthoredResource>,
        target: &crate::capability::TargetProfile,
        limits: &crate::source::AuthoringLimits,
        registry: &RegistryBuilder,
    ) -> Result<Self, Vec<Finding>> {
        let processing = crate::processing::NativeOperationBudget::new(limits.parser.processing);
        let mut target_findings = target.findings();
        processing.finish_report(&mut target_findings, Phase::Generation);
        if crate::diagnostic::has_errors(&target_findings) {
            return Err(target_findings);
        }
        if !limits.valid() || values.len() > limits.max_resources || values.len() > limits.parser.max_documents {
            return Err(vec![Finding::error(FindingCode::LimitExceeded, Phase::Generation)]);
        }
        let budget = crate::syntax::EncodingBudget::in_operation(*limits, processing.clone());
        let ctx = registry::EncodeContext {
            target: Some(target),
            include_unknown: true,
            authoring_snapshot: true,
            occurrences: None,
            budget: budget.clone(),
            limits: limits.parser,
        };
        // Check collection length before reserving its storage.
        let mut inputs = Vec::with_capacity(values.len());
        for (index, value) in values.into_iter().enumerate() {
            let mut builder = crate::syntax::SyntaxBuilder::new();
            value
                .0
                .encode_known(&ctx, &mut builder)
                .map_err(|finding| vec![positionless(finding)])?;
            let tree = builder.finish().map_err(|finding| vec![positionless(finding)])?;
            let bytes = budget.snapshot(&tree).map_err(|finding| vec![positionless(finding)])?;
            let id = SourceId(
                u64::try_from(index)
                    .map_err(|_| vec![Finding::error(FindingCode::LimitExceeded, Phase::Generation)])?,
            );
            let mut parsed = crate::parser::parse_source_in(
                crate::source::SourceInput {
                    id,
                    format: crate::source::DocumentFormat::Json,
                    origin: InputOrigin::Authored,
                    source_version: None,
                    bytes: &bytes,
                },
                &limits.parser,
                &processing,
            )
            .map_err(|findings| findings.into_iter().map(positionless).collect::<Vec<_>>())?;
            parsed.evidence = Arc::new(SourceEvidence::native_authored_with_limits(id, bytes, limits.parser));
            for tree in &mut parsed.trees {
                clear_positions(tree);
            }
            inputs.push(parsed);
        }
        let mut set = Self::with_registry_in(inputs, registry, processing.clone())
            .map_err(|findings| findings.into_iter().map(positionless).collect::<Vec<_>>())?;
        let findings = crate::generation::validate_in(
            &set,
            target,
            crate::generation::NativeValidationIntent::Unspecified,
            processing,
        )
        .into_iter()
        .map(|finding| {
            let mut finding = positionless(finding);
            if finding.code == FindingCode::UnadmittedField {
                finding.severity = crate::diagnostic::Severity::Warning;
            }
            finding
        })
        .collect::<Vec<_>>();
        if crate::diagnostic::has_errors(&findings) {
            return Err(findings);
        }
        set.findings.extend(findings);
        Ok(set)
    }
    /// Materialize explicit parsed inputs, retaining unadmitted resources and every wrapper.
    /// # Errors
    /// Rejects malformed identities/Lists, conflicting scope evidence, and duplicate objects.
    pub fn from_inputs(inputs: Vec<ParsedInput>) -> Result<Self, Vec<Finding>> {
        Self::with_registry(inputs, &crate::resources::registry()?)
    }
    pub(crate) fn with_registry(inputs: Vec<ParsedInput>, registry: &RegistryBuilder) -> Result<Self, Vec<Finding>> {
        let limits = inputs
            .iter()
            .fold(crate::processing::NativeProcessingLimits::default(), |limits, input| {
                limits.lowered_by(input.limits.processing)
            });
        Self::with_registry_in(inputs, registry, crate::processing::NativeOperationBudget::new(limits))
    }
    pub(crate) fn with_registry_in(
        inputs: Vec<ParsedInput>,
        registry: &RegistryBuilder,
        processing: crate::processing::NativeOperationBudget,
    ) -> Result<Self, Vec<Finding>> {
        let mut set = Self {
            documents: Vec::new(),
            lists: Vec::new(),
            sources: Vec::new(),
            findings: Vec::new(),
            processing,
        };
        let mut ids = BTreeSet::new();
        for input in inputs {
            if let Err(finding) = set
                .processing
                .work(1, Phase::Decoding)
                .and_then(|()| set.processing.payload_array::<SourceId>(1, Phase::Decoding))
            {
                return Err(set.construction_failure(finding));
            }
            if !ids.insert(input.evidence.id) {
                return Err(set.construction_failure(Finding::error(FindingCode::DuplicateIdentity, Phase::Decoding)));
            }
            for (document, tree) in input.documents.iter().zip(input.trees) {
                let source = SourceRef {
                    source: input.evidence.id,
                    document_index: document.document_index,
                };
                if let Err(finding) =
                    set.add_node(tree, source, None, input.evidence.clone(), document.clone(), registry)
                {
                    return Err(set.construction_failure(finding));
                }
            }
            if let Err(finding) = set.processing.payload_array::<Arc<SourceEvidence>>(1, Phase::Decoding) {
                return Err(set.construction_failure(finding));
            }
            set.sources.push(input.evidence);
        }
        if let Err(finding) = set.resolve_crd_scopes() {
            return Err(set.construction_failure(finding));
        }
        let mut report = crate::processing::ProcessingReport::from_report(
            std::mem::take(&mut set.findings),
            set.processing.clone(),
            Phase::Decoding,
        );
        set.identity_findings_into(true, None, &mut report);
        let findings = report.into_vec();
        if crate::diagnostic::has_errors(&findings) {
            return Err(findings);
        }
        set.findings = findings;
        Ok(set)
    }
    /// Ordered retained native documents.
    #[must_use]
    pub fn documents(&self) -> &[ResourceDocument] {
        &self.documents
    }
    /// Edit documents; every derived view is subsequently recomputed.
    #[must_use]
    pub fn documents_mut(&mut self) -> &mut [ResourceDocument] {
        &mut self.documents
    }
    /// Ordered retained collection wrappers.
    #[must_use]
    pub fn lists(&self) -> &[ListDocument] {
        &self.lists
    }
    /// Preservation/admission findings, never a claim of native compatibility.
    #[must_use]
    pub fn findings(&self) -> &[Finding] {
        &self.findings
    }
    /// Immutable input sources.
    #[must_use]
    pub fn sources(&self) -> &[Arc<SourceEvidence>] {
        &self.sources
    }
    pub(crate) fn operation(
        &self,
        lower: Option<crate::processing::NativeProcessingLimits>,
    ) -> crate::processing::NativeOperationBudget {
        let limits = self.sources.iter().fold(self.processing.limits(), |limits, source| {
            limits.lowered_by(source.limits().processing)
        });
        let limits = self.documents.iter().fold(limits, |limits, document| {
            limits.lowered_by(document.edit_processing_limits)
        });
        crate::processing::NativeOperationBudget::new(lower.map_or(limits, |lower| limits.lowered_by(lower)))
    }
    pub(crate) fn encoding<'a>(
        &self,
        target: Option<&'a crate::capability::TargetProfile>,
        processing: crate::processing::NativeOperationBudget,
    ) -> registry::EncodeContext<'a> {
        let mut limits = crate::source::ParseLimits::default();
        limits.processing = self.processing.limits().lowered_by(processing.limits());
        // Native shape limits remain independently source-relative at each decode.
        registry::EncodeContext::in_operation(target, limits, processing)
    }
    /// Recheck effective identities after edits; served versions are excluded from collisions.
    #[must_use]
    pub fn identity_findings(&self) -> Vec<Finding> {
        let context = self.encoding(None, self.operation(None));
        let mut report = crate::processing::ProcessingReport::new(context.budget.processing().clone(), Phase::Analysis);
        self.identity_findings_into(false, Some(&context), &mut report);
        report.into_vec()
    }
    pub(crate) fn identity_findings_into(
        &self,
        original: bool,
        context: Option<&registry::EncodeContext<'_>>,
        out: &mut crate::processing::ProcessingReport,
    ) {
        let processing = out.processing().clone();
        let mut seen = BTreeMap::new();
        let mut list_ids = BTreeSet::new();
        for list in &self.lists {
            if out.failed() {
                break;
            }
            if let Err(finding) = processing
                .work(1, Phase::Analysis)
                .and_then(|()| processing.payload_array::<ListId>(1, Phase::Analysis))
            {
                out.push(finding);
                break;
            }
            if !list_ids.insert(list.id) {
                let mut finding =
                    Finding::error(FindingCode::InvalidIdentity, Phase::Analysis).for_wrapper(WrapperSubject {
                        source: list.source,
                        list: list.id,
                    });
                finding.source = list.original.start;
                out.push(finding);
            }
        }
        let mut ids = BTreeSet::new();
        for document in &self.documents {
            if out.failed() {
                break;
            }
            if let Err(finding) = processing
                .work(1, Phase::Analysis)
                .and_then(|()| processing.payload_array::<ResourceId>(1, Phase::Analysis))
            {
                out.push(finding);
                break;
            }
            if !ids.insert(document.id) {
                out.push(Finding::error(FindingCode::InvalidIdentity, Phase::Analysis).for_resource(document.id));
            }
            match if original {
                charge_identity_copy(&document.original_identity, &processing, Phase::Analysis)
                    .map(|()| document.original_identity.clone())
            } else {
                document
                    .current_tree_in(None, context)
                    .and_then(|tree| identity(&tree, document.original_identity.scope))
            } {
                Ok(identity) => {
                    if let Err(finding) = charge_identity_copy(&identity, &processing, Phase::Analysis) {
                        out.push(finding.for_resource(document.id));
                        break;
                    }
                    if let Some(key) = identity.collision_key() {
                        if let Some(previous) = seen.insert(key, document.id) {
                            out.push(
                                Finding::error(FindingCode::DuplicateIdentity, Phase::Analysis).for_resource(previous),
                            );
                            out.push(
                                Finding::error(FindingCode::DuplicateIdentity, Phase::Analysis)
                                    .for_resource(document.id),
                            );
                        }
                    }
                }
                Err(finding) => out.push(finding.for_resource(document.id)),
            }
        }
    }
    fn construction_failure(&mut self, finding: Finding) -> Vec<Finding> {
        let mut report = crate::processing::ProcessingReport::from_report(
            std::mem::take(&mut self.findings),
            self.processing.clone(),
            Phase::Decoding,
        );
        report.push(finding);
        report.into_vec()
    }
    fn add_node(
        &mut self,
        tree: TreeNode,
        source: SourceRef,
        collection: Option<CollectionPath>,
        evidence: Arc<SourceEvidence>,
        syntax: Arc<SyntaxDocument>,
        registry: &RegistryBuilder,
    ) -> Result<Vec<ResourceId>, Finding> {
        self.processing.work(1, Phase::Decoding)?;
        charge_gvk(&tree, &self.processing, Phase::Decoding)?;
        let gvk = tree_gvk(&tree)?;
        let typed_list = registry.lists.get(&gvk);
        if gvk.group.is_none() && gvk.version == "v1" && gvk.kind == "List" || typed_list.is_some() {
            return self.add_list(&tree, source, collection.as_ref(), &evidence, &syntax, registry);
        }
        if tree.as_mapping().is_none() {
            return Err(invalid());
        }
        let scope = crate::capability::builtin_scope(&gvk).unwrap_or(ResourceScope::Unknown);
        charge_identity(&tree, &self.processing, Phase::Decoding)?;
        let original_identity = identity(&tree, scope)?;
        let id = ResourceId(u64::try_from(self.documents.len()).map_err(|_| invalid())?);
        let (resource, original_known, original_occurrences, capability) =
            if let Some(entry) = registry.entries.get(&gvk) {
                if entry.gvk != gvk || entry.scope != scope {
                    return Err(Finding::error(FindingCode::InvalidRegistration, Phase::Decoding));
                }
                let resource = (entry.decode)(
                    &tree,
                    &evidence,
                    &DecodeContext {
                        gvk: &gvk,
                        scope,
                        fields: registry::FieldDecodeContext::new(
                            *evidence.limits(),
                            self.processing.clone(),
                            Phase::Decoding,
                        ),
                    },
                )
                .map_err(|findings| {
                    findings
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding))
                        .for_resource(id)
                })?;
                let ctx = registry::EncodeContext::in_operation(None, *evidence.limits(), self.processing.clone())
                    .observed()?;
                let known = registry::encode_in(resource.as_ref(), &ctx)?;
                charge_identity(&known, &self.processing, Phase::Decoding)?;
                if identity(&known, scope)? != original_identity {
                    return Err(Finding::error(FindingCode::CodecIdentityMismatch, Phase::Decoding));
                }
                (
                    Some(resource),
                    Some(known),
                    ctx.take_occurrences(),
                    Some(entry.capability.clone()),
                )
            } else {
                let finding = Finding::warning(
                    if crate::capability::builtin_scope(&gvk).is_some() {
                        FindingCode::UnadmittedKind
                    } else {
                        FindingCode::UnknownKind
                    },
                    Phase::Decoding,
                )
                .for_resource(id);
                self.processing.report(&finding, Phase::Decoding)?;
                self.findings.push(finding);
                (None, None, BTreeMap::new(), None)
            };
        crate::source::check_observation_budget(&tree, &gvk)?;
        let mut observations = crate::source::root_observation_paths();
        if let Some(resource) = &resource {
            resource.collect_observation_paths(&tree, &mut observations);
        }
        crate::source::retain_reviewed_observations(&tree, &gvk, evidence.source_version, &mut observations);
        let mut fields = FieldEvidenceMap::default();
        collect_evidence(&tree, &FieldPath::default(), &evidence, &observations, &mut fields);
        self.processing.payload_array::<ResourceDocument>(1, Phase::Decoding)?;
        self.processing.payload_array::<ResourceId>(1, Phase::Decoding)?;
        self.documents.push(ResourceDocument {
            id,
            source,
            collection,
            original_identity,
            original: tree,
            syntax,
            evidence,
            field_evidence: fields,
            original_known,
            original_occurrences,
            resource,
            decode: registry.entries.get(&gvk).map(|entry| entry.decode),
            capability,
            edits: Vec::new(),
            edit_processing_limits: crate::processing::NativeProcessingLimits::default(),
        });
        Ok(vec![id])
    }
    fn add_list(
        &mut self,
        tree: &TreeNode,
        source: SourceRef,
        collection: Option<&CollectionPath>,
        evidence: &Arc<SourceEvidence>,
        syntax: &Arc<SyntaxDocument>,
        registry: &RegistryBuilder,
    ) -> Result<Vec<ResourceId>, Finding> {
        let gvk = tree_gvk(tree)?;
        let typed_list = registry.lists.get(&gvk);
        let id = ListId(u64::try_from(self.lists.len()).map_err(|_| invalid())?);
        let result = (|| {
            let Some(items) = tree.get("items").and_then(TreeNode::as_sequence) else {
                return Err(invalid());
            };
            self.processing.tree_copy(tree, Phase::Decoding)?;
            self.processing.payload_array::<ListDocument>(1, Phase::Decoding)?;
            self.lists.push(ListDocument {
                id,
                source,
                item_ids: Vec::new(),
                original: tree.clone(),
                syntax: Arc::clone(syntax),
                collection: collection.cloned(),
            });
            let mut resource_ids = Vec::new();
            for (index, item) in items.iter().enumerate() {
                self.processing.work(1, Phase::Decoding)?;
                self.processing.tree_copy(item, Phase::Decoding)?;
                self.processing.payload_array::<(ListId, usize)>(
                    collection
                        .map_or(Some(1), |path| path.items.len().checked_add(1))
                        .ok_or_else(|| self.processing.fail(Phase::Decoding))?,
                    Phase::Decoding,
                )?;
                if typed_list.is_some_and(|expected| tree_gvk(item).is_ok_and(|actual| &actual != expected)) {
                    let mut finding = invalid().at_path(FieldPath(vec!["items".into(), index.to_string()]));
                    finding.source = item.start;
                    return Err(finding);
                }
                let mut path = collection.cloned().unwrap_or(CollectionPath { items: Vec::new() });
                path.items.push((id, index));
                let added = self
                    .add_node(
                        item.clone(),
                        source,
                        Some(path),
                        Arc::clone(evidence),
                        Arc::clone(syntax),
                        registry,
                    )
                    .map_err(|mut finding| {
                        if finding.code == FindingCode::LimitExceeded {
                            return finding;
                        }
                        if finding.wrapper.is_none() {
                            if finding.path.is_none() {
                                finding.path = Some(FieldPath(vec!["items".into(), index.to_string()]));
                            }
                            if finding.source.is_none() {
                                finding.source = item.start;
                            }
                        }
                        finding
                    })?;
                self.processing
                    .payload_array::<ResourceId>(added.len(), Phase::Decoding)?;
                resource_ids.extend(added);
            }
            self.processing
                .payload_array::<ResourceId>(resource_ids.len(), Phase::Decoding)?;
            self.lists[usize::try_from(id.0).map_err(|_| invalid())?]
                .item_ids
                .clone_from(&resource_ids);
            Ok(resource_ids)
        })();
        result.map_err(|mut finding: Finding| {
            if finding.code == FindingCode::LimitExceeded {
                return finding;
            }
            if finding.wrapper.is_none() {
                finding = finding.for_wrapper(WrapperSubject { source, list: id });
                if finding.source.is_none() {
                    finding.source = tree.get("items").and_then(|node| node.start).or(tree.start);
                }
                if finding.path.is_none() {
                    finding.path = Some(FieldPath(vec!["items".into()]));
                }
            }
            finding
        })
    }
    pub(crate) fn crd_scopes(&self) -> Result<BTreeMap<(String, String, String), bool>, Finding> {
        let mut crds = BTreeMap::new();
        for doc in &self.documents {
            self.processing.work(1, Phase::Decoding)?;
            if doc.original_identity.gvk.group.as_deref() != Some("apiextensions.k8s.io")
                || doc.original_identity.gvk.kind != "CustomResourceDefinition"
            {
                continue;
            }
            let Some(spec) = doc.original.get("spec") else {
                continue;
            };
            let Some(group) = spec.get("group").and_then(TreeNode::as_str) else {
                continue;
            };
            let Some(kind) = spec
                .get("names")
                .and_then(|names| names.get("kind"))
                .and_then(TreeNode::as_str)
            else {
                continue;
            };
            let namespaced = match spec.get("scope").and_then(TreeNode::as_str) {
                Some("Namespaced") => true,
                Some("Cluster") => false,
                _ => continue,
            };
            let mut versions = Vec::new();
            if let Some(items) = spec.get("versions").and_then(TreeNode::as_sequence) {
                for item in items {
                    self.processing.work(1, Phase::Decoding)?;
                    if item.get("served").is_some_and(|n| n.value == TreeValue::Bool(true)) {
                        if let Some(version) = item.get("name").and_then(TreeNode::as_str) {
                            self.processing.payload(version.len(), Phase::Decoding)?;
                            versions.push(version.to_owned());
                        }
                    }
                }
            } else if let Some(version) = spec.get("version").and_then(TreeNode::as_str) {
                self.processing.payload(version.len(), Phase::Decoding)?;
                versions.push(version.to_owned());
            }
            for version in versions {
                self.processing.work(1, Phase::Decoding)?;
                self.processing
                    .payload_sizes([group.len(), kind.len()], Phase::Decoding)?;
                if crds
                    .insert((group.to_owned(), kind.to_owned(), version), namespaced)
                    .is_some()
                {
                    return Err(Finding::error(FindingCode::ScopeMismatch, Phase::Decoding));
                }
            }
        }
        Ok(crds)
    }
    fn resolve_crd_scopes(&mut self) -> Result<(), Finding> {
        let crds = self.crd_scopes()?;
        for doc in &mut self.documents {
            self.processing.work(1, Phase::Decoding)?;
            if doc.original_identity.scope != ResourceScope::Unknown {
                continue;
            }
            let gvk = &doc.original_identity.gvk;
            self.processing.payload_sizes(
                [
                    gvk.group.as_ref().map_or(0, String::len),
                    gvk.kind.len(),
                    gvk.version.len(),
                ],
                Phase::Decoding,
            )?;
            if let Some(namespaced) = gvk
                .group
                .as_ref()
                .and_then(|g| crds.get(&(g.clone(), gvk.kind.clone(), gvk.version.clone())))
            {
                let scope = ResourceScope::CrdResolved {
                    namespaced: *namespaced,
                };
                charge_identity(&doc.original, &self.processing, Phase::Decoding)?;
                doc.original_identity = identity(&doc.original, scope)?;
            }
        }
        Ok(())
    }
}
/// Opaque authoring input; only delivered native kinds provide public conversions.
/// There is no public raw-JSON constructor or externally implementable codec.
pub struct AuthoredResource(Box<dyn NativeResource>);
impl AuthoredResource {
    pub(crate) fn new(value: Box<dyn NativeResource>) -> Self {
        Self(value)
    }
}
impl fmt::Debug for AuthoredResource {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AuthoredResource(<private>)")
    }
}
fn positionless(mut finding: Finding) -> Finding {
    finding.source = None;
    finding
}
fn clear_positions(node: &mut TreeNode) {
    node.start = None;
    match &mut node.value {
        TreeValue::Mapping(entries) => {
            for (_, value) in entries {
                clear_positions(value);
            }
        }
        TreeValue::Sequence(items) => {
            for item in items {
                clear_positions(item);
            }
        }
        TreeValue::Tagged(_, value) => clear_positions(value),
        _ => {}
    }
}
fn invalid() -> Finding {
    Finding::error(FindingCode::InvalidIdentity, Phase::Decoding)
}
fn charge_gvk(
    tree: &TreeNode,
    processing: &crate::processing::NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    processing.payload_sizes(
        ["apiVersion", "kind"].map(|key| tree.get(key).and_then(TreeNode::as_str).map_or(0, str::len)),
        phase,
    )
}
pub(crate) fn charge_identity(
    tree: &TreeNode,
    processing: &crate::processing::NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    charge_gvk(tree, processing, phase)?;
    let metadata = tree.get("metadata");
    processing.payload_sizes(
        ["name", "namespace", "generateName"].map(|key| {
            metadata
                .and_then(|node| node.get(key))
                .and_then(TreeNode::as_str)
                .map_or(0, str::len)
        }),
        phase,
    )
}
fn charge_identity_copy(
    identity: &ResourceIdentity,
    processing: &crate::processing::NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    processing.payload_sizes(
        [
            identity.gvk.group.as_ref().map_or(0, String::len),
            identity.gvk.version.len(),
            identity.gvk.kind.len(),
            identity.name.value().map_or(0, String::len),
            identity.namespace.value().map_or(0, String::len),
            identity.generate_name.value().map_or(0, String::len),
        ],
        phase,
    )
}
pub(crate) fn tree_gvk(tree: &TreeNode) -> Result<GroupVersionKind, Finding> {
    let api = tree.get("apiVersion").and_then(TreeNode::as_str).ok_or_else(invalid)?;
    let kind = tree.get("kind").and_then(TreeNode::as_str).ok_or_else(invalid)?;
    GroupVersionKind::new(api, kind)
}
pub(crate) fn string_field(tree: Option<&TreeNode>) -> Result<Presence<String>, Finding> {
    match tree {
        None => Ok(Presence::Absent),
        Some(n) if n.value == TreeValue::Null => Ok(Presence::Null),
        Some(n) => n.as_str().map(|v| Presence::Value(v.to_owned())).ok_or_else(invalid),
    }
}
pub(crate) fn identity_in(
    tree: &TreeNode,
    scope: ResourceScope,
    processing: &crate::processing::NativeOperationBudget,
    phase: Phase,
) -> Result<ResourceIdentity, Finding> {
    charge_identity(tree, processing, phase)?;
    identity(tree, scope)
}

pub(crate) fn identity(tree: &TreeNode, scope: ResourceScope) -> Result<ResourceIdentity, Finding> {
    let gvk = tree_gvk(tree)?;
    let metadata = tree.get("metadata");
    if metadata.is_some_and(|n| n.as_mapping().is_none()) {
        return Err(invalid());
    }
    let field = |name| string_field(metadata.and_then(|m| m.get(name)));
    let namespace = field("namespace")?;
    let name = field("name")?;
    let generate_name = field("generateName")?;
    if name.value().is_some_and(|n| !crate::value::dns_subdomain(n))
        || namespace.value().is_some_and(|n| !crate::value::dns_label(n))
        || generate_name
            .value()
            .is_some_and(|n| n.is_empty() || n.len() > 253 || !crate::value::dns_subdomain(n.trim_end_matches('-')))
    {
        return Err(invalid());
    }
    if name.value().is_none() && generate_name.value().is_none() {
        return Err(invalid());
    }
    if scope.namespaced() == Some(false) && namespace.value().is_some() {
        return Err(Finding::error(FindingCode::ScopeMismatch, Phase::Decoding));
    }
    Ok(ResourceIdentity {
        gvk,
        scope,
        namespace,
        name,
        generate_name,
    })
}
fn collect_evidence(
    node: &TreeNode,
    path: &FieldPath,
    source: &SourceEvidence,
    observations: &[crate::source::ObservationPath],
    out: &mut FieldEvidenceMap,
) {
    let observed = source.origin == EvidenceOrigin::Supplied(InputOrigin::ClusterExport)
        && observations
            .iter()
            .any(|observation| path.0.starts_with(&observation.path.0));
    let origin = if observed {
        ValueOrigin::Observed
    } else if source.origin == EvidenceOrigin::Supplied(InputOrigin::Authored) {
        ValueOrigin::Authored
    } else if source.origin == EvidenceOrigin::NativeAuthored {
        ValueOrigin::Generated
    } else {
        ValueOrigin::CallerSupplied
    };
    out.0.insert(
        path.clone(),
        FieldEvidence {
            source: source.id,
            position: if source.origin == EvidenceOrigin::NativeAuthored {
                None
            } else {
                node.start
            },
            origin,
        },
    );
    match &node.value {
        TreeValue::Mapping(entries) => {
            for (key, value) in entries {
                collect_evidence(value, &path.child(key), source, observations, out);
            }
        }
        TreeValue::Sequence(items) => {
            for (index, value) in items.iter().enumerate() {
                collect_evidence(value, &path.child(index.to_string()), source, observations, out);
            }
        }
        _ => {}
    }
}

pub(crate) struct EffectiveProjection {
    comparisons: std::cell::RefCell<BTreeMap<FieldPath, bool>>,
    pub(crate) findings: Vec<Finding>,
    pub(crate) tree: TreeNode,
    /// Candidates from current typed encoding, captured before effective decode mints new tokens.
    pub(crate) occurrences: crate::syntax::NativeOccurrences,
    pub(crate) identity: ResourceIdentity,
    pub(crate) resource: Option<Box<dyn NativeResource>>,
    pub(crate) observations: Vec<crate::source::ObservationPath>,
}
