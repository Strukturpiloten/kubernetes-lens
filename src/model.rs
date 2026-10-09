//! Native identities, shared metadata, immutable evidence, and retained collection wrappers.
use crate::{
    capability::KindCapability,
    diagnostic::{FieldPath, Finding, FindingCode, Phase, ResourceId, WrapperSubject},
    parser::ParsedInput,
    registry::{self, DecodeContext, NativeResource, RegistryBuilder},
    source::{FieldEvidence, FieldEvidenceMap, InputOrigin, SourceEvidence, SourceId, ValueOrigin},
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
    pub(crate) resource: Option<Box<dyn NativeResource>>,
    pub(crate) capability: Option<KindCapability>,
    pub(crate) edits: Vec<FieldEdit>,
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
        let Some(value) = value.trees.into_iter().next() else {
            return Err(invalid());
        };
        self.edits.push(FieldEdit::Set { path, value });
        Ok(())
    }
    pub(crate) fn current_tree(&self, target: Option<&crate::capability::TargetProfile>) -> Result<TreeNode, Finding> {
        let mut tree = if let (Some(resource), Some(original_known)) = (&self.resource, &self.original_known) {
            let known = registry::encode(resource.as_ref(), target)?;
            let encoded_identity = identity(&known, self.original_identity.scope)?;
            if encoded_identity.gvk != self.original_identity.gvk {
                return Err(Finding::error(FindingCode::CodecIdentityMismatch, Phase::Generation));
            }
            crate::generation::merge_delta(
                &self.original,
                original_known,
                &known,
                &FieldPath::default(),
                self.capability.as_ref().map_or(&[], |c| c.fields),
                &self.edits,
            )?
        } else {
            self.original.clone()
        };
        for edit in &self.edits {
            crate::generation::apply_edit(&mut tree, edit)?;
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
                    (Some(before), Some(after)) => !before.semantic_eq(after),
                    (None, None) => false,
                    _ => true,
                } {
                    return Err(
                        Finding::error(FindingCode::UnsupportedSemanticConversion, Phase::Generation).at_path(path),
                    );
                }
            }
        }
        let current = identity(&tree, self.original_identity.scope)?;
        if current.gvk != self.original_identity.gvk {
            return Err(Finding::error(
                FindingCode::UnsupportedSemanticConversion,
                Phase::Generation,
            ));
        }
        Ok(tree)
    }
}
/// Ordered supplied resources, retained wrappers, and immutable private sources.
pub struct ResourceSet {
    pub(crate) documents: Vec<ResourceDocument>,
    pub(crate) lists: Vec<ListDocument>,
    pub(crate) sources: Vec<Arc<SourceEvidence>>,
    pub(crate) findings: Vec<Finding>,
}
impl fmt::Debug for ResourceSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ResourceSet")
            .field("resource_count", &self.documents.len())
            .field("list_count", &self.lists.len())
            .field("sources", &self.sources)
            .field("findings", &self.findings)
            .finish()
    }
}
impl ResourceSet {
    /// Materialize explicit parsed inputs, retaining unadmitted resources and every wrapper.
    /// # Errors
    /// Rejects malformed identities/Lists, conflicting scope evidence, and duplicate objects.
    pub fn from_inputs(inputs: Vec<ParsedInput>) -> Result<Self, Vec<Finding>> {
        Self::with_registry(inputs, &crate::resources::registry()?)
    }
    pub(crate) fn with_registry(inputs: Vec<ParsedInput>, registry: &RegistryBuilder) -> Result<Self, Vec<Finding>> {
        let mut set = Self {
            documents: Vec::new(),
            lists: Vec::new(),
            sources: Vec::new(),
            findings: Vec::new(),
        };
        let mut ids = BTreeSet::new();
        for input in inputs {
            if !ids.insert(input.evidence.id) {
                return Err(vec![Finding::error(FindingCode::DuplicateIdentity, Phase::Decoding)]);
            }
            for (document, tree) in input.documents.iter().zip(input.trees) {
                let source = SourceRef {
                    source: input.evidence.id,
                    document_index: document.document_index,
                };
                set.add_node(tree, source, None, input.evidence.clone(), document.clone(), registry)
                    .map_err(|e| vec![e])?;
            }
            set.sources.push(input.evidence);
        }
        set.resolve_crd_scopes().map_err(|e| vec![e])?;
        let findings = set.identity_findings();
        if crate::diagnostic::has_errors(&findings) {
            return Err(findings);
        }
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
    /// Recheck effective identities after edits; served versions are excluded from collisions.
    #[must_use]
    pub fn identity_findings(&self) -> Vec<Finding> {
        let mut seen = BTreeMap::new();
        let mut out = Vec::new();
        let mut list_ids = BTreeSet::new();
        for list in &self.lists {
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
            if !ids.insert(document.id) {
                out.push(Finding::error(FindingCode::InvalidIdentity, Phase::Analysis).for_resource(document.id));
            }
            match document.identity() {
                Ok(identity) => {
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
        out
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
        let gvk = tree_gvk(&tree)?;
        let typed_list = registry.lists.get(&gvk);
        if gvk.group.is_none() && gvk.version == "v1" && gvk.kind == "List" || typed_list.is_some() {
            return self.add_list(&tree, source, collection.as_ref(), &evidence, &syntax, registry);
        }
        if tree.as_mapping().is_none() {
            return Err(invalid());
        }
        let scope = crate::capability::builtin_scope(&gvk).unwrap_or(ResourceScope::Unknown);
        let original_identity = identity(&tree, scope)?;
        let id = ResourceId(u64::try_from(self.documents.len()).map_err(|_| invalid())?);
        let (resource, original_known, capability) = if let Some(entry) = registry.entries.get(&gvk) {
            if entry.gvk != gvk || entry.scope != scope {
                return Err(Finding::error(FindingCode::InvalidRegistration, Phase::Decoding));
            }
            let resource =
                (entry.decode)(&tree, &evidence, &DecodeContext { gvk: &gvk, scope }).map_err(|findings| {
                    findings
                        .into_iter()
                        .next()
                        .unwrap_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding))
                        .for_resource(id)
                })?;
            let known = registry::encode(resource.as_ref(), None)?;
            if identity(&known, scope)? != original_identity {
                return Err(Finding::error(FindingCode::CodecIdentityMismatch, Phase::Decoding));
            }
            (Some(resource), Some(known), Some(entry.capability.clone()))
        } else {
            self.findings.push(
                Finding::warning(
                    if crate::capability::builtin_scope(&gvk).is_some() {
                        FindingCode::UnadmittedKind
                    } else {
                        FindingCode::UnknownKind
                    },
                    Phase::Decoding,
                )
                .for_resource(id),
            );
            (None, None, None)
        };
        let mut fields = FieldEvidenceMap::default();
        collect_evidence(&tree, &FieldPath::default(), &evidence, &mut fields);
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
            resource,
            capability,
            edits: Vec::new(),
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
                if typed_list.is_some_and(|expected| tree_gvk(item).is_ok_and(|actual| &actual != expected)) {
                    let mut finding = invalid().at_path(FieldPath(vec!["items".into(), index.to_string()]));
                    finding.source = item.start;
                    return Err(finding);
                }
                let mut path = collection.cloned().unwrap_or(CollectionPath { items: Vec::new() });
                path.items.push((id, index));
                resource_ids.extend(
                    self.add_node(
                        item.clone(),
                        source,
                        Some(path),
                        Arc::clone(evidence),
                        Arc::clone(syntax),
                        registry,
                    )
                    .map_err(|mut finding| {
                        if finding.wrapper.is_none() {
                            if finding.path.is_none() {
                                finding.path = Some(FieldPath(vec!["items".into(), index.to_string()]));
                            }
                            if finding.source.is_none() {
                                finding.source = item.start;
                            }
                        }
                        finding
                    })?,
                );
            }
            self.lists[usize::try_from(id.0).map_err(|_| invalid())?]
                .item_ids
                .clone_from(&resource_ids);
            Ok(resource_ids)
        })();
        result.map_err(|mut finding: Finding| {
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
                    if item.get("served").is_some_and(|n| n.value == TreeValue::Bool(true)) {
                        if let Some(version) = item.get("name").and_then(TreeNode::as_str) {
                            versions.push(version.to_owned());
                        }
                    }
                }
            } else if let Some(version) = spec.get("version").and_then(TreeNode::as_str) {
                versions.push(version.to_owned());
            }
            for version in versions {
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
            if doc.original_identity.scope != ResourceScope::Unknown {
                continue;
            }
            let gvk = &doc.original_identity.gvk;
            if let Some(namespaced) = gvk
                .group
                .as_ref()
                .and_then(|g| crds.get(&(g.clone(), gvk.kind.clone(), gvk.version.clone())))
            {
                let scope = ResourceScope::CrdResolved {
                    namespaced: *namespaced,
                };
                doc.original_identity = identity(&doc.original, scope)?;
            }
        }
        Ok(())
    }
}
fn invalid() -> Finding {
    Finding::error(FindingCode::InvalidIdentity, Phase::Decoding)
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
fn collect_evidence(node: &TreeNode, path: &FieldPath, source: &SourceEvidence, out: &mut FieldEvidenceMap) {
    let observed = source.origin == InputOrigin::ClusterExport
        && (path.0.first().is_some_and(|s| s == "status")
            || path.0.first().is_some_and(|s| s == "metadata")
                && path.0.get(1).is_some_and(|s| {
                    matches!(
                        s.as_str(),
                        "uid" | "resourceVersion" | "managedFields" | "creationTimestamp" | "generation"
                    )
                }));
    let origin = if observed {
        ValueOrigin::Observed
    } else if source.origin == InputOrigin::Authored {
        ValueOrigin::Authored
    } else {
        ValueOrigin::CallerSupplied
    };
    out.0.insert(
        path.clone(),
        FieldEvidence {
            source: source.id,
            position: node.start,
            origin,
        },
    );
    match &node.value {
        TreeValue::Mapping(entries) => {
            for (key, value) in entries {
                collect_evidence(value, &path.child(key), source, out);
            }
        }
        TreeValue::Sequence(items) => {
            for (index, value) in items.iter().enumerate() {
                collect_evidence(value, &path.child(index.to_string()), source, out);
            }
        }
        _ => {}
    }
}
