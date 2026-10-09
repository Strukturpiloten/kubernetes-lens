//! Supplied-only reference resolution, without ambient namespace or cluster discovery.
use crate::{
    capability::KindId,
    diagnostic::{FieldPath, Finding, FindingCode, Phase, ResourceId},
    model::{GroupVersionKind, ResourceIdentity, ResourceSet},
    registry,
    value::{LabelSelector, Presence},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};
/// Explicit codec relationship class.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RelationshipKind {
    /// Native ownership.
    Owner,
    /// Admitted selector.
    Selector,
    /// Explicit named dependency.
    Dependency,
    /// Operator-controlled dependency.
    Operator,
    /// Storage dependency.
    Storage,
    /// Identity/access dependency.
    Identity,
}
/// External prerequisite, never an existence assertion.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExternalRefKind {
    /// Remote system.
    Remote,
    /// External storage.
    Storage,
    /// External operator.
    Operator,
    /// Other explicit prerequisite.
    Other,
}
/// Explicit reference scope, separate from authored metadata.
#[derive(Clone)]
pub enum ReferenceScope {
    /// Source namespace or separate caller context.
    SameNamespace,
    /// Explicit authored namespace presence.
    Namespace(Presence<String>),
    /// Cluster scope.
    Cluster,
    /// Scope is not established.
    Unknown,
}
impl fmt::Debug for ReferenceScope {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReferenceScope(<private>)")
    }
}
/// Native reference payload with redacted Debug.
#[derive(Clone)]
pub enum ReferenceTarget {
    /// Exact identity; served version remains evidence, not lookup identity.
    Exact {
        /// Expected GVK.
        gvk: Option<GroupVersionKind>,
        /// Exact name.
        name: String,
    },
    /// Native selector filtered by kinds and namespace/scope.
    LabelSelector {
        /// Selected kinds.
        kinds: &'static [KindId],
        /// Explicit selector.
        selector: LabelSelector,
    },
    /// Owner with served GVK and UID evidence.
    Owner {
        /// Expected owner GVK.
        gvk: GroupVersionKind,
        /// Authored UID.
        uid: Presence<String>,
        /// Authored name.
        name: Presence<String>,
    },
    /// Explicit external prerequisite.
    External {
        /// External class.
        kind: ExternalRefKind,
    },
}
impl fmt::Debug for ReferenceTarget {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ReferenceTarget(<private>)")
    }
}
/// Explicit supplied dependency candidate.
#[derive(Clone, Debug)]
pub struct Reference {
    /// Input-local source ID.
    pub from: ResourceId,
    /// Private field path.
    pub path: FieldPath,
    /// Relationship class.
    pub relation: RelationshipKind,
    /// Exact target evidence.
    pub target: ReferenceTarget,
    /// Explicit scope.
    pub scope: ReferenceScope,
}
pub(crate) trait ReferenceSink {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    fn push(&mut self, reference: Reference);
}
impl ReferenceSink for Vec<Reference> {
    fn push(&mut self, reference: Reference) {
        Self::push(self, reference);
    }
}
/// Fixed safe unsupported reason.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SafeReason {
    /// Namespace/scope unavailable.
    ScopeUnknown,
    /// Relationship or selector unsupported.
    UnsupportedRelationship,
    /// Owner UID contradicts supplied target.
    OwnerUidMismatch,
    /// Edited identity invalid.
    InvalidIdentity,
    /// Operator-owned target.
    OperatorOwned,
}
/// Supplied-only resolution.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Resolution {
    /// Matching supplied IDs.
    Resolved(Vec<ResourceId>),
    /// No matches.
    Missing,
    /// Duplicate exact matches.
    Ambiguous(Vec<ResourceId>),
    /// External prerequisite.
    External(ExternalRefKind),
    /// Explicit unsupported outcome.
    Unsupported(SafeReason),
}
/// Caller namespace context, never copied into authored metadata.
#[derive(Clone, Default)]
pub struct ReferenceContext {
    /// Separately declared caller namespace.
    pub default_namespace: Option<String>,
}
impl fmt::Debug for ReferenceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReferenceContext")
            .field("has_namespace", &self.default_namespace.is_some())
            .finish()
    }
}
/// One analyzed edge.
#[derive(Clone, Debug)]
pub struct ResolvedReference {
    /// Original evidence.
    pub reference: Reference,
    /// Supplied-set outcome.
    pub resolution: Resolution,
}
/// Offline graph recomputed from effective live identities.
#[derive(Clone, Debug)]
pub struct ReferenceGraph {
    /// Deterministic edges.
    pub edges: Vec<ResolvedReference>,
    /// Safe missing/ambiguity/cycle findings.
    pub findings: Vec<Finding>,
}
/// Resolve codec-emitted and metadata owner edges with no ambient context.
#[must_use]
pub fn resolve_references(resources: &ResourceSet) -> ReferenceGraph {
    resolve_references_with_context(resources, &ReferenceContext::default())
}
/// Resolve native edges with a separate explicit namespace context.
#[must_use]
pub fn resolve_references_with_context(resources: &ResourceSet, context: &ReferenceContext) -> ReferenceGraph {
    let mut refs = Vec::new();
    let mut findings = Vec::new();
    for doc in &resources.documents {
        if let Some(resource) = &doc.resource {
            let mut emitted = registry::collect(resource.as_ref());
            for r in &mut emitted {
                r.from = doc.id;
            }
            refs.extend(emitted);
        }
        let Ok(tree) = doc.current_tree(None) else { continue };
        let path = FieldPath(vec!["metadata".into(), "ownerReferences".into()]);
        let Some(owners) = tree.get_path(&path) else { continue };
        let Some(items) = owners.as_sequence() else {
            findings.push(owner_error(owners, path, doc.id));
            continue;
        };
        for (index, owner) in items.iter().enumerate() {
            let path = path.child(index.to_string());
            match owner_reference(owner, path.clone(), doc.id) {
                Ok(reference) => refs.push(reference),
                Err(finding) => {
                    findings.push(finding);
                    continue;
                }
            }
            if let Some(entries) = owner.as_mapping() {
                for (key, node) in entries {
                    if !matches!(
                        key.as_str(),
                        "apiVersion" | "kind" | "name" | "uid" | "controller" | "blockOwnerDeletion"
                    ) {
                        let mut finding = Finding::warning(FindingCode::UnadmittedField, Phase::Analysis)
                            .for_resource(doc.id)
                            .at_path(path.child(key));
                        finding.source = node.start;
                        findings.push(finding);
                    }
                }
            }
        }
    }
    let mut graph = resolve_supplied_references(resources, &refs, context);
    graph.findings.extend(findings);
    graph
}
fn owner_error(node: &crate::syntax::TreeNode, path: FieldPath, id: ResourceId) -> Finding {
    let mut finding = Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis)
        .for_resource(id)
        .at_path(path);
    finding.source = node.start;
    finding
}
fn owner_reference(node: &crate::syntax::TreeNode, path: FieldPath, id: ResourceId) -> Result<Reference, Finding> {
    if node.as_mapping().is_none() {
        return Err(owner_error(node, path, id));
    }
    let string = |key: &str| -> Result<&str, Finding> {
        node.get(key)
            .and_then(crate::syntax::TreeNode::as_str)
            .filter(|value| !value.is_empty())
            .ok_or_else(|| owner_error(node.get(key).unwrap_or(node), path.child(key), id))
    };
    let api = string("apiVersion")?;
    let kind = string("kind")?;
    let gvk = GroupVersionKind::new(api, kind).map_err(|_| owner_error(node, path.clone(), id))?;
    let name = string("name")?;
    if !crate::value::dns_subdomain(name) {
        return Err(owner_error(node, path.child("name"), id));
    }
    let uid = crate::model::string_field(node.get("uid"))
        .map_err(|_| owner_error(node.get("uid").unwrap_or(node), path.child("uid"), id))?;
    if uid.value().is_some_and(String::is_empty) {
        return Err(owner_error(node, path.child("uid"), id));
    }
    for key in ["controller", "blockOwnerDeletion"] {
        if let Some(value) = node.get(key) {
            if !matches!(value.value, crate::syntax::TreeValue::Bool(_)) {
                return Err(owner_error(value, path.child(key), id));
            }
        }
    }
    Ok(Reference {
        from: id,
        path,
        relation: RelationshipKind::Owner,
        target: ReferenceTarget::Owner {
            gvk,
            uid,
            name: Presence::Value(name.to_owned()),
        },
        scope: ReferenceScope::Unknown,
    })
}
/// Analyze explicit edges only against supplied current resources.
#[must_use]
pub fn resolve_supplied_references(
    resources: &ResourceSet,
    refs: &[Reference],
    context: &ReferenceContext,
) -> ReferenceGraph {
    let mut identities = BTreeMap::new();
    let mut graph = ReferenceGraph {
        edges: Vec::new(),
        findings: resources.identity_findings(),
    };
    for document in &resources.documents {
        if let Ok(identity) = document.identity() {
            if identities.insert(document.id, identity).is_some() {
                graph.edges = refs
                    .iter()
                    .map(|reference| ResolvedReference {
                        reference: reference.clone(),
                        resolution: Resolution::Unsupported(SafeReason::InvalidIdentity),
                    })
                    .collect();
                return graph;
            }
        }
    }
    for r in refs {
        let resolution = resolve_one(resources, &identities, r, context);
        let code = match &resolution {
            Resolution::Missing => Some(if matches!(r.target, ReferenceTarget::LabelSelector { .. }) {
                FindingCode::SelectorNoMatches
            } else {
                FindingCode::MissingReference
            }),
            Resolution::Ambiguous(_) => Some(FindingCode::AmbiguousReference),
            Resolution::External(_) => Some(FindingCode::ExternalPrerequisite),
            Resolution::Unsupported(SafeReason::OperatorOwned) => Some(FindingCode::OperatorOwned),
            Resolution::Unsupported(SafeReason::ScopeUnknown) => Some(FindingCode::ScopeUnknown),
            Resolution::Unsupported(_) => Some(FindingCode::NativeFieldInvalid),
            Resolution::Resolved(_) => None,
        };
        if let Some(code) = code {
            graph.findings.push(
                Finding::warning(code, Phase::Analysis)
                    .for_resource(r.from)
                    .at_path(r.path.clone()),
            );
        }
        graph.edges.push(ResolvedReference {
            reference: r.clone(),
            resolution,
        });
    }
    let mut adjacency = BTreeMap::<ResourceId, Vec<ResourceId>>::new();
    for edge in &graph.edges {
        if let Resolution::Resolved(ids) = &edge.resolution {
            adjacency.entry(edge.reference.from).or_default().extend(ids);
        }
    }
    for id in identities.keys() {
        let mut pending = adjacency.get(id).cloned().unwrap_or_default();
        let mut visited = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if next == *id {
                graph
                    .findings
                    .push(Finding::warning(FindingCode::ReferenceCycle, Phase::Analysis).for_resource(*id));
                break;
            }
            if visited.insert(next) {
                pending.extend(adjacency.get(&next).into_iter().flatten().copied());
            }
        }
    }
    graph
}
fn namespace<'a>(
    r: &'a Reference,
    from: &'a ResourceIdentity,
    context: &'a ReferenceContext,
) -> Result<Option<&'a str>, SafeReason> {
    match &r.scope {
        ReferenceScope::Cluster => Ok(None),
        ReferenceScope::SameNamespace => from
            .namespace
            .value()
            .map(String::as_str)
            .or(context.default_namespace.as_deref())
            .map(Some)
            .ok_or(SafeReason::ScopeUnknown),
        ReferenceScope::Namespace(Presence::Value(ns)) => Ok(Some(ns)),
        ReferenceScope::Namespace(_) | ReferenceScope::Unknown => Err(SafeReason::ScopeUnknown),
    }
}
fn owner_scope(
    resources: &ResourceSet,
    identities: &BTreeMap<ResourceId, ResourceIdentity>,
    gvk: &GroupVersionKind,
) -> ReferenceScope {
    let mut scopes = BTreeSet::new();
    for candidate in identities
        .values()
        .filter(|candidate| candidate.gvk.group == gvk.group && candidate.gvk.kind == gvk.kind)
    {
        scopes.insert(candidate.scope.namespaced());
    }
    let namespaced = if scopes.is_empty() {
        crate::capability::builtin_scope(gvk)
            .and_then(crate::model::ResourceScope::namespaced)
            .or_else(|| {
                resources
                    .crd_scopes()
                    .ok()?
                    .get(&(gvk.group.clone()?, gvk.kind.clone(), gvk.version.clone()))
                    .copied()
            })
    } else if scopes.len() == 1 {
        scopes.first().copied().flatten()
    } else {
        return ReferenceScope::Unknown;
    };
    match namespaced {
        Some(true) => ReferenceScope::SameNamespace,
        Some(false) => ReferenceScope::Cluster,
        None => ReferenceScope::Unknown,
    }
}
fn resolve_one(
    resources: &ResourceSet,
    identities: &BTreeMap<ResourceId, ResourceIdentity>,
    r: &Reference,
    context: &ReferenceContext,
) -> Resolution {
    if let ReferenceTarget::External { kind } = &r.target {
        return Resolution::External(*kind);
    }
    if r.relation == RelationshipKind::Operator {
        return Resolution::Unsupported(SafeReason::OperatorOwned);
    }
    let Some(from) = identities.get(&r.from) else {
        return Resolution::Unsupported(SafeReason::InvalidIdentity);
    };
    let mut owner;
    let r = if let ReferenceTarget::Owner { gvk, .. } = &r.target {
        owner = r.clone();
        owner.scope = owner_scope(resources, identities, gvk);
        &owner
    } else {
        r
    };
    let ns = match namespace(r, from, context) {
        Ok(ns) => ns,
        Err(reason) => return Resolution::Unsupported(reason),
    };
    if r.relation == RelationshipKind::Owner && from.scope.namespaced() == Some(false) && ns.is_some() {
        return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
    }
    let mut matches = Vec::new();
    for (id, candidate) in identities {
        let Some(namespaced) = candidate.scope.namespaced() else {
            continue;
        };
        if namespaced != ns.is_some() {
            continue;
        }
        if namespaced
            && candidate
                .namespace
                .value()
                .map(String::as_str)
                .or(context.default_namespace.as_deref())
                != ns
        {
            continue;
        }
        let selected = match &r.target {
            ReferenceTarget::Exact { gvk: Some(gvk), name } => {
                candidate.gvk.group == gvk.group
                    && candidate.gvk.kind == gvk.kind
                    && candidate.name.value() == Some(name)
            }
            ReferenceTarget::Exact { gvk: None, .. } => {
                return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
            }
            ReferenceTarget::Owner { gvk, name, .. } => {
                candidate.gvk.group == gvk.group
                    && candidate.gvk.kind == gvk.kind
                    && name.value().is_some()
                    && candidate.name.value() == name.value()
            }
            ReferenceTarget::LabelSelector { kinds, selector } => {
                match selector_match(resources, *id, candidate, kinds, selector) {
                    Ok(matches) => matches,
                    Err(reason) => return Resolution::Unsupported(reason),
                }
            }
            ReferenceTarget::External { .. } => false,
        };
        if selected {
            matches.push(*id);
        }
    }
    if let ReferenceTarget::Owner {
        uid: Presence::Value(expected),
        ..
    } = &r.target
    {
        if matches.len() == 1 {
            let actual = resources
                .documents
                .iter()
                .find(|d| d.id == matches[0])
                .and_then(|d| d.current_tree(None).ok())
                .and_then(|t| {
                    t.get("metadata")
                        .and_then(|m| m.get("uid"))
                        .and_then(crate::syntax::TreeNode::as_str)
                        .map(str::to_owned)
                });
            if actual.as_ref() != Some(expected) {
                return Resolution::Unsupported(SafeReason::OwnerUidMismatch);
            }
        }
    }
    if matches.is_empty() {
        Resolution::Missing
    } else if matches!(r.target, ReferenceTarget::LabelSelector { .. }) || matches.len() == 1 {
        Resolution::Resolved(matches)
    } else {
        Resolution::Ambiguous(matches)
    }
}

fn selector_match(
    resources: &ResourceSet,
    id: ResourceId,
    candidate: &ResourceIdentity,
    kinds: &[KindId],
    selector: &LabelSelector,
) -> Result<bool, SafeReason> {
    if crate::capability::builtin_scope(&candidate.gvk).is_none()
        || !kinds.iter().any(|kind| kind.as_str() == candidate.gvk.kind)
    {
        return Ok(false);
    }
    let doc = resources
        .documents
        .iter()
        .find(|doc| doc.id == id)
        .ok_or(SafeReason::InvalidIdentity)?;
    let tree = doc.current_tree(None).map_err(|_| SafeReason::InvalidIdentity)?;
    let mut labels = BTreeMap::new();
    if let Some(entries) = tree
        .get("metadata")
        .and_then(|metadata| metadata.get("labels"))
        .and_then(crate::syntax::TreeNode::as_mapping)
    {
        for (key, value) in entries {
            labels.insert(
                key.clone(),
                value.as_str().ok_or(SafeReason::UnsupportedRelationship)?.to_owned(),
            );
        }
    }
    selector
        .matches(&labels)
        .map_err(|_| SafeReason::UnsupportedRelationship)
}
