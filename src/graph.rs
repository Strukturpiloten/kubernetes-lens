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
    /// Exact selected version nested inside the actual supplied CRD document.
    SuppliedCustomResourceVersion {
        /// Sealed source-bound descriptor emitted by custom-document analysis.
        descriptor: crate::resources::extensions::custom_documents::SuppliedCustomResourceDescriptor,
    },
    /// Exact object with a closed admitted native predicate and explicit optionality.
    CheckedObject {
        /// Exact expected GVK.
        gvk: GroupVersionKind,
        /// Explicit object name.
        name: String,
        /// Optional closed predicate.
        predicate: Option<ReferencePredicate>,
        /// Exact native optional flag presence.
        optional: Presence<bool>,
    },
    /// Select supplied object or template subjects under a closed policy.
    SubjectSelector {
        /// Explicit selected kinds.
        kinds: &'static [KindId],
        /// Native selector.
        selector: LabelSelector,
        /// Closed subject selection.
        selection: SubjectSelection,
    },
    /// Native group/kind/name identity without a manufactured served version.
    GroupKindName {
        /// Absent means core group for comparison only; null stays unavailable.
        group: Presence<String>,
        /// Explicit native kind.
        kind: String,
        /// Explicit native name.
        name: String,
    },
    /// Conjunctive selectors belonging to one `NetworkPolicy` peer entry.
    NetworkPolicyPeer {
        /// Exact native namespace-selector presence.
        namespace_selector: Presence<LabelSelector>,
        /// Exact native Pod-selector presence.
        pod_selector: Presence<LabelSelector>,
    },
    /// Universal peer declaration on one existing allow rule, not imagined subjects.
    NetworkPolicyAllPeers {
        /// Exact absent/empty/native-null peer-list distinction.
        presence: PeerListPresence,
    },
    /// Service-selected Pod/template subjects with an admitted named container port.
    NamedServiceTargetPort {
        /// Nonempty native Service selector.
        selector: LabelSelector,
        /// Native targetPort name.
        name: crate::value::Protected<String>,
        /// Native Service protocol presence; absent/empty compares as TCP only under a target witness.
        protocol: Presence<String>,
    },
    /// Future native claim identity expectation, never runtime existence proof.
    GeneratedClaims {
        /// Closed core-bound expectation rule.
        pattern: ClaimPattern,
    },
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
    fn exhausted(&self) -> bool {
        false
    }
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
    /// Required native evidence is incomplete.
    FactUnknown(FactGap),
    /// Required native evidence is outside delivered admission.
    FactUnadmitted,
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
    /// Established supplied native subjects.
    ResolvedSubjects(Vec<GraphSubject>),
    /// Established positive matches alongside unavailable supplying candidates.
    PartiallyResolvedSubjects {
        /// Established matches.
        matched: Vec<GraphSubject>,
        /// Explicit unknown/unadmitted candidate gaps.
        unavailable: Vec<SubjectGap>,
    },
    /// Existing supplied object with a complete admitted key set lacking this key.
    MissingKey {
        /// Existing object.
        object: ResourceId,
        /// Exact native domain.
        domain: KeyDomain,
        /// Protected selected key.
        key: crate::value::Protected<String>,
    },
    /// Existing Service with complete front-port evidence lacking this name or number.
    MissingServicePort {
        /// Exact supplying Service.
        object: ResourceId,
    },
    /// Multiple front-port declarations match a protocol-free backend selector.
    AmbiguousServicePorts(Vec<GraphSubject>),
    /// Complete selected Pod/template declarations lack the named container port.
    MissingContainerPort {
        /// Actual selected subjects, without runtime existence proof.
        selected: Vec<GraphSubject>,
    },
    /// Universal peers declared by one actual allow rule.
    NetworkPolicyAllPeers(PeerListPresence),
    /// Explicitly optional absent supplied object/key.
    OptionalMissing(MissingSubject),
    /// Established supplied predicate incompatibility.
    Incompatible {
        /// Supplied subject.
        subject: GraphSubject,
        /// Closed reason.
        reason: PredicateMismatch,
    },
    /// Future identity-rule expectations and actual supplied PVC candidates.
    ExpectedClaims {
        /// Rule completeness.
        state: ClaimExpectationState,
        /// Actual matching supplied PVCs.
        matching_supplied: Vec<ClaimMatch>,
    },
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
    /// Optional ceilings that can only lower retained source ceilings.
    pub processing: Option<crate::processing::NativeProcessingLimits>,
}
impl fmt::Debug for ReferenceContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ReferenceContext")
            .field("has_namespace", &self.default_namespace.is_some())
            .field("processing", &self.processing)
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
    /// All contributing supplier/source/path records.
    pub evidence: Vec<FactEvidence>,
}
/// Offline graph recomputed from effective live identities.
#[derive(Clone, Debug)]
pub struct ReferenceGraph {
    /// Deterministic edges.
    pub edges: Vec<ResolvedReference>,
    /// Safe missing/ambiguity/cycle findings.
    pub findings: Vec<Finding>,
    /// Source-bound custom-document outcomes and successful selected-version descriptors.
    pub custom_documents: Vec<crate::resources::extensions::custom_documents::CustomDocumentGraphRecord>,
    target: Option<std::sync::Arc<GraphTargetWitness>>,
}
struct WorkingGraph {
    edges: Vec<ResolvedReference>,
    findings: crate::processing::ProcessingReport,
    custom_documents: Vec<crate::resources::extensions::custom_documents::CustomDocumentGraphRecord>,
    target: Option<std::sync::Arc<GraphTargetWitness>>,
}
impl WorkingGraph {
    fn finish(mut self) -> ReferenceGraph {
        if self.findings.failed() {
            for edge in &mut self.edges {
                edge.resolution = Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
                edge.evidence.clear();
            }
        }
        ReferenceGraph {
            edges: self.edges,
            findings: self.findings.into_vec(),
            custom_documents: self.custom_documents,
            target: self.target,
        }
    }
}
impl ReferenceGraph {
    /// Complete explicit checked target retained even by an empty graph.
    #[must_use]
    pub fn target_witness(&self) -> Option<&GraphTargetWitness> {
        self.target.as_deref()
    }
}
/// Resolve codec-emitted and metadata owner edges with no ambient context.
#[must_use]
pub fn resolve_references(resources: &ResourceSet) -> ReferenceGraph {
    resolve_references_with_context(resources, &ReferenceContext::default())
}
/// Resolve native edges with a separate explicit namespace context.
#[must_use]
pub fn resolve_references_with_context(resources: &ResourceSet, context: &ReferenceContext) -> ReferenceGraph {
    analyze(resources, None, context, None)
}
/// Resolve native relationships under an explicit complete target profile.
#[must_use]
pub fn resolve_references_for_target(
    resources: &ResourceSet,
    target: &crate::capability::TargetProfile,
) -> ReferenceGraph {
    analyze(resources, None, &ReferenceContext::default(), Some(target))
}
/// Resolve native relationships with explicit namespace and target contexts.
#[must_use]
pub fn resolve_references_with_context_for_target(
    resources: &ResourceSet,
    context: &ReferenceContext,
    target: &crate::capability::TargetProfile,
) -> ReferenceGraph {
    analyze(resources, None, context, Some(target))
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
    analyze(resources, Some(refs), context, None)
}
/// Analyze caller-supplied edges under an explicit target without acquiring runtime data.
#[must_use]
pub fn resolve_supplied_references_for_target(
    resources: &ResourceSet,
    refs: &[Reference],
    context: &ReferenceContext,
    target: &crate::capability::TargetProfile,
) -> ReferenceGraph {
    analyze(resources, Some(refs), context, Some(target))
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
    _resources: &ResourceSet,
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
        crate::capability::builtin_scope(gvk).and_then(crate::model::ResourceScope::namespaced)
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
fn reference_candidate(
    target: &ReferenceTarget,
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    id: ResourceId,
    candidate: &ResourceIdentity,
) -> Result<bool, SafeReason> {
    Ok(match target {
        ReferenceTarget::SuppliedCustomResourceVersion { descriptor } => {
            id == descriptor.crd_resource_id() && candidate.gvk == *descriptor.crd_gvk()
        }
        ReferenceTarget::Exact { gvk: Some(gvk), name } => {
            candidate.gvk.group == gvk.group && candidate.gvk.kind == gvk.kind && candidate.name.value() == Some(name)
        }
        ReferenceTarget::Exact { gvk: None, .. } => {
            return Err(SafeReason::UnsupportedRelationship);
        }
        ReferenceTarget::Owner { gvk, name, .. } => {
            candidate.gvk.group == gvk.group
                && candidate.gvk.kind == gvk.kind
                && name.value().is_some()
                && candidate.name.value() == name.value()
        }
        ReferenceTarget::LabelSelector { kinds, selector } => {
            selector_match(projections, id, candidate, kinds, selector)?
        }
        ReferenceTarget::External { .. } => false,
        ReferenceTarget::CheckedObject { .. }
        | ReferenceTarget::SubjectSelector { .. }
        | ReferenceTarget::GeneratedClaims { .. }
        | ReferenceTarget::GroupKindName { .. }
        | ReferenceTarget::NetworkPolicyPeer { .. }
        | ReferenceTarget::NetworkPolicyAllPeers { .. }
        | ReferenceTarget::NamedServiceTargetPort { .. } => {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
    })
}
fn resolve_one(
    resources: &ResourceSet,
    identities: &BTreeMap<ResourceId, ResourceIdentity>,
    r: &Reference,
    context: &ReferenceContext,
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
) -> Resolution {
    if matches!(
        r.target,
        ReferenceTarget::CheckedObject { .. }
            | ReferenceTarget::SubjectSelector { .. }
            | ReferenceTarget::GeneratedClaims { .. }
    ) {
        return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
    }
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
        let selected = match reference_candidate(&r.target, projections, *id, candidate) {
            Ok(selected) => selected,
            Err(reason) => return Resolution::Unsupported(reason),
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
            let actual = projections
                .get(&matches[0])
                .and_then(|projection| projection.tree.get("metadata"))
                .and_then(|metadata| metadata.get("uid"))
                .and_then(crate::syntax::TreeNode::as_str);
            if actual != Some(expected.as_str()) {
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
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
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
    let tree = &projections.get(&id).ok_or(SafeReason::InvalidIdentity)?.tree;
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

/// Closed reasons why native facts cannot yet establish a supplied relationship.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactGap {
    /// Duplicate supplied identities prevent establishing unique evidence.
    AmbiguousSuppliedEvidence,
    /// A reviewed gate or conditional field requires an explicit target profile.
    TargetProfileRequired,
    /// Source-version evidence required by the rule was not supplied.
    SourceProfileRequired,
    /// Explicit native evidence is incomplete.
    IncompleteSuppliedEvidence,
}
/// Kind of explicitly supplied controller template.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum TemplateKind {
    /// Native Pod template, without a deployed-Pod assertion.
    Pod,
    /// Native Job template.
    Job,
    /// Full native PVC claim template.
    PersistentVolumeClaim,
}
/// Native key-set domain; values are never exposed by graph facts.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd)]
pub enum KeyDomain {
    /// `ConfigMap` text data only.
    ConfigMapText,
    /// `ConfigMap` text or binary data.
    ConfigMapTextOrBinary,
    /// Secret data or stringData.
    Secret,
}
#[derive(Clone)]
pub(crate) enum FactState<T> {
    Known(T),
    Unknown(FactGap),
    Unadmitted,
}
impl<T> fmt::Debug for FactState<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Known(_) => "Known(<private>)",
            Self::Unknown(_) => "Unknown(<private>)",
            Self::Unadmitted => "Unadmitted",
        })
    }
}
#[derive(Clone, Debug)]
pub(crate) enum LocalSubject {
    Object,
    Template {
        path: FieldPath,
        template_kind: TemplateKind,
    },
}
#[derive(Clone)]
pub(crate) struct KeyNames(pub(crate) BTreeMap<String, FieldPath>);
#[derive(Clone)]
pub(crate) struct LabelFacts {
    pub(crate) values: BTreeMap<String, String>,
    pub(crate) path: FieldPath,
}
#[derive(Clone)]
pub(crate) struct PortFact {
    pub(crate) name: Presence<String>,
    pub(crate) container_port: i32,
    pub(crate) protocol: Presence<String>,
    pub(crate) name_path: FieldPath,
    pub(crate) container_port_path: FieldPath,
    pub(crate) protocol_path: FieldPath,
}
#[derive(Clone)]
pub(crate) struct ServicePortFact {
    pub(crate) name: Presence<String>,
    pub(crate) port: i32,
    pub(crate) protocol: Presence<String>,
    pub(crate) path: FieldPath,
}
#[derive(Clone)]
pub(crate) enum ClaimPatternDraft {
    StatefulSet {
        template_path: FieldPath,
        template_name: Presence<crate::value::Protected<String>>,
        controller_name: Presence<crate::value::Protected<String>>,
        replicas: Presence<i32>,
        start_ordinal: Presence<i32>,
    },
    PodEphemeral {
        pod_subject: LocalSubject,
        volume_path: FieldPath,
        volume_name: Presence<crate::value::Protected<String>>,
        pod_name: Presence<crate::value::Protected<String>>,
        pod_uid: Presence<crate::value::Protected<String>>,
    },
}
#[derive(Clone)]
pub(crate) enum NativeFact {
    Keys {
        domain: KeyDomain,
        state: FactState<KeyNames>,
        path: FieldPath,
    },
    ServiceHeadless {
        state: FactState<bool>,
        path: FieldPath,
    },
    ServicePorts {
        state: FactState<Vec<ServicePortFact>>,
        path: FieldPath,
    },
    SelectorSubject {
        subject: LocalSubject,
        labels: FactState<LabelFacts>,
    },
    ContainerPorts {
        subject: LocalSubject,
        ports: FactState<Vec<PortFact>>,
    },
    ClaimExpectation {
        pattern: ClaimPatternDraft,
        path: FieldPath,
    },
}
macro_rules! private_debug {
    ($($name:ty),+ $(,)?) => { $(impl fmt::Debug for $name { fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(concat!(stringify!($name), "(<private>)")) } })+ };
}
private_debug!(
    KeyNames,
    LabelFacts,
    PortFact,
    ServicePortFact,
    ClaimPatternDraft,
    NativeFact
);

/// Supplied native object, template or key; templates do not assert deployed Pods.
#[derive(Clone, Eq, PartialEq)]
pub enum GraphSubject {
    /// Actual supplied resource.
    Object {
        /// Input-local supplied resource ID.
        resource: ResourceId,
    },
    /// Exact supplied template occurrence.
    Template {
        /// Owning supplied resource ID.
        resource: ResourceId,
        /// Resource-relative template path.
        path: FieldPath,
        /// Native template kind.
        template_kind: TemplateKind,
    },
    /// One exact supplying Service front-port declaration.
    ServicePort {
        /// Supplying Service resource.
        resource: ResourceId,
        /// Effective declaration path.
        path: FieldPath,
    },
    /// An admitted key belonging to a supplied resource.
    Key {
        /// Supplying resource ID.
        resource: ResourceId,
        /// Native map domain.
        domain: KeyDomain,
        /// Protected exact key name.
        key: crate::value::Protected<String>,
    },
}
/// Closed supplied-object predicates.
#[derive(Clone)]
pub enum ReferencePredicate {
    /// Establish key membership without examining its value.
    KeyExists {
        /// Native map domain.
        domain: KeyDomain,
        /// Exact selected key.
        key: crate::value::Protected<String>,
    },
    /// Match declared Service front ports only; no target/container/node ports.
    ServicePortExists {
        /// Native backend port selector.
        port: ServicePortSelector,
    },
    /// Require explicit clusterIP None.
    HeadlessService,
}
/// Native Ingress backend Service-port selector with private spelling.
#[derive(Clone, Eq, PartialEq)]
pub enum ServicePortSelector {
    /// Null, absent or malformed native backend-port evidence.
    Unavailable(FactGap),
    /// Exact declared Service-port name.
    Name(crate::value::Protected<String>),
    /// Exact declared Service front-port number.
    Number(i32),
}
/// Presence of a peer list on an actual `NetworkPolicy` allow rule.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PeerListPresence {
    /// No from/to field on the rule.
    Absent,
    /// Explicit empty from/to sequence.
    ExplicitEmpty,
    /// Explicit null is unavailable, not universal.
    Null,
}
/// Closed selector subject policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SubjectSelection {
    /// Object metadata only.
    Objects,
    /// Supplied Pod objects and supplied Pod templates.
    PodObjectsAndTemplates,
    /// Supplied Pod objects only.
    PodObjectsOnly,
}
/// Unavailable fact distinction retained by graph outcomes.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FactUnavailable {
    /// Native evidence is incomplete.
    Unknown(FactGap),
    /// The field or kind is outside delivered admission.
    Unadmitted,
}
/// A supplying candidate with unavailable fact knowledge.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct SubjectGap {
    /// Supplied resource, without claiming that it contains a template.
    pub resource: ResourceId,
    /// Exact known occurrence, if available.
    pub path: Option<FieldPath>,
    /// Safe reason for unavailable knowledge.
    pub reason: FactUnavailable,
}
/// Optional absent subject, without a runtime existence assertion.
#[derive(Clone, Eq, PartialEq)]
pub enum MissingSubject {
    /// No supplied object with the selected identity.
    Object,
    /// A complete admitted key set lacks this key.
    Key {
        /// Existing supplied object.
        object: ResourceId,
        /// Native map domain.
        domain: KeyDomain,
        /// Exact private key.
        key: crate::value::Protected<String>,
    },
}
/// Established predicate incompatibility.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum PredicateMismatch {
    /// Explicit concrete cluster IP contradicts headless requirement.
    HeadlessRequired,
    /// Complete supplied controller/UID evidence contradicts claim ownership.
    ClaimOwnerMismatch,
}
/// Closed future claim identity rule, never a created native resource.
#[derive(Clone)]
pub enum ClaimPattern {
    /// Arithmetic `StatefulSet` claim identity range.
    StatefulSet {
        /// Full PVC template occurrence.
        template_path: FieldPath,
        /// Explicit template name.
        template_name: Presence<crate::value::Protected<String>>,
        /// Explicit `StatefulSet` name.
        controller_name: Presence<crate::value::Protected<String>>,
        /// Explicit replica count.
        replicas: Presence<i32>,
        /// Explicit starting ordinal.
        start_ordinal: Presence<i32>,
    },
    /// Actual-Pod or symbolic future-Pod ephemeral claim rule.
    PodEphemeral {
        /// Core-bound Pod object or template.
        pod_subject: GraphSubject,
        /// Exact ephemeral volume occurrence.
        volume_path: FieldPath,
        /// Explicit volume name.
        volume_name: Presence<crate::value::Protected<String>>,
        /// Explicit actual Pod name only.
        pod_name: Presence<crate::value::Protected<String>>,
        /// Explicit actual Pod UID.
        pod_uid: Presence<crate::value::Protected<String>>,
    },
}
/// Missing explicit claim-rule inputs; no native defaults are materialized.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimEvidenceGap {
    /// Controller or actual Pod name missing.
    SourceName,
    /// PVC template name missing.
    TemplateName,
    /// Replica count missing.
    ReplicaCount,
    /// Starting ordinal missing.
    StartOrdinal,
    /// A template does not establish a future Pod name.
    FuturePodName,
    /// Actual Pod UID missing.
    PodUid,
    /// Namespace/scope evidence missing.
    Scope,
}
/// Future rule completeness independent of supplied runtime candidates.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum ClaimExpectationState {
    /// Native identity rule lacks explicit inputs.
    Symbolic {
        /// Missing inputs.
        missing: Vec<ClaimEvidenceGap>,
    },
    /// A complete arithmetic or actual-Pod naming rule is established.
    IdentityRuleEstablished,
}
/// Supplied claim owner evidence, independent of binding/readiness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ClaimOwnership {
    /// Explicit supplied controller UID agrees.
    VerifiedSupplied,
    /// Owner evidence is incomplete.
    Unknown,
    /// Complete supplied evidence contradicts ownership.
    Contradictory,
    /// This reviewed identity rule does not require an owner predicate.
    NotRequiredByThisRule,
}
private_debug!(
    GraphSubject,
    ReferencePredicate,
    ServicePortSelector,
    MissingSubject,
    ClaimPattern
);

/// Exact origin of one resolved gate setting in a retained target witness.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum GateResolutionOrigin {
    /// Caller explicitly supplied the setting.
    ExplicitOverride,
    /// Caller opted into this immutable documented-default evidence.
    DocumentedDefault {
        /// Reviewed evidence record set.
        evidence: crate::capability::FeatureGateEvidenceId,
    },
    /// Caller supplied no usable resolution evidence.
    NoEvidence,
}
/// Immutable resolved gate and its non-lossy origin.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct GateWitness {
    resolution: Result<crate::capability::FeatureGateState, FindingCode>,
    origin: GateResolutionOrigin,
}
impl GateWitness {
    /// Exact resolved state or fixed failure category.
    /// # Errors
    /// Returns the fixed category when supplied gate evidence cannot establish a state.
    pub const fn resolution(&self) -> Result<crate::capability::FeatureGateState, FindingCode> {
        self.resolution
    }
    /// Exact override/default/no-evidence origin.
    #[must_use]
    pub const fn origin(&self) -> GateResolutionOrigin {
        self.origin
    }
}
/// Complete immutable validation context, never an observed cluster configuration.
#[derive(Clone, Debug)]
pub struct GraphTargetWitness {
    profile: crate::capability::TargetProfile,
    resolved_gates: BTreeMap<crate::capability::FeatureGateId, GateWitness>,
    ledger_sha256: [u8; 32],
}
impl PartialEq for GraphTargetWitness {
    fn eq(&self, other: &Self) -> bool {
        self.profile.kubernetes == other.profile.kubernetes
            && self.profile.renderer == other.profile.renderer
            && self.profile.feature_gates.states == other.profile.feature_gates.states
            && self.profile.feature_gates.resolution == other.profile.feature_gates.resolution
            && self.resolved_gates == other.resolved_gates
            && self.ledger_sha256 == other.ledger_sha256
    }
}
impl Eq for GraphTargetWitness {}
impl GraphTargetWitness {
    fn new(profile: &crate::capability::TargetProfile) -> Self {
        use crate::capability::{FeatureGateId, FeatureGateResolution};
        let resolved_gates = FeatureGateId::ALL
            .iter()
            .map(|gate| {
                let origin = if profile.feature_gates.states.contains_key(gate) {
                    GateResolutionOrigin::ExplicitOverride
                } else {
                    match profile.feature_gates.resolution {
                        FeatureGateResolution::RequireExplicit => GateResolutionOrigin::NoEvidence,
                        FeatureGateResolution::ResolveFromEvidence(evidence) => {
                            GateResolutionOrigin::DocumentedDefault { evidence }
                        }
                    }
                };
                (
                    *gate,
                    GateWitness {
                        resolution: profile
                            .feature_gates
                            .resolve(*gate, profile.kubernetes)
                            .map_err(|finding| finding.code),
                        origin,
                    },
                )
            })
            .collect();
        Self {
            profile: profile.clone(),
            resolved_gates,
            ledger_sha256: ledger_digest(crate::capability::capability_ledger_bytes()),
        }
    }
    /// Complete original explicit target profile.
    #[must_use]
    pub const fn profile(&self) -> &crate::capability::TargetProfile {
        &self.profile
    }
    /// Every finite gate's resolved state and evidence origin.
    #[must_use]
    pub const fn resolved_gates(&self) -> &BTreeMap<crate::capability::FeatureGateId, GateWitness> {
        &self.resolved_gates
    }
    /// SHA-256 of the exact embedded capability ledger bytes.
    #[must_use]
    pub const fn ledger_sha256(&self) -> &[u8; 32] {
        &self.ledger_sha256
    }
}
/// Core-bound contribution from its actual supplying resource and source document.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FactEvidence {
    /// Actual supplying input-local resource.
    pub resource: ResourceId,
    /// Immutable supplying source/document coordinates.
    pub source: crate::model::SourceRef,
    /// Exact supplied object/template/key subject.
    pub subject: GraphSubject,
    /// Resource-relative contribution path.
    pub path: FieldPath,
    /// Original or generated field origin.
    pub origin: crate::source::ValueOrigin,
    /// Original position only for unchanged source evidence.
    pub position: Option<crate::diagnostic::SourcePosition>,
    /// Shared complete checked target, if explicitly supplied.
    pub checked_target: Option<std::sync::Arc<GraphTargetWitness>>,
}
/// Supplied PVC matching a future identity rule, without a binding/readiness claim.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ClaimMatch {
    /// Actual supplied PVC.
    pub resource: ResourceId,
    /// Immutable supplying field contributions.
    pub evidence: Vec<FactEvidence>,
    /// Exact supplied ownership result.
    pub ownership: ClaimOwnership,
}
fn ledger_digest(bytes: &[u8]) -> [u8; 32] {
    let mut state: [u32; 8] = [
        0x6a09_e667,
        0xbb67_ae85,
        0x3c6e_f372,
        0xa54f_f53a,
        0x510e_527f,
        0x9b05_688c,
        0x1f83_d9ab,
        0x5be0_cd19,
    ];
    let mut chunks = bytes.chunks_exact(64);
    for block in &mut chunks {
        digest_block(block, &mut state);
    }
    let remainder = chunks.remainder();
    let mut tail = [0u8; 128];
    tail[..remainder.len()].copy_from_slice(remainder);
    tail[remainder.len()] = 128;
    let end = if remainder.len() < 56 { 64 } else { 128 };
    let bits = u64::try_from(bytes.len()).unwrap_or(u64::MAX).wrapping_mul(8);
    tail[end - 8..end].copy_from_slice(&bits.to_be_bytes());
    for block in tail[..end].chunks_exact(64) {
        digest_block(block, &mut state);
    }
    let mut digest = [0u8; 32];
    for (word, slot) in state.iter().zip(digest.chunks_exact_mut(4)) {
        slot.copy_from_slice(&word.to_be_bytes());
    }
    digest
}
fn digest_block(block: &[u8], state: &mut [u32; 8]) {
    const ROUND: [u32; 64] = [
        0x428a_2f98,
        0x7137_4491,
        0xb5c0_fbcf,
        0xe9b5_dba5,
        0x3956_c25b,
        0x59f1_11f1,
        0x923f_82a4,
        0xab1c_5ed5,
        0xd807_aa98,
        0x1283_5b01,
        0x2431_85be,
        0x550c_7dc3,
        0x72be_5d74,
        0x80de_b1fe,
        0x9bdc_06a7,
        0xc19b_f174,
        0xe49b_69c1,
        0xefbe_4786,
        0x0fc1_9dc6,
        0x240c_a1cc,
        0x2de9_2c6f,
        0x4a74_84aa,
        0x5cb0_a9dc,
        0x76f9_88da,
        0x983e_5152,
        0xa831_c66d,
        0xb003_27c8,
        0xbf59_7fc7,
        0xc6e0_0bf3,
        0xd5a7_9147,
        0x06ca_6351,
        0x1429_2967,
        0x27b7_0a85,
        0x2e1b_2138,
        0x4d2c_6dfc,
        0x5338_0d13,
        0x650a_7354,
        0x766a_0abb,
        0x81c2_c92e,
        0x9272_2c85,
        0xa2bf_e8a1,
        0xa81a_664b,
        0xc24b_8b70,
        0xc76c_51a3,
        0xd192_e819,
        0xd699_0624,
        0xf40e_3585,
        0x106a_a070,
        0x19a4_c116,
        0x1e37_6c08,
        0x2748_774c,
        0x34b0_bcb5,
        0x391c_0cb3,
        0x4ed8_aa4a,
        0x5b9c_ca4f,
        0x682e_6ff3,
        0x748f_82ee,
        0x78a5_636f,
        0x84c8_7814,
        0x8cc7_0208,
        0x90be_fffa,
        0xa450_6ceb,
        0xbef9_a3f7,
        0xc671_78f2,
    ];
    let mut schedule = [0u32; 64];
    for (index, chunk) in block.chunks_exact(4).enumerate() {
        schedule[index] = u32::from_be_bytes([chunk[0], chunk[1], chunk[2], chunk[3]]);
    }
    for index in 16..64 {
        let left = schedule[index - 15];
        let right = schedule[index - 2];
        schedule[index] = schedule[index - 16]
            .wrapping_add(left.rotate_right(7) ^ left.rotate_right(18) ^ (left >> 3))
            .wrapping_add(schedule[index - 7])
            .wrapping_add(right.rotate_right(17) ^ right.rotate_right(19) ^ (right >> 10));
    }
    let mut work = *state;
    for (constant, message) in ROUND.iter().zip(schedule) {
        let first = work[7]
            .wrapping_add(work[4].rotate_right(6) ^ work[4].rotate_right(11) ^ work[4].rotate_right(25))
            .wrapping_add((work[4] & work[5]) ^ (!work[4] & work[6]))
            .wrapping_add(*constant)
            .wrapping_add(message);
        let second = (work[0].rotate_right(2) ^ work[0].rotate_right(13) ^ work[0].rotate_right(22))
            .wrapping_add((work[0] & work[1]) ^ (work[0] & work[2]) ^ (work[1] & work[2]));
        work.rotate_right(1);
        work[4] = work[4].wrapping_add(first);
        work[0] = first.wrapping_add(second);
    }
    for (word, extra) in state.iter_mut().zip(work) {
        *word = word.wrapping_add(extra);
    }
}

struct GraphBudget {
    remaining: std::cell::Cell<usize>,
    failed: std::cell::Cell<bool>,
    processing: crate::processing::NativeOperationBudget,
}
impl GraphBudget {
    fn new(processing: crate::processing::NativeOperationBudget) -> Self {
        Self {
            processing,
            remaining: std::cell::Cell::new(crate::source::ParseLimits::default().max_events),
            failed: std::cell::Cell::new(false),
        }
    }
    fn retain<T>(&self, count: usize) -> bool {
        self.processing.payload_array::<T>(count, Phase::Analysis).is_ok()
    }
    fn path_copy(&self, path: &FieldPath, copies: usize) -> bool {
        self.retain::<String>(path.0.len().saturating_mul(copies))
            && self
                .processing
                .payload_sizes(
                    path.0.iter().map(|part| part.len().saturating_mul(copies)),
                    Phase::Analysis,
                )
                .is_ok()
    }
    fn local_copy(&self, subject: &LocalSubject, copies: usize) -> bool {
        match subject {
            LocalSubject::Object => true,
            LocalSubject::Template { path, .. } => self.path_copy(path, copies),
        }
    }
    fn selector_work(&self, selector: &LabelSelector, labels: Option<&BTreeMap<String, String>>) -> bool {
        let mut bytes = 1_usize;
        if let Some(required) = selector.match_labels.value() {
            for (key, value) in required {
                if !self.take(1) {
                    return false;
                }
                bytes = bytes
                    .saturating_add(key.len())
                    .saturating_add(value.len())
                    .saturating_add(1);
            }
        }
        if let Some(required) = selector.match_expressions.value() {
            for requirement in required {
                if !self.take(1) {
                    return false;
                }
                bytes = bytes.saturating_add(requirement.key.len()).saturating_add(1);
                if let Some(values) = requirement.values.value() {
                    for value in values {
                        if !self.take(1) {
                            return false;
                        }
                        bytes = bytes.saturating_add(value.len()).saturating_add(1);
                    }
                }
            }
        }
        let mut label_bytes = 1_usize;
        if let Some(labels) = labels {
            for (key, value) in labels {
                if !self.take(1) {
                    return false;
                }
                label_bytes = label_bytes
                    .saturating_add(key.len())
                    .saturating_add(value.len())
                    .saturating_add(1);
            }
        }
        // Covers grammar validation, tree-map key comparisons and expression value comparisons.
        self.take(bytes.saturating_mul(label_bytes).saturating_mul(4))
    }
    fn take(&self, count: usize) -> bool {
        if self.failed.get() || self.processing.work(count, Phase::Analysis).is_err() || count > self.remaining.get() {
            self.failed.set(true);
            self.processing.fail(Phase::Analysis);
            false
        } else {
            self.remaining.set(self.remaining.get() - count);
            true
        }
    }
}
struct BoundedReferences<'a> {
    budget: &'a GraphBudget,
    references: Vec<Reference>,
    exhausted: bool,
}
impl ReferenceSink for BoundedReferences<'_> {
    fn exhausted(&self) -> bool {
        self.exhausted || self.budget.processing.exhausted()
    }
    fn push(&mut self, reference: Reference) {
        if self.budget.take(1)
            && self
                .budget
                .processing
                .payload_array::<Reference>(1, Phase::Analysis)
                .is_ok()
        {
            self.references.push(reference);
        } else {
            self.exhausted = true;
        }
    }
}
fn local_subject(resource: ResourceId, subject: &LocalSubject) -> GraphSubject {
    match subject {
        LocalSubject::Object => GraphSubject::Object { resource },
        LocalSubject::Template { path, template_kind } => GraphSubject::Template {
            resource,
            path: path.clone(),
            template_kind: *template_kind,
        },
    }
}
fn subject_resource(subject: &GraphSubject) -> ResourceId {
    match subject {
        GraphSubject::Object { resource }
        | GraphSubject::Template { resource, .. }
        | GraphSubject::Key { resource, .. }
        | GraphSubject::ServicePort { resource, .. } => *resource,
    }
}
fn subject_path(subject: &LocalSubject) -> FieldPath {
    match subject {
        LocalSubject::Object => FieldPath::default(),
        LocalSubject::Template { path, .. } => path.clone(),
    }
}
fn bind_claim(resource: ResourceId, draft: &ClaimPatternDraft) -> ClaimPattern {
    match draft {
        ClaimPatternDraft::StatefulSet {
            template_path,
            template_name,
            controller_name,
            replicas,
            start_ordinal,
        } => ClaimPattern::StatefulSet {
            template_path: template_path.clone(),
            template_name: template_name.clone(),
            controller_name: controller_name.clone(),
            replicas: replicas.clone(),
            start_ordinal: start_ordinal.clone(),
        },
        ClaimPatternDraft::PodEphemeral {
            pod_subject,
            volume_path,
            volume_name,
            pod_name,
            pod_uid,
        } => ClaimPattern::PodEphemeral {
            pod_subject: local_subject(resource, pod_subject),
            volume_path: volume_path.clone(),
            volume_name: volume_name.clone(),
            pod_name: pod_name.clone(),
            pod_uid: pod_uid.clone(),
        },
    }
}
fn contribution(
    budget: &GraphBudget,
    resources: &ResourceSet,
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    witness: Option<&std::sync::Arc<GraphTargetWitness>>,
    subject: GraphSubject,
    path: FieldPath,
) -> Option<FactEvidence> {
    let resource = subject_resource(&subject);
    if !budget.retain::<FactEvidence>(1) || !budget.path_copy(&path, 1) || !budget.take(resources.documents.len()) {
        return None;
    }
    let document = resources.documents.iter().find(|document| document.id == resource)?;
    let projection = projections.get(&resource)?;
    let field = document.effective_evidence(projection, &path, |before, after| {
        budget.take(tree_cost(before).saturating_add(tree_cost(after)))
    })?;
    Some(FactEvidence {
        resource,
        source: document.source,
        subject,
        path,
        origin: field.origin,
        position: field.position,
        checked_target: witness.cloned(),
    })
}
struct ProjectionBatch {
    projections: BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    identities: BTreeMap<ResourceId, ResourceIdentity>,
    facts: BTreeMap<ResourceId, Vec<NativeFact>>,
    failed: BTreeMap<ResourceId, ResourceIdentity>,
}
/// Charge one graph event for each visited node (including tagged wrappers)
/// and each mapping key, before visiting children. Scalar/key/tag bytes are
/// not read here: inherited projection primitives still charge their scans and
/// copies. Original trees already satisfy retained syntax/depth limits; this
/// short-circuiting walk allocates no traversal buffers and stops on exhaustion.
fn preflight_projection_events(node: &crate::syntax::TreeNode, budget: &GraphBudget) -> bool {
    use crate::syntax::TreeValue;
    if !budget.take(1) {
        return false;
    }
    match &node.value {
        TreeValue::Mapping(entries) => entries
            .iter()
            .all(|(_, child)| budget.take(1) && preflight_projection_events(child, budget)),
        TreeValue::Sequence(items) => items.iter().all(|child| preflight_projection_events(child, budget)),
        TreeValue::Tagged(_, child) => preflight_projection_events(child, budget),
        TreeValue::Null | TreeValue::Bool(_) | TreeValue::String(_) | TreeValue::Number(_) => true,
    }
}
fn project_documents(
    resources: &ResourceSet,
    target: Option<&crate::capability::TargetProfile>,
    collect: bool,
    collector: &mut BoundedReferences<'_>,
    graph: &mut WorkingGraph,
) -> ProjectionBatch {
    let budget = collector.budget;
    let construction = resources.encoding(target, budget.processing.clone());
    let mut projections = BTreeMap::new();
    let mut identities = BTreeMap::new();
    let mut facts = BTreeMap::new();
    let mut failed = BTreeMap::new();
    for document in &resources.documents {
        if graph.findings.failed() {
            break;
        }
        if !preflight_projection_events(&document.original, budget) {
            failed.insert(document.id, document.original_identity.clone());
            graph
                .findings
                .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis).for_resource(document.id));
            continue;
        }
        let projection = match document.project_in(target, Some(&construction)) {
            Ok(projection) => projection,
            Err(findings) => {
                failed.insert(document.id, document.original_identity.clone());
                graph.findings.extend(findings);
                continue;
            }
        };
        graph.findings.extend(projection.findings.clone());
        if document.decode.is_some() && projection.resource.is_none() {
            failed.insert(document.id, projection.identity.clone());
        }
        identities.insert(document.id, projection.identity.clone());
        if let (Some(native), Some(capability)) = (&projection.resource, &document.capability) {
            let ctx = registry::ProjectionContext::new_in(
                &projection.tree,
                &projection.identity.gvk,
                &document.evidence,
                target,
                capability,
                budget.processing.clone(),
            );
            let mut emitted = Vec::new();
            native.collect_native_facts(&ctx, &mut emitted);
            if budget.take(emitted.len()) {
                let mut seen = BTreeSet::new();
                let mut invalid = false;
                for fact in &mut emitted {
                    let signature = recheck_fact(&ctx, fact);
                    if !seen.insert(signature) {
                        invalid = true;
                    }
                }
                if invalid {
                    graph.findings.push(
                        Finding::error(FindingCode::InvalidRegistration, Phase::Analysis).for_resource(document.id),
                    );
                } else {
                    if collect {
                        for fact in &emitted {
                            if let NativeFact::ClaimExpectation { pattern, path } = fact {
                                collector.push(Reference {
                                    from: document.id,
                                    path: path.clone(),
                                    relation: RelationshipKind::Storage,
                                    target: ReferenceTarget::GeneratedClaims {
                                        pattern: bind_claim(document.id, pattern),
                                    },
                                    scope: ReferenceScope::SameNamespace,
                                });
                            }
                        }
                    }
                    facts.insert(document.id, emitted);
                }
            } else {
                collector.exhausted = true;
            }
            graph.findings.append_charged(
                ctx.take_findings()
                    .into_iter()
                    .map(|finding| finding.for_resource(document.id)),
            );
            if collect {
                let start = collector.references.len();
                native.collect_references(&construction.for_source(*document.evidence.limits()), collector);
                for reference in &mut collector.references[start..] {
                    reference.from = document.id;
                }
            }
        }
        if collect {
            collect_projected_owners(&projection.tree, document.id, collector, &mut graph.findings);
        }
        projections.insert(document.id, projection);
    }
    ProjectionBatch {
        projections,
        identities,
        facts,
        failed,
    }
}
fn recheck_fact(ctx: &registry::ProjectionContext<'_>, fact: &mut NativeFact) -> (u8, Option<KeyDomain>, FieldPath) {
    match fact {
        NativeFact::Keys { domain, state, path } => {
            *state = recheck_keys(ctx, *domain, path, state.clone());
            (0, Some(*domain), path.clone())
        }
        NativeFact::ServiceHeadless { state, path } => {
            *state = ctx.state(path, state.clone());
            if ctx.gvk.group.is_some() || ctx.gvk.kind != "Service" || path.0 != ["spec", "clusterIP"] {
                *state = FactState::Unadmitted;
            } else if matches!(state, FactState::Known(_)) {
                *state = match ctx.tree.get_path(path).and_then(crate::syntax::TreeNode::as_str) {
                    Some("None") => FactState::Known(true),
                    Some(address) if address.parse::<std::net::IpAddr>().is_ok() => FactState::Known(false),
                    _ => FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
                };
            }
            (1, None, path.clone())
        }
        NativeFact::SelectorSubject { subject, labels } => {
            *labels = recheck_labels(ctx, subject, labels.clone());
            (2, None, subject_path(subject))
        }
        NativeFact::ContainerPorts { subject, ports } => {
            *ports = recheck_ports(ctx, subject, ports.clone());
            (3, None, subject_path(subject))
        }
        NativeFact::ServicePorts { state, path } => {
            *state = recheck_service_ports(
                ctx,
                path,
                std::mem::replace(state, FactState::Unknown(FactGap::IncompleteSuppliedEvidence)),
            );
            (5, None, path.clone())
        }
        NativeFact::ClaimExpectation { path, .. } => (4, None, path.clone()),
    }
}
fn collect_projected_owners(
    tree: &crate::syntax::TreeNode,
    id: ResourceId,
    collector: &mut BoundedReferences<'_>,
    findings: &mut crate::processing::ProcessingReport,
) {
    let owner_path = FieldPath(vec!["metadata".into(), "ownerReferences".into()]);
    if let Some(owners) = tree.get_path(&owner_path) {
        if let Some(items) = owners.as_sequence() {
            for (index, owner) in items.iter().enumerate() {
                if findings.failed() || !collector.budget.take(1) {
                    break;
                }
                let path = owner_path.child(index.to_string());
                match owner_reference(owner, path.clone(), id) {
                    Ok(reference) => collector.push(reference),
                    Err(finding) => findings.push(finding),
                }
                if let Some(entries) = owner.as_mapping() {
                    for (key, node) in entries {
                        if !matches!(
                            key.as_str(),
                            "apiVersion" | "kind" | "name" | "uid" | "controller" | "blockOwnerDeletion"
                        ) {
                            let mut finding = Finding::warning(FindingCode::UnadmittedField, Phase::Analysis)
                                .for_resource(id)
                                .at_path(path.child(key));
                            finding.source = node.start;
                            findings.push(finding);
                        }
                    }
                }
            }
        } else if owners.value != crate::syntax::TreeValue::Null {
            findings.push(owner_error(owners, owner_path, id));
        }
    }
}
fn check_claim_collisions(
    index: &GraphIndex<'_>,
    references: &[Reference],
    findings: &mut crate::processing::ProcessingReport,
) {
    let GraphIndex {
        resources,
        projections,
        identities,
        context,
        witness,
        budget,
        ..
    } = index;
    // Ephemeral name composition can collide even when supplied Pod identities differ.
    // Keys remain private and no owner equality or runtime existence is inferred.
    let mut claims = BTreeMap::<(String, String), Vec<(ResourceId, FieldPath)>>::new();
    for reference in references {
        if findings.failed() {
            break;
        }
        let ReferenceTarget::GeneratedClaims {
            pattern:
                ClaimPattern::PodEphemeral {
                    pod_subject: GraphSubject::Object { .. },
                    volume_path,
                    volume_name: Presence::Value(volume),
                    pod_name: Presence::Value(pod),
                    ..
                },
        } = &reference.target
        else {
            continue;
        };
        if !budget.take(resources.documents.len().saturating_add(1)) {
            break;
        }
        if claim_admission(
            budget,
            resources,
            projections,
            reference,
            match &reference.target {
                ReferenceTarget::GeneratedClaims { pattern } => pattern,
                _ => continue,
            },
            *witness,
        )
        .is_err()
        {
            continue;
        }
        let Ok(Some(namespace)) = selected_namespace(reference, identities, context) else {
            continue;
        };
        let length = namespace
            .len()
            .saturating_add(pod.native_value().len())
            .saturating_add(volume.native_value().len())
            .saturating_add(1);
        if !budget.take(length) {
            break;
        }
        let suppliers = claims
            .entry((
                namespace.to_owned(),
                format!("{}-{}", pod.native_value(), volume.native_value()),
            ))
            .or_default();
        let supplier = (reference.from, volume_path.clone());
        if !suppliers.contains(&supplier) {
            suppliers.push(supplier);
        }
    }
    for suppliers in claims.into_values().filter(|suppliers| suppliers.len() > 1) {
        for (resource, path) in suppliers {
            findings.push(
                Finding::error(FindingCode::ClaimIdentityCollision, Phase::Analysis)
                    .for_resource(resource)
                    .at_path(path),
            );
        }
    }
}
impl GraphIndex<'_> {
    fn resolve_reference(&self, reference: &Reference, evidence: &mut Vec<FactEvidence>) -> Resolution {
        match &reference.target {
            ReferenceTarget::CheckedObject {
                gvk,
                name,
                predicate,
                optional,
            } => self.checked_object(reference, gvk, name, predicate.as_ref(), optional, evidence),
            ReferenceTarget::SubjectSelector {
                kinds,
                selector,
                selection,
            } => self.select_subjects(reference, kinds, selector, *selection, evidence),
            ReferenceTarget::GroupKindName { group, kind, name } => {
                self.group_kind_name(reference, group, kind, name, evidence)
            }
            ReferenceTarget::NetworkPolicyPeer {
                namespace_selector,
                pod_selector,
            } => self.policy_peer(reference, namespace_selector, pod_selector, evidence),
            ReferenceTarget::NetworkPolicyAllPeers { presence } => self.all_peers(reference, *presence),
            ReferenceTarget::NamedServiceTargetPort {
                selector,
                name,
                protocol,
            } => self.named_target_port(reference, selector, name.native_value(), protocol, evidence),
            ReferenceTarget::GeneratedClaims { pattern } => self.evaluate_claims(reference, pattern, evidence),
            _ => {
                if self.failed.values().any(|identity| match &reference.target {
                    ReferenceTarget::Exact { gvk: Some(gvk), .. } | ReferenceTarget::Owner { gvk, .. } => {
                        identity.gvk.group == gvk.group && identity.gvk.kind == gvk.kind
                    }
                    ReferenceTarget::SuppliedCustomResourceVersion { descriptor } => {
                        identity.gvk == *descriptor.crd_gvk()
                    }
                    ReferenceTarget::LabelSelector { kinds, .. } => {
                        kinds.iter().any(|kind| kind.as_str() == identity.gvk.kind)
                    }
                    _ => false,
                }) {
                    Resolution::Unsupported(SafeReason::InvalidIdentity)
                } else {
                    resolve_one(
                        self.resources,
                        self.identities,
                        reference,
                        self.context,
                        self.projections,
                    )
                }
            }
        }
    }
}
fn current_custom_descriptor(
    index: &GraphIndex<'_>,
    reference: &Reference,
    records: &[crate::resources::extensions::custom_documents::CustomDocumentGraphRecord],
) -> bool {
    let ReferenceTarget::SuppliedCustomResourceVersion { descriptor } = &reference.target else {
        return true;
    };
    for record in records {
        if !index.budget.take(1) {
            return false;
        }
        if record.resource_id() != reference.from {
            continue;
        }
        if !index.budget.take(index.resources.documents().len()) {
            return false;
        }
        let (Some(current), Some(document)) = (
            record.descriptor(),
            index
                .resources
                .documents()
                .iter()
                .find(|document| document.id == reference.from),
        ) else {
            return false;
        };
        return document
            .field_decode_context(&index.budget.processing, Phase::Analysis)
            .and_then(|fields| descriptor.matches_current(current, &fields))
            .unwrap_or(false);
    }
    false
}
fn contribute_custom_descriptor(
    reference: &Reference,
    resolution: &Resolution,
    index: &GraphIndex<'_>,
    evidence: &mut Vec<FactEvidence>,
) {
    if matches!(resolution, Resolution::Resolved(_)) {
        if let ReferenceTarget::SuppliedCustomResourceVersion { descriptor } = &reference.target {
            let resource = descriptor.resource_id();
            for path in [descriptor.version_path(), descriptor.schema_path()] {
                if let Some(field) = contribution(
                    index.budget,
                    index.resources,
                    index.projections,
                    index.witness,
                    GraphSubject::Object { resource },
                    path.clone(),
                ) {
                    evidence.push(field);
                }
            }
        }
    }
}
fn resolve_edges(index: &GraphIndex<'_>, references: Vec<Reference>, graph: &mut WorkingGraph) {
    let resources = index.resources;
    let projections = index.projections;
    let witness = index.witness;
    let budget = index.budget;
    for reference in references {
        if graph.findings.failed() {
            break;
        }
        let mut evidence = contribution(
            budget,
            resources,
            projections,
            witness,
            GraphSubject::Object {
                resource: reference.from,
            },
            reference.path.clone(),
        )
        .into_iter()
        .collect::<Vec<_>>();
        let mut resolution = if budget.take(1) {
            if current_custom_descriptor(index, &reference, &graph.custom_documents) {
                index.resolve_reference(&reference, &mut evidence)
            } else {
                Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))
            }
        } else {
            graph
                .findings
                .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
            Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))
        };
        for resource in match &resolution {
            Resolution::Resolved(ids) | Resolution::Ambiguous(ids) => ids.as_slice(),
            _ => &[],
        } {
            if let Some(field) = contribution(
                budget,
                resources,
                projections,
                witness,
                GraphSubject::Object { resource: *resource },
                FieldPath(vec!["metadata".into(), "name".into()]),
            ) {
                evidence.push(field);
            }
        }
        contribute_custom_descriptor(&reference, &resolution, index, &mut evidence);
        if budget.failed.get() {
            resolution = Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let code = match &resolution {
            Resolution::Missing => Some(
                if matches!(
                    reference.target,
                    ReferenceTarget::LabelSelector { .. } | ReferenceTarget::SubjectSelector { .. }
                ) {
                    FindingCode::SelectorNoMatches
                } else {
                    FindingCode::MissingReference
                },
            ),
            Resolution::MissingKey { .. }
            | Resolution::MissingServicePort { .. }
            | Resolution::MissingContainerPort { .. } => Some(FindingCode::MissingReference),
            Resolution::AmbiguousServicePorts(_) | Resolution::Ambiguous(_) => Some(FindingCode::AmbiguousReference),
            Resolution::External(_) => Some(FindingCode::ExternalPrerequisite),
            Resolution::Unsupported(SafeReason::OperatorOwned) => Some(FindingCode::OperatorOwned),
            Resolution::Unsupported(SafeReason::ScopeUnknown) => Some(FindingCode::ScopeUnknown),
            Resolution::Unsupported(SafeReason::FactUnadmitted) => Some(FindingCode::UnadmittedField),
            Resolution::Unsupported(_) | Resolution::Incompatible { .. } => Some(FindingCode::NativeFieldInvalid),
            _ => None,
        };
        if let Some(code) = code {
            graph.findings.push(
                Finding::warning(code, Phase::Analysis)
                    .for_resource(reference.from)
                    .at_path(reference.path.clone()),
            );
        }
        if graph.findings.failed() {
            break;
        }
        graph.edges.push(ResolvedReference {
            reference,
            resolution,
            evidence,
        });
    }
}

fn collect_custom_documents(
    resources: &ResourceSet,
    target: Option<&crate::capability::TargetProfile>,
    budget: &GraphBudget,
    collector: &mut BoundedReferences<'_>,
    graph: &mut WorkingGraph,
) {
    if !budget.processing.exhausted() && !budget.failed.get() {
        match crate::resources::extensions::custom_documents::check_custom_documents_in(
            resources,
            target,
            &budget.processing,
        ) {
            Ok(results) => {
                if budget.take(results.len())
                    && budget
                        .processing
                        .payload_array::<crate::resources::extensions::custom_documents::CustomDocumentGraphRecord>(
                            results.len(),
                            Phase::Analysis,
                        )
                        .is_ok()
                    && graph.custom_documents.try_reserve(results.len()).is_ok()
                {
                    for result in results {
                        graph.custom_documents.push(result.graph_record());
                        collector.push(result.controller_prerequisite());
                        if let Some(reference) = result.crd_version_reference() {
                            collector.push(reference);
                        }
                    }
                } else {
                    graph
                        .findings
                        .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
                }
            }
            Err(finding) => graph.findings.push(finding),
        }
    }
}
fn analyze(
    resources: &ResourceSet,
    supplied: Option<&[Reference]>,
    context: &ReferenceContext,
    target: Option<&crate::capability::TargetProfile>,
) -> ReferenceGraph {
    let processing = resources.operation(context.processing);
    let budget = GraphBudget::new(processing.clone());
    let witness = target.map(|target| std::sync::Arc::new(GraphTargetWitness::new(target)));
    let mut graph = WorkingGraph {
        edges: Vec::new(),
        findings: crate::processing::ProcessingReport::new(processing, Phase::Analysis),
        custom_documents: Vec::new(),
        target: witness.clone(),
    };
    graph
        .findings
        .extend(target.map_or_else(Vec::new, crate::capability::TargetProfile::findings));
    let mut collector = BoundedReferences {
        budget: &budget,
        references: Vec::new(),
        exhausted: false,
    };
    if !budget.take(resources.documents.len()) {
        graph
            .findings
            .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
        return graph.finish();
    }
    let mut ids = BTreeSet::new();
    for document in &resources.documents {
        if !ids.insert(document.id) {
            graph
                .findings
                .push(Finding::error(FindingCode::InvalidIdentity, Phase::Analysis).for_resource(document.id));
            return graph.finish();
        }
    }
    let ProjectionBatch {
        projections,
        identities,
        facts,
        failed,
    } = project_documents(resources, target, supplied.is_none(), &mut collector, &mut graph);
    collect_custom_documents(resources, target, &budget, &mut collector, &mut graph);
    if let Some(refs) = supplied {
        for reference in refs {
            if collector.exhausted() {
                break;
            }
            collector.push(reference.clone());
        }
    }
    if collector.exhausted {
        graph
            .findings
            .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
    }
    let mut collision = BTreeMap::<crate::model::CollisionKey, Vec<ResourceId>>::new();
    for (resource, identity) in &identities {
        if let Some(key) = identity.collision_key() {
            collision.entry(key).or_default().push(*resource);
        }
    }
    for ids in collision.values().filter(|ids| ids.len() > 1) {
        for resource in ids {
            graph
                .findings
                .push(Finding::error(FindingCode::DuplicateIdentity, Phase::Analysis).for_resource(*resource));
        }
    }
    let index = GraphIndex {
        resources,
        projections: &projections,
        identities: &identities,
        facts: &facts,
        failed: &failed,
        context,
        witness: witness.as_ref(),
        budget: &budget,
    };
    check_claim_collisions(&index, &collector.references, &mut graph.findings);
    resolve_edges(&index, collector.references, &mut graph);
    find_cycles(&identities, &mut graph, &budget);
    if budget.failed.get() {
        graph
            .findings
            .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
    }
    graph.finish()
}
fn recheck_keys(
    ctx: &registry::ProjectionContext<'_>,
    domain: KeyDomain,
    path: &FieldPath,
    state: FactState<KeyNames>,
) -> FactState<KeyNames> {
    // ConfigMap and Secret inventories aggregate separate root maps. The empty
    // aggregate path is not a native field; each exact map/key is admitted below.
    let state = if path.0.is_empty() {
        state
    } else {
        ctx.state(path, state)
    };
    if let FactState::Known(keys) = &state {
        let fields: &[&str] = match domain {
            KeyDomain::ConfigMapText => &["data"],
            KeyDomain::ConfigMapTextOrBinary => &["data", "binaryData"],
            KeyDomain::Secret => &["data", "stringData"],
        };
        let valid_kind = ctx.gvk.group.is_none()
            && match domain {
                KeyDomain::Secret => ctx.gvk.kind == "Secret",
                _ => ctx.gvk.kind == "ConfigMap",
            };
        if !valid_kind {
            return FactState::Unadmitted;
        }
        let mut expected = BTreeSet::new();
        for field in fields {
            let map_path = FieldPath(vec![(*field).into()]);
            match ctx.state(&map_path, FactState::Known(())) {
                FactState::Known(()) => {}
                FactState::Unknown(gap) => return FactState::Unknown(gap),
                FactState::Unadmitted => return FactState::Unadmitted,
            }
            if let Some(node) = ctx.tree.get(field) {
                let Some(entries) = node.as_mapping() else {
                    return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
                };
                for (key, _) in entries {
                    expected.insert(key);
                }
            }
        }
        if !expected.iter().copied().eq(keys.0.keys()) {
            return FactState::Unadmitted;
        }
        for (name, path) in &keys.0 {
            let valid_domain = path.0.len() == 2 && fields.iter().any(|field| path.0[0] == *field);
            if !valid_domain
                || path.0.last() != Some(name)
                || ctx.tree.get_path(path).is_none()
                || !matches!(ctx.state(path, FactState::Known(())), FactState::Known(()))
            {
                return FactState::Unadmitted;
            }
        }
    }
    state
}
fn recheck_ports(
    ctx: &registry::ProjectionContext<'_>,
    subject: &LocalSubject,
    state: FactState<Vec<PortFact>>,
) -> FactState<Vec<PortFact>> {
    if let FactState::Known(ports) = &state {
        let base = subject_path(subject);
        for port in ports {
            if !port.container_port_path.0.starts_with(&base.0)
                || !(1..=65535).contains(&port.container_port)
                || port
                    .protocol
                    .value()
                    .is_some_and(|protocol| !matches!(protocol.as_str(), "TCP" | "UDP" | "SCTP"))
                || matches!(port.protocol, Presence::Null)
            {
                return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
            }
            let Some((field, parent)) = port.container_port_path.0.split_last() else {
                return FactState::Unadmitted;
            };
            if field != "containerPort"
                || port.name_path != FieldPath(parent.to_vec()).child("name")
                || port.protocol_path != FieldPath(parent.to_vec()).child("protocol")
            {
                return FactState::Unadmitted;
            }
            let actual = ctx.tree.get_path(&port.container_port_path).and_then(|node| {
                if let crate::syntax::TreeValue::Number(value) = &node.value {
                    value.parse::<i32>().ok()
                } else {
                    None
                }
            });
            if actual != Some(port.container_port) {
                return FactState::Unadmitted;
            }
            for (path, value) in [(&port.name_path, &port.name), (&port.protocol_path, &port.protocol)] {
                let actual = match ctx.tree.get_path(path) {
                    None => Presence::Absent,
                    Some(node) if node.value == crate::syntax::TreeValue::Null => Presence::Null,
                    Some(node) => match node.as_str() {
                        Some(value) => Presence::Value(value.to_owned()),
                        None => return FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
                    },
                };
                if &actual != value {
                    return FactState::Unadmitted;
                }
            }
            for path in [&port.name_path, &port.container_port_path, &port.protocol_path] {
                match ctx.state(path, FactState::Known(())) {
                    FactState::Known(()) => {}
                    FactState::Unknown(gap) => return FactState::Unknown(gap),
                    FactState::Unadmitted => return FactState::Unadmitted,
                }
            }
        }
    }
    state
}
fn find_cycles(identities: &BTreeMap<ResourceId, ResourceIdentity>, graph: &mut WorkingGraph, budget: &GraphBudget) {
    let mut adjacency = BTreeMap::<ResourceId, Vec<ResourceId>>::new();
    for edge in &graph.edges {
        if edge.reference.relation == RelationshipKind::Selector
            || matches!(edge.reference.target, ReferenceTarget::GeneratedClaims { .. })
        {
            continue;
        }
        match &edge.resolution {
            Resolution::Resolved(ids) => adjacency.entry(edge.reference.from).or_default().extend(ids),
            Resolution::ResolvedSubjects(subjects) => {
                for subject in subjects {
                    if let GraphSubject::Object { resource } = subject {
                        adjacency.entry(edge.reference.from).or_default().push(*resource);
                    }
                }
            }
            _ => {}
        }
    }
    for id in identities.keys() {
        if graph.findings.failed() {
            break;
        }
        let mut pending = adjacency.get(id).cloned().unwrap_or_default();
        let mut visited = BTreeSet::new();
        while let Some(next) = pending.pop() {
            if !budget.take(1) {
                graph
                    .findings
                    .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis));
                return;
            }
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
}

fn unavailable<T>(state: &FactState<T>) -> Option<SafeReason> {
    match state {
        FactState::Known(_) => None,
        FactState::Unknown(gap) => Some(SafeReason::FactUnknown(*gap)),
        FactState::Unadmitted => Some(SafeReason::FactUnadmitted),
    }
}
fn selected_namespace<'a>(
    reference: &'a Reference,
    identities: &'a BTreeMap<ResourceId, ResourceIdentity>,
    context: &'a ReferenceContext,
) -> Result<Option<&'a str>, SafeReason> {
    namespace(
        reference,
        identities.get(&reference.from).ok_or(SafeReason::InvalidIdentity)?,
        context,
    )
}
fn in_namespace(identity: &ResourceIdentity, selected: Option<&str>, context: &ReferenceContext) -> bool {
    identity.scope.namespaced() == Some(selected.is_some())
        && (selected.is_none()
            || identity
                .namespace
                .value()
                .map(String::as_str)
                .or(context.default_namespace.as_deref())
                == selected)
}
// Supplied-reference syntax envelopes do not infer target create/gate policy.
fn checked_reference_name(gvk: &GroupVersionKind, name: &str) -> bool {
    if name.is_empty() {
        return false;
    }
    if (gvk.group.as_deref() == Some("rbac.authorization.k8s.io")
        && matches!(
            gvk.kind.as_str(),
            "Role" | "RoleBinding" | "ClusterRole" | "ClusterRoleBinding"
        ))
        || (gvk.group.as_deref() == Some("policy") && gvk.kind == "PodDisruptionBudget")
    {
        return !matches!(name, "." | "..") && !name.bytes().any(|byte| matches!(byte, b'/' | b'%'));
    }
    if gvk.group.is_none() && matches!(gvk.kind.as_str(), "Namespace" | "Service") {
        return crate::value::dns_label(name);
    }
    name.len() <= 253
        && name.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && part.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && part.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}
fn checked_reference_key(key: &str) -> bool {
    !key.is_empty()
        && key.len() <= 253
        && key != "."
        && !key.starts_with("..")
        && key
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
}
impl GraphIndex<'_> {
    fn checked_object(
        &self,
        reference: &Reference,
        gvk: &GroupVersionKind,
        name: &str,
        predicate: Option<&ReferencePredicate>,
        optional: &Presence<bool>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let resources = self.resources;
        let projections = self.projections;
        let identities = self.identities;
        let context = self.context;
        let witness = self.witness;
        let budget = self.budget;

        if !checked_reference_name(gvk, name) {
            return Resolution::Unsupported(SafeReason::InvalidIdentity);
        }
        if predicate.is_some_and(|predicate| {
            matches!(predicate, ReferencePredicate::KeyExists { key, .. } if !checked_reference_key(key.native_value()))
        }) || matches!(optional, Presence::Null) {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        if let Some(ReferencePredicate::ServicePortExists { port }) = predicate {
            if let Err(reason) = self.check_backend_port(reference, name, port, evidence) {
                return Resolution::Unsupported(reason);
            }
        }
        let namespace = match selected_namespace(reference, identities, context) {
            Ok(namespace) => namespace,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        if crate::capability::builtin_scope(gvk).and_then(crate::model::ResourceScope::namespaced)
            != Some(namespace.is_some())
        {
            return Resolution::Unsupported(SafeReason::ScopeUnknown);
        }
        let mut matches = Vec::new();
        for (id, identity) in identities {
            if !budget.take(1) {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            if identity.gvk.group == gvk.group
                && identity.gvk.kind == gvk.kind
                && identity.name.value().is_some_and(|value| value == name)
                && in_namespace(identity, namespace, context)
            {
                matches.push(*id);
            }
        }
        if matches.len() > 1 {
            return Resolution::Ambiguous(matches);
        }
        if self
            .failed
            .values()
            .any(|identity| identity.gvk.group == gvk.group && identity.gvk.kind == gvk.kind)
        {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let Some(object) = matches.first().copied() else {
            return if optional.value() == Some(&true) {
                Resolution::OptionalMissing(MissingSubject::Object)
            } else {
                Resolution::Missing
            };
        };
        let subject = GraphSubject::Object { resource: object };
        if let Some(field) = contribution(
            budget,
            resources,
            projections,
            witness,
            subject.clone(),
            FieldPath(vec!["metadata".into(), "name".into()]),
        ) {
            evidence.push(field);
        }
        if let Some(projection) = projections.get(&object) {
            if !projection.findings.is_empty() {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
        }
        self.checked_predicate(gvk, object, subject, predicate, optional, evidence)
    }
    fn checked_predicate(
        &self,
        gvk: &GroupVersionKind,
        object: ResourceId,
        subject: GraphSubject,
        predicate: Option<&ReferencePredicate>,
        optional: &Presence<bool>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let facts = self.facts;
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let witness = self.witness;
        match predicate {
            None => Resolution::ResolvedSubjects(vec![subject]),
            Some(predicate @ ReferencePredicate::KeyExists { .. }) => {
                self.checked_key(gvk, object, subject, predicate, optional, evidence)
            }
            Some(ReferencePredicate::ServicePortExists { port }) => {
                self.service_front_port(gvk, object, port, evidence)
            }
            Some(ReferencePredicate::HeadlessService) => {
                if gvk.group.is_some() || gvk.kind != "Service" {
                    return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
                }
                let Some((state, path)) = facts.get(&object).into_iter().flatten().find_map(|fact| {
                    if let NativeFact::ServiceHeadless { state, path } = fact {
                        Some((state, path))
                    } else {
                        None
                    }
                }) else {
                    return Resolution::Unsupported(SafeReason::FactUnadmitted);
                };
                if let Some(field) =
                    contribution(budget, resources, projections, witness, subject.clone(), path.clone())
                {
                    evidence.push(field);
                }
                match state {
                    FactState::Known(true) => Resolution::ResolvedSubjects(vec![subject]),
                    FactState::Known(false) => Resolution::Incompatible {
                        subject,
                        reason: PredicateMismatch::HeadlessRequired,
                    },
                    _ => Resolution::Unsupported(unavailable(state).unwrap_or(SafeReason::FactUnadmitted)),
                }
            }
        }
    }
    fn checked_key(
        &self,
        gvk: &GroupVersionKind,
        object: ResourceId,
        subject: GraphSubject,
        predicate: &ReferencePredicate,
        optional: &Presence<bool>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let ReferencePredicate::KeyExists { domain, key } = predicate else {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        };
        let facts = self.facts;
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let witness = self.witness;
        let valid_kind = match domain {
            KeyDomain::ConfigMapText | KeyDomain::ConfigMapTextOrBinary => {
                gvk.group.is_none() && gvk.kind == "ConfigMap"
            }
            KeyDomain::Secret => gvk.group.is_none() && gvk.kind == "Secret",
        };
        if !valid_kind {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        }
        let Some((state, path)) = facts.get(&object).into_iter().flatten().find_map(|fact| {
            if let NativeFact::Keys {
                domain: candidate,
                state,
                path,
            } = fact
            {
                (*candidate == *domain).then_some((state, path))
            } else {
                None
            }
        }) else {
            return Resolution::Unsupported(SafeReason::FactUnadmitted);
        };
        if let Some(reason) = unavailable(state) {
            return Resolution::Unsupported(reason);
        }
        if let FactState::Known(names) = state {
            if let Some(path) = names.0.get(key.native_value()) {
                let subject = GraphSubject::Key {
                    resource: object,
                    domain: *domain,
                    key: key.clone(),
                };
                if let Some(field) =
                    contribution(budget, resources, projections, witness, subject.clone(), path.clone())
                {
                    evidence.push(field);
                }
                Resolution::ResolvedSubjects(vec![subject])
            } else {
                if let Some(field) = contribution(budget, resources, projections, witness, subject, path.clone()) {
                    evidence.push(field);
                }
                if optional.value() == Some(&true) {
                    Resolution::OptionalMissing(MissingSubject::Key {
                        object,
                        domain: *domain,
                        key: key.clone(),
                    })
                } else {
                    Resolution::MissingKey {
                        object,
                        domain: *domain,
                        key: key.clone(),
                    }
                }
            }
        } else {
            Resolution::Unsupported(SafeReason::FactUnadmitted)
        }
    }
}

struct SelectedSubjects {
    matched: Vec<GraphSubject>,
    gaps: Vec<SubjectGap>,
}
fn pod_template_owner(identity: &ResourceIdentity) -> bool {
    matches!(
        (identity.gvk.group.as_deref(), identity.gvk.kind.as_str()),
        (None, "Pod" | "ReplicationController")
            | (Some("apps"), "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet")
            | (Some("batch"), "Job" | "CronJob")
    )
}
impl GraphIndex<'_> {
    fn select_subjects(
        &self,
        reference: &Reference,
        kinds: &[KindId],
        selector: &LabelSelector,
        selection: SubjectSelection,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let projections = self.projections;
        let identities = self.identities;
        let context = self.context;
        let budget = self.budget;
        let facts = self.facts;

        if !budget.selector_work(selector, None)
            || !budget.retain::<SubjectGap>(self.failed.len().saturating_add(identities.len()))
        {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        if selector.validate().is_err() {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        }
        let namespace = match selected_namespace(reference, identities, context) {
            Ok(namespace) => namespace,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        let mut result = SelectedSubjects {
            matched: Vec::new(),
            gaps: self
                .failed
                .iter()
                .filter(|(_, identity)| {
                    kinds.iter().any(|kind| kind.as_str() == identity.gvk.kind)
                        || selection == SubjectSelection::PodObjectsAndTemplates
                            && kinds.contains(&KindId::Pod)
                            && pod_template_owner(identity)
                })
                .map(|(resource, _)| SubjectGap {
                    resource: *resource,
                    path: None,
                    reason: FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence),
                })
                .collect::<Vec<_>>(),
        };
        for (resource, identity) in identities {
            if !budget.take(1) {
                result.gaps.push(SubjectGap {
                    resource: *resource,
                    path: None,
                    reason: FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence),
                });
                break;
            }
            if !in_namespace(identity, namespace, context) {
                continue;
            }
            let object_kind = kinds.iter().any(|kind| kind.as_str() == identity.gvk.kind);
            let pod_templates = selection == SubjectSelection::PodObjectsAndTemplates
                && kinds.contains(&KindId::Pod)
                && pod_template_owner(identity);
            if !object_kind && !pod_templates {
                continue;
            }
            let mut found = false;
            for fact in facts.get(resource).into_iter().flatten() {
                let NativeFact::SelectorSubject { subject, labels } = fact else {
                    continue;
                };
                let selected = match subject {
                    LocalSubject::Object => {
                        object_kind
                            && (selection == SubjectSelection::Objects
                                || identity.gvk.group.is_none() && identity.gvk.kind == "Pod")
                    }
                    LocalSubject::Template {
                        template_kind: TemplateKind::Pod,
                        ..
                    } => selection == SubjectSelection::PodObjectsAndTemplates && kinds.contains(&KindId::Pod),
                    LocalSubject::Template { .. } => false,
                };
                if !selected {
                    continue;
                }
                found = true;
                self.select_fact(*resource, subject, labels, selector, evidence, &mut result);
            }
            if !found {
                result.gaps.push(SubjectGap {
                    resource: *resource,
                    path: None,
                    reason: if projections
                        .get(resource)
                        .is_some_and(|projection| !projection.findings.is_empty())
                    {
                        FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence)
                    } else {
                        FactUnavailable::Unadmitted
                    },
                });
            }
        }
        resolution_subjects(result)
    }
    fn select_fact(
        &self,
        resource: ResourceId,
        subject: &LocalSubject,
        labels: &FactState<LabelFacts>,
        selector: &LabelSelector,
        evidence: &mut Vec<FactEvidence>,
        result: &mut SelectedSubjects,
    ) {
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let witness = self.witness;
        if !budget.retain::<GraphSubject>(1) || !budget.retain::<SubjectGap>(1) || !budget.local_copy(subject, 3) {
            return;
        }
        let bound = local_subject(resource, subject);
        match labels {
            FactState::Known(labels) => {
                if !budget.selector_work(selector, Some(&labels.values)) || !budget.path_copy(&labels.path, 2) {
                    return;
                }
                if let Some(field) = contribution(
                    budget,
                    resources,
                    projections,
                    witness,
                    bound.clone(),
                    labels.path.clone(),
                ) {
                    evidence.push(field);
                }
                match selector.matches(&labels.values) {
                    Ok(true) => result.matched.push(bound),
                    Ok(false) => {}
                    Err(_) => result.gaps.push(SubjectGap {
                        resource,
                        path: Some(labels.path.clone()),
                        reason: FactUnavailable::Unadmitted,
                    }),
                }
            }
            FactState::Unknown(gap) => result.gaps.push(SubjectGap {
                resource,
                path: Some(subject_path(subject)),
                reason: FactUnavailable::Unknown(*gap),
            }),
            FactState::Unadmitted => result.gaps.push(SubjectGap {
                resource,
                path: Some(subject_path(subject)),
                reason: FactUnavailable::Unadmitted,
            }),
        }
    }
}

impl GraphIndex<'_> {
    fn evaluate_claims(
        &self,
        reference: &Reference,
        pattern: &ClaimPattern,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let resources = self.resources;
        let projections = self.projections;
        let identities = self.identities;
        let context = self.context;
        let witness = self.witness;
        let budget = self.budget;

        if !budget.take(resources.documents.len()) {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        if let Err(reason) = claim_admission(budget, resources, projections, reference, pattern, witness) {
            return Resolution::Unsupported(reason);
        }
        let namespace = match selected_namespace(reference, identities, context) {
            Ok(Some(namespace)) => Some(namespace),
            _ => None,
        };
        for identity in self.failed.values() {
            if !budget.take(1) {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            if identity.gvk.group.is_none()
                && identity.gvk.kind == "PersistentVolumeClaim"
                && in_namespace(identity, namespace, context)
            {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
        }
        let mut missing = Vec::new();
        if namespace.is_none() {
            missing.push(ClaimEvidenceGap::Scope);
        }
        let rule = match pattern {
            ClaimPattern::StatefulSet { .. } => self.stateful_claim_rule(reference, pattern, evidence, &mut missing),
            ClaimPattern::PodEphemeral { .. } => self.ephemeral_claim_rule(reference, pattern, evidence, &mut missing),
        };
        let rule = match rule {
            Ok(rule) => rule,
            Err(reason) => return Resolution::Unsupported(reason),
        };

        let state = if missing.iter().any(|gap| *gap != ClaimEvidenceGap::PodUid) {
            ClaimExpectationState::Symbolic { missing }
        } else {
            ClaimExpectationState::IdentityRuleEstablished
        };
        self.match_claims(rule, namespace, state, evidence)
    }
    fn match_claims(
        &self,
        rule: ClaimRule<'_>,
        namespace: Option<&str>,
        state: ClaimExpectationState,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let ClaimRule { prefix, range, pod_uid } = rule;
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let identities = self.identities;
        let context = self.context;
        let witness = self.witness;
        let mut incompatible = None;
        let mut matching = Vec::new();
        let mut duplicates = BTreeMap::<String, Vec<ResourceId>>::new();
        if let (Some(namespace), Some(prefix)) = (namespace, prefix) {
            for (resource, identity) in identities {
                if !budget.take(1) {
                    return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
                }
                if identity.gvk.group.is_some()
                    || identity.gvk.kind != "PersistentVolumeClaim"
                    || !in_namespace(identity, Some(namespace), context)
                {
                    continue;
                }
                let Some(name) = identity.name.value() else {
                    continue;
                };
                let matches = if let Some((start, end)) = range {
                    name.strip_prefix(&prefix)
                        .filter(|ordinal| !ordinal.is_empty() && ordinal.bytes().all(|byte| byte.is_ascii_digit()))
                        .and_then(|ordinal| ordinal.parse::<i64>().ok())
                        .is_some_and(|ordinal| {
                            ordinal >= start && ordinal < end && name == &format!("{prefix}{ordinal}")
                        })
                } else {
                    matches!(pod_uid, ClaimUid::Ephemeral(_)) && name == &prefix
                };
                if !matches {
                    continue;
                }
                duplicates.entry(name.clone()).or_default().push(*resource);
                let subject = GraphSubject::Object { resource: *resource };
                let mut fields = contribution(
                    budget,
                    resources,
                    projections,
                    witness,
                    subject.clone(),
                    FieldPath(vec!["metadata".into(), "name".into()]),
                )
                .into_iter()
                .collect::<Vec<_>>();
                let ownership = if let ClaimUid::Ephemeral(uid) = pod_uid {
                    claim_owner(budget, resources, projections, *resource, uid, witness, &mut fields)
                } else {
                    ClaimOwnership::NotRequiredByThisRule
                };
                if ownership == ClaimOwnership::Contradictory {
                    incompatible = Some(subject);
                    evidence.extend(fields.clone());
                }
                matching.push(ClaimMatch {
                    resource: *resource,
                    evidence: fields,
                    ownership,
                });
            }
        }
        if let Some(ids) = duplicates.into_values().find(|ids| ids.len() > 1) {
            return Resolution::Ambiguous(ids);
        }
        if let Some(subject) = incompatible {
            return Resolution::Incompatible {
                subject,
                reason: PredicateMismatch::ClaimOwnerMismatch,
            };
        }
        Resolution::ExpectedClaims {
            state,
            matching_supplied: matching,
        }
    }
    fn stateful_claim_rule<'a>(
        &self,
        reference: &Reference,
        pattern: &'a ClaimPattern,
        evidence: &mut Vec<FactEvidence>,
        missing: &mut Vec<ClaimEvidenceGap>,
    ) -> Result<ClaimRule<'a>, SafeReason> {
        let ClaimPattern::StatefulSet {
            template_path,
            template_name,
            controller_name,
            replicas,
            start_ordinal,
        } = pattern
        else {
            return Err(SafeReason::UnsupportedRelationship);
        };
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let witness = self.witness;
        let identities = self.identities;
        let source_subject = GraphSubject::Object {
            resource: reference.from,
        };

        if !identities
            .get(&reference.from)
            .is_some_and(|identity| identity.gvk.group.as_deref() == Some("apps") && identity.gvk.kind == "StatefulSet")
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        for path in [
            template_path.child("metadata").child("name"),
            FieldPath(vec!["metadata".into(), "name".into()]),
            FieldPath(vec!["spec".into(), "replicas".into()]),
            FieldPath(vec!["spec".into(), "ordinals".into(), "start".into()]),
        ] {
            if let Some(field) = contribution(budget, resources, projections, witness, source_subject.clone(), path) {
                evidence.push(field);
            }
        }
        if template_name.value().is_none() {
            missing.push(ClaimEvidenceGap::TemplateName);
        }
        if controller_name.value().is_none() {
            missing.push(ClaimEvidenceGap::SourceName);
        }
        if replicas.value().is_none() {
            missing.push(ClaimEvidenceGap::ReplicaCount);
        }
        if start_ordinal.value().is_none() {
            missing.push(ClaimEvidenceGap::StartOrdinal);
        }
        let prefix = template_name
            .value()
            .zip(controller_name.value())
            .map(|(template, controller)| format!("{}-{}-", template.native_value(), controller.native_value()));
        let range = replicas
            .value()
            .zip(start_ordinal.value())
            .and_then(|(replicas, start)| {
                if *replicas >= 0 && *start >= 0 {
                    Some((i64::from(*start), i64::from(*start) + i64::from(*replicas)))
                } else {
                    None
                }
            });
        if replicas.value().is_some_and(|replicas| *replicas < 0)
            || start_ordinal.value().is_some_and(|start| *start < 0)
        {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        Ok(ClaimRule {
            prefix,
            range,
            pod_uid: ClaimUid::NotRequired,
        })
    }

    fn ephemeral_claim_rule<'a>(
        &self,
        reference: &Reference,
        pattern: &'a ClaimPattern,
        evidence: &mut Vec<FactEvidence>,
        missing: &mut Vec<ClaimEvidenceGap>,
    ) -> Result<ClaimRule<'a>, SafeReason> {
        let ClaimPattern::PodEphemeral {
            pod_subject,
            volume_path,
            volume_name,
            pod_name,
            pod_uid,
        } = pattern
        else {
            return Err(SafeReason::UnsupportedRelationship);
        };
        let budget = self.budget;
        let resources = self.resources;
        let projections = self.projections;
        let witness = self.witness;

        if subject_resource(pod_subject) != reference.from {
            return Err(SafeReason::InvalidIdentity);
        }
        if !matches!(pod_subject, GraphSubject::Object { .. }) {
            missing.push(ClaimEvidenceGap::FuturePodName);
        }
        if pod_name.value().is_none() {
            missing.push(ClaimEvidenceGap::SourceName);
        }
        if volume_name.value().is_none() {
            missing.push(ClaimEvidenceGap::TemplateName);
        }
        if pod_uid.value().is_none() {
            missing.push(ClaimEvidenceGap::PodUid);
        }
        for path in [
            volume_path.child("name"),
            FieldPath(vec!["metadata".into(), "name".into()]),
            FieldPath(vec!["metadata".into(), "uid".into()]),
        ] {
            if let Some(field) = contribution(budget, resources, projections, witness, pod_subject.clone(), path) {
                evidence.push(field);
            }
        }
        let prefix = if matches!(pod_subject, GraphSubject::Object { .. }) {
            pod_name
                .value()
                .zip(volume_name.value())
                .map(|(pod, volume)| format!("{}-{}", pod.native_value(), volume.native_value()))
        } else {
            None
        };
        Ok(ClaimRule {
            prefix,
            range: None,
            pod_uid: ClaimUid::Ephemeral(pod_uid.value().map(crate::value::Protected::native_value)),
        })
    }
}

enum ClaimUid<'a> {
    NotRequired,
    Ephemeral(Option<&'a String>),
}
struct ClaimRule<'a> {
    prefix: Option<String>,
    range: Option<(i64, i64)>,
    pod_uid: ClaimUid<'a>,
}
fn claim_owner(
    budget: &GraphBudget,
    resources: &ResourceSet,
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    resource: ResourceId,
    uid: Option<&String>,
    witness: Option<&std::sync::Arc<GraphTargetWitness>>,
    evidence: &mut Vec<FactEvidence>,
) -> ClaimOwnership {
    let Some(projection) = projections.get(&resource) else {
        return ClaimOwnership::Unknown;
    };
    if !budget.take(resources.documents.len()) {
        return ClaimOwnership::Unknown;
    }
    let Some(document) = resources.documents.iter().find(|document| document.id == resource) else {
        return ClaimOwnership::Unknown;
    };
    let Some(capability) = document.capability.as_ref() else {
        return ClaimOwnership::Unknown;
    };
    if projection.resource.is_none() {
        return ClaimOwnership::Unknown;
    }
    let ctx = registry::ProjectionContext::new_in(
        &projection.tree,
        &projection.identity.gvk,
        &document.evidence,
        witness.as_ref().map(|witness| witness.profile()),
        capability,
        budget.processing.clone(),
    );
    let path = FieldPath(vec!["metadata".into(), "ownerReferences".into()]);
    if let Some(field) = contribution(
        budget,
        resources,
        projections,
        witness,
        GraphSubject::Object { resource },
        path.clone(),
    ) {
        evidence.push(field);
    }
    let Some(records) = projection
        .tree
        .get_path(&path)
        .and_then(crate::syntax::TreeNode::as_sequence)
    else {
        return ClaimOwnership::Unknown;
    };
    if !matches!(ctx.state(&path, FactState::Known(())), FactState::Known(())) {
        return ClaimOwnership::Unknown;
    }
    let mut controller = false;
    let mut incomplete = false;
    for (index, owner) in records.iter().enumerate() {
        let path = path.child(index.to_string());
        if owner.as_mapping().is_none() || owner_reference(owner, path.clone(), resource).is_err() {
            return ClaimOwnership::Unknown;
        }
        let flag = match owner.get("controller") {
            Some(node) if node.value == crate::syntax::TreeValue::Bool(true) => true,
            Some(node) if node.value == crate::syntax::TreeValue::Bool(false) => false,
            None => false,
            _ => return ClaimOwnership::Unknown,
        };
        if !flag {
            continue;
        }
        controller = true;
        let Some(owner_uid) = owner.get("uid").and_then(crate::syntax::TreeNode::as_str) else {
            incomplete = true;
            continue;
        };
        for member in ["uid", "controller"] {
            if !matches!(
                ctx.state(&path.child(member), FactState::Known(())),
                FactState::Known(())
            ) {
                return ClaimOwnership::Unknown;
            }
            if let Some(field) = contribution(
                budget,
                resources,
                projections,
                witness,
                GraphSubject::Object { resource },
                path.child(member),
            ) {
                evidence.push(field);
            }
        }
        let Some(expected) = uid else {
            return ClaimOwnership::Unknown;
        };
        if owner_uid == expected {
            return ClaimOwnership::VerifiedSupplied;
        }
        return ClaimOwnership::Contradictory;
    }
    if incomplete || uid.is_none() {
        ClaimOwnership::Unknown
    } else if !controller {
        ClaimOwnership::Contradictory
    } else {
        ClaimOwnership::Unknown
    }
}

fn recheck_labels(
    ctx: &registry::ProjectionContext<'_>,
    subject: &LocalSubject,
    state: FactState<LabelFacts>,
) -> FactState<LabelFacts> {
    let expected = subject_path(subject).child("metadata").child("labels");
    if let LocalSubject::Template { path, .. } = subject {
        if ctx
            .tree
            .get_path(path)
            .and_then(crate::syntax::TreeNode::as_mapping)
            .is_none()
        {
            return FactState::Unadmitted;
        }
        match ctx.state(path, FactState::Known(())) {
            FactState::Known(()) => {}
            FactState::Unknown(gap) => return FactState::Unknown(gap),
            FactState::Unadmitted => return FactState::Unadmitted,
        }
    }
    if let FactState::Known(labels) = &state {
        if labels.path != expected {
            return FactState::Unadmitted;
        }
        let source = match ctx.tree.get_path(&expected) {
            None => BTreeMap::new(),
            Some(node) => {
                match <BTreeMap<String, String> as registry::codec::FieldCodec>::decode(node, &ctx.fields, &expected) {
                    Ok(labels) => labels,
                    Err(_) => return FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
                }
            }
        };
        if source
            .iter()
            .any(|(key, value)| !crate::value::label_key(key) || !crate::value::label_value(value))
        {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        }
        if source != labels.values {
            return FactState::Unadmitted;
        }
        for key in source.keys() {
            match ctx.state(&expected.child(key), FactState::Known(())) {
                FactState::Known(()) => {}
                FactState::Unknown(gap) => return FactState::Unknown(gap),
                FactState::Unadmitted => return FactState::Unadmitted,
            }
        }
    }
    ctx.state(&expected, state)
}
fn claim_pattern_paths(
    fields: &registry::FieldDecodeContext,
    reference: &Reference,
    pattern: &ClaimPattern,
    projection: &crate::model::EffectiveProjection,
) -> Result<Vec<FieldPath>, SafeReason> {
    let mut paths = vec![reference.path.clone()];
    match pattern {
        ClaimPattern::StatefulSet { .. } => recheck_stateful_claim(fields, pattern, projection, &mut paths)?,
        ClaimPattern::PodEphemeral { .. } => recheck_ephemeral_claim(reference, pattern, projection, &mut paths)?,
    }
    Ok(paths)
}
fn recheck_stateful_claim(
    fields: &registry::FieldDecodeContext,
    pattern: &ClaimPattern,
    projection: &crate::model::EffectiveProjection,
    paths: &mut Vec<FieldPath>,
) -> Result<(), SafeReason> {
    let ClaimPattern::StatefulSet {
        template_path,
        controller_name,
        template_name,
        replicas,
        start_ordinal,
    } = pattern
    else {
        return Err(SafeReason::UnsupportedRelationship);
    };

    if template_path.0.len() != 3
        || template_path.0[0] != "spec"
        || template_path.0[1] != "volumeClaimTemplates"
        || template_path.0[2].parse::<usize>().is_err()
    {
        return Err(SafeReason::FactUnadmitted);
    }
    if controller_name.value().map(crate::value::Protected::native_value) != projection.identity.name.value()
        || template_name.value().map(|name| name.native_value().as_str())
            != projection
                .tree
                .get_path(&template_path.child("metadata").child("name"))
                .and_then(crate::syntax::TreeNode::as_str)
    {
        return Err(SafeReason::FactUnadmitted);
    }
    for (path, value) in [
        (FieldPath(vec!["spec".into(), "replicas".into()]), replicas),
        (
            FieldPath(vec!["spec".into(), "ordinals".into(), "start".into()]),
            start_ordinal,
        ),
    ] {
        let source = match projection.tree.get_path(&path) {
            None => Presence::Absent,
            Some(node) if node.value == crate::syntax::TreeValue::Null => Presence::Null,
            Some(node) => match <i32 as registry::codec::FieldCodec>::decode(node, fields, &path) {
                Ok(value) => Presence::Value(value),
                Err(_) => return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence)),
            },
        };
        if &source != value {
            return Err(SafeReason::FactUnadmitted);
        }
        if !source.is_absent() {
            paths.push(path);
        }
    }
    paths.extend([
        template_path.clone(),
        template_path.child("metadata").child("name"),
        FieldPath(vec!["metadata".into(), "name".into()]),
    ]);
    Ok(())
}
fn recheck_ephemeral_claim(
    reference: &Reference,
    pattern: &ClaimPattern,
    projection: &crate::model::EffectiveProjection,
    paths: &mut Vec<FieldPath>,
) -> Result<(), SafeReason> {
    let ClaimPattern::PodEphemeral {
        pod_subject,
        volume_path,
        volume_name,
        pod_name,
        pod_uid,
    } = pattern
    else {
        return Err(SafeReason::UnsupportedRelationship);
    };

    if subject_resource(pod_subject) != reference.from {
        return Err(SafeReason::InvalidIdentity);
    }
    if volume_name.value().map(|name| name.native_value().as_str())
        != projection
            .tree
            .get_path(&volume_path.child("name"))
            .and_then(crate::syntax::TreeNode::as_str)
    {
        return Err(SafeReason::FactUnadmitted);
    }
    match pod_subject {
        GraphSubject::Object { .. } => {
            if projection.identity.gvk.group.is_some()
                || projection.identity.gvk.kind != "Pod"
                || pod_name.value().map(crate::value::Protected::native_value) != projection.identity.name.value()
                || pod_uid.value().map(|uid| uid.native_value().as_str())
                    != projection
                        .tree
                        .get_path(&FieldPath(vec!["metadata".into(), "uid".into()]))
                        .and_then(crate::syntax::TreeNode::as_str)
            {
                return Err(SafeReason::FactUnadmitted);
            }
            paths.extend([
                FieldPath(vec!["metadata".into(), "name".into()]),
                FieldPath(vec!["metadata".into(), "uid".into()]),
            ]);
        }
        GraphSubject::Template {
            path,
            template_kind: TemplateKind::Pod,
            ..
        } => {
            if pod_name.value().is_some()
                || pod_uid.value().is_some()
                || projection
                    .tree
                    .get_path(path)
                    .and_then(crate::syntax::TreeNode::as_mapping)
                    .is_none()
                || !volume_path.0.starts_with(&path.0)
            {
                return Err(SafeReason::FactUnadmitted);
            }
            paths.push(path.clone());
        }
        _ => return Err(SafeReason::FactUnadmitted),
    }
    paths.extend([
        volume_path.child("name"),
        volume_path.child("ephemeral"),
        volume_path.child("ephemeral").child("volumeClaimTemplate"),
    ]);
    Ok(())
}
fn claim_admission(
    budget: &GraphBudget,
    resources: &ResourceSet,
    projections: &BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    reference: &Reference,
    pattern: &ClaimPattern,
    witness: Option<&std::sync::Arc<GraphTargetWitness>>,
) -> Result<(), SafeReason> {
    let document = resources
        .documents
        .iter()
        .find(|document| document.id == reference.from)
        .ok_or(SafeReason::InvalidIdentity)?;
    let projection = projections.get(&reference.from).ok_or(SafeReason::InvalidIdentity)?;
    let capability = document.capability.as_ref().ok_or(SafeReason::FactUnadmitted)?;
    if projection.resource.is_none() {
        return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
    }
    let ctx = registry::ProjectionContext::new_in(
        &projection.tree,
        &projection.identity.gvk,
        &document.evidence,
        witness.as_ref().map(|witness| witness.profile()),
        capability,
        budget.processing.clone(),
    );
    let paths = claim_pattern_paths(&ctx.fields, reference, pattern, projection)?;
    for path in paths {
        if projection.tree.get_path(&path).is_none() {
            continue;
        }
        match ctx.state(&path, FactState::Known(())) {
            FactState::Known(()) => {}
            FactState::Unknown(gap) => return Err(SafeReason::FactUnknown(gap)),
            FactState::Unadmitted => return Err(SafeReason::FactUnadmitted),
        }
    }
    Ok(())
}

struct GraphIndex<'a> {
    resources: &'a ResourceSet,
    projections: &'a BTreeMap<ResourceId, crate::model::EffectiveProjection>,
    identities: &'a BTreeMap<ResourceId, ResourceIdentity>,
    facts: &'a BTreeMap<ResourceId, Vec<NativeFact>>,
    failed: &'a BTreeMap<ResourceId, ResourceIdentity>,
    context: &'a ReferenceContext,
    witness: Option<&'a std::sync::Arc<GraphTargetWitness>>,
    budget: &'a GraphBudget,
}

#[cfg(test)]
#[path = "../tests/foundation/graph.rs"]
mod tests;

fn tree_cost(node: &crate::syntax::TreeNode) -> usize {
    match &node.value {
        crate::syntax::TreeValue::Mapping(entries) => entries.iter().fold(1usize, |total, (key, node)| {
            total
                .saturating_add(key.len())
                .saturating_add(1)
                .saturating_add(tree_cost(node))
        }),
        crate::syntax::TreeValue::Sequence(items) => items
            .iter()
            .fold(1usize, |total, node| total.saturating_add(tree_cost(node))),
        crate::syntax::TreeValue::Tagged(tag, node) => tag.len().saturating_add(1).saturating_add(tree_cost(node)),
        crate::syntax::TreeValue::String(value) | crate::syntax::TreeValue::Number(value) => {
            value.len().saturating_add(1)
        }
        _ => 1,
    }
}

fn native_string(
    node: Option<&crate::syntax::TreeNode>,
    processing: &crate::processing::NativeOperationBudget,
) -> Result<Presence<String>, FactGap> {
    match node {
        None => Ok(Presence::Absent),
        Some(node) if node.value == crate::syntax::TreeValue::Null => Ok(Presence::Null),
        Some(node) => {
            let value = node.as_str().ok_or(FactGap::IncompleteSuppliedEvidence)?;
            processing
                .work(value.len().saturating_add(1), Phase::Analysis)
                .map_err(|_| FactGap::IncompleteSuppliedEvidence)?;
            processing
                .payload(value.len(), Phase::Analysis)
                .map_err(|_| FactGap::IncompleteSuppliedEvidence)?;
            Ok(Presence::Value(value.to_owned()))
        }
    }
}
pub(crate) fn service_port_declarations(
    tree: &crate::syntax::TreeNode,
    path: &FieldPath,
    fields: &registry::FieldDecodeContext,
) -> FactState<Vec<ServicePortFact>> {
    let Some(node) = tree.get_path(path) else {
        return FactState::Known(Vec::new());
    };
    let Some(items) = node.as_sequence() else {
        return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
    };
    if fields
        .processing
        .payload_array::<ServicePortFact>(items.len(), fields.phase)
        .is_err()
    {
        return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
    }
    let mut declarations = Vec::new();
    for (index, item) in items.iter().enumerate() {
        if fields.processing.work(tree_cost(item), fields.phase).is_err()
            || fields
                .processing
                .payload_array::<String>(path.0.len().saturating_add(1), fields.phase)
                .is_err()
            || fields
                .processing
                .payload_sizes(path.0.iter().map(String::len).chain([20]), fields.phase)
                .is_err()
        {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        }

        let port = item.get("port").and_then(|node| match &node.value {
            crate::syntax::TreeValue::Number(value) => value.parse::<i32>().ok(),
            _ => None,
        });
        let (Some(port), Ok(name), Ok(protocol)) = (
            port,
            native_string(item.get("name"), &fields.processing),
            native_string(item.get("protocol"), &fields.processing),
        ) else {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        };
        if !(1..=65535).contains(&port)
            || matches!(name, Presence::Null)
            || matches!(protocol, Presence::Null)
            || protocol
                .value()
                .is_some_and(|value| !matches!(value.as_str(), "" | "TCP" | "UDP" | "SCTP"))
            || name
                .value()
                .is_some_and(|value| !value.is_empty() && !crate::value::dns_label(value))
        {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        }
        declarations.push(ServicePortFact {
            name,
            port,
            protocol,
            path: path.child(index.to_string()),
        });
    }
    FactState::Known(declarations)
}
fn recheck_service_ports(
    ctx: &registry::ProjectionContext<'_>,
    path: &FieldPath,
    state: FactState<Vec<ServicePortFact>>,
) -> FactState<Vec<ServicePortFact>> {
    if ctx.gvk.group.is_some() || ctx.gvk.version != "v1" || ctx.gvk.kind != "Service" || path.0 != ["spec", "ports"] {
        return FactState::Unadmitted;
    }
    let FactState::Known(emitted) = &state else {
        return ctx.state(path, state);
    };
    let actual = service_port_declarations(ctx.tree, path, &ctx.fields);
    let FactState::Known(actual) = actual else {
        return ctx.state(path, actual);
    };
    for port in actual.iter().chain(emitted) {
        if ctx
            .fields
            .processing
            .work(
                port.path
                    .0
                    .iter()
                    .map(String::len)
                    .sum::<usize>()
                    .saturating_add(port.name.value().map_or(0, String::len))
                    .saturating_add(port.protocol.value().map_or(0, String::len))
                    .saturating_add(1),
                ctx.fields.phase,
            )
            .is_err()
        {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        }
    }
    if actual.len() != emitted.len()
        || actual
            .iter()
            .zip(emitted)
            .any(|(a, b)| a.path != b.path || a.port != b.port || a.name != b.name || a.protocol != b.protocol)
    {
        return FactState::Unadmitted;
    }
    for port in &actual {
        for leaf in ["name", "port", "protocol"] {
            match ctx.state(&port.path.child(leaf), FactState::Known(())) {
                FactState::Known(()) => {}
                FactState::Unknown(gap) => return FactState::Unknown(gap),
                FactState::Unadmitted => return FactState::Unadmitted,
            }
        }
    }
    ctx.state(path, FactState::Known(actual))
}
fn resolution_subjects(result: SelectedSubjects) -> Resolution {
    if !result.gaps.is_empty() {
        Resolution::PartiallyResolvedSubjects {
            matched: result.matched,
            unavailable: result.gaps,
        }
    } else if result.matched.is_empty() {
        Resolution::Missing
    } else {
        Resolution::ResolvedSubjects(result.matched)
    }
}
fn source_backend_port(source: &crate::syntax::TreeNode) -> Option<ServicePortSelector> {
    if source.as_mapping().is_some() {
        let has_name = source
            .get("name")
            .and_then(crate::syntax::TreeNode::as_str)
            .is_some_and(|value| !value.is_empty());
        let has_number = source.get("number").is_some_and(|node| match &node.value {
            crate::syntax::TreeValue::Number(value) => value.parse::<i32>().is_ok_and(|value| value != 0),
            _ => false,
        });
        if has_name == has_number {
            return None;
        }
    }
    if let Some(value) = source.as_str() {
        Some(ServicePortSelector::Name(crate::value::Protected::new(
            value.to_owned(),
        )))
    } else if let crate::syntax::TreeValue::Number(value) = &source.value {
        value.parse::<i32>().ok().map(ServicePortSelector::Number)
    } else if let Some(value) = source
        .get("name")
        .and_then(crate::syntax::TreeNode::as_str)
        .filter(|value| !value.is_empty())
    {
        Some(ServicePortSelector::Name(crate::value::Protected::new(
            value.to_owned(),
        )))
    } else {
        source
            .get("number")
            .and_then(|node| match &node.value {
                crate::syntax::TreeValue::Number(value) => value.parse::<i32>().ok(),
                _ => None,
            })
            .filter(|number| *number != 0)
            .map(ServicePortSelector::Number)
    }
}
impl GraphIndex<'_> {
    fn add_evidence(&self, subject: GraphSubject, path: FieldPath, evidence: &mut Vec<FactEvidence>) {
        if let Some(field) = contribution(
            self.budget,
            self.resources,
            self.projections,
            self.witness,
            subject,
            path,
        ) {
            evidence.push(field);
        }
    }
    fn path_admission(&self, resource: ResourceId, path: &FieldPath) -> Result<(), SafeReason> {
        if !self.budget.take(self.resources.documents.len()) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let doc = self
            .resources
            .documents
            .iter()
            .find(|doc| doc.id == resource)
            .ok_or(SafeReason::InvalidIdentity)?;
        let projection = self.projections.get(&resource).ok_or(SafeReason::InvalidIdentity)?;
        let capability = doc.capability.as_ref().ok_or(SafeReason::FactUnadmitted)?;
        if !self
            .budget
            .take(tree_cost(&projection.tree).saturating_add(capability.fields.len()))
        {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let ctx = registry::ProjectionContext::new_in(
            &projection.tree,
            &projection.identity.gvk,
            &doc.evidence,
            self.witness.map(|witness| witness.profile()),
            capability,
            self.budget.processing.clone(),
        );
        match ctx.state(path, FactState::Known(())) {
            FactState::Known(()) => Ok(()),
            FactState::Unknown(gap) => Err(SafeReason::FactUnknown(gap)),
            FactState::Unadmitted => Err(SafeReason::FactUnadmitted),
        }
    }
    fn check_backend_port(
        &self,
        reference: &Reference,
        name: &str,
        selected: &ServicePortSelector,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<(), SafeReason> {
        if let ServicePortSelector::Unavailable(gap) = selected {
            return Err(SafeReason::FactUnknown(*gap));
        }
        let projection = self
            .projections
            .get(&reference.from)
            .ok_or(SafeReason::InvalidIdentity)?;
        if reference.path.0.len() > 9 {
            return Err(SafeReason::UnsupportedRelationship);
        }
        if !self.budget.retain::<&str>(reference.path.0.len())
            || !self.budget.path_copy(&reference.path, 4)
            || !self.budget.take(tree_cost(&projection.tree).saturating_mul(8))
        {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let parts: Vec<&str> = reference.path.0.iter().map(String::as_str).collect();
        let path_matches = matches!(
            parts.as_slice(),
            ["spec", "defaultBackend", "service", "port"] | ["spec", "backend", "servicePort"]
        ) || matches!(parts.as_slice(), ["spec","rules",rule,"http","paths",entry,"backend","service","port"] | ["spec","rules",rule,"http","paths",entry,"backend","servicePort"] if rule.parse::<usize>().is_ok() && entry.parse::<usize>().is_ok());
        if projection.identity.gvk.kind != "Ingress"
            || !matches!(
                projection.identity.gvk.group.as_deref(),
                Some("networking.k8s.io" | "extensions")
            )
            || !matches!(reference.scope, ReferenceScope::SameNamespace)
            || !path_matches
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        let source = projection
            .tree
            .get_path(&reference.path)
            .ok_or(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))?;
        let parent = FieldPath(reference.path.0[..reference.path.0.len().saturating_sub(1)].to_vec());
        let name_path = parent.child(if source.as_mapping().is_some() {
            "name"
        } else {
            "serviceName"
        });
        if projection
            .tree
            .get_path(&name_path)
            .and_then(crate::syntax::TreeNode::as_str)
            != Some(name)
        {
            return Err(SafeReason::FactUnadmitted);
        }
        let actual = source_backend_port(source);
        if actual.as_ref() != Some(selected) {
            return Err(SafeReason::FactUnadmitted);
        }
        self.path_admission(reference.from, &reference.path)?;
        self.path_admission(reference.from, &name_path)?;
        if source.as_mapping().is_some() {
            self.path_admission(
                reference.from,
                &reference.path.child(match selected {
                    ServicePortSelector::Name(_) => "name",
                    ServicePortSelector::Number(_) => "number",
                    ServicePortSelector::Unavailable(_) => {
                        return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
                    }
                }),
            )?;
        }
        self.add_evidence(
            GraphSubject::Object {
                resource: reference.from,
            },
            name_path,
            evidence,
        );
        Ok(())
    }
    fn service_front_port(
        &self,
        gvk: &GroupVersionKind,
        object: ResourceId,
        selected: &ServicePortSelector,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        if gvk.group.is_some() || gvk.kind != "Service" {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        }
        if matches!(selected, ServicePortSelector::Number(number) if !(1..=65535).contains(number))
            || matches!(selected, ServicePortSelector::Name(name) if name.native_value().is_empty())
        {
            return Resolution::Unsupported(SafeReason::InvalidIdentity);
        }
        let Some((state, path)) = self
            .facts
            .get(&object)
            .into_iter()
            .flatten()
            .find_map(|fact| match fact {
                NativeFact::ServicePorts { state, path } => Some((state, path)),
                _ => None,
            })
        else {
            return Resolution::Unsupported(SafeReason::FactUnadmitted);
        };
        self.add_evidence(GraphSubject::Object { resource: object }, path.clone(), evidence);
        let FactState::Known(ports) = state else {
            return Resolution::Unsupported(unavailable(state).unwrap_or(SafeReason::FactUnadmitted));
        };
        let mut matches = Vec::new();
        for port in ports {
            if !self
                .budget
                .take(port.name.value().map_or(0, String::len).saturating_add(1))
                || !self.budget.retain::<GraphSubject>(1)
                || !self.budget.path_copy(&port.path, 8)
            {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            let selected_here = match selected {
                ServicePortSelector::Unavailable(gap) => return Resolution::Unsupported(SafeReason::FactUnknown(*gap)),
                ServicePortSelector::Number(number) => port.port == *number,
                ServicePortSelector::Name(name) => port.name.value().is_some_and(|value| value == name.native_value()),
            };
            if selected_here {
                let subject = GraphSubject::ServicePort {
                    resource: object,
                    path: port.path.clone(),
                };
                for leaf in ["name", "port", "protocol"] {
                    self.add_evidence(subject.clone(), port.path.child(leaf), evidence);
                }
                matches.push(subject);
            }
        }
        match matches.len() {
            0 => Resolution::MissingServicePort { object },
            1 => Resolution::ResolvedSubjects(matches),
            _ => Resolution::AmbiguousServicePorts(matches),
        }
    }
    fn group_kind_scope_binding(
        &self,
        reference: &Reference,
        projection: &crate::model::EffectiveProjection,
        source: &crate::syntax::TreeNode,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<(), SafeReason> {
        let gvk = &projection.identity.gvk;
        if reference.path.0.len() > 8 {
            return Err(SafeReason::UnsupportedRelationship);
        }
        if !self.budget.retain::<&str>(reference.path.0.len())
            || !self.budget.path_copy(&reference.path, 12)
            || !self.budget.take(tree_cost(&projection.tree).saturating_mul(8))
        {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let parts: Vec<&str> = reference.path.0.iter().map(String::as_str).collect();
        if gvk.kind == "Ingress" && matches!(gvk.group.as_deref(), Some("networking.k8s.io" | "extensions")) {
            let path_matches = matches!(parts.as_slice(), ["spec", "defaultBackend" | "backend", "resource"])
                || matches!(parts.as_slice(),["spec","rules",rule,"http","paths",entry,"backend","resource"] if rule.parse::<usize>().is_ok() && entry.parse::<usize>().is_ok());
            return if path_matches && matches!(reference.scope, ReferenceScope::SameNamespace) {
                Ok(())
            } else {
                Err(SafeReason::UnsupportedRelationship)
            };
        }
        if gvk.kind != "IngressClass"
            || gvk.group.as_deref() != Some("networking.k8s.io")
            || parts != ["spec", "parameters"]
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        let scope_matches = match source.get("scope") {
            None => matches!(reference.scope, ReferenceScope::Cluster),
            Some(scope) if scope.as_str() == Some("Cluster") => matches!(reference.scope, ReferenceScope::Cluster),
            Some(scope) if scope.as_str() == Some("Namespace") => {
                matches!(&reference.scope,ReferenceScope::Namespace(namespace) if native_string(source.get("namespace"), &self.budget.processing).ok().as_ref() == Some(namespace))
            }
            _ => return Err(SafeReason::ScopeUnknown),
        };
        if !scope_matches {
            return Err(SafeReason::FactUnadmitted);
        }
        for leaf in ["scope", "namespace"] {
            let path = reference.path.child(leaf);
            if source.get(leaf).is_some() {
                self.path_admission(reference.from, &path)?;
            }
            self.add_evidence(
                GraphSubject::Object {
                    resource: reference.from,
                },
                path,
                evidence,
            );
        }
        Ok(())
    }
    fn group_kind_binding<'b>(
        &self,
        reference: &Reference,
        group: &'b Presence<String>,
        kind: &str,
        name: &str,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<Option<&'b str>, SafeReason> {
        let Some(projection) = self.projections.get(&reference.from) else {
            return Err(SafeReason::InvalidIdentity);
        };
        if !self.budget.take(
            kind.len()
                .saturating_add(name.len())
                .saturating_add(group.value().map_or(0, String::len))
                .saturating_mul(4)
                .saturating_add(1),
        ) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let Some(source) = projection.tree.get_path(&reference.path) else {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        };
        self.group_kind_scope_binding(reference, projection, source, evidence)?;
        if native_string(source.get("apiGroup"), &self.budget.processing)
            .ok()
            .as_ref()
            != Some(group)
            || source.get("kind").and_then(crate::syntax::TreeNode::as_str) != Some(kind)
            || source.get("name").and_then(crate::syntax::TreeNode::as_str) != Some(name)
        {
            return Err(SafeReason::FactUnadmitted);
        }
        for leaf in ["apiGroup", "kind", "name"] {
            let path = reference.path.child(leaf);
            if source.get(leaf).is_some() {
                self.path_admission(reference.from, &path)?;
            }
            self.add_evidence(
                GraphSubject::Object {
                    resource: reference.from,
                },
                path,
                evidence,
            );
        }
        let group = match group {
            Presence::Absent => None,
            Presence::Value(value) if !value.is_empty() && crate::value::dns_subdomain(value) => Some(value.as_str()),
            _ => return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence)),
        };
        // These networking references use native path segments, independent of a
        // supplied object's own metadata-name grammar.
        let path_segment =
            |value: &str| !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '%']);
        if !path_segment(kind) || !path_segment(name) {
            return Err(SafeReason::InvalidIdentity);
        }
        Ok(group)
    }
    fn identity_match_work(
        &self,
        identity: &ResourceIdentity,
        group: Option<&str>,
        kind: &str,
        name: &str,
        namespace: Option<&str>,
    ) -> bool {
        self.budget.take(
            identity
                .gvk
                .kind
                .len()
                .saturating_add(identity.gvk.group.as_ref().map_or(0, String::len))
                .saturating_add(identity.name.value().map_or(0, String::len))
                .saturating_add(identity.namespace.value().map_or(0, String::len))
                .saturating_add(kind.len())
                .saturating_add(name.len())
                .saturating_add(group.map_or(0, str::len))
                .saturating_add(namespace.map_or(0, str::len))
                .saturating_add(1),
        )
    }
    fn group_kind_name(
        &self,
        reference: &Reference,
        group: &Presence<String>,
        kind: &str,
        name: &str,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let group = match self.group_kind_binding(reference, group, kind, name, evidence) {
            Ok(group) => group,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        let namespace = match selected_namespace(reference, self.identities, self.context) {
            Ok(namespace) => namespace,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        if !self.budget.retain::<ResourceId>(self.identities.len())
            || !self.budget.retain::<GraphSubject>(self.identities.len())
        {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let mut matches = Vec::new();
        let mut unknown_scope = false;
        let mut failed = false;
        for (resource, identity) in self.identities {
            if !self.identity_match_work(identity, group, kind, name, namespace) {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            if identity.gvk.group.as_deref() != group
                || identity.gvk.kind != kind
                || identity.name.value().is_none_or(|value| value != name)
            {
                continue;
            }
            if identity.scope.namespaced().is_none() {
                unknown_scope = true;
                continue;
            }
            if in_namespace(identity, namespace, self.context) {
                matches.push(*resource);
            }
        }
        for identity in self.failed.values() {
            if !self.identity_match_work(identity, group, kind, name, namespace) {
                return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            if identity.gvk.group.as_deref() == group
                && identity.gvk.kind == kind
                && identity.name.value().is_some_and(|value| value == name)
            {
                failed = true;
            }
        }
        for resource in &matches {
            self.add_evidence(
                GraphSubject::Object { resource: *resource },
                FieldPath(vec!["metadata".into(), "name".into()]),
                evidence,
            );
        }
        if matches.len() > 1 {
            Resolution::Ambiguous(matches)
        } else if unknown_scope {
            Resolution::Unsupported(SafeReason::ScopeUnknown)
        } else if failed {
            Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))
        } else if matches.is_empty() {
            Resolution::Missing
        } else {
            let identity = &self.identities[&matches[0]];
            if let Some(declaration) = crate::capability::declaration(&identity.gvk) {
                if self.witness.is_some_and(|witness| {
                    !(declaration.first..=declaration.last).contains(&witness.profile().kubernetes.minor())
                }) {
                    return Resolution::Unsupported(SafeReason::FactUnadmitted);
                }
                if self.witness.is_none() && (declaration.first > 20 || declaration.last < 37) {
                    return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::TargetProfileRequired));
                }
            } else if crate::capability::builtin_scope(&identity.gvk).is_some() {
                return Resolution::Unsupported(SafeReason::FactUnadmitted);
            }
            Resolution::ResolvedSubjects(
                matches
                    .into_iter()
                    .map(|resource| GraphSubject::Object { resource })
                    .collect(),
            )
        }
    }
    fn all_peers(&self, reference: &Reference, presence: PeerListPresence) -> Resolution {
        let Some(projection) = self.projections.get(&reference.from) else {
            return Resolution::Unsupported(SafeReason::InvalidIdentity);
        };
        let path = &reference.path;
        let [spec, direction, index, peers] = path.0.as_slice() else {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        };
        if projection.identity.gvk.group.as_deref() != Some("networking.k8s.io")
            || projection.identity.gvk.kind != "NetworkPolicy"
            || spec != "spec"
            || !matches!(
                (direction.as_str(), peers.as_str()),
                ("ingress", "from") | ("egress", "to")
            )
            || index.parse::<usize>().is_err()
        {
            return Resolution::Unsupported(SafeReason::UnsupportedRelationship);
        }
        let parent = FieldPath(path.0[..3].to_vec());
        if projection
            .tree
            .get_path(&parent)
            .is_none_or(|node| node.as_mapping().is_none())
        {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let actual = match projection.tree.get_path(path) {
            None => PeerListPresence::Absent,
            Some(node) if node.as_sequence().is_some_and(<[_]>::is_empty) => PeerListPresence::ExplicitEmpty,
            _ => return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence)),
        };
        if actual != presence {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        match self.path_admission(reference.from, path) {
            Ok(()) => Resolution::NetworkPolicyAllPeers(presence),
            Err(reason) => Resolution::Unsupported(reason),
        }
    }
    fn namespace_conjunct(
        &self,
        identity: &ResourceIdentity,
        namespace_selector: &Presence<LabelSelector>,
        policy_namespace: Option<&str>,
        namespaces: &BTreeMap<String, Vec<ResourceId>>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<bool, FactUnavailable> {
        let namespace = match &identity.namespace {
            Presence::Value(value) => Some(value.as_str()),
            Presence::Absent => self.context.default_namespace.as_deref(),
            Presence::Null => None,
        };
        let unknown = FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence);
        if !self.budget.take(
            namespace
                .map_or(0, str::len)
                .saturating_add(policy_namespace.map_or(0, str::len))
                .saturating_mul(namespaces.len().saturating_add(1))
                .saturating_add(1),
        ) {
            return Err(unknown);
        }
        match namespace_selector {
            Presence::Absent => namespace
                .zip(policy_namespace)
                .map(|(candidate, policy)| candidate == policy)
                .ok_or(unknown),
            Presence::Null => Err(unknown),
            Presence::Value(selector) => {
                if selector.match_labels.value().is_none_or(BTreeMap::is_empty)
                    && selector.match_expressions.value().is_none_or(Vec::is_empty)
                {
                    return Ok(true);
                }
                let ids = namespace.and_then(|name| namespaces.get(name)).ok_or(unknown)?;
                if ids.len() != 1 {
                    for id in ids {
                        self.add_evidence(
                            GraphSubject::Object { resource: *id },
                            FieldPath(vec!["metadata".into(), "name".into()]),
                            evidence,
                        );
                    }
                    return Err(FactUnavailable::Unknown(FactGap::AmbiguousSuppliedEvidence));
                }
                let resource = ids[0];
                let state = self
                    .facts
                    .get(&resource)
                    .into_iter()
                    .flatten()
                    .find_map(|fact| match fact {
                        NativeFact::SelectorSubject {
                            subject: LocalSubject::Object,
                            labels,
                        } => Some(labels),
                        _ => None,
                    })
                    .ok_or(FactUnavailable::Unadmitted)?;
                self.label_conjunct(resource, &LocalSubject::Object, state, selector, evidence)
            }
        }
    }
    fn label_conjunct(
        &self,
        resource: ResourceId,
        subject: &LocalSubject,
        state: &FactState<LabelFacts>,
        selector: &LabelSelector,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<bool, FactUnavailable> {
        if !self.budget.take(1) {
            return Err(FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence));
        }
        match state {
            FactState::Known(labels) => {
                if !self.budget.selector_work(selector, Some(&labels.values))
                    || !self.budget.local_copy(subject, 1)
                    || !self.budget.path_copy(&labels.path, 1)
                {
                    return Err(FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence));
                }
                self.add_evidence(local_subject(resource, subject), labels.path.clone(), evidence);
                selector
                    .matches(&labels.values)
                    .map_err(|_| FactUnavailable::Unadmitted)
            }
            FactState::Unknown(gap) => Err(FactUnavailable::Unknown(*gap)),
            FactState::Unadmitted => Err(FactUnavailable::Unadmitted),
        }
    }
    fn policy_peer_binding(
        &self,
        reference: &Reference,
        namespace_selector: &Presence<LabelSelector>,
        pod_selector: &Presence<LabelSelector>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<(), SafeReason> {
        for selector in [namespace_selector.value(), pod_selector.value()].into_iter().flatten() {
            if !self.budget.selector_work(selector, None) {
                return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
        }
        if !self.budget.path_copy(&reference.path, 4) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        if matches!(namespace_selector, Presence::Null)
            || matches!(pod_selector, Presence::Null)
            || matches!((namespace_selector, pod_selector), (Presence::Absent, Presence::Absent))
            || namespace_selector
                .value()
                .is_some_and(|selector| selector.validate().is_err())
            || pod_selector
                .value()
                .is_some_and(|selector| selector.validate().is_err())
        {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let Some(projection) = self.projections.get(&reference.from) else {
            return Err(SafeReason::InvalidIdentity);
        };
        let [spec, direction, rule, peers, entry] = reference.path.0.as_slice() else {
            return Err(SafeReason::UnsupportedRelationship);
        };
        if projection.identity.gvk.group.as_deref() != Some("networking.k8s.io")
            || projection.identity.gvk.kind != "NetworkPolicy"
            || spec != "spec"
            || !matches!(
                (direction.as_str(), peers.as_str()),
                ("ingress", "from") | ("egress", "to")
            )
            || rule.parse::<usize>().is_err()
            || entry.parse::<usize>().is_err()
            || !matches!(reference.scope, ReferenceScope::SameNamespace)
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        let Some(source) = projection.tree.get_path(&reference.path) else {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        };
        if !self.budget.take(self.resources.documents.len()) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let document = self
            .resources
            .documents
            .iter()
            .find(|document| document.id == reference.from)
            .ok_or(SafeReason::InvalidIdentity)?;
        let fields = registry::FieldDecodeContext::new(
            *document.evidence.limits(),
            self.budget.processing.clone(),
            Phase::Analysis,
        );
        if !self.budget.take(tree_cost(source).saturating_mul(4)) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let actual = |key| match source.get(key) {
            None => Ok(Presence::Absent),
            Some(node) if node.value == crate::syntax::TreeValue::Null => Ok(Presence::Null),
            Some(node) => {
                <LabelSelector as registry::codec::FieldCodec>::decode(node, &fields, &reference.path.child(key))
                    .map(Presence::Value)
                    .map_err(|_| SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))
            }
        };
        if source.get("ipBlock").is_some()
            || actual("namespaceSelector").ok().as_ref() != Some(namespace_selector)
            || actual("podSelector").ok().as_ref() != Some(pod_selector)
        {
            return Err(SafeReason::FactUnadmitted);
        }
        for leaf in ["namespaceSelector", "podSelector"] {
            if source.get(leaf).is_some() {
                let path = reference.path.child(leaf);
                self.path_admission(reference.from, &path)?;
                self.add_evidence(
                    GraphSubject::Object {
                        resource: reference.from,
                    },
                    path,
                    evidence,
                );
            }
        }
        self.path_admission(reference.from, &reference.path)?;
        Ok(())
    }
    fn supplied_namespaces(&self) -> Result<BTreeMap<String, Vec<ResourceId>>, SafeReason> {
        let mut namespaces = BTreeMap::<String, Vec<ResourceId>>::new();
        for (resource, identity) in self.identities {
            if !self.budget.take(1) {
                return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
            }
            if identity.gvk.group.is_none()
                && identity.gvk.kind == "Namespace"
                && identity.scope.namespaced() == Some(false)
            {
                if let Some(name) = identity.name.value() {
                    if !self
                        .budget
                        .take(name.len().saturating_mul(self.identities.len().saturating_add(1)))
                        || !self.budget.retain::<(String, Vec<ResourceId>)>(1)
                        || !self.budget.retain::<ResourceId>(1)
                        || self.budget.processing.payload(name.len(), Phase::Analysis).is_err()
                    {
                        return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
                    }
                    namespaces.entry(name.clone()).or_default().push(*resource);
                }
            }
        }
        Ok(namespaces)
    }
    fn policy_peer(
        &self,
        reference: &Reference,
        namespace_selector: &Presence<LabelSelector>,
        pod_selector: &Presence<LabelSelector>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        if let Err(reason) = self.policy_peer_binding(reference, namespace_selector, pod_selector, evidence) {
            return Resolution::Unsupported(reason);
        }
        let policy_namespace = selected_namespace(reference, self.identities, self.context)
            .ok()
            .flatten();
        if !self
            .budget
            .retain::<SubjectGap>(self.identities.len().saturating_add(self.failed.len()))
        {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let namespaces = match self.supplied_namespaces() {
            Ok(namespaces) => namespaces,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        let mut result = SelectedSubjects {
            matched: Vec::new(),
            gaps: Vec::new(),
        };
        for (resource, identity) in self.identities {
            if !self.budget.take(1) {
                break;
            }
            if !pod_template_owner(identity) {
                continue;
            }
            let namespace =
                self.namespace_conjunct(identity, namespace_selector, policy_namespace, &namespaces, evidence);
            if namespace == Ok(false) {
                continue;
            }
            let mut found = false;
            for fact in self.facts.get(resource).into_iter().flatten() {
                if !self.budget.take(1) {
                    break;
                }
                let NativeFact::SelectorSubject { subject, labels } = fact else {
                    continue;
                };
                if !(matches!(
                    subject,
                    LocalSubject::Template {
                        template_kind: TemplateKind::Pod,
                        ..
                    }
                ) || matches!(subject, LocalSubject::Object)
                    && identity.gvk.group.is_none()
                    && identity.gvk.kind == "Pod")
                {
                    continue;
                }
                if !self.budget.retain::<GraphSubject>(1)
                    || !self.budget.retain::<SubjectGap>(1)
                    || !self.budget.local_copy(subject, 2)
                {
                    break;
                }
                found = true;
                let pod = pod_selector.value().map_or(Ok(true), |selector| {
                    self.label_conjunct(*resource, subject, labels, selector, evidence)
                });
                // A known false conjunct excludes even when the other evidence is unknown.
                if pod == Ok(false) {
                    continue;
                }
                match (pod, namespace) {
                    (Ok(true), Ok(true)) => result.matched.push(local_subject(*resource, subject)),
                    (Err(reason), _) | (_, Err(reason)) => result.gaps.push(SubjectGap {
                        resource: *resource,
                        path: Some(subject_path(subject)),
                        reason,
                    }),
                    _ => {}
                }
            }
            if !found {
                result.gaps.push(SubjectGap {
                    resource: *resource,
                    path: None,
                    reason: FactUnavailable::Unadmitted,
                });
            }
        }
        for (resource, identity) in self.failed {
            if !self.budget.take(1) {
                break;
            }
            if pod_template_owner(identity)
                && !result.gaps.iter().any(|gap| gap.resource == *resource)
                && self.namespace_conjunct(identity, namespace_selector, policy_namespace, &namespaces, evidence)
                    != Ok(false)
            {
                result.gaps.push(SubjectGap {
                    resource: *resource,
                    path: None,
                    reason: FactUnavailable::Unknown(FactGap::IncompleteSuppliedEvidence),
                });
            }
        }
        resolution_subjects(result)
    }
    fn named_target_port_binding<'b>(
        &self,
        reference: &Reference,
        selector: &LabelSelector,
        name: &str,
        protocol: &'b Presence<String>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Result<&'b str, SafeReason> {
        if name.is_empty()
            || selector.match_labels.value().is_none_or(BTreeMap::is_empty)
                && selector.match_expressions.value().is_none_or(Vec::is_empty)
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        let Some(projection) = self.projections.get(&reference.from) else {
            return Err(SafeReason::InvalidIdentity);
        };
        if projection.identity.gvk.group.is_some()
            || projection.identity.gvk.kind != "Service"
            || reference.path.0.len() != 4
            || reference.path.0[..2] != ["spec", "ports"]
            || reference.path.0[3] != "targetPort"
        {
            return Err(SafeReason::UnsupportedRelationship);
        }
        let base = FieldPath(reference.path.0[..3].to_vec());
        if projection
            .tree
            .get_path(&reference.path)
            .and_then(crate::syntax::TreeNode::as_str)
            != Some(name)
            || native_string(
                projection.tree.get_path(&base.child("protocol")),
                &self.budget.processing,
            )
            .ok()
            .as_ref()
                != Some(protocol)
        {
            return Err(SafeReason::FactUnadmitted);
        }
        let selector_path = FieldPath(vec!["spec".into(), "selector".into()]);
        if !self.budget.path_copy(&reference.path, 4) || !self.budget.take(name.len().saturating_add(1)) {
            return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        if let Some(source) = projection.tree.get_path(&selector_path) {
            self.budget
                .processing
                .tree_copy(source, Phase::Analysis)
                .map_err(|_| SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence))?;
        }
        let actual = projection
            .tree
            .get_path(&selector_path)
            .and_then(crate::syntax::TreeNode::as_mapping)
            .and_then(|values| {
                values
                    .iter()
                    .map(|(key, value)| value.as_str().map(|value| (key.clone(), value.to_owned())))
                    .collect::<Option<BTreeMap<_, _>>>()
            });
        if actual.as_ref() != selector.match_labels.value() || !selector.match_expressions.is_absent() {
            return Err(SafeReason::FactUnadmitted);
        }
        for path in [selector_path, base.child("protocol")] {
            self.path_admission(reference.from, &path)?;
            self.add_evidence(
                GraphSubject::Object {
                    resource: reference.from,
                },
                path,
                evidence,
            );
        }
        let requested = match protocol {
            Presence::Value(value) if matches!(value.as_str(), "TCP" | "UDP" | "SCTP") => value.as_str(),
            Presence::Value(value) if value.is_empty() && self.witness.is_some() => "TCP",
            Presence::Absent if self.witness.is_some() => "TCP",
            Presence::Absent => {
                return Err(SafeReason::FactUnknown(FactGap::TargetProfileRequired));
            }
            _ => return Err(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence)),
        };
        self.path_admission(reference.from, &reference.path)?;
        Ok(requested)
    }
    fn subject_ports(&self, resource: ResourceId, subject: &GraphSubject) -> Option<&FactState<Vec<PortFact>>> {
        for fact in self.facts.get(&resource)? {
            if !self.budget.take(1) {
                return None;
            }
            let NativeFact::ContainerPorts { subject: local, ports } = fact else {
                continue;
            };
            let same = match (local, subject) {
                (LocalSubject::Object, GraphSubject::Object { resource: id }) => *id == resource,
                (
                    LocalSubject::Template { path, template_kind },
                    GraphSubject::Template {
                        resource: id,
                        path: actual,
                        template_kind: kind,
                    },
                ) => {
                    if !self.budget.take(
                        path.0
                            .iter()
                            .map(String::len)
                            .sum::<usize>()
                            .saturating_add(actual.0.iter().map(String::len).sum::<usize>())
                            .saturating_add(1),
                    ) {
                        return None;
                    }
                    *id == resource && path == actual && template_kind == kind
                }
                _ => false,
            };
            if same {
                return Some(ports);
            }
        }
        None
    }
    fn named_target_port(
        &self,
        reference: &Reference,
        selector: &LabelSelector,
        name: &str,
        protocol: &Presence<String>,
        evidence: &mut Vec<FactEvidence>,
    ) -> Resolution {
        let requested = match self.named_target_port_binding(reference, selector, name, protocol, evidence) {
            Ok(requested) => requested,
            Err(reason) => return Resolution::Unsupported(reason),
        };
        let selection = self.select_subjects(
            reference,
            &[KindId::Pod],
            selector,
            SubjectSelection::PodObjectsAndTemplates,
            evidence,
        );
        let (selected, mut gaps) = match selection {
            Resolution::ResolvedSubjects(subjects) => (subjects, Vec::new()),
            Resolution::PartiallyResolvedSubjects { matched, unavailable } => (matched, unavailable),
            other => return other,
        };
        if !self.budget.retain::<GraphSubject>(selected.len()) || !self.budget.retain::<SubjectGap>(selected.len()) {
            return Resolution::Unsupported(SafeReason::FactUnknown(FactGap::IncompleteSuppliedEvidence));
        }
        let mut matched = Vec::new();
        for subject in &selected {
            if !self.budget.take(1) {
                break;
            }
            let resource = subject_resource(subject);
            let state = self.subject_ports(resource, subject);
            match state {
                Some(FactState::Known(ports)) => {
                    let mut found = false;
                    let mut unknown = false;
                    for port in ports {
                        if !self.budget.take(
                            port.name
                                .value()
                                .map_or(0, String::len)
                                .saturating_add(name.len())
                                .saturating_add(1),
                        ) || !self.budget.path_copy(&port.name_path, 1)
                            || !self.budget.path_copy(&port.protocol_path, 1)
                            || !self.budget.path_copy(&port.container_port_path, 1)
                        {
                            break;
                        }
                        self.add_evidence(subject.clone(), port.name_path.clone(), evidence);
                        self.add_evidence(subject.clone(), port.protocol_path.clone(), evidence);
                        self.add_evidence(subject.clone(), port.container_port_path.clone(), evidence);
                        if port.name.value().is_none_or(|value| value != name) {
                            continue;
                        }
                        let candidate = match &port.protocol {
                            Presence::Value(value) => Some(value.as_str()),
                            Presence::Absent if self.witness.is_some() => Some("TCP"),
                            _ => None,
                        };
                        if candidate == Some(requested) {
                            found = true;
                        } else if candidate.is_none() {
                            unknown = true;
                        }
                    }
                    if found {
                        matched.push(subject.clone());
                    } else if unknown {
                        gaps.push(SubjectGap {
                            resource,
                            path: None,
                            reason: FactUnavailable::Unknown(FactGap::TargetProfileRequired),
                        });
                    }
                }
                Some(FactState::Unknown(gap)) => gaps.push(SubjectGap {
                    resource,
                    path: None,
                    reason: FactUnavailable::Unknown(*gap),
                }),
                _ => gaps.push(SubjectGap {
                    resource,
                    path: None,
                    reason: FactUnavailable::Unadmitted,
                }),
            }
        }
        if !gaps.is_empty() {
            Resolution::PartiallyResolvedSubjects {
                matched,
                unavailable: gaps,
            }
        } else if matched.is_empty() {
            Resolution::MissingContainerPort { selected }
        } else {
            Resolution::ResolvedSubjects(matched)
        }
    }
}
