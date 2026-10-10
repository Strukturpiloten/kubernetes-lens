//! Source-bound views and offline checks for explicitly supplied custom resources.
//!
//! This module deliberately exposes no custom-resource authoring API and makes no API-server
//! admission claim. A report exists only when a supplied CRD and supplied custom document have
//! matching group/kind/version/scope evidence.
use super::roots::{
    CustomResourceDefinitionSpecCrdV1, CustomResourceDefinitionSpecCrdV1beta1, CustomResourceDefinitionV1,
    CustomResourceDefinitionV1beta1,
};
use super::{JSONSchemaPropsCrdV1, JSONSchemaPropsCrdV1beta1};
use crate::{
    capability::TargetProfile,
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::{ExternalRefKind, Reference, ReferenceScope, ReferenceTarget, RelationshipKind},
    model::{ResourceDocument, ResourceIdentity, ResourceScope, ResourceSet, SourceRef, tree_gvk},
    processing::NativeOperationBudget,
    registry::codec::FieldCodec,
    source::SourceEvidence,
    value::{Presence, ProtectedJsonValue},
};
use std::{fmt, mem::size_of};

/// Protected structured view of one supplied custom resource and its immutable origin.
pub struct CustomResourceView {
    source: SourceRef,
    pointer: FieldPath,
    identity: ResourceIdentity,
    body: Option<ProtectedJsonValue>,
    evidence: SourceEvidence,
}
impl fmt::Debug for CustomResourceView {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomResourceView")
            .field("source", &self.source)
            .field("pointer_depth", &self.pointer.depth())
            .field("identity", &"<private>")
            .field("body_present", &self.body.is_some())
            .field("evidence", &"<private>")
            .finish()
    }
}
impl CustomResourceView {
    /// Immutable source document coordinates.
    #[must_use]
    pub const fn source(&self) -> SourceRef {
        self.source
    }
    /// Exact effective custom-resource identity, version, and known scope.
    #[must_use]
    pub const fn identity(&self) -> &ResourceIdentity {
        &self.identity
    }
    /// Reveal the original source pointer only with explicit access.
    #[must_use]
    pub fn pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.pointer.reveal(access)
    }
    /// Borrow the protected structured body; serialization still requires explicit access.
    #[must_use]
    pub const fn body(&self) -> Option<&ProtectedJsonValue> {
        self.body.as_ref()
    }
    /// Immutable original source evidence, whose bytes require explicit access to reveal.
    #[must_use]
    pub const fn source_evidence(&self) -> &SourceEvidence {
        &self.evidence
    }
}

/// Exact source binding selected for one supplied custom resource.
pub struct CustomDocumentBinding {
    document: SourceRef,
    document_pointer: FieldPath,
    descriptor: SuppliedCustomResourceDescriptor,
}
impl fmt::Debug for CustomDocumentBinding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomDocumentBinding")
            .field("document", &self.document)
            .field("document_pointer_depth", &self.document_pointer.depth())
            .field("descriptor", &self.descriptor)
            .finish_non_exhaustive()
    }
}

#[derive(Clone)]
struct SuppliedSetAuthority(std::sync::Arc<()>);
impl PartialEq for SuppliedSetAuthority {
    fn eq(&self, other: &Self) -> bool {
        std::sync::Arc::ptr_eq(&self.0, &other.0)
    }
}
impl Eq for SuppliedSetAuthority {}

#[derive(Eq, PartialEq)]
struct DescriptorAuthority {
    set: SuppliedSetAuthority,
    effective_crd: ProtectedJsonValue,
    target: Option<TargetProfile>,
}

/// Immutable source-bound description of one selected served custom-resource version.
///
/// This establishes only that the supplied CRD names the selected served version, scope, and
/// schema at these source coordinates. It does not establish controller behavior or runtime
/// conformance.
/// Sealed binding to one resource set, effective supplied CRD, selected schema and full target.
/// Reuse requires a fresh successful check of the current supplied facts under inherited limits.
#[derive(Clone, Eq, PartialEq)]
pub struct SuppliedCustomResourceDescriptor {
    authority: Option<std::sync::Arc<DescriptorAuthority>>,
    resource: crate::diagnostic::ResourceId,
    crd: SourceRef,
    crd_gvk: crate::model::GroupVersionKind,
    crd_pointer: FieldPath,
    group: String,
    kind: String,
    version: String,
    version_pointer: FieldPath,
    version_path: FieldPath,
    scope: ResourceScope,
    storage: bool,
    schema_pointer: FieldPath,
    schema_path: FieldPath,
    schema_family: &'static str,
}
impl fmt::Debug for SuppliedCustomResourceDescriptor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SuppliedCustomResourceDescriptor")
            .field("resource", &self.resource)
            .field("crd", &self.crd)
            .field("crd_pointer_depth", &self.crd_pointer.depth())
            .field("version_pointer_depth", &self.version_pointer.depth())
            .field("schema_pointer_depth", &self.schema_pointer.depth())
            .field("scope", &self.scope)
            .field("storage", &self.storage)
            .field("schema_family", &self.schema_family)
            .finish_non_exhaustive()
    }
}
impl SuppliedCustomResourceDescriptor {
    pub(crate) fn matches_current(
        &self,
        other: &Self,
        fields: &crate::registry::FieldDecodeContext,
    ) -> Result<bool, Finding> {
        let (Some(left_authority), Some(right_authority)) = (&self.authority, &other.authority) else {
            return Ok(false);
        };
        if left_authority.set != right_authority.set {
            return Ok(false);
        }
        for descriptor in [self, other] {
            fields.processing.work(1, Phase::Analysis)?;
            for scalar in [
                &descriptor.group,
                &descriptor.kind,
                &descriptor.version,
                &descriptor.crd_gvk.version,
                &descriptor.crd_gvk.kind,
            ] {
                fields.processing.work(scalar.len(), Phase::Analysis)?;
            }
            if let Some(group) = &descriptor.crd_gvk.group {
                fields.processing.work(group.len(), Phase::Analysis)?;
            }
            for path in [
                &descriptor.crd_pointer,
                &descriptor.version_pointer,
                &descriptor.version_path,
                &descriptor.schema_pointer,
                &descriptor.schema_path,
            ] {
                for segment in &path.0 {
                    fields
                        .processing
                        .work(segment.len().saturating_add(1), Phase::Analysis)?;
                }
            }
            if let Some(target) = descriptor
                .authority
                .as_ref()
                .and_then(|authority| authority.target.as_ref())
            {
                fields
                    .processing
                    .work(target.feature_gates.states.len().saturating_add(1), Phase::Analysis)?;
            }
        }
        if left_authority.target != right_authority.target
            || self.resource != other.resource
            || self.crd != other.crd
            || self.crd_gvk != other.crd_gvk
            || self.crd_pointer != other.crd_pointer
            || self.group != other.group
            || self.kind != other.kind
            || self.version != other.version
            || self.version_pointer != other.version_pointer
            || self.version_path != other.version_path
            || self.scope != other.scope
            || self.storage != other.storage
            || self.schema_pointer != other.schema_pointer
            || self.schema_path != other.schema_path
            || self.schema_family != other.schema_family
        {
            return Ok(false);
        }
        left_authority
            .effective_crd
            .equivalent_in(&right_authority.effective_crd, &fields.processing, Phase::Analysis)
    }

    /// Input-local `ResourceId` of the actual supplied CRD document.
    #[must_use]
    pub const fn resource_id(&self) -> crate::diagnostic::ResourceId {
        self.resource
    }
    /// Source coordinates of the supplying CRD document.
    #[must_use]
    pub const fn crd_source(&self) -> SourceRef {
        self.crd
    }
    /// Exact CRD API identity.
    #[must_use]
    pub const fn crd_gvk(&self) -> &crate::model::GroupVersionKind {
        &self.crd_gvk
    }
    /// Group, kind, and selected served version.
    #[must_use]
    pub fn identity(&self) -> (&str, &str, &str) {
        (&self.group, &self.kind, &self.version)
    }
    /// Scope explicitly declared by the CRD.
    #[must_use]
    pub const fn scope(&self) -> ResourceScope {
        self.scope
    }
    /// Whether the selected served version is the CRD storage version.
    #[must_use]
    pub const fn storage(&self) -> bool {
        self.storage
    }
    /// The selected version is marked served by the supplied CRD.
    #[must_use]
    pub const fn served(&self) -> bool {
        true
    }
    /// API family of the selected structural schema.
    #[must_use]
    pub const fn schema_family(&self) -> &'static str {
        self.schema_family
    }
    /// Reveal the CRD root pointer only with explicit source access.
    #[must_use]
    pub fn crd_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.crd_pointer.reveal(access)
    }
    /// Reveal the selected version pointer only with explicit source access.
    #[must_use]
    pub fn version_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.version_pointer.reveal(access)
    }
    /// Reveal the selected schema pointer only with explicit source access.
    #[must_use]
    pub fn schema_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.schema_pointer.reveal(access)
    }
    pub(crate) const fn crd_resource_id(&self) -> crate::diagnostic::ResourceId {
        self.resource
    }
    pub(crate) fn version_path(&self) -> &FieldPath {
        &self.version_path
    }
    pub(crate) fn schema_path(&self) -> &FieldPath {
        &self.schema_path
    }
}
impl CustomDocumentBinding {
    /// Source coordinates of the custom resource document.
    #[must_use]
    pub const fn document(&self) -> SourceRef {
        self.document
    }
    /// Source coordinates of the matching supplied CRD.
    #[must_use]
    pub const fn crd(&self) -> SourceRef {
        self.descriptor.crd
    }
    /// Group, kind, served version, and scope selected by the supplied CRD.
    #[must_use]
    pub fn descriptor(&self) -> (&str, &str, &str, bool, bool) {
        let (group, kind, version) = self.descriptor.identity();
        (
            group,
            kind,
            version,
            self.descriptor.scope.namespaced() == Some(true),
            self.descriptor.storage,
        )
    }
    /// The sealed source-bound descriptor selected by this binding.
    #[must_use]
    pub const fn supplied_descriptor(&self) -> &SuppliedCustomResourceDescriptor {
        &self.descriptor
    }
    /// Reveal the custom-resource root pointer only with explicit access.
    #[must_use]
    pub fn document_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.document_pointer.reveal(access)
    }
    /// Reveal the CRD root pointer only with explicit access.
    #[must_use]
    pub fn crd_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.descriptor.crd_pointer(access)
    }
    /// Reveal the selected CRD version pointer only with explicit access.
    #[must_use]
    pub fn version_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.descriptor.version_pointer(access)
    }
    /// Reveal the selected schema pointer only with explicit access.
    #[must_use]
    pub fn schema_pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.descriptor.schema_pointer(access)
    }
    /// API family of the selected structural schema, if one was present.
    #[must_use]
    pub const fn schema_family(&self) -> &'static str {
        self.descriptor.schema_family
    }
}

/// Result of resolving an explicitly supplied custom document against supplied CRDs.
pub enum CustomDocumentCheck {
    /// Graph collection could not check a selected schema without an explicit target profile.
    TargetProfileRequired,
    /// No matching supplied CRD was present.
    MissingCrd,
    /// More than one supplied CRD matched the custom resource group and kind.
    AmbiguousCrd,
    /// The supplied CRD or resource identity did not form one exact source binding.
    InvalidBinding,
    /// The CRD does not list the resource's served version.
    VersionNotListed,
    /// The CRD lists the version but does not mark it served.
    VersionNotServed,
    /// The custom resource scope conflicts with the supplied CRD scope.
    ScopeMismatch,
    /// The selected CRD version has no structural schema.
    MissingSchema,
    /// The source schema or custom resource could not be decoded for local checking.
    InvalidSchema,
    /// The supported schema subset found unsupported schema behavior.
    UnsupportedSchema(super::SchemaCheckReport),
    /// The supported local schema subset found one or more document violations.
    SchemaViolations(super::SchemaCheckReport),
    /// The supported local schema subset completed without a reported violation.
    Checked(super::SchemaCheckReport),
    /// The local schema check could not establish a complete result.
    Incomplete(super::SchemaCheckReport),
    /// A sticky processing ceiling stopped the local check.
    LimitExceeded(Option<super::SchemaCheckReport>),
}
impl fmt::Debug for CustomDocumentCheck {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self {
            Self::TargetProfileRequired => "TargetProfileRequired",
            Self::MissingCrd => "MissingCrd",
            Self::AmbiguousCrd => "AmbiguousCrd",
            Self::InvalidBinding => "InvalidBinding",
            Self::VersionNotListed => "VersionNotListed",
            Self::VersionNotServed => "VersionNotServed",
            Self::ScopeMismatch => "ScopeMismatch",
            Self::MissingSchema => "MissingSchema",
            Self::InvalidSchema => "InvalidSchema",
            Self::UnsupportedSchema(_) => "UnsupportedSchema",
            Self::SchemaViolations(_) => "SchemaViolations",
            Self::Checked(_) => "Checked",
            Self::Incomplete(_) => "Incomplete",
            Self::LimitExceeded(_) => "LimitExceeded",
        };
        f.write_str(name)
    }
}

/// One result keyed to the actual retained source document.
pub struct CustomDocumentResult {
    resource: crate::diagnostic::ResourceId,
    source: SourceRef,
    pointer: FieldPath,
    view: CustomResourceView,
    binding: Option<CustomDocumentBinding>,
    check: CustomDocumentCheck,
}

/// Coarse graph outcome for one supplied custom document; detailed checker results remain
/// available from [`ResourceSet::check_custom_documents`](crate::model::ResourceSet::check_custom_documents).
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum CustomDocumentGraphStatus {
    /// A unique supplied CRD, served version, scope, and supported schema check completed.
    Bound,
    /// No matching supplied CRD was present.
    MissingCrd,
    /// Multiple supplied CRDs matched the custom resource group and kind.
    AmbiguousCrd,
    /// Source identity or CRD evidence did not form one exact binding.
    InvalidBinding,
    /// The CRD does not list this version.
    VersionNotListed,
    /// The CRD lists this version but does not mark it served.
    VersionNotServed,
    /// The custom resource scope conflicts with the supplied CRD scope.
    ScopeMismatch,
    /// The selected served version has no structural schema.
    MissingSchema,
    /// The source schema or custom resource could not be decoded.
    InvalidSchema,
    /// Unsupported schema behavior prevents a complete binding.
    UnsupportedSchema,
    /// The supported local schema subset found one or more document violations.
    SchemaViolations,
    /// The local schema check could not establish a complete result.
    Incomplete,
    /// A processing ceiling stopped the local check.
    LimitExceeded,
    /// A target profile is required before a selected schema can be checked.
    TargetProfileRequired,
}

/// Source-bound graph evidence for one supplied custom resource.
#[derive(Clone)]
pub struct CustomDocumentGraphRecord {
    resource: crate::diagnostic::ResourceId,
    source: SourceRef,
    pointer: FieldPath,
    status: CustomDocumentGraphStatus,
    descriptor: Option<SuppliedCustomResourceDescriptor>,
}
impl fmt::Debug for CustomDocumentGraphRecord {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomDocumentGraphRecord")
            .field("resource", &self.resource)
            .field("source", &self.source)
            .field("pointer_depth", &self.pointer.depth())
            .field("status", &self.status)
            .field("has_descriptor", &self.descriptor.is_some())
            .finish()
    }
}
impl CustomDocumentGraphRecord {
    /// Input-local ID of the custom document.
    #[must_use]
    pub const fn resource_id(&self) -> crate::diagnostic::ResourceId {
        self.resource
    }
    /// Immutable source document coordinates.
    #[must_use]
    pub const fn source(&self) -> SourceRef {
        self.source
    }
    /// Graph binding outcome without private schema or document values.
    #[must_use]
    pub const fn status(&self) -> CustomDocumentGraphStatus {
        self.status
    }
    /// Selected descriptor only when the supported local check completed successfully.
    #[must_use]
    pub const fn descriptor(&self) -> Option<&SuppliedCustomResourceDescriptor> {
        self.descriptor.as_ref()
    }
    /// Reveal the custom-resource source pointer only with explicit source access.
    #[must_use]
    pub fn pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.pointer.reveal(access)
    }
}
impl fmt::Debug for CustomDocumentResult {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CustomDocumentResult")
            .field("source", &self.source)
            .field("pointer_depth", &self.pointer.depth())
            .field("binding", &self.binding)
            .field("check", &self.check)
            .finish_non_exhaustive()
    }
}
impl CustomDocumentResult {
    /// Immutable source document coordinates.
    #[must_use]
    pub const fn source(&self) -> SourceRef {
        self.source
    }
    /// Input-local resource ID retained by the resource set.
    #[must_use]
    pub const fn resource_id(&self) -> crate::diagnostic::ResourceId {
        self.resource
    }
    /// Protected source-bound resource identity and body.
    #[must_use]
    pub const fn resource(&self) -> &CustomResourceView {
        &self.view
    }
    /// Reveal the resource pointer only with explicit access.
    #[must_use]
    pub fn pointer(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.pointer.reveal(access)
    }
    /// Exact supplied CRD/version binding, when resolution selected one.
    #[must_use]
    pub const fn binding(&self) -> Option<&CustomDocumentBinding> {
        self.binding.as_ref()
    }
    /// Offline schema-resolution/check outcome; never an API-server admission result.
    #[must_use]
    pub const fn check(&self) -> &CustomDocumentCheck {
        &self.check
    }

    pub(crate) fn graph_record(&self) -> CustomDocumentGraphRecord {
        let status = match &self.check {
            CustomDocumentCheck::TargetProfileRequired => CustomDocumentGraphStatus::TargetProfileRequired,
            CustomDocumentCheck::MissingCrd => CustomDocumentGraphStatus::MissingCrd,
            CustomDocumentCheck::AmbiguousCrd => CustomDocumentGraphStatus::AmbiguousCrd,
            CustomDocumentCheck::InvalidBinding => CustomDocumentGraphStatus::InvalidBinding,
            CustomDocumentCheck::VersionNotListed => CustomDocumentGraphStatus::VersionNotListed,
            CustomDocumentCheck::VersionNotServed => CustomDocumentGraphStatus::VersionNotServed,
            CustomDocumentCheck::ScopeMismatch => CustomDocumentGraphStatus::ScopeMismatch,
            CustomDocumentCheck::MissingSchema => CustomDocumentGraphStatus::MissingSchema,
            CustomDocumentCheck::InvalidSchema => CustomDocumentGraphStatus::InvalidSchema,
            CustomDocumentCheck::UnsupportedSchema(_) => CustomDocumentGraphStatus::UnsupportedSchema,
            CustomDocumentCheck::SchemaViolations(_) => CustomDocumentGraphStatus::SchemaViolations,
            CustomDocumentCheck::Checked(_) => CustomDocumentGraphStatus::Bound,
            CustomDocumentCheck::Incomplete(_) => CustomDocumentGraphStatus::Incomplete,
            CustomDocumentCheck::LimitExceeded(_) => CustomDocumentGraphStatus::LimitExceeded,
        };
        CustomDocumentGraphRecord {
            resource: self.resource,
            source: self.source,
            pointer: self.pointer.clone(),
            status,
            descriptor: if status == CustomDocumentGraphStatus::Bound {
                self.binding.as_ref().map(|binding| binding.descriptor.clone())
            } else {
                None
            },
        }
    }

    pub(crate) fn controller_prerequisite(&self) -> Reference {
        Reference {
            from: self.resource,
            path: FieldPath::default(),
            relation: RelationshipKind::Operator,
            target: ReferenceTarget::External {
                kind: ExternalRefKind::Operator,
            },
            scope: ReferenceScope::Unknown,
        }
    }

    pub(crate) fn crd_version_reference(&self) -> Option<Reference> {
        if !matches!(&self.check, CustomDocumentCheck::Checked(_)) {
            return None;
        }
        let descriptor = self.binding.as_ref()?.descriptor.clone();
        Some(Reference {
            from: self.resource,
            path: FieldPath::default(),
            relation: RelationshipKind::Dependency,
            target: ReferenceTarget::SuppliedCustomResourceVersion { descriptor },
            scope: ReferenceScope::Cluster,
        })
    }
}

enum SchemaReference {
    Stable(JSONSchemaPropsCrdV1),
    Beta(JSONSchemaPropsCrdV1beta1),
}
struct VersionReference {
    name: String,
    served: Option<bool>,
    storage: Option<bool>,
    pointer: FieldPath,
    path: FieldPath,
    schema_pointer: FieldPath,
    schema_path: FieldPath,
    schema: Option<SchemaReference>,
}
struct CrdReference {
    resource: crate::diagnostic::ResourceId,
    source: SourceRef,
    pointer: FieldPath,
    gvk: crate::model::GroupVersionKind,
    group: String,
    kind: String,
    scope: Option<bool>,
    versions: Vec<VersionReference>,
    legacy_beta: Option<VersionReference>,
    invalid: bool,
}

/// Resolve and check unknown-scope documents against all actual supplied CRD documents.
///
/// The caller owns one operation budget for this entire pass. No source-free authored snapshot
/// can become a complete result because its evidence origin is preserved in the report.
pub(crate) fn check_custom_documents_with_limits(
    resources: &ResourceSet,
    target: &TargetProfile,
    limits: crate::processing::NativeProcessingLimits,
) -> Result<Vec<CustomDocumentResult>, Finding> {
    let processing = resources.operation(Some(limits));
    check_custom_documents_in(resources, Some(target), &processing)
}

/// Run the source-bound pass inside an existing operation session, including graph analysis.
pub(crate) fn check_custom_documents_in(
    resources: &ResourceSet,
    target: Option<&TargetProfile>,
    processing: &NativeOperationBudget,
) -> Result<Vec<CustomDocumentResult>, Finding> {
    let encoding = resources.encoding(target, processing.clone());
    let crds = collect_crds(resources, target, processing, &encoding)?;

    let mut results = Vec::new();
    for document in resources.documents() {
        if processing.exhausted() {
            return Err(processing.fail(Phase::Analysis));
        }
        let tree = document.current_tree_in(target, Some(&encoding))?;
        let gvk = tree_gvk(&tree)?;
        if gvk.group.as_deref() == Some("apiextensions.k8s.io")
            || matches!(
                document.original_identity().scope,
                ResourceScope::Cluster | ResourceScope::Namespaced
            )
        {
            continue;
        }
        if gvk.group.is_none() {
            continue;
        }
        processing.payload_array::<CustomDocumentResult>(1, Phase::Analysis)?;
        results.try_reserve(1).map_err(|_| processing.fail(Phase::Analysis))?;
        let identity = document.identity()?;
        let fields = document.field_decode_context(processing, Phase::Analysis)?;
        let pointer = fields.source_pointer().clone();
        let source = fields.source_ref().ok_or_else(|| processing.fail(Phase::Analysis))?;
        let (protected, body_failure) = match ProtectedJsonValue::decode(&tree, &fields, &pointer) {
            Ok(protected) => (Some(protected), None),
            Err(finding) if finding.code == FindingCode::LimitExceeded => return Err(finding),
            Err(_) => (None, Some(CustomDocumentCheck::InvalidSchema)),
        };
        let view = CustomResourceView {
            source,
            pointer: pointer.clone(),
            identity: identity.clone(),
            body: protected.clone(),
            evidence: document.source_evidence().clone(),
        };
        if gvk != document.original_identity().gvk {
            results.push(CustomDocumentResult {
                resource: document.id,
                source,
                pointer,
                view,
                binding: None,
                check: CustomDocumentCheck::InvalidBinding,
            });
            continue;
        }
        processing.work(crds.len(), Phase::Analysis)?;
        processing.payload_array::<&CrdReference>(crds.len(), Phase::Analysis)?;
        let candidates = crds
            .iter()
            .filter(|crd| crd.group == gvk.group.as_deref().unwrap_or_default() && crd.kind == gvk.kind)
            .collect::<Vec<_>>();
        let (binding, check) = if let Some(failure) = body_failure {
            (None, failure)
        } else {
            match candidates.as_slice() {
                [] => (None, CustomDocumentCheck::MissingCrd),
                [crd] => resolve_one(
                    document,
                    &pointer,
                    &identity,
                    crd,
                    target,
                    protected
                        .as_ref()
                        .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?,
                    &fields,
                ),
                _ => (None, CustomDocumentCheck::AmbiguousCrd),
            }
        };
        if processing.exhausted() {
            return Err(processing.fail(Phase::Analysis));
        }
        let binding = seal_binding(binding, resources, target, processing, &encoding)?;
        results.push(CustomDocumentResult {
            resource: document.id,
            source,
            pointer,
            view,
            binding,
            check,
        });
    }
    Ok(results)
}

fn collect_crds(
    resources: &ResourceSet,
    target: Option<&TargetProfile>,
    processing: &NativeOperationBudget,
    encoding: &crate::registry::EncodeContext<'_>,
) -> Result<Vec<CrdReference>, Finding> {
    let mut crds = Vec::new();
    for document in resources.documents() {
        if processing.exhausted() {
            return Err(processing.fail(Phase::Analysis));
        }
        let tree = document.current_tree_in(target, Some(encoding))?;
        let gvk = tree_gvk(&tree)?;
        if gvk.group.as_deref() != Some("apiextensions.k8s.io") || gvk.kind != "CustomResourceDefinition" {
            continue;
        }
        let fields = document.field_decode_context(processing, Phase::Analysis)?;
        let crd_pointer = fields.source_pointer().clone();
        if gvk.version == "v1" {
            let root = CustomResourceDefinitionV1::decode(&tree, &fields, &crd_pointer)?;
            crds.push(stable_crd(document, &crd_pointer, &root.spec, processing)?);
        } else if gvk.version == "v1beta1" {
            let root = CustomResourceDefinitionV1beta1::decode(&tree, &fields, &crd_pointer)?;
            crds.push(beta_crd(document, &crd_pointer, &root.spec, processing)?);
        }
    }

    Ok(crds)
}

fn seal_binding(
    binding: Option<CustomDocumentBinding>,
    resources: &ResourceSet,
    target: Option<&TargetProfile>,
    processing: &NativeOperationBudget,
    encoding: &crate::registry::EncodeContext<'_>,
) -> Result<Option<CustomDocumentBinding>, Finding> {
    let binding = if let Some(mut binding) = binding {
        processing.work(resources.documents().len(), Phase::Analysis)?;
        let crd_document = resources
            .documents()
            .iter()
            .find(|document| document.id == binding.descriptor.resource)
            .ok_or_else(|| Finding::error(FindingCode::InvalidIdentity, Phase::Analysis))?;
        let crd_tree = crd_document.current_tree_in(target, Some(encoding))?;
        let crd_fields = crd_document.field_decode_context(processing, Phase::Analysis)?;
        let effective_crd = ProtectedJsonValue::decode(&crd_tree, &crd_fields, crd_fields.source_pointer())?;
        if let Some(target) = target {
            processing.payload_array::<(crate::capability::FeatureGateId, bool)>(
                target.feature_gates.states.len(),
                Phase::Analysis,
            )?;
        }
        processing.payload(size_of::<DescriptorAuthority>(), Phase::Analysis)?;
        binding.descriptor.authority = Some(std::sync::Arc::new(DescriptorAuthority {
            set: SuppliedSetAuthority(resources.custom_authority.clone()),
            effective_crd,
            target: target.cloned(),
        }));
        Some(binding)
    } else {
        None
    };
    Ok(binding)
}

fn stable_crd(
    document: &ResourceDocument,
    root_pointer: &FieldPath,
    spec: &Presence<CustomResourceDefinitionSpecCrdV1>,
    processing: &NativeOperationBudget,
) -> Result<CrdReference, Finding> {
    let Some(spec) = spec.value() else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let (Some(group), Some(names)) = (spec.group.value(), spec.names.value()) else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let Some(kind) = names.kind.value() else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let scope = scope_value(spec.scope.value());
    let mut versions = Vec::new();
    let mut invalid = scope.is_none() || !valid_crd_group_kind(group, kind);
    match spec.versions.value() {
        Some(items) => {
            processing.payload_array::<VersionReference>(items.len(), Phase::Analysis)?;
            for (index, item) in items.iter().enumerate() {
                processing.work(1, Phase::Analysis)?;
                let path = FieldPath::default()
                    .child("spec")
                    .child("versions")
                    .child(index.to_string());
                let pointer = root_pointer
                    .clone()
                    .child("spec")
                    .child("versions")
                    .child(index.to_string());
                versions.push(stable_version(item, pointer, path));
            }
        }
        None => invalid = true,
    }
    invalid |= invalid_versions(&versions);
    invalid |= versions.iter().any(|item| !valid_crd_version(group, kind, &item.name));
    Ok(CrdReference {
        resource: document.id,
        source: document.source(),
        pointer: root_pointer.clone(),
        gvk: document.original_identity().gvk.clone(),
        group: group.clone(),
        kind: kind.clone(),
        scope,
        versions,
        legacy_beta: None,
        invalid,
    })
}

fn beta_crd(
    document: &ResourceDocument,
    root_pointer: &FieldPath,
    spec: &Presence<CustomResourceDefinitionSpecCrdV1beta1>,
    processing: &NativeOperationBudget,
) -> Result<CrdReference, Finding> {
    let Some(spec) = spec.value() else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let (Some(group), Some(names)) = (spec.group.value(), spec.names.value()) else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let Some(kind) = names.kind.value() else {
        return Ok(invalid_crd(document, root_pointer));
    };
    let scope = scope_value(spec.scope.value());
    let mut versions = Vec::new();
    let mut invalid = scope.is_none() || !valid_crd_group_kind(group, kind);
    if let Some(items) = spec.versions.value() {
        processing.payload_array::<VersionReference>(items.len(), Phase::Analysis)?;
        for (index, item) in items.iter().enumerate() {
            processing.work(1, Phase::Analysis)?;
            let path = FieldPath::default()
                .child("spec")
                .child("versions")
                .child(index.to_string());
            let pointer = root_pointer
                .clone()
                .child("spec")
                .child("versions")
                .child(index.to_string());
            versions.push(beta_version(item, pointer, path));
        }
        invalid |= invalid_versions(&versions);
        invalid |= versions.iter().any(|item| !valid_crd_version(group, kind, &item.name));
    }
    let legacy_beta = spec.version.value().map(|version| {
        let spec_pointer = root_pointer.child("spec");
        let schema = spec
            .validation
            .value()
            .and_then(|validation| validation.open_api_v3_schema.value())
            .cloned();
        VersionReference {
            name: version.clone(),
            // Beta singular-version defaulting/conversion semantics remain unresolved.
            served: None,
            storage: None,
            pointer: spec_pointer.child("version"),
            path: FieldPath::default().child("spec").child("version"),
            schema_pointer: spec_pointer.child("validation").child("openAPIV3Schema"),
            schema_path: FieldPath::default()
                .child("spec")
                .child("validation")
                .child("openAPIV3Schema"),
            schema: schema.map(SchemaReference::Beta),
        }
    });
    if spec.versions.is_absent() || (spec.version.is_absent() && spec.validation.value().is_some()) {
        invalid = true;
    }
    Ok(CrdReference {
        resource: document.id,
        source: document.source(),
        pointer: root_pointer.clone(),
        gvk: document.original_identity().gvk.clone(),
        group: group.clone(),
        kind: kind.clone(),
        scope,
        versions,
        legacy_beta,
        invalid,
    })
}

fn stable_version(
    item: &super::CustomResourceDefinitionVersionCrdV1,
    pointer: FieldPath,
    path: FieldPath,
) -> VersionReference {
    let schema = item
        .schema
        .value()
        .and_then(|validation| validation.open_api_v3_schema.value())
        .cloned();
    VersionReference {
        name: item.name.value().cloned().unwrap_or_default(),
        served: item.served.value().copied(),
        storage: item.storage.value().copied(),
        schema_path: path.child("schema").child("openAPIV3Schema"),
        schema_pointer: pointer.child("schema").child("openAPIV3Schema"),
        pointer,
        path,
        schema: schema.map(SchemaReference::Stable),
    }
}

fn beta_version(
    item: &super::CustomResourceDefinitionVersionCrdV1beta1,
    pointer: FieldPath,
    path: FieldPath,
) -> VersionReference {
    let schema = item
        .schema
        .value()
        .and_then(|validation| validation.open_api_v3_schema.value())
        .cloned();
    VersionReference {
        name: item.name.value().cloned().unwrap_or_default(),
        served: item.served.value().copied(),
        storage: item.storage.value().copied(),
        schema_path: path.child("schema").child("openAPIV3Schema"),
        schema_pointer: pointer.child("schema").child("openAPIV3Schema"),
        pointer,
        path,
        schema: schema.map(SchemaReference::Beta),
    }
}

fn invalid_versions(versions: &[VersionReference]) -> bool {
    let mut names = std::collections::BTreeSet::new();
    let mut storage_count = 0usize;
    for version in versions {
        if version.name.is_empty()
            || !names.insert(version.name.as_str())
            || version.served.is_none()
            || version.storage.is_none()
        {
            return true;
        }
        storage_count += usize::from(version.storage == Some(true));
    }
    storage_count != 1
}

fn invalid_crd(document: &ResourceDocument, pointer: &FieldPath) -> CrdReference {
    CrdReference {
        resource: document.id,
        source: document.source(),
        pointer: pointer.clone(),
        gvk: document.original_identity().gvk.clone(),
        group: String::new(),
        kind: String::new(),
        scope: None,
        versions: Vec::new(),
        legacy_beta: None,
        invalid: true,
    }
}

fn scope_value(value: Option<&String>) -> Option<bool> {
    match value.map(String::as_str) {
        Some("Namespaced") => Some(true),
        Some("Cluster") => Some(false),
        _ => None,
    }
}

fn valid_crd_group_kind(group: &str, kind: &str) -> bool {
    crate::value::dns_subdomain(group) && valid_ascii_identity(kind)
}

fn valid_crd_version(group: &str, kind: &str, version: &str) -> bool {
    crate::value::dns_subdomain(group) && valid_ascii_identity(kind) && valid_ascii_identity(version)
}

fn valid_ascii_identity(value: &str) -> bool {
    !value.is_empty() && value.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
fn document_pointer(collection: Option<&crate::model::CollectionPath>) -> FieldPath {
    let mut pointer = FieldPath::default();
    if let Some(collection) = collection {
        for (_, index) in &collection.items {
            pointer = pointer.child("items").child(index.to_string());
        }
    }
    pointer
}

fn resolve_one(
    document: &ResourceDocument,
    document_pointer: &FieldPath,
    identity: &ResourceIdentity,
    crd: &CrdReference,
    target: Option<&TargetProfile>,
    protected: &ProtectedJsonValue,
    fields: &crate::registry::FieldDecodeContext,
) -> (Option<CustomDocumentBinding>, CustomDocumentCheck) {
    let group = identity.gvk.group.as_deref().unwrap_or_default();
    let kind = identity.gvk.kind.as_str();
    let version = identity.gvk.version.as_str();
    let Some(namespaced) = crd.scope else {
        return (None, CustomDocumentCheck::InvalidBinding);
    };
    if crd.invalid {
        return (None, CustomDocumentCheck::InvalidBinding);
    }
    let version_matches = crd
        .versions
        .iter()
        .filter(|item| item.name == version)
        .collect::<Vec<_>>();
    if version_matches.len() > 1 {
        return (None, CustomDocumentCheck::InvalidBinding);
    }
    let selected = if let Some(found) = version_matches.first() {
        if let Some(legacy) = &crd.legacy_beta {
            if legacy.name == version && legacy.schema.is_some() && found.schema.is_some() {
                return (None, CustomDocumentCheck::InvalidBinding);
            }
        }
        *found
    } else if crd.versions.is_empty() {
        match &crd.legacy_beta {
            Some(legacy) if legacy.name == version => legacy,
            _ => return (None, CustomDocumentCheck::VersionNotListed),
        }
    } else {
        return (None, CustomDocumentCheck::VersionNotListed);
    };
    if selected.served != Some(true) {
        return (None, CustomDocumentCheck::VersionNotServed);
    }
    if identity.scope != (ResourceScope::CrdResolved { namespaced }) {
        return (None, CustomDocumentCheck::ScopeMismatch);
    }
    let Some(schema) = &selected.schema else {
        return (None, CustomDocumentCheck::MissingSchema);
    };
    let binding = CustomDocumentBinding {
        document: document.source(),
        document_pointer: document_pointer.clone(),
        descriptor: SuppliedCustomResourceDescriptor {
            authority: None,
            resource: crd.resource,
            crd: crd.source,
            crd_gvk: crd.gvk.clone(),
            crd_pointer: crd.pointer.clone(),
            group: group.to_owned(),
            kind: kind.to_owned(),
            version: version.to_owned(),
            version_pointer: selected.pointer.clone(),
            version_path: selected.path.clone(),
            scope: ResourceScope::CrdResolved { namespaced },
            storage: selected.storage.unwrap_or(false),
            schema_pointer: selected.schema_pointer.clone(),
            schema_path: selected.schema_path.clone(),
            schema_family: match schema {
                SchemaReference::Stable(_) => "v1",
                SchemaReference::Beta(_) => "v1beta1",
            },
        },
    };
    let Some(target) = target else {
        return (Some(binding), CustomDocumentCheck::TargetProfileRequired);
    };
    let compiled = match schema {
        SchemaReference::Stable(schema) => schema.compile_inherited(target, fields),
        SchemaReference::Beta(schema) => schema.compile_inherited(target, fields),
    };
    let compiled = match compiled {
        Ok(compiled) => compiled,
        Err(finding) if finding.code == FindingCode::LimitExceeded => {
            return (Some(binding), CustomDocumentCheck::LimitExceeded(None));
        }
        Err(_) => return (Some(binding), CustomDocumentCheck::InvalidSchema),
    };
    let report = match compiled.check_inherited(protected, fields, document_pointer) {
        Ok(report) => report,
        Err(finding) if finding.code == FindingCode::LimitExceeded => {
            return (Some(binding), CustomDocumentCheck::LimitExceeded(None));
        }
        Err(_) => return (Some(binding), CustomDocumentCheck::InvalidSchema),
    };
    // The descriptor stays attached even when the result is incomplete or unsupported.
    let check = if report.limit_exceeded() {
        CustomDocumentCheck::LimitExceeded(Some(report))
    } else if report.incomplete() {
        CustomDocumentCheck::Incomplete(report)
    } else if report.unsupported_count() > 0 {
        CustomDocumentCheck::UnsupportedSchema(report)
    } else if !report.supported_subset_satisfied() {
        CustomDocumentCheck::SchemaViolations(report)
    } else {
        CustomDocumentCheck::Checked(report)
    };
    (Some(binding), check)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::extensions::test_support::{TestRequired, TestResult};
    use crate::{
        capability::KubernetesVersion,
        parser::parse_source_in,
        source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
    };

    fn set(text: &str) -> TestResult<ResourceSet> {
        let limits = ParseLimits::default();
        parse_source_in(
            SourceInput {
                id: SourceId(7),
                format: DocumentFormat::Json,
                origin: InputOrigin::ClusterExport,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &limits,
            &NativeOperationBudget::new(limits.processing),
        )
        .required("parse")?
        .flatten_resources()
        .required("flatten")
    }

    fn set_yaml(text: &str) -> TestResult<ResourceSet> {
        let limits = ParseLimits::default();
        parse_source_in(
            SourceInput {
                id: SourceId(7),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::ClusterExport,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &limits,
            &NativeOperationBudget::new(limits.processing),
        )
        .required("parse")?
        .flatten_resources()
        .required("flatten")
    }

    fn target() -> TestResult<TargetProfile> {
        Ok(TargetProfile::documented_defaults(
            KubernetesVersion::new(1, 37).required("version")?,
        ))
    }

    fn check(resources: &ResourceSet) -> TestResult<Vec<CustomDocumentResult>> {
        resources
            .check_custom_documents(&target()?, crate::processing::NativeProcessingLimits::default())
            .required("custom document check")
    }

    const STABLE: &str = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","singular":"widget","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object","required":["name"],"properties":{"name":{"type":"string","minLength":2,"pattern":"private-pattern"}}}}}]}}"#;

    #[test]
    fn supplied_crd_binds_schema_and_reports_supported_and_unsupported_checks() -> TestResult {
        let text = format!(
            "{STABLE}\n---\napiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: n\nname: x"
        );
        let set = set_yaml(&text)?;
        let results = check(&set)?;
        let result = results.first().required("custom document result")?;
        assert_eq!(result.check_kind_for_test(), "UnsupportedSchema");
        let CustomDocumentCheck::UnsupportedSchema(report) = &result.check else {
            return Err("expected unsupported schema report".into());
        };
        assert_eq!(report.unsupported_count(), 1);
        assert_eq!(report.issues().len(), 1);
        let binding = result.binding.as_ref().required("binding")?;
        let access = crate::source::ExplicitSourceAccess::explicitly_allow_raw_source();
        assert_eq!(binding.document_pointer(&access), "");
        assert_eq!(
            binding.schema_pointer(&access),
            "/spec/versions/0/schema/openAPIV3Schema"
        );
        Ok(())
    }

    #[test]
    fn supplied_crd_binds_custom_document_inside_a_valid_core_list() -> TestResult {
        let text = format!(
            "---\napiVersion: v1\nkind: List\nitems:\n- apiVersion: example.test/v1\n  kind: Widget\n  metadata:\n    name: w\n    namespace: n\n  name: x\n---\n{STABLE}"
        );
        let set = set_yaml(&text)?;
        let results = check(&set)?;
        let result = results.first().required("custom document result")?;
        assert_eq!(result.check_kind_for_test(), "UnsupportedSchema");
        let binding = result.binding.as_ref().required("source binding")?;
        let access = crate::source::ExplicitSourceAccess::explicitly_allow_raw_source();
        assert_eq!(binding.document_pointer(&access), "/items/0");
        assert_eq!(
            binding.schema_pointer(&access),
            "/spec/versions/0/schema/openAPIV3Schema"
        );
        let debug = format!("{result:?}");
        assert!(!debug.contains("private-pattern"));
        assert!(!debug.contains("widgets"));
        Ok(())
    }

    #[test]
    fn list_contained_crd_pointers_include_each_source_collection_prefix() -> TestResult {
        let text = concat!(
            "apiVersion: v1\nkind: List\nitems:\n",
            "- apiVersion: apiextensions.k8s.io/v1\n  kind: CustomResourceDefinition\n",
            "  metadata:\n    name: widgets.example.test\n",
            "  spec:\n    group: example.test\n    scope: Namespaced\n",
            "    names:\n      plural: widgets\n      kind: Widget\n",
            "    versions:\n    - name: v1\n      served: true\n      storage: true\n",
            "      schema:\n        openAPIV3Schema:\n          type: object\n",
            "          properties:\n            name:\n              type: string\n              pattern: private-list-pattern\n",
            "---\napiVersion: v1\nkind: List\nitems:\n",
            "- apiVersion: example.test/v1\n  kind: Widget\n",
            "  metadata:\n    name: w\n    namespace: n\n  name: x\n",
        );
        let set = set_yaml(text)?;
        let results = check(&set)?;
        let result = results.first().required("custom document result")?;
        let binding = result.binding.as_ref().required("source binding")?;
        let access = crate::source::ExplicitSourceAccess::explicitly_allow_raw_source();
        assert_eq!(binding.crd_pointer(&access), "/items/0");
        assert_eq!(binding.document_pointer(&access), "/items/0");
        assert_eq!(binding.version_pointer(&access), "/items/0/spec/versions/0");
        assert_eq!(
            binding.schema_pointer(&access),
            "/items/0/spec/versions/0/schema/openAPIV3Schema"
        );
        let CustomDocumentCheck::UnsupportedSchema(report) = &result.check else {
            return Err("expected unsupported schema outcome".into());
        };
        assert_eq!(
            report.unsupported_path(0, &access).as_deref(),
            Some("/items/0/spec/versions/0/schema/openAPIV3Schema/properties/name/pattern")
        );
        let debug = format!("{result:?}");
        assert!(!debug.contains("example.test"));
        Ok(())
    }

    #[test]
    fn absent_crd_and_source_free_evidence_never_claim_a_complete_binding() -> TestResult {
        let set = set(r#"{"apiVersion":"example.test/v1","kind":"Widget","metadata":{"name":"w"}}"#)?;
        let results = check(&set)?;
        assert_eq!(results[0].check_kind_for_test(), "MissingCrd");
        Ok(())
    }

    #[test]
    fn served_schema_and_version_binding_failures_stay_distinct() -> TestResult {
        let unserved = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":false,"storage":true}]}}"#;
        let missing_schema = r#"{"apiVersion":"apiextensions.k8s.io/v1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true}]}}"#;
        let custom_v1 = "apiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: n";
        let custom_v2 = custom_v1.replace("/v1", "/v2");
        let make = |crd: &str, custom: &str| set_yaml(&format!("{crd}\n---\n{custom}"));
        let unserved_set = make(unserved, custom_v1)?;
        let result = check(&unserved_set)?;
        assert_eq!(result[0].check_kind_for_test(), "VersionNotServed");

        let missing_set = make(missing_schema, custom_v1)?;
        let result = check(&missing_set)?;
        assert_eq!(result[0].check_kind_for_test(), "MissingSchema");

        let listed_set = make(missing_schema, &custom_v2)?;
        let result = check(&listed_set)?;
        assert_eq!(result[0].check_kind_for_test(), "VersionNotListed");
        Ok(())
    }

    #[test]
    fn beta_singular_and_per_version_schemas_remain_ambiguous_or_unresolved() -> TestResult {
        let beta_ambiguous = r#"{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","version":"v1","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"validation":{"openAPIV3Schema":{"type":"object"}},"versions":[{"name":"v1","served":true,"storage":true,"schema":{"openAPIV3Schema":{"type":"object"}}}]}}"#;
        let beta_legacy_only = r#"{"apiVersion":"apiextensions.k8s.io/v1beta1","kind":"CustomResourceDefinition","metadata":{"name":"widgets.example.test"},"spec":{"group":"example.test","version":"v1","scope":"Namespaced","names":{"plural":"widgets","kind":"Widget"},"validation":{"openAPIV3Schema":{"type":"object"}}}}"#;
        let custom = "apiVersion: example.test/v1\nkind: Widget\nmetadata:\n  name: w\n  namespace: n";
        for (crd, expected) in [(beta_ambiguous, "InvalidBinding"), (beta_legacy_only, "InvalidBinding")] {
            let resources = set_yaml(&format!("{crd}\n---\n{custom}"))?;
            let result = check(&resources)?;
            assert_eq!(result[0].check_kind_for_test(), expected);
        }
        Ok(())
    }

    #[test]
    fn nested_list_coordinates_build_exact_private_document_pointer() {
        let collection = crate::model::CollectionPath {
            items: vec![(crate::model::ListId(3), 2), (crate::model::ListId(8), 5)],
        };
        let pointer = document_pointer(Some(&collection));
        let access = crate::source::ExplicitSourceAccess::explicitly_allow_raw_source();
        assert_eq!(pointer.reveal(&access), "/items/2/items/5");
    }

    impl CustomDocumentResult {
        fn check_kind_for_test(&self) -> &'static str {
            match &self.check {
                CustomDocumentCheck::TargetProfileRequired => "TargetProfileRequired",
                CustomDocumentCheck::MissingCrd => "MissingCrd",
                CustomDocumentCheck::UnsupportedSchema(_) => "UnsupportedSchema",
                CustomDocumentCheck::SchemaViolations(_) => "SchemaViolations",
                CustomDocumentCheck::Checked(_) => "Checked",
                CustomDocumentCheck::Incomplete(_) => "Incomplete",
                CustomDocumentCheck::InvalidBinding => "InvalidBinding",
                CustomDocumentCheck::VersionNotListed => "VersionNotListed",
                CustomDocumentCheck::VersionNotServed => "VersionNotServed",
                CustomDocumentCheck::MissingSchema => "MissingSchema",
                _ => "Other",
            }
        }
    }
}
