//! Sealed codec interface and fixed cohort extension boundary.
use crate::{
    capability::{KindCapability, TargetProfile},
    diagnostic::{Finding, FindingCode, Phase},
    graph::{Reference, ReferenceSink},
    model::{GroupVersionKind, ResourceScope},
    source::SourceEvidence,
    syntax::{SyntaxBuilder, TreeNode},
};
use std::{any::Any, collections::BTreeMap};

pub(crate) trait FindingSink {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    fn push(&mut self, finding: Finding);
}
impl FindingSink for Vec<Finding> {
    fn push(&mut self, finding: Finding) {
        Self::push(self, finding);
    }
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Sealed cohort extension; no production codecs are delivered yet"
    )
)]
pub(crate) struct DecodeContext<'a> {
    pub(crate) gvk: &'a GroupVersionKind,
    pub(crate) scope: ResourceScope,
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Sealed cohort extension; no production codecs are delivered yet"
    )
)]
pub(crate) struct EncodeContext<'a> {
    pub(crate) target: Option<&'a TargetProfile>,
}
#[cfg_attr(
    not(test),
    expect(
        dead_code,
        reason = "Sealed cohort extension; no production codecs are delivered yet"
    )
)]
pub(crate) struct ValidationContext<'a> {
    pub(crate) target: &'a TargetProfile,
}
pub(crate) trait NativeResource: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn collect_references(&self, out: &mut dyn ReferenceSink);
    fn collect_protected_paths(&self, out: &mut Vec<crate::diagnostic::FieldPath>);
    fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink);
    fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding>;
}
pub(crate) type DecodeFn =
    fn(&TreeNode, &SourceEvidence, &DecodeContext<'_>) -> Result<Box<dyn NativeResource>, Vec<Finding>>;
pub(crate) struct ResourceRegistration {
    pub(crate) gvk: GroupVersionKind,
    pub(crate) scope: ResourceScope,
    pub(crate) decode: DecodeFn,
    pub(crate) capability: KindCapability,
}
pub(crate) struct TypedListRegistration {
    pub(crate) gvk: GroupVersionKind,
    pub(crate) item_gvk: GroupVersionKind,
}
pub(crate) struct RegistryBuilder {
    pub(crate) entries: BTreeMap<GroupVersionKind, ResourceRegistration>,
    pub(crate) lists: BTreeMap<GroupVersionKind, GroupVersionKind>,
}
impl RegistryBuilder {
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            lists: BTreeMap::new(),
        }
    }
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Sealed cohort extension; no production codecs are delivered yet"
        )
    )]
    pub(crate) fn register(&mut self, entry: ResourceRegistration) -> Result<(), Finding> {
        if entry.gvk != entry.capability.gvk
            || entry.scope != entry.capability.scope
            || self.entries.contains_key(&entry.gvk)
            || self.lists.contains_key(&entry.gvk)
            || crate::capability::declaration(&entry.gvk).is_none_or(|decl| decl.scope != entry.scope)
        {
            return Err(invalid());
        }
        self.entries.insert(entry.gvk.clone(), entry);
        Ok(())
    }
    pub(crate) fn register_list(&mut self, entry: TypedListRegistration) -> Result<(), Finding> {
        if self.lists.contains_key(&entry.gvk)
            || self.entries.contains_key(&entry.gvk)
            || entry.gvk.group != entry.item_gvk.group
            || entry.gvk.version != entry.item_gvk.version
            || entry.gvk.kind != format!("{}List", entry.item_gvk.kind)
            || crate::capability::declaration(&entry.item_gvk).is_none()
        {
            return Err(invalid());
        }
        self.lists.insert(entry.gvk, entry.item_gvk);
        Ok(())
    }
}
fn invalid() -> Finding {
    Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)
}
pub(crate) fn encode(resource: &dyn NativeResource, target: Option<&TargetProfile>) -> Result<TreeNode, Finding> {
    let mut out = SyntaxBuilder::new();
    resource.encode_known(&EncodeContext { target }, &mut out)?;
    out.finish()
}
pub(crate) fn collect(resource: &dyn NativeResource) -> Vec<Reference> {
    let mut out = Vec::new();
    resource.collect_references(&mut out);
    out
}
