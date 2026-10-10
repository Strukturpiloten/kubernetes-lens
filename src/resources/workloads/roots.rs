//! Concrete roots have one fixed served API identity, independent of source-minor evidence.
use super::{
    CronJobV1Beta1Spec, CronJobV1Spec, DaemonSetSpec, DeploymentSpec, EncodeContext, FieldCodec, FieldPath, Finding,
    FindingCode, JobSpec, Metadata, Phase, PodSpec, Presence, ReplicaSetSpec, ReplicationControllerSpec,
    StatefulSetSpec, TreeNode,
};
use crate::{
    graph::ReferenceSink,
    model::{GroupVersionKind, ResourceScope},
    registry::{DecodeContext, FindingSink, NativeResource, RegistryBuilder, ResourceRegistration, ValidationContext},
    source::SourceEvidence,
    syntax::{SyntaxBuilder, UnknownFields},
};
use std::any::Any;

macro_rules! root {
    ($name:ident, $api:literal, $kind:literal, $spec:ty, $first:literal, $last:literal) => {
        #[doc = concat!("Native `", $api, "` `", $kind, "`; omitted members remain omitted.")]
        #[derive(Clone, Default, Debug)]
        pub struct $name {
            /// Explicit native metadata presence.
            pub metadata: Presence<Metadata>,
            /// Explicit native specification presence.
            pub spec: Presence<$spec>,
            pub(crate) unknown: UnknownFields,
        }
        impl $name {
            /// Exact served API spelling of this concrete native type.
            pub const API_VERSION: &'static str = $api;
            /// Exact native kind spelling.
            pub const KIND: &'static str = $kind;
            /// Borrow retained unadmitted root members without revealing payloads.
            #[must_use]
            pub const fn unknown_fields(&self) -> &UnknownFields {
                &self.unknown
            }
        }
        impl crate::resources::common::UnknownScopes for $name {
            fn unknown_scopes(&self, path: &FieldPath, out: &mut std::collections::BTreeSet<FieldPath>) {
                if !self.unknown.is_empty() {
                    out.insert(path.clone());
                }
                crate::resources::common::UnknownScopes::unknown_scopes(&self.spec, &path.child("spec"), out);
            }
        }
        impl FieldCodec for $name {
            fn decode(
                node: &TreeNode,
                ctx: &crate::registry::FieldDecodeContext,
                path: &FieldPath,
            ) -> Result<Self, Finding> {
                crate::registry::codec::object(node, path)?;
                if node.get("apiVersion").and_then(TreeNode::as_str) != Some($api)
                    || node.get("kind").and_then(TreeNode::as_str) != Some($kind)
                {
                    return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding).at_path(path.clone()));
                }
                Ok(Self {
                    metadata: crate::registry::codec::read_presence(node, "metadata", ctx, path)?,
                    spec: crate::registry::codec::read_presence(node, "spec", ctx, path)?,
                    unknown: UnknownFields::capture(node, &["apiVersion", "kind", "metadata", "spec"]),
                })
            }
            fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
                let mut entries = vec![
                    (
                        ctx.key("apiVersion", path)?,
                        ctx.string($api, &path.child("apiVersion"))?,
                    ),
                    (ctx.key("kind", path)?, ctx.string($kind, &path.child("kind"))?),
                ];
                crate::registry::codec::write_presence(&mut entries, "metadata", &self.metadata, ctx, path)?;
                crate::registry::codec::write_presence(&mut entries, "spec", &self.spec, ctx, path)?;
                crate::registry::codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
                ctx.object(entries, path)
            }
        }
        impl From<$name> for crate::model::AuthoredResource {
            fn from(value: $name) -> Self {
                Self::new(Box::new(value))
            }
        }
        impl NativeResource for $name {
            fn as_any(&self) -> &dyn Any {
                self
            }
            fn as_any_mut(&mut self) -> &mut dyn Any {
                self
            }
            fn collect_references(&self, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
                self.references(ctx, out);
            }
            fn collect_protected_paths(&self, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
                self.protected_paths(ctx, out);
            }
            fn collect_native_facts(
                &self,
                ctx: &crate::registry::ProjectionContext<'_>,
                out: &mut Vec<crate::graph::NativeFact>,
            ) {
                super::facts::collect($kind, ctx, out);
            }
            fn collect_observation_paths(&self, tree: &TreeNode, out: &mut Vec<crate::source::ObservationPath>) {
                super::facts::observations($kind, tree, out);
            }
            fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
                self.validate_native(ctx, out);
            }
            fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding> {
                out.set_root(self.encode(ctx, &FieldPath::default())?);
                Ok(())
            }
        }
    };
}
root!(Pod, "v1", "Pod", PodSpec, 20, 37);
root!(Deployment, "apps/v1", "Deployment", DeploymentSpec, 20, 37);
root!(StatefulSet, "apps/v1", "StatefulSet", StatefulSetSpec, 20, 37);
root!(DaemonSet, "apps/v1", "DaemonSet", DaemonSetSpec, 20, 37);
root!(ReplicaSet, "apps/v1", "ReplicaSet", ReplicaSetSpec, 20, 37);
root!(
    ReplicationController,
    "v1",
    "ReplicationController",
    ReplicationControllerSpec,
    20,
    37
);
root!(Job, "batch/v1", "Job", JobSpec, 20, 37);
root!(CronJobV1, "batch/v1", "CronJob", CronJobV1Spec, 21, 37);
root!(CronJobV1Beta1, "batch/v1beta1", "CronJob", CronJobV1Beta1Spec, 20, 24);

pub(super) trait RootHooks {
    fn references(&self, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink);
    fn protected_paths(&self, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>);
    fn validate_native(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink);
}

pub(crate) fn register(registry: &mut RegistryBuilder) -> Result<(), Finding> {
    macro_rules! register {
        ($name:ident) => {{
            fn decode(
                node: &TreeNode,
                _: &SourceEvidence,
                ctx: &DecodeContext<'_>,
            ) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
                if ctx.scope != ResourceScope::Namespaced
                    || ctx.gvk.kind != $name::KIND
                    || ctx.gvk.api_version() != $name::API_VERSION
                {
                    return Err(vec![Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)]);
                }
                $name::decode(node, &ctx.fields, &FieldPath::default())
                    .map(|v| Box::new(v) as Box<dyn NativeResource>)
                    .map_err(|e| vec![e])
            }
            let gvk = GroupVersionKind::new($name::API_VERSION, $name::KIND)?;
            registry.register(ResourceRegistration {
                gvk: gvk.clone(),
                scope: ResourceScope::Namespaced,
                decode,
                capability: super::capabilities::for_api(gvk)?,
            })?;
        }};
    }
    register!(Pod);
    register!(Deployment);
    register!(StatefulSet);
    register!(DaemonSet);
    register!(ReplicaSet);
    register!(ReplicationController);
    register!(Job);
    register!(CronJobV1);
    register!(CronJobV1Beta1);
    Ok(())
}
