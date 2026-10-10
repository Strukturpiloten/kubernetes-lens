//! Concrete native API roots and fixed registry entries.
use super::types::{
    EndpointDiscoveryV1, EndpointDiscoveryV1beta1, EndpointPortDiscoveryV1, EndpointPortDiscoveryV1beta1,
    EndpointSubset, IngressClassV1Beta1Spec, IngressClassV1Spec, IngressExtensionsV1Beta1Spec, IngressV1Beta1Spec,
    IngressV1Spec, NetworkPolicySpec, ServiceSpec,
};
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::{NativeFact, ReferenceSink},
    model::{AuthoredResource, GroupVersionKind, Metadata, ResourceScope},
    registry::{
        DecodeContext, EncodeContext, FindingSink, NativeResource, ProjectionContext, RegistryBuilder,
        ResourceRegistration, ValidationContext,
        codec::{self, FieldCodec},
    },
    resources::common::UnknownScopes,
    source::SourceEvidence,
    syntax::{SyntaxBuilder, TreeNode, UnknownFields},
    value::Presence,
};
use std::any::Any;
#[cfg(test)]
use std::collections::BTreeSet;

macro_rules! root {
    ($name:ident, $api:literal, $kind:literal, $scope:ident, {$($wire:literal => $member:ident: $ty:ty,)*}) => {
        #[doc = concat!("Native `", $api, "` `", $kind, "`; no API or runtime defaults are materialized.")]
        #[derive(Clone, Default, Debug)]
        pub struct $name {
            /// Exact authored metadata presence.
            pub metadata: Presence<Metadata>,
            $(#[doc = concat!("Explicit native `", $wire, "` presence.")]
            pub $member: Presence<$ty>,)*
            unknown: UnknownFields,
        }
        impl $name {
            /// Exact served API identity.
            pub const API_VERSION: &'static str = $api;
            /// Native kind identity.
            pub const KIND: &'static str = $kind;
            /// Private retained unadmitted root members.
            #[must_use]
            pub const fn unknown_fields(&self) -> &UnknownFields { &self.unknown }
        }
        impl super::validation::Profile for $name {
            const API: &'static str = $api;
            const KIND: &'static str = $kind;
        }
        impl UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, path: &FieldPath, out: &mut BTreeSet<FieldPath>) {
                if !self.unknown.is_empty() { out.insert(path.clone()); }
                self.metadata.unknown_scopes(&path.child("metadata"),out);
                $(self.$member.unknown_scopes(&path.child($wire),out);)*
            }
            fn visit_unknown_scopes(&self, path: &FieldPath, visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>) -> bool {
                if !visitor.step() || (!self.unknown.is_empty() && !visitor.found(path)) { return false; }
                let Some(child) = visitor.child(path, "metadata") else { return false; };
                if !self.metadata.visit_unknown_scopes(&child, visitor) { return false; }
                $(let Some(child) = visitor.child(path, $wire) else { return false; };
                  if !self.$member.visit_unknown_scopes(&child, visitor) { return false; })*
                true
            }
        }
        impl FieldCodec for $name {
            fn decode(node: &TreeNode, ctx: &crate::registry::FieldDecodeContext, path: &FieldPath) -> Result<Self,Finding> {
                ctx.processing.tree_copy(node,ctx.phase)?;
                codec::object(node,path)?;
                if node.get("apiVersion").and_then(TreeNode::as_str)!=Some($api) || node.get("kind").and_then(TreeNode::as_str)!=Some($kind) {
                    return Err(Finding::error(FindingCode::CodecIdentityMismatch,Phase::Decoding).at_path(path.clone()));
                }
                Ok(Self {metadata:codec::read_presence(node,"metadata",ctx,path)?,
                    $($member:codec::read_presence(node,$wire,ctx,path)?,)*
                    unknown:UnknownFields::capture_in(node,&["apiVersion","kind","metadata",$($wire,)*],ctx)?,
                })
            }
            fn encode(&self,ctx:&EncodeContext<'_>,path:&FieldPath)->Result<TreeNode,Finding> {
                let mut entries=vec![(ctx.key("apiVersion",path)?,ctx.string($api,&path.child("apiVersion"))?),
                    (ctx.key("kind",path)?,ctx.string($kind,&path.child("kind"))?)];
                codec::write_presence(&mut entries,"metadata",&self.metadata,ctx,path)?;
                $(codec::write_presence(&mut entries,$wire,&self.$member,ctx,path)?;)*
                codec::append_unknown(&self.unknown,&mut entries,ctx,path)?;
                ctx.object(entries,path)
            }
        }
        impl From<$name> for AuthoredResource {
            fn from(value:$name)->Self {Self::new(Box::new(value))}
        }
        impl NativeResource for $name {
            fn as_any(&self)->&dyn Any {self}
            fn as_any_mut(&mut self)->&mut dyn Any {self}
            fn collect_references(&self,ctx:&EncodeContext<'_>,out:&mut dyn ReferenceSink) {super::facts::references(self,ctx,out);}
            fn collect_protected_paths(&self,ctx:&EncodeContext<'_>,out:&mut Vec<FieldPath>) {super::facts::protected(self,ctx,out);}
            fn collect_native_facts(&self,ctx:&ProjectionContext<'_>,out:&mut Vec<NativeFact>) {super::facts::collect($kind,ctx,out);}
            fn validate(&self,ctx:&ValidationContext<'_>,out:&mut dyn FindingSink) {super::validation::validate(self,ctx,out);}
            fn encode_known(&self,ctx:&EncodeContext<'_>,out:&mut SyntaxBuilder)->Result<(),Finding> {
                out.set_root(self.encode(ctx,&FieldPath::default())?);Ok(())
            }
        }
    };
}
root!(Service,"v1","Service",Namespaced,{"spec"=>spec:ServiceSpec,});
root!(Endpoints,"v1","Endpoints",Namespaced,{"subsets"=>subsets:Vec<EndpointSubset>,});
root!(EndpointSliceV1,"discovery.k8s.io/v1","EndpointSlice",Namespaced,{
    "addressType"=>address_type:String,"endpoints"=>endpoints:Vec<EndpointDiscoveryV1>,"ports"=>ports:Vec<EndpointPortDiscoveryV1>,
});
root!(EndpointSliceV1Beta1,"discovery.k8s.io/v1beta1","EndpointSlice",Namespaced,{
    "addressType"=>address_type:String,"endpoints"=>endpoints:Vec<EndpointDiscoveryV1beta1>,"ports"=>ports:Vec<EndpointPortDiscoveryV1beta1>,
});
root!(IngressV1,"networking.k8s.io/v1","Ingress",Namespaced,{"spec"=>spec:IngressV1Spec,});
root!(IngressV1Beta1,"networking.k8s.io/v1beta1","Ingress",Namespaced,{"spec"=>spec:IngressV1Beta1Spec,});
root!(IngressExtensionsV1Beta1,"extensions/v1beta1","Ingress",Namespaced,{"spec"=>spec:IngressExtensionsV1Beta1Spec,});
root!(IngressClassV1,"networking.k8s.io/v1","IngressClass",Cluster,{"spec"=>spec:IngressClassV1Spec,});
root!(IngressClassV1Beta1,"networking.k8s.io/v1beta1","IngressClass",Cluster,{"spec"=>spec:IngressClassV1Beta1Spec,});
root!(NetworkPolicy,"networking.k8s.io/v1","NetworkPolicy",Namespaced,{"spec"=>spec:NetworkPolicySpec,});

pub(crate) fn register(registry: &mut RegistryBuilder) -> Result<(), Finding> {
    macro_rules! register {
        ($name:ident,$scope:ident) => {{
            fn decode(
                node: &TreeNode,
                _: &SourceEvidence,
                ctx: &DecodeContext<'_>,
            ) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
                if ctx.scope != ResourceScope::$scope
                    || ctx.gvk.kind != $name::KIND
                    || ctx.gvk.api_version() != $name::API_VERSION
                {
                    return Err(vec![Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)]);
                }
                $name::decode(node, &ctx.fields, &FieldPath::default())
                    .map(|value| Box::new(value) as Box<dyn NativeResource>)
                    .map_err(|error| vec![error])
            }
            let gvk = GroupVersionKind::new($name::API_VERSION, $name::KIND)?;
            registry.register(ResourceRegistration {
                gvk: gvk.clone(),
                scope: ResourceScope::$scope,
                decode,
                capability: super::capabilities::for_api(gvk)?,
            })?;
        }};
    }
    register!(Service, Namespaced);
    register!(Endpoints, Namespaced);
    register!(EndpointSliceV1, Namespaced);
    register!(EndpointSliceV1Beta1, Namespaced);
    register!(IngressV1, Namespaced);
    register!(IngressV1Beta1, Namespaced);
    register!(IngressExtensionsV1Beta1, Namespaced);
    register!(IngressClassV1, Cluster);
    register!(IngressClassV1Beta1, Cluster);
    register!(NetworkPolicy, Namespaced);
    Ok(())
}
