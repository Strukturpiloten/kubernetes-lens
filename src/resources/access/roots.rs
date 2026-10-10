//! Fixed served roots and sealed registrations; no fabricated kinds or defaults.
use super::types::{
    AggregationRule, HorizontalPodAutoscalerV1Spec, HorizontalPodAutoscalerV2Beta1Spec,
    HorizontalPodAutoscalerV2Beta2Spec, HorizontalPodAutoscalerV2Spec, LimitRangeSpec, OverheadV1, OverheadV1Beta1,
    PodDisruptionBudgetV1Beta1Spec, PodDisruptionBudgetV1Spec, PodSecurityPolicySpec, PolicyRule, ResourceQuotaSpec,
    RoleRef, SchedulingV1, SchedulingV1Beta1, Subject,
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
    resources::common::{LocalObjectReference, ObjectReference, UnknownScopes},
    source::SourceEvidence,
    syntax::{SyntaxBuilder, TreeNode, UnknownFields},
    value::Presence,
};
use std::any::Any;
#[cfg(test)]
use std::collections::BTreeSet;
macro_rules! root {
 ($name:ident,$api:literal,$kind:literal,$scope:ident,{$($wire:literal=>$member:ident:$ty:ty,)*})=>{
  #[doc=concat!("Native `",$api,"` `",$kind,"`; all presences stay explicit.")]
  #[derive(Clone,Default,Debug)]
  pub struct $name {
   /// Explicit native metadata; concrete identity is never inferred from a prefix.
   pub metadata:Presence<Metadata>,
   $(#[doc=concat!("Explicit native `",$wire,"` presence.")] pub $member:Presence<$ty>,)*
   unknown:UnknownFields,
  }
  impl $name {
   /// Exact served API spelling.
   pub const API_VERSION:&'static str=$api;
   /// Native kind spelling.
   pub const KIND:&'static str=$kind;
   /// Retained private unselected root members.
   #[must_use] pub const fn unknown_fields(&self)->&UnknownFields {&self.unknown}
   fn register(registry:&mut RegistryBuilder)->Result<(),Finding> {
    fn decode(tree:&TreeNode,_:&SourceEvidence,ctx:&DecodeContext<'_>)->Result<Box<dyn NativeResource>,Vec<Finding>> {
     if ctx.scope!=ResourceScope::$scope || ctx.gvk.kind!=$kind || ctx.gvk.api_version()!=$api {return Err(vec![Finding::error(FindingCode::InvalidRegistration,Phase::Decoding)]);}
     $name::decode(tree,&ctx.fields,&FieldPath::default()).map(|resource|Box::new(resource) as Box<dyn NativeResource>).map_err(|finding|vec![finding])
    }
    let gvk=GroupVersionKind::new($api,$kind)?;
    let capability=super::capabilities::for_api(gvk.clone())?;
    registry.register(ResourceRegistration {gvk,scope:ResourceScope::$scope,decode,capability})
   }
  }
  impl UnknownScopes for $name {
   #[cfg(test)]
   fn unknown_scopes(&self,path:&FieldPath,out:&mut BTreeSet<FieldPath>) {
    if !self.unknown.is_empty() {out.insert(path.clone());}
    self.metadata.unknown_scopes(&path.child("metadata"),out);
    $(self.$member.unknown_scopes(&path.child($wire),out);)*
   }
   fn visit_unknown_scopes(&self,path:&FieldPath,visitor:&mut crate::resources::common::UnknownScopeVisitor<'_>)->bool {
    if !visitor.step() || (!self.unknown.is_empty() && !visitor.found(path)) {return false;}
    let Some(child)=visitor.child(path,"metadata") else {return false;};
    if !self.metadata.visit_unknown_scopes(&child,visitor) {return false;}
    $(let Some(child)=visitor.child(path,$wire) else {return false;};
    if !self.$member.visit_unknown_scopes(&child,visitor) {return false;})*
    true
   }
  }
  impl FieldCodec for $name {
   fn decode(tree:&TreeNode,ctx:&crate::registry::FieldDecodeContext,path:&FieldPath)->Result<Self,Finding> {
    codec::object(tree,path)?;ctx.processing.work(1,ctx.phase)?;
    if tree.get("apiVersion").and_then(TreeNode::as_str)!=Some($api) || tree.get("kind").and_then(TreeNode::as_str)!=Some($kind) {return Err(Finding::error(FindingCode::CodecIdentityMismatch,Phase::Decoding).at_path(path.clone()));}
    Ok(Self {metadata:codec::read_presence(tree,"metadata",ctx,path)?,$($member:codec::read_presence(tree,$wire,ctx,path)?,)*unknown:UnknownFields::capture_in(tree,&["apiVersion","kind","metadata",$($wire,)*],ctx)?})
   }
   fn encode(&self,ctx:&EncodeContext<'_>,path:&FieldPath)->Result<TreeNode,Finding> {
    let mut entries=vec![(ctx.key("apiVersion",&path.child("apiVersion"))?,ctx.string($api,&path.child("apiVersion"))?),(ctx.key("kind",&path.child("kind"))?,ctx.string($kind,&path.child("kind"))?)];
    codec::write_presence(&mut entries,"metadata",&self.metadata,ctx,path)?;
    $(codec::write_presence(&mut entries,$wire,&self.$member,ctx,path)?;)*
    codec::append_unknown(&self.unknown,&mut entries,ctx,path)?;
    ctx.object(entries,path)
   }
  }
  impl From<$name> for AuthoredResource { fn from(resource:$name)->Self {Self::new(Box::new(resource))} }
  impl super::validation::Profile for $name {const API:&'static str=$api;const KIND:&'static str=$kind;}
  impl NativeResource for $name {
   fn as_any(&self)->&dyn Any {self}
   fn as_any_mut(&mut self)->&mut dyn Any {self}
   fn collect_references(&self,ctx:&EncodeContext<'_>,out:&mut dyn ReferenceSink) {super::facts::references(self,ctx,out);}
   fn collect_protected_paths(&self,ctx:&EncodeContext<'_>,out:&mut Vec<FieldPath>) {super::facts::protected(self,ctx,out);}
   fn collect_native_facts(&self,ctx:&ProjectionContext<'_>,out:&mut Vec<NativeFact>) {super::facts::native(ctx,out);}
   fn validate(&self,ctx:&ValidationContext<'_>,out:&mut dyn FindingSink) {super::validation::validate(self,ctx,out);}
   fn encode_known(&self,ctx:&EncodeContext<'_>,out:&mut SyntaxBuilder)->Result<(),Finding> {out.set_root(self.encode(ctx,&FieldPath::default())?);Ok(())}
  }
 };
}
root!(Namespace, "v1", "Namespace", Cluster, {});
root!(ServiceAccount,"v1","ServiceAccount",Namespaced,{"automountServiceAccountToken"=>automount_service_account_token:bool,"imagePullSecrets"=>image_pull_secrets:Vec<LocalObjectReference>,"secrets"=>secrets:Vec<ObjectReference>,});
root!(Role,"rbac.authorization.k8s.io/v1","Role",Namespaced,{"rules"=>rules:Vec<PolicyRule>,});
root!(RoleBinding,"rbac.authorization.k8s.io/v1","RoleBinding",Namespaced,{"subjects"=>subjects:Vec<Subject>,"roleRef"=>role_ref:RoleRef,});
root!(ClusterRole,"rbac.authorization.k8s.io/v1","ClusterRole",Cluster,{"rules"=>rules:Vec<PolicyRule>,"aggregationRule"=>aggregation_rule:AggregationRule,});
root!(ClusterRoleBinding,"rbac.authorization.k8s.io/v1","ClusterRoleBinding",Cluster,{"subjects"=>subjects:Vec<Subject>,"roleRef"=>role_ref:RoleRef,});
root!(HorizontalPodAutoscalerV1,"autoscaling/v1","HorizontalPodAutoscaler",Namespaced,{"spec"=>spec:HorizontalPodAutoscalerV1Spec,});
root!(HorizontalPodAutoscalerV2,"autoscaling/v2","HorizontalPodAutoscaler",Namespaced,{"spec"=>spec:HorizontalPodAutoscalerV2Spec,});
root!(HorizontalPodAutoscalerV2Beta1,"autoscaling/v2beta1","HorizontalPodAutoscaler",Namespaced,{"spec"=>spec:HorizontalPodAutoscalerV2Beta1Spec,});
root!(HorizontalPodAutoscalerV2Beta2,"autoscaling/v2beta2","HorizontalPodAutoscaler",Namespaced,{"spec"=>spec:HorizontalPodAutoscalerV2Beta2Spec,});
root!(PodDisruptionBudgetV1,"policy/v1","PodDisruptionBudget",Namespaced,{"spec"=>spec:PodDisruptionBudgetV1Spec,});
root!(PodDisruptionBudgetV1Beta1,"policy/v1beta1","PodDisruptionBudget",Namespaced,{"spec"=>spec:PodDisruptionBudgetV1Beta1Spec,});
root!(ResourceQuota,"v1","ResourceQuota",Namespaced,{"spec"=>spec:ResourceQuotaSpec,});
root!(LimitRange,"v1","LimitRange",Namespaced,{"spec"=>spec:LimitRangeSpec,});
root!(PriorityClass,"scheduling.k8s.io/v1","PriorityClass",Cluster,{"value"=>value:i32,"globalDefault"=>global_default:bool,"description"=>description:String,"preemptionPolicy"=>preemption_policy:String,});
root!(RuntimeClassV1,"node.k8s.io/v1","RuntimeClass",Cluster,{"handler"=>handler:String,"overhead"=>overhead:OverheadV1,"scheduling"=>scheduling:SchedulingV1,});
root!(RuntimeClassV1Beta1,"node.k8s.io/v1beta1","RuntimeClass",Cluster,{"handler"=>handler:String,"overhead"=>overhead:OverheadV1Beta1,"scheduling"=>scheduling:SchedulingV1Beta1,});
root!(PodSecurityPolicy,"policy/v1beta1","PodSecurityPolicy",Cluster,{"spec"=>spec:PodSecurityPolicySpec,});

pub(crate) fn register(registry: &mut RegistryBuilder) -> Result<(), Finding> {
    Namespace::register(registry)?;
    ServiceAccount::register(registry)?;
    Role::register(registry)?;
    RoleBinding::register(registry)?;
    ClusterRole::register(registry)?;
    ClusterRoleBinding::register(registry)?;
    HorizontalPodAutoscalerV1::register(registry)?;
    HorizontalPodAutoscalerV2::register(registry)?;
    HorizontalPodAutoscalerV2Beta1::register(registry)?;
    HorizontalPodAutoscalerV2Beta2::register(registry)?;
    PodDisruptionBudgetV1::register(registry)?;
    PodDisruptionBudgetV1Beta1::register(registry)?;
    ResourceQuota::register(registry)?;
    LimitRange::register(registry)?;
    PriorityClass::register(registry)?;
    RuntimeClassV1::register(registry)?;
    RuntimeClassV1Beta1::register(registry)?;
    PodSecurityPolicy::register(registry)?;
    Ok(())
}
