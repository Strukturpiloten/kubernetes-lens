//! Sealed typed roots for the three admitted extension API kinds.
use super::{
    capabilities,
    helpers::{
        CustomResourceColumnDefinitionCrdV1beta1, CustomResourceConversionCrdV1, CustomResourceConversionCrdV1beta1,
        CustomResourceDefinitionNamesCrdV1, CustomResourceDefinitionNamesCrdV1beta1,
        CustomResourceDefinitionVersionCrdV1, CustomResourceDefinitionVersionCrdV1beta1,
        CustomResourceSubresourcesCrdV1beta1, CustomResourceValidationCrdV1beta1, MutatingWebhookAdmissionV1,
        MutatingWebhookAdmissionV1beta1, ValidatingWebhookAdmissionV1, ValidatingWebhookAdmissionV1beta1,
    },
    validation,
};
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::ReferenceSink,
    model::{GroupVersionKind, Metadata, ResourceScope},
    registry::{
        DecodeContext, EncodeContext, FieldDecodeContext, FindingSink, NativeResource, ProjectionContext,
        RegistryBuilder, ResourceRegistration, ValidationContext,
        codec::{self, FieldCodec},
    },
    source::{ObservationPath, SourceEvidence, root_observation_paths},
    syntax::{SyntaxBuilder, TreeNode, UnknownFields},
    value::Presence,
};

macro_rules! extension_root {
    ($name:ident, $api:literal, $kind:literal, {$($wire:literal => $field:ident: $ty:ty,)*}) => {
        #[doc = concat!("Typed native `", $api, "` `", $kind, "`; unadmitted descendants remain private.")]
        #[derive(Clone, Default)]
        pub struct $name {
            /// Explicit authored metadata; cluster scope never implies a namespace default.
            pub metadata: Presence<Metadata>,
            $(#[doc = concat!("Explicit authored presence of `", $wire, "`.")]
              pub $field: Presence<$ty>,)*
            pub(crate) unknown: UnknownFields,
        }
        impl $name {
            /// Exact served API identity.
            pub const API_VERSION: &'static str = $api;
            /// Exact native resource kind.
            pub const KIND: &'static str = $kind;
            const NATIVE_FIELDS: &'static [&'static str] = &["metadata", $($wire,)*];
            /// Borrow retained unadmitted immediate root members without revealing their payloads.
            #[must_use]
            pub const fn unknown_fields(&self) -> &UnknownFields { &self.unknown }
        }
        impl From<$name> for crate::model::AuthoredResource {
            fn from(value: $name) -> Self { Self::new(Box::new(value)) }
        }
        impl crate::resources::common::UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, path: &FieldPath, out: &mut std::collections::BTreeSet<FieldPath>) {
                if !self.unknown.is_empty() { out.insert(path.clone()); }
                crate::resources::common::UnknownScopes::unknown_scopes(&self.metadata, &path.child("metadata"), out);
                $($crate::resources::common::UnknownScopes::unknown_scopes(&self.$field, &path.child($wire), out);)*
            }
            fn visit_unknown_scopes(
                &self,
                path: &FieldPath,
                visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>,
            ) -> bool {
                if !visitor.step() { return false; }
                if !self.unknown.is_empty() && !visitor.found(path) { return false; }
                let Some(metadata) = visitor.child(path, "metadata") else { return false; };
                if !crate::resources::common::UnknownScopes::visit_unknown_scopes(&self.metadata, &metadata, visitor) {
                    return false;
                }
                $(
                    let Some(child) = visitor.child(path, $wire) else { return false; };
                    if !crate::resources::common::UnknownScopes::visit_unknown_scopes(&self.$field, &child, visitor) {
                        return false;
                    }
                )*
                true
            }
        }
        impl FieldCodec for $name {
            fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
                codec::object(node, path)?;
                if node.get("apiVersion").and_then(TreeNode::as_str) != Some($api)
                    || node.get("kind").and_then(TreeNode::as_str) != Some($kind) {
                    return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
                }
                ctx.processing.work(1, ctx.phase)?;
                Ok(Self {
                    metadata: codec::read_presence(node, "metadata", ctx, path)?,
                    $($field: codec::read_presence(node, $wire, ctx, path)?,)*
                    unknown: UnknownFields::capture_in(node, Self::NATIVE_FIELDS, ctx)?,
                })
            }
            fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
                let mut entries = vec![
                    (ctx.key("apiVersion", &path.child("apiVersion"))?, ctx.string($api, &path.child("apiVersion"))?),
                    (ctx.key("kind", &path.child("kind"))?, ctx.string($kind, &path.child("kind"))?),
                ];
                codec::write_presence(&mut entries, "metadata", &self.metadata, ctx, path)?;
                $(codec::write_presence(&mut entries, $wire, &self.$field, ctx, path)?;)*
                codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
                ctx.object(entries, path)
            }
        }
        impl NativeResource for $name {
            fn as_any(&self) -> &dyn std::any::Any { self }
            fn as_any_mut(&mut self) -> &mut dyn std::any::Any { self }
            fn collect_references(&self, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
                if let Ok(tree) = self.encode(ctx, &FieldPath::default()) {
                    validation::references($api, $kind, &tree, ctx, out);
                }
            }
            fn collect_protected_paths(&self, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
                if let Ok(tree) = self.encode(ctx, &FieldPath::default()) {
                    validation::protected_paths($kind, &tree, ctx, out);
                }
            }
            fn collect_native_facts(&self, _ctx: &ProjectionContext<'_>, _out: &mut Vec<crate::graph::NativeFact>) {}
            fn collect_observation_paths(&self, _tree: &TreeNode, out: &mut Vec<ObservationPath>) {
                out.extend(root_observation_paths());
            }
            fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
                match self.encode(&ctx.encoding(), &FieldPath::default()) {
                    Ok(tree) => validation::validate($api, $kind, &tree, ctx, out),
                    Err(finding) => out.push(finding),
                }
            }
            fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding> {
                out.set_root(self.encode(ctx, &FieldPath::default())?);
                Ok(())
            }
        }
    };
}

extension_root!(CustomResourceDefinitionV1, "apiextensions.k8s.io/v1", "CustomResourceDefinition", {
    "spec" => spec: CustomResourceDefinitionSpecCrdV1,
});
extension_root!(CustomResourceDefinitionV1beta1, "apiextensions.k8s.io/v1beta1", "CustomResourceDefinition", {
    "spec" => spec: CustomResourceDefinitionSpecCrdV1beta1,
});
extension_root!(MutatingWebhookConfigurationV1, "admissionregistration.k8s.io/v1", "MutatingWebhookConfiguration", {
    "webhooks" => webhooks: Vec<MutatingWebhookAdmissionV1>,
});
extension_root!(MutatingWebhookConfigurationV1beta1, "admissionregistration.k8s.io/v1beta1", "MutatingWebhookConfiguration", {
    "webhooks" => webhooks: Vec<MutatingWebhookAdmissionV1beta1>,
});
extension_root!(ValidatingWebhookConfigurationV1, "admissionregistration.k8s.io/v1", "ValidatingWebhookConfiguration", {
    "webhooks" => webhooks: Vec<ValidatingWebhookAdmissionV1>,
});
extension_root!(ValidatingWebhookConfigurationV1beta1, "admissionregistration.k8s.io/v1beta1", "ValidatingWebhookConfiguration", {
    "webhooks" => webhooks: Vec<ValidatingWebhookAdmissionV1beta1>,
});

super::extension_object! {
    pub struct CustomResourceDefinitionSpecCrdV1 {
        "group" => group: String,
        "names" => names: CustomResourceDefinitionNamesCrdV1,
        "scope" => scope: String,
        "versions" => versions: Vec<CustomResourceDefinitionVersionCrdV1>,
        "conversion" => conversion: CustomResourceConversionCrdV1,
        "preserveUnknownFields" => preserve_unknown_fields: bool,
    }
}
super::extension_object! {
    pub struct CustomResourceDefinitionSpecCrdV1beta1 {
        "group" => group: String,
        "names" => names: CustomResourceDefinitionNamesCrdV1beta1,
        "scope" => scope: String,
        "version" => version: String,
        "versions" => versions: Vec<CustomResourceDefinitionVersionCrdV1beta1>,
        "validation" => validation: CustomResourceValidationCrdV1beta1,
        "subresources" => subresources: CustomResourceSubresourcesCrdV1beta1,
        "additionalPrinterColumns" => additional_printer_columns: Vec<CustomResourceColumnDefinitionCrdV1beta1>,
        "conversion" => conversion: CustomResourceConversionCrdV1beta1,
        "preserveUnknownFields" => preserve_unknown_fields: bool,
    }
}

pub(crate) fn register(registry: &mut RegistryBuilder) -> Result<(), Finding> {
    macro_rules! one {
        ($name:ident, $scope:expr) => {{
            fn decode(
                node: &TreeNode,
                _: &SourceEvidence,
                ctx: &DecodeContext<'_>,
            ) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
                if ctx.scope != $scope || ctx.gvk.kind != $name::KIND || ctx.gvk.api_version() != $name::API_VERSION {
                    return Err(vec![Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)]);
                }
                <$name as FieldCodec>::decode(node, &ctx.fields, ctx.fields.source_pointer())
                    .map(|value| Box::new(value) as Box<dyn NativeResource>)
                    .map_err(|finding| vec![finding])
            }
            let gvk = GroupVersionKind::new($name::API_VERSION, $name::KIND)?;
            registry.register(ResourceRegistration {
                gvk: gvk.clone(),
                scope: $scope,
                decode,
                capability: capabilities::for_api(gvk)?,
            })?;
        }};
    }
    one!(CustomResourceDefinitionV1, ResourceScope::Cluster);
    one!(CustomResourceDefinitionV1beta1, ResourceScope::Cluster);
    one!(MutatingWebhookConfigurationV1, ResourceScope::Cluster);
    one!(MutatingWebhookConfigurationV1beta1, ResourceScope::Cluster);
    one!(ValidatingWebhookConfigurationV1, ResourceScope::Cluster);
    one!(ValidatingWebhookConfigurationV1beta1, ResourceScope::Cluster);
    Ok(())
}
