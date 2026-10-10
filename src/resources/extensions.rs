//! Bounded native Kubernetes extension roots and local CRD schema tooling.
//!
//! Typed CRDs establish only source descriptors. They do not bind arbitrary custom-resource
//! documents or claim API-server, admission, conversion, or controller behavior.
pub(crate) mod capabilities;
pub mod custom_documents;
mod helpers;
pub(crate) mod roots;
mod schema;
#[cfg(test)]
mod test_support;
mod validation;

pub use custom_documents::{CustomDocumentBinding, CustomDocumentCheck, CustomDocumentResult, CustomResourceView};
pub use helpers::*;
pub use roots::{
    CustomResourceDefinitionV1, CustomResourceDefinitionV1beta1, MutatingWebhookConfigurationV1,
    MutatingWebhookConfigurationV1beta1, ValidatingWebhookConfigurationV1, ValidatingWebhookConfigurationV1beta1,
};
pub use schema::*;

macro_rules! extension_object {
    ($(#[$doc:meta])* pub struct $name:ident { $($wire:literal => $field:ident: $ty:ty,)* }) => {
        $(#[$doc])*
        #[doc = concat!("Typed native helper wire shape `", stringify!($name), "`.")]
        #[derive(Clone, Default)]
        pub struct $name {
            $(#[doc = concat!("Explicit authored presence of `", $wire, "`.")]
              pub $field: $crate::value::Presence<$ty>,)*
            pub(crate) unknown: $crate::syntax::UnknownFields,
        }
        impl $name {
            pub(crate) const NATIVE_FIELDS: &'static [&'static str] = &[$($wire,)*];
            /// Borrow retained unadmitted immediate members without exposing values.
            #[must_use]
            pub const fn unknown_fields(&self) -> &$crate::syntax::UnknownFields { &self.unknown }
        }
        impl $crate::resources::common::UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, path: &$crate::diagnostic::FieldPath, out: &mut std::collections::BTreeSet<$crate::diagnostic::FieldPath>) {
                if !self.unknown.is_empty() { out.insert(path.clone()); }
                $($crate::resources::common::UnknownScopes::unknown_scopes(&self.$field, &path.child($wire), out);)*
            }
            fn visit_unknown_scopes(
                &self,
                path: &$crate::diagnostic::FieldPath,
                visitor: &mut $crate::resources::common::UnknownScopeVisitor<'_>,
            ) -> bool {
                if !visitor.step() { return false; }
                if !self.unknown.is_empty() && !visitor.found(path) { return false; }
                $(
                    let Some(child) = visitor.child(path, $wire) else { return false; };
                    if !$crate::resources::common::UnknownScopes::visit_unknown_scopes(&self.$field, &child, visitor) {
                        return false;
                    }
                )*
                true
            }
        }
        impl $crate::registry::codec::FieldCodec for $name {
            fn decode(node: &$crate::syntax::TreeNode, ctx: &$crate::registry::FieldDecodeContext, path: &$crate::diagnostic::FieldPath) -> Result<Self, $crate::diagnostic::Finding> {
                $crate::registry::codec::object(node, path)?;
                ctx.processing.work(1, ctx.phase)?;
                Ok(Self {
                    $($field: $crate::registry::codec::read_presence(node, $wire, ctx, path)?,)*
                    unknown: $crate::syntax::UnknownFields::capture_in(node, Self::NATIVE_FIELDS, ctx)?,
                })
            }
            fn encode(&self, ctx: &$crate::registry::EncodeContext<'_>, path: &$crate::diagnostic::FieldPath) -> Result<$crate::syntax::TreeNode, $crate::diagnostic::Finding> {
                let mut entries = Vec::new();
                $($crate::registry::codec::write_presence(&mut entries, $wire, &self.$field, ctx, path)?;)*
                $crate::registry::codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
                ctx.object(entries, path)
            }
        }
    };
}
pub(crate) use extension_object;
