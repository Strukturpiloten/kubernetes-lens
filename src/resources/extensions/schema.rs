//! Stable and historical beta CRD schema documents remain API-distinct and value-protected.
use crate::{
    diagnostic::{FieldPath, Finding},
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    resources::common::{UnknownScopeVisitor, UnknownScopes},
    source::{ExplicitSourceAccess, ParseLimits},
    syntax::TreeNode,
    value::ProtectedJsonValue,
};
use std::fmt;
use std::sync::LazyLock;

mod arena;
pub use arena::{
    BetaSchemaFieldsView, BetaSchemaNodeView, CompiledSchemaPlan, JSONSchemaPropsCrdV1, JSONSchemaPropsCrdV1beta1,
    SchemaBuilder, SchemaCheckIssue, SchemaCheckReport, SchemaFields, SchemaFieldsBeta, SchemaIssueKind, SchemaNodeId,
    SchemaUnsupported, StableSchemaFieldsView, StableSchemaNodeView,
};

macro_rules! schema_value {
    ($name:ident, $doc:literal) => {
        #[doc = $doc]
        #[allow(non_camel_case_types)]
        #[derive(Clone)]
        pub struct $name(ProtectedJsonValue);
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<private>)"))
            }
        }
        impl PartialEq for $name {
            fn eq(&self, other: &Self) -> bool {
                self.0 == other.0
            }
        }
        impl $name {
            #[allow(dead_code)]
            pub(crate) fn is_null(&self) -> bool {
                static NULL_VALUE: LazyLock<Option<ProtectedJsonValue>> =
                    LazyLock::new(|| ProtectedJsonValue::parse_json(b"null", &ParseLimits::default()).ok());
                NULL_VALUE.as_ref().is_some_and(|null| self.0 == *null)
            }
            /// Parse one bounded schema JSON value without evaluating Kubernetes behavior.
            /// # Errors
            /// Rejects malformed JSON, excessive shape and processing limits.
            pub fn parse_json(bytes: &[u8], limits: &ParseLimits) -> Result<Self, Vec<Finding>> {
                ProtectedJsonValue::parse_json(bytes, limits).map(Self)
            }
            /// Serialize the retained schema only with explicit private-value authorization.
            /// # Errors
            /// Refuses output and processing limits.
            pub fn to_json(&self, access: &ExplicitSourceAccess, limits: &ParseLimits) -> Result<Vec<u8>, Finding> {
                self.0.to_json(access, limits)
            }
        }
        impl UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
            fn visit_unknown_scopes(&self, _: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
                visitor.step()
            }
        }
        impl FieldCodec for $name {
            fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
                ProtectedJsonValue::decode(node, ctx, path).map(Self)
            }
            fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
                self.0.encode(ctx, path)
            }
        }
    };
}

schema_value!(JSONCrdV1, "A bounded opaque stable-API JSON value.");
schema_value!(JSONCrdV1beta1, "A bounded opaque historical beta-API JSON value.");
impl JSONCrdV1 {
    pub(crate) fn clone_beta(&self) -> JSONCrdV1beta1 {
        JSONCrdV1beta1(self.0.clone())
    }
    pub(crate) fn retained_json_len(&self, context: &FieldDecodeContext) -> Result<usize, Finding> {
        self.0.retained_json_len_in(context)
    }
}
impl JSONCrdV1beta1 {
    pub(crate) fn clone_stable(&self) -> JSONCrdV1 {
        JSONCrdV1(self.0.clone())
    }
}

macro_rules! schema_or_bool {
    ($name:ident) => {
        #[allow(non_camel_case_types)]
        #[doc = concat!("Closed schema-or-boolean union `", stringify!($name), "`.")]
        #[derive(Clone, Debug)]
        pub enum $name {
            /// A schema object.
            Schema(crate::resources::extensions::schema::SchemaNodeId),
            /// A literal boolean schema value.
            Bool(bool),
        }
        impl UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
            fn visit_unknown_scopes(&self, path: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
                let _ = path;
                visitor.step()
            }
        }
    };
}
schema_or_bool!(JSONSchemaPropsOrBoolCrdV1);
schema_or_bool!(JSONSchemaPropsOrBoolCrdV1beta1);

macro_rules! schema_or_array {
    ($name:ident) => {
        #[allow(non_camel_case_types)]
        #[doc = concat!("Closed schema-or-array union `", stringify!($name), "`.")]
        #[derive(Clone, Debug)]
        pub enum $name {
            /// A single schema object.
            Schema(crate::resources::extensions::schema::SchemaNodeId),
            /// An ordered array of schema objects.
            Array(Vec<crate::resources::extensions::SchemaNodeId>),
        }
        impl UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
            fn visit_unknown_scopes(&self, _: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
                visitor.step()
            }
        }
    };
}
schema_or_array!(JSONSchemaPropsOrArrayCrdV1);
schema_or_array!(JSONSchemaPropsOrArrayCrdV1beta1);

macro_rules! schema_or_string_array {
    ($name:ident) => {
        #[allow(non_camel_case_types)]
        #[doc = concat!("Closed schema-or-string-array union `", stringify!($name), "`.")]
        #[derive(Clone)]
        pub enum $name {
            /// A dependency schema.
            Schema(crate::resources::extensions::SchemaNodeId),
            /// An ordered array of required property names.
            Array(Vec<String>),
        }
        impl fmt::Debug for $name {
            fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str(concat!(stringify!($name), "(<private>)"))
            }
        }
        impl UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
            fn visit_unknown_scopes(&self, _: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
                visitor.step()
            }
        }
    };
}
schema_or_string_array!(JSONSchemaPropsOrStringArrayCrdV1);
schema_or_string_array!(JSONSchemaPropsOrStringArrayCrdV1beta1);
