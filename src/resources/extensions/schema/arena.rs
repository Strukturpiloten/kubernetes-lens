//! Flat, builder-owned `JSONSchemaProps` nodes shared by the distinct served API wrappers.
use super::{
    JSONCrdV1, JSONCrdV1beta1, JSONSchemaPropsOrArrayCrdV1, JSONSchemaPropsOrArrayCrdV1beta1,
    JSONSchemaPropsOrBoolCrdV1, JSONSchemaPropsOrBoolCrdV1beta1, JSONSchemaPropsOrStringArrayCrdV1,
    JSONSchemaPropsOrStringArrayCrdV1beta1,
};
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    processing::NativeOperationBudget,
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    resources::common::{UnknownScopeVisitor, UnknownScopes},
    source::{ParseLimits, SourceEvidence},
    syntax::{TreeNode, TreeValue, UnknownFields},
    value::{ExactJsonNumber, Presence},
};
use std::{collections::HashMap, fmt, mem::size_of, sync::Arc};

mod evaluator;
pub use evaluator::{CompiledSchemaPlan, SchemaCheckIssue, SchemaCheckReport, SchemaIssueKind, SchemaUnsupported};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SchemaFamily {
    V1,
    V1beta1,
}
struct SchemaNode {
    fields: SchemaFields,
    beta_helpers: BetaSchemaHelpers,
    unknown: UnknownFields,
    source_path: Option<FieldPath>,
}
// Beta helper storage is created once during bounded sealing; public views only borrow it.
#[derive(Default)]
struct BetaSchemaHelpers {
    additional_items: Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
    additional_properties: Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
    dependencies: Presence<std::collections::BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1beta1>>,
    enum_values: Presence<Vec<JSONCrdV1beta1>>,
    example: Presence<JSONCrdV1beta1>,
    external_docs: Presence<crate::resources::extensions::ExternalDocumentationCrdV1beta1>,
    items: Presence<JSONSchemaPropsOrArrayCrdV1beta1>,
}
fn borrow_presence<T, U>(value: &Presence<T>, map: impl FnOnce(&T) -> U) -> Presence<U> {
    match value {
        Presence::Absent => Presence::Absent,
        Presence::Null => Presence::Null,
        Presence::Value(value) => Presence::Value(map(value)),
    }
}
impl BetaSchemaHelpers {
    fn new(fields: &SchemaFields, context: &FieldDecodeContext) -> Result<Self, Finding> {
        let processing = &context.processing;
        let phase = context.phase;
        // Precharge every copied container, scalar, opaque tree and protected payload before cloning.
        if let Presence::Value(values) = &fields.enum_values {
            processing.payload_array::<JSONCrdV1beta1>(values.len(), phase)?;
            for value in values {
                processing.payload(value.retained_json_len(context)?, phase)?;
            }
        }
        if let Presence::Value(value) = &fields.example {
            processing.payload(value.retained_json_len(context)?, phase)?;
        }
        if let Presence::Value(values) = &fields.dependencies {
            processing.payload_array::<(String, JSONSchemaPropsOrStringArrayCrdV1beta1)>(values.len(), phase)?;
            for (name, value) in values {
                processing.work(1, phase)?;
                charge_scalar(name, context, phase)?;
                if let JSONSchemaPropsOrStringArrayCrdV1::Array(names) = value {
                    processing.payload_array::<String>(names.len(), phase)?;
                    for name in names {
                        charge_scalar(name, context, phase)?;
                    }
                }
            }
        }
        if let Presence::Value(JSONSchemaPropsOrArrayCrdV1::Array(values)) = &fields.items {
            processing.payload_array::<SchemaNodeId>(values.len(), phase)?;
        }
        if let Presence::Value(value) = &fields.external_docs {
            for text in [&value.description, &value.url] {
                if let Presence::Value(text) = text {
                    charge_scalar(text, context, phase)?;
                }
            }
            processing.payload_array::<(String, crate::syntax::OpaqueNode)>(value.unknown.entries.len(), phase)?;
            for (key, node) in &value.unknown.entries {
                charge_scalar(key, context, phase)?;
                processing.tree_copy(&node.0, phase)?;
            }
        }
        let bool_rule = |value: &JSONSchemaPropsOrBoolCrdV1| match value {
            JSONSchemaPropsOrBoolCrdV1::Schema(id) => JSONSchemaPropsOrBoolCrdV1beta1::Schema(id.clone()),
            JSONSchemaPropsOrBoolCrdV1::Bool(value) => JSONSchemaPropsOrBoolCrdV1beta1::Bool(*value),
        };
        Ok(Self {
            additional_items: borrow_presence(&fields.additional_items, bool_rule),
            additional_properties: borrow_presence(&fields.additional_properties, bool_rule),
            dependencies: borrow_presence(&fields.dependencies, |values| {
                values
                    .iter()
                    .map(|(name, value)| {
                        let value = match value {
                            JSONSchemaPropsOrStringArrayCrdV1::Schema(id) => {
                                JSONSchemaPropsOrStringArrayCrdV1beta1::Schema(id.clone())
                            }
                            JSONSchemaPropsOrStringArrayCrdV1::Array(names) => {
                                JSONSchemaPropsOrStringArrayCrdV1beta1::Array(names.clone())
                            }
                        };
                        (name.clone(), value)
                    })
                    .collect()
            }),
            enum_values: borrow_presence(&fields.enum_values, |values| {
                values.iter().map(JSONCrdV1::clone_beta).collect()
            }),
            example: borrow_presence(&fields.example, JSONCrdV1::clone_beta),
            external_docs: borrow_presence(&fields.external_docs, |value| {
                crate::resources::extensions::ExternalDocumentationCrdV1beta1 {
                    description: value.description.clone(),
                    url: value.url.clone(),
                    unknown: value.unknown.clone(),
                }
            }),
            items: borrow_presence(&fields.items, |value| match value {
                JSONSchemaPropsOrArrayCrdV1::Schema(id) => JSONSchemaPropsOrArrayCrdV1beta1::Schema(id.clone()),
                JSONSchemaPropsOrArrayCrdV1::Array(ids) => JSONSchemaPropsOrArrayCrdV1beta1::Array(ids.clone()),
            }),
        })
    }
}
struct SchemaArena {
    identity: Arc<()>,
    nodes: Vec<SchemaNode>,
    root: usize,
    family: SchemaFamily,
    limits: ParseLimits,
    evidence: SchemaEvidenceOrigin,
}

#[derive(Clone)]
enum SchemaEvidenceOrigin {
    Decoded { source: SourceEvidence, pointer: FieldPath },
    NativeAuthored { pointer: FieldPath },
    Incomplete,
}

/// Opaque reference to a prior node owned by one schema builder.
#[derive(Clone)]
pub struct SchemaNodeId {
    identity: Arc<()>,
    family: SchemaFamily,
    index: usize,
}
impl fmt::Debug for SchemaNodeId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SchemaNodeId(<private>)")
    }
}

/// One typed `JSONSchemaProps` node. References point only to earlier builder nodes.
#[derive(Clone, Default)]
pub struct SchemaFields {
    /// `additionalItems`, preserved but outside the local checker subset.
    pub additional_items: Presence<JSONSchemaPropsOrBoolCrdV1>,
    /// Additional object-property rule.
    pub additional_properties: Presence<JSONSchemaPropsOrBoolCrdV1>,
    /// allOf branch list.
    pub all_of: Presence<Vec<SchemaNodeId>>,
    /// anyOf branch list.
    pub any_of: Presence<Vec<SchemaNodeId>>,
    /// Named definitions.
    pub definitions: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Dependency declarations.
    pub dependencies: Presence<std::collections::BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1>>,
    /// Human-readable description.
    pub description: Presence<String>,
    /// Protected enum values.
    pub enum_values: Presence<Vec<JSONCrdV1>>,
    /// Protected example.
    pub example: Presence<JSONCrdV1>,
    /// Exclusive maximum flag.
    pub exclusive_maximum: Presence<bool>,
    /// Exclusive minimum flag.
    pub exclusive_minimum: Presence<bool>,
    /// External documentation.
    pub external_docs: Presence<crate::resources::extensions::ExternalDocumentationCrdV1>,
    /// Format annotation; not evaluated.
    pub format: Presence<String>,
    /// Identifier annotation.
    pub id: Presence<String>,
    /// Single schema or historical tuple schema form.
    pub items: Presence<JSONSchemaPropsOrArrayCrdV1>,
    /// Maximum item count, unsupported by the local checker.
    pub max_items: Presence<i64>,
    /// Maximum Unicode-scalar string length.
    pub max_length: Presence<i64>,
    /// Maximum object property count, unsupported by the local checker.
    pub max_properties: Presence<i64>,
    /// Exact maximum numeric bound.
    pub maximum: Presence<ExactJsonNumber>,
    /// Minimum item count, unsupported by the local checker.
    pub min_items: Presence<i64>,
    /// Minimum Unicode-scalar string length.
    pub min_length: Presence<i64>,
    /// Minimum object property count, unsupported by the local checker.
    pub min_properties: Presence<i64>,
    /// Exact minimum numeric bound.
    pub minimum: Presence<ExactJsonNumber>,
    /// Multiple-of constraint, unsupported by the local checker.
    pub multiple_of: Presence<ExactJsonNumber>,
    /// not branch.
    pub not: Presence<SchemaNodeId>,
    /// Nullable annotation.
    pub nullable: Presence<bool>,
    /// oneOf branch list.
    pub one_of: Presence<Vec<SchemaNodeId>>,
    /// Pattern annotation; not evaluated.
    pub pattern: Presence<String>,
    /// Pattern properties; not evaluated.
    pub pattern_properties: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Named property schemas.
    pub properties: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Required property names.
    pub required: Presence<Vec<String>>,
    /// Title annotation.
    pub title: Presence<String>,
    /// JSON schema type name.
    pub type_name: Presence<String>,
    /// Uniqueness constraint, unsupported by the local checker.
    pub unique_items: Presence<bool>,
    /// Embedded resource marker.
    pub x_kubernetes_embedded_resource: Presence<bool>,
    /// Int-or-string marker; remains unsupported.
    pub x_kubernetes_int_or_string: Presence<bool>,
    /// List-map key annotations.
    pub x_kubernetes_list_map_keys: Presence<Vec<String>>,
    /// List type annotation.
    pub x_kubernetes_list_type: Presence<String>,
    /// Map type annotation.
    pub x_kubernetes_map_type: Presence<String>,
    /// Preserve unknown fields at this schema node.
    pub x_kubernetes_preserve_unknown_fields: Presence<bool>,
}

/// Historical beta `JSONSchemaProps` draft with beta-family unions and protected JSON values.
#[derive(Clone, Default)]
pub struct SchemaFieldsBeta {
    /// Beta `additionalItems` field.
    pub additional_items: Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
    /// Beta `additionalProperties` field.
    pub additional_properties: Presence<JSONSchemaPropsOrBoolCrdV1beta1>,
    /// Beta allOf branches.
    pub all_of: Presence<Vec<SchemaNodeId>>,
    /// Beta anyOf branches.
    pub any_of: Presence<Vec<SchemaNodeId>>,
    /// Beta definitions.
    pub definitions: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Beta dependency declarations.
    pub dependencies: Presence<std::collections::BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1beta1>>,
    /// Human-readable description.
    pub description: Presence<String>,
    /// Protected beta enum members.
    pub enum_values: Presence<Vec<JSONCrdV1beta1>>,
    /// Protected beta example.
    pub example: Presence<JSONCrdV1beta1>,
    /// Exclusive maximum flag.
    pub exclusive_maximum: Presence<bool>,
    /// Exclusive minimum flag.
    pub exclusive_minimum: Presence<bool>,
    /// Beta external documentation fields.
    pub external_docs: Presence<crate::resources::extensions::ExternalDocumentationCrdV1beta1>,
    /// Format annotation.
    pub format: Presence<String>,
    /// Schema identifier.
    pub id: Presence<String>,
    /// Beta single-schema or tuple items.
    pub items: Presence<JSONSchemaPropsOrArrayCrdV1beta1>,
    /// Maximum item count.
    pub max_items: Presence<i64>,
    /// Maximum string length.
    pub max_length: Presence<i64>,
    /// Maximum object property count.
    pub max_properties: Presence<i64>,
    /// Exact maximum number.
    pub maximum: Presence<ExactJsonNumber>,
    /// Minimum item count.
    pub min_items: Presence<i64>,
    /// Minimum string length.
    pub min_length: Presence<i64>,
    /// Minimum object property count.
    pub min_properties: Presence<i64>,
    /// Exact minimum number.
    pub minimum: Presence<ExactJsonNumber>,
    /// Multiple-of constraint.
    pub multiple_of: Presence<ExactJsonNumber>,
    /// Beta negation schema.
    pub not: Presence<SchemaNodeId>,
    /// Nullable annotation.
    pub nullable: Presence<bool>,
    /// Beta oneOf branches.
    pub one_of: Presence<Vec<SchemaNodeId>>,
    /// Pattern annotation.
    pub pattern: Presence<String>,
    /// Pattern-property schemas.
    pub pattern_properties: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Named property schemas.
    pub properties: Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    /// Required property names.
    pub required: Presence<Vec<String>>,
    /// Schema title.
    pub title: Presence<String>,
    /// JSON schema type name.
    pub type_name: Presence<String>,
    /// Uniqueness constraint.
    pub unique_items: Presence<bool>,
    /// Embedded-resource marker.
    pub x_kubernetes_embedded_resource: Presence<bool>,
    /// Int-or-string marker.
    pub x_kubernetes_int_or_string: Presence<bool>,
    /// Kubernetes list-map keys.
    pub x_kubernetes_list_map_keys: Presence<Vec<String>>,
    /// Kubernetes list topology type.
    pub x_kubernetes_list_type: Presence<String>,
    /// Kubernetes map topology type.
    pub x_kubernetes_map_type: Presence<String>,
    /// Preserve-unknown transform marker.
    pub x_kubernetes_preserve_unknown_fields: Presence<bool>,
}

impl From<SchemaFieldsBeta> for SchemaFields {
    fn from(fields: SchemaFieldsBeta) -> Self {
        let additional_items = map_presence(fields.additional_items, |value| match value {
            JSONSchemaPropsOrBoolCrdV1beta1::Schema(id) => JSONSchemaPropsOrBoolCrdV1::Schema(id),
            JSONSchemaPropsOrBoolCrdV1beta1::Bool(value) => JSONSchemaPropsOrBoolCrdV1::Bool(value),
        });
        let additional_properties = map_presence(fields.additional_properties, |value| match value {
            JSONSchemaPropsOrBoolCrdV1beta1::Schema(id) => JSONSchemaPropsOrBoolCrdV1::Schema(id),
            JSONSchemaPropsOrBoolCrdV1beta1::Bool(value) => JSONSchemaPropsOrBoolCrdV1::Bool(value),
        });
        let dependencies = map_presence(fields.dependencies, |values| {
            values
                .into_iter()
                .map(|(name, dependency)| {
                    let dependency = match dependency {
                        JSONSchemaPropsOrStringArrayCrdV1beta1::Schema(id) => {
                            JSONSchemaPropsOrStringArrayCrdV1::Schema(id)
                        }
                        JSONSchemaPropsOrStringArrayCrdV1beta1::Array(names) => {
                            JSONSchemaPropsOrStringArrayCrdV1::Array(names)
                        }
                    };
                    (name, dependency)
                })
                .collect()
        });
        let items = map_presence(fields.items, |value| match value {
            JSONSchemaPropsOrArrayCrdV1beta1::Schema(id) => JSONSchemaPropsOrArrayCrdV1::Schema(id),
            JSONSchemaPropsOrArrayCrdV1beta1::Array(ids) => JSONSchemaPropsOrArrayCrdV1::Array(ids),
        });
        let external_docs = map_presence(fields.external_docs, |value| {
            crate::resources::extensions::ExternalDocumentationCrdV1 {
                description: value.description,
                url: value.url,
                unknown: value.unknown,
            }
        });
        Self {
            additional_items,
            additional_properties,
            all_of: fields.all_of,
            any_of: fields.any_of,
            definitions: fields.definitions,
            dependencies,
            description: fields.description,
            enum_values: map_presence(fields.enum_values, |values| {
                values.into_iter().map(|value| value.clone_stable()).collect()
            }),
            example: map_presence(fields.example, |value| value.clone_stable()),
            exclusive_maximum: fields.exclusive_maximum,
            exclusive_minimum: fields.exclusive_minimum,
            external_docs,
            format: fields.format,
            id: fields.id,
            items,
            max_items: fields.max_items,
            max_length: fields.max_length,
            max_properties: fields.max_properties,
            maximum: fields.maximum,
            min_items: fields.min_items,
            min_length: fields.min_length,
            min_properties: fields.min_properties,
            minimum: fields.minimum,
            multiple_of: fields.multiple_of,
            not: fields.not,
            nullable: fields.nullable,
            one_of: fields.one_of,
            pattern: fields.pattern,
            pattern_properties: fields.pattern_properties,
            properties: fields.properties,
            required: fields.required,
            title: fields.title,
            type_name: fields.type_name,
            unique_items: fields.unique_items,
            x_kubernetes_embedded_resource: fields.x_kubernetes_embedded_resource,
            x_kubernetes_int_or_string: fields.x_kubernetes_int_or_string,
            x_kubernetes_list_map_keys: fields.x_kubernetes_list_map_keys,
            x_kubernetes_list_type: fields.x_kubernetes_list_type,
            x_kubernetes_map_type: fields.x_kubernetes_map_type,
            x_kubernetes_preserve_unknown_fields: fields.x_kubernetes_preserve_unknown_fields,
        }
    }
}

fn map_presence<T, U>(value: Presence<T>, map: impl FnOnce(T) -> U) -> Presence<U> {
    match value {
        Presence::Absent => Presence::Absent,
        Presence::Null => Presence::Null,
        Presence::Value(value) => Presence::Value(map(value)),
    }
}

/// A flat bounded schema builder; handles are valid only here and only for earlier nodes.
pub struct SchemaBuilder {
    identity: Arc<()>,
    family: SchemaFamily,
    fields: FieldDecodeContext,
    nodes: Vec<SchemaNode>,
}
impl fmt::Debug for SchemaBuilder {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SchemaBuilder(<private>)")
    }
}
impl SchemaBuilder {
    /// Start a stable `apiextensions.k8s.io/v1` schema builder.
    /// # Errors
    /// Rejects invalid limits or an exhausted operation.
    pub fn stable(limits: &ParseLimits) -> Result<Self, Finding> {
        Self::new(SchemaFamily::V1, limits)
    }
    /// Start a historical `apiextensions.k8s.io/v1beta1` schema builder.
    /// # Errors
    /// Rejects invalid limits or an exhausted operation.
    pub fn beta(limits: &ParseLimits) -> Result<Self, Finding> {
        Self::new(SchemaFamily::V1beta1, limits)
    }
    fn new(family: SchemaFamily, limits: &ParseLimits) -> Result<Self, Finding> {
        let processing = NativeOperationBudget::new(limits.processing);
        if !limits.valid() {
            return Err(processing.fail(Phase::Generation));
        }
        processing.work(1, Phase::Generation)?;
        processing.payload(size_of::<Self>(), Phase::Generation)?;
        Ok(Self {
            identity: Arc::new(()),
            family,
            fields: FieldDecodeContext::new(*limits, processing, Phase::Generation),
            nodes: Vec::new(),
        })
    }
    /// Add a node after validating that all schema handles belong to this builder and precede it.
    /// # Errors
    /// Rejects foreign, future, or cross-version handles and cumulative budget exhaustion.
    pub fn add(&mut self, fields: SchemaFields) -> Result<SchemaNodeId, Finding> {
        self.add_with_unknown(fields, UnknownFields::default(), None)
    }
    /// Add a historical beta schema node using beta-family union and JSON draft types.
    /// # Errors
    /// Rejects use with a stable builder, foreign handles, or exhausted budgets.
    pub fn add_beta(&mut self, fields: SchemaFieldsBeta) -> Result<SchemaNodeId, Finding> {
        if self.family != SchemaFamily::V1beta1 {
            return Err(Finding::error(FindingCode::NativeFieldInvalid, self.fields.phase));
        }
        if let Presence::Value(values) = &fields.enum_values {
            self.fields
                .processing
                .payload_array::<JSONCrdV1>(values.len(), self.fields.phase)?;
        }
        if let Presence::Value(values) = &fields.dependencies {
            self.fields
                .processing
                .payload_array::<(String, JSONSchemaPropsOrStringArrayCrdV1)>(values.len(), self.fields.phase)?;
        }
        self.add(SchemaFields::from(fields))
    }
    fn add_with_unknown(
        &mut self,
        fields: SchemaFields,
        unknown: UnknownFields,
        source_path: Option<FieldPath>,
    ) -> Result<SchemaNodeId, Finding> {
        self.fields
            .processing
            .payload_array::<(String, crate::syntax::OpaqueNode)>(unknown.entries.len(), self.fields.phase)?;
        for (key, node) in &unknown.entries {
            charge_scalar(key, &self.fields, self.fields.phase)?;
            self.fields.processing.tree_copy(&node.0, self.fields.phase)?;
            validate_tree_scalar_limits(&node.0, &self.fields, self.fields.phase)?;
        }
        if let Presence::Value(example) = &fields.example {
            self.fields.processing.work(1, self.fields.phase)?;
            if example.is_null() {
                return Err(Finding::error(FindingCode::NativeFieldInvalid, self.fields.phase));
            }
        }
        self.fields.processing.work(1, self.fields.phase)?;
        validate_schema_refs(
            &fields,
            &self.identity,
            self.family,
            self.nodes.len(),
            &self.fields.processing,
            self.fields.phase,
        )?;
        charge_schema_scalars(&fields, &self.fields)?;
        charge_schema_containers(&fields, &self.fields)?;
        if self.nodes.len() >= self.fields.limits.max_nodes {
            return Err(self.fields.processing.fail(self.fields.phase));
        }
        self.fields
            .processing
            .payload_array::<SchemaNode>(1, self.fields.phase)?;
        self.nodes
            .try_reserve(1)
            .map_err(|_| self.fields.processing.fail(self.fields.phase))?;
        let index = self.nodes.len();
        self.nodes.push(SchemaNode {
            beta_helpers: BetaSchemaHelpers::default(),
            fields,
            unknown,
            source_path,
        });
        Ok(SchemaNodeId {
            identity: self.identity.clone(),
            family: self.family,
            index,
        })
    }
    /// Seal the stable schema root; unrelated builder nodes do not become part of the result.
    /// # Errors
    /// Rejects a foreign root or exhausted processing budget.
    pub fn finish_stable(self, root: &SchemaNodeId) -> Result<JSONSchemaPropsCrdV1, Finding> {
        if !Arc::ptr_eq(&self.identity, &root.identity)
            || self.family != SchemaFamily::V1
            || root.family != SchemaFamily::V1
            || root.index >= self.nodes.len()
        {
            return Err(Finding::error(FindingCode::NativeFieldInvalid, self.fields.phase));
        }
        let root_index = root.index;
        let (nodes, root_index) = seal_reachable(
            self.nodes,
            root_index,
            &self.identity,
            self.family,
            self.fields.limits,
            &self.fields.processing,
            self.fields.phase,
        )?;
        self.fields
            .processing
            .payload(size_of::<SchemaArena>(), self.fields.phase)?;
        Ok(JSONSchemaPropsCrdV1(Arc::new(SchemaArena {
            identity: self.identity,
            nodes,
            root: root_index,
            family: self.family,
            limits: self.fields.limits,
            evidence: SchemaEvidenceOrigin::NativeAuthored {
                pointer: FieldPath::default(),
            },
        })))
    }
    /// Seal the historical beta schema root.
    /// # Errors
    /// Rejects a foreign root or exhausted processing budget.
    pub fn finish_beta(self, root: &SchemaNodeId) -> Result<JSONSchemaPropsCrdV1beta1, Finding> {
        if !Arc::ptr_eq(&self.identity, &root.identity)
            || self.family != SchemaFamily::V1beta1
            || root.family != SchemaFamily::V1beta1
            || root.index >= self.nodes.len()
        {
            return Err(Finding::error(FindingCode::NativeFieldInvalid, self.fields.phase));
        }
        let root_index = root.index;
        let (nodes, root_index) = seal_reachable(
            self.nodes,
            root_index,
            &self.identity,
            self.family,
            self.fields.limits,
            &self.fields.processing,
            self.fields.phase,
        )?;
        self.fields
            .processing
            .payload(size_of::<SchemaArena>(), self.fields.phase)?;
        Ok(JSONSchemaPropsCrdV1beta1(Arc::new(SchemaArena {
            identity: self.identity,
            nodes,
            root: root_index,
            family: self.family,
            limits: self.fields.limits,
            evidence: SchemaEvidenceOrigin::NativeAuthored {
                pointer: FieldPath::default(),
            },
        })))
    }
}

fn charge_scalar(value: &str, context: &FieldDecodeContext, phase: Phase) -> Result<(), Finding> {
    if value.len() > context.limits.max_scalar_bytes {
        return Err(context.processing.fail(phase));
    }
    context.processing.payload(value.len(), phase)
}

fn validate_tree_scalar_limits(root: &TreeNode, context: &FieldDecodeContext, phase: Phase) -> Result<(), Finding> {
    let mut pending = vec![(root, 0usize)];
    while let Some((node, depth)) = pending.pop() {
        context.processing.work(1, phase)?;
        if depth > context.limits.max_depth {
            return Err(context.processing.fail(phase));
        }
        match &node.value {
            TreeValue::String(value) | TreeValue::Number(value) if value.len() > context.limits.max_scalar_bytes => {
                return Err(context.processing.fail(phase));
            }
            TreeValue::Mapping(entries) => {
                for (key, value) in entries {
                    charge_scalar(key, context, phase)?;
                    pending.try_reserve(1).map_err(|_| context.processing.fail(phase))?;
                    pending.push((
                        value,
                        depth.checked_add(1).ok_or_else(|| context.processing.fail(phase))?,
                    ));
                }
            }
            TreeValue::Sequence(items) => {
                for value in items {
                    pending.try_reserve(1).map_err(|_| context.processing.fail(phase))?;
                    pending.push((
                        value,
                        depth.checked_add(1).ok_or_else(|| context.processing.fail(phase))?,
                    ));
                }
            }
            TreeValue::Tagged(tag, value) => {
                charge_scalar(tag, context, phase)?;
                pending.try_reserve(1).map_err(|_| context.processing.fail(phase))?;
                pending.push((
                    value,
                    depth.checked_add(1).ok_or_else(|| context.processing.fail(phase))?,
                ));
            }
            _ => {}
        }
    }
    Ok(())
}

fn validate_schema_ref(
    reference: &SchemaNodeId,
    identity: &Arc<()>,
    family: SchemaFamily,
    node_count: usize,
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    processing.work(1, phase)?;
    if !Arc::ptr_eq(identity, &reference.identity) || reference.family != family || reference.index >= node_count {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, phase));
    }
    Ok(())
}

fn validate_schema_refs(
    fields: &SchemaFields,
    identity: &Arc<()>,
    family: SchemaFamily,
    node_count: usize,
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    for presence in [&fields.all_of, &fields.any_of, &fields.one_of] {
        if let Presence::Value(values) = presence {
            for reference in values {
                validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
            }
        }
    }
    for presence in [&fields.definitions, &fields.pattern_properties, &fields.properties] {
        if let Presence::Value(values) = presence {
            for reference in values.values() {
                validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
            }
        }
    }
    if let Presence::Value(values) = &fields.dependencies {
        for reference in values.values().filter_map(|value| match value {
            JSONSchemaPropsOrStringArrayCrdV1::Schema(id) => Some(id),
            JSONSchemaPropsOrStringArrayCrdV1::Array(_) => None,
        }) {
            validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
        }
    }
    if let Presence::Value(reference) = &fields.not {
        validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
    }
    for presence in [&fields.additional_items, &fields.additional_properties] {
        if let Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(reference)) = presence {
            validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
        }
    }
    if let Presence::Value(value) = &fields.items {
        match value {
            JSONSchemaPropsOrArrayCrdV1::Schema(reference) => {
                validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
            }
            JSONSchemaPropsOrArrayCrdV1::Array(references) => {
                for reference in references {
                    validate_schema_ref(reference, identity, family, node_count, processing, phase)?;
                }
            }
        }
    }
    Ok(())
}

fn charge_schema_scalars(fields: &SchemaFields, context: &FieldDecodeContext) -> Result<(), Finding> {
    for value in [
        &fields.description,
        &fields.format,
        &fields.id,
        &fields.pattern,
        &fields.title,
        &fields.type_name,
    ] {
        if let Presence::Value(value) = value {
            charge_scalar(value, context, context.phase)?;
        }
    }
    for value in [&fields.maximum, &fields.minimum, &fields.multiple_of] {
        if let Presence::Value(value) = value {
            charge_scalar(value.native_lexeme(), context, context.phase)?;
        }
    }
    if let Presence::Value(value) = &fields.external_docs {
        for text in [&value.description, &value.url] {
            if let Presence::Value(text) = text {
                charge_scalar(text, context, context.phase)?;
            }
        }
        context.processing.payload_array::<String>(2, context.phase)?;
    }
    if let Presence::Value(values) = &fields.enum_values {
        context
            .processing
            .payload_array::<JSONCrdV1>(values.len(), context.phase)?;
        for value in values {
            context
                .processing
                .payload(value.retained_json_len(context)?, context.phase)?;
        }
    }
    if let Presence::Value(value) = &fields.example {
        context
            .processing
            .payload(value.retained_json_len(context)?, context.phase)?;
    }
    if let Presence::Value(values) = &fields.required {
        context
            .processing
            .payload_array::<String>(values.len(), context.phase)?;
        for value in values {
            charge_scalar(value, context, context.phase)?;
        }
    }
    Ok(())
}
fn charge_schema_containers(fields: &SchemaFields, context: &FieldDecodeContext) -> Result<(), Finding> {
    for map in [&fields.definitions, &fields.pattern_properties, &fields.properties] {
        if let Presence::Value(values) = map {
            context
                .processing
                .payload_array::<(String, SchemaNodeId)>(values.len(), context.phase)?;
            for name in values.keys() {
                charge_scalar(name, context, context.phase)?;
            }
        }
    }
    if let Presence::Value(values) = &fields.dependencies {
        context
            .processing
            .payload_array::<(String, JSONSchemaPropsOrStringArrayCrdV1)>(values.len(), context.phase)?;
        for (name, dependency) in values {
            charge_scalar(name, context, context.phase)?;
            if let JSONSchemaPropsOrStringArrayCrdV1::Array(names) = dependency {
                context.processing.payload_array::<String>(names.len(), context.phase)?;
                for name in names {
                    charge_scalar(name, context, context.phase)?;
                }
            }
        }
    }
    for values in [&fields.all_of, &fields.any_of, &fields.one_of] {
        if let Presence::Value(values) = values {
            context
                .processing
                .payload_array::<SchemaNodeId>(values.len(), context.phase)?;
        }
    }
    if let Presence::Value(JSONSchemaPropsOrArrayCrdV1::Array(values)) = &fields.items {
        context
            .processing
            .payload_array::<SchemaNodeId>(values.len(), context.phase)?;
    }
    if let Presence::Value(values) = &fields.x_kubernetes_list_map_keys {
        context
            .processing
            .payload_array::<String>(values.len(), context.phase)?;
        for key in values {
            charge_scalar(key, context, context.phase)?;
        }
    }
    for value in [&fields.x_kubernetes_list_type, &fields.x_kubernetes_map_type] {
        if let Presence::Value(value) = value {
            charge_scalar(value, context, context.phase)?;
        }
    }
    Ok(())
}
fn reachability_buffers(
    retained: usize,
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(Vec<bool>, Vec<usize>), Finding> {
    processing.payload_array::<bool>(retained, phase)?;
    processing.payload_array::<usize>(retained, phase)?;
    let mut reachable = Vec::new();
    let mut remap = Vec::new();
    reachable.try_reserve(retained).map_err(|_| processing.fail(phase))?;
    remap.try_reserve(retained).map_err(|_| processing.fail(phase))?;
    reachable.resize(retained, false);
    remap.resize(retained, usize::MAX);
    Ok((reachable, remap))
}
fn seal_reachable(
    nodes: Vec<SchemaNode>,
    root: usize,
    identity: &Arc<()>,
    family: SchemaFamily,
    limits: ParseLimits,
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(Vec<SchemaNode>, usize), Finding> {
    let field_context = FieldDecodeContext::new(limits, processing.clone(), phase);
    let retained = root.checked_add(1).ok_or_else(|| processing.fail(phase))?;
    let (mut reachable, mut remap) = reachability_buffers(retained, processing, phase)?;
    processing.payload_array::<(usize, usize)>(1, phase)?;
    let mut pending = Vec::new();
    pending.try_reserve(1).map_err(|_| processing.fail(phase))?;
    pending.push((root, 0usize));
    let mut expanded = 0usize;
    while let Some((index, depth)) = pending.pop() {
        processing.work(1, phase)?;
        expanded = expanded.checked_add(1).ok_or_else(|| processing.fail(phase))?;
        if index >= retained || depth > limits.max_depth || expanded > limits.max_nodes || expanded > limits.max_events
        {
            return Err(processing.fail(phase));
        }
        charge_expanded_field_payload(&nodes[index].fields, &field_context)?;
        reachable[index] = true;
        let node = nodes
            .get(index)
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, phase))?;
        let fields = &node.fields;
        let mut add = |id: &SchemaNodeId| -> Result<(), Finding> {
            processing.work(1, phase)?;
            if !Arc::ptr_eq(identity, &id.identity) || id.family != family || id.index >= index {
                return Err(Finding::error(FindingCode::NativeFieldInvalid, phase));
            }
            processing.payload_array::<(usize, usize)>(1, phase)?;
            pending.try_reserve(1).map_err(|_| processing.fail(phase))?;
            pending.push((id.index, depth.checked_add(1).ok_or_else(|| processing.fail(phase))?));
            Ok(())
        };
        for values in [&fields.all_of, &fields.any_of, &fields.one_of] {
            if let Presence::Value(values) = values {
                for id in values {
                    add(id)?;
                }
            }
        }
        for values in [&fields.definitions, &fields.pattern_properties, &fields.properties] {
            if let Presence::Value(values) = values {
                for id in values.values() {
                    add(id)?;
                }
            }
        }
        if let Presence::Value(values) = &fields.dependencies {
            for dependency in values.values() {
                if let JSONSchemaPropsOrStringArrayCrdV1::Schema(id) = dependency {
                    add(id)?;
                }
            }
        }
        if let Presence::Value(id) = &fields.not {
            add(id)?;
        }
        for value in [&fields.additional_items, &fields.additional_properties] {
            if let Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(id)) = value {
                add(id)?;
            }
        }
        if let Presence::Value(items) = &fields.items {
            match items {
                JSONSchemaPropsOrArrayCrdV1::Schema(id) => add(id)?,
                JSONSchemaPropsOrArrayCrdV1::Array(ids) => {
                    for id in ids {
                        add(id)?;
                    }
                }
            }
        }
    }
    let mut next = 0usize;
    for (old, is_reachable) in reachable.iter().copied().enumerate() {
        if is_reachable {
            remap[old] = next;
            next = next.checked_add(1).ok_or_else(|| processing.fail(phase))?;
        }
    }
    processing.payload_array::<SchemaNode>(next, phase)?;
    let mut sealed = Vec::new();
    sealed.try_reserve(next).map_err(|_| processing.fail(phase))?;
    for (old, mut node) in nodes.into_iter().enumerate().take(retained) {
        if !reachable[old] {
            continue;
        }
        remap_schema_fields(&mut node.fields, &remap, identity, family, processing, phase)?;
        if family == SchemaFamily::V1beta1 {
            node.beta_helpers = BetaSchemaHelpers::new(&node.fields, &field_context)?;
        }
        sealed.push(node);
    }
    let new_root = remap[root];
    if new_root == usize::MAX || sealed.len() != next {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, phase));
    }
    Ok((sealed, new_root))
}

fn remap_schema_fields(
    fields: &mut SchemaFields,
    remap: &[usize],
    identity: &Arc<()>,
    family: SchemaFamily,
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    let remap_id = |id: &mut SchemaNodeId| -> Result<(), Finding> {
        processing.work(1, phase)?;
        if !Arc::ptr_eq(identity, &id.identity) || id.family != family {
            return Err(Finding::error(FindingCode::NativeFieldInvalid, phase));
        }
        id.index = *remap
            .get(id.index)
            .filter(|index| **index != usize::MAX)
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, phase))?;
        Ok(())
    };
    for values in [&mut fields.all_of, &mut fields.any_of, &mut fields.one_of] {
        if let Presence::Value(values) = values {
            for id in values {
                remap_id(id)?;
            }
        }
    }
    for values in [
        &mut fields.definitions,
        &mut fields.pattern_properties,
        &mut fields.properties,
    ] {
        if let Presence::Value(values) = values {
            for id in values.values_mut() {
                remap_id(id)?;
            }
        }
    }
    if let Presence::Value(values) = &mut fields.dependencies {
        for dependency in values.values_mut() {
            if let JSONSchemaPropsOrStringArrayCrdV1::Schema(id) = dependency {
                remap_id(id)?;
            }
        }
    }
    if let Presence::Value(id) = &mut fields.not {
        remap_id(id)?;
    }
    for value in [&mut fields.additional_items, &mut fields.additional_properties] {
        if let Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(id)) = value {
            remap_id(id)?;
        }
    }
    if let Presence::Value(items) = &mut fields.items {
        match items {
            JSONSchemaPropsOrArrayCrdV1::Schema(id) => remap_id(id)?,
            JSONSchemaPropsOrArrayCrdV1::Array(ids) => {
                for id in ids {
                    remap_id(id)?;
                }
            }
        }
    }
    Ok(())
}

fn charge_expanded_field_payload(fields: &SchemaFields, context: &FieldDecodeContext) -> Result<(), Finding> {
    let scalar = |value: &str| -> Result<(), Finding> {
        if value.len() > context.limits.max_scalar_bytes {
            return Err(context.processing.fail(context.phase));
        }
        context.processing.payload(value.len(), context.phase)
    };
    for value in [
        &fields.description,
        &fields.format,
        &fields.id,
        &fields.pattern,
        &fields.title,
        &fields.type_name,
    ] {
        if let Presence::Value(value) = value {
            scalar(value)?;
        }
    }
    for value in [&fields.maximum, &fields.minimum, &fields.multiple_of] {
        if let Presence::Value(value) = value {
            scalar(value.native_lexeme())?;
        }
    }
    for values in [&fields.required, &fields.x_kubernetes_list_map_keys] {
        if let Presence::Value(values) = values {
            for value in values {
                scalar(value)?;
            }
        }
    }
    for map in [&fields.definitions, &fields.pattern_properties, &fields.properties] {
        if let Presence::Value(values) = map {
            for name in values.keys() {
                scalar(name)?;
            }
        }
    }
    if let Presence::Value(values) = &fields.enum_values {
        for value in values {
            context
                .processing
                .payload(value.retained_json_len(context)?, context.phase)?;
        }
    }
    if let Presence::Value(value) = &fields.example {
        context
            .processing
            .payload(value.retained_json_len(context)?, context.phase)?;
    }
    if let Presence::Value(value) = &fields.external_docs {
        for text in [&value.description, &value.url] {
            if let Presence::Value(text) = text {
                scalar(text)?;
            }
        }
    }
    for value in [&fields.x_kubernetes_list_type, &fields.x_kubernetes_map_type] {
        if let Presence::Value(value) = value {
            scalar(value)?;
        }
    }
    Ok(())
}

/// Stable `JSONSchemaProps` value backed by a flat arena.
#[allow(non_camel_case_types)]
pub struct JSONSchemaPropsCrdV1(Arc<SchemaArena>);
/// Historical beta `JSONSchemaProps` value backed by a separate API-family arena.
#[allow(non_camel_case_types)]
pub struct JSONSchemaPropsCrdV1beta1(Arc<SchemaArena>);

/// Typed stable node view borrowing one sealed schema arena.
pub struct StableSchemaNodeView<'a> {
    arena: &'a SchemaArena,
    index: usize,
}
/// Typed historical beta node view borrowing one sealed schema arena.
pub struct BetaSchemaNodeView<'a> {
    arena: &'a SchemaArena,
    index: usize,
}
/// Selected stable fields from one decoded or authored schema node.
pub struct StableSchemaFieldsView<'a> {
    arena: &'a SchemaArena,
    fields: &'a SchemaFields,
}
/// Selected beta fields from one decoded or authored schema node.
pub struct BetaSchemaFieldsView<'a> {
    arena: &'a SchemaArena,
    fields: &'a SchemaFields,
    helpers: &'a BetaSchemaHelpers,
}

macro_rules! schema_fields_view {
    ($view:ident, $node_view:ident, $helpers:ident, $json:ident, $bool:ident, $array:ident, $dependency:ident, $docs:ident) => {
        impl<'a> $view<'a> {
            /// Explicit type member, preserving absent/null/value distinction.
            #[must_use]
            pub const fn type_name(&self) -> &'a Presence<String> {
                &self.fields.type_name
            }
            /// Explicit description member.
            #[must_use]
            pub const fn description(&self) -> &'a Presence<String> {
                &self.fields.description
            }
            /// Explicit title member.
            #[must_use]
            pub const fn title(&self) -> &'a Presence<String> {
                &self.fields.title
            }
            /// Explicit format annotation.
            #[must_use]
            pub const fn format(&self) -> &'a Presence<String> {
                &self.fields.format
            }
            /// Explicit schema identifier.
            #[must_use]
            pub const fn id(&self) -> &'a Presence<String> {
                &self.fields.id
            }
            /// Explicit pattern annotation.
            #[must_use]
            pub const fn pattern(&self) -> &'a Presence<String> {
                &self.fields.pattern
            }
            /// Explicit required names, preserving absent/null/value.
            #[must_use]
            pub const fn required(&self) -> &'a Presence<Vec<String>> {
                &self.fields.required
            }
            /// Exact lower numeric bound, if present.
            #[must_use]
            pub const fn minimum(&self) -> &'a Presence<ExactJsonNumber> {
                &self.fields.minimum
            }
            /// Exact upper numeric bound, if present.
            #[must_use]
            pub const fn maximum(&self) -> &'a Presence<ExactJsonNumber> {
                &self.fields.maximum
            }
            /// Explicit exclusive lower-bound flag.
            #[must_use]
            pub const fn exclusive_minimum(&self) -> &'a Presence<bool> {
                &self.fields.exclusive_minimum
            }
            /// Explicit exclusive upper-bound flag.
            #[must_use]
            pub const fn exclusive_maximum(&self) -> &'a Presence<bool> {
                &self.fields.exclusive_maximum
            }
            /// Explicit nullable annotation.
            #[must_use]
            pub const fn nullable(&self) -> &'a Presence<bool> {
                &self.fields.nullable
            }
            /// Explicit exact multiple-of number.
            #[must_use]
            pub const fn multiple_of(&self) -> &'a Presence<ExactJsonNumber> {
                &self.fields.multiple_of
            }
            /// Explicit minimum string length.
            #[must_use]
            pub const fn min_length(&self) -> &'a Presence<i64> {
                &self.fields.min_length
            }
            /// Explicit maximum string length.
            #[must_use]
            pub const fn max_length(&self) -> &'a Presence<i64> {
                &self.fields.max_length
            }
            /// Explicit minimum array length.
            #[must_use]
            pub const fn min_items(&self) -> &'a Presence<i64> {
                &self.fields.min_items
            }
            /// Explicit maximum array length.
            #[must_use]
            pub const fn max_items(&self) -> &'a Presence<i64> {
                &self.fields.max_items
            }
            /// Explicit minimum object-property count.
            #[must_use]
            pub const fn min_properties(&self) -> &'a Presence<i64> {
                &self.fields.min_properties
            }
            /// Explicit maximum object-property count.
            #[must_use]
            pub const fn max_properties(&self) -> &'a Presence<i64> {
                &self.fields.max_properties
            }
            /// Explicit uniqueness annotation.
            #[must_use]
            pub const fn unique_items(&self) -> &'a Presence<bool> {
                &self.fields.unique_items
            }
            /// Explicit selected enum payloads. Raw values still require explicit access.
            #[must_use]
            pub const fn enum_values(&self) -> &'a Presence<Vec<$json>> {
                &self.$helpers.enum_values
            }
            /// Explicit selected example payload. Raw value access still requires authorization.
            #[must_use]
            pub const fn example(&self) -> &'a Presence<$json> {
                &self.$helpers.example
            }
            /// Explicit typed property map, including its original presence.
            #[must_use]
            pub const fn properties(&self) -> &'a Presence<std::collections::BTreeMap<String, SchemaNodeId>> {
                &self.fields.properties
            }
            /// Borrow property names without exposing retained schema values.
            pub fn property_names(&self) -> impl Iterator<Item = &str> {
                self.fields
                    .properties
                    .value()
                    .into_iter()
                    .flat_map(|properties| properties.keys().map(String::as_str))
            }
            /// Look up one named typed property schema.
            #[must_use]
            pub fn property(&self, name: &str) -> Option<$node_view<'a>> {
                let id = self.fields.properties.value()?.get(name)?;
                self.node(id)
            }
            /// Explicit named schema definitions.
            #[must_use]
            pub const fn definitions(&self) -> &'a Presence<std::collections::BTreeMap<String, SchemaNodeId>> {
                &self.fields.definitions
            }
            /// Look up one named definition schema.
            #[must_use]
            pub fn definition(&self, name: &str) -> Option<$node_view<'a>> {
                self.node(self.fields.definitions.value()?.get(name)?)
            }
            /// Explicit pattern-property schemas.
            #[must_use]
            pub const fn pattern_properties(&self) -> &'a Presence<std::collections::BTreeMap<String, SchemaNodeId>> {
                &self.fields.pattern_properties
            }
            /// Look up one pattern-property schema by its exact source pattern.
            #[must_use]
            pub fn pattern_property(&self, pattern: &str) -> Option<$node_view<'a>> {
                self.node(self.fields.pattern_properties.value()?.get(pattern)?)
            }
            /// Explicit dependency declarations, retaining schema or required-name form.
            #[must_use]
            pub const fn dependencies(&self) -> &'a Presence<std::collections::BTreeMap<String, $dependency>> {
                &self.$helpers.dependencies
            }
            /// Borrow a dependency schema when the declaration uses schema form.
            #[must_use]
            pub fn dependency_schema(&self, name: &str) -> Option<$node_view<'a>> {
                match self.$helpers.dependencies.value()?.get(name)? {
                    $dependency::Schema(id) => self.node(id),
                    $dependency::Array(_) => None,
                }
            }
            /// Explicit `items`, preserving schema-versus-tuple form.
            #[must_use]
            pub const fn items(&self) -> &'a Presence<$array> {
                &self.$helpers.items
            }
            /// Borrow one child schema from single-schema or tuple `items` form.
            #[must_use]
            pub fn item_schema(&self, index: usize) -> Option<$node_view<'a>> {
                match self.$helpers.items.value()? {
                    $array::Schema(id) if index == 0 => self.node(id),
                    $array::Array(ids) => self.node(ids.get(index)?),
                    _ => None,
                }
            }
            /// Explicit additional-properties rule.
            #[must_use]
            pub const fn additional_properties(&self) -> &'a Presence<$bool> {
                &self.$helpers.additional_properties
            }
            /// Borrow the additional-properties schema when schema form is selected.
            #[must_use]
            pub fn additional_properties_schema(&self) -> Option<$node_view<'a>> {
                match self.$helpers.additional_properties.value()? {
                    $bool::Schema(id) => self.node(id),
                    $bool::Bool(_) => None,
                }
            }
            /// Explicit additional-items rule.
            #[must_use]
            pub const fn additional_items(&self) -> &'a Presence<$bool> {
                &self.$helpers.additional_items
            }
            /// Borrow the additional-items schema when schema form is selected.
            #[must_use]
            pub fn additional_items_schema(&self) -> Option<$node_view<'a>> {
                match self.$helpers.additional_items.value()? {
                    $bool::Schema(id) => self.node(id),
                    $bool::Bool(_) => None,
                }
            }
            /// Explicit `allOf` branches.
            #[must_use]
            pub const fn all_of(&self) -> &'a Presence<Vec<SchemaNodeId>> {
                &self.fields.all_of
            }
            /// Borrow one `allOf` schema branch.
            #[must_use]
            pub fn all_of_schema(&self, index: usize) -> Option<$node_view<'a>> {
                self.node(self.fields.all_of.value()?.get(index)?)
            }
            /// Explicit `anyOf` branches.
            #[must_use]
            pub const fn any_of(&self) -> &'a Presence<Vec<SchemaNodeId>> {
                &self.fields.any_of
            }
            /// Borrow one `anyOf` schema branch.
            #[must_use]
            pub fn any_of_schema(&self, index: usize) -> Option<$node_view<'a>> {
                self.node(self.fields.any_of.value()?.get(index)?)
            }
            /// Explicit `oneOf` branches.
            #[must_use]
            pub const fn one_of(&self) -> &'a Presence<Vec<SchemaNodeId>> {
                &self.fields.one_of
            }
            /// Borrow one `oneOf` schema branch.
            #[must_use]
            pub fn one_of_schema(&self, index: usize) -> Option<$node_view<'a>> {
                self.node(self.fields.one_of.value()?.get(index)?)
            }
            /// Explicit negated schema branch.
            #[must_use]
            pub const fn not(&self) -> &'a Presence<SchemaNodeId> {
                &self.fields.not
            }
            /// Borrow the negated schema branch.
            #[must_use]
            pub fn not_schema(&self) -> Option<$node_view<'a>> {
                self.node(self.fields.not.value()?)
            }
            /// Explicit external documentation members.
            #[must_use]
            pub const fn external_docs(&self) -> &'a Presence<crate::resources::extensions::$docs> {
                &self.$helpers.external_docs
            }
            /// Explicit embedded-resource extension.
            #[must_use]
            pub const fn x_kubernetes_embedded_resource(&self) -> &'a Presence<bool> {
                &self.fields.x_kubernetes_embedded_resource
            }
            /// Explicit `IntOrString` extension.
            #[must_use]
            pub const fn x_kubernetes_int_or_string(&self) -> &'a Presence<bool> {
                &self.fields.x_kubernetes_int_or_string
            }
            /// Explicit Kubernetes list-map keys.
            #[must_use]
            pub const fn x_kubernetes_list_map_keys(&self) -> &'a Presence<Vec<String>> {
                &self.fields.x_kubernetes_list_map_keys
            }
            /// Explicit Kubernetes list topology.
            #[must_use]
            pub const fn x_kubernetes_list_type(&self) -> &'a Presence<String> {
                &self.fields.x_kubernetes_list_type
            }
            /// Explicit Kubernetes map topology.
            #[must_use]
            pub const fn x_kubernetes_map_type(&self) -> &'a Presence<String> {
                &self.fields.x_kubernetes_map_type
            }
            /// Explicit unknown-field preservation extension.
            #[must_use]
            pub const fn x_kubernetes_preserve_unknown_fields(&self) -> &'a Presence<bool> {
                &self.fields.x_kubernetes_preserve_unknown_fields
            }
            /// Borrow a prior schema handle only when it belongs to this sealed arena and API family.
            #[must_use]
            pub fn node(&self, id: &SchemaNodeId) -> Option<$node_view<'a>> {
                if id.family != self.arena.family
                    || id.index >= self.arena.nodes.len()
                    || !Arc::ptr_eq(&id.identity, &self.arena.identity)
                {
                    return None;
                }
                Some($node_view {
                    arena: self.arena,
                    index: id.index,
                })
            }
            /// Root's selected schema fields remain privately held by the arena.
            #[must_use]
            pub const fn has_enum_values(&self) -> bool {
                matches!(self.$helpers.enum_values, Presence::Value(_))
            }
        }
    };
}

impl<'a> StableSchemaNodeView<'a> {
    /// Typed fields on this node.
    #[must_use]
    pub fn fields(&self) -> StableSchemaFieldsView<'a> {
        StableSchemaFieldsView {
            arena: self.arena,
            fields: &self.arena.nodes[self.index].fields,
        }
    }
}
impl<'a> BetaSchemaNodeView<'a> {
    /// Typed fields on this node.
    #[must_use]
    pub fn fields(&self) -> BetaSchemaFieldsView<'a> {
        BetaSchemaFieldsView {
            arena: self.arena,
            fields: &self.arena.nodes[self.index].fields,
            helpers: &self.arena.nodes[self.index].beta_helpers,
        }
    }
}
schema_fields_view!(
    StableSchemaFieldsView,
    StableSchemaNodeView,
    fields,
    JSONCrdV1,
    JSONSchemaPropsOrBoolCrdV1,
    JSONSchemaPropsOrArrayCrdV1,
    JSONSchemaPropsOrStringArrayCrdV1,
    ExternalDocumentationCrdV1
);
schema_fields_view!(
    BetaSchemaFieldsView,
    BetaSchemaNodeView,
    helpers,
    JSONCrdV1beta1,
    JSONSchemaPropsOrBoolCrdV1beta1,
    JSONSchemaPropsOrArrayCrdV1beta1,
    JSONSchemaPropsOrStringArrayCrdV1beta1,
    ExternalDocumentationCrdV1beta1
);
impl Clone for JSONSchemaPropsCrdV1 {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl Clone for JSONSchemaPropsCrdV1beta1 {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}
impl JSONSchemaPropsCrdV1 {
    /// Borrow the selected root node without exposing private decoder metadata.
    #[must_use]
    pub fn root_view(&self) -> StableSchemaNodeView<'_> {
        StableSchemaNodeView {
            arena: &self.0,
            index: self.0.root,
        }
    }
    /// Borrow a node only when its opaque handle belongs to this exact stable arena.
    #[must_use]
    pub fn node_view(&self, id: &SchemaNodeId) -> Option<StableSchemaNodeView<'_>> {
        (id.family == SchemaFamily::V1 && id.index < self.0.nodes.len() && Arc::ptr_eq(&id.identity, &self.0.identity))
            .then_some(StableSchemaNodeView {
                arena: &self.0,
                index: id.index,
            })
    }
}
impl JSONSchemaPropsCrdV1beta1 {
    /// Borrow the selected root node without exposing private decoder metadata.
    #[must_use]
    pub fn root_view(&self) -> BetaSchemaNodeView<'_> {
        BetaSchemaNodeView {
            arena: &self.0,
            index: self.0.root,
        }
    }
    /// Borrow a node only when its opaque handle belongs to this exact beta arena.
    #[must_use]
    pub fn node_view(&self, id: &SchemaNodeId) -> Option<BetaSchemaNodeView<'_>> {
        (id.family == SchemaFamily::V1beta1
            && id.index < self.0.nodes.len()
            && Arc::ptr_eq(&id.identity, &self.0.identity))
        .then_some(BetaSchemaNodeView {
            arena: &self.0,
            index: id.index,
        })
    }
}
impl fmt::Debug for JSONSchemaPropsCrdV1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSONSchemaPropsCrdV1(<private>)")
    }
}
impl fmt::Debug for JSONSchemaPropsCrdV1beta1 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JSONSchemaPropsCrdV1beta1(<private>)")
    }
}

const SCHEMA_FIELDS: &[&str] = super::super::capabilities::SCHEMA_FIELDS;

fn child_path(path: &FieldPath, key: &str, ctx: &FieldDecodeContext) -> Result<FieldPath, Finding> {
    let depth = path
        .0
        .len()
        .checked_add(1)
        .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
    let bytes = path
        .0
        .iter()
        .try_fold(key.len(), |n, part| n.checked_add(part.len()))
        .ok_or_else(|| ctx.processing.fail(ctx.phase))?;
    ctx.processing.work(depth.saturating_add(1), ctx.phase)?;
    ctx.processing.payload_array::<String>(depth, ctx.phase)?;
    ctx.processing.payload(bytes, ctx.phase)?;
    Ok(path.child(key))
}
fn schema_child_nodes<'a>(
    node: &'a TreeNode,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
) -> Result<Vec<(&'a TreeNode, FieldPath)>, Finding> {
    let mut children = Vec::new();
    let Some(members) = node.as_mapping() else {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
    };
    for (key, value) in members {
        ctx.processing.work(1, ctx.phase)?;
        let base = child_path(path, key, ctx)?;
        let mut add_map = |value: &'a TreeNode| -> Result<(), Finding> {
            let Some(fields) = value.as_mapping() else {
                return Ok(());
            };
            for (name, schema) in fields {
                ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                children.push((schema, child_path(&base, name, ctx)?));
            }
            Ok(())
        };
        match key.as_str() {
            "properties" | "patternProperties" | "definitions" => add_map(value)?,
            "dependencies" => {
                if let Some(dependencies) = value.as_mapping() {
                    for (name, schema) in dependencies {
                        if schema.as_mapping().is_some() {
                            ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                            let dependency_path = child_path(&base, name, ctx)?;
                            children.push((schema, dependency_path));
                        }
                    }
                }
            }
            "additionalItems" | "additionalProperties" | "not" => {
                if value.as_mapping().is_some() {
                    ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                    children.push((value, base));
                }
            }
            "items" => {
                if let Some(items) = value.as_sequence() {
                    for (index, schema) in items.iter().enumerate() {
                        ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                        children.push((schema, child_path(&base, &index.to_string(), ctx)?));
                    }
                } else if value.as_mapping().is_some() {
                    ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                    children.push((value, base));
                }
            }
            "allOf" | "anyOf" | "oneOf" => {
                if let Some(items) = value.as_sequence() {
                    for (index, schema) in items.iter().enumerate() {
                        ctx.processing.payload_array::<(&TreeNode, FieldPath)>(1, ctx.phase)?;
                        children.push((schema, child_path(&base, &index.to_string(), ctx)?));
                    }
                }
            }
            _ => {}
        }
    }
    Ok(children)
}
fn schema_id(
    ids: &HashMap<usize, SchemaNodeId>,
    node: &TreeNode,
    ctx: &FieldDecodeContext,
    path: &FieldPath,
) -> Result<SchemaNodeId, Finding> {
    ctx.processing.work(1, ctx.phase)?;
    ids.get(&(std::ptr::from_ref(node) as usize))
        .cloned()
        .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()))
}
fn decode_schema_fields(
    node: &TreeNode,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
    family: SchemaFamily,
) -> Result<SchemaFields, Finding> {
    use crate::registry::codec;
    let mut fields = SchemaFields {
        description: codec::read_presence(node, "description", ctx, path)?,
        ..SchemaFields::default()
    };
    fields.enum_values = codec::read_presence(node, "enum", ctx, path)?;
    fields.example = codec::read_presence(node, "example", ctx, path)?;
    fields.exclusive_maximum = codec::read_presence(node, "exclusiveMaximum", ctx, path)?;
    fields.exclusive_minimum = codec::read_presence(node, "exclusiveMinimum", ctx, path)?;
    fields.external_docs = codec::read_presence(node, "externalDocs", ctx, path)?;
    fields.format = codec::read_presence(node, "format", ctx, path)?;
    fields.id = codec::read_presence(node, "id", ctx, path)?;
    fields.max_items = codec::read_presence(node, "maxItems", ctx, path)?;
    fields.max_length = codec::read_presence(node, "maxLength", ctx, path)?;
    fields.max_properties = codec::read_presence(node, "maxProperties", ctx, path)?;
    fields.maximum = codec::read_presence(node, "maximum", ctx, path)?;
    fields.min_items = codec::read_presence(node, "minItems", ctx, path)?;
    fields.min_length = codec::read_presence(node, "minLength", ctx, path)?;
    fields.min_properties = codec::read_presence(node, "minProperties", ctx, path)?;
    fields.minimum = codec::read_presence(node, "minimum", ctx, path)?;
    fields.multiple_of = codec::read_presence(node, "multipleOf", ctx, path)?;
    fields.nullable = codec::read_presence(node, "nullable", ctx, path)?;
    fields.pattern = codec::read_presence(node, "pattern", ctx, path)?;
    fields.required = codec::read_presence(node, "required", ctx, path)?;
    fields.title = codec::read_presence(node, "title", ctx, path)?;
    fields.type_name = codec::read_presence(node, "type", ctx, path)?;
    fields.unique_items = codec::read_presence(node, "uniqueItems", ctx, path)?;
    fields.x_kubernetes_embedded_resource = codec::read_presence(node, "x-kubernetes-embedded-resource", ctx, path)?;
    fields.x_kubernetes_int_or_string = codec::read_presence(node, "x-kubernetes-int-or-string", ctx, path)?;
    fields.x_kubernetes_list_map_keys = codec::read_presence(node, "x-kubernetes-list-map-keys", ctx, path)?;
    fields.x_kubernetes_list_type = codec::read_presence(node, "x-kubernetes-list-type", ctx, path)?;
    fields.x_kubernetes_map_type = codec::read_presence(node, "x-kubernetes-map-type", ctx, path)?;
    fields.x_kubernetes_preserve_unknown_fields =
        codec::read_presence(node, "x-kubernetes-preserve-unknown-fields", ctx, path)?;
    fields.dependencies = read_dependencies(node, path, ctx, ids)?;
    fields.all_of = read_refs(node, "allOf", path, ctx, ids)?;
    fields.any_of = read_refs(node, "anyOf", path, ctx, ids)?;
    fields.one_of = read_refs(node, "oneOf", path, ctx, ids)?;
    fields.definitions = read_ref_map(node, "definitions", path, ctx, ids)?;
    fields.pattern_properties = read_ref_map(node, "patternProperties", path, ctx, ids)?;
    fields.properties = read_ref_map(node, "properties", path, ctx, ids)?;
    fields.not = read_ref(node, "not", path, ctx, ids)?;
    fields.additional_items = read_bool_schema(node, "additionalItems", path, ctx, ids, family)?;
    fields.additional_properties = read_bool_schema(node, "additionalProperties", path, ctx, ids, family)?;
    fields.items = read_items(node, path, ctx, ids, family)?;
    Ok(fields)
}
fn read_refs(
    node: &TreeNode,
    key: &str,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
) -> Result<Presence<Vec<SchemaNodeId>>, Finding> {
    let Some(value) = node.get(key) else {
        return Ok(Presence::Absent);
    };
    if matches!(value.value, TreeValue::Null) {
        return Ok(Presence::Null);
    }
    let Some(items) = value.as_sequence() else {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
    };
    ctx.processing.payload_array::<SchemaNodeId>(items.len(), ctx.phase)?;
    items
        .iter()
        .enumerate()
        .map(|(i, item)| schema_id(ids, item, ctx, &path.child(key).child(i.to_string())))
        .collect::<Result<Vec<_>, _>>()
        .map(Presence::Value)
}
fn read_ref_map(
    node: &TreeNode,
    key: &str,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
) -> Result<Presence<std::collections::BTreeMap<String, SchemaNodeId>>, Finding> {
    let Some(value) = node.get(key) else {
        return Ok(Presence::Absent);
    };
    if matches!(value.value, TreeValue::Null) {
        return Ok(Presence::Null);
    }
    let Some(entries) = value.as_mapping() else {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
    };
    ctx.processing
        .payload_array::<(String, SchemaNodeId)>(entries.len(), ctx.phase)?;
    let mut map = std::collections::BTreeMap::new();
    for (name, child) in entries {
        ctx.processing.payload(name.len(), ctx.phase)?;
        map.insert(name.clone(), schema_id(ids, child, ctx, &path.child(key).child(name))?);
    }
    Ok(Presence::Value(map))
}
fn read_ref(
    node: &TreeNode,
    key: &str,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
) -> Result<Presence<SchemaNodeId>, Finding> {
    match node.get(key) {
        None => Ok(Presence::Absent),
        Some(value) if matches!(value.value, TreeValue::Null) => Ok(Presence::Null),
        Some(value) => schema_id(ids, value, ctx, &path.child(key)).map(Presence::Value),
    }
}

fn read_dependencies(
    node: &TreeNode,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
) -> Result<Presence<std::collections::BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1>>, Finding> {
    let Some(value) = node.get("dependencies") else {
        return Ok(Presence::Absent);
    };
    if matches!(value.value, TreeValue::Null) {
        return Ok(Presence::Null);
    }
    let Some(dependencies) = value.as_mapping() else {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
    };
    ctx.processing
        .payload_array::<(String, JSONSchemaPropsOrStringArrayCrdV1)>(dependencies.len(), ctx.phase)?;
    let mut output = std::collections::BTreeMap::new();
    for (name, dependency) in dependencies {
        ctx.processing.payload(name.len(), ctx.phase)?;
        let dependency_path = path.child("dependencies").child(name);
        let decoded = if dependency.as_mapping().is_some() {
            JSONSchemaPropsOrStringArrayCrdV1::Schema(schema_id(ids, dependency, ctx, &dependency_path)?)
        } else {
            JSONSchemaPropsOrStringArrayCrdV1::Array(Vec::<String>::decode(dependency, ctx, &dependency_path)?)
        };
        output.insert(name.clone(), decoded);
    }
    Ok(Presence::Value(output))
}
fn read_bool_schema(
    node: &TreeNode,
    key: &str,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
    _family: SchemaFamily,
) -> Result<Presence<JSONSchemaPropsOrBoolCrdV1>, Finding> {
    match node.get(key) {
        None => Ok(Presence::Absent),
        Some(value) if matches!(value.value, TreeValue::Null) => Ok(Presence::Null),
        Some(value) => match &value.value {
            TreeValue::Bool(b) => Ok(Presence::Value(JSONSchemaPropsOrBoolCrdV1::Bool(*b))),
            TreeValue::Mapping(_) => Ok(Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(schema_id(
                ids,
                value,
                ctx,
                &path.child(key),
            )?))),
            _ => Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.child(key))),
        },
    }
}
fn read_items(
    node: &TreeNode,
    path: &FieldPath,
    ctx: &FieldDecodeContext,
    ids: &HashMap<usize, SchemaNodeId>,
    _family: SchemaFamily,
) -> Result<Presence<JSONSchemaPropsOrArrayCrdV1>, Finding> {
    match node.get("items") {
        None => Ok(Presence::Absent),
        Some(value) if matches!(value.value, TreeValue::Null) => Ok(Presence::Null),
        Some(value) if value.as_mapping().is_some() => Ok(Presence::Value(JSONSchemaPropsOrArrayCrdV1::Schema(
            schema_id(ids, value, ctx, &path.child("items"))?,
        ))),
        Some(value) => {
            let Some(items) = value.as_sequence() else {
                return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.child("items")));
            };
            ctx.processing.payload_array::<SchemaNodeId>(items.len(), ctx.phase)?;
            let refs = items
                .iter()
                .enumerate()
                .map(|(i, item)| schema_id(ids, item, ctx, &path.child("items").child(i.to_string())))
                .collect::<Result<Vec<_>, _>>()?;
            Ok(Presence::Value(JSONSchemaPropsOrArrayCrdV1::Array(refs)))
        }
    }
}

fn decode_arena(
    node: &TreeNode,
    ctx: &FieldDecodeContext,
    path: &FieldPath,
    family: SchemaFamily,
) -> Result<SchemaArena, Finding> {
    enum Step<'a> {
        Visit(&'a TreeNode, FieldPath),
        Finish(&'a TreeNode, FieldPath),
    }
    let mut builder = if family == SchemaFamily::V1 {
        SchemaBuilder::stable(&ctx.limits)?
    } else {
        SchemaBuilder::beta(&ctx.limits)?
    };
    builder.fields = ctx.clone();
    ctx.processing.payload_array::<Step<'_>>(1, ctx.phase)?;
    let mut pending = vec![Step::Visit(node, path.clone())];
    let mut ids: HashMap<usize, SchemaNodeId> = HashMap::new();
    while let Some(step) = pending.pop() {
        ctx.processing.work(1, ctx.phase)?;
        match step {
            Step::Visit(current, current_path) => {
                let children = schema_child_nodes(current, &current_path, ctx)?;
                ctx.processing.payload_array::<Step<'_>>(
                    children
                        .len()
                        .checked_add(1)
                        .ok_or_else(|| ctx.processing.fail(ctx.phase))?,
                    ctx.phase,
                )?;
                pending.push(Step::Finish(current, current_path));
                pending.extend(
                    children
                        .into_iter()
                        .rev()
                        .map(|(child, child_path)| Step::Visit(child, child_path)),
                );
            }
            Step::Finish(current, current_path) => {
                let fields = decode_schema_fields(current, &current_path, ctx, &ids, family)?;
                let unknown = UnknownFields::capture_in(current, SCHEMA_FIELDS, ctx)?;
                let id = builder.add_with_unknown(fields, unknown, Some(current_path))?;
                ctx.processing.payload(size_of::<(usize, SchemaNodeId)>(), ctx.phase)?;
                ids.insert(std::ptr::from_ref(current) as usize, id);
            }
        }
    }
    let root = schema_id(&ids, node, ctx, path)?;
    let builder = if family == SchemaFamily::V1 {
        builder.finish_stable(&root)?.0
    } else {
        builder.finish_beta(&root)?.0
    };
    let mut arena = Arc::try_unwrap(builder).map_err(|_| Finding::error(FindingCode::NativeFieldInvalid, ctx.phase))?;
    arena.evidence = match ctx.source_evidence() {
        Some(source) => SchemaEvidenceOrigin::Decoded {
            source: source.clone(),
            pointer: path.clone(),
        },
        None => SchemaEvidenceOrigin::Incomplete,
    };
    Ok(arena)
}

impl FieldCodec for JSONSchemaPropsCrdV1 {
    fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        decode_arena(node, ctx, path, SchemaFamily::V1).map(|arena| Self(Arc::new(arena)))
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        encode_arena(&self.0, SchemaFamily::V1, ctx, path)
    }
}
impl FieldCodec for JSONSchemaPropsCrdV1beta1 {
    fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        decode_arena(node, ctx, path, SchemaFamily::V1beta1).map(|arena| Self(Arc::new(arena)))
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        encode_arena(&self.0, SchemaFamily::V1beta1, ctx, path)
    }
}

impl UnknownScopes for JSONSchemaPropsCrdV1 {
    #[cfg(test)]
    fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
    fn visit_unknown_scopes(&self, path: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
        visitor.step() && visit_unknown(&self.0, path, visitor)
    }
}
impl UnknownScopes for JSONSchemaPropsCrdV1beta1 {
    #[cfg(test)]
    fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
    fn visit_unknown_scopes(&self, path: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
        visitor.step() && visit_unknown(&self.0, path, visitor)
    }
}

// A cached child is copied only while a later direct reference still needs it.
// Every direct occurrence is counted, including repeated edges to a shared DAG node.
struct SchemaEncodingCache<'a> {
    arena: &'a SchemaArena,
    nodes: Vec<Option<TreeNode>>,
    remaining: Vec<usize>,
}
impl<'a> SchemaEncodingCache<'a> {
    fn new(arena: &'a SchemaArena, ctx: &EncodeContext<'_>) -> Result<Self, Finding> {
        let processing = ctx.budget.processing();
        let phase = ctx.budget.phase();
        let retained = arena.root.checked_add(1).ok_or_else(|| processing.fail(phase))?;
        processing.payload_array::<Option<TreeNode>>(retained, phase)?;
        processing.payload_array::<usize>(retained, phase)?;
        let mut nodes = Vec::new();
        let mut remaining = Vec::new();
        nodes.try_reserve(retained).map_err(|_| processing.fail(phase))?;
        remaining.try_reserve(retained).map_err(|_| processing.fail(phase))?;
        processing.work(retained, phase)?;
        remaining.resize(retained, 0usize);
        for (index, node) in arena.nodes.iter().take(retained).enumerate() {
            processing.work(1, phase)?;
            count_encoding_refs(&node.fields, arena, index, &mut remaining, processing, phase)?;
        }
        Ok(Self {
            arena,
            nodes,
            remaining,
        })
    }
    fn reference(&mut self, id: &SchemaNodeId, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        validate_schema_ref(
            id,
            &self.arena.identity,
            self.arena.family,
            self.nodes.len(),
            ctx.budget.processing(),
            ctx.budget.phase(),
        )
        .map_err(|finding| finding.at_path(path.clone()))?;
        let invalid = || Finding::error(FindingCode::NativeFieldInvalid, ctx.budget.phase()).at_path(path.clone());
        let remaining = self.remaining.get_mut(id.index).ok_or_else(invalid)?;
        let next = remaining.checked_sub(1).ok_or_else(invalid)?;
        let cached = self.nodes.get_mut(id.index).ok_or_else(invalid)?;
        let value = if next == 0 {
            // Moving ownership does not allocate or visit the subtree. The normal
            // registry/snapshot final-shape verification still checks assembled depth.
            cached.take().ok_or_else(invalid)?
        } else {
            ctx.clone_node(cached.as_ref().ok_or_else(invalid)?, path)?
        };
        *remaining = next;
        Ok(value)
    }
}
fn count_encoding_refs(
    fields: &SchemaFields,
    arena: &SchemaArena,
    index: usize,
    remaining: &mut [usize],
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<(), Finding> {
    let mut count = |id: &SchemaNodeId| -> Result<(), Finding> {
        validate_schema_ref(id, &arena.identity, arena.family, index, processing, phase)?;
        let uses = remaining
            .get_mut(id.index)
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, phase))?;
        *uses = uses.checked_add(1).ok_or_else(|| processing.fail(phase))?;
        Ok(())
    };
    for presence in [&fields.all_of, &fields.any_of, &fields.one_of] {
        processing.work(1, phase)?;
        if let Presence::Value(values) = presence {
            for id in values {
                count(id)?;
            }
        }
    }
    for presence in [&fields.definitions, &fields.pattern_properties, &fields.properties] {
        processing.work(1, phase)?;
        if let Presence::Value(values) = presence {
            for id in values.values() {
                count(id)?;
            }
        }
    }
    processing.work(1, phase)?;
    if let Presence::Value(values) = &fields.dependencies {
        for dependency in values.values() {
            processing.work(1, phase)?;
            if let JSONSchemaPropsOrStringArrayCrdV1::Schema(id) = dependency {
                count(id)?;
            }
        }
    }
    processing.work(1, phase)?;
    if let Presence::Value(id) = &fields.not {
        count(id)?;
    }
    for presence in [&fields.additional_items, &fields.additional_properties] {
        processing.work(1, phase)?;
        if let Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(id)) = presence {
            count(id)?;
        }
    }
    processing.work(1, phase)?;
    if let Presence::Value(items) = &fields.items {
        match items {
            JSONSchemaPropsOrArrayCrdV1::Schema(id) => count(id)?,
            JSONSchemaPropsOrArrayCrdV1::Array(ids) => {
                for id in ids {
                    count(id)?;
                }
            }
        }
    }
    Ok(())
}
fn encoded_ref(
    id: &SchemaNodeId,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<TreeNode, Finding> {
    encoded.reference(id, ctx, path)
}

fn write_ref(
    entries: &mut Vec<(String, TreeNode)>,
    key: &str,
    value: &Presence<SchemaNodeId>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(id) => encoded_ref(id, encoded, ctx, &child_path)?,
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn write_ref_vec(
    entries: &mut Vec<(String, TreeNode)>,
    key: &str,
    value: &Presence<Vec<SchemaNodeId>>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(ids) => {
            ctx.check_sequence_len(ids.len(), &child_path)?;
            ctx.budget
                .processing()
                .payload_array::<TreeNode>(ids.len(), ctx.budget.phase())?;
            let mut items = Vec::new();
            items
                .try_reserve(ids.len())
                .map_err(|_| ctx.budget.processing().fail(ctx.budget.phase()))?;
            for (index, id) in ids.iter().enumerate() {
                items.push(encoded_ref(id, encoded, ctx, &child_path.child(index.to_string()))?);
            }
            ctx.sequence(items, &child_path)?
        }
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn write_ref_map(
    entries: &mut Vec<(String, TreeNode)>,
    key: &str,
    value: &Presence<std::collections::BTreeMap<String, SchemaNodeId>>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(values) => {
            ctx.check_sequence_len(values.len(), &child_path)?;
            ctx.budget
                .processing()
                .payload_array::<(String, TreeNode)>(values.len(), ctx.budget.phase())?;
            let mut members = Vec::new();
            members
                .try_reserve(values.len())
                .map_err(|_| ctx.budget.processing().fail(ctx.budget.phase()))?;
            for (name, id) in values {
                let value_path = child_path.child(name);
                members.push((ctx.key(name, &value_path)?, encoded_ref(id, encoded, ctx, &value_path)?));
            }
            ctx.object(members, &child_path)?
        }
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn write_dependencies(
    entries: &mut Vec<(String, TreeNode)>,
    value: &Presence<std::collections::BTreeMap<String, JSONSchemaPropsOrStringArrayCrdV1>>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let key = "dependencies";
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(values) => {
            ctx.check_sequence_len(values.len(), &child_path)?;
            ctx.budget
                .processing()
                .payload_array::<(String, TreeNode)>(values.len(), ctx.budget.phase())?;
            let mut members = Vec::new();
            members
                .try_reserve(values.len())
                .map_err(|_| ctx.budget.processing().fail(ctx.budget.phase()))?;
            for (name, dependency) in values {
                let value_path = child_path.child(name);
                let value = match dependency {
                    JSONSchemaPropsOrStringArrayCrdV1::Schema(id) => encoded_ref(id, encoded, ctx, &value_path)?,
                    JSONSchemaPropsOrStringArrayCrdV1::Array(names) => names.encode(ctx, &value_path)?,
                };
                members.push((ctx.key(name, &value_path)?, value));
            }
            ctx.object(members, &child_path)?
        }
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn write_schema_bool(
    entries: &mut Vec<(String, TreeNode)>,
    key: &str,
    value: &Presence<JSONSchemaPropsOrBoolCrdV1>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(JSONSchemaPropsOrBoolCrdV1::Bool(value)) => ctx.boolean(*value, &child_path)?,
        Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(id)) => encoded_ref(id, encoded, ctx, &child_path)?,
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn write_items(
    entries: &mut Vec<(String, TreeNode)>,
    value: &Presence<JSONSchemaPropsOrArrayCrdV1>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    let key = "items";
    let child_path = path.child(key);
    let node = match value {
        Presence::Absent => return Ok(()),
        Presence::Null => ctx.null(&child_path)?,
        Presence::Value(JSONSchemaPropsOrArrayCrdV1::Schema(id)) => encoded_ref(id, encoded, ctx, &child_path)?,
        Presence::Value(JSONSchemaPropsOrArrayCrdV1::Array(ids)) => {
            ctx.check_sequence_len(ids.len(), &child_path)?;
            ctx.budget
                .processing()
                .payload_array::<TreeNode>(ids.len(), ctx.budget.phase())?;
            let mut items = Vec::new();
            items
                .try_reserve(ids.len())
                .map_err(|_| ctx.budget.processing().fail(ctx.budget.phase()))?;
            for (index, id) in ids.iter().enumerate() {
                items.push(encoded_ref(id, encoded, ctx, &child_path.child(index.to_string()))?);
            }
            ctx.sequence(items, &child_path)?
        }
    };
    entries.push((ctx.key(key, &child_path)?, node));
    Ok(())
}

fn encode_schema_prefix(
    fields: &SchemaFields,
    entries: &mut Vec<(String, TreeNode)>,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<(), Finding> {
    write_schema_bool(entries, "additionalItems", &fields.additional_items, encoded, ctx, path)?;
    write_schema_bool(
        entries,
        "additionalProperties",
        &fields.additional_properties,
        encoded,
        ctx,
        path,
    )?;
    write_ref_vec(entries, "allOf", &fields.all_of, encoded, ctx, path)?;
    write_ref_vec(entries, "anyOf", &fields.any_of, encoded, ctx, path)?;
    write_ref_map(entries, "definitions", &fields.definitions, encoded, ctx, path)?;
    write_dependencies(entries, &fields.dependencies, encoded, ctx, path)?;
    Ok(())
}
fn encode_schema_node(
    node: &SchemaNode,
    encoded: &mut SchemaEncodingCache<'_>,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<TreeNode, Finding> {
    use crate::registry::codec::{append_unknown, write_presence};
    let fields = &node.fields;
    let mut entries = Vec::new();
    entries
        .try_reserve(48)
        .map_err(|_| ctx.budget.processing().fail(ctx.budget.phase()))?;
    encode_schema_prefix(fields, &mut entries, encoded, ctx, path)?;
    write_presence(&mut entries, "description", &fields.description, ctx, path)?;
    write_presence(&mut entries, "enum", &fields.enum_values, ctx, path)?;
    write_presence(&mut entries, "example", &fields.example, ctx, path)?;
    write_presence(&mut entries, "exclusiveMaximum", &fields.exclusive_maximum, ctx, path)?;
    write_presence(&mut entries, "exclusiveMinimum", &fields.exclusive_minimum, ctx, path)?;
    write_presence(&mut entries, "externalDocs", &fields.external_docs, ctx, path)?;
    write_presence(&mut entries, "format", &fields.format, ctx, path)?;
    write_presence(&mut entries, "id", &fields.id, ctx, path)?;
    write_items(&mut entries, &fields.items, encoded, ctx, path)?;
    write_presence(&mut entries, "maxItems", &fields.max_items, ctx, path)?;
    write_presence(&mut entries, "maxLength", &fields.max_length, ctx, path)?;
    write_presence(&mut entries, "maxProperties", &fields.max_properties, ctx, path)?;
    write_presence(&mut entries, "maximum", &fields.maximum, ctx, path)?;
    write_presence(&mut entries, "minItems", &fields.min_items, ctx, path)?;
    write_presence(&mut entries, "minLength", &fields.min_length, ctx, path)?;
    write_presence(&mut entries, "minProperties", &fields.min_properties, ctx, path)?;
    write_presence(&mut entries, "minimum", &fields.minimum, ctx, path)?;
    write_presence(&mut entries, "multipleOf", &fields.multiple_of, ctx, path)?;
    write_ref(&mut entries, "not", &fields.not, encoded, ctx, path)?;
    write_presence(&mut entries, "nullable", &fields.nullable, ctx, path)?;
    write_ref_vec(&mut entries, "oneOf", &fields.one_of, encoded, ctx, path)?;
    write_presence(&mut entries, "pattern", &fields.pattern, ctx, path)?;
    write_ref_map(
        &mut entries,
        "patternProperties",
        &fields.pattern_properties,
        encoded,
        ctx,
        path,
    )?;
    write_ref_map(&mut entries, "properties", &fields.properties, encoded, ctx, path)?;
    write_presence(&mut entries, "required", &fields.required, ctx, path)?;
    write_presence(&mut entries, "title", &fields.title, ctx, path)?;
    write_presence(&mut entries, "type", &fields.type_name, ctx, path)?;
    write_presence(&mut entries, "uniqueItems", &fields.unique_items, ctx, path)?;
    write_presence(
        &mut entries,
        "x-kubernetes-embedded-resource",
        &fields.x_kubernetes_embedded_resource,
        ctx,
        path,
    )?;
    write_presence(
        &mut entries,
        "x-kubernetes-int-or-string",
        &fields.x_kubernetes_int_or_string,
        ctx,
        path,
    )?;
    write_presence(
        &mut entries,
        "x-kubernetes-list-map-keys",
        &fields.x_kubernetes_list_map_keys,
        ctx,
        path,
    )?;
    write_presence(
        &mut entries,
        "x-kubernetes-list-type",
        &fields.x_kubernetes_list_type,
        ctx,
        path,
    )?;
    write_presence(
        &mut entries,
        "x-kubernetes-map-type",
        &fields.x_kubernetes_map_type,
        ctx,
        path,
    )?;
    write_presence(
        &mut entries,
        "x-kubernetes-preserve-unknown-fields",
        &fields.x_kubernetes_preserve_unknown_fields,
        ctx,
        path,
    )?;
    append_unknown(
        &node.unknown,
        &mut entries,
        ctx,
        node.source_path.as_ref().unwrap_or(path),
    )?;
    ctx.object(entries, path)
}

fn encode_arena(
    arena: &SchemaArena,
    expected_family: SchemaFamily,
    ctx: &EncodeContext<'_>,
    path: &FieldPath,
) -> Result<TreeNode, Finding> {
    if arena.family != expected_family || arena.root >= arena.nodes.len() {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.budget.phase()).at_path(path.clone()));
    }
    let bounded = ctx.for_source(arena.limits);
    let ctx = &bounded;
    let mut encoded = SchemaEncodingCache::new(arena, ctx)?;
    for node in arena.nodes.iter().take(arena.root.saturating_add(1)) {
        ctx.budget.processing().work(1, ctx.budget.phase())?;
        let tree = encode_schema_node(node, &mut encoded, ctx, path)?;
        encoded.nodes.push(Some(tree));
    }
    encoded
        .nodes
        .pop()
        .flatten()
        .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, ctx.budget.phase()).at_path(path.clone()))
}
fn enqueue_unknown_child(
    pending: &mut Vec<(usize, FieldPath)>,
    id: &SchemaNodeId,
    path: &FieldPath,
    segment: &str,
    child_segment: Option<&str>,
    visitor: &UnknownScopeVisitor<'_>,
) -> bool {
    if !visitor.charge(1) {
        return false;
    }
    let Some(mut child_path) = visitor.child(path, segment) else {
        return false;
    };
    if let Some(segment) = child_segment {
        let Some(next_path) = visitor.child(&child_path, segment) else {
            return false;
        };
        child_path = next_path;
    }
    if pending.try_reserve(1).is_err() {
        return false;
    }
    pending.push((id.index, child_path));
    true
}

fn visit_unknown(arena: &SchemaArena, path: &FieldPath, visitor: &mut UnknownScopeVisitor<'_>) -> bool {
    if !visitor.charge(1) {
        return false;
    }
    let mut pending = Vec::new();
    if pending.try_reserve(1).is_err() {
        return false;
    }
    pending.push((arena.root, path.clone()));
    while let Some((index, current_path)) = pending.pop() {
        if !visitor.step() {
            return false;
        }
        let Some(node) = arena.nodes.get(index) else {
            return false;
        };
        if !node.unknown.is_empty() && !visitor.found(&current_path) {
            return false;
        }
        if !queue_unknown_children(&node.fields, &current_path, &mut pending, visitor) {
            return false;
        }
    }
    true
}

fn queue_unknown_children(
    fields: &SchemaFields,
    current_path: &FieldPath,
    pending: &mut Vec<(usize, FieldPath)>,
    visitor: &mut UnknownScopeVisitor<'_>,
) -> bool {
    for (key, refs) in [
        ("allOf", &fields.all_of),
        ("anyOf", &fields.any_of),
        ("oneOf", &fields.one_of),
    ] {
        if let Presence::Value(children) = refs {
            for (child_index, child) in children.iter().enumerate() {
                if !enqueue_unknown_child(
                    pending,
                    child,
                    current_path,
                    key,
                    Some(&child_index.to_string()),
                    visitor,
                ) {
                    return false;
                }
            }
        }
    }
    for (key, refs) in [
        ("definitions", &fields.definitions),
        ("patternProperties", &fields.pattern_properties),
        ("properties", &fields.properties),
    ] {
        if let Presence::Value(children) = refs {
            for (name, child) in children {
                if !enqueue_unknown_child(pending, child, current_path, key, Some(name), visitor) {
                    return false;
                }
            }
        }
    }
    if let Presence::Value(dependencies) = &fields.dependencies {
        for (name, dependency) in dependencies {
            if let JSONSchemaPropsOrStringArrayCrdV1::Schema(child) = dependency {
                if !enqueue_unknown_child(pending, child, current_path, "dependencies", Some(name), visitor) {
                    return false;
                }
            }
        }
    }
    if let Presence::Value(child) = &fields.not {
        if !enqueue_unknown_child(pending, child, current_path, "not", None, visitor) {
            return false;
        }
    }
    for (key, value) in [
        ("additionalItems", &fields.additional_items),
        ("additionalProperties", &fields.additional_properties),
    ] {
        if let Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(child)) = value {
            if !enqueue_unknown_child(pending, child, current_path, key, None, visitor) {
                return false;
            }
        }
    }
    if let Presence::Value(items) = &fields.items {
        match items {
            JSONSchemaPropsOrArrayCrdV1::Schema(child) => {
                if !enqueue_unknown_child(pending, child, current_path, "items", None, visitor) {
                    return false;
                }
            }
            JSONSchemaPropsOrArrayCrdV1::Array(children) => {
                for (child_index, child) in children.iter().enumerate() {
                    if !enqueue_unknown_child(
                        pending,
                        child,
                        current_path,
                        "items",
                        Some(&child_index.to_string()),
                        visitor,
                    ) {
                        return false;
                    }
                }
            }
        }
    }
    true
}

#[cfg(test)]
mod inherited_budget_tests {
    use super::*;
    use crate::processing::NativeProcessingLimits;
    use crate::resources::extensions::test_support::{TestRequired, TestResult};

    #[test]
    fn beta_enum_conversion_precharges_before_allocating_and_sticks_on_failure() -> TestResult {
        let value = JSONCrdV1beta1::parse_json(b"1", &ParseLimits::default()).required("protected beta JSON")?;
        let limits = ParseLimits {
            processing: NativeProcessingLimits {
                max_payload_bytes: size_of::<SchemaBuilder>() + size_of::<JSONCrdV1>() - 1,
                ..NativeProcessingLimits::default()
            },
            ..ParseLimits::default()
        };
        let mut builder = SchemaBuilder::beta(&limits).required("builder initialization fits")?;
        let first = builder.add_beta(SchemaFieldsBeta {
            enum_values: Presence::Value(vec![value]),
            ..SchemaFieldsBeta::default()
        });
        assert_eq!(
            first.err().required("enum conversion must be precharged")?.code,
            FindingCode::LimitExceeded
        );
        assert!(builder.fields.processing.exhausted());
        let later = builder.add_beta(SchemaFieldsBeta::default());
        assert_eq!(
            later.err().required("failed builder stays exhausted")?.code,
            FindingCode::LimitExceeded
        );
        Ok(())
    }
}

#[cfg(test)]
mod encoding_cache_tests {
    use super::*;
    use crate::processing::NativeProcessingLimits;
    use crate::resources::extensions::test_support::{TestRequired, TestResult};
    use std::collections::BTreeMap;

    fn chain(family: SchemaFamily, count: usize, scalar_bytes: usize) -> TestResult<Arc<SchemaArena>> {
        let mut builder = SchemaBuilder::new(family, &ParseLimits::default()).required("schema builder")?;
        let mut child = None;
        for _ in 0..count {
            let properties = match child.take() {
                Some(id) => Presence::Value(BTreeMap::from([("next".to_owned(), id)])),
                None => Presence::Absent,
            };
            child = Some(
                builder
                    .add(SchemaFields {
                        description: Presence::Value("d".repeat(scalar_bytes)),
                        properties,
                        ..SchemaFields::default()
                    })
                    .required("chain node")?,
            );
        }
        let root = child.required("nonempty schema chain")?;
        match family {
            SchemaFamily::V1 => builder
                .finish_stable(&root)
                .map(|schema| schema.0)
                .required("stable chain"),
            SchemaFamily::V1beta1 => builder.finish_beta(&root).map(|schema| schema.0).required("beta chain"),
        }
    }
    fn encode(
        arena: &Arc<SchemaArena>,
        family: SchemaFamily,
        context: &EncodeContext<'_>,
    ) -> Result<TreeNode, Finding> {
        match family {
            SchemaFamily::V1 => JSONSchemaPropsCrdV1(arena.clone()).encode(context, &FieldPath::default()),
            SchemaFamily::V1beta1 => JSONSchemaPropsCrdV1beta1(arena.clone()).encode(context, &FieldPath::default()),
        }
    }
    fn encoding_context(limits: ParseLimits) -> EncodeContext<'static> {
        EncodeContext::in_operation(None, limits, NativeOperationBudget::new(limits.processing))
    }
    fn fanout(count: usize) -> TestResult<Arc<SchemaArena>> {
        let mut builder = SchemaBuilder::stable(&ParseLimits::default()).required("fanout builder")?;
        let leaf = builder
            .add(SchemaFields {
                description: Presence::Value("s".repeat(100)),
                ..SchemaFields::default()
            })
            .required("fanout leaf")?;
        let root = builder
            .add(SchemaFields {
                all_of: Presence::Value(vec![leaf; count]),
                ..SchemaFields::default()
            })
            .required("fanout root")?;
        builder
            .finish_stable(&root)
            .map(|schema| schema.0)
            .required("fanout schema")
    }

    #[test]
    fn deep_ordinary_schema_fits_original_limits_in_both_served_wrappers() -> TestResult {
        // The actual output carries 2.4 MB of scalars. Recopying the growing cache
        // at each ancestor previously charged roughly 30 MB against the 8 MiB cap.
        for family in [SchemaFamily::V1, SchemaFamily::V1beta1] {
            let arena = chain(family, 24, 100_000)?;
            let context = EncodeContext::new(None);
            let tree = encode(&arena, family, &context).required("ordinary deep schema fits")?;
            context.budget.verify(&tree).required("actual assembled shape fits")?;
            let mut current = &tree;
            for index in 0..24 {
                let description = current
                    .get("description")
                    .and_then(TreeNode::as_str)
                    .required("every description is retained")?;
                assert_eq!(description.len(), 100_000);
                assert!(description.bytes().all(|byte| byte == b'd'));
                if index == 23 {
                    assert!(current.get("properties").is_none());
                } else {
                    current = current
                        .get("properties")
                        .and_then(|properties| properties.get("next"))
                        .required("every chain edge is retained")?;
                }
            }
            let bytes = context
                .budget
                .snapshot(&tree)
                .required("snapshot still verifies and fits")?;
            assert!(bytes.len() > 2_400_000);
        }
        Ok(())
    }

    #[test]
    fn repeated_dag_edges_and_all_reference_helpers_preserve_exact_output() -> TestResult {
        for family in [SchemaFamily::V1, SchemaFamily::V1beta1] {
            let mut builder = SchemaBuilder::new(family, &ParseLimits::default()).required("DAG builder")?;
            let leaf = builder
                .add(SchemaFields {
                    type_name: Presence::Value("string".to_owned()),
                    pattern: Presence::Value("^literal$".to_owned()),
                    ..SchemaFields::default()
                })
                .required("DAG leaf")?;
            let middle = builder
                .add(SchemaFields {
                    additional_properties: Presence::Value(JSONSchemaPropsOrBoolCrdV1::Bool(true)),
                    items: Presence::Value(JSONSchemaPropsOrArrayCrdV1::Schema(leaf.clone())),
                    properties: Presence::Value(BTreeMap::from([("value".to_owned(), leaf.clone())])),
                    ..SchemaFields::default()
                })
                .required("DAG middle")?;
            let fields = SchemaFields {
                additional_items: Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(leaf.clone())),
                additional_properties: Presence::Value(JSONSchemaPropsOrBoolCrdV1::Schema(leaf.clone())),
                all_of: Presence::Value(vec![middle.clone(), middle]),
                any_of: Presence::Value(vec![leaf.clone(), leaf.clone()]),
                definitions: Presence::Value(BTreeMap::from([("leaf".to_owned(), leaf.clone())])),
                dependencies: Presence::Value(BTreeMap::from([
                    (
                        "array".to_owned(),
                        JSONSchemaPropsOrStringArrayCrdV1::Array(vec!["name".to_owned()]),
                    ),
                    (
                        "schema".to_owned(),
                        JSONSchemaPropsOrStringArrayCrdV1::Schema(leaf.clone()),
                    ),
                ])),
                items: Presence::Value(JSONSchemaPropsOrArrayCrdV1::Array(vec![leaf.clone(), leaf.clone()])),
                not: Presence::Value(leaf.clone()),
                one_of: Presence::Value(vec![leaf.clone()]),
                pattern_properties: Presence::Value(BTreeMap::from([("^x".to_owned(), leaf.clone())])),
                properties: Presence::Value(BTreeMap::from([
                    ("one".to_owned(), leaf.clone()),
                    ("two".to_owned(), leaf),
                ])),
                ..SchemaFields::default()
            };
            let root = builder
                .add(fields)
                .required("DAG root with duplicate and mixed edges")?;
            let arena = match family {
                SchemaFamily::V1 => builder
                    .finish_stable(&root)
                    .map(|schema| schema.0)
                    .required("stable DAG")?,
                SchemaFamily::V1beta1 => builder.finish_beta(&root).map(|schema| schema.0).required("beta DAG")?,
            };
            let context = EncodeContext::new(None);
            let tree = encode(&arena, family, &context).required("DAG encoding")?;
            let bytes = context.budget.snapshot(&tree).required("DAG snapshot")?;
            let actual: serde_json::Value = serde_json::from_slice(&bytes).required("DAG JSON")?;
            let leaf = serde_json::json!({"type":"string", "pattern":"^literal$"});
            let middle = serde_json::json!({"additionalProperties":true, "items":leaf, "properties":{"value":leaf}});
            let expected = serde_json::json!({
                "additionalItems":leaf, "additionalProperties":leaf,
                "allOf":[middle,middle], "anyOf":[leaf,leaf], "definitions":{"leaf":leaf},
                "dependencies":{"array":["name"],"schema":leaf}, "items":[leaf,leaf], "not":leaf,
                "oneOf":[leaf], "patternProperties":{"^x":leaf}, "properties":{"one":leaf,"two":leaf}
            });
            assert_eq!(actual, expected);
        }
        Ok(())
    }

    #[test]
    fn beta_union_inputs_preserve_repeated_schema_and_nonschema_helpers() -> TestResult {
        let mut builder = SchemaBuilder::beta(&ParseLimits::default()).required("beta helper builder")?;
        let leaf = builder
            .add_beta(SchemaFieldsBeta {
                type_name: Presence::Value("integer".to_owned()),
                ..SchemaFieldsBeta::default()
            })
            .required("beta helper leaf")?;
        let root = builder
            .add_beta(SchemaFieldsBeta {
                additional_items: Presence::Value(JSONSchemaPropsOrBoolCrdV1beta1::Schema(leaf.clone())),
                additional_properties: Presence::Value(JSONSchemaPropsOrBoolCrdV1beta1::Bool(false)),
                dependencies: Presence::Value(BTreeMap::from([
                    (
                        "array".to_owned(),
                        JSONSchemaPropsOrStringArrayCrdV1beta1::Array(vec!["field".to_owned()]),
                    ),
                    (
                        "schema".to_owned(),
                        JSONSchemaPropsOrStringArrayCrdV1beta1::Schema(leaf.clone()),
                    ),
                ])),
                items: Presence::Value(JSONSchemaPropsOrArrayCrdV1beta1::Array(vec![leaf.clone(), leaf])),
                ..SchemaFieldsBeta::default()
            })
            .required("beta helper root")?;
        let schema = builder.finish_beta(&root).required("beta helper schema")?;
        let context = EncodeContext::new(None);
        let tree = schema
            .encode(&context, &FieldPath::default())
            .required("beta helper encoding")?;
        let bytes = context.budget.snapshot(&tree).required("beta helper snapshot")?;
        let actual: serde_json::Value = serde_json::from_slice(&bytes).required("beta helper JSON")?;
        assert_eq!(
            actual,
            serde_json::json!({
                "additionalItems":{"type":"integer"}, "additionalProperties":false,
                "dependencies":{"array":["field"],"schema":{"type":"integer"}},
                "items":[{"type":"integer"},{"type":"integer"}]
            })
        );
        Ok(())
    }

    #[test]
    fn unchanged_encoded_prefix_does_not_skip_newly_unreferenced_nodes() -> TestResult {
        let mut arena = chain(SchemaFamily::V1, 2, 100)?;
        let owned = Arc::get_mut(&mut arena).required("exclusive prefix test arena")?;
        let root = owned.nodes.get_mut(owned.root).required("prefix root")?;
        root.fields.properties = Presence::Absent;
        root.fields.description = Presence::Absent;
        let context = encoding_context(ParseLimits {
            max_scalar_bytes: 50,
            ..ParseLimits::default()
        });
        assert_eq!(
            encode(&arena, SchemaFamily::V1, &context)
                .err()
                .required("unused earlier scalar still checked")?
                .code,
            FindingCode::LimitExceeded
        );
        Ok(())
    }

    #[test]
    fn repeated_output_occurrences_still_exhaust_node_event_and_scalar_limits() -> TestResult {
        let arena = fanout(12)?;
        for limits in [
            ParseLimits {
                max_nodes: 20,
                ..ParseLimits::default()
            },
            ParseLimits {
                max_events: 20,
                ..ParseLimits::default()
            },
        ] {
            let context = encoding_context(limits);
            let finding = encode(&arena, SchemaFamily::V1, &context)
                .err()
                .required("expanded output refuses")?;
            assert_eq!(finding.code, FindingCode::LimitExceeded);
        }
        let mut context = encoding_context(ParseLimits::default());
        let processing = context.budget.processing().clone();
        processing
            .payload(7, Phase::Generation)
            .required("prior shared operation charge")?;
        context.budget = crate::syntax::EncodingBudget::in_operation(
            crate::source::AuthoringLimits {
                max_total_snapshot_bytes: 1024,
                ..crate::source::AuthoringLimits::default()
            },
            processing,
        );
        assert_eq!(context.budget.processing().charged_payload_bytes(), 7);
        let finding = encode(&arena, SchemaFamily::V1, &context)
            .err()
            .required("expanded scalar occurrences exhaust aggregate allowance")?;
        assert_eq!(finding.code, FindingCode::LimitExceeded);

        let context = encoding_context(ParseLimits {
            max_input_bytes: 1024,
            ..ParseLimits::default()
        });
        let tree = encode(&arena, SchemaFamily::V1, &context)
            .required("per-snapshot limit does not lower construction scalar allowance")?;
        let finding = context
            .budget
            .snapshot(&tree)
            .err()
            .required("expanded serialized snapshot exceeds its own allowance")?;
        assert_eq!(finding.code, FindingCode::LimitExceeded);
        Ok(())
    }

    #[test]
    fn moved_subtrees_cannot_bypass_final_depth_or_scalar_shape_verification() -> TestResult {
        for family in [SchemaFamily::V1, SchemaFamily::V1beta1] {
            let arena = chain(family, 8, 100)?;
            let context = encoding_context(ParseLimits {
                max_depth: 4,
                ..ParseLimits::default()
            });
            let tree = encode(&arena, family, &context).required("moves do not rewalk child depth")?;
            assert_eq!(
                context
                    .budget
                    .verify(&tree)
                    .err()
                    .required("final actual depth refuses")?
                    .code,
                FindingCode::LimitExceeded
            );
            let context = encoding_context(ParseLimits {
                max_scalar_bytes: 50,
                ..ParseLimits::default()
            });
            assert_eq!(
                encode(&arena, family, &context)
                    .err()
                    .required("scalar still refuses")?
                    .code,
                FindingCode::LimitExceeded
            );
        }
        Ok(())
    }

    #[test]
    fn cache_and_use_count_buffers_and_scan_work_are_precharged_and_sticky() -> TestResult {
        let arena = fanout(2)?;
        for processing in [
            NativeProcessingLimits {
                max_payload_bytes: 2 * (size_of::<Option<TreeNode>>() + size_of::<usize>()) - 1,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_processing_units: 1,
                ..NativeProcessingLimits::default()
            },
        ] {
            let context = encoding_context(ParseLimits {
                processing,
                ..ParseLimits::default()
            });
            let finding = encode(&arena, SchemaFamily::V1, &context)
                .err()
                .required("cache preflight refuses")?;
            assert_eq!(finding.code, FindingCode::LimitExceeded);
            assert!(context.budget.processing().exhausted());
            assert_eq!(
                context
                    .budget
                    .processing()
                    .work(0, Phase::Generation)
                    .err()
                    .required("failure remains terminal")?
                    .code,
                FindingCode::LimitExceeded
            );
        }
        Ok(())
    }

    #[test]
    fn cache_precount_rejects_foreign_cross_family_future_and_out_of_range_handles() -> TestResult {
        for family in [SchemaFamily::V1, SchemaFamily::V1beta1] {
            for invalid_kind in 0..4 {
                let mut arena = chain(family, 2, 0)?;
                let owned = Arc::get_mut(&mut arena).required("exclusive test arena")?;
                let mut id = SchemaNodeId {
                    identity: owned.identity.clone(),
                    family,
                    index: 0,
                };
                match invalid_kind {
                    0 => id.identity = Arc::new(()),
                    1 => {
                        id.family = if family == SchemaFamily::V1 {
                            SchemaFamily::V1beta1
                        } else {
                            SchemaFamily::V1
                        }
                    }
                    2 => id.index = owned.root,
                    _ => id.index = usize::MAX,
                }
                let root = owned.nodes.get_mut(owned.root).required("root exists")?;
                root.fields.properties = Presence::Value(BTreeMap::from([("next".to_owned(), id)]));
                let context = EncodeContext::new(None);
                let finding = encode(&arena, family, &context)
                    .err()
                    .required("malformed reference refuses")?;
                assert_eq!(finding.code, FindingCode::NativeFieldInvalid);
            }
            let arena = chain(family, 1, 0)?;
            let other = if family == SchemaFamily::V1 {
                SchemaFamily::V1beta1
            } else {
                SchemaFamily::V1
            };
            let context = EncodeContext::new(None);
            assert_eq!(
                encode(&arena, other, &context)
                    .err()
                    .required("wrong served wrapper refuses")?
                    .code,
                FindingCode::NativeFieldInvalid
            );
        }
        Ok(())
    }
}
