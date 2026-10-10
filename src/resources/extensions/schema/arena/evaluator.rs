//! Bounded local subset compilation and checking for typed CRD schemas.
use super::{
    JSONSchemaPropsCrdV1, JSONSchemaPropsCrdV1beta1, SchemaArena, SchemaEvidenceOrigin, SchemaFamily, SchemaNodeId,
};
use crate::{
    capability::TargetProfile,
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    processing::NativeOperationBudget,
    registry::FieldDecodeContext,
    source::{EvidenceOrigin, ParseLimits, SourceEvidence},
    value::{Presence, ProtectedJsonValue},
};
use std::{cmp::Ordering, fmt, sync::Arc};

const EVALUATOR_VERSION: &str = "kubernetes-schema-subset-v1";

/// Supported local mathematical/schema violations. Paths and values remain private by default.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaIssueKind {
    /// A supplied value has a different JSON kind from the supported schema type.
    TypeMismatch,
    /// A required object property is absent.
    RequiredPropertyMissing,
    /// A supplied value does not equal any protected enum member.
    EnumMismatch,
    /// An exact number is below its inclusive/exclusive lower bound.
    MinimumViolation,
    /// An exact number is above its inclusive/exclusive upper bound.
    MaximumViolation,
    /// A string is shorter than the configured Unicode-scalar lower bound.
    MinimumLengthViolation,
    /// A string is longer than the configured Unicode-scalar upper bound.
    MaximumLengthViolation,
    /// An object property is excluded by `additionalProperties` false.
    AdditionalPropertyRejected,
}

/// Fixed unsupported-schema category; no schema keyword payload is disclosed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SchemaUnsupported {
    /// General composition and negation.
    Combinator,
    /// Schema dependencies and required-name dependencies.
    Dependencies,
    /// Definitions are retained but not evaluated as references.
    Definitions,
    /// Pattern properties are not evaluated.
    PatternProperties,
    /// Regex pattern constraints are not evaluated.
    Pattern,
    /// Format annotations do not imply validation.
    Format,
    /// Multiple-of numeric constraints are not evaluated.
    MultipleOf,
    /// Array/object cardinality and uniqueness are not evaluated.
    Cardinality,
    /// Tuple-form items and `additionalItems` are not evaluated.
    TupleItems,
    /// A type name is outside the local checker vocabulary.
    UnknownType,
    /// The `IntOrString` extension is not interpreted.
    IntOrString,
    /// Embedded Kubernetes resources need native structural schema handling.
    EmbeddedResource,
    /// Kubernetes list merge topology is retained but not interpreted locally.
    ListTopology,
    /// Kubernetes map merge topology is retained but not interpreted locally.
    MapTopology,
    /// Server-side unknown-field transformation is an expectation, not local pruning.
    PreserveUnknownTransform,
    /// A retained schema reference is not fetched or expanded.
    SchemaReference,
    /// A retained default is not applied.
    Defaulting,
    /// CEL validation expressions are not executed.
    CelValidation,
    /// A retained schema keyword has no typed local interpretation.
    UnknownSchemaField,
}

/// One private-path local subset issue.
#[derive(Clone)]
pub struct SchemaCheckIssue {
    kind: SchemaIssueKind,
    path: FieldPath,
}
impl SchemaCheckIssue {
    /// Return the fixed, payload-free issue category.
    #[must_use]
    pub const fn kind(&self) -> SchemaIssueKind {
        self.kind
    }
    /// Reveal the exact custom-resource path only with explicit access.
    #[must_use]
    pub fn path(&self, access: &crate::source::ExplicitSourceAccess) -> String {
        self.path.reveal(access)
    }
}
impl fmt::Debug for SchemaCheckIssue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaCheckIssue")
            .field("kind", &self.kind)
            .field("path", &"<private>")
            .finish()
    }
}

#[derive(Clone)]
struct UnsupportedAt {
    kind: SchemaUnsupported,
    path: FieldPath,
}

/// Local report; supported-subset satisfaction does not claim Kubernetes validity or admission.
pub struct SchemaCheckReport {
    target: TargetProfile,
    evaluator_version: &'static str,
    schema: Arc<SchemaArena>,
    schema_evidence: SchemaEvidenceOrigin,
    document_evidence: Option<SourceEvidence>,
    document_pointer: FieldPath,
    issues: Vec<SchemaCheckIssue>,
    unsupported: Vec<UnsupportedAt>,
    numeric_semantics_uncertain: bool,
    incomplete: bool,
    limit_exceeded: bool,
}
impl fmt::Debug for SchemaCheckReport {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SchemaCheckReport")
            .field("target", &self.target)
            .field("evaluator_version", &self.evaluator_version)
            .field("issue_count", &self.issues.len())
            .field("unsupported_count", &self.unsupported.len())
            .field("schema_node_count", &self.schema.nodes.len())
            .field("document_evidence_present", &self.document_evidence.is_some())
            .field("schema_pointer_depth", &schema_pointer_depth(&self.schema_evidence))
            .field("document_pointer_depth", &self.document_pointer.depth())
            .field("numeric_semantics_uncertain", &self.numeric_semantics_uncertain)
            .field("incomplete", &self.incomplete)
            .field("limit_exceeded", &self.limit_exceeded)
            .finish_non_exhaustive()
    }
}
impl SchemaCheckReport {
    /// The complete target profile to which this report is bound.
    #[must_use]
    pub const fn target(&self) -> &TargetProfile {
        &self.target
    }
    /// Stable identifier for evaluator behavior.
    #[must_use]
    pub const fn evaluator_version(&self) -> &'static str {
        self.evaluator_version
    }
    /// Whether all supported local checks completed without a violation.
    #[must_use]
    pub fn supported_subset_satisfied(&self) -> bool {
        self.issues.is_empty() && !self.limit_exceeded && !self.incomplete
    }
    /// Fixed-category local issues with paths hidden unless explicitly revealed.
    #[must_use]
    pub fn issues(&self) -> &[SchemaCheckIssue] {
        &self.issues
    }
    /// Number of unsupported schema constructs retained in this report.
    #[must_use]
    pub fn unsupported_count(&self) -> usize {
        self.unsupported.len()
    }
    /// Return the category at the requested index without copying private paths.
    #[must_use]
    pub fn unsupported_kind(&self, index: usize) -> Option<SchemaUnsupported> {
        self.unsupported.get(index).map(|item| item.kind)
    }
    /// Reveal a schema pointer only with explicit access.
    #[must_use]
    pub fn unsupported_path(&self, index: usize, access: &crate::source::ExplicitSourceAccess) -> Option<String> {
        self.unsupported.get(index).map(|item| item.path.reveal(access))
    }
    /// Whether mathematical checks may differ from Kubernetes double-number semantics.
    #[must_use]
    pub const fn numeric_semantics_uncertain(&self) -> bool {
        self.numeric_semantics_uncertain
    }
    /// Whether source evidence/context was unavailable or incomplete.
    #[must_use]
    pub const fn incomplete(&self) -> bool {
        self.incomplete
    }
    /// Whether a sticky processing/report limit prevented completion.
    #[must_use]
    pub const fn limit_exceeded(&self) -> bool {
        self.limit_exceeded
    }
}

/// Immutable schema compilation bound to one exact arena and complete target profile.
pub struct CompiledSchemaPlan {
    arena: Arc<SchemaArena>,
    target: TargetProfile,
    evaluator_version: &'static str,
    limits: ParseLimits,
    unsupported: Vec<UnsupportedAt>,
    numeric_semantics_uncertain: bool,
}
impl fmt::Debug for CompiledSchemaPlan {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("CompiledSchemaPlan")
            .field("target", &self.target)
            .field("evaluator_version", &self.evaluator_version)
            .field("schema_node_count", &self.arena.nodes.len())
            .field("unsupported_count", &self.unsupported.len())
            .finish_non_exhaustive()
    }
}
impl CompiledSchemaPlan {
    /// Target profile to which this immutable plan is bound.
    #[must_use]
    pub const fn target(&self) -> &TargetProfile {
        &self.target
    }
    /// Evaluator identifier retained in derived reports.
    #[must_use]
    pub const fn evaluator_version(&self) -> &'static str {
        self.evaluator_version
    }

    /// Check a core-decoded document while inheriting actual source context and limits.
    /// This remains crate-private until custom-resource evidence is integrated by the core.
    pub(crate) fn check_inherited(
        &self,
        document: &ProtectedJsonValue,
        context: &FieldDecodeContext,
        document_pointer: &FieldPath,
    ) -> Result<SchemaCheckReport, Finding> {
        // The value was decoded under this source-bound context; the shared protected-value
        // API intentionally does not expose its private retained limits.
        let limits = lowered_limits(self.limits, context.limits, context.limits);
        // Preserve the caller's operation counters. Constructing a new budget here used to
        // erase work already charged while decoding the CRD and custom document.
        let processing = context.processing.clone();
        let schema_source_supplied = matches!(
            &self.arena.evidence,
            SchemaEvidenceOrigin::Decoded { source, .. } if !matches!(source.origin, EvidenceOrigin::NativeAuthored)
        );
        let document_source_supplied = context
            .source_evidence()
            .is_some_and(|source| !matches!(source.origin, EvidenceOrigin::NativeAuthored));
        let complete_evidence = schema_source_supplied && document_source_supplied;
        let mut report = SchemaCheckReport {
            target: self.target.clone(),
            evaluator_version: self.evaluator_version,
            schema: self.arena.clone(),
            schema_evidence: self.arena.evidence.clone(),
            document_evidence: context.source_evidence().cloned(),
            document_pointer: document_pointer.clone(),
            issues: Vec::new(),
            unsupported: Vec::new(),
            numeric_semantics_uncertain: self.numeric_semantics_uncertain,
            incomplete: !complete_evidence,
            limit_exceeded: false,
        };
        report.unsupported = match copy_unsupported(&self.unsupported, &processing, context.phase) {
            Ok(unsupported) => unsupported,
            Err(finding) if finding.code == FindingCode::LimitExceeded => {
                report.limit_exceeded = true;
                return Ok(report);
            }
            Err(finding) => return Err(finding),
        };
        if context.source_evidence().is_none() {
            return Ok(report);
        }
        let mut pending = Vec::new();
        if processing.payload_array::<EvalStep>(1, Phase::Analysis).is_err() {
            report.limit_exceeded = true;
            return Ok(report);
        }
        pending.push(EvalStep {
            schema: self.arena.root,
            value: document.root(),
            schema_path: FieldPath::default(),
            value_path: document_pointer.clone(),
            depth: 0,
        });
        let mut expanded = 0usize;
        while let Some(step) = pending.pop() {
            if let Err(finding) = processing.work(1, Phase::Analysis) {
                report.limit_exceeded = finding.code == FindingCode::LimitExceeded;
                break;
            }
            expanded = expanded.saturating_add(1);
            if expanded > limits.max_nodes || expanded > limits.max_events {
                report.limit_exceeded = true;
                break;
            }
            let schema_node = self
                .arena
                .nodes
                .get(step.schema)
                .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?;
            let json_value = document
                .node(step.value)
                .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?;
            match eval_node(
                &schema_node.fields,
                document,
                json_value,
                &step,
                &mut pending,
                &mut report,
                &EvaluationContext {
                    family: self.arena.family,
                    limits,
                    processing: &processing,
                },
            ) {
                Ok(()) => {}
                Err(finding) if finding.code == FindingCode::LimitExceeded => {
                    report.limit_exceeded = true;
                    break;
                }
                Err(finding) => return Err(finding),
            }
        }
        Ok(report)
    }
}

impl JSONSchemaPropsCrdV1 {
    /// Compile this exact stable schema with a complete, validated target profile.
    /// # Errors
    /// Rejects incomplete source evidence, invalid target profiles, or exhausted limits.
    pub fn compile(&self, target: &TargetProfile) -> Result<CompiledSchemaPlan, Finding> {
        compile(&self.0, SchemaFamily::V1, target)
    }
    pub(crate) fn compile_inherited(
        &self,
        target: &TargetProfile,
        context: &FieldDecodeContext,
    ) -> Result<CompiledSchemaPlan, Finding> {
        compile_inherited(&self.0, SchemaFamily::V1, target, context)
    }
}
impl JSONSchemaPropsCrdV1beta1 {
    /// Compile this exact historical beta schema with a complete, validated target profile.
    /// # Errors
    /// Rejects incomplete source evidence, invalid target profiles, or exhausted limits.
    pub fn compile(&self, target: &TargetProfile) -> Result<CompiledSchemaPlan, Finding> {
        compile(&self.0, SchemaFamily::V1beta1, target)
    }
    pub(crate) fn compile_inherited(
        &self,
        target: &TargetProfile,
        context: &FieldDecodeContext,
    ) -> Result<CompiledSchemaPlan, Finding> {
        compile_inherited(&self.0, SchemaFamily::V1beta1, target, context)
    }
}

fn compile(
    arena: &Arc<SchemaArena>,
    family: SchemaFamily,
    target: &TargetProfile,
) -> Result<CompiledSchemaPlan, Finding> {
    compile_inner(arena, family, target, None)
}

fn compile_inherited(
    arena: &Arc<SchemaArena>,
    family: SchemaFamily,
    target: &TargetProfile,
    context: &FieldDecodeContext,
) -> Result<CompiledSchemaPlan, Finding> {
    compile_inner(arena, family, target, Some(context))
}

fn collect_unsupported(
    node: &super::SchemaNode,
    path: &FieldPath,
    processing: &NativeOperationBudget,
    unsupported: &mut Vec<UnsupportedAt>,
) -> Result<(), Finding> {
    let fields = &node.fields;
    let mut mark = |condition: bool, keyword: &str, kind: SchemaUnsupported| -> Result<(), Finding> {
        if condition {
            processing.work(1, Phase::Analysis)?;
            processing.payload_array::<UnsupportedAt>(1, Phase::Analysis)?;
            processing.payload_array::<String>(path.0.len().saturating_add(1), Phase::Analysis)?;
            for part in &path.0 {
                processing.payload(part.len(), Phase::Analysis)?;
            }
            processing.payload(keyword.len(), Phase::Analysis)?;
            unsupported
                .try_reserve(1)
                .map_err(|_| processing.fail(Phase::Analysis))?;
            unsupported.push(UnsupportedAt {
                kind,
                path: path.clone().child(keyword),
            });
        }
        Ok(())
    };
    for (condition, keyword, kind) in scalar_unsupported(fields)
        .into_iter()
        .chain(structural_unsupported(fields))
    {
        mark(condition, keyword, kind)?;
    }
    for (key, _) in &node.unknown.entries {
        let kind = match key.as_str() {
            "$ref" => SchemaUnsupported::SchemaReference,
            "default" => SchemaUnsupported::Defaulting,
            "x-kubernetes-validations" => SchemaUnsupported::CelValidation,
            _ => SchemaUnsupported::UnknownSchemaField,
        };
        mark(true, key, kind)?;
    }
    if matches!(&fields.type_name, Presence::Value(name) if !matches!(name.as_str(), "null" | "boolean" | "object" | "array" | "number" | "integer" | "string"))
    {
        mark(true, "type", SchemaUnsupported::UnknownType)?;
    }
    Ok(())
}

fn compile_inner(
    arena: &Arc<SchemaArena>,
    family: SchemaFamily,
    target: &TargetProfile,
    context: Option<&FieldDecodeContext>,
) -> Result<CompiledSchemaPlan, Finding> {
    if arena.family != family || arena.root >= arena.nodes.len() {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis));
    }
    if !target.findings().is_empty() {
        return Err(Finding::error(FindingCode::InvalidTargetProfile, Phase::Analysis));
    }
    if matches!(arena.evidence, SchemaEvidenceOrigin::Incomplete) {
        return Err(Finding::error(FindingCode::NativeContextRequired, Phase::Analysis));
    }
    let limits = context.map_or(arena.limits, |context| {
        lowered_limits(arena.limits, context.limits, arena.limits)
    });
    let processing = context.map_or_else(
        || NativeOperationBudget::new(limits.processing),
        |context| context.processing.clone(),
    );
    let mut unsupported = Vec::new();
    let mut pending = Vec::new();
    processing.payload_array::<(usize, FieldPath, usize)>(1, Phase::Analysis)?;
    pending.try_reserve(1).map_err(|_| processing.fail(Phase::Analysis))?;
    let root_pointer = match &arena.evidence {
        SchemaEvidenceOrigin::Decoded { pointer, .. } | SchemaEvidenceOrigin::NativeAuthored { pointer } => {
            pointer.clone()
        }
        SchemaEvidenceOrigin::Incomplete => FieldPath::default(),
    };
    pending.push((arena.root, root_pointer, 0usize));
    let mut numeric_semantics_uncertain = false;
    let mut expanded = 0usize;
    while let Some((index, path, depth)) = pending.pop() {
        processing.work(1, Phase::Analysis)?;
        expanded = expanded
            .checked_add(1)
            .ok_or_else(|| processing.fail(Phase::Analysis))?;
        if depth > limits.max_depth || expanded > limits.max_nodes || expanded > limits.max_events {
            return Err(processing.fail(Phase::Analysis));
        }
        let node = arena
            .nodes
            .get(index)
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis))?;
        let fields = &node.fields;
        if matches!(&fields.minimum, Presence::Value(_))
            || matches!(&fields.maximum, Presence::Value(_))
            || matches!(&fields.type_name, Presence::Value(name) if name == "integer" || name == "number")
        {
            numeric_semantics_uncertain = true;
        }
        collect_unsupported(node, &path, &processing, &mut unsupported)?;
        let children = schema_children(fields, &path, &processing)?;
        processing.payload_array::<(usize, FieldPath, usize)>(children.len(), Phase::Analysis)?;
        pending
            .try_reserve(children.len())
            .map_err(|_| processing.fail(Phase::Analysis))?;
        for (id, child_path) in children.into_iter().rev() {
            if id.family != family || id.index >= arena.nodes.len() || !Arc::ptr_eq(&id.identity, &arena.identity) {
                return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis));
            }
            pending.push((
                id.index,
                child_path,
                depth.checked_add(1).ok_or_else(|| processing.fail(Phase::Analysis))?,
            ));
        }
    }
    Ok(CompiledSchemaPlan {
        arena: arena.clone(),
        target: target.clone(),
        evaluator_version: EVALUATOR_VERSION,
        limits,
        unsupported,
        numeric_semantics_uncertain,
    })
}

fn present<T>(value: &Presence<T>) -> bool {
    matches!(value, Presence::Value(_))
}
fn schema_children(
    fields: &super::SchemaFields,
    base: &FieldPath,
    processing: &NativeOperationBudget,
) -> Result<Vec<(SchemaNodeId, FieldPath)>, Finding> {
    let mut out = Vec::new();
    let mut add = |id: &SchemaNodeId, path: FieldPath| -> Result<(), Finding> {
        processing.work(1, Phase::Analysis)?;
        processing.payload_array::<(SchemaNodeId, FieldPath)>(1, Phase::Analysis)?;
        processing.payload_array::<String>(path.0.len(), Phase::Analysis)?;
        for segment in &path.0 {
            processing.payload(segment.len(), Phase::Analysis)?;
        }
        out.try_reserve(1).map_err(|_| processing.fail(Phase::Analysis))?;
        out.push((id.clone(), path));
        Ok(())
    };
    for (wire, values) in [
        ("allOf", &fields.all_of),
        ("anyOf", &fields.any_of),
        ("oneOf", &fields.one_of),
    ] {
        if let Presence::Value(children) = values {
            for (i, id) in children.iter().enumerate() {
                add(id, base.child(wire).child(i.to_string()))?;
            }
        }
    }
    for (wire, values) in [
        ("definitions", &fields.definitions),
        ("patternProperties", &fields.pattern_properties),
        ("properties", &fields.properties),
    ] {
        if let Presence::Value(children) = values {
            for (name, id) in children {
                add(id, base.child(wire).child(name.clone()))?;
            }
        }
    }
    if let Presence::Value(id) = &fields.not {
        add(id, base.child("not"))?;
    }
    if let Presence::Value(super::JSONSchemaPropsOrBoolCrdV1::Schema(id)) = &fields.additional_properties {
        add(id, base.child("additionalProperties"))?;
    }
    if let Presence::Value(items) = &fields.items {
        match items {
            super::JSONSchemaPropsOrArrayCrdV1::Schema(id) => add(id, base.child("items"))?,
            super::JSONSchemaPropsOrArrayCrdV1::Array(ids) => {
                for (i, id) in ids.iter().enumerate() {
                    add(id, base.child("items").child(i.to_string()))?;
                }
            }
        }
    }
    if let Presence::Value(super::JSONSchemaPropsOrBoolCrdV1::Schema(id)) = &fields.additional_items {
        add(id, base.child("additionalItems"))?;
    }
    if let Presence::Value(dependencies) = &fields.dependencies {
        for (name, value) in dependencies {
            if let super::JSONSchemaPropsOrStringArrayCrdV1::Schema(id) = value {
                add(id, base.child("dependencies").child(name.clone()))?;
            }
        }
    }
    Ok(out)
}

struct EvalStep {
    schema: usize,
    value: usize,
    schema_path: FieldPath,
    value_path: FieldPath,
    depth: usize,
}
struct EvaluationContext<'a> {
    family: SchemaFamily,
    limits: ParseLimits,
    processing: &'a NativeOperationBudget,
}

fn emit_issue(
    report: &mut SchemaCheckReport,
    processing: &NativeOperationBudget,
    kind: SchemaIssueKind,
    path: &FieldPath,
) -> Result<(), Finding> {
    processing.work(1, Phase::Analysis)?;
    processing.report(
        &Finding::warning(FindingCode::NativeContextRequired, Phase::Analysis).at_path(path.clone()),
        Phase::Analysis,
    )?;
    processing.payload_array::<SchemaCheckIssue>(1, Phase::Analysis)?;
    processing.payload_array::<String>(path.0.len(), Phase::Analysis)?;
    for part in &path.0 {
        processing.payload(part.len(), Phase::Analysis)?;
    }
    report
        .issues
        .try_reserve(1)
        .map_err(|_| processing.fail(Phase::Analysis))?;
    report.issues.push(SchemaCheckIssue {
        kind,
        path: path.clone(),
    });
    Ok(())
}
fn eval_scalar(
    fields: &super::SchemaFields,
    document: &ProtectedJsonValue,
    value: &crate::value::protected_json::JsonNode,
    step: &EvalStep,
    context: &EvaluationContext<'_>,
    report: &mut SchemaCheckReport,
) -> Result<(), Finding> {
    use crate::value::protected_json::JsonNode;
    let processing = context.processing;
    let mut issue = |kind, path: &FieldPath| emit_issue(report, processing, kind, path);
    let is_null = matches!(value, JsonNode::Null);
    let nullable = matches!(&fields.nullable, Presence::Value(true));
    if let Presence::Value(expected) = &fields.type_name {
        if !(matches_type(expected, value) || is_null && nullable) {
            issue(SchemaIssueKind::TypeMismatch, &step.value_path)?;
        }
    }
    if let Presence::Value(values) = &fields.enum_values {
        let mut matched = false;
        for expected in values {
            if equivalent_at(&expected.0, expected.0.root(), document, step.value, processing)? {
                matched = true;
                break;
            }
        }
        if !matched {
            issue(SchemaIssueKind::EnumMismatch, &step.value_path)?;
        }
    }
    if let JsonNode::Number(number) = value {
        if let Presence::Value(minimum) = &fields.minimum {
            let order = number.compare_in(minimum, processing, Phase::Analysis)?;
            let exclusive = matches!(&fields.exclusive_minimum, Presence::Value(true));
            if order == Ordering::Less || (exclusive && order == Ordering::Equal) {
                issue(SchemaIssueKind::MinimumViolation, &step.value_path)?;
            }
        }
        if let Presence::Value(maximum) = &fields.maximum {
            let order = number.compare_in(maximum, processing, Phase::Analysis)?;
            let exclusive = matches!(&fields.exclusive_maximum, Presence::Value(true));
            if order == Ordering::Greater || (exclusive && order == Ordering::Equal) {
                issue(SchemaIssueKind::MaximumViolation, &step.value_path)?;
            }
        }
    }
    if let JsonNode::String(text) = value {
        processing.work(text.len(), Phase::Analysis)?;
        let length = i128::try_from(text.chars().count()).unwrap_or(i128::MAX);
        if matches!(&fields.min_length, Presence::Value(bound) if length < i128::from(*bound)) {
            issue(SchemaIssueKind::MinimumLengthViolation, &step.value_path)?;
        }
        if matches!(&fields.max_length, Presence::Value(bound) if length > i128::from(*bound)) {
            issue(SchemaIssueKind::MaximumLengthViolation, &step.value_path)?;
        }
    }
    Ok(())
}
fn eval_node(
    fields: &super::SchemaFields,
    document: &ProtectedJsonValue,
    value: &crate::value::protected_json::JsonNode,
    step: &EvalStep,
    pending: &mut Vec<EvalStep>,
    report: &mut SchemaCheckReport,
    context: &EvaluationContext<'_>,
) -> Result<(), Finding> {
    use crate::value::protected_json::JsonNode;
    let processing = context.processing;
    eval_scalar(fields, document, value, step, context, report)?;
    let mut issue = |kind, path: &FieldPath| emit_issue(report, processing, kind, path);
    if let JsonNode::Object(entries) = value {
        if let Presence::Value(required) = &fields.required {
            for name in required {
                let scan_cost = entries
                    .iter()
                    .try_fold(name.len(), |total, (key, _)| {
                        total.checked_add(key.len().saturating_add(1))
                    })
                    .ok_or_else(|| processing.fail(Phase::Analysis))?;
                processing.work(scan_cost, Phase::Analysis)?;
                if !entries.iter().any(|(key, _)| key == name) {
                    issue(
                        SchemaIssueKind::RequiredPropertyMissing,
                        &step.value_path.child(name.clone()),
                    )?;
                }
            }
        }
        for (name, child) in entries {
            processing.work(name.len().saturating_add(1), Phase::Analysis)?;
            let property_schema = match &fields.properties {
                Presence::Value(properties) => properties.get(name),
                _ => None,
            };
            if let Some(schema) = property_schema {
                enqueue_eval(
                    pending,
                    schema,
                    *child,
                    &step.schema_path.child("properties").child(name.clone()),
                    &step.value_path.child(name.clone()),
                    step.depth,
                    context,
                )?;
            } else if let Presence::Value(rule) = &fields.additional_properties {
                match rule {
                    super::JSONSchemaPropsOrBoolCrdV1::Bool(false) => issue(
                        SchemaIssueKind::AdditionalPropertyRejected,
                        &step.value_path.child(name.clone()),
                    )?,
                    super::JSONSchemaPropsOrBoolCrdV1::Schema(schema) => enqueue_eval(
                        pending,
                        schema,
                        *child,
                        &step.schema_path.child("additionalProperties"),
                        &step.value_path.child(name.clone()),
                        step.depth,
                        context,
                    )?,
                    super::JSONSchemaPropsOrBoolCrdV1::Bool(true) => {}
                }
            }
        }
    }
    if let JsonNode::Array(items) = value {
        if let Presence::Value(super::JSONSchemaPropsOrArrayCrdV1::Schema(schema)) = &fields.items {
            for (index, child) in items.iter().enumerate() {
                enqueue_eval(
                    pending,
                    schema,
                    *child,
                    &step.schema_path.child("items"),
                    &step.value_path.child(index.to_string()),
                    step.depth,
                    context,
                )?;
            }
        }
    }
    Ok(())
}

fn schema_pointer_depth(evidence: &SchemaEvidenceOrigin) -> usize {
    match evidence {
        SchemaEvidenceOrigin::Decoded { pointer, .. } | SchemaEvidenceOrigin::NativeAuthored { pointer } => {
            pointer.depth()
        }
        SchemaEvidenceOrigin::Incomplete => 0,
    }
}

fn equivalent_at(
    left: &ProtectedJsonValue,
    left_root: usize,
    right: &ProtectedJsonValue,
    right_root: usize,
    processing: &NativeOperationBudget,
) -> Result<bool, Finding> {
    use crate::value::protected_json::JsonNode;
    let mut pending = Vec::new();
    processing.payload_array::<(usize, usize)>(1, Phase::Analysis)?;
    pending.try_reserve(1).map_err(|_| processing.fail(Phase::Analysis))?;
    pending.push((left_root, right_root));
    while let Some((a, b)) = pending.pop() {
        processing.work(1, Phase::Analysis)?;
        match (left.node(a), right.node(b)) {
            (Some(JsonNode::Null), Some(JsonNode::Null)) => {}
            (Some(JsonNode::Boolean(a)), Some(JsonNode::Boolean(b))) if a == b => {}
            (Some(JsonNode::Number(a)), Some(JsonNode::Number(b)))
                if a.compare_in(b, processing, Phase::Analysis)? == Ordering::Equal => {}
            (Some(JsonNode::String(a)), Some(JsonNode::String(b))) => {
                processing.work(a.len().saturating_add(b.len()), Phase::Analysis)?;
                if a != b {
                    return Ok(false);
                }
            }
            (Some(JsonNode::Array(a)), Some(JsonNode::Array(b))) if a.len() == b.len() => {
                processing.payload_array::<(usize, usize)>(a.len(), Phase::Analysis)?;
                pending
                    .try_reserve(a.len())
                    .map_err(|_| processing.fail(Phase::Analysis))?;
                for (a, b) in a.iter().zip(b) {
                    pending.push((*a, *b));
                }
            }
            (Some(JsonNode::Object(a)), Some(JsonNode::Object(b))) if a.len() == b.len() => {
                processing.payload_array::<(usize, usize)>(a.len(), Phase::Analysis)?;
                pending
                    .try_reserve(a.len())
                    .map_err(|_| processing.fail(Phase::Analysis))?;
                for (left_key, left_value) in a {
                    let mut matched = None;
                    for (right_key, right_value) in b {
                        processing.work(left_key.len().saturating_add(right_key.len()), Phase::Analysis)?;
                        if left_key == right_key {
                            matched = Some(*right_value);
                            break;
                        }
                    }
                    let Some(right_value) = matched else { return Ok(false) };
                    pending.push((*left_value, right_value));
                }
            }
            _ => return Ok(false),
        }
    }
    Ok(true)
}

fn enqueue_eval(
    pending: &mut Vec<EvalStep>,
    id: &SchemaNodeId,
    value: usize,
    schema_path: &FieldPath,
    value_path: &FieldPath,
    depth: usize,
    context: &EvaluationContext<'_>,
) -> Result<(), Finding> {
    let EvaluationContext {
        family,
        limits,
        processing,
    } = context;
    processing.work(1, Phase::Analysis)?;
    if id.family != *family {
        return Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Analysis));
    }
    let next_depth = depth.checked_add(1).ok_or_else(|| processing.fail(Phase::Analysis))?;
    if next_depth > limits.max_depth {
        return Err(processing.fail(Phase::Analysis));
    }
    processing.payload_array::<EvalStep>(1, Phase::Analysis)?;
    for path in [schema_path, value_path] {
        processing.payload_array::<String>(path.0.len(), Phase::Analysis)?;
        for segment in &path.0 {
            processing.payload(segment.len(), Phase::Analysis)?;
        }
    }
    pending.try_reserve(1).map_err(|_| processing.fail(Phase::Analysis))?;
    pending.push(EvalStep {
        schema: id.index,
        value,
        schema_path: schema_path.clone(),
        value_path: value_path.clone(),
        depth: next_depth,
    });
    Ok(())
}

fn matches_type(expected: &str, value: &crate::value::protected_json::JsonNode) -> bool {
    use crate::value::protected_json::JsonNode;
    match expected {
        "null" => matches!(value, JsonNode::Null),
        "boolean" => matches!(value, JsonNode::Boolean(_)),
        "object" => matches!(value, JsonNode::Object(_)),
        "array" => matches!(value, JsonNode::Array(_)),
        "number" => matches!(value, JsonNode::Number(_)),
        "integer" => matches!(value, JsonNode::Number(number) if number_is_integral(number)),
        "string" => matches!(value, JsonNode::String(_)),
        _ => true,
    }
}

fn number_is_integral(number: &crate::value::ExactJsonNumber) -> bool {
    let lexeme = number.native_lexeme();
    let (mantissa, exponent) = lexeme.find(['e', 'E']).map_or((lexeme, 0_i64), |index| {
        let exponent = lexeme[index + 1..].parse::<i64>().unwrap_or(i64::MAX);
        (&lexeme[..index], exponent)
    });
    if exponent == i64::MAX {
        return false;
    }
    let mantissa = mantissa.strip_prefix('-').unwrap_or(mantissa);
    let fraction_len = mantissa.split_once('.').map_or(0, |(_, fraction)| fraction.len());
    if mantissa.bytes().all(|byte| matches!(byte, b'0' | b'.')) {
        return true;
    }
    let scale = i64::try_from(fraction_len)
        .ok()
        .and_then(|fraction| fraction.checked_sub(exponent));
    let Some(scale) = scale else {
        return false;
    };
    if scale <= 0 {
        return true;
    }
    let trailing_zeroes = mantissa.bytes().rev().take_while(|byte| *byte == b'0').count();
    usize::try_from(scale).is_ok_and(|scale| trailing_zeroes >= scale)
}

fn lowered_limits(a: ParseLimits, b: ParseLimits, c: ParseLimits) -> ParseLimits {
    let mut limits = a;
    limits.processing = a.processing.lowered_by(b.processing).lowered_by(c.processing);
    limits.max_input_bytes = a.max_input_bytes.min(b.max_input_bytes).min(c.max_input_bytes);
    limits.max_documents = a.max_documents.min(b.max_documents).min(c.max_documents);
    limits.max_events = a.max_events.min(b.max_events).min(c.max_events);
    limits.max_nodes = a.max_nodes.min(b.max_nodes).min(c.max_nodes);
    limits.max_depth = a.max_depth.min(b.max_depth).min(c.max_depth);
    limits.max_scalar_bytes = a.max_scalar_bytes.min(b.max_scalar_bytes).min(c.max_scalar_bytes);
    limits.max_aliases = a.max_aliases.min(b.max_aliases).min(c.max_aliases);
    limits.max_alias_visits = a.max_alias_visits.min(b.max_alias_visits).min(c.max_alias_visits);
    limits
}
fn copy_unsupported(
    values: &[UnsupportedAt],
    processing: &NativeOperationBudget,
    phase: Phase,
) -> Result<Vec<UnsupportedAt>, Finding> {
    processing.payload_array::<UnsupportedAt>(values.len(), phase)?;
    let mut copied = Vec::new();
    copied.try_reserve(values.len()).map_err(|_| processing.fail(phase))?;
    for value in values {
        processing.work(1, phase)?;
        processing.report(
            &Finding::warning(FindingCode::NativeContextRequired, phase).at_path(value.path.clone()),
            phase,
        )?;
        processing.payload_array::<String>(value.path.0.len(), phase)?;
        for segment in &value.path.0 {
            processing.payload(segment.len(), phase)?;
        }
        copied.push(value.clone());
    }
    Ok(copied)
}

fn scalar_unsupported(fields: &super::SchemaFields) -> [(bool, &'static str, SchemaUnsupported); 10] {
    [
        (present(&fields.all_of), "allOf", SchemaUnsupported::Combinator),
        (present(&fields.any_of), "anyOf", SchemaUnsupported::Combinator),
        (present(&fields.one_of), "oneOf", SchemaUnsupported::Combinator),
        (present(&fields.not), "not", SchemaUnsupported::Combinator),
        (
            present(&fields.dependencies),
            "dependencies",
            SchemaUnsupported::Dependencies,
        ),
        (
            present(&fields.definitions),
            "definitions",
            SchemaUnsupported::Definitions,
        ),
        (
            present(&fields.pattern_properties),
            "patternProperties",
            SchemaUnsupported::PatternProperties,
        ),
        (present(&fields.pattern), "pattern", SchemaUnsupported::Pattern),
        (present(&fields.format), "format", SchemaUnsupported::Format),
        (
            present(&fields.multiple_of),
            "multipleOf",
            SchemaUnsupported::MultipleOf,
        ),
    ]
}

fn structural_unsupported(fields: &super::SchemaFields) -> [(bool, &'static str, SchemaUnsupported); 13] {
    [
        (present(&fields.max_items), "maxItems", SchemaUnsupported::Cardinality),
        (present(&fields.min_items), "minItems", SchemaUnsupported::Cardinality),
        (
            present(&fields.max_properties),
            "maxProperties",
            SchemaUnsupported::Cardinality,
        ),
        (
            present(&fields.min_properties),
            "minProperties",
            SchemaUnsupported::Cardinality,
        ),
        (
            present(&fields.unique_items),
            "uniqueItems",
            SchemaUnsupported::Cardinality,
        ),
        (
            present(&fields.additional_items),
            "additionalItems",
            SchemaUnsupported::TupleItems,
        ),
        (
            matches!(
                &fields.items,
                Presence::Value(super::JSONSchemaPropsOrArrayCrdV1::Array(_))
            ),
            "items",
            SchemaUnsupported::TupleItems,
        ),
        (
            matches!(&fields.x_kubernetes_int_or_string, Presence::Value(true)),
            "x-kubernetes-int-or-string",
            SchemaUnsupported::IntOrString,
        ),
        (
            matches!(&fields.x_kubernetes_embedded_resource, Presence::Value(true)),
            "x-kubernetes-embedded-resource",
            SchemaUnsupported::EmbeddedResource,
        ),
        (
            present(&fields.x_kubernetes_list_map_keys),
            "x-kubernetes-list-map-keys",
            SchemaUnsupported::ListTopology,
        ),
        (
            present(&fields.x_kubernetes_list_type),
            "x-kubernetes-list-type",
            SchemaUnsupported::ListTopology,
        ),
        (
            present(&fields.x_kubernetes_map_type),
            "x-kubernetes-map-type",
            SchemaUnsupported::MapTopology,
        ),
        (
            matches!(&fields.x_kubernetes_preserve_unknown_fields, Presence::Value(true)),
            "x-kubernetes-preserve-unknown-fields",
            SchemaUnsupported::PreserveUnknownTransform,
        ),
    ]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resources::extensions::test_support::{TestRequired, TestResult};
    use crate::{
        capability::KubernetesVersion,
        diagnostic::FieldPath,
        processing::NativeOperationBudget,
        source::{DocumentFormat, InputOrigin, SourceEvidence, SourceId, SourceInput},
        value::Presence,
    };
    use std::collections::BTreeMap;

    fn test_context(bytes: &[u8]) -> FieldDecodeContext {
        let limits = ParseLimits::default();
        let source = SourceEvidence::from_input(&SourceInput {
            id: SourceId(41),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes,
        });
        FieldDecodeContext::new(limits, NativeOperationBudget::new(limits.processing), Phase::Analysis)
            .with_evidence(&source)
    }

    #[test]
    fn supported_failures_survive_unsupported_constructs_and_hide_private_paths() -> TestResult {
        let limits = ParseLimits::default();
        let mut builder = super::super::SchemaBuilder::stable(&limits).required("builder")?;
        let child = builder
            .add(super::super::SchemaFields {
                type_name: Presence::Value("string".into()),
                min_length: Presence::Value(2),
                pattern: Presence::Value("private-pattern".into()),
                ..Default::default()
            })
            .required("child")?;
        let root = builder
            .add(super::super::SchemaFields {
                type_name: Presence::Value("object".into()),
                properties: Presence::Value(BTreeMap::from([("private-key".into(), child)])),
                ..Default::default()
            })
            .required("root")?;
        let schema = builder.finish_stable(&root).required("schema")?;
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37).required("target")?);
        let plan = schema.compile(&target).required("plan")?;

        let source = br#"{"private-key":"x"}"#;
        let document = ProtectedJsonValue::parse_json(source, &limits).required("document")?;
        let report = plan
            .check_inherited(&document, &test_context(source), &FieldPath::default())
            .required("report")?;

        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.issues()[0].kind(), SchemaIssueKind::MinimumLengthViolation);
        assert_eq!(report.unsupported_count(), 1);
        assert_eq!(report.unsupported_kind(0), Some(SchemaUnsupported::Pattern));
        assert!(!report.supported_subset_satisfied());
        assert!(report.incomplete());
        let debug = format!("{report:?}{:?}", report.issues()[0]);
        assert!(!debug.contains("private-key"));
        assert!(!debug.contains("private-pattern"));
        Ok(())
    }

    #[test]
    fn absent_optional_property_still_reports_unsupported_child_schema() -> TestResult {
        let limits = ParseLimits::default();
        let mut builder = super::super::SchemaBuilder::stable(&limits).required("builder")?;
        let child = builder
            .add(super::super::SchemaFields {
                pattern: Presence::Value("secret".into()),
                ..Default::default()
            })
            .required("child")?;
        let root = builder
            .add(super::super::SchemaFields {
                properties: Presence::Value(BTreeMap::from([("absent-name".into(), child)])),
                ..Default::default()
            })
            .required("root")?;
        let schema = builder.finish_stable(&root).required("schema")?;
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37).required("target")?);
        let plan = schema.compile(&target).required("plan")?;
        let source = b"{}";
        let document = ProtectedJsonValue::parse_json(source, &limits).required("document")?;
        let report = plan
            .check_inherited(&document, &test_context(source), &FieldPath::default())
            .required("report")?;
        assert_eq!(report.unsupported_count(), 1);
        assert_eq!(report.unsupported_kind(0), Some(SchemaUnsupported::Pattern));
        Ok(())
    }

    #[test]
    fn native_topology_extensions_remain_unsupported_under_absent_properties() -> TestResult {
        let limits = ParseLimits::default();
        let mut builder = super::super::SchemaBuilder::stable(&limits).required("builder")?;
        let child = builder
            .add(super::super::SchemaFields {
                x_kubernetes_embedded_resource: Presence::Value(true),
                x_kubernetes_list_map_keys: Presence::Value(vec!["name".into()]),
                x_kubernetes_list_type: Presence::Value("map".into()),
                x_kubernetes_map_type: Presence::Value("granular".into()),
                ..Default::default()
            })
            .required("child")?;
        let root = builder
            .add(super::super::SchemaFields {
                type_name: Presence::Value("object".into()),
                required: Presence::Value(vec!["known".into()]),
                properties: Presence::Value(BTreeMap::from([("absent".into(), child)])),
                ..Default::default()
            })
            .required("root")?;
        let schema = builder.finish_stable(&root).required("schema")?;
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37).required("target")?);
        let plan = schema.compile(&target).required("plan")?;
        let source = b"{}";
        let document = ProtectedJsonValue::parse_json(source, &limits).required("document")?;
        let report = plan
            .check_inherited(&document, &test_context(source), &FieldPath::default())
            .required("report")?;
        assert_eq!(report.issues().len(), 1);
        assert_eq!(report.issues()[0].kind(), SchemaIssueKind::RequiredPropertyMissing);
        assert_eq!(report.unsupported_count(), 4);
        let access = crate::source::ExplicitSourceAccess::explicitly_allow_raw_source();
        let paths = (0..report.unsupported_count())
            .filter_map(|index| report.unsupported_path(index, &access))
            .collect::<Vec<_>>();
        assert!(paths.contains(&"/properties/absent/x-kubernetes-list-map-keys".to_owned()));
        assert!(paths.contains(&"/properties/absent/x-kubernetes-list-type".to_owned()));
        let kinds = (0..report.unsupported_count())
            .filter_map(|index| report.unsupported_kind(index))
            .collect::<Vec<_>>();
        assert!(kinds.contains(&SchemaUnsupported::EmbeddedResource));
        assert!(kinds.contains(&SchemaUnsupported::ListTopology));
        assert!(kinds.contains(&SchemaUnsupported::MapTopology));
        Ok(())
    }

    #[test]
    fn schema_builder_charges_scalar_and_retained_json_limits() -> TestResult {
        let scalar_limits = ParseLimits {
            max_scalar_bytes: 8,
            ..ParseLimits::default()
        };
        let mut scalar_builder = super::super::SchemaBuilder::stable(&scalar_limits).required("builder")?;
        assert!(
            scalar_builder
                .add(super::super::SchemaFields {
                    x_kubernetes_list_map_keys: Presence::Value(vec!["too-long-key".into()]),
                    ..Default::default()
                })
                .is_err()
        );

        let mut payload_limits = ParseLimits::default();
        payload_limits.processing.max_payload_bytes = 4096;
        let marker = "x".repeat(5_000);
        let encoded = format!("\"{marker}\"");
        let value = crate::resources::extensions::JSONCrdV1::parse_json(encoded.as_bytes(), &ParseLimits::default())
            .required("large enum JSON")?;
        let mut payload_builder = super::super::SchemaBuilder::stable(&payload_limits).required("builder")?;
        assert!(
            payload_builder
                .add(super::super::SchemaFields {
                    enum_values: Presence::Value(vec![value]),
                    ..Default::default()
                })
                .is_err()
        );
        Ok(())
    }

    #[test]
    fn shared_schema_dag_occurrences_charge_expanded_scalar_payload() -> TestResult {
        let mut limits = ParseLimits::default();
        limits.processing.max_payload_bytes = 6_000;
        let mut builder = super::super::SchemaBuilder::stable(&limits).required("builder")?;
        let child = builder
            .add(super::super::SchemaFields {
                description: Presence::Value("x".repeat(1_500)),
                ..Default::default()
            })
            .required("child")?;
        let root = builder
            .add(super::super::SchemaFields {
                all_of: Presence::Value(vec![child.clone(), child]),
                ..Default::default()
            })
            .required("root")?;
        assert!(builder.finish_stable(&root).is_err());
        Ok(())
    }

    #[test]
    fn inherited_check_uses_prior_operation_charges_and_keeps_authored_evidence_incomplete() -> TestResult {
        let limits = ParseLimits::default();
        let mut builder = super::super::SchemaBuilder::stable(&limits).required("builder")?;
        let root = builder
            .add(super::super::SchemaFields {
                type_name: Presence::Value("string".into()),
                ..Default::default()
            })
            .required("root")?;
        let schema = builder.finish_stable(&root).required("schema")?;
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37).required("target")?);
        let plan = schema.compile(&target).required("plan")?;
        let bytes = br#""value""#;
        let document = ProtectedJsonValue::parse_json(bytes, &limits).required("document")?;
        let evidence = SourceEvidence::native_authored_with_limits(SourceId(99), bytes.to_vec(), limits);
        let context = FieldDecodeContext::new(limits, NativeOperationBudget::new(limits.processing), Phase::Analysis)
            .with_evidence(&evidence);
        context
            .processing
            .work(context.processing.limits().max_processing_units, Phase::Analysis)
            .required("prior operation charge")?;
        let report = plan
            .check_inherited(&document, &context, &FieldPath::default())
            .required("bounded report")?;
        assert!(report.limit_exceeded());
        assert!(report.incomplete());
        assert!(!report.supported_subset_satisfied());
        Ok(())
    }
}
