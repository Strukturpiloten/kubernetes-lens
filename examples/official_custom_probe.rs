//! Original offline custom-document acceptance; no server or controller behavior is claimed.
#[path = "official_native_probe.rs"]
mod native;

use kubernetes_lens::{
    Finding, FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    generation::{
        CollectionOutput, ExplicitArtifactAccess, GenerationOptions, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
    },
    graph::{
        ExternalRefKind, ReferenceContext, ReferenceGraph, ReferenceTarget, RelationshipKind, Resolution,
        resolve_references_with_context_for_target,
    },
    model::{ResourceDocument, ResourceSet},
    processing::NativeProcessingLimits,
    resources::extensions::{CustomDocumentBinding, CustomDocumentCheck, CustomDocumentResult, SchemaCheckReport},
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const MAX_REQUEST: u64 = 12 * 1024 * 1024;
const MAX_ASSERTIONS: usize = 128;
fn required<'a>(value: &'a Value, key: &str) -> Result<&'a Value, &'static str> {
    value.get(key).ok_or("invalid-custom-request")
}
fn integer(value: &Value, key: &str) -> Result<usize, &'static str> {
    usize::try_from(required(value, key)?.as_u64().ok_or("invalid-custom-request")?)
        .map_err(|_| "invalid-custom-request")
}
fn text<'a>(value: &'a Value, key: &str) -> Result<&'a str, &'static str> {
    required(value, key)?.as_str().ok_or("invalid-custom-request")
}
fn counts(findings: &[Finding]) -> Value {
    let mut counts = BTreeMap::new();
    for finding in findings {
        *counts.entry(finding.code.as_str()).or_insert(0usize) += 1;
    }
    json!(counts)
}
fn report(check: &CustomDocumentCheck) -> Option<&SchemaCheckReport> {
    match check {
        CustomDocumentCheck::UnsupportedSchema(r)
        | CustomDocumentCheck::SchemaViolations(r)
        | CustomDocumentCheck::Checked(r)
        | CustomDocumentCheck::Incomplete(r) => Some(r),
        CustomDocumentCheck::LimitExceeded(r) => r.as_ref(),
        _ => None,
    }
}
fn check_name(check: &CustomDocumentCheck) -> &'static str {
    match check {
        CustomDocumentCheck::TargetProfileRequired => "TargetProfileRequired",
        CustomDocumentCheck::MissingCrd => "MissingCrd",
        CustomDocumentCheck::AmbiguousCrd => "AmbiguousCrd",
        CustomDocumentCheck::InvalidBinding => "InvalidBinding",
        CustomDocumentCheck::VersionNotListed => "VersionNotListed",
        CustomDocumentCheck::VersionNotServed => "VersionNotServed",
        CustomDocumentCheck::ScopeMismatch => "ScopeMismatch",
        CustomDocumentCheck::MissingSchema => "MissingSchema",
        CustomDocumentCheck::InvalidSchema => "InvalidSchema",
        CustomDocumentCheck::UnsupportedSchema(_) => "UnsupportedSchema",
        CustomDocumentCheck::SchemaViolations(_) => "SchemaViolations",
        CustomDocumentCheck::Checked(_) => "Bound",
        CustomDocumentCheck::Incomplete(_) => "Incomplete",
        CustomDocumentCheck::LimitExceeded(_) => "LimitExceeded",
    }
}
fn categories(report: Option<&SchemaCheckReport>) -> BTreeMap<String, usize> {
    let mut result = BTreeMap::new();
    if let Some(report) = report {
        for index in 0..report.unsupported_count() {
            if let Some(kind) = report.unsupported_kind(index) {
                *result.entry(format!("{kind:?}")).or_default() += 1;
            }
        }
    }
    result
}
fn parse_inputs(request: &Value) -> Result<ResourceSet, &'static str> {
    let limits = ParseLimits {
        max_input_bytes: integer(request, "max_input_bytes")?,
        ..ParseLimits::default()
    };
    let mut inputs = Vec::new();
    for (index, source) in required(request, "sources")?
        .as_array()
        .ok_or("invalid-custom-request")?
        .iter()
        .enumerate()
    {
        let format = match text(source, "format")? {
            "yaml" => DocumentFormat::YamlStream,
            "json" => DocumentFormat::Json,
            _ => return Err("invalid-format"),
        };
        inputs.push(
            kubernetes_lens::parse_source(
                SourceInput {
                    id: SourceId(u64::try_from(index).map_err(|_| "invalid-custom-request")?),
                    format,
                    origin: InputOrigin::CallerSupplied,
                    source_version: None,
                    bytes: text(source, "content")?.as_bytes(),
                },
                &limits,
            )
            .map_err(|_| "custom-parse-refused")?,
        );
    }
    ResourceSet::from_inputs(inputs).map_err(|_| "custom-decode-refused")
}
fn binding_matches(
    binding: Option<&CustomDocumentBinding>,
    expected: &Value,
    resources: &ResourceSet,
) -> Result<bool, &'static str> {
    if expected.is_null() {
        return Ok(binding.is_none());
    }
    let Some(binding) = binding else {
        return Ok(false);
    };
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let descriptor = binding.supplied_descriptor();
    let crd = resources
        .documents()
        .get(integer(expected, "crd_index")?)
        .ok_or("invalid-custom-assertion")?;
    let version_pointer = text(expected, "version_pointer")?;
    let schema_pointer = text(expected, "schema_pointer")?;
    Ok(descriptor.resource_id() == crd.id()
        && descriptor.crd_source() == crd.source()
        && descriptor.crd_source().source.0
            == u64::try_from(integer(expected, "source_id")?).map_err(|_| "invalid-custom-assertion")?
        && u64::from(descriptor.crd_source().document_index)
            == u64::try_from(integer(expected, "source_document")?).map_err(|_| "invalid-custom-assertion")?
        && descriptor.crd_gvk() == &crd.original_identity().gvk
        && descriptor.crd_gvk().api_version() == text(expected, "crd_api_version")?
        && descriptor.crd_pointer(&access) == text(expected, "crd_pointer")?
        && descriptor.version_pointer(&access) == version_pointer
        && descriptor.schema_pointer(&access) == schema_pointer
        && descriptor.scope().namespaced() == required(expected, "namespaced")?.as_bool()
        && Some(descriptor.served()) == required(expected, "served")?.as_bool()
        && Some(descriptor.storage()) == required(expected, "storage")?.as_bool()
        && descriptor.schema_family() == text(expected, "schema_family")?)
}
fn selected_graph_matches(
    result: &CustomDocumentResult,
    expected: &Value,
    graph: &ReferenceGraph,
    resources: &ResourceSet,
) -> Result<(bool, usize, usize), &'static str> {
    let records = graph
        .custom_documents
        .iter()
        .filter(|r| r.resource_id() == result.resource_id())
        .collect::<Vec<_>>();
    let expected_state = text(expected, "check")?;
    let positive = required(expected, "positive_dependency")?
        .as_bool()
        .ok_or("invalid-custom-assertion")?;
    let operators = graph
        .edges
        .iter()
        .filter(|e| {
            e.reference.from == result.resource_id()
                && e.reference.relation == RelationshipKind::Operator
                && matches!(e.resolution, Resolution::External(ExternalRefKind::Operator))
        })
        .count();
    let dependencies = graph
        .edges
        .iter()
        .filter(|e| {
            e.reference.from == result.resource_id()
                && matches!(
                    &e.reference.target,
                    ReferenceTarget::SuppliedCustomResourceVersion { .. }
                )
        })
        .collect::<Vec<_>>();
    let expected_binding = required(expected, "binding")?;
    let evidence_ok = if positive {
        let access = ExplicitSourceAccess::explicitly_allow_raw_source();
        let crd = resources
            .documents()
            .get(integer(expected_binding, "crd_index")?)
            .ok_or("invalid-custom-assertion")?;
        dependencies.len() == 1
            && dependencies[0].resolution == Resolution::Resolved(vec![crd.id()])
            && dependencies[0].reference.relation == RelationshipKind::Dependency
            && ["/spec/versions/0", "/spec/versions/0/schema/openAPIV3Schema"]
                .iter()
                .all(|path| {
                    dependencies[0]
                        .evidence
                        .iter()
                        .any(|e| e.resource == crd.id() && e.path.reveal(&access) == *path)
                })
    } else {
        dependencies.is_empty()
    };
    let record_ok = records.len() == 1
        && format!("{:?}", records[0].status()) == expected_state
        && records[0].source() == result.source()
        && records[0].pointer(&ExplicitSourceAccess::explicitly_allow_raw_source())
            == result.pointer(&ExplicitSourceAccess::explicitly_allow_raw_source())
        && records[0].descriptor().is_some() == positive
        && records[0]
            .descriptor()
            .is_none_or(|d| result.binding().is_some_and(|b| d == b.supplied_descriptor()));
    Ok((
        record_ok && evidence_ok && operators == 1,
        operators,
        dependencies.len(),
    ))
}
fn source_matches(
    result: &CustomDocumentResult,
    document: &ResourceDocument,
    assertion: &Value,
    request: &Value,
) -> Result<bool, &'static str> {
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let source = required(request, "sources")?
        .as_array()
        .ok_or("invalid-custom-request")?
        .get(integer(assertion, "source_id")?)
        .ok_or("invalid-custom-assertion")?;
    Ok(result.source() == document.source()
        && result.resource().source() == result.source()
        && result.resource().source_evidence().id == result.source().source
        && result.source().source.0
            == u64::try_from(integer(assertion, "source_id")?).map_err(|_| "invalid-custom-assertion")?
        && u64::from(result.source().document_index)
            == u64::try_from(integer(assertion, "source_document")?).map_err(|_| "invalid-custom-assertion")?
        && result.pointer(&access) == text(assertion, "source_pointer")?
        && result.resource().pointer(&access) == result.pointer(&access)
        && result.resource().body().is_some()
        && result.resource().source_evidence().reveal_raw(&access) == text(source, "content")?.as_bytes())
}
fn custom_assertions(request: &Value, resources: &ResourceSet, target: &TargetProfile) -> Result<Value, &'static str> {
    let expected = required(request, "custom_assertions")?
        .as_array()
        .ok_or("invalid-custom-request")?;
    let mut limits = NativeProcessingLimits::default();
    if let Some(value) = request.get("custom_processing_units") {
        let units =
            usize::try_from(value.as_u64().ok_or("invalid-custom-budget")?).map_err(|_| "invalid-custom-budget")?;
        if units > limits.max_processing_units {
            return Err("invalid-custom-budget");
        }
        limits.max_processing_units = units;
    }
    let checks = match resources.check_custom_documents(target, limits) {
        Ok(checks) => checks,
        Err(finding) => {
            return Ok(
                json!({"state":"processing-refused", "findings":counts(&[finding]), "records":[], "failures":1}),
            );
        }
    };
    let graph = resolve_references_with_context_for_target(
        resources,
        &ReferenceContext {
            default_namespace: Some(text(request, "namespace")?.to_owned()),
            ..ReferenceContext::default()
        },
        target,
    );
    if graph.findings.iter().any(|f| f.code == FindingCode::LimitExceeded) {
        return Ok(
            json!({"state":"processing-refused", "findings":counts(&graph.findings), "records":[], "failures":1}),
        );
    }
    let mut failures = usize::from(checks.len() != expected.len());
    let mut records = Vec::new();
    let mut selected = std::collections::BTreeSet::new();
    for (assertion_index, assertion) in expected.iter().enumerate() {
        let document = resources
            .documents()
            .get(integer(assertion, "resource_index")?)
            .ok_or("invalid-custom-assertion")?;
        if !selected.insert(document.id()) {
            return Err("duplicate-custom-assertion");
        }
        let matches = checks
            .iter()
            .filter(|c| c.resource_id() == document.id())
            .collect::<Vec<_>>();
        let Some(result) = matches.first().copied().filter(|_| matches.len() == 1) else {
            failures += 1;
            records.push(json!({"assertion_index":assertion_index,"state":"missing-custom-result"}));
            continue;
        };
        let identity = result.resource().identity();
        let expected_identity = required(assertion, "identity")?;
        let source_ok = source_matches(result, document, assertion, request)?;
        let identity_ok = identity.gvk.group.as_deref() == Some(text(expected_identity, "group")?)
            && identity.gvk.kind == text(expected_identity, "kind")?
            && identity.gvk.version == text(expected_identity, "version")?;
        let binding_ok = binding_matches(result.binding(), required(assertion, "binding")?, resources)?
            && result.binding().is_none_or(|b| {
                b.supplied_descriptor().identity()
                    == (
                        text(expected_identity, "group").unwrap_or_default(),
                        text(expected_identity, "kind").unwrap_or_default(),
                        text(expected_identity, "version").unwrap_or_default(),
                    )
            });
        let schema = report(result.check());
        let actual_categories = categories(schema);
        let witnessed = required(assertion, "unsupported_categories")?
            .as_array()
            .ok_or("invalid-custom-assertion")?
            .iter()
            .all(|c| c.as_str().is_some_and(|c| actual_categories.contains_key(c)));
        let schema_ok = check_name(result.check()) == text(assertion, "check")?
            && witnessed
            && assertion
                .get("supported_subset_satisfied")
                .is_none_or(|v| schema.map(SchemaCheckReport::supported_subset_satisfied) == v.as_bool())
            && assertion
                .get("issue_count")
                .is_none_or(|v| schema.map(|s| s.issues().len() as u64) == v.as_u64());
        let (graph_ok, operators, dependencies) = selected_graph_matches(result, assertion, &graph, resources)?;
        let passed = source_ok && identity_ok && binding_ok && schema_ok && graph_ok;
        failures += usize::from(!passed);
        records.push(json!({"assertion_index":assertion_index,"state":check_name(result.check()),"passed":passed,
            "source_evidence_checked":source_ok,"identity_match":identity_ok,"binding_match":binding_ok,"graph_match":graph_ok,
            "unsupported_categories":actual_categories,"issue_count":schema.map(|s|s.issues().len()),
            "supported_subset_satisfied":schema.map(SchemaCheckReport::supported_subset_satisfied),
            "numeric_semantics_uncertain":schema.map(SchemaCheckReport::numeric_semantics_uncertain),
            "operator_prerequisites":operators,"positive_dependencies":dependencies}));
    }
    Ok(
        json!({"state":"checked", "records":records, "failures":failures, "custom_documents":checks.len(), "graph_findings":counts(&graph.findings)}),
    )
}

fn signatures(
    resources: &ResourceSet,
    target: &TargetProfile,
    namespace: &str,
) -> Result<BTreeMap<String, Value>, &'static str> {
    let checks = resources
        .check_custom_documents(target, NativeProcessingLimits::default())
        .map_err(|_| "custom-recheck-refused")?;
    let graph = resolve_references_with_context_for_target(
        resources,
        &ReferenceContext {
            default_namespace: Some(namespace.to_owned()),
            ..ReferenceContext::default()
        },
        target,
    );
    if graph.findings.iter().any(|f| f.code == FindingCode::LimitExceeded) {
        return Err("custom-regraph-refused");
    }
    let mut signatures = BTreeMap::new();
    for result in checks {
        let identity = result.resource().identity();
        let key = serde_json::to_string(&json!([
            identity.gvk.api_version(),
            identity.gvk.kind,
            identity.name.value(),
            identity.namespace.value(),
            identity.generate_name.value()
        ]))
        .map_err(|_| "custom-identity-refused")?;
        let records = graph
            .custom_documents
            .iter()
            .filter(|r| r.resource_id() == result.resource_id())
            .collect::<Vec<_>>();
        let positive = matches!(result.check(), CustomDocumentCheck::Checked(_));
        let operators = graph
            .edges
            .iter()
            .filter(|e| {
                e.reference.from == result.resource_id()
                    && e.reference.relation == RelationshipKind::Operator
                    && matches!(e.resolution, Resolution::External(ExternalRefKind::Operator))
            })
            .count();
        let dependencies = graph
            .edges
            .iter()
            .filter(|e| {
                e.reference.from == result.resource_id()
                    && matches!(
                        &e.reference.target,
                        ReferenceTarget::SuppliedCustomResourceVersion { .. }
                    )
            })
            .collect::<Vec<_>>();
        let dependency_ok = if positive {
            dependencies.len() == 1
                && result.binding().is_some_and(|b| {
                    dependencies[0].resolution == Resolution::Resolved(vec![b.supplied_descriptor().resource_id()])
                })
        } else {
            dependencies.is_empty()
        };
        if records.len() != 1
            || format!("{:?}", records[0].status()) != check_name(result.check())
            || records[0].descriptor().is_some() != positive
            || operators != 1
            || !dependency_ok
        {
            return Err("custom-regraph-mismatch");
        }
        let value = json!({"state":check_name(result.check()),"categories":categories(report(result.check())),"issues":report(result.check()).map(|r|r.issues().len()),"subset":report(result.check()).map(SchemaCheckReport::supported_subset_satisfied),"descriptor":result.binding().map(CustomDocumentBinding::descriptor),"numeric_uncertainty":report(result.check()).map(SchemaCheckReport::numeric_semantics_uncertain)});
        if signatures.insert(key, value).is_some() {
            return Err("ambiguous-custom-identity");
        }
    }
    Ok(signatures)
}
fn recheck(request: &Value, resources: &ResourceSet, target: &TargetProfile) -> Result<usize, &'static str> {
    let namespace = text(request, "namespace")?;
    let expected = signatures(resources, target, namespace)?;
    let include = required(request, "include_protected")?
        .as_bool()
        .ok_or("invalid-custom-request")?;
    let preserve = required(request, "preserve_unknown")?
        .as_bool()
        .ok_or("invalid-custom-request")?;
    let options = GenerationOptions {
        protected_output: if include {
            ProtectedOutput::Include
        } else {
            ProtectedOutput::Deny
        },
        opaque_fields: if preserve {
            OpaqueFieldPolicy::PreserveWithFinding
        } else {
            OpaqueFieldPolicy::Block
        },
        collections: CollectionOutput::PreserveWrappers,
        ..GenerationOptions::default()
    };
    let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    let limits = ParseLimits {
        max_input_bytes: integer(request, "max_input_bytes")?,
        ..ParseLimits::default()
    };
    let mut failures = 0;
    for (output, input) in [
        (OutputFormat::Json, DocumentFormat::Json),
        (OutputFormat::Yaml, DocumentFormat::YamlStream),
    ] {
        let generated = kubernetes_lens::generate(resources, target, output, &options)
            .map_err(|_| "custom-regeneration-refused")?;
        let set = kubernetes_lens::parse_source(
            SourceInput {
                id: SourceId(0),
                format: input,
                origin: InputOrigin::CallerSupplied,
                source_version: None,
                bytes: generated.reveal_bytes(&access),
            },
            &limits,
        )
        .map_err(|_| "custom-reparse-refused")?
        .flatten_resources()
        .map_err(|_| "custom-redecode-refused")?;
        failures += usize::from(signatures(&set, target, namespace)? != expected);
    }
    Ok(failures)
}
/// Run native assertions and independent precise custom/schema/graph checks without live acquisition.
/// # Errors
/// Returns only fixed safe codes for malformed request or a refused operation.
pub fn evaluate(request: &Value) -> Result<Value, &'static str> {
    let assertions = required(request, "custom_assertions")?
        .as_array()
        .ok_or("invalid-custom-request")?;
    if assertions.is_empty() || assertions.len() > MAX_ASSERTIONS {
        return Err("custom-assertion-budget");
    }
    let mut receipt = native::evaluate(request)?;
    receipt["custom_assertions"] = json!(assertions.len());
    receipt["custom_reprojection"] = json!("not-executed-native-refusal");
    if matches!(
        receipt["state"].as_str(),
        Some("parse-refused" | "decode-refused" | "processing-refused")
    ) {
        return Ok(receipt);
    }
    let minor = u8::try_from(integer(request, "target_minor")?).map_err(|_| "invalid-target")?;
    let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, minor).map_err(|_| "invalid-target")?);
    let resources = parse_inputs(request)?;
    receipt["custom"] = custom_assertions(request, &resources, &target)?;
    if receipt["custom"]["state"] == "processing-refused" {
        receipt["state"] = json!("processing-refused");
        return Ok(receipt);
    }
    if receipt["state"] == "static-assertions-passed" {
        let failures = recheck(request, &resources, &target)?;
        receipt["custom_reprojection_failures"] = json!(failures);
        receipt["custom_reprojection"] = json!("checked");
        if failures != 0 || receipt["custom"]["failures"] != 0 {
            receipt["state"] = json!("static-assertions-failed");
        }
    }
    Ok(receipt)
}
#[allow(dead_code)]
fn main() {
    let mut input = Vec::new();
    let result = std::io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut input)
        .map_err(|_| "input-refused")
        .and_then(|_| {
            if input.len() as u64 > MAX_REQUEST {
                Err("request-budget")
            } else {
                serde_json::from_slice::<Value>(&input).map_err(|_| "invalid-request")
            }
        })
        .and_then(|request| evaluate(&request));
    let failed = result.is_err();
    let receipt = result.unwrap_or_else(|code| json!({"schema_version":1,"state":"request-refused","code":code}));
    let written = serde_json::to_writer(std::io::stdout().lock(), &receipt)
        .and_then(|()| std::io::stdout().write_all(b"\n").map_err(serde_json::Error::io));
    if failed || written.is_err() {
        std::process::exit(2);
    }
}
