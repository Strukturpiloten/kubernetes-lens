//! Bounded offline probe for authenticated official-corpus requests.
//! Its safe receipt establishes neither API-server nor controller/runtime conformance.
use kubernetes_lens::{
    Finding, FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    generation::{
        CollectionOutput, ExplicitArtifactAccess, GenerationOptions, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
    },
    graph::{GraphSubject, ReferenceContext, Resolution, resolve_references_with_context_for_target},
    model::{ResourceDocument, ResourceSet},
    resources::{access, configuration_storage, networking, workloads},
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::Presence,
};
use serde_json::{Value, json};
use std::{
    collections::BTreeMap,
    io::{Read, Write},
};

const MAX_REQUEST: u64 = 12 * 1024 * 1024;
const MAX_SOURCES: usize = 16;
const MAX_ASSERTIONS: usize = 128;

fn required<'a>(request: &'a Value, key: &str) -> Result<&'a Value, &'static str> {
    request.get(key).ok_or("invalid-request")
}
fn boolean(request: &Value, key: &str) -> Result<bool, &'static str> {
    required(request, key)?.as_bool().ok_or("invalid-request")
}
fn counts(findings: &[Finding]) -> Value {
    let mut counts = BTreeMap::<&str, usize>::new();
    for finding in findings {
        *counts.entry(finding.code.as_str()).or_default() += 1;
    }
    json!(counts)
}
fn exhausted(findings: &[Finding]) -> bool {
    findings
        .iter()
        .any(|finding| finding.code == FindingCode::LimitExceeded)
}
fn selected_builtin(document: &ResourceDocument) -> bool {
    macro_rules! any { ($module:ident; $($kind:ident),+ $(,)?) => {
        false $(|| document.resource::<$module::$kind>().is_some())+
    }; }
    any!(workloads; Pod, Deployment, StatefulSet, DaemonSet, ReplicaSet, ReplicationController, Job, CronJobV1, CronJobV1Beta1)
        || any!(networking; Service, Endpoints, EndpointSliceV1, EndpointSliceV1Beta1, IngressV1, IngressV1Beta1, IngressExtensionsV1Beta1, IngressClassV1, IngressClassV1Beta1, NetworkPolicy)
        || any!(configuration_storage; ConfigMap, Secret, PersistentVolumeClaim, PersistentVolume, StorageClass)
        || any!(access; Namespace, ServiceAccount, Role, RoleBinding, ClusterRole, ClusterRoleBinding, HorizontalPodAutoscalerV1, HorizontalPodAutoscalerV2, HorizontalPodAutoscalerV2Beta1, HorizontalPodAutoscalerV2Beta2, PodDisruptionBudgetV1, PodDisruptionBudgetV1Beta1, ResourceQuota, LimitRange, PriorityClass, RuntimeClassV1, RuntimeClassV1Beta1, PodSecurityPolicy)
}
fn resolution_name(resolution: &Resolution) -> &'static str {
    match resolution {
        Resolution::ResolvedSubjects(_) => "resolved-subjects",
        Resolution::Resolved(_) => "resolved",
        Resolution::Missing => "missing",
        Resolution::MissingKey { .. } => "missing-key",
        Resolution::MissingContainerPort { .. } => "missing-container-port",
        Resolution::MissingServicePort { .. } => "missing-service-port",
        Resolution::External(_) => "external",
        Resolution::Unsupported(_) => "unsupported",
        _ => "other-explicit-outcome",
    }
}
fn resolution_count(resolution: &Resolution) -> Option<usize> {
    match resolution {
        Resolution::ResolvedSubjects(subjects) => Some(subjects.len()),
        Resolution::Resolved(objects) => Some(objects.len()),
        _ => None,
    }
}

fn flatten_items<'a>(value: &'a Value, output: &mut Vec<&'a Value>, depth: usize) -> Result<(), &'static str> {
    if depth > 64 {
        return Err("native-list-depth");
    }
    if value
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "List" || kind.ends_with("List"))
    {
        for item in value
            .get("items")
            .and_then(Value::as_array)
            .ok_or("invalid-native-list")?
        {
            flatten_items(item, output, depth + 1)?;
        }
    } else {
        output.push(value);
    }
    Ok(())
}

fn retained_wrappers<'a>(value: &'a Value, output: &mut Vec<&'a Value>, depth: usize) -> Result<(), &'static str> {
    if depth > 64 {
        return Err("native-list-depth");
    }
    if value
        .get("kind")
        .and_then(Value::as_str)
        .is_some_and(|kind| kind == "List" || kind.ends_with("List"))
    {
        output.push(value);
        for item in value
            .get("items")
            .and_then(Value::as_array)
            .ok_or("invalid-native-list")?
        {
            retained_wrappers(item, output, depth + 1)?;
        }
    }
    Ok(())
}

fn matches_presence(value: Option<&Value>, expected: &Presence<String>) -> bool {
    match expected {
        Presence::Absent => value.is_none(),
        Presence::Null => value == Some(&Value::Null),
        Presence::Value(text) => value.and_then(Value::as_str) == Some(text.as_str()),
    }
}
fn ordered_values<'a>(value: &'a Value, resources: &ResourceSet) -> Result<Vec<&'a Value>, &'static str> {
    let mut items = Vec::new();
    flatten_items(value, &mut items, 0)?;
    if items.len() != resources.documents().len() {
        return Err("resource-count-changed");
    }
    resources
        .documents()
        .iter()
        .map(|document| {
            let identity = document.identity().map_err(|_| "invalid-effective-identity")?;
            let matched = items
                .iter()
                .filter(|item| {
                    item.get("apiVersion").and_then(Value::as_str) == Some(identity.gvk.api_version().as_str())
                        && item.get("kind").and_then(Value::as_str) == Some(identity.gvk.kind.as_str())
                        && matches_presence(item.pointer("/metadata/name"), &identity.name)
                        && matches_presence(item.pointer("/metadata/namespace"), &identity.namespace)
                        && matches_presence(item.pointer("/metadata/generateName"), &identity.generate_name)
                })
                .copied()
                .collect::<Vec<_>>();
            if matched.len() == 1 {
                Ok(matched[0])
            } else {
                Err("generated-identity-mismatch")
            }
        })
        .collect()
}

fn expected_targets(resolution: &Resolution, resources: &ResourceSet, assertion: &Value) -> bool {
    let Some(expected) = assertion.get("target_indices").and_then(Value::as_array) else {
        return true;
    };
    let (actual, kind): (Vec<_>, _) = match resolution {
        Resolution::Resolved(ids) => (ids.clone(), "object"),
        Resolution::ResolvedSubjects(subjects) => {
            let mut ids = Vec::new();
            let mut shape = None;
            for subject in subjects {
                let (id, name) = match subject {
                    GraphSubject::Object { resource } => (*resource, "object"),
                    GraphSubject::Template { resource, .. } => (*resource, "template"),
                    GraphSubject::ServicePort { resource, .. } => (*resource, "service-port"),
                    GraphSubject::Key { resource, .. } => (*resource, "key"),
                };
                if shape.is_some_and(|previous| previous != name) {
                    return false;
                }
                shape = Some(name);
                ids.push(id);
            }
            (ids, shape.unwrap_or("none"))
        }
        _ => return false,
    };
    let expected_ids = expected
        .iter()
        .map(|index| {
            index
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .and_then(|index| resources.documents().get(index))
                .map(ResourceDocument::id)
        })
        .collect::<Option<Vec<_>>>();
    let Some(mut expected_ids) = expected_ids else {
        return false;
    };
    let mut actual = actual;
    actual.sort();
    expected_ids.sort();
    actual == expected_ids && assertion.get("subject_kind").and_then(Value::as_str) == Some(kind)
}

fn generation_options(preserve: bool, include: bool) -> GenerationOptions {
    GenerationOptions {
        opaque_fields: if preserve {
            OpaqueFieldPolicy::PreserveWithFinding
        } else {
            OpaqueFieldPolicy::Block
        },
        protected_output: if include {
            ProtectedOutput::Include
        } else {
            ProtectedOutput::Deny
        },
        collections: CollectionOutput::PreserveWrappers,
        ..GenerationOptions::default()
    }
}
fn parse_generated(bytes: &[u8], format: DocumentFormat, limits: &ParseLimits) -> Result<ResourceSet, Vec<Finding>> {
    kubernetes_lens::parse_source(
        SourceInput {
            id: SourceId(0),
            format,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes,
        },
        limits,
    )?
    .flatten_resources()
}

struct ProbeRequest<'a> {
    target: TargetProfile,
    namespace: &'a str,
    options: GenerationOptions,
    limits: ParseLimits,
    sources: &'a [Value],
    assertions: &'a [Value],
    graph_assertions: &'a [Value],
    wrapper_assertions: &'a [Value],
    binding: &'a str,
    minor: u8,
}
fn checked_request(request: &Value) -> Result<ProbeRequest<'_>, &'static str> {
    if required(request, "schema_version")? != &json!(1) {
        return Err("invalid-request");
    }
    let binding = required(request, "binding")?.as_str().ok_or("invalid-binding")?;
    if binding.len() != 64
        || !binding
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err("invalid-binding");
    }
    let minor = u8::try_from(required(request, "target_minor")?.as_u64().ok_or("invalid-target")?)
        .map_err(|_| "invalid-target")?;
    let version = KubernetesVersion::new(1, minor).map_err(|_| "invalid-target")?;
    if !boolean(request, "documented_gate_defaults")? {
        return Err("explicit-gate-profile-required");
    }
    let target = TargetProfile::documented_defaults(version);
    let namespace = required(request, "namespace")?
        .as_str()
        .ok_or("explicit-namespace-required")?;
    if namespace.is_empty()
        || namespace.starts_with('-')
        || namespace.ends_with('-')
        || namespace.len() > 63
        || !namespace
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err("invalid-namespace");
    }
    let options = generation_options(
        boolean(request, "preserve_unknown")?,
        boolean(request, "include_protected")?,
    );
    let max_bytes = usize::try_from(required(request, "max_input_bytes")?.as_u64().ok_or("invalid-budget")?)
        .map_err(|_| "invalid-budget")?;
    let mut limits = ParseLimits::default();
    if max_bytes == 0 || max_bytes > limits.max_input_bytes {
        return Err("invalid-budget");
    }
    limits.max_input_bytes = max_bytes;
    let sources = required(request, "sources")?.as_array().ok_or("invalid-request")?;
    let assertions = required(request, "assertions")?.as_array().ok_or("invalid-request")?;
    let graph_assertions = required(request, "graph_assertions")?
        .as_array()
        .ok_or("invalid-request")?;
    let wrapper_assertions = required(request, "wrapper_assertions")?
        .as_array()
        .ok_or("invalid-request")?;
    if sources.is_empty()
        || sources.len() > MAX_SOURCES
        || assertions.is_empty()
        || assertions.len() > MAX_ASSERTIONS
        || graph_assertions.len() > MAX_ASSERTIONS
        || wrapper_assertions.len() > MAX_ASSERTIONS
    {
        return Err("request-budget");
    }
    Ok(ProbeRequest {
        target,
        namespace,
        options,
        limits,
        sources,
        assertions,
        graph_assertions,
        wrapper_assertions,
        binding,
        minor,
    })
}
fn decode_inputs(request: &ProbeRequest<'_>, receipt: &mut Value) -> Result<Option<ResourceSet>, &'static str> {
    let mut total = 0usize;
    let mut parsed = Vec::new();
    for (index, source) in request.sources.iter().enumerate() {
        let text = required(source, "content")?.as_str().ok_or("invalid-request")?;
        total = total.checked_add(text.len()).ok_or("request-budget")?;
        if total > request.limits.max_input_bytes {
            return Err("request-budget");
        }
        let format = match required(source, "format")?.as_str() {
            Some("yaml") => DocumentFormat::YamlStream,
            Some("json") => DocumentFormat::Json,
            _ => return Err("invalid-format"),
        };
        let result = kubernetes_lens::parse_source(
            SourceInput {
                id: SourceId(u64::try_from(index).map_err(|_| "request-budget")?),
                format,
                origin: InputOrigin::CallerSupplied,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &request.limits,
        );
        match result {
            Ok(input) => parsed.push(input),
            Err(findings) => {
                receipt["state"] = json!("parse-refused");
                receipt["findings"] = counts(&findings);
                return Ok(None);
            }
        }
    }
    let resources = match ResourceSet::from_inputs(parsed) {
        Ok(set) => set,
        Err(findings) => {
            receipt["state"] = json!("decode-refused");
            receipt["findings"] = counts(&findings);
            return Ok(None);
        }
    };
    Ok(Some(resources))
}
fn graph_failures(
    graph: &kubernetes_lens::graph::ReferenceGraph,
    resources: &ResourceSet,
    assertions: &[Value],
) -> Result<usize, &'static str> {
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    let mut graph_failures = 0;
    for assertion in assertions {
        let index = usize::try_from(
            required(assertion, "resource_index")?
                .as_u64()
                .ok_or("invalid-assertion")?,
        )
        .map_err(|_| "invalid-assertion")?;
        let document = resources.documents().get(index).ok_or("invalid-assertion")?;
        let path = required(assertion, "path")?.as_str().ok_or("invalid-assertion")?;
        let state = required(assertion, "resolution")?.as_str().ok_or("invalid-assertion")?;
        let matches = graph
            .edges
            .iter()
            .filter(|edge| edge.reference.from == document.id() && edge.reference.path.reveal(&access) == path)
            .collect::<Vec<_>>();
        let passed = matches.len() == 1
            && resolution_name(&matches[0].resolution) == state
            && expected_targets(&matches[0].resolution, resources, assertion)
            && assertion.get("count").is_none_or(|count| {
                count.as_u64().and_then(|count| usize::try_from(count).ok()) == resolution_count(&matches[0].resolution)
            });
        if !passed {
            graph_failures += 1;
        }
    }
    Ok(graph_failures)
}
fn field_failures(
    request: &ProbeRequest<'_>,
    resources: &ResourceSet,
    output: &Value,
    items: &[&Value],
) -> Result<(usize, usize), &'static str> {
    let mut wrappers = Vec::new();
    for root in output
        .get("items")
        .and_then(Value::as_array)
        .ok_or("invalid-native-list")?
    {
        retained_wrappers(root, &mut wrappers, 0)?;
    }
    if wrappers.len() != resources.lists().len() {
        return Err("wrapper-count-changed");
    }
    let mut wrapper_failures = 0;
    for assertion in request.wrapper_assertions {
        let index = usize::try_from(
            required(assertion, "wrapper_index")?
                .as_u64()
                .ok_or("invalid-assertion")?,
        )
        .map_err(|_| "invalid-assertion")?;
        let pointer = required(assertion, "pointer")?.as_str().ok_or("invalid-assertion")?;
        if wrappers.get(index).and_then(|item| item.pointer(pointer)) != Some(required(assertion, "equals")?) {
            wrapper_failures += 1;
        }
    }
    let mut failures = 0;
    for assertion in request.assertions {
        let index = usize::try_from(
            required(assertion, "resource_index")?
                .as_u64()
                .ok_or("invalid-assertion")?,
        )
        .map_err(|_| "invalid-assertion")?;
        let pointer = required(assertion, "pointer")?.as_str().ok_or("invalid-assertion")?;
        let actual = items.get(index).and_then(|item| item.pointer(pointer));
        let typed_matches = assertion.get("selected_builtin_codec").is_none_or(|expected| {
            resources
                .documents()
                .get(index)
                .is_some_and(|document| Some(selected_builtin(document)) == expected.as_bool())
        });
        if actual != Some(required(assertion, "equals")?) || !typed_matches {
            failures += 1;
        }
    }
    Ok((failures, wrapper_failures))
}
fn reprojection_failures(
    request: &ProbeRequest<'_>,
    resources: &ResourceSet,
    items: &[&Value],
) -> Result<usize, &'static str> {
    let raw_access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    // Both output syntaxes are regenerated and reparsed. Equality is preservation evidence only.
    let mut reprojection_failures = 0;
    for (format, input_format) in [
        (OutputFormat::Json, DocumentFormat::Json),
        (OutputFormat::Yaml, DocumentFormat::YamlStream),
    ] {
        let generated = kubernetes_lens::generate(resources, &request.target, format, &request.options)
            .map_err(|_| "second-generation-refused")?;
        let reparsed = parse_generated(generated.reveal_bytes(&raw_access), input_format, &request.limits)
            .map_err(|_| "reparse-refused")?;
        let projected = kubernetes_lens::generate(&reparsed, &request.target, OutputFormat::Json, &request.options)
            .map_err(|_| "reprojection-refused")?;
        let repeated = kubernetes_lens::generate(resources, &request.target, format, &request.options)
            .map_err(|_| "repeat-generation-refused")?;
        let projected_value: Value =
            serde_json::from_slice(projected.reveal_bytes(&raw_access)).map_err(|_| "invalid-native-json")?;
        let projected_items = ordered_values(&projected_value, resources)?;
        let preserved_yaml = if format == OutputFormat::Yaml {
            kubernetes_lens::generate(&reparsed, &request.target, OutputFormat::Yaml, &request.options)
                .map_err(|_| "reprojection-refused")?
                .reveal_bytes(&raw_access)
                == generated.reveal_bytes(&raw_access)
        } else {
            true
        };
        if projected_items != items
            || !preserved_yaml
            || repeated.reveal_bytes(&raw_access) != generated.reveal_bytes(&raw_access)
        {
            reprojection_failures += 1;
        }
    }
    Ok(reprojection_failures)
}
/// Evaluate one explicit request; returned receipts contain no source, names, paths or values.
///
/// # Errors
/// Returns fixed safe codes for invalid request structure or native-output inconsistencies.
pub fn evaluate(value: &Value) -> Result<Value, &'static str> {
    let request = checked_request(value)?;
    let mut receipt = json!({"schema_version":1, "binding":request.binding, "target_minor":request.minor,
        "state":"pending", "api":"pending", "runtime":"pending", "controller":"not-proven",
        "field_assertions":request.assertions.len(), "graph_assertions":request.graph_assertions.len(), "wrapper_assertions":request.wrapper_assertions.len()});
    let Some(resources) = decode_inputs(&request, &mut receipt)? else {
        return Ok(receipt);
    };
    if resources.documents().len() > 1024 || resources.lists().len() > 1024 {
        receipt["state"] = json!("processing-refused");
        receipt["findings"] = json!({"limit-exceeded":1});
        return Ok(receipt);
    }
    receipt["resources"] = json!(resources.documents().len());
    receipt["selected_builtin_codecs"] = json!(
        resources
            .documents()
            .iter()
            .filter(|document| selected_builtin(document))
            .count()
    );
    receipt["decode_findings"] = counts(resources.findings());
    let validation = kubernetes_lens::validate_for_target(&resources, &request.target);
    receipt["validation_findings"] = counts(&validation);
    let graph = resolve_references_with_context_for_target(
        &resources,
        &ReferenceContext {
            default_namespace: Some(request.namespace.to_owned()),
            ..ReferenceContext::default()
        },
        &request.target,
    );
    receipt["graph_findings"] = counts(&graph.findings);
    receipt["graph_edges"] = json!(graph.edges.len());
    if exhausted(&validation) || exhausted(&graph.findings) {
        receipt["state"] = json!("processing-refused");
        return Ok(receipt);
    }
    let graph_failures = graph_failures(&graph, &resources, request.graph_assertions)?;
    receipt["graph_failures"] = json!(graph_failures);
    receipt["default_generation"] = match kubernetes_lens::generate(
        &resources,
        &request.target,
        OutputFormat::Json,
        &GenerationOptions::default(),
    ) {
        Ok(_) => json!({"state":"generated"}),
        Err(findings) => json!({"state":"refused", "findings":counts(&findings)}),
    };
    let artifact = match kubernetes_lens::generate(&resources, &request.target, OutputFormat::Json, &request.options) {
        Ok(artifact) => artifact,
        Err(findings) => {
            receipt["state"] = json!("generation-refused");
            receipt["generation_findings"] = counts(&findings);
            return Ok(receipt);
        }
    };
    receipt["generation_findings"] = counts(artifact.findings());
    receipt["opaque_preservation"] = json!(
        if request.options.opaque_fields == OpaqueFieldPolicy::PreserveWithFinding
            && receipt
                .pointer("/default_generation/findings/opaque-output-denied")
                .and_then(Value::as_u64)
                .is_some_and(|count| count > 0)
        {
            "selected-unadmitted-source"
        } else {
            "not-required-by-default-check"
        }
    );
    let raw_access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    let output: Value =
        serde_json::from_slice(artifact.reveal_bytes(&raw_access)).map_err(|_| "invalid-native-json")?;
    let items = ordered_values(&output, &resources)?;
    let (failures, wrapper_failures) = field_failures(&request, &resources, &output, &items)?;
    receipt["field_failures"] = json!(failures);
    receipt["wrapper_failures"] = json!(wrapper_failures);
    let reprojection_failures = reprojection_failures(&request, &resources, &items)?;
    receipt["reprojection_failures"] = json!(reprojection_failures);
    receipt["state"] =
        json!(
            if failures == 0 && graph_failures == 0 && wrapper_failures == 0 && reprojection_failures == 0 {
                "static-assertions-passed"
            } else {
                "static-assertions-failed"
            }
        );
    Ok(receipt)
}

#[allow(dead_code)]
fn main() {
    let mut bytes = Vec::new();
    let result = std::io::stdin()
        .take(MAX_REQUEST + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| "input-failed")
        .and({
            if bytes.len() as u64 > MAX_REQUEST {
                Err("request-budget")
            } else {
                Ok(())
            }
        })
        .and_then(|()| serde_json::from_slice::<Value>(&bytes).map_err(|_| "invalid-request"))
        .and_then(|request| evaluate(&request));
    let failed = result.is_err();
    let receipt = result.unwrap_or_else(|code| json!({"schema_version":1, "state":"request-refused", "code":code}));
    let written = serde_json::to_writer(std::io::stdout().lock(), &receipt)
        .and_then(|()| std::io::stdout().write_all(b"\n").map_err(serde_json::Error::io));
    if failed || written.is_err() {
        std::process::exit(2);
    }
}
