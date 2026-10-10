//! Independent offline networking expectations, never server/controller/CNI conformance.
use kubernetes_lens::{
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::{FieldPath, Finding, FindingCode},
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, ProtectedOutput,
    },
    model::ResourceSet,
    parse_source,
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
    validate_for_target,
};
use serde_json::{Value, json};
type TestResult<T> = Result<T, Box<dyn std::error::Error>>;
trait Required<T> {
    fn required(self) -> TestResult<T>;
}
impl<T> Required<T> for Option<T> {
    fn required(self) -> TestResult<T> {
        self.ok_or_else(|| "missing networking fixture".into())
    }
}
impl<T, E: std::fmt::Debug> Required<T> for Result<T, E> {
    fn required(self) -> TestResult<T> {
        self.map_err(|error| format!("networking fixture operation failed: {error:?}").into())
    }
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn resources(value: &Value) -> TestResult<ResourceSet> {
    let bytes = serde_json::to_vec(value)?;
    parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .required()?
    .flatten_resources()
    .required()
}
fn document(api: &str, kind: &str, body: Value) -> Value {
    let mut value = json!({"apiVersion":api,"kind":kind,"metadata":{"name":"native","namespace":"ns"}});
    if kind == "IngressClass" {
        value["metadata"]
            .as_object_mut()
            .map(|metadata| metadata.remove("namespace"));
    }
    if let Value::Object(entries) = body {
        for (key, member) in entries {
            value[key] = member;
        }
    }
    value
}
fn service() -> Value {
    document(
        "v1",
        "Service",
        json!({"spec":{"ports":[{"port":80,"protocol":"TCP"}]}}),
    )
}
fn ingress(api: &str) -> Value {
    let spec = if api == "networking.k8s.io/v1" {
        json!({"defaultBackend":{"service":{"name":"native","port":{"number":80}}}})
    } else {
        json!({"backend":{"serviceName":"native","servicePort":80}})
    };
    document(api, "Ingress", json!({"spec":spec}))
}
fn slice(api: &str) -> Value {
    document(
        api,
        "EndpointSlice",
        json!({"addressType":"IPv4","endpoints":[{"addresses":["10.0.0.1"]}]}),
    )
}
fn policy() -> Value {
    document(
        "networking.k8s.io/v1",
        "NetworkPolicy",
        json!({"spec":{"podSelector":{},"ingress":[{}]}}),
    )
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    }
}
fn output(set: &ResourceSet, minor: u8) -> TestResult<Value> {
    let artifact = generate(set, &target(minor)?, OutputFormat::Json, &options()).required()?;
    Ok(serde_json::from_slice(artifact.reveal_bytes(
        &ExplicitArtifactAccess::explicitly_allow_raw_artifact(),
    ))?)
}
fn has(findings: &[Finding], code: FindingCode, path: &str) -> TestResult<bool> {
    let expected = FieldPath::parse(path)?;
    Ok(findings
        .iter()
        .any(|finding| finding.code == code && finding.path.as_ref() == Some(&expected)))
}
fn valid(value: &Value, minor: u8) -> TestResult<()> {
    let findings = validate_for_target(&resources(value)?, &target(minor)?);
    assert!(
        !findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid),
        "{:?}",
        findings
            .iter()
            .map(|finding| (
                &finding.code,
                finding
                    .path
                    .as_ref()
                    .map(|path| path
                        .reveal(&kubernetes_lens::source::ExplicitSourceAccess::explicitly_allow_raw_source()))
            ))
            .collect::<Vec<_>>()
    );
    Ok(())
}
#[path = "networking/authoring.rs"]
mod authoring;
#[path = "networking/availability.rs"]
mod availability;
#[path = "networking/native.rs"]
mod native;
#[path = "networking/preservation.rs"]
mod preservation;
#[path = "networking/references.rs"]
mod references;

#[path = "networking/processing.rs"]
mod processing;

#[path = "networking/static_contract.rs"]
mod static_contract;
