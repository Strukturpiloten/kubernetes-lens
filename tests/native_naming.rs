//! Independent frozen naming cases and public pipeline/privacy regressions.
use kubernetes_lens::{
    FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::{FieldPath, Finding, Severity},
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, NativeValidationIntent, OpaqueFieldPolicy, OutputFormat,
        ProtectedOutput, generate, validate_for_target_with_intent, validate_for_target_with_limits,
    },
    graph::{ReferenceContext, Resolution, resolve_references_for_target, resolve_supplied_references_for_target},
    model::{Metadata, ResourceSet},
    parse_source,
    processing::NativeProcessingLimits,
    resources::{access::Role, workloads::Pod},
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    value::Presence,
};
use serde_json::{Value, json};
type TestResult = Result<(), String>;
fn target(minor: u8) -> Result<TargetProfile, String> {
    KubernetesVersion::new(1, minor)
        .map(TargetProfile::documented_defaults)
        .map_err(|_| "target".into())
}
fn parse(value: &Value) -> Result<ResourceSet, Vec<Finding>> {
    let text = serde_json::to_vec(value).map_err(|_| Vec::new())?;
    parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: &text,
        },
        &ParseLimits::default(),
    )?
    .flatten_resources()
}
fn fixture(api: &str, kind: &str, name: &str) -> Value {
    let mut document = json!({"apiVersion":api,"kind":kind,"metadata":{"name":name}});
    if !matches!(
        kind,
        "Namespace"
            | "PersistentVolume"
            | "StorageClass"
            | "ClusterRole"
            | "ClusterRoleBinding"
            | "PriorityClass"
            | "RuntimeClass"
            | "PodSecurityPolicy"
            | "CustomResourceDefinition"
            | "MutatingWebhookConfiguration"
            | "ValidatingWebhookConfiguration"
            | "IngressClass"
    ) {
        document["metadata"]["namespace"] = json!("ns");
    }
    match kind {
        "Pod" => document["spec"] = json!({"containers":[{"name":"main","image":"example.invalid/app:v1"}]}),
        "Role" | "ClusterRole" => document["rules"] = json!([{"apiGroups":[""],"resources":["pods"],"verbs":["get"]}]),
        "CustomResourceDefinition" => {
            document["spec"] = json!({"group":"example.com","scope":"Namespaced",
            "names":{"plural":"widgets","kind":"Widget"},"versions":[{"name":"v1","served":true,"storage":true}]});
        }
        _ => (),
    }
    document
}
fn code_at(findings: &[Finding], code: FindingCode, path: &str) -> bool {
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    findings
        .iter()
        .any(|finding| finding.code == code && finding.path.as_ref().is_some_and(|p| p.reveal(&access) == path))
}
fn private_value(case: &Value) -> Result<Option<Value>, String> {
    let value = &case["protected_synthetic_value"];
    match value["constructor"].as_str().ok_or("constructor")? {
        "literal" | "integer" => Ok(Some(value["value"].clone())),
        "repeat-and-suffix" => Ok(Some(json!(format!(
            "{}{}",
            value["character"]
                .as_str()
                .ok_or("character")?
                .repeat(usize::try_from(value["count"].as_u64().ok_or("count")?).map_err(|_| "count")?),
            value["suffix"].as_str().ok_or("suffix")?
        )))),
        "absent" => Ok(None),
        "empty" => Ok(Some(json!(""))),
        "null" => Ok(Some(Value::Null)),
        _ => Err("unknown constructor".into()),
    }
}
fn owner_cases(case: &Value, value: Option<&Value>, profile: &TargetProfile) -> TestResult {
    let mut doc = fixture("v1", "Pod", "subject");
    doc["metadata"]["ownerReferences"] = json!([{"apiVersion":"rbac.authorization.k8s.io/v1",
        "kind":"Role","name":value,"uid":"caller-supplied-exact-test-uid"}]);
    let set = parse(&doc).map_err(|_| "owner parse")?;
    let graph = resolve_references_for_target(&set, profile);
    let missing = case["id"] == "owner-name-empty";
    assert_eq!(
        code_at(
            &graph.findings,
            FindingCode::NativeFieldInvalid,
            "/metadata/ownerReferences/0/name"
        ),
        missing
    );
    if !missing {
        assert!(!graph.edges.is_empty());
    }
    Ok(())
}

#[test]
fn replay_all_125_independent_primary_corrected_cases() -> TestResult {
    let evidence: Value = serde_json::from_str(include_str!(
        "../schemas/capabilities/native-naming-independent-cases.json"
    ))
    .map_err(|_| "cases")?;
    let cases = evidence["cases"].as_array().ok_or("cases")?;
    assert_eq!(cases.len(), 125);
    for case in cases {
        replay_case(case)?;
    }
    Ok(())
}

fn replay_case(case: &Value) -> TestResult {
    let id = case["id"].as_str().ok_or("id")?;
    let api = case["api_version"].as_str().ok_or("api")?;
    let kind = case["kind"].as_str().ok_or("kind")?;
    let path = case["field_path"].as_str().ok_or("path")?;
    let value = private_value(case)?;
    let minor = case["target_minor"]
        .as_str()
        .and_then(|v| v.strip_prefix("1."))
        .and_then(|v| v.parse().ok())
        .unwrap_or(37);
    let profile = target(minor)?;
    if path.contains("ownerReferences") {
        owner_cases(case, value.as_ref(), &profile)?;
        return Ok(());
    }
    let mut doc = fixture(api, kind, "valid");
    let key = if path.ends_with("generateName") {
        "generateName"
    } else {
        "name"
    };
    if key == "generateName" {
        doc["metadata"].as_object_mut().ok_or("metadata")?.remove("name");
    }
    if let Some(value) = &value {
        doc["metadata"][key] = value.clone();
    } else {
        doc["metadata"].as_object_mut().ok_or("metadata")?.remove(key);
    }
    for (field, wire) in [
        ("metadata.generateName", "generateName"),
        ("metadata.namespace", "namespace"),
    ] {
        if let Some(value) = case["extra"].get(field) {
            doc["metadata"][wire] = value.clone();
        }
    }
    if id == "pdb-served-api-version-collision124" {
        let mut other = doc.clone();
        other["apiVersion"] = json!("policy/v1");
        let errors = parse(&json!({"apiVersion":"v1","kind":"List","items":[doc,other]}))
            .err()
            .ok_or("missing collision")?;
        assert!(
            errors
                .iter()
                .any(|finding| finding.code == FindingCode::DuplicateIdentity)
        );
        return Ok(());
    }
    if matches!(id, "case-sensitive-duplicates" | "unicode-no-normalization") {
        let mut other = doc.clone();
        other["metadata"]["name"] = case["extra"]["second_name"].clone();
        let set =
            parse(&json!({"apiVersion":"v1","kind":"List","items":[doc,other]})).map_err(|_| "distinct identities")?;
        assert_eq!(set.documents().len(), 2);
        return Ok(());
    }
    if id == "name-wrong-type" {
        let findings = parse(&doc).err().ok_or("wrong type accepted")?;
        assert!(code_at(&findings, FindingCode::NativeFieldInvalid, path));
        return Ok(());
    }
    let set = parse(&doc).map_err(|errors| format!("{id}: acquisition {errors:?}"))?;
    assert_eq!(set.documents().len(), 1);
    let debug = format!("{:?}{:?}", set, set.documents()[0].identity().map_err(|_| "identity")?);
    if let Some(private) = value.as_ref().and_then(Value::as_str).filter(|v| v.len() > 3) {
        assert!(!debug.contains(private), "{id}: private Debug");
    }
    if id.starts_with("acquire-no-profile") {
        return Ok(());
    }
    if id == "unicode-private-budget" {
        let findings = validate_for_target_with_limits(
            &set,
            &profile,
            NativeValidationIntent::Unspecified,
            &NativeProcessingLimits {
                max_processing_units: 5,
                ..NativeProcessingLimits::default()
            },
        );
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
        );
        return Ok(());
    }
    let intent = if case["intent"] == "Create" {
        NativeValidationIntent::Create
    } else {
        NativeValidationIntent::Unspecified
    };
    let findings = validate_for_target_with_intent(&set, &profile, intent);
    assert_case_outcome(case, id, path, &findings)
}

fn assert_case_outcome(case: &Value, id: &str, path: &str, findings: &[Finding]) -> TestResult {
    let expected = case["expected"].as_str().ok_or("expected")?;
    if expected.contains("unavailable-api") || expected.contains("api-unavailable") {
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnavailableApi),
            "{id}"
        );
    } else if expected.contains("outside-frozen") {
        assert!(code_at(findings, FindingCode::UnadmittedField, path), "{id}");
    } else if expected.contains("compatibility-unverified") {
        assert!(code_at(findings, FindingCode::NativeNamingUnverified, path), "{id}");
    } else if expected.contains("invalid")
        || matches!(
            id,
            "name-absent-without-prefix" | "name-empty-without-prefix" | "name-null-retention"
        )
    {
        let error_path = if id == "namespace-invalid-separate" {
            "/metadata/namespace"
        } else {
            path
        };
        assert!(
            code_at(findings, FindingCode::NativeFieldInvalid, error_path),
            "{id}: {findings:?}"
        );
    } else if expected.contains("context-required")
        || expected.contains("pending-name-generation")
        || expected.contains("identity-pending")
        || expected.contains("generation-context-pending")
        || expected.contains("final-create-length-unverified")
        || expected.contains("no-generated-final")
    {
        assert!(
            code_at(findings, FindingCode::NativeContextRequired, path),
            "{id}: {findings:?}"
        );
        assert!(
            !code_at(findings, FindingCode::NativeFieldInvalid, path),
            "{id}: {findings:?}"
        );
    } else {
        assert!(
            !code_at(findings, FindingCode::NativeFieldInvalid, path)
                && !code_at(findings, FindingCode::UnadmittedField, path),
            "{id}: {findings:?}"
        );
    }
    Ok(())
}

fn options(private: bool) -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: if private {
            ProtectedOutput::Include
        } else {
            ProtectedOutput::Deny
        },
        ..GenerationOptions::default()
    }
}
#[test]
fn controls_and_unicode_keep_explicit_output_access_and_edit_identity() -> TestResult {
    let mut doc = fixture("rbac.authorization.k8s.io/v1", "Role", "Role\nΩ\u{0}");
    doc["metadata"]["privateUnknown"] = json!("retained-private-marker");
    let mut set = parse(&doc).map_err(|_| "parse")?;
    let profile = target(37)?;
    let findings = generate(&set, &profile, OutputFormat::Json, &options(false))
        .err()
        .ok_or("private output allowed")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    let artifact = generate(&set, &profile, OutputFormat::Json, &options(true))
        .map_err(|errors| format!("private generation {errors:?}"))?;
    let bytes = artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
    let result: Value = serde_json::from_slice(bytes).map_err(|_| "output")?;
    assert_eq!(result["metadata"]["name"], doc["metadata"]["name"]);
    assert_eq!(result["metadata"]["privateUnknown"], doc["metadata"]["privateUnknown"]);
    let original = set.documents()[0].original_identity().name.clone();
    let role = set.documents_mut()[0].resource_mut::<Role>().ok_or("Role")?;
    let Presence::Value(metadata) = &mut role.metadata else {
        return Err("metadata".into());
    };
    metadata.name = Presence::Value("system:reader".into());
    assert_eq!(
        set.documents()[0]
            .identity()
            .map_err(|_| "identity")?
            .name
            .value()
            .map(String::as_str),
        Some("system:reader")
    );
    assert_eq!(set.documents()[0].original_identity().name, original);
    let changed = generate(&set, &profile, OutputFormat::Json, &options(true)).map_err(|_| "edited generation")?;
    let changed: Value =
        serde_json::from_slice(changed.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
            .map_err(|_| "changed")?;
    assert_eq!(changed["metadata"]["name"], "system:reader");
    assert_eq!(changed["metadata"]["privateUnknown"], "retained-private-marker");
    Ok(())
}
#[test]
fn authored_invalid_names_and_generated_only_names_cannot_create_positive_target_evidence() -> TestResult {
    let mut pod = Pod::default();
    pod.metadata = Presence::Value(Metadata {
        name: Presence::Value("Bad / Ω".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    });
    let findings = ResourceSet::from_authored(vec![pod.into()], &target(37)?, &AuthoringLimits::default())
        .err()
        .ok_or("invalid authoring accepted")?;
    assert!(code_at(&findings, FindingCode::NativeFieldInvalid, "/metadata/name"));
    let mut doc = fixture("v1", "Pod", "valid");
    doc["metadata"].as_object_mut().ok_or("metadata")?.remove("name");
    doc["metadata"]["generateName"] = json!("prefix-");
    let set = parse(&doc).map_err(|_| "generated-only")?;
    assert!(
        set.documents()[0]
            .identity()
            .map_err(|_| "identity")?
            .collision_key()
            .is_none()
    );
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(
        graph
            .edges
            .iter()
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)))
    );
    assert!(code_at(
        &graph.findings,
        FindingCode::NativeContextRequired,
        "/metadata/generateName"
    ));
    Ok(())
}

#[test]
fn independent_all_35_dispatch_covers_every_frozen_gvk_and_version_boundary() -> TestResult {
    let table: Value = serde_json::from_str(include_str!("../schemas/capabilities/native-naming-contract.json"))
        .map_err(|_| "table")?;
    let kinds = table["kind_policies"].as_array().ok_or("kind policies")?;
    assert_eq!(kinds.len(), 35);
    let mut profiles = 0;
    for kind in kinds {
        let name = kind["kind"].as_str().ok_or("kind")?;
        for api in kind["frozen_api_profiles"].as_array().ok_or("profiles")? {
            profiles += 1;
            let spelling = api["api_version"].as_str().ok_or("api")?;
            for range in api["target_availability_ranges"].as_array().ok_or("ranges")? {
                let minor = |key: &str| -> Result<u8, String> {
                    range[key]
                        .as_str()
                        .and_then(|v| v.strip_prefix("1."))
                        .and_then(|v| v.parse().ok())
                        .ok_or_else(|| "minor".into())
                };
                let first = minor("from")?;
                let last = minor("through")?;
                for version in first..=last {
                    let candidate = if name == "CustomResourceDefinition" {
                        "widgets.example.com"
                    } else {
                        "a.b"
                    };
                    let set = parse(&fixture(spelling, name, candidate))
                        .map_err(|_| format!("dispatch {name}/{spelling}"))?;
                    let findings =
                        validate_for_target_with_intent(&set, &target(version)?, NativeValidationIntent::Unspecified);
                    let invalid = matches!(name, "Namespace" | "Service") || name == "StatefulSet" && version >= 27;
                    assert_eq!(
                        code_at(&findings, FindingCode::NativeFieldInvalid, "/metadata/name"),
                        invalid,
                        "{name}/{spelling}/1.{version}: {findings:?}"
                    );
                    let set = parse(&fixture(spelling, name, "Bad / Ω")).map_err(|_| "invalid acquisition")?;
                    let findings =
                        validate_for_target_with_intent(&set, &target(version)?, NativeValidationIntent::Unspecified);
                    assert!(
                        code_at(&findings, FindingCode::NativeFieldInvalid, "/metadata/name"),
                        "missing dispatch {name}/{spelling}/1.{version}"
                    );
                }
                for version in [first.checked_sub(1), last.checked_add(1)]
                    .into_iter()
                    .flatten()
                    .filter(|version| (20..=37).contains(version))
                {
                    let set = parse(&fixture(spelling, name, "Bad / Ω")).map_err(|_| "unavailable acquisition")?;
                    let findings =
                        validate_for_target_with_intent(&set, &target(version)?, NativeValidationIntent::Unspecified);
                    assert!(
                        findings
                            .iter()
                            .any(|finding| finding.code == FindingCode::UnavailableApi),
                        "{name}/{spelling}/1.{version}"
                    );
                    assert!(
                        !code_at(&findings, FindingCode::NativeFieldInvalid, "/metadata/name"),
                        "naming guessed for unavailable API {name}/{spelling}/1.{version}"
                    );
                }
            }
        }
    }
    assert_eq!(profiles, 48);
    Ok(())
}

#[test]
fn target_graph_rechecks_edited_names_and_keeps_exact_source_identity() -> TestResult {
    use kubernetes_lens::graph::{Reference, ReferenceScope, ReferenceTarget, RelationshipKind};
    use kubernetes_lens::model::GroupVersionKind;
    let mut doc = fixture("v1", "Pod", "subject");
    doc["metadata"]["ownerReferences"] =
        json!([{"apiVersion":"rbac.authorization.k8s.io/v1","kind":"Role","name":"Role Ω","uid":"owner-uid"}]);
    let mut role = fixture("rbac.authorization.k8s.io/v1", "Role", "Role Ω");
    role["metadata"]["uid"] = json!("owner-uid");
    let mut set = parse(&json!({"apiVersion":"v1","kind":"List","items":[doc,role]})).map_err(|_| "owners")?;
    let profile = target(37)?;
    let initial = resolve_references_for_target(&set, &profile);
    assert!(
        initial
            .edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::Resolved(_)))
    );
    let edited = fixture("rbac.authorization.k8s.io/v1", "Role", "Bad/Role");
    let text = serde_json::to_vec(&edited["metadata"]["name"]).map_err(|_| "patch")?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(1),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: &text,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "patch parse")?;
    set.documents_mut()[1]
        .set_field_from_source(FieldPath::parse("/metadata/name").map_err(|_| "path")?, parsed)
        .map_err(|_| "patch apply")?;
    let invalid_ref = Reference {
        from: set.documents()[0].id(),
        path: FieldPath::default(),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::Exact {
            gvk: Some(GroupVersionKind::new("rbac.authorization.k8s.io/v1", "Role").map_err(|_| "gvk")?),
            name: "Bad/Role".into(),
        },
        scope: ReferenceScope::SameNamespace,
    };
    let current = resolve_supplied_references_for_target(&set, &[invalid_ref], &ReferenceContext::default(), &profile);
    assert!(code_at(
        &current.findings,
        FindingCode::NativeFieldInvalid,
        "/metadata/name"
    ));
    assert!(
        current
            .edges
            .iter()
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)))
    );
    assert_eq!(
        set.documents()[1].original_identity().name.value().map(String::as_str),
        Some("Role Ω")
    );
    Ok(())
}

#[test]
fn historical_hazard_has_distinct_actionable_warning_in_both_intents() -> TestResult {
    let mut doc = fixture("v1", "Pod", "valid");
    doc["metadata"]["generateName"] = json!("-");
    let set = parse(&doc).map_err(|_| "hazard parse")?;
    for intent in [NativeValidationIntent::Create, NativeValidationIntent::Unspecified] {
        let findings = validate_for_target_with_intent(&set, &target(20)?, intent);
        let finding = findings
            .iter()
            .find(|finding| finding.code == FindingCode::NativeNamingUnverified)
            .ok_or("missing unverified")?;
        assert_eq!(finding.severity, Severity::Warning);
        assert!(finding.remediation().contains("Create does not establish"));
        assert!(code_at(
            &findings,
            FindingCode::NativeNamingUnverified,
            "/metadata/generateName"
        ));
    }
    let findings = validate_for_target_with_intent(&set, &target(22)?, NativeValidationIntent::Unspecified);
    assert!(code_at(
        &findings,
        FindingCode::NativeFieldInvalid,
        "/metadata/generateName"
    ));
    Ok(())
}

#[test]
fn unrelated_failed_identity_does_not_poison_exact_owner_resolution() -> TestResult {
    let mut pod = fixture("v1", "Pod", "subject");
    pod["metadata"]["ownerReferences"] = json!([{"apiVersion":"rbac.authorization.k8s.io/v1",
        "kind":"Role","name":"Good Role","uid":"exact-owner-uid"}]);
    let mut good = fixture("rbac.authorization.k8s.io/v1", "Role", "Good Role");
    good["metadata"]["uid"] = json!("exact-owner-uid");
    let invalid = fixture("rbac.authorization.k8s.io/v1", "Role", "Bad/Role");
    let mut invalid_namespace = fixture("rbac.authorization.k8s.io/v1", "Role", "Good Role");
    invalid_namespace["metadata"]["namespace"] = json!("Bad/Namespace");
    let set = parse(&json!({"apiVersion":"v1","kind":"List","items":[pod, good, invalid, invalid_namespace]}))
        .map_err(|_| "mixed identities")?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    assert!(code_at(
        &graph.findings,
        FindingCode::NativeFieldInvalid,
        "/metadata/name"
    ));
    assert!(graph.edges.iter().any(
        |edge| edge.reference.relation == kubernetes_lens::graph::RelationshipKind::Owner
            && matches!(&edge.resolution, Resolution::Resolved(ids) if ids == &[set.documents()[1].id()])
    ));
    Ok(())
}

#[test]
fn crd_naming_needs_current_group_and_plural_evidence() -> TestResult {
    for pointer in ["/spec/group", "/spec/names/plural"] {
        for replacement in [None, Some(Value::Null)] {
            let mut crd = fixture(
                "apiextensions.k8s.io/v1",
                "CustomResourceDefinition",
                "widgets.example.test",
            );
            crd["spec"] = json!({"group":"example.test","names":{"plural":"widgets","kind":"Widget"},
                "scope":"Namespaced","versions":[{"name":"v1","served":true,"storage":true,
                    "schema":{"openAPIV3Schema":{"type":"object"}}}]});
            let (parent, field) = pointer.rsplit_once('/').ok_or("pointer")?;
            let map = crd.pointer_mut(parent).and_then(Value::as_object_mut).ok_or("parent")?;
            if let Some(value) = replacement {
                map.insert(field.into(), value);
            } else {
                map.remove(field);
            }
            let set = parse(&crd).map_err(|_| "CRD acquisition")?;
            let findings = validate_for_target_with_intent(&set, &target(37)?, NativeValidationIntent::Unspecified);
            assert!(code_at(&findings, FindingCode::NativeFieldInvalid, "/metadata/name"));
            let graph = resolve_references_for_target(&set, &target(37)?);
            assert!(code_at(
                &graph.findings,
                FindingCode::NativeFieldInvalid,
                "/metadata/name"
            ));
        }
    }
    Ok(())
}

#[test]
fn target_graph_retains_removed_api_diagnostic_without_guessing_name_rules() -> TestResult {
    let doc = fixture("policy/v1beta1", "PodDisruptionBudget", "PDB Ω");
    let set = parse(&doc).map_err(|_| "removed beta")?;
    let graph = resolve_references_for_target(&set, &target(25)?);
    assert!(
        graph
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::UnavailableApi)
    );
    assert!(!code_at(
        &graph.findings,
        FindingCode::NativeFieldInvalid,
        "/metadata/name"
    ));
    Ok(())
}

#[test]
fn edited_crd_name_cannot_reuse_old_naming_evidence() -> TestResult {
    let doc = fixture(
        "apiextensions.k8s.io/v1",
        "CustomResourceDefinition",
        "widgets.example.com",
    );
    let mut set = parse(&doc).map_err(|_| "CRD")?;
    let profile = target(37)?;
    assert!(!code_at(
        &validate_for_target_with_intent(&set, &profile, NativeValidationIntent::Unspecified),
        FindingCode::NativeFieldInvalid,
        "/metadata/name"
    ));
    let null = parse_source(
        SourceInput {
            id: SourceId(1),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: b"null",
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "null patch")?;
    set.documents_mut()[0]
        .set_field_from_source(FieldPath::parse("/spec/group").map_err(|_| "path")?, null)
        .map_err(|_| "stage group patch")?;
    let rejected = resolve_references_for_target(&set, &profile);
    assert!(code_at(
        &rejected.findings,
        FindingCode::UnsupportedSemanticConversion,
        "/spec/group"
    ));
    assert!(
        rejected
            .edges
            .iter()
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)))
    );
    let mut set = parse(&doc).map_err(|_| "fresh CRD")?;
    let changed = parse_source(
        SourceInput {
            id: SourceId(2),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: br#""widgets.changed.example.com""#,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "name patch")?;
    set.documents_mut()[0]
        .set_field_from_source(FieldPath::parse("/metadata/name").map_err(|_| "path")?, changed)
        .map_err(|_| "apply name patch")?;
    let graph = resolve_references_for_target(&set, &profile);
    assert!(code_at(
        &graph.findings,
        FindingCode::NativeFieldInvalid,
        "/metadata/name"
    ));
    assert_eq!(
        set.documents()[0].original_identity().name.value().map(String::as_str),
        Some("widgets.example.com")
    );
    Ok(())
}

#[test]
fn source_free_authoring_preserves_private_rbac_and_refuses_relaxed_service_naming() -> TestResult {
    let mut role = Role::default();
    role.metadata = Presence::Value(Metadata {
        name: Presence::Value("system:reader Ω".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    });
    let set = ResourceSet::from_authored(vec![role.into()], &target(37)?, &AuthoringLimits::default())
        .map_err(|errors| format!("valid RBAC authoring {errors:?}"))?;
    assert_eq!(
        set.documents()[0]
            .identity()
            .map_err(|_| "identity")?
            .name
            .value()
            .map(String::as_str),
        Some("system:reader Ω")
    );
    let errors = generate(&set, &target(37)?, OutputFormat::Json, &options(false))
        .err()
        .ok_or("private authoring leaked")?;
    assert!(
        errors
            .iter()
            .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
    );
    generate(&set, &target(37)?, OutputFormat::Json, &options(true)).map_err(|_| "explicit private authoring")?;

    let mut service = kubernetes_lens::resources::networking::Service::default();
    service.metadata = Presence::Value(Metadata {
        name: Presence::Value("1service".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    });
    let errors = ResourceSet::from_authored(vec![service.into()], &target(37)?, &AuthoringLimits::default())
        .err()
        .ok_or("relaxed Service branch authored")?;
    assert!(code_at(&errors, FindingCode::UnadmittedField, "/metadata/name"));
    assert!(
        errors
            .iter()
            .any(|finding| finding.code == FindingCode::UnadmittedField && finding.severity == Severity::Error)
    );
    Ok(())
}

#[test]
fn invalid_owner_source_cannot_supply_positive_target_evidence() -> TestResult {
    for (name, prefix, minor, code) in [
        ("Bad/Pod", None, 37, FindingCode::NativeFieldInvalid),
        ("valid", Some("-"), 20, FindingCode::NativeNamingUnverified),
    ] {
        let mut pod = fixture("v1", "Pod", name);
        if let Some(prefix) = prefix {
            pod["metadata"]["generateName"] = json!(prefix);
        }
        pod["metadata"]["ownerReferences"] = json!([{"apiVersion":"rbac.authorization.k8s.io/v1",
            "kind":"Role","name":"Good Role","uid":"exact-owner-uid"}]);
        let mut role = fixture("rbac.authorization.k8s.io/v1", "Role", "Good Role");
        role["metadata"]["uid"] = json!("exact-owner-uid");
        let set = parse(&json!({"apiVersion":"v1","kind":"List","items":[pod,role]})).map_err(|_| "owner source")?;
        let profile = target(minor)?;
        let graph = resolve_references_for_target(&set, &profile);
        assert!(code_at(
            &graph.findings,
            code,
            if prefix.is_some() {
                "/metadata/generateName"
            } else {
                "/metadata/name"
            }
        ));
        let edge = graph.edges.first().ok_or("retained owner edge")?;
        assert!(matches!(
            edge.resolution,
            Resolution::Unsupported(kubernetes_lens::graph::SafeReason::InvalidIdentity)
        ));
        assert!(
            edge.evidence
                .iter()
                .all(|field| field.resource == set.documents()[0].id())
        );
        let supplied = resolve_supplied_references_for_target(
            &set,
            std::slice::from_ref(&edge.reference),
            &ReferenceContext::default(),
            &profile,
        );
        assert!(supplied.edges.iter().all(|edge| {
            matches!(
                edge.resolution,
                Resolution::Unsupported(kubernetes_lens::graph::SafeReason::InvalidIdentity)
            ) && edge
                .evidence
                .iter()
                .all(|field| field.resource == set.documents()[0].id())
        }));
        let no_profile = kubernetes_lens::graph::resolve_references(&set);
        assert!(
            no_profile
                .edges
                .iter()
                .any(|edge| matches!(edge.resolution, Resolution::Resolved(_)))
        );
    }
    Ok(())
}

#[test]
fn repeated_failed_long_names_exhaust_lookup_work_without_positive_evidence() -> TestResult {
    use kubernetes_lens::graph::{Reference, ReferenceScope, ReferenceTarget, RelationshipKind};
    use kubernetes_lens::model::GroupVersionKind;
    let prefix = "a".repeat(1024);
    let name = format!("{prefix}valid");
    let mut items = vec![
        fixture("v1", "Pod", "source"),
        fixture("rbac.authorization.k8s.io/v1", "Role", &name),
    ];
    for number in 0..4 {
        items.push(fixture(
            "rbac.authorization.k8s.io/v1",
            "Role",
            &format!("{prefix}/{number}"),
        ));
    }
    let set = parse(&json!({"apiVersion":"v1","kind":"List","items":items})).map_err(|_| "long names")?;
    let reference = Reference {
        from: set.documents()[0].id(),
        path: FieldPath::default(),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::Exact {
            gvk: Some(GroupVersionKind::new("rbac.authorization.k8s.io/v1", "Role").map_err(|_| "gvk")?),
            name,
        },
        scope: ReferenceScope::SameNamespace,
    };
    let context = ReferenceContext {
        processing: Some(NativeProcessingLimits {
            max_processing_units: 512_000,
            ..NativeProcessingLimits::default()
        }),
        ..ReferenceContext::default()
    };
    let profile = target(37)?;
    let one = resolve_supplied_references_for_target(&set, std::slice::from_ref(&reference), &context, &profile);
    assert!(
        !one.findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded)
    );
    assert!(
        one.edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::Resolved(_)))
    );
    let references = vec![reference; 64];
    let ordinary = resolve_supplied_references_for_target(&set, &references, &ReferenceContext::default(), &profile);
    assert!(
        !ordinary
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded)
    );
    assert!(
        ordinary
            .edges
            .iter()
            .all(|edge| matches!(edge.resolution, Resolution::Resolved(_)))
    );
    let exhausted = resolve_supplied_references_for_target(&set, &references, &context, &profile);
    assert!(
        exhausted
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
    );
    assert!(
        exhausted
            .edges
            .iter()
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)) && edge.evidence.is_empty())
    );
    Ok(())
}

#[test]
fn ordinary_generated_prefix_keeps_output_eligibility_while_broader_prefix_is_private() -> TestResult {
    for (prefix, private) in [("ordinary-", false), (".-", true)] {
        let mut doc = fixture("v1", "Pod", "valid");
        doc["metadata"]["generateName"] = json!(prefix);
        let set = parse(&doc).map_err(|_| "prefix")?;
        let ordinary = generate(&set, &target(37)?, OutputFormat::Json, &options(false));
        if private {
            let errors = ordinary.err().ok_or("broader prefix leaked")?;
            assert!(
                errors
                    .iter()
                    .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
            );
        } else {
            ordinary.map_err(|errors| format!("ordinary prefix generation {errors:?}"))?;
        }
        let artifact =
            generate(&set, &target(37)?, OutputFormat::Json, &options(true)).map_err(|_| "explicit prefix")?;
        let value: Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
                .map_err(|_| "prefix output")?;
        assert_eq!(value["metadata"]["generateName"], prefix);
    }
    Ok(())
}

fn custom_set(name: &str, crd_name: &str) -> Result<ResourceSet, Vec<Finding>> {
    let mut crd = fixture("apiextensions.k8s.io/v1", "CustomResourceDefinition", crd_name);
    crd["spec"]["group"] = json!("example.test");
    crd["spec"]["versions"][0]["schema"] = json!({"openAPIV3Schema":{"type":"object"}});
    let custom = fixture("example.test/v1", "Widget", name);
    let pod = fixture("v1", "Pod", "source");
    parse(&json!({"apiVersion":"v1","kind":"List","items":[crd,custom,pod]}))
}

fn custom_ordinary_references(set: &ResourceSet, name: &str) -> Result<Vec<kubernetes_lens::graph::Reference>, String> {
    use kubernetes_lens::graph::{ExternalRefKind, Reference, ReferenceScope, ReferenceTarget, RelationshipKind};
    use kubernetes_lens::model::GroupVersionKind;
    let gvk = GroupVersionKind::new("example.test/v1", "Widget").map_err(|_| "gvk")?;
    let exact = Reference {
        from: set.documents()[2].id(),
        path: FieldPath::default(),
        relation: RelationshipKind::Dependency,
        target: ReferenceTarget::Exact {
            gvk: Some(gvk.clone()),
            name: name.into(),
        },
        scope: ReferenceScope::SameNamespace,
    };
    let from_custom = Reference {
        from: set.documents()[1].id(),
        target: ReferenceTarget::Exact {
            gvk: Some(GroupVersionKind::new("v1", "Pod").map_err(|_| "Pod gvk")?),
            name: "source".into(),
        },
        ..exact.clone()
    };
    let owner = Reference {
        relation: RelationshipKind::Owner,
        target: ReferenceTarget::Owner {
            gvk,
            uid: Presence::Absent,
            name: Presence::Value(name.into()),
        },
        ..exact.clone()
    };
    let external = Reference {
        from: set.documents()[1].id(),
        target: ReferenceTarget::External {
            kind: ExternalRefKind::Other,
        },
        ..exact.clone()
    };
    let mislabelled_operator = Reference {
        from: set.documents()[1].id(),
        target: ReferenceTarget::External {
            kind: ExternalRefKind::Operator,
        },
        ..exact.clone()
    };
    Ok(vec![exact, from_custom, owner, external, mislabelled_operator])
}

fn assert_custom_supplier_failure(
    name: &str,
    profile: &TargetProfile,
    reference: &kubernetes_lens::graph::Reference,
) -> TestResult {
    use kubernetes_lens::graph::ReferenceTarget;
    let mut invalid_supplier = custom_set(name, "Bad/CRD").map_err(|_| "invalid supplier")?;
    let invalid_graph = resolve_references_for_target(&invalid_supplier, profile);
    assert!(
        invalid_graph
            .edges
            .iter()
            .filter(|edge| matches!(
                edge.reference.target,
                ReferenceTarget::SuppliedCustomResourceVersion { .. }
            ))
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)))
    );
    let empty = parse_source(
        SourceInput {
            id: SourceId(2),
            format: DocumentFormat::Json,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: br#""changed.example.test""#,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "stale patch")?;
    invalid_supplier.documents_mut()[0]
        .set_field_from_source(FieldPath::parse("/metadata/name").map_err(|_| "path")?, empty)
        .map_err(|_| "stage supplier patch")?;
    let stale = resolve_supplied_references_for_target(
        &invalid_supplier,
        std::slice::from_ref(reference),
        &ReferenceContext::default(),
        profile,
    );
    assert!(
        stale
            .edges
            .iter()
            .all(|edge| !matches!(edge.resolution, Resolution::Resolved(_)))
    );
    Ok(())
}

#[test]
fn undeclared_custom_naming_is_unverified_while_rechecked_schema_edges_remain_narrow() -> TestResult {
    use kubernetes_lens::graph::{ExternalRefKind, ReferenceTarget, RelationshipKind};
    use kubernetes_lens::resources::extensions::custom_documents::{CustomDocumentCheck, CustomDocumentGraphStatus};
    for name in ["widget", "Bad/Name"] {
        let set = custom_set(name, "widgets.example.test").map_err(|_| "custom set")?;
        let profile = target(37)?;
        let checks = set
            .check_custom_documents(&profile, NativeProcessingLimits::default())
            .map_err(|_| "schema")?;
        assert!(matches!(checks[0].check(), CustomDocumentCheck::Checked(_)));
        let findings = validate_for_target_with_intent(&set, &profile, NativeValidationIntent::Unspecified);
        assert!(code_at(
            &findings,
            FindingCode::NativeNamingUnverified,
            "/metadata/name"
        ));
        assert!(
            !findings
                .iter()
                .any(|finding| finding.resource == Some(set.documents()[1].id())
                    && finding.code == FindingCode::NativeFieldInvalid)
        );
        let graph = resolve_references_for_target(&set, &profile);
        assert_eq!(graph.custom_documents[0].status(), CustomDocumentGraphStatus::Bound);
        let edge = graph
            .edges
            .iter()
            .find(|edge| {
                matches!(
                    edge.reference.target,
                    ReferenceTarget::SuppliedCustomResourceVersion { .. }
                )
            })
            .ok_or("schema edge")?;
        assert!(matches!(&edge.resolution, Resolution::Resolved(ids) if ids == &[set.documents()[0].id()]));
        assert!(
            graph
                .edges
                .iter()
                .any(|edge| matches!(edge.resolution, Resolution::External(ExternalRefKind::Operator)))
        );
        let references = custom_ordinary_references(&set, name)?;
        let ordinary =
            resolve_supplied_references_for_target(&set, &references, &ReferenceContext::default(), &profile);
        let requested = ordinary
            .edges
            .iter()
            .filter(|edge| {
                matches!(
                    edge.reference.target,
                    ReferenceTarget::Exact { .. } | ReferenceTarget::Owner { .. }
                ) || edge.reference.relation == RelationshipKind::Dependency
                    && matches!(edge.reference.target, ReferenceTarget::External { .. })
            })
            .collect::<Vec<_>>();
        assert_eq!(requested.len(), references.len());
        assert!(
            requested
                .iter()
                .all(|edge| matches!(edge.resolution, Resolution::Unsupported(_)))
        );
        assert_custom_supplier_failure(name, &profile, &edge.reference)?;
    }
    Ok(())
}

#[test]
fn unknown_api_names_keep_private_warning_generation_and_exhaustion_policy() -> TestResult {
    let mut doc = fixture("example.test/v99", "Widget", "Private/Unknown Ω");
    let set = parse(&doc).map_err(|_| "unknown API")?;
    let profile = target(37)?;
    let findings = validate_for_target_with_intent(&set, &profile, NativeValidationIntent::Unspecified);
    let warning = findings
        .iter()
        .find(|finding| finding.code == FindingCode::NativeNamingUnverified)
        .ok_or("warning")?;
    assert_eq!(warning.severity, Severity::Warning);
    assert!(warning.source.is_some());
    assert!(!format!("{warning:?}").contains("Private/Unknown"));
    assert!(generate(&set, &profile, OutputFormat::Json, &options(false)).is_err());
    let artifact = generate(&set, &profile, OutputFormat::Json, &options(true))
        .map_err(|errors| format!("unknown preserve {errors:?}"))?;
    assert!(
        artifact
            .findings()
            .iter()
            .any(|finding| finding.code == FindingCode::NativeNamingUnverified)
    );
    let output: Value =
        serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))
            .map_err(|_| "output")?;
    assert_eq!(output["metadata"]["name"], doc["metadata"]["name"]);
    let exhausted = validate_for_target_with_limits(
        &set,
        &profile,
        NativeValidationIntent::Unspecified,
        &NativeProcessingLimits {
            max_processing_units: 5,
            ..NativeProcessingLimits::default()
        },
    );
    assert!(
        exhausted
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
    );
    doc["metadata"].as_object_mut().ok_or("metadata")?.remove("name");
    doc["metadata"]["generateName"] = json!("prefix-");
    let generated = parse(&doc).map_err(|_| "unknown prefix")?;
    let findings = validate_for_target_with_intent(&generated, &profile, NativeValidationIntent::Unspecified);
    assert!(code_at(
        &findings,
        FindingCode::NativeNamingUnverified,
        "/metadata/generateName"
    ));
    Ok(())
}
