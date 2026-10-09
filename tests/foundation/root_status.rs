//! Independent finite schema-role expectations; no runtime conformance claim.
use super::*;
use crate::{
    capability::TargetProfile,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, OutputIntent,
        ProtectedOutput,
    },
    source::{ObservationPath, ValueOrigin},
};
fn path(value: &str) -> TestResult<FieldPath> {
    FieldPath::parse(value).required()
}
fn set(api: &str, kind: &str, version: Option<KubernetesVersion>) -> TestResult<ResourceSet> {
    let text = format!(
        "apiVersion: {api}\nkind: {kind}\nmetadata: {{name: sample}}\nstatus: {{private: role-test-private}}\n"
    );
    parse_source(
        SourceInput {
            id: SourceId(51),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::ClusterExport,
            source_version: version,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .required()?
    .flatten_resources()
    .required()
}
fn has_status(paths: &[ObservationPath]) -> bool {
    paths.iter().any(|descriptor| descriptor.path.0 == ["status"])
}
#[test]
fn finite_status_roles_match_all_independent_authenticated_gvk_profiles() -> TestResult<()> {
    let evidence: serde_json::Value = serde_json::from_str(include_str!("root-status-role-evidence.json"))?;
    let witness: serde_json::Value = serde_json::from_str(include_str!(
        "../../schemas/capabilities/kubernetes-schema-witnesses.json"
    ))?;
    let schemas = evidence["schemas"].as_array().required()?;
    assert_eq!(schemas.len(), 18);
    for schema in schemas {
        let profile = witness["profiles"]
            .as_array()
            .required()?
            .iter()
            .find(|profile| profile["schema_id"] == schema["schema_id"])
            .required()?;
        assert_eq!(profile["source_sha256"], schema["source_sha256"]);
    }
    let mut yes = std::collections::BTreeSet::new();
    let mut no = std::collections::BTreeSet::new();
    let apis = evidence["apis"].as_array().required()?;
    assert_eq!(apis.len(), 48);
    for api in apis {
        let gvk = GroupVersionKind::new(
            api["api_version"].as_str().required()?,
            api["kind"].as_str().required()?,
        )
        .required()?;
        let first = api["admitted"][0].as_u64().required()?;
        let last = api["admitted"][1].as_u64().required()?;
        let range = api["status"].as_array();
        if range.is_some() {
            yes.insert(gvk.kind.clone());
        } else {
            no.insert(gvk.kind.clone());
        }
        for minor in 20..=37 {
            let expected = if let Some(range) = range {
                first <= u64::from(minor)
                    && u64::from(minor) <= last
                    && range[0].as_u64().required()? <= u64::from(minor)
                    && u64::from(minor) <= range[1].as_u64().required()?
            } else {
                false
            };
            assert_eq!(
                crate::source::root_status_role(&gvk, Some(KubernetesVersion::new(1, minor)?)),
                expected,
                "{gvk:?} {minor}"
            );
        }
        let all = api["status"] == api["admitted"];
        assert_eq!(crate::source::root_status_role(&gvk, None), all);
    }
    assert_eq!(yes.len(), 18);
    assert_eq!(no.len(), 17);
    assert!(yes.is_disjoint(&no));
    for (api, kind) in [
        ("example.test/v1", "Pod"),
        ("v1beta1", "Pod"),
        ("v1", "MadeUp"),
        ("v1", "List"),
        ("v1", "PodList"),
    ] {
        assert!(!crate::source::root_status_role(
            &GroupVersionKind::new(api, kind).required()?,
            Some(KubernetesVersion::MAX)
        ));
    }
    Ok(())
}
#[test]
fn original_source_profile_has_precedence_over_effective_target_roles() -> TestResult<()> {
    let status = path("/status")?;
    for (source, target, original, effective) in [
        (Some(23), 24, false, false),
        (Some(24), 28, true, true),
        (Some(27), 23, true, true),
        (Some(28), 24, false, false),
        (None, 24, false, true),
        (None, 28, false, false),
    ] {
        let resources = set(
            "networking.k8s.io/v1",
            "NetworkPolicy",
            source.map(|minor| KubernetesVersion::new(1, minor)).transpose()?,
        )?;
        let doc = &resources.documents()[0];
        assert_eq!(
            doc.field_evidence.get(&status).required()?.origin == ValueOrigin::Observed,
            original
        );
        let projection = doc
            .project(Some(&TargetProfile::documented_defaults(KubernetesVersion::new(
                1, target,
            )?)))
            .required()?;
        assert_eq!(has_status(&projection.observations), effective);
        assert!(projection.tree.get("status").is_some());
        assert!(doc.original.get("status").is_some());
        assert!(!format!("{resources:?}").contains("role-test-private"));
    }
    Ok(())
}
#[test]
fn list_metadata_roles_never_strip_object_metadata_or_arbitrary_status() -> TestResult<()> {
    for kind in ["List", "PodList"] {
        let text = format!(
            "apiVersion: v1\nkind: {kind}\nmetadata: {{resourceVersion: rv, selfLink: link, continue: cursor, remainingItemCount: 1, uid: private-list-uid, generation: 2, managedFields: [], creationTimestamp: '2026-01-01T00:00:00Z'}}\nstatus: {{private: retained}}\nitems: []\n"
        );
        let resources = input(&text)?.flatten_resources().required()?;
        let options = GenerationOptions {
            intent: OutputIntent::AuthoredIntent,
            json_shape: JsonShape::SingleResource,
            opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
            protected_output: ProtectedOutput::Include,
            ..GenerationOptions::default()
        };
        let artifact = crate::generate(
            &resources,
            &TargetProfile::documented_defaults(KubernetesVersion::MAX),
            OutputFormat::Json,
            &options,
        )
        .required()?;
        let json: serde_json::Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        for member in ["resourceVersion", "selfLink", "continue", "remainingItemCount"] {
            assert!(json["metadata"].get(member).is_none());
        }
        for member in ["uid", "generation", "managedFields", "creationTimestamp"] {
            assert!(json["metadata"].get(member).is_some());
        }
        assert!(json.get("status").is_some());
        assert_eq!(
            artifact
                .findings()
                .iter()
                .filter(|finding| finding.code == FindingCode::ObservedFieldRemoved)
                .count(),
            4
        );
        assert!(
            artifact
                .findings()
                .iter()
                .all(|finding| finding.code != FindingCode::ObservedFieldRemoved || finding.wrapper.is_some())
        );
    }
    Ok(())
}
#[test]
fn positive_workload_status_at_both_bounds_is_removed_only_by_authored_intent() -> TestResult<()> {
    for minor in [20, 37] {
        let text = "apiVersion: v1\nkind: Pod\nmetadata: {name: p, namespace: ns}\nspec: {containers: [{name: main, image: example/app:v1}]}\nstatus: {phase: Running}\n";
        let resources = input(text)?.flatten_resources().required()?;
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?);
        let options = GenerationOptions {
            intent: OutputIntent::AuthoredIntent,
            json_shape: JsonShape::SingleResource,
            opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
            protected_output: ProtectedOutput::Include,
            ..GenerationOptions::default()
        };
        let artifact = crate::generate(&resources, &target, OutputFormat::Json, &options).required()?;
        let json: serde_json::Value =
            serde_json::from_slice(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
        assert!(json.get("status").is_none());
        let options = GenerationOptions {
            intent: OutputIntent::PreserveObservation,
            ..options
        };
        match crate::generate(&resources, &target, OutputFormat::Json, &options) {
            Ok(artifact) => {
                let json: serde_json::Value = serde_json::from_slice(
                    artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                )?;
                assert!(json.get("status").is_some());
            }
            Err(findings) => assert!(
                !findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::ObservedFieldRemoved)
            ),
        }
        assert!(resources.documents()[0].original.get("status").is_some());
    }
    Ok(())
}

#[test]
fn every_exact_gvk_classifies_original_and_effective_root_status_at_admitted_bounds() -> TestResult<()> {
    let evidence: serde_json::Value = serde_json::from_str(include_str!("root-status-role-evidence.json"))?;
    let status = path("/status/private")?;
    for row in evidence["apis"].as_array().required()? {
        for bound in [0, 1] {
            let minor = u8::try_from(row["admitted"][bound].as_u64().required()?)?;
            let version = KubernetesVersion::new(1, minor)?;
            let api = row["api_version"].as_str().required()?;
            let kind = row["kind"].as_str().required()?;
            let expected = if let Some(range) = row["status"].as_array() {
                range[0].as_u64().required()? <= u64::from(minor) && u64::from(minor) <= range[1].as_u64().required()?
            } else {
                false
            };
            let resources = set(api, kind, Some(version)).map_err(|error| format!("{api} {kind} {minor}: {error}"))?;
            let document = &resources.documents()[0];
            assert_eq!(
                document.field_evidence.get(&status).required()?.origin == ValueOrigin::Observed,
                expected,
                "{api} {kind} {minor}"
            );
            let projection = document
                .project(Some(&TargetProfile::documented_defaults(version)))
                .required()?;
            assert_eq!(has_status(&projection.observations), expected, "{api} {kind} {minor}");
        }
    }
    Ok(())
}

#[test]
fn edited_effective_status_keeps_original_evidence_and_current_role() -> TestResult<()> {
    let mut resources = set("v1", "Pod", Some(KubernetesVersion::MAX))?;
    let leaf = path("/status/private")?;
    resources.documents_mut()[0]
        .set_field_from_source(leaf.clone(), input("edited")?)
        .required()?;
    let document = &resources.documents()[0];
    let projection = document
        .project(Some(&TargetProfile::documented_defaults(KubernetesVersion::MAX)))
        .required()?;
    assert!(has_status(&projection.observations));
    assert_eq!(
        projection.tree.get_path(&leaf).and_then(TreeNode::as_str),
        Some("edited")
    );
    assert_eq!(
        document.original.get_path(&leaf).and_then(TreeNode::as_str),
        Some("role-test-private")
    );
    assert_eq!(
        document.field_evidence.get(&leaf).required()?.origin,
        ValueOrigin::Observed
    );
    assert_eq!(
        document
            .effective_evidence(&projection, &leaf, |_, _| true)
            .required()?
            .origin,
        ValueOrigin::Generated
    );
    Ok(())
}

#[test]
fn absent_and_custom_root_status_remain_present_under_both_output_intents() -> TestResult<()> {
    let status_path = path("/status")?;
    for (api, kind) in [("v1", "ConfigMap"), ("v1", "Secret"), ("example.test/v1", "Pod")] {
        let resources = set(api, kind, Some(KubernetesVersion::MAX))?;
        for intent in [OutputIntent::AuthoredIntent, OutputIntent::PreserveObservation] {
            let options = GenerationOptions {
                intent,
                json_shape: JsonShape::SingleResource,
                opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
                protected_output: ProtectedOutput::Include,
                ..GenerationOptions::default()
            };
            let artifact = crate::generate(
                &resources,
                &TargetProfile::documented_defaults(KubernetesVersion::MAX),
                OutputFormat::Json,
                &options,
            )
            .required()?;
            let json: serde_json::Value = serde_json::from_slice(
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            )?;
            assert_eq!(json["status"]["private"], "role-test-private");
            assert!(
                artifact
                    .findings()
                    .iter()
                    .all(|finding| finding.code != FindingCode::ObservedFieldRemoved
                        || finding.path.as_ref() != Some(&status_path))
            );
        }
    }
    Ok(())
}
