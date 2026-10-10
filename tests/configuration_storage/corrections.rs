//! Independent regressions for the five reviewed storage contract gaps.
use super::{TestResult, set, target};
use kubernetes_lens::{
    capability::{FeatureGateId, FeatureGateState},
    diagnostic::{FieldPath, FindingCode, Severity},
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, NativeValidationIntent, OpaqueFieldPolicy, OutputFormat,
        ProtectedOutput,
    },
    graph::{KeyDomain, ReferencePredicate, ReferenceTarget, Resolution, resolve_references_for_target},
    model::ResourceSet,
    resources::configuration_storage::{ConfigMap, PersistentVolumeClaim, Secret},
    source::{AuthoringLimits, ExplicitSourceAccess},
    validate_for_target_with_intent,
};
use serde_json::{Value, json};
fn config() -> Value {
    json!({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"settings","namespace":"app"},"data":{"text":"private-storage-correction-marker"},"binaryData":{"blob":"AQID"}})
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        validation_intent: NativeValidationIntent::Create,
        ..GenerationOptions::default()
    }
}
#[test]
fn pvc_unknown_selector_evidence_cannot_mask_known_label_or_cardinality_errors() -> TestResult<()> {
    let selector_path = FieldPath::parse("/spec/selector")?;
    for minor in [20, 37] {
        for selector in [
            json!({"matchLabels":{"bad key":"valid"},"vendorFuture":true}),
            json!({"matchLabels":{"key":"bad value"},"vendorFuture":true}),
            json!({"matchExpressions":[{"key":"bad key","operator":"Exists","vendorFuture":true}]}),
            json!({"matchExpressions":[{"key":"key","operator":"In","values":[],"vendorFuture":true}]}),
            json!({"matchExpressions":[{"key":"key","operator":"Exists","values":["x"],"vendorFuture":true}]}),
            json!({"matchExpressions":[{"key":"key","operator":"NotIn","values":["bad value"],"vendorFuture":true}]}),
        ] {
            let value = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"claim","namespace":"app"},
                "spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}},"selector":selector}});
            let text = serde_json::to_string(&value)?;
            let resources = set(&text)?;
            let findings = validate_for_target_with_intent(&resources, &target(minor)?, NativeValidationIntent::Create);
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref() == Some(&selector_path))
            );
            assert_eq!(
                resources.documents()[0]
                    .source_evidence()
                    .reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
                text.as_bytes()
            );
        }
        let value = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim","metadata":{"name":"claim","namespace":"app"},
            "spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}},"selector":{"matchLabels":{"key":"valid"},"vendorFuture":true}}});
        let resources = set(&serde_json::to_string(&value)?)?;
        let findings = validate_for_target_with_intent(&resources, &target(minor)?, NativeValidationIntent::Create);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnadmittedField)
        );
        assert!(
            !findings
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
        );
        assert!(resources.documents()[0].resource::<PersistentVolumeClaim>().is_some());
    }
    Ok(())
}
#[test]
fn configmap_text_requires_explicit_access_and_output_permission_in_both_source_paths() -> TestResult<()> {
    let value = config();
    let resources = set(&serde_json::to_string(&value)?)?;
    let root = resources.documents()[0].resource::<ConfigMap>().ok_or("ConfigMap")?;
    assert!(!format!("{root:?}").contains("private-storage-correction-marker"));
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(
        root.data
            .value()
            .and_then(|map| map.get("text"))
            .ok_or("text")?
            .reveal(&access),
        "private-storage-correction-marker"
    );
    let fresh = ResourceSet::from_authored(vec![root.clone().into()], &target(37)?, &AuthoringLimits::default())
        .map_err(|_| "authoring")?;
    for resources in [&resources, &fresh] {
        for minor in [20, 37] {
            let denied = generate(
                resources,
                &target(minor)?,
                OutputFormat::Json,
                &GenerationOptions::default(),
            )
            .err()
            .ok_or("unexpected public output")?;
            assert!(
                denied
                    .iter()
                    .any(|finding| finding.code == FindingCode::ProtectedOutputDenied)
            );
            assert!(!format!("{denied:?}").contains("private-storage-correction-marker"));
            let artifact =
                generate(resources, &target(minor)?, OutputFormat::Json, &options()).map_err(|_| "private output")?;
            let bytes = artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
            let reparsed = set(std::str::from_utf8(bytes)?)?;
            let again =
                generate(&reparsed, &target(minor)?, OutputFormat::Json, &options()).map_err(|_| "reparsed output")?;
            assert_eq!(
                bytes,
                again.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact())
            );
            assert!(std::str::from_utf8(bytes)?.contains("private-storage-correction-marker"));
        }
    }
    Ok(())
}
#[test]
fn immutable_configuration_fields_respect_stable_only_and_removed_control_boundaries() -> TestResult<()> {
    let immutable_path = FieldPath::parse("/immutable")?;
    for kind in ["ConfigMap", "Secret"] {
        for flag in [Value::Null, json!(false), json!(true)] {
            let value = json!({"apiVersion":"v1","kind":kind,"metadata":{"name":"immutable","namespace":"app"},"immutable":flag});
            let resources = set(&serde_json::to_string(&value)?)?;
            for setting in [None, Some(FeatureGateState::Enabled), Some(FeatureGateState::Disabled)] {
                let mut beta = target(20)?;
                if let Some(setting) = setting {
                    beta.feature_gates
                        .states
                        .insert(FeatureGateId::ImmutableEphemeralVolumes, setting);
                }
                let findings = validate_for_target_with_intent(&resources, &beta, NativeValidationIntent::Create);
                assert!(
                    findings
                        .iter()
                        .any(|finding| finding.code == FindingCode::UnavailableField
                            && finding.path.as_ref() == Some(&immutable_path))
                );
                assert!(generate(&resources, &beta, OutputFormat::Json, &options()).is_err());
            }
            for minor in [21, 24, 25, 37] {
                let profile = target(minor)?;
                let findings = validate_for_target_with_intent(&resources, &profile, NativeValidationIntent::Create);
                assert!(!findings.iter().any(|finding| finding.severity == Severity::Error));
                let root = &resources.documents()[0];
                let authored = if kind == "ConfigMap" {
                    root.resource::<ConfigMap>().ok_or("ConfigMap")?.clone().into()
                } else {
                    root.resource::<Secret>().ok_or("Secret")?.clone().into()
                };
                let fresh = ResourceSet::from_authored(vec![authored], &profile, &AuthoringLimits::default())
                    .map_err(|_| "immutable authoring")?;
                for supplied in [&resources, &fresh] {
                    let artifact =
                        generate(supplied, &profile, OutputFormat::Json, &options()).map_err(|_| "immutable output")?;
                    let reparsed = set(std::str::from_utf8(
                        artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                    )?)?;
                    let again = generate(&reparsed, &profile, OutputFormat::Json, &options())
                        .map_err(|_| "immutable fixed point")?;
                    assert_eq!(
                        artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                        again.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact())
                    );
                }
            }
            for state in [FeatureGateState::Enabled, FeatureGateState::Disabled] {
                let mut removed = target(25)?;
                removed
                    .feature_gates
                    .states
                    .insert(FeatureGateId::ImmutableEphemeralVolumes, state);
                assert!(
                    removed
                        .findings()
                        .iter()
                        .any(|finding| finding.severity == Severity::Error)
                );
            }
        }
    }
    Ok(())
}
fn consumer(key: &str) -> Value {
    json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"consumer","namespace":"app"},"spec":{
        "containers":[{"name":"main","image":"image","env":[{"name":"MODE","valueFrom":{"configMapKeyRef":{"name":"settings","key":key}}}]}],
        "volumes":[{"name":"configuration","configMap":{"name":"settings","items":[{"key":"blob","path":"file"}]}}]}})
}
#[test]
fn configmap_env_and_mount_keys_use_separate_domains_and_exact_supplied_evidence() -> TestResult<()> {
    for minor in [20, 37] {
        let bundle = json!({"apiVersion":"v1","kind":"List","items":[config(),consumer("text")]});
        let resources = set(&serde_json::to_string(&bundle)?)?;
        let graph = resolve_references_for_target(&resources, &target(minor)?);
        for (domain, path) in [
            (KeyDomain::ConfigMapText, "/data/text"),
            (KeyDomain::ConfigMapTextOrBinary, "/binaryData/blob"),
        ] {
            let path = FieldPath::parse(path)?;
            let edge = graph
                .edges
                .iter()
                .find(|edge| {
                    matches!(&edge.reference.target, ReferenceTarget::CheckedObject {
                predicate: Some(ReferencePredicate::KeyExists { domain: actual, .. }), .. } if *actual == domain)
                })
                .ok_or("key edge")?;
            assert!(
                matches!(edge.resolution, Resolution::ResolvedSubjects(_)),
                "{domain:?}: {:?}",
                edge.resolution
            );
            assert!(edge.evidence.iter().any(|evidence| evidence.path == path));
        }
        let binary_env = json!({"apiVersion":"v1","kind":"List","items":[config(),consumer("blob")]});
        let graph = resolve_references_for_target(&set(&serde_json::to_string(&binary_env)?)?, &target(minor)?);
        assert!(graph.edges.iter().any(|edge| matches!(
            edge.resolution,
            Resolution::MissingKey {
                domain: KeyDomain::ConfigMapText,
                ..
            }
        )));
        assert!(!format!("{graph:?}").contains("private-storage-correction-marker"));
    }
    Ok(())
}
#[test]
fn malformed_configmap_key_suppliers_never_certify_membership() -> TestResult<()> {
    use kubernetes_lens::{
        parse_source,
        source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
    };
    for data in [
        json!({"text":"valid","bad key":"x"}),
        json!({"text":"valid","blob":"overlap"}),
    ] {
        let mut supplier = config();
        supplier["data"] = data;
        let bundle = json!({"apiVersion":"v1","kind":"List","items":[supplier,consumer("text")]});
        let graph = resolve_references_for_target(&set(&serde_json::to_string(&bundle)?)?, &target(37)?);
        let edge = graph
            .edges
            .iter()
            .find(|edge| {
                matches!(
                    &edge.reference.target,
                    ReferenceTarget::CheckedObject {
                        predicate: Some(ReferencePredicate::KeyExists {
                            domain: KeyDomain::ConfigMapText,
                            ..
                        }),
                        ..
                    }
                )
            })
            .ok_or("malformed supplier edge")?;
        assert!(matches!(edge.resolution, Resolution::Unsupported(_)));
    }
    let mut supplier = config();
    supplier["data"] = json!({"text":{"vendorFuture":"x"}});
    let text = serde_json::to_string(&supplier)?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(189),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "malformed supplier parse")?;
    let findings = parsed
        .flatten_resources()
        .err()
        .ok_or("malformed scalar unexpectedly admitted")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}

#[test]
fn invalid_body_and_absent_configmap_maps_have_no_positive_membership() -> TestResult<()> {
    for oversized in [false, true] {
        let mut supplier = config();
        if oversized {
            supplier["data"]["text"] = json!("x".repeat(1_048_574));
            supplier["data"]["extra"] = json!("xxxx");
        } else {
            supplier.as_object_mut().ok_or("supplier")?.remove("data");
            supplier.as_object_mut().ok_or("supplier")?.remove("binaryData");
        }
        let bundle = json!({"apiVersion":"v1","kind":"List","items":[supplier,consumer("text")]});
        let resources = set(&serde_json::to_string(&bundle)?)?;
        let graph = resolve_references_for_target(&resources, &target(37)?);
        for domain in [KeyDomain::ConfigMapText, KeyDomain::ConfigMapTextOrBinary] {
            let edge = graph.edges.iter().find(|edge| {
                matches!(&edge.reference.target, ReferenceTarget::CheckedObject {
                predicate: Some(ReferencePredicate::KeyExists { domain: actual, .. }), .. } if *actual == domain)
            });
            let Some(edge) = edge else {
                assert!(
                    oversized
                        && graph
                            .findings
                            .iter()
                            .any(|finding| finding.code == FindingCode::LimitExceeded),
                    "{graph:?}"
                );
                assert!(
                    !graph
                        .edges
                        .iter()
                        .any(|edge| matches!(edge.resolution, Resolution::ResolvedSubjects(_)))
                );
                continue;
            };
            if oversized {
                assert!(matches!(edge.resolution, Resolution::Unsupported(_)));
            } else {
                assert!(matches!(edge.resolution, Resolution::MissingKey { .. }));
            }
        }
    }
    let bundle = json!({"apiVersion":"v1","kind":"List","items":[config(),consumer("text")]});
    let resources = set(&serde_json::to_string(&bundle)?)?;
    for limits in [
        kubernetes_lens::processing::NativeProcessingLimits {
            max_processing_units: 0,
            ..Default::default()
        },
        kubernetes_lens::processing::NativeProcessingLimits {
            max_payload_bytes: 0,
            ..Default::default()
        },
    ] {
        let context = kubernetes_lens::graph::ReferenceContext {
            processing: Some(limits),
            ..Default::default()
        };
        let graph =
            kubernetes_lens::graph::resolve_references_with_context_for_target(&resources, &context, &target(37)?);
        assert!(
            graph
                .findings
                .iter()
                .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
        );
        assert!(!format!("{graph:?}").contains("private-storage-correction-marker"));
    }
    Ok(())
}

#[test]
fn secret_env_and_mount_keys_resolve_exact_overlay_evidence_and_refuse_incomplete_suppliers() -> TestResult<()> {
    let consumer = json!({"apiVersion":"v1","kind":"Pod","metadata":{"name":"consumer","namespace":"app"},
        "spec":{"containers":[{"name":"app","image":"example.invalid/app:1",
            "env":[{"name":"PASSWORD","valueFrom":{"secretKeyRef":{"name":"credentials","key":"overlaid"}}}],
            "volumeMounts":[{"name":"credentials","mountPath":"/credentials"}]}],
            "volumes":[{"name":"credentials","secret":{"secretName":"credentials",
                "items":[{"key":"encoded","path":"password"}]}}]}});
    for minor in [20, 37] {
        for shape in [0, 1, 2] {
            let mut secret = json!({"apiVersion":"v1","kind":"Secret","metadata":{"name":"credentials","namespace":"app"},
                "data":{"encoded":"c2VjcmV0","overlaid":"b3JpZ2luYWw="},
                "stringData":{"overlaid":"private-secret-graph-marker"}});
            if shape == 1 {
                secret.as_object_mut().ok_or("secret")?.remove("data");
                secret.as_object_mut().ok_or("secret")?.remove("stringData");
            } else if shape == 2 {
                secret["stringData"]["bad key"] = json!("private-invalid-key-marker");
            }
            let bundle = json!({"apiVersion":"v1","kind":"List","items":[secret,consumer]});
            let resources = set(&serde_json::to_string(&bundle)?)?;
            let graph = resolve_references_for_target(&resources, &target(minor)?);
            let edges: Vec<_> = graph
                .edges
                .iter()
                .filter(|edge| {
                    matches!(
                        &edge.reference.target,
                        ReferenceTarget::CheckedObject {
                            predicate: Some(ReferencePredicate::KeyExists {
                                domain: KeyDomain::Secret,
                                ..
                            }),
                            ..
                        }
                    )
                })
                .collect();
            assert_eq!(edges.len(), 2, "{minor}/{shape}: {graph:?}");
            for edge in edges {
                match shape {
                    0 => {
                        assert!(
                            matches!(edge.resolution, Resolution::ResolvedSubjects(_)),
                            "{minor}: {:?}",
                            edge.resolution
                        );
                        let ReferenceTarget::CheckedObject {
                            predicate: Some(ReferencePredicate::KeyExists { key, .. }),
                            ..
                        } = &edge.reference.target
                        else {
                            return Err("secret key predicate".into());
                        };
                        let expected = if key.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()) == "overlaid"
                        {
                            "/stringData/overlaid"
                        } else {
                            "/data/encoded"
                        };
                        let expected = FieldPath::parse(expected)?;
                        assert!(edge.evidence.iter().any(|evidence| evidence.path == expected));
                    }
                    1 => assert!(matches!(
                        edge.resolution,
                        Resolution::MissingKey {
                            domain: KeyDomain::Secret,
                            ..
                        }
                    )),
                    _ => assert!(matches!(edge.resolution, Resolution::Unsupported(_))),
                }
            }
            assert!(!format!("{graph:?}").contains("private-secret-graph-marker"));
            assert!(!format!("{graph:?}").contains("private-invalid-key-marker"));
        }
    }
    Ok(())
}

#[test]
fn pvc_empty_optional_bindings_preserve_intent_without_invalid_reference_edges() -> TestResult<()> {
    for minor in [20, 37] {
        for volume in [None, Some(""), Some("volume"), Some("missing")] {
            for class in [None, Some(""), Some("fast"), Some("missing")] {
                let mut claim = json!({"apiVersion":"v1","kind":"PersistentVolumeClaim",
                    "metadata":{"name":"claim","namespace":"app"},
                    "spec":{"accessModes":["ReadWriteOnce"],"resources":{"requests":{"storage":"1Gi"}}}});
                for (field, value) in [("volumeName", volume), ("storageClassName", class)] {
                    if let Some(value) = value {
                        claim["spec"][field] = json!(value);
                    }
                }
                let bundle = json!({"apiVersion":"v1","kind":"List","items":[claim,
                    {"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"volume"},
                        "spec":{"capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"],
                            "nfs":{"server":"storage","path":"/data"}}},
                    {"apiVersion":"storage.k8s.io/v1","kind":"StorageClass","metadata":{"name":"fast"},
                        "provisioner":"example.csi"}]});
                let resources = set(&serde_json::to_string(&bundle)?)?;
                let typed = resources.documents()[0]
                    .resource::<PersistentVolumeClaim>()
                    .ok_or("typed claim")?;
                let spec = typed.spec.value().ok_or("claim spec")?;
                assert_eq!(spec.volume_name.value().map(String::as_str), volume);
                assert_eq!(spec.storage_class_name.value().map(String::as_str), class);
                let graph = resolve_references_for_target(&resources, &target(minor)?);
                for (field, value, supplied) in [("volumeName", volume, 1), ("storageClassName", class, 2)] {
                    let path = FieldPath::parse(&format!("/spec/{field}"))?;
                    let edges: Vec<_> = graph
                        .edges
                        .iter()
                        .filter(|edge| edge.reference.from.0 == 0 && edge.reference.path == path)
                        .collect();
                    if value.is_some_and(|name| !name.is_empty()) {
                        assert_eq!(edges.len(), 1);
                        if value == Some("missing") {
                            assert_eq!(edges[0].resolution, Resolution::Missing);
                        } else {
                            assert_eq!(
                                edges[0].resolution,
                                Resolution::ResolvedSubjects(vec![kubernetes_lens::graph::GraphSubject::Object {
                                    resource: kubernetes_lens::diagnostic::ResourceId(supplied)
                                }])
                            );
                        }
                    } else {
                        assert!(
                            edges.is_empty(),
                            "empty/absent {field} produced a reference at 1.{minor}"
                        );
                        assert!(
                            !graph
                                .findings
                                .iter()
                                .any(|finding| finding.path.as_ref() == Some(&path))
                        );
                    }
                }
                let artifact = generate(
                    &resources,
                    &target(minor)?,
                    OutputFormat::Json,
                    &GenerationOptions {
                        json_shape: JsonShape::KubernetesList,
                        ..options()
                    },
                )
                .map_err(|_| "claim intent generation failed")?;
                let reparsed = set(std::str::from_utf8(
                    artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                )?)?;
                let generated_claim = reparsed
                    .documents()
                    .iter()
                    .find_map(|document| document.resource::<PersistentVolumeClaim>())
                    .ok_or("generated claim")?;
                let generated_spec = generated_claim.spec.value().ok_or("generated claim spec")?;
                assert_eq!(generated_spec.volume_name.value().map(String::as_str), volume);
                assert_eq!(generated_spec.storage_class_name.value().map(String::as_str), class);
                let reparsed_graph = resolve_references_for_target(&reparsed, &target(minor)?);
                assert_eq!(reparsed_graph.edges.len(), graph.edges.len());
            }
        }
    }
    Ok(())
}
