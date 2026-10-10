//! Independent finite-access-mode and supplied-occurrence regressions; no native conformance.
use kubernetes_lens::{
    FieldPath, FindingCode,
    capability::{KubernetesVersion, TargetProfile},
    diagnostic::Severity,
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, OpaqueFieldPolicy, OutputFormat, OutputIntent,
        ProtectedOutput,
    },
    model::{Metadata, ResourceSet},
    parse_source,
    resources::workloads::{StatefulSet, StatefulSetClaimTemplate},
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    validate_for_target,
    value::{AccessModeCompleteness, AccessModes, EstablishedVolumeAccessMode as Mode, Presence},
};
use serde_json::{Value, json};
type TestResult<T = ()> = Result<T, Box<dyn std::error::Error>>;
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn set(text: &str) -> TestResult<ResourceSet> {
    parse_source(
        SourceInput {
            id: SourceId(91),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::ClusterExport,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "parse fixture")?
    .flatten_resources()
    .map_err(|_| "flatten fixture".into())
}
fn options() -> GenerationOptions {
    GenerationOptions {
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        protected_output: ProtectedOutput::Include,
        json_shape: JsonShape::SingleResource,
        ..GenerationOptions::default()
    }
}
fn output(set: &ResourceSet, minor: u8, opts: &GenerationOptions) -> TestResult<Value> {
    let artifact = generate(set, &target(minor)?, OutputFormat::Json, opts).map_err(|findings| {
        format!(
            "generation failed: {:?}",
            findings
                .iter()
                .map(|f| (
                    f.code,
                    f.path
                        .as_ref()
                        .map(|p| p.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()))
                ))
                .collect::<Vec<_>>()
        )
    })?;
    Ok(serde_json::from_slice(artifact.reveal_bytes(
        &ExplicitArtifactAccess::explicitly_allow_raw_artifact(),
    ))?)
}
fn paths(set: &ResourceSet, minor: u8, code: FindingCode) -> TestResult<Vec<String>> {
    Ok(validate_for_target(set, &target(minor)?)
        .iter()
        .filter(|f| f.code == code)
        .filter_map(|f| {
            f.path
                .as_ref()
                .map(|p| p.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()).clone())
        })
        .collect())
}
fn stateful(modes: &Value, status: Option<&Value>, count: usize) -> TestResult<String> {
    let claims: Vec<_> = (0..count).map(|i| {
        let mut claim = json!({"metadata":{"name":format!("claim{i}")}, "spec":{"accessModes":modes,"resources":{"requests":{"storage":"1Gi"}}}});
        if let Some(status) = status { claim["status"] = json!({"accessModes":status}); }
        claim
    }).collect();
    Ok(serde_json::to_string(
        &json!({"apiVersion":"apps/v1", "kind":"StatefulSet", "metadata":{"name":"app","namespace":"ns"}, "spec":{"serviceName":"headless", "selector":{"matchLabels":{"app":"web"}}, "template":{"metadata":{"labels":{"app":"web"}},"spec":{"containers":[{"name":"web","image":"i"}]}}, "volumeClaimTemplates":claims}}),
    )?)
}
fn claim(set: &mut ResourceSet, index: usize) -> TestResult<&mut StatefulSetClaimTemplate> {
    let native = set.documents_mut()[0]
        .resource_mut::<StatefulSet>()
        .ok_or("missing stateful root")?;
    let Presence::Value(spec) = &mut native.spec else {
        return Err("missing spec".into());
    };
    let Presence::Value(claims) = &mut spec.volume_claim_templates else {
        return Err("missing claims".into());
    };
    claims.get_mut(index).ok_or_else(|| "missing claim".into())
}
fn modes(set: &mut ResourceSet) -> TestResult<&mut AccessModes> {
    let Presence::Value(spec) = &mut claim(set, 0)?.spec else {
        return Err("missing claim spec".into());
    };
    let Presence::Value(modes) = &mut spec.access_modes else {
        return Err("missing modes".into());
    };
    Ok(modes)
}
fn patch(set: &mut ResourceSet, path: &str, value: &Value) -> TestResult {
    let bytes = serde_json::to_vec(value)?;
    let input = parse_source(
        SourceInput {
            id: SourceId(91),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "parse patch")?;
    set.documents_mut()[0].set_field_from_source(FieldPath::parse(path)?, input)?;
    Ok(())
}
fn denied(set: &ResourceSet, opts: &GenerationOptions) -> TestResult {
    let errors = generate(set, &target(37)?, OutputFormat::Json, opts)
        .err()
        .ok_or("unexpected output")?;
    assert!(errors.iter().any(|f| matches!(
        f.code,
        FindingCode::UnadmittedField | FindingCode::MergeConflict | FindingCode::NativeFieldInvalid
    )));
    Ok(())
}
#[test]
fn finite_construction_preserves_order_duplicates_and_completeness() {
    let values = vec![
        Mode::ReadWriteMany,
        Mode::ReadOnlyMany,
        Mode::ReadWriteOnce,
        Mode::ReadWriteOnce,
    ];
    let modes = AccessModes::new(values.clone());
    let (completeness, selected) = modes.selected();
    assert_eq!(completeness, AccessModeCompleteness::Complete);
    assert_eq!(
        selected.collect::<Vec<_>>(),
        values.into_iter().enumerate().collect::<Vec<_>>()
    );
    assert_eq!(modes.len(), 4);
    assert!(!modes.is_empty());
    assert!(AccessModes::default().is_empty());
    assert_eq!(AccessModes::default().completeness(), AccessModeCompleteness::Complete);
}
#[test]
fn decoded_partial_values_are_indexed_private_and_never_coerced() -> TestResult {
    let sequence = json!([
        "ReadWriteOnce",
        "private-unselected",
        "ReadWriteOncePod",
        "ReadWriteOnce"
    ]);
    let source = stateful(&sequence, None, 1)?;
    let mut resources = set(&source)?;
    let value = modes(&mut resources)?;
    let (complete, selected) = value.selected();
    assert_eq!(complete, AccessModeCompleteness::Partial);
    assert_eq!(
        selected.collect::<Vec<_>>(),
        vec![(0, Mode::ReadWriteOnce), (3, Mode::ReadWriteOnce)]
    );
    let access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(
        value.original_values(&access).collect::<Vec<_>>(),
        vec![
            "ReadWriteOnce",
            "private-unselected",
            "ReadWriteOncePod",
            "ReadWriteOnce"
        ]
    );
    assert_eq!(
        value.unsupported(&access).collect::<Vec<_>>(),
        vec![(1, "private-unselected"), (2, "ReadWriteOncePod")]
    );
    assert!(!format!("{value:?}").contains("private-unselected"));
    assert_eq!(
        paths(&resources, 37, FindingCode::UnadmittedField)?,
        vec![
            "/spec/volumeClaimTemplates/0/spec/accessModes/1",
            "/spec/volumeClaimTemplates/0/spec/accessModes/2"
        ]
    );
    assert!(
        generate(
            &resources,
            &target(37)?,
            OutputFormat::Json,
            &GenerationOptions::default()
        )
        .is_err()
    );
    let artifact = generate(&resources, &target(37)?, OutputFormat::Json, &options()).map_err(|_| "preserve output")?;
    assert!(
        artifact
            .findings()
            .iter()
            .filter(|f| f.code == FindingCode::UnadmittedField)
            .all(|f| f.severity == Severity::Warning)
    );
    assert!(!format!("{:?}", artifact.findings()).contains("private-unselected"));
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"],
        sequence
    );
    assert_eq!(
        resources.documents()[0].source_evidence().reveal_raw(&access),
        source.as_bytes()
    );
    Ok(())
}
#[test]
fn every_rwop_historical_stage_and_preservation_only_root_stays_unadmitted() -> TestResult {
    for kind in ["PersistentVolume", "PersistentVolumeClaim"] {
        let resources = set(&serde_json::to_string(
            &json!({"apiVersion":"v1", "kind":kind, "metadata":if kind == "PersistentVolume" {json!({"name":"storage"})} else {json!({"name":"storage","namespace":"ns"})}, "spec":{"accessModes":["ReadWriteOnce", "ReadWriteOncePod", "ReadWriteMany"]}}),
        )?)?;
        for minor in [20, 22, 25, 28, 29, 37] {
            assert!(paths(&resources, minor, FindingCode::UnadmittedField)?.contains(&"/spec/accessModes/1".into()));
            assert!(
                generate(
                    &resources,
                    &target(minor)?,
                    OutputFormat::Json,
                    &GenerationOptions::default()
                )
                .is_err()
            );
            assert_eq!(
                output(&resources, minor, &options())?["spec"]["accessModes"][1],
                "ReadWriteOncePod"
            );
        }
    }
    Ok(())
}
#[test]
fn neighboring_typed_edits_allow_preservation_but_sequence_edits_do_not() -> TestResult {
    let source = stateful(&json!(["ReadWriteOncePod", "ReadWriteOnce"]), None, 1)?;
    let mut resources = set(&source)?;
    let Presence::Value(spec) = &mut claim(&mut resources, 0)?.spec else {
        return Err("missing spec".into());
    };
    spec.storage_class_name = Presence::Value("neighbor".into());
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"],
        "neighbor"
    );
    let mut resources = set(&source)?;
    let native = resources.documents_mut()[0]
        .resource_mut::<StatefulSet>()
        .ok_or("root")?;
    let Presence::Value(spec) = &mut native.spec else {
        return Err("spec".into());
    };
    spec.service_name = Presence::Value("neighbor-service".into());
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["serviceName"],
        "neighbor-service"
    );
    patch(
        &mut resources,
        "/spec/volumeClaimTemplates/0/spec/storageClassName",
        &json!("neighbor"),
    )?;
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"][0]["spec"]["storageClassName"],
        "neighbor"
    );
    patch(
        &mut resources,
        "/spec/volumeClaimTemplates/0/spec/accessModes",
        &json!(["ReadWriteOnce", "ReadWriteOncePod"]),
    )?;
    denied(&resources, &options())?;
    let mut resources = set(&source)?;
    patch(
        &mut resources,
        "/spec/volumeClaimTemplates/0/spec/accessModes",
        &json!(["new-private-mode", "ReadWriteOnce"]),
    )?;
    denied(&resources, &options())?;
    let mut resources = set(&source)?;
    patch(
        &mut resources,
        "/spec/volumeClaimTemplates/0/spec/accessModes",
        &json!(["ReadWriteMany", "ReadWriteMany"]),
    )?;
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"],
        json!(["ReadWriteMany", "ReadWriteMany"])
    );
    Ok(())
}
#[test]
fn template_reorder_transplant_and_same_position_patch_fail_closed() -> TestResult {
    let source = stateful(&json!(["ReadWriteOncePod"]), None, 2)?;
    let mut resources = set(&source)?;
    let first = claim(&mut resources, 0)?.clone();
    *claim(&mut resources, 1)? = first;
    denied(&resources, &options())?;
    let mut resources = set(&source)?;
    let native = resources.documents_mut()[0]
        .resource_mut::<StatefulSet>()
        .ok_or("root")?;
    let Presence::Value(spec) = &mut native.spec else {
        return Err("spec".into());
    };
    let Presence::Value(claims) = &mut spec.volume_claim_templates else {
        return Err("claims".into());
    };
    claims.swap(0, 1);
    denied(&resources, &options())?;
    let mut resources = set(&source)?;
    let claims = output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"].clone();
    patch(&mut resources, "/spec/volumeClaimTemplates", &claims)?;
    denied(&resources, &options())?;
    Ok(())
}
#[test]
fn source_free_finite_authoring_works_and_copied_partial_holder_cannot_author() -> TestResult {
    let mut resources = set(&stateful(&json!(["ReadWriteOncePod"]), None, 1)?)?;
    let native = resources.documents()[0]
        .resource::<StatefulSet>()
        .ok_or("root")?
        .clone();
    assert!(ResourceSet::from_authored(vec![native.into()], &target(37)?, &AuthoringLimits::default()).is_err());
    *modes(&mut resources)? = AccessModes::new(vec![Mode::ReadOnlyMany, Mode::ReadWriteMany, Mode::ReadWriteMany]);
    let mut native = resources.documents()[0]
        .resource::<StatefulSet>()
        .ok_or("root")?
        .clone();
    // Deliberately replace all source-only metadata rather than borrowing original evidence.
    let metadata = Metadata {
        name: Presence::Value("new".into()),
        namespace: Presence::Value("ns".into()),
        ..Metadata::default()
    };
    native.metadata = Presence::Value(metadata);
    let authored = ResourceSet::from_authored(vec![native.into()], &target(37)?, &AuthoringLimits::default())
        .map_err(|_| "finite authoring")?;
    assert_eq!(
        output(&authored, 37, &options())?["spec"]["volumeClaimTemplates"][0]["spec"]["accessModes"],
        json!(["ReadOnlyMany", "ReadWriteMany", "ReadWriteMany"])
    );
    Ok(())
}
#[test]
fn presence_cardinality_malformed_values_and_duplicates_remain_distinct() -> TestResult {
    for value in [json!([]), Value::Null, json!(["ReadWriteOnce", "ReadWriteOnce"])] {
        let mut resources = set(&stateful(&value, None, 1)?)?;
        assert!(paths(&resources, 37, FindingCode::NativeFieldInvalid)?.is_empty());
        assert!(paths(&resources, 37, FindingCode::UnadmittedField)?.is_empty());
        let Presence::Value(spec) = &claim(&mut resources, 0)?.spec else {
            return Err("spec".into());
        };
        if value.is_null() {
            assert!(matches!(spec.access_modes, Presence::Null));
        } else {
            let Presence::Value(modes) = &spec.access_modes else {
                return Err("modes".into());
            };
            assert_eq!(modes.len(), value.as_array().ok_or("array")?.len());
        }
    }
    for value in [json!([1]), json!({})] {
        let text = stateful(&value, None, 1)?;
        let parsed = parse_source(
            SourceInput {
                id: SourceId(91),
                format: DocumentFormat::Json,
                origin: InputOrigin::ClusterExport,
                source_version: None,
                bytes: text.as_bytes(),
            },
            &ParseLimits::default(),
        )
        .map_err(|_| "parse malformed fixture")?;
        let findings = parsed.flatten_resources().err().ok_or("malformed field accepted")?;
        assert!(findings.iter().any(|f| f.code == FindingCode::NativeFieldInvalid));
        assert!(findings.iter().all(|f| f.code != FindingCode::UnadmittedField));
    }
    let mut document: Value = serde_json::from_str(&stateful(&json!(["ReadWriteOnce"]), None, 1)?)?;
    document["spec"]["volumeClaimTemplates"][0]["spec"]
        .as_object_mut()
        .ok_or("spec")?
        .remove("accessModes");
    assert!(
        paths(
            &set(&serde_json::to_string(&document)?)?,
            37,
            FindingCode::UnadmittedField
        )?
        .is_empty()
    );
    Ok(())
}
#[test]
fn observed_status_is_stripped_before_authored_intent_rejects_unadmitted_values() -> TestResult {
    let resources = set(&stateful(
        &json!(["ReadWriteOnce"]),
        Some(&json!(["ReadWriteOncePod"])),
        1,
    )?)?;
    assert!(
        paths(&resources, 37, FindingCode::UnadmittedField)?
            .contains(&"/spec/volumeClaimTemplates/0/status/accessModes/0".into())
    );
    assert_eq!(
        output(&resources, 37, &options())?["spec"]["volumeClaimTemplates"][0]["status"]["accessModes"],
        json!(["ReadWriteOncePod"])
    );
    let mut opts = options();
    opts.intent = OutputIntent::AuthoredIntent;
    assert!(
        output(&resources, 37, &opts)?["spec"]["volumeClaimTemplates"][0]
            .get("status")
            .is_none()
    );
    Ok(())
}
#[test]
fn generic_ephemeral_access_modes_are_indexed_in_every_served_pod_binding() -> TestResult {
    for (api, kind, minor) in [
        ("v1", "Pod", 37),
        ("apps/v1", "Deployment", 37),
        ("apps/v1", "StatefulSet", 37),
        ("apps/v1", "DaemonSet", 37),
        ("apps/v1", "ReplicaSet", 37),
        ("v1", "ReplicationController", 37),
        ("batch/v1", "Job", 37),
        ("batch/v1beta1", "CronJob", 21),
        ("batch/v1", "CronJob", 37),
    ] {
        let pod = json!({"containers":[{"name":"web","image":"i"}], "restartPolicy":if matches!(kind,"Job"|"CronJob") {"OnFailure"} else {"Always"}, "volumes":[{"name":"data","ephemeral":{"volumeClaimTemplate":{"spec":{"accessModes":["ReadWriteOncePod"],"resources":{"requests":{"storage":"1Gi"}}}}}}]});
        let template = json!({"metadata":{"labels":{"app":"web"}},"spec":pod});
        let (spec, pointer) = match kind {
            "Pod" => (pod, "/spec"),
            "CronJob" => (
                json!({"schedule":"0 * * * *", "jobTemplate":{"spec":{"template":template}}}),
                "/spec/jobTemplate/spec/template/spec",
            ),
            "Job" => (json!({"template":template}), "/spec/template/spec"),
            "ReplicationController" => (
                json!({"selector":{"app":"web"},"template":template}),
                "/spec/template/spec",
            ),
            "StatefulSet" => (
                json!({"serviceName":"headless","selector":{"matchLabels":{"app":"web"}},"template":template}),
                "/spec/template/spec",
            ),
            _ => (
                json!({"selector":{"matchLabels":{"app":"web"}},"template":template}),
                "/spec/template/spec",
            ),
        };
        let resources = set(&serde_json::to_string(
            &json!({"apiVersion":api,"kind":kind,"metadata":{"name":"app","namespace":"ns"},"spec":spec}),
        )?)?;
        let path = format!("{pointer}/volumes/0/ephemeral/volumeClaimTemplate/spec/accessModes/0");
        assert!(
            paths(&resources, minor, FindingCode::UnadmittedField)?.contains(&path),
            "{kind}"
        );
        if kind == "CronJob" && api == "batch/v1beta1" {
            assert!(generate(&resources, &target(minor)?, OutputFormat::Json, &options()).is_err());
            continue;
        }
        assert_eq!(
            output(&resources, minor, &options())?.pointer(&format!(
                "{pointer}/volumes/0/ephemeral/volumeClaimTemplate/spec/accessModes/0"
            )),
            Some(&json!("ReadWriteOncePod"))
        );
    }
    Ok(())
}

#[test]
fn preservation_only_roots_report_malformed_shapes_separately_from_unadmitted_strings() -> TestResult {
    for (value, suffix) in [(json!("ReadWriteOncePod"), ""), (json!([1]), "/0"), (json!({}), "")] {
        let resources = set(&serde_json::to_string(
            &json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"sample"},"spec":{"accessModes":value}}),
        )?)?;
        assert!(
            paths(&resources, 37, FindingCode::NativeFieldInvalid)?.contains(&format!("/spec/accessModes{suffix}"))
        );
        assert!(paths(&resources, 37, FindingCode::UnadmittedField)?.is_empty());
        assert!(generate(&resources, &target(37)?, OutputFormat::Json, &options()).is_err());
    }
    Ok(())
}

#[test]
fn same_source_coordinates_foreign_donors_and_restored_leaf_transplants_are_denied() -> TestResult {
    let source = stateful(&json!(["ReadWriteOncePod"]), None, 1)?;
    // Independent parses deliberately share SourceId, byte offsets and all values.
    let mut original = set(&source)?;
    let mut foreign = set(&source)?;
    let donor = claim(&mut foreign, 0)?.clone();
    *claim(&mut original, 0)? = donor;
    denied(&original, &options())?;
    let mut original = set(&source)?;
    let original_modes = modes(&mut original)?.clone();
    *claim(&mut original, 0)? = claim(&mut foreign, 0)?.clone();
    *modes(&mut original)? = original_modes;
    // Restoring only the original leaf cannot authorize its transplanted owner.
    denied(&original, &options())?;
    Ok(())
}
