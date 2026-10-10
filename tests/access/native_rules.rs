//! Independent native-boundary fixtures drawn from immutable official specification witnesses.
use super::*;
use kubernetes_lens::generation::NativeValidationIntent;

fn create_result(value: &Value, minor: u8) -> TestResult<Result<Value, Vec<Finding>>> {
    let mut options = options();
    options.validation_intent = NativeValidationIntent::Create;
    match generate(&resources(value)?, &target(minor)?, OutputFormat::Json, &options) {
        Ok(artifact) => Ok(Ok(serde_json::from_slice(
            artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
        )?)),
        Err(findings) => Ok(Err(findings)),
    }
}

#[test]
fn hpa_target_api_create_boundary_keeps_native_parser_and_unspecified_context_distinct() -> TestResult {
    for (kind, api, valid_new) in [
        ("Deployment", None, false),
        ("Deployment", Some(""), false),
        ("Deployment", Some("v1"), false),
        ("Deployment", Some("/v1"), false),
        ("Deployment", Some("apps/v1"), true),
        ("Deployment", Some("apps/"), true),
        ("Deployment", Some("apps/v1/extra"), false),
        ("ReplicationController", None, true),
        ("ReplicationController", Some("/"), true),
        ("ReplicationController", Some("v1"), true),
        ("CustomScale", Some("custom.example/v7"), true),
    ] {
        let mut value = hpa("autoscaling/v1");
        value["spec"]["scaleTargetRef"]["kind"] = json!(kind);
        if let Some(api) = api {
            value["spec"]["scaleTargetRef"]["apiVersion"] = json!(api);
        } else {
            value["spec"]["scaleTargetRef"]
                .as_object_mut()
                .required()?
                .remove("apiVersion");
        }
        for minor in [33, 34, 37] {
            let result = create_result(&value, minor)?;
            let valid = minor == 33 || valid_new;
            assert_eq!(result.is_ok(), valid, "{kind} {api:?} at {minor}: {result:?}");
            if let Err(findings) = result {
                assert!(has(&findings, FindingCode::NativeFieldInvalid));
            }
            let set = resources(&value)?;
            let unspecified = validate_for_target(&set, &target(minor)?);
            assert!(!has(&unspecified, FindingCode::NativeFieldInvalid));
            if minor >= 34 && !valid_new {
                assert!(has(&unspecified, FindingCode::NativeContextRequired));
            }
        }
    }
    for name in [".", "..", "a/b", "a%b"] {
        let mut value = hpa("autoscaling/v1");
        value["spec"]["scaleTargetRef"]["name"] = json!(name);
        for minor in [20, 37] {
            assert!(has(
                &create_result(&value, minor)?.err().required()?,
                FindingCode::NativeFieldInvalid
            ));
        }
    }
    Ok(())
}

#[test]
fn quota_scopes_apply_only_native_conflicts_cardinality_and_standard_resource_rules() -> TestResult {
    for (spec, valid) in [
        (json!({"hard":{"pods":"2"},"scopes":["BestEffort","BestEffort"]}), true),
        (
            json!({"hard":{"pods":"2"},"scopes":["BestEffort","NotBestEffort"]}),
            false,
        ),
        (
            json!({"hard":{"pods":"2"},"scopes":["Terminating","NotTerminating"]}),
            false,
        ),
        (
            json!({"hard":{"pods":"2"},"scopes":["BestEffort"],"scopeSelector":{"matchExpressions":[{"scopeName":"NotBestEffort","operator":"Exists"}]}}),
            true,
        ),
        (json!({"hard":{"cpu":"2"},"scopes":["BestEffort"]}), false),
        (json!({"hard":{"cpu":"2"},"scopes":["PriorityClass"]}), true),
        (
            json!({"hard":{"requests.storage":"2Gi"},"scopes":["PriorityClass"]}),
            false,
        ),
        (
            json!({"hard":{"count/widgets.example":"2"},"scopes":["BestEffort"]}),
            true,
        ),
        (
            json!({"hard":{"requests.hugepages-2Mi":"2Mi"},"scopes":["PriorityClass"]}),
            false,
        ),
        (
            json!({"hard":{"requests.ephemeral-storage":"2Gi"},"scopes":["PriorityClass"]}),
            false,
        ),
        (json!({"hard":{"pods":"2"},"scopes":["InventedScope"]}), false),
    ] {
        let value = document("v1", "ResourceQuota", json!({"spec":spec}));
        for minor in [20, 37] {
            assert_eq!(create_result(&value, minor)?.is_ok(), valid, "{value} at {minor}");
        }
    }
    for (scope, boolean) in [("BestEffort", true), ("PriorityClass", false)] {
        for (operator, values) in [
            ("Exists", json!([])),
            ("DoesNotExist", json!([])),
            ("In", json!(["high"])),
            ("NotIn", json!(["low"])),
            ("Exists", json!(["bad"])),
            ("In", json!([])),
            ("", json!([])),
        ] {
            let valid = if boolean {
                operator == "Exists" && values.as_array().required()?.is_empty()
            } else {
                matches!(operator, "In" | "NotIn") && !values.as_array().required()?.is_empty()
                    || matches!(operator, "Exists" | "DoesNotExist") && values.as_array().required()?.is_empty()
            };
            let value = document(
                "v1",
                "ResourceQuota",
                json!({"spec":{"hard":{"pods":"2"},"scopeSelector":{"matchExpressions":[{"scopeName":scope,"operator":operator,"values":values}]}}}),
            );
            assert_eq!(create_result(&value, 37)?.is_ok(), valid, "{scope} {operator} {values}");
        }
    }
    Ok(())
}

#[test]
fn quota_scope_versions_and_reviewed_gate_defaults_are_independent() -> TestResult {
    let value = document(
        "v1",
        "ResourceQuota",
        json!({"spec":{"hard":{"pods":"2"},"scopes":["CrossNamespacePodAffinity"]}}),
    );
    for (minor, expected) in [(20, false), (21, false), (22, true), (23, true), (24, true), (37, true)] {
        assert_eq!(create_result(&value, minor)?.is_ok(), expected, "{minor}");
    }
    for enabled in [false, true] {
        let mut profile = target(21)?;
        profile.feature_gates.states.insert(
            FeatureGateId::PodAffinityNamespaceSelector,
            if enabled {
                FeatureGateState::Enabled
            } else {
                FeatureGateState::Disabled
            },
        );
        assert_eq!(
            generate(&resources(&value)?, &profile, OutputFormat::Json, &options()).is_ok(),
            enabled
        );
    }
    let value = document(
        "v1",
        "ResourceQuota",
        json!({"spec":{"hard":{"persistentvolumeclaims":"2","requests.storage":"4Gi"},"scopes":["VolumeAttributesClass"]}}),
    );
    assert!(create_result(&value, 32)?.is_err());
    assert!(create_result(&value, 33)?.is_ok());
    Ok(())
}

#[test]
fn limit_range_supplied_integral_relationships_have_exact_failure_paths() -> TestResult {
    for (limits, failed_key) in [
        (json!({"min":{"memory":"2"},"max":{"memory":"1"}}), "min"),
        (
            json!({"min":{"memory":"2"},"defaultRequest":{"memory":"1"}}),
            "defaultRequest",
        ),
        (
            json!({"defaultRequest":{"memory":"2"},"max":{"memory":"1"}}),
            "defaultRequest",
        ),
        (
            json!({"defaultRequest":{"memory":"2"},"default":{"memory":"1"}}),
            "defaultRequest",
        ),
        (json!({"min":{"memory":"2"},"default":{"memory":"1"}}), "default"),
        (json!({"default":{"memory":"2"},"max":{"memory":"1"}}), "default"),
        (json!({"maxLimitRequestRatio":{"memory":"0"}}), "maxLimitRequestRatio"),
    ] {
        let mut item = limits;
        item["type"] = json!("Container");
        let value = document("v1", "LimitRange", json!({"spec":{"limits":[item]}}));
        for minor in [20, 37] {
            let findings = create_result(&value, minor)?.err().required()?;
            let expected = path(&format!("/spec/limits/0/{failed_key}/memory"))?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref() == Some(&expected)),
                "{findings:?}"
            );
        }
    }
    let value = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container","min":{"memory":"1Ki"},"max":{"memory":"2Ki"},"default":{"memory":"1024"},"defaultRequest":{"memory":"1Ki"}}]}}),
    );
    for minor in [20, 37] {
        assert!(create_result(&value, minor)?.is_ok());
    }
    Ok(())
}

#[test]
fn limit_range_non_overcommit_pod_and_pvc_rules_do_not_invent_defaults() -> TestResult {
    for (item, valid) in [
        (
            json!({"type":"Container","default":{"example.org/device":"2"},"defaultRequest":{"example.org/device":"1"}}),
            false,
        ),
        (
            json!({"type":"Container","default":{"hugepages-2Mi":"4Mi"},"defaultRequest":{"hugepages-2Mi":"2Mi"}}),
            false,
        ),
        (
            json!({"type":"Container","default":{"memory":"2"},"defaultRequest":{"memory":"1"}}),
            true,
        ),
        (json!({"type":"Pod","default":{"memory":"2"}}), false),
        (json!({"type":"PersistentVolumeClaim"}), false),
        (json!({"type":"PersistentVolumeClaim","min":{"storage":"1Gi"}}), true),
    ] {
        let value = document("v1", "LimitRange", json!({"spec":{"limits":[item]}}));
        for minor in [20, 37] {
            assert_eq!(create_result(&value, minor)?.is_ok(), valid, "{item}");
        }
    }
    let value = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container","min":{"cpu":"1m"},"max":{"cpu":"2m"}}]}}),
    );
    let findings = validate_for_target(&resources(&value)?, &target(37)?);
    assert!(has(&findings, FindingCode::UnadmittedField));
    assert!(!has(&findings, FindingCode::NativeFieldInvalid));
    let generated = output(&resources(&value)?, 37)?;
    assert_eq!(generated["spec"], value["spec"]);
    Ok(())
}

#[test]
fn source_free_limit_range_validation_keeps_cumulative_work_and_terminal_privacy() -> TestResult {
    use kubernetes_lens::{processing::NativeProcessingLimits, validate_for_target_with_limits};
    let value = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container",
        "min":{"memory":"1Ki"},"max":{"memory":"2Ki"},
        "default":{"memory":"2Ki"},"defaultRequest":{"memory":"1Ki"}}]}}),
    );
    let parsed = resources(&value)?;
    let native = parsed.documents()[0].resource::<LimitRange>().required()?.clone();
    let profile = target(37)?;
    let single =
        ResourceSet::from_authored(vec![native.clone().into()], &profile, &AuthoringLimits::default()).required()?;
    assert_eq!(
        single.documents()[0].source_evidence().origin,
        EvidenceOrigin::NativeAuthored
    );
    let mut second = native.clone();
    let Presence::Value(metadata) = &mut second.metadata else {
        return Err("missing authored metadata".into());
    };
    metadata.name = Presence::Value("second".into());
    let pair = ResourceSet::from_authored(
        vec![native.into(), second.into()],
        &profile,
        &AuthoringLimits::default(),
    )
    .required()?;
    let findings_at = |set: &ResourceSet, units| {
        validate_for_target_with_limits(
            set,
            &profile,
            NativeValidationIntent::Create,
            &NativeProcessingLimits {
                max_processing_units: units,
                ..NativeProcessingLimits::default()
            },
        )
    };
    let mut low = 0;
    let mut high = NativeProcessingLimits::default().max_processing_units;
    assert!(!has(&findings_at(&single, high), FindingCode::LimitExceeded));
    while low < high {
        let mid = low + (high - low) / 2;
        if has(&findings_at(&single, mid), FindingCode::LimitExceeded) {
            low = mid + 1;
        } else {
            high = mid;
        }
    }
    assert!(low > 0);
    assert!(!has(&findings_at(&single, low), FindingCode::LimitExceeded));
    for set in [&single, &pair] {
        let findings = findings_at(set, low - 1);
        processing_terminal(&findings);
        assert!(!has(&findings, FindingCode::NativeFieldInvalid));
        assert!(!format!("{findings:?}").contains("memory"));
    }
    // One successful resource cannot restart the operation-wide allowance for the next.
    processing_terminal(&findings_at(&pair, low));
    Ok(())
}

#[test]
fn source_free_limit_range_invalid_relationship_is_attributed_without_defaults() -> TestResult {
    let value = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container",
        "default":{"memory":"1Ki"},"defaultRequest":{"memory":"2Ki"}}]}}),
    );
    let parsed = resources(&value)?;
    let native = parsed.documents()[0].resource::<LimitRange>().required()?.clone();
    let findings = ResourceSet::from_authored(vec![native.into()], &target(37)?, &AuthoringLimits::default())
        .err()
        .required()?;
    let expected = path("/spec/limits/0/defaultRequest/memory")?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                && finding.path.as_ref() == Some(&expected)
                && finding.resource == Some(ResourceId(0)))
    );
    Ok(())
}

#[test]
fn hpa_metric_identifiers_use_path_segments_across_actual_served_api_forms() -> TestResult {
    for (api, minor) in [
        ("autoscaling/v2beta1", 20),
        ("autoscaling/v2beta2", 20),
        ("autoscaling/v2", 23),
        ("autoscaling/v2", 37),
    ] {
        for (name, valid) in [
            ("", false),
            (".", false),
            ("..", false),
            ("a/b", false),
            ("a%b", false),
            ("Upper_case.Name", true),
        ] {
            let mut value = hpa(api);
            let body = if api == "autoscaling/v2beta1" {
                json!({"metricName":name,"targetAverageValue":"1"})
            } else {
                json!({"metric":{"name":name},"target":{"type":"AverageValue","averageValue":"1"}})
            };
            value["spec"]["metrics"] = json!([{"type":"Pods","pods":body}]);
            assert_eq!(create_result(&value, minor)?.is_ok(), valid, "{api} {name}");
        }
    }
    Ok(())
}

#[test]
fn hpa_object_metric_reference_api_is_create_context_but_always_allows_core_group() -> TestResult {
    for (api, valid) in [
        (None, true),
        (Some("v1"), true),
        (Some("/"), true),
        (Some("apps/"), true),
        (Some("apps/v1/extra"), false),
    ] {
        let mut object = json!({"kind":"Deployment","name":"d"});
        if let Some(api) = api {
            object["apiVersion"] = json!(api);
        }
        let mut value = hpa("autoscaling/v2");
        value["spec"]["metrics"] = json!([{"type":"Object","object":{"describedObject":object,"metric":{"name":"metric"},"target":{"type":"Value","value":"1"}}}]);
        for minor in [33, 34, 37] {
            assert_eq!(
                create_result(&value, minor)?.is_ok(),
                minor == 33 || valid,
                "{api:?} at{minor}"
            );
            let findings = validate_for_target(&resources(&value)?, &target(minor)?);
            assert!(!has(&findings, FindingCode::NativeFieldInvalid));
            if minor >= 34 && !valid {
                assert!(has(&findings, FindingCode::NativeContextRequired));
            }
        }
    }
    for (api, minor, key) in [
        ("autoscaling/v2beta1", 20, "target"),
        ("autoscaling/v2beta2", 20, "describedObject"),
        ("autoscaling/v2", 37, "describedObject"),
    ] {
        let mut value = hpa(api);
        let mut object = if api == "autoscaling/v2beta1" {
            json!({"metricName":"metric","targetValue":"1"})
        } else {
            json!({"metric":{"name":"metric"},"target":{"type":"Value","value":"1"}})
        };
        object[key] = json!({"kind":"Bad/Kind","name":"d","apiVersion":"apps/v1"});
        value["spec"]["metrics"] = json!([{"type":"Object","object":object}]);
        assert!(has(
            &create_result(&value, minor)?.err().required()?,
            FindingCode::NativeFieldInvalid
        ));
    }
    Ok(())
}

#[test]
fn hpa_resource_names_and_container_labels_keep_native_source_rules_distinct() -> TestResult {
    let prefix = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(61)
    );
    assert_eq!(prefix.len(), 253);
    for (name, valid_container) in [
        ("", false),
        ("cpu", true),
        ("memory", true),
        ("ephemeral-storage", true),
        ("hugepages-bogus", true),
        ("example.org/device", true),
        ("kubernetes.io/foo", true),
        ("example.kubernetes.io/Foo", true),
        ("storage", false),
        ("gpu", false),
        ("requests.example.org/device", false),
        ("bad/name/extra", false),
        ("example.org/bad value", false),
    ] {
        for source in ["Resource", "ContainerResource"] {
            let mut value = hpa("autoscaling/v2");
            let mut body = json!({"name":name,"target":{"type":"Utilization","averageUtilization":50}});
            let field = if source == "Resource" {
                "resource"
            } else {
                body["container"] = json!("0container");
                "containerResource"
            };
            let mut metric = json!({"type":source});
            metric[field] = body;
            value["spec"]["metrics"] = json!([metric]);
            assert_eq!(
                create_result(&value, 37)?.is_ok(),
                if source == "Resource" {
                    !name.is_empty()
                } else {
                    valid_container
                },
                "{source} {name}"
            );
        }
    }
    let mut value = hpa("autoscaling/v2");
    value["spec"]["metrics"] = json!([{"type":"ContainerResource","containerResource":{"name":format!("{prefix}/device"),"container":"valid","target":{"type":"Utilization","averageUtilization":50}}}]);
    assert!(has(
        &create_result(&value, 37)?.err().required()?,
        FindingCode::NativeFieldInvalid
    ));
    value["spec"]["metrics"][0]["containerResource"]["name"] = json!("cpu");
    for (container, valid) in [
        ("valid-0", true),
        ("0valid", true),
        ("", false),
        ("UPPER", false),
        ("a/b", false),
    ] {
        value["spec"]["metrics"][0]["containerResource"]["container"] = json!(container);
        assert_eq!(create_result(&value, 37)?.is_ok(), valid, "{container}");
    }
    Ok(())
}

#[test]
fn unsupported_selectors_preserve_private_output_and_explicit_graph_outcomes() -> TestResult {
    for (mut value, pointer) in [
        (pdb("policy/v1"), "/spec/selector"),
        (role("ClusterRole"), "/aggregationRule/clusterRoleSelectors/0"),
    ] {
        if value["kind"] == "ClusterRole" {
            value["aggregationRule"] = json!({"clusterRoleSelectors":[{}]});
        }
        *value.pointer_mut(pointer).required()? =
            json!({"matchLabels":{"app":"web"},"vendorFuture":"private-selector"});
        let set = resources(&value)?;
        let findings = validate_for_target(&set, &target(37)?);
        assert!(has(&findings, FindingCode::UnadmittedField));
        assert!(!has(&findings, FindingCode::NativeFieldInvalid));
        assert_eq!(
            output(&set, 37)?.pointer(pointer).required()?["vendorFuture"],
            "private-selector"
        );
        assert!(generate(&set, &target(37)?, OutputFormat::Json, &GenerationOptions::default()).is_err());
        let graph = resolve_references_for_target(&set, &target(37)?);
        assert!(graph.edges.iter().any(|edge| matches!(
            edge.reference.target,
            ReferenceTarget::SubjectSelector { .. }
        ) && matches!(edge.resolution, Resolution::Unsupported(_))));
        assert!(!format!("{graph:?} {findings:?}").contains("private-selector"));
    }
    Ok(())
}

#[test]
fn invalid_binding_groups_and_role_kinds_never_resolve_positive_same_name_identities() -> TestResult {
    let mut bound = binding("RoleBinding");
    bound["subjects"] = json!([{"kind":"ServiceAccount","apiGroup":"foreign.example","name":"sa","namespace":"ns"}]);
    bound["roleRef"]["apiGroup"] = json!("foreign.example");
    let mut sa = document("v1", "ServiceAccount", json!({}));
    sa["metadata"]["name"] = json!("sa");
    let set = resources(&json!({"apiVersion":"v1","kind":"List","items":[bound,sa,role("Role")]}))?;
    let graph = resolve_references_for_target(&set, &target(37)?);
    let edges = graph
        .edges
        .iter()
        .filter(|edge| edge.reference.from == ResourceId(0))
        .collect::<Vec<_>>();
    assert_eq!(
        edges
            .iter()
            .filter(
                |edge| matches!(edge.reference.target, ReferenceTarget::Exact { gvk: None, .. })
                    && matches!(edge.resolution, Resolution::Unsupported(_))
            )
            .count(),
        2
    );
    assert!(
        !edges
            .iter()
            .any(|edge| matches!(edge.resolution, Resolution::ResolvedSubjects(_)))
    );
    Ok(())
}

#[test]
fn runtime_toleration_uniqueness_uses_raw_tuple_and_ignores_seconds_in_both_input_paths() -> TestResult {
    let first = json!({"key":"node","effect":"NoExecute","value":"v","tolerationSeconds":1});
    for (mut second, duplicate) in [
        (first.clone(), true),
        (
            json!({"key":"node","operator":"","effect":"NoExecute","value":"v"}),
            true,
        ),
        (
            json!({"key":"node","operator":"Equal","effect":"NoExecute","value":"v"}),
            false,
        ),
    ] {
        second["tolerationSeconds"] = json!(9);
        let value = document(
            "node.k8s.io/v1",
            "RuntimeClass",
            json!({"handler":"runc","scheduling":{"tolerations":[first,second]}}),
        );
        let set = resources(&value)?;
        assert_eq!(
            has(
                &validate_for_target(&set, &target(37)?),
                FindingCode::NativeFieldInvalid
            ),
            duplicate
        );
        let native = set.documents()[0].resource::<RuntimeClassV1>().required()?.clone();
        let authored = ResourceSet::from_authored(vec![native.into()], &target(37)?, &AuthoringLimits::default());
        assert_eq!(authored.is_err(), duplicate);
    }
    Ok(())
}

#[test]
fn admitted_resource_names_and_native_integer_quantity_domain_are_distinct() -> TestResult {
    for (name, quantity, invalid, unresolved) in [
        ("widgets", "1", true, false),
        ("pods", "0.5", true, false),
        ("pods", "2", false, false),
        ("count/widgets.example", "0.5", true, false),
        ("requests.example.org/device", "0.5", false, false),
        ("example.org/device", "0.5", true, false),
        ("pods", "0.999999", false, true),
        ("pods", "9223372036854776", false, true),
    ] {
        let quota = document("v1", "ResourceQuota", json!({"spec":{"hard":{name:quantity}}}));
        let findings = validate_for_target(&resources(&quota)?, &target(37)?);
        assert_eq!(
            has(&findings, FindingCode::NativeFieldInvalid),
            invalid,
            "{name} {quantity}"
        );
        assert_eq!(
            has(&findings, FindingCode::UnadmittedField),
            unresolved,
            "{name} {quantity}"
        );
    }
    let limit = document(
        "v1",
        "LimitRange",
        json!({"spec":{"limits":[{"type":"Container","min":{"storage":"1"}}]}}),
    );
    assert!(has(
        &validate_for_target(&resources(&limit)?, &target(37)?),
        FindingCode::NativeFieldInvalid
    ));
    for (name, quantity, invalid, unresolved) in [
        ("storage", "1", true, false),
        ("example.org/device", "0.5", true, false),
        ("example.org/device", "2", false, false),
        ("cpu", "500m", false, false),
        ("hugepages-2Mi", "2Mi", false, true),
    ] {
        let value = document(
            "node.k8s.io/v1",
            "RuntimeClass",
            json!({"handler":"runc","overhead":{"podFixed":{name:quantity}}}),
        );
        let findings = validate_for_target(&resources(&value)?, &target(37)?);
        assert_eq!(has(&findings, FindingCode::NativeFieldInvalid), invalid);
        assert_eq!(has(&findings, FindingCode::UnadmittedField), unresolved);
    }
    Ok(())
}

#[test]
fn empty_native_policy_collections_are_distinct_from_absent_or_null_values() -> TestResult {
    for value in [json!({"policies":[]}), json!({})] {
        for direction in ["scaleUp", "scaleDown"] {
            let mut value_hpa = hpa("autoscaling/v2");
            value_hpa["spec"]["behavior"] = json!({direction:value});
            assert_eq!(
                has(
                    &validate_for_target(&resources(&value_hpa)?, &target(37)?),
                    FindingCode::NativeFieldInvalid
                ),
                value.get("policies").is_some()
            );
        }
    }
    for aggregation in [json!({}), json!({"clusterRoleSelectors":[]}), Value::Null] {
        let mut value = role("ClusterRole");
        value["aggregationRule"] = aggregation.clone();
        assert_eq!(
            has(
                &validate_for_target(&resources(&value)?, &target(37)?),
                FindingCode::NativeFieldInvalid
            ),
            !aggregation.is_null()
        );
    }
    Ok(())
}

#[test]
fn limit_range_type_accepts_only_native_kinds_or_qualified_extension_names() -> TestResult {
    for (kind, invalid, unsupported) in [
        ("Pod", false, false),
        ("Container", false, false),
        ("PersistentVolumeClaim", false, false),
        ("Widget", true, false),
        ("bad/name/extra", true, false),
        ("example.org/Widget", false, true),
    ] {
        let value = document(
            "v1",
            "LimitRange",
            json!({"spec":{"limits":[{"type":kind,"max":{"storage":"1Gi"}}]}}),
        );
        let mut value = value;
        if kind == "Pod" || kind == "Container" {
            value["spec"]["limits"][0]["max"] = json!({"memory":"1Gi"});
        }
        let findings = validate_for_target(&resources(&value)?, &target(37)?);
        assert_eq!(has(&findings, FindingCode::NativeFieldInvalid), invalid, "{kind}");
        if !invalid {
            assert_eq!(has(&findings, FindingCode::UnadmittedField), unsupported, "{kind}");
        }
    }
    Ok(())
}

#[test]
fn historical_security_policy_checks_native_escalation_drivers_and_runtime_names() -> TestResult {
    let mut profile = target(20)?;
    profile
        .feature_gates
        .states
        .insert(FeatureGateId::CSIInlineVolume, FeatureGateState::Enabled);
    for (field, value, invalid) in [
        ("allowedFlexVolumes", json!([{"driver":""}]), true),
        ("allowedFlexVolumes", json!([{"driver":"opaque driver"}]), false),
        ("allowedCSIDrivers", json!([{"name":"CSI.Example"}]), false),
        ("allowedCSIDrivers", json!([{"name":"bad_name"}]), true),
        ("allowedCSIDrivers", json!([{"name":"x".repeat(64)}]), true),
        ("runtimeClass", json!({"allowedRuntimeClassNames":["a","a"]}), true),
        ("runtimeClass", json!({"allowedRuntimeClassNames":["*","a"]}), true),
        (
            "runtimeClass",
            json!({"allowedRuntimeClassNames":["*"],"defaultRuntimeClassName":"*"}),
            true,
        ),
        ("runtimeClass", json!({"allowedRuntimeClassNames":["Bad"]}), true),
        (
            "runtimeClass",
            json!({"allowedRuntimeClassNames":["*"],"defaultRuntimeClassName":"a"}),
            false,
        ),
        (
            "runtimeClass",
            json!({"allowedRuntimeClassNames":["x".repeat(64)],"defaultRuntimeClassName":"x".repeat(64)}),
            false,
        ),
    ] {
        let mut policy = psp();
        policy["spec"][field] = value.clone();
        assert_eq!(
            has(
                &validate_for_target(&resources(&policy)?, &profile),
                FindingCode::NativeFieldInvalid
            ),
            invalid,
            "{field}"
        );
        if !invalid && field == "allowedCSIDrivers" {
            // The frozen contract retains pre-stable CSI values but does not admit output during PSP's lifetime.
            let set = resources(&policy)?;
            let native = set.documents()[0].resource::<PodSecurityPolicy>().required()?;
            assert_eq!(
                native.spec.value().required()?.allowed_csi_drivers.value().required()?[0]
                    .name
                    .value()
                    .required()?,
                "CSI.Example"
            );
            assert!(has(
                &generate(&set, &profile, OutputFormat::Json, &options())
                    .err()
                    .required()?,
                FindingCode::FeatureGateRequired
            ));
        } else if !invalid {
            let artifact =
                generate(&resources(&policy)?, &profile, OutputFormat::Json, &options()).map_err(|findings| {
                    format!(
                        "{field}: {:?}",
                        findings
                            .iter()
                            .map(|finding| (
                                finding.code,
                                finding.path.as_ref().map(|path| path.reveal(
                                    &kubernetes_lens::source::ExplicitSourceAccess::explicitly_allow_raw_source()
                                ))
                            ))
                            .collect::<Vec<_>>()
                    )
                })?;
            let generated: Value = serde_json::from_slice(
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            )?;
            assert_eq!(generated["spec"][field], value);
        }
    }
    let mut policy = psp();
    policy["spec"]["defaultAllowPrivilegeEscalation"] = json!(true);
    policy["spec"]["allowPrivilegeEscalation"] = json!(false);
    assert!(has(
        &validate_for_target(&resources(&policy)?, &profile),
        FindingCode::NativeFieldInvalid
    ));
    Ok(())
}
