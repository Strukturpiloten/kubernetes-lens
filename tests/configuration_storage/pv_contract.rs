//! Independent PV/source expectations from the authenticated specification, never native execution.
use super::{TestResult, set, target};
use kubernetes_lens::{
    diagnostic::{FieldPath, Finding, FindingCode, Severity},
    generate,
    generation::{
        ExplicitArtifactAccess, GenerationOptions, JsonShape, NativeValidationIntent as Intent, OpaqueFieldPolicy,
        OutputFormat, ProtectedOutput,
    },
    model::ResourceSet,
    parse_source,
    processing::NativeProcessingLimits,
    resources::configuration_storage::PersistentVolume,
    source::{AuthoringLimits, DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    validate_for_target_with_intent, validate_for_target_with_limits,
};
use serde_json::{Value, json};
fn volume(branch: &str, source: Value) -> Value {
    let mut value = json!({"apiVersion":"v1","kind":"PersistentVolume","metadata":{"name":"volume"},"spec":{
        "capacity":{"storage":"1Gi"},"accessModes":["ReadWriteOnce"]}});
    value["spec"][branch] = source;
    if branch == "local" {
        value["spec"]["nodeAffinity"] = json!({"required":{"nodeSelectorTerms":[{}]}});
    }
    value
}
fn findings(value: &Value, minor: u8, intent: Intent) -> TestResult<Vec<Finding>> {
    let bytes = serde_json::to_vec(value)?;
    let parsed = parse_source(
        SourceInput {
            id: SourceId(191),
            format: DocumentFormat::Json,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: &bytes,
        },
        &ParseLimits::default(),
    )
    .map_err(|_| "PV parse")?;
    Ok(match parsed.flatten_resources() {
        Ok(resources) => validate_for_target_with_intent(&resources, &target(minor)?, intent),
        Err(findings) => findings,
    })
}
fn invalid(value: &Value, minor: u8, path: &str) -> TestResult<()> {
    let path = FieldPath::parse(path)?;
    assert!(
        findings(value, minor, Intent::Create)?
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid && finding.path.as_ref() == Some(&path)),
        "{}",
        path.reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
    );
    Ok(())
}
fn valid(value: &Value, minor: u8) -> TestResult<()> {
    let findings = findings(value, minor, Intent::Create)?;
    assert!(
        !findings.iter().any(|finding| finding.severity == Severity::Error),
        "{findings:?}"
    );
    Ok(())
}
fn options() -> GenerationOptions {
    GenerationOptions {
        json_shape: JsonShape::SingleResource,
        validation_intent: Intent::Create,
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    }
}
fn selected_sources() -> Vec<(&'static str, Value)> {
    vec![
        ("gcePersistentDisk", json!({"pdName":"disk","partition":0})),
        ("awsElasticBlockStore", json!({"volumeID":"vol-example"})),
        ("hostPath", json!({"path":"relative/path","type":"Directory"})),
        ("glusterfs", json!({"endpoints":"gluster","path":"volume"})),
        ("nfs", json!({"server":"nfs.example","path":"/export"})),
        ("rbd", json!({"monitors":["monitor"],"image":"image"})),
        (
            "iscsi",
            json!({"targetPortal":"target.example:3260","iqn":"iqn.2020-01.example:disk","lun":0}),
        ),
        ("cinder", json!({"volumeID":"id"})),
        ("cephfs", json!({"monitors":["monitor"]})),
        ("fc", json!({"wwids":["id"]})),
        ("flocker", json!({"datasetName":"dataset"})),
        ("flexVolume", json!({"driver":"vendor/driver"})),
        ("azureFile", json!({"secretName":"azure","shareName":"share"})),
        ("vsphereVolume", json!({"volumePath":"disk.vmdk"})),
        ("quobyte", json!({"registry":"registry.example:7861","volume":"volume"})),
        (
            "azureDisk",
            json!({"diskName":"disk","diskURI":"/subscriptions/example","kind":"Managed"}),
        ),
        ("photonPersistentDisk", json!({"pdID":"disk"})),
        (
            "scaleIO",
            json!({"gateway":"gateway","system":"system","volumeName":"volume"}),
        ),
        ("local", json!({"path":"relative/path"})),
        ("storageos", json!({"volumeName":"volume"})),
        ("csi", json!({"driver":"EXAMPLE.CSI","volumeHandle":"handle"})),
    ]
}
#[test]
fn every_selected_pv_source_has_static_create_validation_and_fresh_fixed_points() -> TestResult<()> {
    for (branch, source) in selected_sources() {
        let value = volume(branch, source);
        let supplied = set(&serde_json::to_string(&value)?)?;
        let typed = supplied.documents()[0].resource::<PersistentVolume>().ok_or("PV")?;
        let fresh = ResourceSet::from_authored(vec![typed.clone().into()], &target(37)?, &AuthoringLimits::default())
            .map_err(|_| "PV authoring")?;
        for minor in [20, 37] {
            valid(&value, minor)?;
            for resources in [&supplied, &fresh] {
                let artifact =
                    generate(resources, &target(minor)?, OutputFormat::Json, &options()).map_err(|_| "PV output")?;
                let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
                let again_set = set(std::str::from_utf8(artifact.reveal_bytes(&access))?)?;
                let again = generate(&again_set, &target(minor)?, OutputFormat::Json, &options())
                    .map_err(|_| "PV fixed point")?;
                assert_eq!(artifact.reveal_bytes(&access), again.reveal_bytes(&access));
            }
        }
        let missing = volume(branch, json!({}));
        assert!(
            findings(&missing, 37, Intent::Create)?
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid),
            "{branch}"
        );
    }
    Ok(())
}
#[test]
fn pv_requires_spec_exact_positive_storage_capacity_and_nonempty_selected_modes() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = volume("hostPath", json!({"path":"/data"}));
        for capacity in [
            Value::Null,
            json!({}),
            json!({"cpu":"1"}),
            json!({"storage":"1Gi","cpu":"1"}),
        ] {
            value["spec"]["capacity"] = capacity;
            invalid(&value, minor, "/spec/capacity")?;
        }
        for quantity in ["0", "-1", "-0.1"] {
            value["spec"]["capacity"] = json!({"storage":quantity});
            invalid(&value, minor, "/spec/capacity/storage")?;
        }
        for quantity in ["0.1", "1", "1Gi"] {
            value["spec"]["capacity"] = json!({"storage":quantity});
            valid(&value, minor)?;
        }
        value["spec"]["accessModes"] = json!([]);
        invalid(&value, minor, "/spec/accessModes")?;
        value["spec"] = Value::Null;
        invalid(&value, minor, "/spec")?;
        value.as_object_mut().ok_or("PV object")?.remove("spec");
        invalid(&value, minor, "/spec")?;
        assert!(
            findings(&value, minor, Intent::Unspecified)?
                .iter()
                .any(|finding| finding.code == FindingCode::NativeContextRequired)
        );
    }
    for modes in [
        json!(["ReadWriteOnce"]),
        json!(["ReadOnlyMany"]),
        json!(["ReadWriteMany", "ReadWriteMany"]),
    ] {
        let mut value = volume("hostPath", json!({"path":"data"}));
        value["spec"]["accessModes"] = modes;
        valid(&value, 37)?;
    }
    Ok(())
}
#[test]
fn source_unions_count_portworx_and_stricter_flex_product_boundaries() -> TestResult<()> {
    for minor in [20, 21, 22, 28, 29, 37] {
        let mut value = volume("hostPath", json!({"path":"/data"}));
        for branch in ["flexVolume", "portworxVolume"] {
            value["spec"][branch] = if branch == "flexVolume" {
                json!({"driver":"driver"})
            } else {
                json!({"volumeID":"volume"})
            };
            invalid(&value, minor, "/spec")?;
            value["spec"].as_object_mut().ok_or("spec")?.remove(branch);
        }
        value["spec"]["accessModes"] = json!(["ReadWriteOncePod"]);
        let findings = findings(&value, minor, Intent::Create)?;
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::UnadmittedField)
        );
        let resources = set(&serde_json::to_string(&value)?)?;
        assert!(generate(&resources, &target(minor)?, OutputFormat::Json, &options()).is_ok());
    }
    Ok(())
}
#[test]
fn source_paths_ranges_unions_and_reserved_option_names_use_native_static_domains() -> TestResult<()> {
    for minor in [20, 37] {
        for (branch, source, path) in [
            ("hostPath", json!({"path":"a/../b"}), "/spec/hostPath/path"),
            ("local", json!({"path":"a/../b"}), "/spec/local/path"),
            ("nfs", json!({"server":"server","path":"relative"}), "/spec/nfs/path"),
            (
                "gcePersistentDisk",
                json!({"pdName":"disk","partition":256}),
                "/spec/gcePersistentDisk/partition",
            ),
            (
                "awsElasticBlockStore",
                json!({"volumeID":"disk","partition":-1}),
                "/spec/awsElasticBlockStore/partition",
            ),
            ("fc", json!({"targetWWNs":["target"],"lun":256}), "/spec/fc/lun"),
            ("fc", json!({"targetWWNs":["target"]}), "/spec/fc/lun"),
            (
                "fc",
                json!({"targetWWNs":["target"],"wwids":["id"],"lun":0}),
                "/spec/fc",
            ),
            (
                "flocker",
                json!({"datasetName":"name","datasetUUID":"id"}),
                "/spec/flocker",
            ),
            (
                "flocker",
                json!({"datasetName":"name/part"}),
                "/spec/flocker/datasetName",
            ),
            (
                "flexVolume",
                json!({"driver":"driver","options":{"prefix.K8S.IO/key":"value"}}),
                "/spec/flexVolume/options/prefix.K8S.IO~1key",
            ),
            (
                "azureDisk",
                json!({"diskName":"disk","diskURI":"https://example","kind":"Managed"}),
                "/spec/azureDisk/diskURI",
            ),
            (
                "quobyte",
                json!({"registry":"host","volume":"volume"}),
                "/spec/quobyte/registry",
            ),
        ] {
            invalid(&volume(branch, source), minor, path)?;
        }
        valid(
            &volume("nfs", json!({"server":"arbitrary server","path":"/a/../b"})),
            minor,
        )?;
        valid(&volume("fc", json!({"wwids":["id"],"lun":256})), minor)?;
        valid(&volume("flocker", json!({"datasetUUID":"not-a-uuid"})), minor)?;
        valid(
            &volume(
                "azureDisk",
                json!({"diskName":"disk","diskURI":"arbitrary","kind":null}),
            ),
            minor,
        )?;
        let mut root = volume("hostPath", json!({"path":"/./"}));
        root["spec"]["persistentVolumeReclaimPolicy"] = json!("Recycle");
        invalid(&root, minor, "/spec/persistentVolumeReclaimPolicy")?;
    }
    Ok(())
}
#[test]
fn iscsi_uses_finite_identifier_chap_and_name_composition_rules() -> TestResult<()> {
    for identifier in [
        "iqn.2020-99.example:disk",
        "euiXabcdefghijklmnop",
        "naa.abcdefghijklmnopqrstuvwxyz123456",
    ] {
        valid(&volume("iscsi", json!({"targetPortal":"target","iqn":identifier})), 37)?;
    }
    for (source, path) in [
        (
            json!({"targetPortal":"target","iqn":"not-an-identifier"}),
            "/spec/iscsi/iqn",
        ),
        (
            json!({"targetPortal":"target","iqn":"iqn.2020-01.example:bad name"}),
            "/spec/iscsi/iqn",
        ),
        (
            json!({"targetPortal":"target","iqn":"iqn.2020-01.example:disk","chapAuthSession":true}),
            "/spec/iscsi/secretRef",
        ),
        (
            json!({"targetPortal":"target","iqn":"iqn.2020-01.example:disk","secretRef":{"name":""}}),
            "/spec/iscsi/secretRef/name",
        ),
    ] {
        invalid(&volume("iscsi", source), 37, path)?;
    }
    let mut value = volume(
        "iscsi",
        json!({"targetPortal":"target","iqn":"iqn.2020-01.example:disk","initiatorName":"iqn.2020-01.example:initiator"}),
    );
    value["metadata"]["name"] = json!("v".repeat(58));
    invalid(&value, 37, "/spec/iscsi/initiatorName")?;
    Ok(())
}
#[test]
fn local_affinity_preserves_empty_terms_and_native_option_uncertainty() -> TestResult<()> {
    for minor in [20, 32, 33, 37] {
        let mut value = volume("local", json!({"path":"relative"}));
        valid(&value, minor)?;
        value["spec"].as_object_mut().ok_or("spec")?.remove("nodeAffinity");
        invalid(&value, minor, "/spec/nodeAffinity")?;
        value["spec"]["nodeAffinity"] = json!({});
        invalid(&value, minor, "/spec/nodeAffinity/required")?;
        value["spec"]["nodeAffinity"] = json!({"required":{"nodeSelectorTerms":[]}});
        invalid(&value, minor, "/spec/nodeAffinity/required/nodeSelectorTerms")?;
        for requirement in [
            json!({"key":"key","operator":"In","values":[]}),
            json!({"key":"key","operator":"Exists","values":["x"]}),
            json!({"key":"bad key","operator":"Gt","values":["1"]}),
        ] {
            value["spec"]["nodeAffinity"] =
                json!({"required":{"nodeSelectorTerms":[{"matchExpressions":[requirement]}]}});
            invalid(
                &value,
                minor,
                "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchExpressions/0",
            )?;
        }
        value["spec"]["nodeAffinity"] = json!({"required":{"nodeSelectorTerms":[{"matchExpressions":[{"key":"key","operator":"Gt","values":["not integer"]}]}]}});
        valid(&value, minor)?;
        assert_eq!(
            findings(&value, minor, Intent::Create)?
                .iter()
                .any(|finding| finding.code == FindingCode::NativeContextRequired),
            minor >= 33
        );
        value["spec"]["nodeAffinity"] = json!({"required":{"nodeSelectorTerms":[{"matchFields":[{"key":"metadata.name","operator":"In","values":["node.a"]}]}]}});
        valid(&value, minor)?;
        value["spec"]["nodeAffinity"]["required"]["nodeSelectorTerms"][0]["matchFields"][0]["values"] =
            json!(["node", "other"]);
        invalid(
            &value,
            minor,
            "/spec/nodeAffinity/required/nodeSelectorTerms/0/matchFields/0",
        )?;
    }
    Ok(())
}
#[test]
fn csi_driver_secret_names_and_expansion_keep_version_and_option_boundaries() -> TestResult<()> {
    for minor in [20, 23, 24, 25, 26, 27, 37] {
        let mut value = volume("csi", json!({"driver":"EXAMPLE.CSI","volumeHandle":"handle"}));
        valid(&value, minor)?;
        value["spec"]["csi"]["driver"] = json!("d".repeat(64));
        invalid(&value, minor, "/spec/csi/driver")?;
        value["spec"]["csi"]["driver"] = json!("d".repeat(63));
        valid(&value, minor)?;
        value["spec"]["csi"]["nodePublishSecretRef"] = json!({"name":"secret.name","namespace":"app"});
        if minor <= 24 {
            invalid(&value, minor, "/spec/csi/nodePublishSecretRef/name")?;
        } else {
            valid(&value, minor)?;
            assert_eq!(
                findings(&value, minor, Intent::Create)?
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeContextRequired),
                (25..=26).contains(&minor)
            );
        }
        value["spec"]["csi"]
            .as_object_mut()
            .ok_or("csi")?
            .remove("nodePublishSecretRef");
        value["spec"]["csi"]["nodeStageSecretRef"] = json!({"name":"","namespace":""});
        assert!(
            !findings(&value, minor, Intent::Create)?
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
        );
        value["spec"]["csi"]
            .as_object_mut()
            .ok_or("csi")?
            .remove("nodeStageSecretRef");
        value["spec"]["csi"]["controllerExpandSecretRef"] = json!({"name":"secret","namespace":"app"});
        assert_eq!(
            findings(&value, minor, Intent::Create)?
                .iter()
                .any(|finding| finding.code == FindingCode::UnavailableField),
            minor < 24
        );
    }
    Ok(())
}
#[test]
fn pv_processing_refuses_budget_exhaustion_without_payload_echo() -> TestResult<()> {
    let value = volume(
        "csi",
        json!({"driver":"EXAMPLE.CSI","volumeHandle":"private-volume-marker"}),
    );
    let resources = set(&serde_json::to_string(&value)?)?;
    for limits in [
        NativeProcessingLimits {
            max_processing_units: 0,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    ] {
        let findings = validate_for_target_with_limits(&resources, &target(37)?, Intent::Create, &limits);
        assert!(
            findings
                .iter()
                .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
        );
        assert!(!format!("{findings:?}").contains("private-volume-marker"));
    }
    Ok(())
}

#[test]
fn preservation_and_uncertain_source_domains_remain_explicit() -> TestResult<()> {
    for minor in [20, 37] {
        let mut value = volume("hostPath", json!({"path":"relative"}));
        value["spec"]["accessModes"] = json!(["ReadWriteOncePod"]);
        let supplied = set(&serde_json::to_string(&value)?)?;
        let typed = supplied.documents()[0].resource::<PersistentVolume>().ok_or("PV")?;
        assert!(
            ResourceSet::from_authored(vec![typed.clone().into()], &target(minor)?, &AuthoringLimits::default())
                .is_err()
        );
        let value = volume("portworxVolume", json!({"volumeID":"opaque","vendorFuture":true}));
        let supplied = set(&serde_json::to_string(&value)?)?;
        let report = validate_for_target_with_intent(&supplied, &target(minor)?, Intent::Create);
        assert!(
            report
                .iter()
                .any(|finding| finding.code == FindingCode::UnadmittedField),
            "{report:?}"
        );
        assert!(
            !report
                .iter()
                .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
        );
        assert!(
            generate(
                &supplied,
                &target(minor)?,
                OutputFormat::Json,
                &GenerationOptions {
                    validation_intent: Intent::Create,
                    json_shape: JsonShape::SingleResource,
                    ..Default::default()
                }
            )
            .is_err()
        );
        let artifact = generate(&supplied, &target(minor)?, OutputFormat::Json, &options())
            .map_err(|_| "Portworx preservation")?;
        assert!(
            std::str::from_utf8(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?
                .contains("vendorFuture")
        );
        for (branch, source) in [
            ("hostPath", json!({"path":"a\\..\\b"})),
            ("quobyte", json!({"registry":"[::1]:7861","volume":"volume"})),
        ] {
            let report = findings(&volume(branch, source), minor, Intent::Create)?;
            assert!(
                report
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeContextRequired)
            );
            assert!(
                !report
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
            );
        }
        for spec in [json!([]), json!("invalid"), json!(false)] {
            let mut value = volume("hostPath", json!({"path":"relative"}));
            value["spec"] = spec;
            assert!(
                findings(&value, minor, Intent::Create)?
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
            );
        }
        for reference in [
            json!({}),
            json!({"name":"secret"}),
            json!({"name":"secret","namespace":"bad.namespace"}),
        ] {
            let mut value = volume("csi", json!({"driver":"driver","volumeHandle":"handle"}));
            value["spec"]["csi"]["nodePublishSecretRef"] = reference;
            assert!(
                findings(&value, minor, Intent::Create)?
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
            );
        }
        for branch in ["gcePersistentDisk", "iscsi"] {
            let value = volume(
                branch,
                if branch == "iscsi" {
                    json!({"targetPortal":"target","iqn":"iqn.2020-01.example:disk","lun":null,"vendorFuture":true})
                } else {
                    json!({"pdName":"disk","partition":null,"vendorFuture":true})
                },
            );
            let supplied = set(&serde_json::to_string(&value)?)?;
            let artifact = generate(&supplied, &target(minor)?, OutputFormat::Json, &options())
                .map_err(|_| "scalar source preservation")?;
            let output: Value = serde_json::from_slice(
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            )?;
            assert_eq!(output["spec"][branch], value["spec"][branch]);
        }
    }
    Ok(())
}

#[test]
fn repeated_iscsi_prefixes_consume_the_shared_work_budget_before_rescanning() -> TestResult<()> {
    let value = volume(
        "iscsi",
        json!({"targetPortal":"target","iqn":"iqn.2020-01.".repeat(1024)}),
    );
    let resources = set(&serde_json::to_string(&value)?)?;
    let limits = NativeProcessingLimits {
        max_processing_units: 1_000_000,
        ..NativeProcessingLimits::default()
    };
    let findings = validate_for_target_with_limits(&resources, &target(37)?, Intent::Create, &limits);
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
    );
    assert!(!format!("{findings:?}").contains("iqn.2020-01."));
    Ok(())
}
