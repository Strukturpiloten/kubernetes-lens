//! Independent expected configuration/storage behavior; these checks are not API-server conformance.
use kubernetes_lens::source::ExplicitSourceAccess;
use kubernetes_lens::{
    capability::{KubernetesVersion, TargetProfile},
    generate,
    generation::{ExplicitArtifactAccess, GenerationOptions, OutputFormat, ProtectedOutput},
    model::ResourceSet,
    parse_source,
    resources::configuration_storage::{ConfigMap, PersistentVolume, PersistentVolumeClaim, Secret, StorageClass},
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
};
use std::error::Error;

type TestResult<T> = Result<T, Box<dyn Error>>;
fn set(text: &str) -> TestResult<ResourceSet> {
    let parsed = parse_source(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
    )
    .map_err(|_| std::io::Error::other("source parsing failed"))?;
    Ok(parsed
        .flatten_resources()
        .map_err(|_| std::io::Error::other("resource flattening failed"))?)
}
fn target(minor: u8) -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, minor)?))
}
fn bundle() -> &'static str {
    "---\napiVersion: v1\nkind: ConfigMap\nmetadata: {name: settings, namespace: app}\ndata: {mode: safe}\nbinaryData: {blob: AQID}\n---\napiVersion: v1\nkind: Secret\nmetadata: {name: credentials, namespace: app}\ndata: {token: c2VjcmV0}\nstringData: {next: private-secret}\n---\napiVersion: v1\nkind: PersistentVolumeClaim\nmetadata: {name: claim, namespace: app}\nspec: {accessModes: [ReadWriteOnce], resources: {requests: {storage: 4Gi}}, storageClassName: fast, volumeName: volume}\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: volume}\nspec: {capacity: {storage: 4Gi}, accessModes: [ReadWriteOnce], claimRef: {name: claim, namespace: app}, storageClassName: fast, csi: {driver: example.csi, volumeHandle: disk-1}}\n---\napiVersion: storage.k8s.io/v1\nkind: StorageClass\nmetadata: {name: fast}\nprovisioner: example.csi\nparameters: {tier: gold}\nreclaimPolicy: Retain\nvolumeBindingMode: WaitForFirstConsumer\nallowVolumeExpansion: true\n"
}

#[test]
fn five_native_roots_decode_as_their_exact_served_kinds() -> TestResult<()> {
    let resources = set(bundle())?;
    assert_eq!(resources.documents().len(), 5);
    assert!(resources.documents()[0].resource::<ConfigMap>().is_some());
    assert!(resources.documents()[1].resource::<Secret>().is_some());
    assert!(resources.documents()[2].resource::<PersistentVolumeClaim>().is_some());
    assert!(resources.documents()[3].resource::<PersistentVolume>().is_some());
    assert!(resources.documents()[4].resource::<StorageClass>().is_some());
    Ok(())
}

#[test]
fn secret_data_is_private_and_generation_requires_explicit_output_authorization() -> TestResult<()> {
    let resources = set(bundle())?;
    let secret = resources.documents()[1]
        .resource::<Secret>()
        .ok_or("Secret did not decode")?;
    let debug = format!("{secret:?}");
    assert!(!debug.contains("private-secret"));
    assert!(!debug.contains("c2VjcmV0"));
    let source_access = ExplicitSourceAccess::explicitly_allow_raw_source();
    assert_eq!(
        secret
            .data
            .value()
            .and_then(|data| data.get("token"))
            .map(|bytes| bytes.bytes(&source_access)),
        Some(b"secret".as_slice()),
    );
    let denied = generate(
        &resources,
        &target(37)?,
        OutputFormat::Yaml,
        &GenerationOptions::default(),
    );
    assert!(denied.is_err());
    let options = GenerationOptions {
        protected_output: ProtectedOutput::Include,
        ..GenerationOptions::default()
    };
    let artifact = generate(&resources, &target(37)?, OutputFormat::Yaml, &options)
        .map_err(|_| std::io::Error::other("storage generation failed"))?;
    let output = std::str::from_utf8(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
    assert!(output.contains("private-secret"));
    assert!(output.contains("c2VjcmV0"));
    Ok(())
}

#[test]
fn source_minor_boundaries_and_unserved_storage_class_api_remain_explicit() -> TestResult<()> {
    for minor in [20, 37] {
        let resources = set(bundle())?;
        assert!(
            generate(
                &resources,
                &target(minor)?,
                OutputFormat::Yaml,
                &GenerationOptions {
                    protected_output: ProtectedOutput::Include,
                    ..GenerationOptions::default()
                }
            )
            .is_ok()
        );
    }
    let beta = set(
        "apiVersion: storage.k8s.io/v1beta1\nkind: StorageClass\nmetadata: {name: old}\nprovisioner: example.csi\n",
    )?;
    assert!(beta.documents()[0].resource::<StorageClass>().is_none());
    assert!(!beta.findings().is_empty());
    Ok(())
}

#[test]
fn persistent_volume_node_affinity_uses_native_required_shape_when_supplied_and_authored() -> TestResult<()> {
    use kubernetes_lens::{model::AuthoredResource, source::AuthoringLimits};

    let supplied = set(
        "apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: affinity}\nspec:\n  nfs: {server: storage, path: /vol}\n  nodeAffinity:\n    required:\n      nodeSelectorTerms:\n      - matchExpressions:\n        - {key: topology.kubernetes.io/zone, operator: In, values: [zone-a]}\n        matchFields:\n        - {key: metadata.name, operator: In, values: [node-a]}\n",
    )?;
    let typed = supplied.documents()[0]
        .resource::<PersistentVolume>()
        .cloned()
        .ok_or_else(|| std::io::Error::other("supplied PersistentVolume was not typed"))?;
    let authored = ResourceSet::from_authored(
        vec![AuthoredResource::from(typed)],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .map_err(|_| std::io::Error::other("fresh PersistentVolume authoring failed"))?;

    for resources in [&supplied, &authored] {
        for minor in [20, 37] {
            let artifact = generate(
                resources,
                &target(minor)?,
                OutputFormat::Yaml,
                &GenerationOptions::default(),
            )
            .map_err(|_| std::io::Error::other("PersistentVolume affinity generation failed"))?;
            let output =
                std::str::from_utf8(artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()))?;
            assert!(!output.contains("requiredDuringSchedulingIgnoredDuringExecution"));
            let reparsed = set(output)?;
            let volume = reparsed.documents()[0]
                .resource::<PersistentVolume>()
                .ok_or("generated PersistentVolume did not decode")?;
            let terms = volume
                .spec
                .value()
                .ok_or("volume spec absent")?
                .node_affinity
                .value()
                .ok_or("volume nodeAffinity absent")?
                .required
                .value()
                .ok_or("volume required node selector absent")?
                .node_selector_terms
                .value()
                .ok_or("node selector terms absent")?;
            assert_eq!(terms.len(), 1);
            for (requirements, key, value) in [
                (&terms[0].match_expressions, "topology.kubernetes.io/zone", "zone-a"),
                (&terms[0].match_fields, "metadata.name", "node-a"),
            ] {
                let requirements = requirements.value().ok_or("node selector requirements absent")?;
                assert_eq!(requirements.len(), 1);
                assert_eq!(requirements[0].key.value().map(String::as_str), Some(key));
                assert_eq!(requirements[0].operator.value().map(String::as_str), Some("In"));
                assert_eq!(requirements[0].values.value(), Some(&vec![value.to_owned()]));
            }
            let regenerated = generate(
                &reparsed,
                &target(minor)?,
                OutputFormat::Yaml,
                &GenerationOptions::default(),
            )
            .map_err(|_| std::io::Error::other("reparsed PersistentVolume generation failed"))?;
            assert_eq!(
                regenerated.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
                artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            );
        }
    }
    Ok(())
}

#[test]
fn persistent_volume_secret_references_keep_admitted_namespace_evidence() -> TestResult<()> {
    use kubernetes_lens::{
        graph::{ReferenceScope, ReferenceTarget, resolve_references},
        value::Presence,
    };

    let resources = set(
        "---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: azure}\nspec:\n  azureFile: {secretName: azure-credentials, secretNamespace: secrets, shareName: data}\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: iscsi}\nspec:\n  iscsi: {targetPortal: storage, iqn: iqn.example:disk, lun: 0, secretRef: {name: iscsi-credentials, namespace: iscsi-secrets}}\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: flex}\nspec:\n  flexVolume: {driver: example.com/flex, secretRef: {name: flex-credentials}}\n",
    )?;
    let graph = resolve_references(&resources);
    let azure = graph
        .edges
        .iter()
        .find(|edge| {
            edge.reference
                .path
                .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                == "/spec/azureFile/secretName"
        })
        .ok_or_else(|| std::io::Error::other("AzureFile Secret reference was not collected"))?;
    assert!(matches!(
        azure.reference.scope,
        ReferenceScope::Namespace(Presence::Value(ref namespace)) if namespace == "secrets"
    ));
    assert!(matches!(
        &azure.reference.target,
        ReferenceTarget::CheckedObject { gvk, name, .. } if gvk.kind == "Secret" && name == "azure-credentials"
    ));

    let iscsi = graph
        .edges
        .iter()
        .find(|edge| {
            edge.reference
                .path
                .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                == "/spec/iscsi/secretRef"
        })
        .ok_or_else(|| std::io::Error::other("iSCSI Secret reference was not collected"))?;
    assert!(matches!(
        iscsi.reference.scope,
        ReferenceScope::Namespace(Presence::Value(ref namespace)) if namespace == "iscsi-secrets"
    ));
    assert!(matches!(
        &iscsi.reference.target,
        ReferenceTarget::CheckedObject { gvk, name, .. } if gvk.kind == "Secret" && name == "iscsi-credentials"
    ));

    let flex = graph
        .edges
        .iter()
        .find(|edge| {
            edge.reference
                .path
                .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source())
                == "/spec/flexVolume/secretRef"
        })
        .ok_or_else(|| std::io::Error::other("FlexVolume Secret reference was not collected"))?;
    assert!(matches!(flex.reference.scope, ReferenceScope::Unknown));
    assert!(matches!(
        &flex.reference.target,
        ReferenceTarget::CheckedObject { gvk, name, .. } if gvk.kind == "Secret" && name == "flex-credentials"
    ));
    Ok(())
}

#[test]
fn persistent_volume_storageos_reference_requires_supported_identity_fields() -> TestResult<()> {
    use kubernetes_lens::diagnostic::FindingCode;
    use kubernetes_lens::graph::{ReferenceScope, ReferenceTarget, resolve_references};

    let resources = set(
        "---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: storageos-valid}\nspec:\n  storageos:\n    secretRef: {apiVersion: v1, fieldPath: token, kind: Secret, name: credentials, namespace: secrets, resourceVersion: rv-1, uid: uid-1}\n    volumeName: volume\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: storageos-wrong-kind}\nspec:\n  storageos:\n    secretRef: {kind: Pod, name: not-a-secret, namespace: secrets}\n    volumeName: another\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: storageos-missing-name}\nspec:\n  storageos:\n    secretRef: {namespace: secrets}\n    volumeName: last\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: storageos-empty-namespace}\nspec:\n  storageos:\n    secretRef: {name: credentials, namespace: ''}\n    volumeName: last\n---\napiVersion: v1\nkind: PersistentVolume\nmetadata: {name: csi-empty-namespace}\nspec:\n  csi:\n    driver: example.csi\n    volumeHandle: disk-2\n    nodeStageSecretRef: {name: credentials, namespace: ''}\n",
    )?;
    let graph = resolve_references(&resources);
    assert_eq!(graph.edges.len(), 2);
    let identities: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| matches!(edge.reference.target, ReferenceTarget::CheckedObject { .. }))
        .collect();
    assert_eq!(identities.len(), 1);
    let external: Vec<_> = graph
        .edges
        .iter()
        .filter(|edge| {
            matches!(
                edge.reference.target,
                ReferenceTarget::External {
                    kind: kubernetes_lens::graph::ExternalRefKind::Storage,
                }
            )
        })
        .collect();
    assert_eq!(external.len(), 1);
    assert_eq!(
        external[0]
            .reference
            .path
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "/spec/csi/driver"
    );
    assert_eq!(
        external[0].reference.relation,
        kubernetes_lens::graph::RelationshipKind::Storage
    );
    assert!(matches!(external[0].reference.scope, ReferenceScope::Unknown));
    let reference = &identities[0].reference;
    assert_eq!(
        reference
            .path
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        "/spec/storageos/secretRef"
    );
    assert!(matches!(
        reference.scope,
        ReferenceScope::Namespace(kubernetes_lens::value::Presence::Value(ref namespace)) if namespace == "secrets"
    ));
    assert!(matches!(
        &reference.target,
        ReferenceTarget::CheckedObject { gvk, name, .. } if gvk.kind == "Secret" && name == "credentials"
    ));
    let findings = generate(
        &resources,
        &target(37)?,
        OutputFormat::Yaml,
        &GenerationOptions {
            validation_intent: kubernetes_lens::generation::NativeValidationIntent::Create,
            ..GenerationOptions::default()
        },
    )
    .err()
    .ok_or_else(|| std::io::Error::other("invalid PV Create fields were emitted"))?;
    assert!(
        findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    Ok(())
}

#[test]
fn portworx_source_is_preserved_as_unadmitted_and_cannot_supply_reference_semantics() -> TestResult<()> {
    use kubernetes_lens::graph::resolve_references;

    let resources = set(
        "apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: portworx}\nspec:\n  portworxVolume: {volumeID: volume, secretRef: {name: not-admitted}}\n",
    )?;
    assert!(resolve_references(&resources).edges.is_empty());
    assert!(
        generate(
            &resources,
            &target(37)?,
            OutputFormat::Yaml,
            &GenerationOptions::default(),
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn csi_controller_expand_secret_reference_requires_stable_gate_availability() -> TestResult<()> {
    use kubernetes_lens::capability::{FeatureGateId, FeatureGateState};
    use kubernetes_lens::diagnostic::FindingCode;

    let resources = set(
        "apiVersion: v1\nkind: PersistentVolume\nmetadata: {name: csi}\nspec:\n  csi:\n    driver: example.csi\n    volumeHandle: disk-1\n    controllerExpandSecretRef: {name: expand, namespace: app}\n",
    )?;
    let pre_stable = generate(
        &resources,
        &target(23)?,
        OutputFormat::Yaml,
        &GenerationOptions::default(),
    )
    .err()
    .ok_or_else(|| std::io::Error::other("stable-only CSI expansion member was emitted in 1.23"))?;
    assert!(
        pre_stable
            .iter()
            .any(|finding| finding.code == FindingCode::FeatureGateRequired)
    );

    let mut disabled = target(24)?;
    disabled
        .feature_gates
        .states
        .insert(FeatureGateId::ExpandCSIVolumes, FeatureGateState::Disabled);
    let explicitly_disabled = generate(&resources, &disabled, OutputFormat::Yaml, &GenerationOptions::default())
        .err()
        .ok_or_else(|| std::io::Error::other("explicitly disabled CSI expansion member was emitted"))?;
    assert!(
        explicitly_disabled
            .iter()
            .any(|finding| finding.code == FindingCode::FeatureGateRequired)
    );

    assert!(
        generate(
            &resources,
            &target(37)?,
            OutputFormat::Yaml,
            &GenerationOptions::default(),
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn typed_pv_pvc_access_modes_author_only_finite_values_and_keep_order() -> TestResult<()> {
    use kubernetes_lens::{
        model::{AuthoredResource, Metadata},
        source::AuthoringLimits,
        value::{AccessModeCompleteness, AccessModes, EstablishedVolumeAccessMode as Mode, Presence},
    };
    let mut resources = set(bundle())?;
    let selected = AccessModes::new(vec![Mode::ReadWriteMany, Mode::ReadWriteOnce, Mode::ReadWriteMany]);
    let mut claim = resources.documents()[2]
        .resource::<PersistentVolumeClaim>()
        .cloned()
        .ok_or("claim")?;
    let mut volume = resources.documents()[3]
        .resource::<PersistentVolume>()
        .cloned()
        .ok_or("volume")?;
    let Presence::Value(claim_spec) = &mut claim.spec else {
        return Err("claim spec".into());
    };
    claim_spec.access_modes = Presence::Value(selected.clone());
    let Presence::Value(volume_spec) = &mut volume.spec else {
        return Err("volume spec".into());
    };
    volume_spec.access_modes = Presence::Value(selected);
    claim.metadata = Presence::Value(Metadata {
        name: Presence::Value("fresh-claim".into()),
        namespace: Presence::Value("app".into()),
        ..Metadata::default()
    });
    volume.metadata = Presence::Value(Metadata {
        name: Presence::Value("fresh-volume".into()),
        ..Metadata::default()
    });
    resources = ResourceSet::from_authored(
        vec![AuthoredResource::from(claim), AuthoredResource::from(volume)],
        &target(37)?,
        &AuthoringLimits::default(),
    )
    .map_err(|_| "finite storage authoring failed")?;
    let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    for minor in [20, 37] {
        let artifact = generate(
            &resources,
            &target(minor)?,
            OutputFormat::Yaml,
            &GenerationOptions::default(),
        )
        .map_err(|_| "finite storage generation failed")?;
        let reparsed = set(std::str::from_utf8(artifact.reveal_bytes(&access))?)?;
        let modes = [
            reparsed
                .documents()
                .iter()
                .find_map(|document| document.resource::<PersistentVolumeClaim>())
                .and_then(|root| root.spec.value())
                .and_then(|spec| spec.access_modes.value()),
            reparsed
                .documents()
                .iter()
                .find_map(|document| document.resource::<PersistentVolume>())
                .and_then(|root| root.spec.value())
                .and_then(|spec| spec.access_modes.value()),
        ];
        for modes in modes {
            let (completeness, values) = modes.ok_or("access modes")?.selected();
            assert_eq!(completeness, AccessModeCompleteness::Complete);
            assert_eq!(
                values.collect::<Vec<_>>(),
                vec![
                    (0, Mode::ReadWriteMany),
                    (1, Mode::ReadWriteOnce),
                    (2, Mode::ReadWriteMany)
                ]
            );
        }
        let again = generate(
            &reparsed,
            &target(minor)?,
            OutputFormat::Yaml,
            &GenerationOptions::default(),
        )
        .map_err(|_| "reparsed storage generation failed")?;
        assert_eq!(artifact.reveal_bytes(&access), again.reveal_bytes(&access));
    }
    Ok(())
}

fn typed_storage_modes<'a>(
    resources: &'a ResourceSet,
    kind: &str,
) -> TestResult<&'a kubernetes_lens::value::AccessModes> {
    let modes = match kind {
        "PersistentVolume" => resources.documents()[0]
            .resource::<PersistentVolume>()
            .and_then(|root| root.spec.value())
            .and_then(|spec| spec.access_modes.value()),
        "PersistentVolumeClaim" => resources.documents()[0]
            .resource::<PersistentVolumeClaim>()
            .and_then(|root| root.spec.value())
            .and_then(|spec| spec.access_modes.value()),
        _ => return Err("unexpected storage kind".into()),
    };
    modes.ok_or_else(|| "typed access modes absent".into())
}

#[test]
fn typed_pv_pvc_partial_modes_preserve_only_supplied_destination_and_never_author() -> TestResult<()> {
    use kubernetes_lens::{
        generation::OpaqueFieldPolicy,
        model::AuthoredResource,
        source::AuthoringLimits,
        value::{AccessModeCompleteness, EstablishedVolumeAccessMode as Mode, Presence},
    };
    for kind in ["PersistentVolume", "PersistentVolumeClaim"] {
        let namespace = if kind == "PersistentVolumeClaim" {
            ", namespace: app"
        } else {
            ""
        };
        let source = if kind == "PersistentVolume" {
            "\n  nfs: {server: storage, path: /data}"
        } else {
            ""
        };
        let text = format!(
            "---\napiVersion: v1\nkind: {kind}\nmetadata: {{name: sample{namespace}}}\nspec:\n  accessModes: [ReadWriteOnce, private-future-mode, ReadWriteMany]{source}\n"
        );
        let mut resources = set(&text)?;
        let modes = typed_storage_modes(&resources, kind)?;
        let (completeness, selected) = modes.selected();
        assert_eq!(completeness, AccessModeCompleteness::Partial);
        assert_eq!(
            selected.collect::<Vec<_>>(),
            vec![(0, Mode::ReadWriteOnce), (2, Mode::ReadWriteMany)]
        );
        assert!(!format!("{modes:?}").contains("private-future-mode"));
        assert_eq!(
            modes
                .unsupported(&ExplicitSourceAccess::explicitly_allow_raw_source())
                .collect::<Vec<_>>(),
            vec![(1, "private-future-mode")]
        );
        let native: AuthoredResource = if kind == "PersistentVolume" {
            resources.documents()[0]
                .resource::<PersistentVolume>()
                .cloned()
                .ok_or("volume")?
                .into()
        } else {
            resources.documents()[0]
                .resource::<PersistentVolumeClaim>()
                .cloned()
                .ok_or("claim")?
                .into()
        };
        assert!(ResourceSet::from_authored(vec![native], &target(37)?, &AuthoringLimits::default()).is_err());
        if kind == "PersistentVolume" {
            let root = resources.documents_mut()[0]
                .resource_mut::<PersistentVolume>()
                .ok_or("volume")?;
            let Presence::Value(spec) = &mut root.spec else {
                return Err("spec".into());
            };
            spec.storage_class_name = Presence::Value("neighbor".into());
        } else {
            let root = resources.documents_mut()[0]
                .resource_mut::<PersistentVolumeClaim>()
                .ok_or("claim")?;
            let Presence::Value(spec) = &mut root.spec else {
                return Err("spec".into());
            };
            spec.storage_class_name = Presence::Value("neighbor".into());
        }
        let options = GenerationOptions {
            opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
            protected_output: ProtectedOutput::Include,
            ..GenerationOptions::default()
        };
        let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
        for minor in [20, 37] {
            assert!(
                generate(
                    &resources,
                    &target(minor)?,
                    OutputFormat::Yaml,
                    &GenerationOptions::default()
                )
                .is_err()
            );
            let artifact = generate(&resources, &target(minor)?, OutputFormat::Yaml, &options)
                .map_err(|_| "supplied sequence preservation failed")?;
            let reparsed = set(std::str::from_utf8(artifact.reveal_bytes(&access))?)?;
            let modes = typed_storage_modes(&reparsed, kind)?;
            assert_eq!(
                modes
                    .original_values(&ExplicitSourceAccess::explicitly_allow_raw_source())
                    .collect::<Vec<_>>(),
                vec!["ReadWriteOnce", "private-future-mode", "ReadWriteMany"]
            );
            let again = generate(&reparsed, &target(minor)?, OutputFormat::Yaml, &options)
                .map_err(|_| "reparsed sequence preservation failed")?;
            assert_eq!(artifact.reveal_bytes(&access), again.reveal_bytes(&access));
        }
    }
    Ok(())
}

#[path = "configuration_storage/static_contract.rs"]
mod static_contract;

#[path = "configuration_storage/corrections.rs"]
mod corrections;

#[path = "configuration_storage/pv_contract.rs"]
mod pv_contract;
