//! Finite, exact root/helper admission for the storage/configuration cohort.
use crate::{
    capability::{FeatureGateId, FieldAdmission, FieldCapability, KindCapability, KubernetesVersion, MergeStrategy},
    diagnostic::{Finding, FindingCode, Phase},
    model::{GroupVersionKind, ResourceScope},
};
use std::sync::LazyLock;

const fn field(path: &'static str, merge: MergeStrategy) -> FieldCapability {
    FieldCapability {
        path,
        since: KubernetesVersion::MIN,
        feature_gate: None,
        removed: None,
        deprecated: None,
        admission: FieldAdmission::Typed,
        merge,
        semantic_note: None,
    }
}
fn stable_gate_field(path: &'static str, merge: MergeStrategy) -> FieldCapability {
    FieldCapability {
        path,
        since: KubernetesVersion::new(1, 24).unwrap_or(KubernetesVersion::MAX),
        feature_gate: Some(FeatureGateId::ExpandCSIVolumes),
        removed: None,
        deprecated: None,
        admission: FieldAdmission::Typed,
        merge,
        semantic_note: None,
    }
}
fn immutable_field() -> FieldCapability {
    FieldCapability {
        since: KubernetesVersion::new(1, 21).unwrap_or(KubernetesVersion::MAX),
        feature_gate: Some(FeatureGateId::ImmutableEphemeralVolumes),
        semantic_note: Some("Stable-only selection begins at 1.21; beta source evidence is retained at 1.20."),
        ..field("/immutable", MergeStrategy::Scalar)
    }
}
const O: MergeStrategy = MergeStrategy::Object;
const S: MergeStrategy = MergeStrategy::Scalar;
const M: MergeStrategy = MergeStrategy::Map;
const A: MergeStrategy = MergeStrategy::AtomicList;
const META: &[FieldCapability] = &[
    field("/metadata", O),
    field("/metadata/name", S),
    field("/metadata/generateName", S),
    field("/metadata/namespace", S),
    field("/metadata/labels", M),
    field("/metadata/labels/*", S),
    field("/metadata/annotations", M),
    field("/metadata/annotations/*", S),
    field("/metadata/finalizers", A),
    field("/metadata/finalizers/*", S),
    field("/metadata/ownerReferences", MergeStrategy::MapList { keys: &["uid"] }),
    field("/metadata/ownerReferences/*", O),
    field("/metadata/ownerReferences/*/apiVersion", S),
    field("/metadata/ownerReferences/*/kind", S),
    field("/metadata/ownerReferences/*/name", S),
    field("/metadata/ownerReferences/*/uid", S),
    field("/metadata/ownerReferences/*/controller", S),
    field("/metadata/ownerReferences/*/blockOwnerDeletion", S),
];
static CONFIG_MAP_FIELDS: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    vec![
        field("/data", M),
        field("/data/*", S),
        field("/binaryData", M),
        field("/binaryData/*", S),
        immutable_field(),
        // Metadata entries are expanded below by `fields` to avoid prefix admission.
    ]
});
static SECRET_FIELDS: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    vec![
        field("/type", S),
        field("/data", M),
        field("/data/*", S),
        field("/stringData", M),
        field("/stringData/*", S),
        immutable_field(),
    ]
});
const CLAIM_FIELDS: &[FieldCapability] = &[
    field("/spec", O),
    field("/spec/accessModes", A),
    field("/spec/accessModes/*", S),
    field("/spec/selector", O),
    field("/spec/selector/matchLabels", M),
    field("/spec/selector/matchLabels/*", S),
    field("/spec/selector/matchExpressions", A),
    field("/spec/selector/matchExpressions/*", O),
    field("/spec/selector/matchExpressions/*/key", S),
    field("/spec/selector/matchExpressions/*/operator", S),
    field("/spec/selector/matchExpressions/*/values", A),
    field("/spec/selector/matchExpressions/*/values/*", S),
    field("/spec/resources", O),
    field("/spec/resources/requests", M),
    field("/spec/resources/requests/*", S),
    field("/spec/resources/limits", M),
    field("/spec/resources/limits/*", S),
    field("/spec/volumeName", S),
    field("/spec/storageClassName", S),
    field("/spec/volumeMode", S),
    field("/spec/dataSource", O),
    field("/spec/dataSource/apiGroup", S),
    field("/spec/dataSource/kind", S),
    field("/spec/dataSource/name", S),
];
static PV_FIELDS: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    vec![
        field("/spec", O),
        field("/spec/capacity", M),
        field("/spec/capacity/*", S),
        field("/spec/accessModes", A),
        field("/spec/accessModes/*", S),
        field("/spec/claimRef", O),
        field("/spec/claimRef/apiVersion", S),
        field("/spec/claimRef/fieldPath", S),
        field("/spec/claimRef/kind", S),
        field("/spec/claimRef/name", S),
        field("/spec/claimRef/namespace", S),
        field("/spec/claimRef/resourceVersion", S),
        field("/spec/claimRef/uid", S),
        field("/spec/persistentVolumeReclaimPolicy", S),
        field("/spec/storageClassName", S),
        field("/spec/mountOptions", A),
        field("/spec/mountOptions/*", S),
        field("/spec/volumeMode", S),
        field("/spec/nodeAffinity", O),
        field("/spec/nodeAffinity/required", O),
        field("/spec/nodeAffinity/required/nodeSelectorTerms", A),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*", O),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions", A),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields", A),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions/*", O),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields/*", O),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions/*/key",
            S,
        ),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions/*/operator",
            S,
        ),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions/*/values",
            A,
        ),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchExpressions/*/values/*",
            S,
        ),
        field("/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields/*/key", S),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields/*/operator",
            S,
        ),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields/*/values",
            A,
        ),
        field(
            "/spec/nodeAffinity/required/nodeSelectorTerms/*/matchFields/*/values/*",
            S,
        ),
        field("/spec/gcePersistentDisk", O),
        field("/spec/awsElasticBlockStore", O),
        field("/spec/hostPath", O),
        field("/spec/glusterfs", O),
        field("/spec/nfs", O),
        field("/spec/rbd", O),
        field("/spec/iscsi", O),
        field("/spec/cinder", O),
        field("/spec/cephfs", O),
        field("/spec/fc", O),
        field("/spec/flocker", O),
        field("/spec/flexVolume", O),
        field("/spec/azureFile", O),
        field("/spec/vsphereVolume", O),
        field("/spec/quobyte", O),
        field("/spec/azureDisk", O),
        field("/spec/photonPersistentDisk", O),
        field("/spec/scaleIO", O),
        field("/spec/local", O),
        field("/spec/storageos", O),
        field("/spec/csi", O),
        // Finite selected source members. Unknown sibling fields remain opaque.
        field("/spec/gcePersistentDisk/fsType", S),
        field("/spec/gcePersistentDisk/partition", S),
        field("/spec/gcePersistentDisk/pdName", S),
        field("/spec/gcePersistentDisk/readOnly", S),
        field("/spec/awsElasticBlockStore/fsType", S),
        field("/spec/awsElasticBlockStore/partition", S),
        field("/spec/awsElasticBlockStore/readOnly", S),
        field("/spec/awsElasticBlockStore/volumeID", S),
        field("/spec/hostPath/path", S),
        field("/spec/hostPath/type", S),
        field("/spec/glusterfs/endpoints", S),
        field("/spec/glusterfs/path", S),
        field("/spec/glusterfs/readOnly", S),
        field("/spec/glusterfs/endpointsNamespace", S),
        field("/spec/nfs/path", S),
        field("/spec/nfs/readOnly", S),
        field("/spec/nfs/server", S),
        field("/spec/rbd/fsType", S),
        field("/spec/rbd/image", S),
        field("/spec/rbd/keyring", S),
        field("/spec/rbd/monitors", A),
        field("/spec/rbd/monitors/*", S),
        field("/spec/rbd/pool", S),
        field("/spec/rbd/readOnly", S),
        field("/spec/rbd/secretRef", O),
        field("/spec/rbd/secretRef/name", S),
        field("/spec/rbd/secretRef/namespace", S),
        field("/spec/rbd/user", S),
        field("/spec/iscsi/chapAuthDiscovery", S),
        field("/spec/iscsi/chapAuthSession", S),
        field("/spec/iscsi/fsType", S),
        field("/spec/iscsi/initiatorName", S),
        field("/spec/iscsi/iqn", S),
        field("/spec/iscsi/iscsiInterface", S),
        field("/spec/iscsi/lun", S),
        field("/spec/iscsi/portals", A),
        field("/spec/iscsi/portals/*", S),
        field("/spec/iscsi/readOnly", S),
        field("/spec/iscsi/secretRef", O),
        field("/spec/iscsi/secretRef/name", S),
        field("/spec/iscsi/secretRef/namespace", S),
        field("/spec/iscsi/targetPortal", S),
        field("/spec/cinder/fsType", S),
        field("/spec/cinder/readOnly", S),
        field("/spec/cinder/secretRef", O),
        field("/spec/cinder/secretRef/name", S),
        field("/spec/cinder/secretRef/namespace", S),
        field("/spec/cinder/volumeID", S),
        field("/spec/cephfs/monitors", A),
        field("/spec/cephfs/monitors/*", S),
        field("/spec/cephfs/path", S),
        field("/spec/cephfs/readOnly", S),
        field("/spec/cephfs/secretFile", S),
        field("/spec/cephfs/secretRef", O),
        field("/spec/cephfs/secretRef/name", S),
        field("/spec/cephfs/secretRef/namespace", S),
        field("/spec/cephfs/user", S),
        field("/spec/fc/fsType", S),
        field("/spec/fc/lun", S),
        field("/spec/fc/readOnly", S),
        field("/spec/fc/targetWWNs", A),
        field("/spec/fc/targetWWNs/*", S),
        field("/spec/fc/wwids", A),
        field("/spec/fc/wwids/*", S),
        field("/spec/flocker/datasetName", S),
        field("/spec/flocker/datasetUUID", S),
        field("/spec/flexVolume/driver", S),
        field("/spec/flexVolume/fsType", S),
        field("/spec/flexVolume/options", M),
        field("/spec/flexVolume/options/*", S),
        field("/spec/flexVolume/readOnly", S),
        field("/spec/flexVolume/secretRef", O),
        field("/spec/flexVolume/secretRef/name", S),
        field("/spec/flexVolume/secretRef/namespace", S),
        field("/spec/azureFile/readOnly", S),
        field("/spec/azureFile/secretName", S),
        field("/spec/azureFile/secretNamespace", S),
        field("/spec/azureFile/shareName", S),
        field("/spec/vsphereVolume/fsType", S),
        field("/spec/vsphereVolume/storagePolicyID", S),
        field("/spec/vsphereVolume/storagePolicyName", S),
        field("/spec/vsphereVolume/volumePath", S),
        field("/spec/quobyte/group", S),
        field("/spec/quobyte/readOnly", S),
        field("/spec/quobyte/registry", S),
        field("/spec/quobyte/tenant", S),
        field("/spec/quobyte/user", S),
        field("/spec/quobyte/volume", S),
        field("/spec/azureDisk/cachingMode", S),
        field("/spec/azureDisk/diskName", S),
        field("/spec/azureDisk/diskURI", S),
        field("/spec/azureDisk/fsType", S),
        field("/spec/azureDisk/kind", S),
        field("/spec/azureDisk/readOnly", S),
        field("/spec/photonPersistentDisk/fsType", S),
        field("/spec/photonPersistentDisk/pdID", S),
        field("/spec/scaleIO/fsType", S),
        field("/spec/scaleIO/gateway", S),
        field("/spec/scaleIO/protectionDomain", S),
        field("/spec/scaleIO/readOnly", S),
        field("/spec/scaleIO/secretRef", O),
        field("/spec/scaleIO/secretRef/name", S),
        field("/spec/scaleIO/secretRef/namespace", S),
        field("/spec/scaleIO/sslEnabled", S),
        field("/spec/scaleIO/storageMode", S),
        field("/spec/scaleIO/storagePool", S),
        field("/spec/scaleIO/system", S),
        field("/spec/scaleIO/volumeName", S),
        field("/spec/local/fsType", S),
        field("/spec/local/path", S),
        field("/spec/storageos/fsType", S),
        field("/spec/storageos/readOnly", S),
        field("/spec/storageos/secretRef", O),
        field("/spec/storageos/secretRef/apiVersion", S),
        field("/spec/storageos/secretRef/fieldPath", S),
        field("/spec/storageos/secretRef/kind", S),
        field("/spec/storageos/secretRef/name", S),
        field("/spec/storageos/secretRef/namespace", S),
        field("/spec/storageos/secretRef/resourceVersion", S),
        field("/spec/storageos/secretRef/uid", S),
        field("/spec/storageos/volumeName", S),
        field("/spec/storageos/volumeNamespace", S),
        field("/spec/csi/driver", S),
        field("/spec/csi/fsType", S),
        field("/spec/csi/volumeAttributes", M),
        field("/spec/csi/volumeAttributes/*", S),
        field("/spec/csi/volumeHandle", S),
        field("/spec/csi/readOnly", S),
        stable_gate_field("/spec/csi/controllerExpandSecretRef", O),
        field("/spec/csi/controllerPublishSecretRef", O),
        stable_gate_field("/spec/csi/controllerExpandSecretRef/name", S),
        stable_gate_field("/spec/csi/controllerExpandSecretRef/namespace", S),
        field("/spec/csi/controllerPublishSecretRef/name", S),
        field("/spec/csi/controllerPublishSecretRef/namespace", S),
        field("/spec/csi/nodePublishSecretRef", O),
        field("/spec/csi/nodePublishSecretRef/name", S),
        field("/spec/csi/nodePublishSecretRef/namespace", S),
        field("/spec/csi/nodeStageSecretRef", O),
        field("/spec/csi/nodeStageSecretRef/name", S),
        field("/spec/csi/nodeStageSecretRef/namespace", S),
    ]
});
const STORAGE_CLASS_FIELDS: &[FieldCapability] = &[
    field("/provisioner", S),
    field("/parameters", M),
    field("/parameters/*", S),
    field("/reclaimPolicy", S),
    field("/mountOptions", A),
    field("/mountOptions/*", S),
    field("/allowVolumeExpansion", S),
    field("/volumeBindingMode", S),
    field("/allowedTopologies", A),
    field("/allowedTopologies/*", O),
    field("/allowedTopologies/*/matchLabelExpressions", A),
    field("/allowedTopologies/*/matchLabelExpressions/*", O),
    field("/allowedTopologies/*/matchLabelExpressions/*/key", S),
    field("/allowedTopologies/*/matchLabelExpressions/*/values", A),
    field("/allowedTopologies/*/matchLabelExpressions/*/values/*", S),
];

fn kind(gvk: GroupVersionKind, scope: ResourceScope, fields: &'static [FieldCapability]) -> KindCapability {
    KindCapability {
        gvk,
        scope,
        api_since: KubernetesVersion::MIN,
        api_removed: None,
        fields,
    }
}
fn with_metadata(base: &[FieldCapability]) -> Vec<FieldCapability> {
    let mut fields = base.to_vec();
    fields.extend_from_slice(META);
    fields
}
static CONFIG_MAP_FIELDS_WITH_META: LazyLock<Vec<FieldCapability>> =
    LazyLock::new(|| with_metadata(CONFIG_MAP_FIELDS.as_slice()));
static SECRET_FIELDS_WITH_META: LazyLock<Vec<FieldCapability>> =
    LazyLock::new(|| with_metadata(SECRET_FIELDS.as_slice()));
static CLAIM_FIELDS_WITH_META: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| with_metadata(CLAIM_FIELDS));
static PV_FIELDS_WITH_META: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| with_metadata(PV_FIELDS.as_slice()));
static STORAGE_CLASS_FIELDS_WITH_META: LazyLock<Vec<FieldCapability>> =
    LazyLock::new(|| with_metadata(STORAGE_CLASS_FIELDS));
pub(super) fn for_api(gvk: GroupVersionKind) -> Result<KindCapability, Finding> {
    let (scope, fields): (ResourceScope, &'static [FieldCapability]) =
        match (gvk.api_version().as_str(), gvk.kind.as_str()) {
            ("v1", "ConfigMap") => (ResourceScope::Namespaced, CONFIG_MAP_FIELDS_WITH_META.as_slice()),
            ("v1", "Secret") => (ResourceScope::Namespaced, SECRET_FIELDS_WITH_META.as_slice()),
            ("v1", "PersistentVolumeClaim") => (ResourceScope::Namespaced, CLAIM_FIELDS_WITH_META.as_slice()),
            ("v1", "PersistentVolume") => (ResourceScope::Cluster, PV_FIELDS_WITH_META.as_slice()),
            ("storage.k8s.io/v1", "StorageClass") => {
                (ResourceScope::Cluster, STORAGE_CLASS_FIELDS_WITH_META.as_slice())
            }
            _ => return Err(Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)),
        };
    Ok(kind(gvk, scope, fields))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn persistent_volume_node_affinity_catalogue_uses_exact_native_descendants() -> Result<(), Finding> {
        let gvk = GroupVersionKind::new("v1", "PersistentVolume")?;
        let capability = for_api(gvk)?;
        let paths: Vec<_> = capability.fields.iter().map(|field| field.path).collect();
        let required = "/spec/nodeAffinity/required";
        for suffix in [
            "nodeSelectorTerms",
            "nodeSelectorTerms/*",
            "nodeSelectorTerms/*/matchExpressions",
            "nodeSelectorTerms/*/matchExpressions/*",
            "nodeSelectorTerms/*/matchExpressions/*/key",
            "nodeSelectorTerms/*/matchExpressions/*/operator",
            "nodeSelectorTerms/*/matchExpressions/*/values",
            "nodeSelectorTerms/*/matchExpressions/*/values/*",
            "nodeSelectorTerms/*/matchFields",
            "nodeSelectorTerms/*/matchFields/*",
            "nodeSelectorTerms/*/matchFields/*/key",
            "nodeSelectorTerms/*/matchFields/*/operator",
            "nodeSelectorTerms/*/matchFields/*/values",
            "nodeSelectorTerms/*/matchFields/*/values/*",
        ] {
            let expected = format!("{required}/{suffix}");
            assert!(paths.contains(&expected.as_str()), "missing capability {expected}");
        }
        assert!(
            !paths
                .iter()
                .any(|path| path.starts_with("/spec/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution",))
        );
        Ok(())
    }
}
