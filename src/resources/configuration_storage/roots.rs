use super::capabilities;
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    graph::ReferenceSink,
    model::{GroupVersionKind, Metadata, ResourceScope},
    registry::{
        DecodeContext, EncodeContext, FieldDecodeContext, FindingSink, NativeResource, ProjectionContext,
        RegistryBuilder, ResourceRegistration, ValidationContext,
        codec::{self, FieldCodec},
    },
    source::{ObservationPath, SourceEvidence},
    syntax::{SyntaxBuilder, TreeNode, UnknownFields},
    value::{AccessModes, NativeBytes, Presence, Quantity},
};
use std::{any::Any, collections::BTreeMap};

crate::resources::common::native_object! {
    /// Selected `PersistentVolumeSpec` fields. Unadmitted descendants remain private.
    pub struct PersistentVolumeSpec {
        "accessModes" => access_modes: AccessModes,
        "capacity" => capacity: BTreeMap<String, Quantity>,
        "claimRef" => claim_ref: crate::resources::common::ObjectReference,
        "mountOptions" => mount_options: Vec<String>,
        "nodeAffinity" => node_affinity: VolumeNodeAffinity,
        "persistentVolumeReclaimPolicy" => persistent_volume_reclaim_policy: String,
        "storageClassName" => storage_class_name: String,
        "volumeMode" => volume_mode: String,
        "awsElasticBlockStore" => aws_elastic_block_store: crate::resources::common::AWSElasticBlockStoreVolumeSource,
        "azureDisk" => azure_disk: crate::resources::common::AzureDiskVolumeSource,
        "azureFile" => azure_file: AzureFilePersistentVolumeSource,
        "cephfs" => cephfs: PersistentVolumeCephFSSource,
        "cinder" => cinder: PersistentVolumeCinderSource,
        "csi" => csi: CSIPersistentVolumeSource,
        "fc" => fc: crate::resources::common::FCVolumeSource,
        "flocker" => flocker: crate::resources::common::FlockerVolumeSource,
        "flexVolume" => flex_volume: PersistentVolumeFlexSource,
        "gcePersistentDisk" => gce_persistent_disk: crate::resources::common::GCEPersistentDiskVolumeSource,
        "glusterfs" => glusterfs: GlusterfsPersistentVolumeSource,
        "hostPath" => host_path: crate::resources::common::HostPathVolumeSource,
        "iscsi" => iscsi: PersistentVolumeISCSISource,
        "local" => local: LocalPersistentVolumeSource,
        "nfs" => nfs: crate::resources::common::NFSVolumeSource,
        "photonPersistentDisk" => photon_persistent_disk: crate::resources::common::PhotonPersistentDiskVolumeSource,
        "quobyte" => quobyte: crate::resources::common::QuobyteVolumeSource,
        "rbd" => rbd: PersistentVolumeRBDSource,
        "scaleIO" => scale_io: PersistentVolumeScaleIOSource,
        "storageos" => storageos: PersistentVolumeStorageOSSource,
        "vsphereVolume" => vsphere_volume: crate::resources::common::VsphereVirtualDiskVolumeSource,
    }
}

crate::resources::common::native_object! {
    /// Persistent volume CSI source; distinct from the Pod inline CSI source.
    pub struct CSIPersistentVolumeSource {
        "controllerExpandSecretRef" => controller_expand_secret_ref: PersistentVolumeSecretReference,
        "controllerPublishSecretRef" => controller_publish_secret_ref: PersistentVolumeSecretReference,
        "driver" => driver: String,
        "fsType" => fs_type: String,
        "nodePublishSecretRef" => node_publish_secret_ref: PersistentVolumeSecretReference,
        "nodeStageSecretRef" => node_stage_secret_ref: PersistentVolumeSecretReference,
        "readOnly" => read_only: bool,
        "volumeAttributes" => volume_attributes: BTreeMap<String, String>,
        "volumeHandle" => volume_handle: String,
    }
}
crate::resources::common::native_object! {
    /// Explicit namespaced CSI secret-reference evidence.
    pub struct PersistentVolumeSecretReference {
        "name" => name: String,
        "namespace" => namespace: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume `CephFS` source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeCephFSSource {
        "monitors" => monitors: Vec<String>,
        "path" => path: String,
        "readOnly" => read_only: bool,
        "secretFile" => secret_file: String,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
        "user" => user: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume Cinder source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeCinderSource {
        "fsType" => fs_type: String,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
        "volumeID" => volume_id: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume Flex source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeFlexSource {
        "driver" => driver: String,
        "fsType" => fs_type: String,
        "options" => options: BTreeMap<String, String>,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume iSCSI source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeISCSISource {
        "chapAuthDiscovery" => chap_auth_discovery: bool,
        "chapAuthSession" => chap_auth_session: bool,
        "fsType" => fs_type: String,
        "initiatorName" => initiator_name: String,
        "iqn" => iqn: String,
        "iscsiInterface" => iscsi_interface: String,
        "lun" => lun: i32,
        "portals" => portals: Vec<String>,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
        "targetPortal" => target_portal: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume RBD source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeRBDSource {
        "fsType" => fs_type: String,
        "image" => image: String,
        "keyring" => keyring: String,
        "monitors" => monitors: Vec<String>,
        "pool" => pool: String,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
        "user" => user: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume `ScaleIO` source with its PV `SecretReference` wire shape.
    pub struct PersistentVolumeScaleIOSource {
        "fsType" => fs_type: String,
        "gateway" => gateway: String,
        "protectionDomain" => protection_domain: String,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: PersistentVolumeSecretReference,
        "sslEnabled" => ssl_enabled: bool,
        "storageMode" => storage_mode: String,
        "storagePool" => storage_pool: String,
        "system" => system: String,
        "volumeName" => volume_name: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume `StorageOS` source; its secret reference is a full object reference.
    pub struct PersistentVolumeStorageOSSource {
        "fsType" => fs_type: String,
        "readOnly" => read_only: bool,
        "secretRef" => secret_ref: crate::resources::common::ObjectReference,
        "volumeName" => volume_name: String,
        "volumeNamespace" => volume_namespace: String,
    }
}
crate::resources::common::native_object! {
    /// Persistent-volume node affinity, distinct from Pod node affinity.
    pub struct VolumeNodeAffinity {
        "required" => required: crate::resources::common::NodeSelector,
    }
}
crate::resources::common::native_object! {
    /// Selected `AzureFilePersistentVolumeSource` fields.
    pub struct AzureFilePersistentVolumeSource {
        "readOnly" => read_only: bool,
        "secretName" => secret_name: String,
        "secretNamespace" => secret_namespace: String,
        "shareName" => share_name: String,
    }
}
crate::resources::common::native_object! {
    /// Selected persistent-volume `GlusterFS` fields.
    pub struct GlusterfsPersistentVolumeSource {
        "endpoints" => endpoints: String,
        "endpointsNamespace" => endpoints_namespace: String,
        "path" => path: String,
        "readOnly" => read_only: bool,
    }
}
crate::resources::common::native_object! {
    /// Selected local persistent volume source.
    pub struct LocalPersistentVolumeSource {
        "fsType" => fs_type: String,
        "path" => path: String,
    }
}

crate::resources::common::native_object! {
    /// Selected topology selector term fields used by `StorageClass`.
    pub struct TopologySelectorTerm {
        "matchLabelExpressions" => match_label_expressions: Vec<TopologySelectorLabelRequirement>,
    }
}
crate::resources::common::native_object! {
    /// Selected topology label requirement fields used by `StorageClass`.
    pub struct TopologySelectorLabelRequirement {
        "key" => key: String,
        "values" => values: Vec<String>,
    }
}

macro_rules! root {
    ($name:ident, $api:literal, $kind:literal, $scope:expr, {$($wire:literal => $field:ident: $ty:ty,)*}) => {
        #[doc = concat!("Typed native `", $api, "` `", $kind, "`; unselected descendants remain private.")]
        #[derive(Clone, Default, Debug)]
        pub struct $name {
            /// Explicit authored metadata. Absence is not materialized.
            pub metadata: Presence<Metadata>,
            $(#[doc = concat!("Explicit authored presence for `", $wire, "`.")]
              pub $field: Presence<$ty>,)*
            pub(crate) unknown: UnknownFields,
        }
        impl From<$name> for crate::model::AuthoredResource {
            fn from(value: $name) -> Self {
                Self::new(Box::new(value))
            }
        }
        impl $name {
            /// Exact served API identity.
            pub const API_VERSION: &'static str = $api;
            /// Exact resource kind.
            pub const KIND: &'static str = $kind;
            /// Retained unadmitted root fields, without exposing their payloads.
            #[must_use]
            pub const fn unknown_fields(&self) -> &UnknownFields { &self.unknown }
        }
        impl crate::resources::common::UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, path: &FieldPath, out: &mut std::collections::BTreeSet<FieldPath>) {
                if !self.unknown.is_empty() { out.insert(path.clone()); }
                crate::resources::common::UnknownScopes::unknown_scopes(&self.metadata, &path.child("metadata"), out);
                $(crate::resources::common::UnknownScopes::unknown_scopes(&self.$field, &path.child($wire), out);)*
            }
            fn visit_unknown_scopes(
                &self,
                path: &FieldPath,
                visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>,
            ) -> bool {
                if !visitor.step() || (!self.unknown.is_empty() && !visitor.found(path)) {
                    return false;
                }
                let Some(child) = visitor.child(path, "metadata") else {
                    return false;
                };
                if !crate::resources::common::UnknownScopes::visit_unknown_scopes(&self.metadata, &child, visitor) {
                    return false;
                }
                $(let Some(child) = visitor.child(path, $wire) else { return false; };
                if !crate::resources::common::UnknownScopes::visit_unknown_scopes(&self.$field, &child, visitor) { return false; })*
                true
            }
        }
        impl FieldCodec for $name {
            fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
                codec::object(node, path)?;
                ctx.processing.work(1, ctx.phase)?;
                if node.get("apiVersion").and_then(TreeNode::as_str) != Some($api)
                    || node.get("kind").and_then(TreeNode::as_str) != Some($kind) {
                    return Err(Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()));
                }
                Ok(Self {
                    metadata: codec::read_presence(node, "metadata", ctx, path)?,
                    $($field: codec::read_presence(node, $wire, ctx, path)?,)*
                    unknown: UnknownFields::capture_in(node, &["apiVersion", "kind", "metadata", $($wire,)*], ctx)?,
                })
            }
            fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
                let mut entries = vec![
                    (ctx.key("apiVersion", &path.child("apiVersion"))?, ctx.string($api, &path.child("apiVersion"))?),
                    (ctx.key("kind", &path.child("kind"))?, ctx.string($kind, &path.child("kind"))?),
                ];
                codec::write_presence(&mut entries, "metadata", &self.metadata, ctx, path)?;
                $(codec::write_presence(&mut entries, $wire, &self.$field, ctx, path)?;)*
                codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
                ctx.object(entries, path)
            }
        }
        impl NativeResource for $name {
            fn as_any(&self) -> &dyn Any { self }
            fn as_any_mut(&mut self) -> &mut dyn Any { self }
            fn collect_references(&self, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
                if let Ok(tree) = self.encode(ctx, &FieldPath::default()) { super::validation::references($kind, &tree, out); }
            }
            fn collect_protected_paths(&self, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
                if let Ok(tree) = self.encode(ctx, &FieldPath::default()) { super::validation::protected_paths($kind, &tree, ctx, out); }
            }
            fn collect_native_facts(&self, ctx: &ProjectionContext<'_>, out: &mut Vec<crate::graph::NativeFact>) {
                super::facts::collect($kind, self, ctx, out);
            }
            fn collect_observation_paths(&self, tree: &TreeNode, out: &mut Vec<ObservationPath>) {
                super::validation::observations($kind, tree, out);
            }
            fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
                match self.encode(&ctx.encoding(), &FieldPath::default()) {
                    Ok(tree) => {
                        let mut retain = |_| !out.exhausted();
                        if crate::resources::common::UnknownScopes::visit_unknown_scopes(
                            self,
                            &FieldPath::default(),
                            &mut crate::resources::common::UnknownScopeVisitor::new(&ctx.fields, &mut retain),
                        ) {
                            super::validation::validate($kind, $api, $scope, &tree, ctx, out);
                            if !out.exhausted() {
                                if let Err(finding) = super::validation::StaticChecks::check(self, ctx, out) { out.push(finding); }
                            }
                        }
                    },
                    Err(finding) => out.push(finding),
                }
            }
            fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding> {
                out.set_root(self.encode(ctx, &FieldPath::default())?);
                Ok(())
            }
        }
    }
}

root!(ConfigMap, "v1", "ConfigMap", ResourceScope::Namespaced, {
    "data" => data: BTreeMap<String, crate::value::Protected<String>>,
    "binaryData" => binary_data: BTreeMap<String, NativeBytes>,
    "immutable" => immutable: bool,
});
root!(Secret, "v1", "Secret", ResourceScope::Namespaced, {
    "type" => r#type: String,
    "data" => data: BTreeMap<String, NativeBytes>,
    "stringData" => string_data: BTreeMap<String, crate::value::Protected<String>>,
    "immutable" => immutable: bool,
});
root!(PersistentVolumeClaim, "v1", "PersistentVolumeClaim", ResourceScope::Namespaced, {
    "spec" => spec: crate::resources::common::PersistentVolumeClaimSpec,
});
root!(PersistentVolume, "v1", "PersistentVolume", ResourceScope::Cluster, {
    "spec" => spec: PersistentVolumeSpec,
});
root!(StorageClass, "storage.k8s.io/v1", "StorageClass", ResourceScope::Cluster, {
    "provisioner" => provisioner: String,
    "parameters" => parameters: BTreeMap<String, String>,
    "reclaimPolicy" => reclaim_policy: String,
    "mountOptions" => mount_options: Vec<String>,
    "allowVolumeExpansion" => allow_volume_expansion: bool,
    "volumeBindingMode" => volume_binding_mode: String,
    "allowedTopologies" => allowed_topologies: Vec<TopologySelectorTerm>,
});

pub(crate) fn register(registry: &mut RegistryBuilder) -> Result<(), Finding> {
    macro_rules! one {
        ($name:ident, $scope:expr) => {{
            fn decode(
                node: &TreeNode,
                _: &SourceEvidence,
                ctx: &DecodeContext<'_>,
            ) -> Result<Box<dyn NativeResource>, Vec<Finding>> {
                if ctx.scope != $scope || ctx.gvk.kind != $name::KIND || ctx.gvk.api_version() != $name::API_VERSION {
                    return Err(vec![Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)]);
                }
                $name::decode(node, &ctx.fields, &FieldPath::default())
                    .map(|value| Box::new(value) as Box<dyn NativeResource>)
                    .map_err(|finding| vec![finding])
            }
            let gvk = GroupVersionKind::new($name::API_VERSION, $name::KIND)?;
            registry.register(ResourceRegistration {
                gvk: gvk.clone(),
                scope: $scope,
                decode,
                capability: capabilities::for_api(gvk)?,
            })?;
        }};
    }
    one!(ConfigMap, ResourceScope::Namespaced);
    one!(Secret, ResourceScope::Namespaced);
    one!(PersistentVolumeClaim, ResourceScope::Namespaced);
    one!(PersistentVolume, ResourceScope::Cluster);
    one!(StorageClass, ResourceScope::Cluster);
    Ok(())
}

#[cfg(test)]
mod streaming_tests {
    use super::*;
    use crate::{
        processing::{NativeOperationBudget, NativeProcessingLimits},
        resources::common::{UnknownScopeVisitor, UnknownScopes},
        source::ParseLimits,
        syntax::TreeValue,
    };
    use std::collections::BTreeSet;

    fn fields(limits: NativeProcessingLimits) -> FieldDecodeContext {
        FieldDecodeContext::new(
            ParseLimits::default(),
            NativeOperationBudget::new(limits),
            Phase::Validation,
        )
    }

    fn check<T: FieldCodec + UnknownScopes>(api: &str, kind: &str, claim: bool) -> Result<(), String> {
        let mut entries = vec![
            ("apiVersion".into(), TreeNode::new(TreeValue::String(api.into()))),
            ("kind".into(), TreeNode::new(TreeValue::String(kind.into()))),
            ("private-root-field".into(), TreeNode::new(TreeValue::Null)),
        ];
        if claim {
            entries.push((
                "spec".into(),
                TreeNode::mapping(vec![
                    ("private-spec-field".into(), TreeNode::new(TreeValue::Null)),
                    (
                        "accessModes".into(),
                        TreeNode::new(TreeValue::Sequence(vec![TreeNode::new(TreeValue::String(
                            "private-future-mode".into(),
                        ))])),
                    ),
                ]),
            ));
        }
        let value = T::decode(
            &TreeNode::mapping(entries),
            &fields(NativeProcessingLimits::default()),
            &FieldPath::default(),
        )
        .map_err(|_| "root decoding failed")?;
        let mut expected = BTreeSet::from([FieldPath::default()]);
        if claim {
            expected.insert(FieldPath(vec!["spec".into()]));
            expected.insert(FieldPath(vec!["spec".into(), "accessModes".into()]));
        }
        let mut legacy = BTreeSet::new();
        value.unknown_scopes(&FieldPath::default(), &mut legacy);
        assert_eq!(legacy, expected);
        let ctx = fields(NativeProcessingLimits::default());
        let mut actual = BTreeSet::new();
        assert!(value.visit_unknown_scopes(
            &FieldPath::default(),
            &mut UnknownScopeVisitor::new(&ctx, &mut |path| {
                actual.insert(path);
                true
            })
        ));
        assert_eq!(actual, expected);
        let mut callbacks = 0;
        assert!(!value.visit_unknown_scopes(
            &FieldPath::default(),
            &mut UnknownScopeVisitor::new(&ctx, &mut |_| {
                callbacks += 1;
                false
            })
        ));
        assert_eq!(callbacks, 1);
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
            let ctx = fields(limits);
            for _ in 0..2 {
                assert!(!value.visit_unknown_scopes(
                    &FieldPath(vec!["resource".into()]),
                    &mut UnknownScopeVisitor::new(&ctx, &mut |_| {
                        callbacks += 1;
                        true
                    })
                ));
                assert!(ctx.processing.exhausted());
                assert_eq!(callbacks, 1);
            }
        }
        Ok(())
    }

    #[test]
    fn every_storage_root_streams_original_scopes_and_stops_after_refusal() -> Result<(), String> {
        check::<ConfigMap>("v1", "ConfigMap", false)?;
        check::<Secret>("v1", "Secret", false)?;
        check::<PersistentVolumeClaim>("v1", "PersistentVolumeClaim", true)?;
        check::<PersistentVolume>("v1", "PersistentVolume", true)?;
        check::<StorageClass>("storage.k8s.io/v1", "StorageClass", false)
    }
}
