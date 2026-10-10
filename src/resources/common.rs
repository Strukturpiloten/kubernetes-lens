//! Shared finite native helpers, independent of concrete resource cohorts.
use crate::value::{LabelSelector, Quantity};
use std::collections::BTreeMap;

macro_rules! native_object {
    ($(#[$doc:meta])* pub struct $name:ident { $($wire:literal => $field:ident: $ty:ty,)* }) => {
        $(#[$doc])*
        #[derive(Clone, Default, Debug)]
        pub struct $name {
            $(#[doc = concat!("Explicit `", $wire, "` presence; absence is never a default.")]
            pub $field: $crate::value::Presence<$ty>,)*
            pub(crate) unknown: $crate::syntax::UnknownFields,
        }
        impl $name {
            pub(crate) const NATIVE_FIELDS: &'static [&'static str] = &[$($wire,)*];
            /// Borrow retained unadmitted immediate members without exposing their values.
            #[must_use]
            pub const fn unknown_fields(&self) -> &$crate::syntax::UnknownFields { &self.unknown }
        }
        impl $crate::resources::common::UnknownScopes for $name {
            fn unknown_scopes(&self, path: &$crate::diagnostic::FieldPath, out: &mut std::collections::BTreeSet<$crate::diagnostic::FieldPath>) {
                if !self.unknown.is_empty() { out.insert(path.clone()); }
                $($crate::resources::common::UnknownScopes::unknown_scopes(&self.$field, &path.child($wire), out);)*
            }
        }
        impl $crate::registry::codec::FieldCodec for $name {
            fn decode(node: &$crate::syntax::TreeNode, ctx: &$crate::registry::FieldDecodeContext, path: &$crate::diagnostic::FieldPath) -> Result<Self, $crate::diagnostic::Finding> {
                $crate::registry::codec::object(node, path)?;
                ctx.processing.work(1, ctx.phase)?;
                Ok(Self {
                    $($field: $crate::registry::codec::read_presence(node, $wire, ctx, path)?,)*
                    unknown: $crate::syntax::UnknownFields::capture(node, Self::NATIVE_FIELDS),
                })
            }
            fn encode(&self, ctx: &$crate::registry::EncodeContext<'_>, path: &$crate::diagnostic::FieldPath) -> Result<$crate::syntax::TreeNode, $crate::diagnostic::Finding> {
                let mut entries = Vec::new();
                $($crate::registry::codec::write_presence(&mut entries, $wire, &self.$field, ctx, path)?;)*
                $crate::registry::codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
                ctx.object(entries, path)
            }
        }
    };
}
pub(crate) use native_object;

/// Identical admitted claim limits/requests wire view across the 1.28/1.29 schema-reference change.
/// This alias never infers a source minor or changes the separate resource helper definitions.
pub type ClaimResourceRequirements = ResourceRequirements;

native_object! {
    /// Selected native `AWSElasticBlockStoreVolumeSource` members; unadmitted descendants remain private.
    pub struct AWSElasticBlockStoreVolumeSource {
    "fsType" => fs_type: String,
    "partition" => partition: i32,
    "readOnly" => read_only: bool,
    "volumeID" => volume_id: String,
    }
}

native_object! {
    /// Selected native `AzureDiskVolumeSource` members; unadmitted descendants remain private.
    pub struct AzureDiskVolumeSource {
    "cachingMode" => caching_mode: String,
    "diskName" => disk_name: String,
    "diskURI" => disk_uri: String,
    "fsType" => fs_type: String,
    "kind" => kind: String,
    "readOnly" => read_only: bool,
    }
}

native_object! {
    /// Selected native `FCVolumeSource` members; unadmitted descendants remain private.
    pub struct FCVolumeSource {
    "fsType" => fs_type: String,
    "lun" => lun: i32,
    "readOnly" => read_only: bool,
    "targetWWNs" => target_ww_ns: Vec<String>,
    "wwids" => wwids: Vec<String>,
    }
}

native_object! {
    /// Selected native `FlockerVolumeSource` members; unadmitted descendants remain private.
    pub struct FlockerVolumeSource {
    "datasetName" => dataset_name: String,
    "datasetUUID" => dataset_uuid: String,
    }
}

native_object! {
    /// Selected native `GCEPersistentDiskVolumeSource` members; unadmitted descendants remain private.
    pub struct GCEPersistentDiskVolumeSource {
    "fsType" => fs_type: String,
    "partition" => partition: i32,
    "pdName" => pd_name: String,
    "readOnly" => read_only: bool,
    }
}

native_object! {
    /// Selected native `HostPathVolumeSource` members; unadmitted descendants remain private.
    pub struct HostPathVolumeSource {
    "path" => path: String,
    "type" => r#type: String,
    }
}

native_object! {
    /// Selected native `LocalObjectReference` members; unadmitted descendants remain private.
    pub struct LocalObjectReference {
    "name" => name: String,
    }
}

native_object! {
    /// Selected native `NFSVolumeSource` members; unadmitted descendants remain private.
    pub struct NFSVolumeSource {
    "path" => path: String,
    "readOnly" => read_only: bool,
    "server" => server: String,
    }
}

native_object! {
    /// Selected native `NodeSelector` members; unadmitted descendants remain private.
    pub struct NodeSelector {
    "nodeSelectorTerms" => node_selector_terms: Vec<NodeSelectorTerm>,
    }
}

native_object! {
    /// Selected native `NodeSelectorRequirement` members; unadmitted descendants remain private.
    pub struct NodeSelectorRequirement {
    "key" => key: String,
    "operator" => operator: String,
    "values" => values: Vec<String>,
    }
}

native_object! {
    /// Selected native `NodeSelectorTerm` members; unadmitted descendants remain private.
    pub struct NodeSelectorTerm {
    "matchExpressions" => match_expressions: Vec<NodeSelectorRequirement>,
    "matchFields" => match_fields: Vec<NodeSelectorRequirement>,
    }
}

native_object! {
    /// Selected native `ObjectReference` members; unadmitted descendants remain private.
    pub struct ObjectReference {
    "apiVersion" => api_version: String,
    "fieldPath" => field_path: String,
    "kind" => kind: String,
    "name" => name: String,
    "namespace" => namespace: String,
    "resourceVersion" => resource_version: String,
    "uid" => uid: String,
    }
}

native_object! {
    /// Selected native `PersistentVolumeClaimSpec` members; unadmitted descendants remain private.
    pub struct PersistentVolumeClaimSpec {
    "accessModes" => access_modes: Vec<String>,
    "dataSource" => data_source: TypedLocalObjectReference,
    "resources" => resources: ClaimResourceRequirements,
    "selector" => selector: LabelSelector,
    "storageClassName" => storage_class_name: String,
    "volumeMode" => volume_mode: String,
    "volumeName" => volume_name: String,
    }
}

native_object! {
    /// Selected native `PhotonPersistentDiskVolumeSource` members; unadmitted descendants remain private.
    pub struct PhotonPersistentDiskVolumeSource {
    "fsType" => fs_type: String,
    "pdID" => pd_id: String,
    }
}

native_object! {
    /// Selected native `PortworxVolumeSource` members; unadmitted descendants remain private.
    pub struct PortworxVolumeSource {
    "fsType" => fs_type: String,
    "readOnly" => read_only: bool,
    "volumeID" => volume_id: String,
    }
}

native_object! {
    /// Selected native `QuobyteVolumeSource` members; unadmitted descendants remain private.
    pub struct QuobyteVolumeSource {
    "group" => group: String,
    "readOnly" => read_only: bool,
    "registry" => registry: String,
    "tenant" => tenant: String,
    "user" => user: String,
    "volume" => volume: String,
    }
}

native_object! {
    /// Selected native `ResourceRequirements` members; unadmitted descendants remain private.
    pub struct ResourceRequirements {
    "limits" => limits: BTreeMap<String, Quantity>,
    "requests" => requests: BTreeMap<String, Quantity>,
    }
}

native_object! {
    /// Selected native `SELinuxOptions` members; unadmitted descendants remain private.
    pub struct SELinuxOptions {
    "level" => level: String,
    "role" => role: String,
    "type" => r#type: String,
    "user" => user: String,
    }
}

native_object! {
    /// Selected native `Toleration` members; unadmitted descendants remain private.
    pub struct Toleration {
    "effect" => effect: String,
    "key" => key: String,
    "operator" => operator: String,
    "tolerationSeconds" => toleration_seconds: i64,
    "value" => value: String,
    }
}

native_object! {
    /// Selected native `TypedLocalObjectReference` members; unadmitted descendants remain private.
    pub struct TypedLocalObjectReference {
    "apiGroup" => api_group: String,
    "kind" => kind: String,
    "name" => name: String,
    }
}

native_object! {
    /// Selected native `VolumeResourceRequirements` members; unadmitted descendants remain private.
    pub struct VolumeResourceRequirements {
    "limits" => limits: BTreeMap<String, Quantity>,
    "requests" => requests: BTreeMap<String, Quantity>,
    }
}

native_object! {
    /// Selected native `VsphereVirtualDiskVolumeSource` members; unadmitted descendants remain private.
    pub struct VsphereVirtualDiskVolumeSource {
    "fsType" => fs_type: String,
    "storagePolicyID" => storage_policy_id: String,
    "storagePolicyName" => storage_policy_name: String,
    "volumePath" => volume_path: String,
    }
}

// Private shape knowledge only: no unknown value, key, token or source bytes are exposed.
pub(crate) trait UnknownScopes {
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    );
}
macro_rules! no_unknown {($($ty:ty),* $(,)?)=>{$(impl UnknownScopes for $ty{fn unknown_scopes(&self,_:&crate::diagnostic::FieldPath,_:&mut std::collections::BTreeSet<crate::diagnostic::FieldPath>) {}})*};}
no_unknown!(
    String,
    bool,
    i32,
    i64,
    Quantity,
    crate::value::NativeBytes,
    crate::value::IntOrString,
    LabelSelector,
    crate::value::SelectorRequirement,
    crate::model::Metadata,
    crate::model::OwnerReference
);
impl<T> UnknownScopes for crate::value::Protected<T> {
    fn unknown_scopes(
        &self,
        _: &crate::diagnostic::FieldPath,
        _: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
    }
}
impl<T: UnknownScopes> UnknownScopes for crate::value::Presence<T> {
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
        if let Self::Value(v) = self {
            v.unknown_scopes(path, out);
        }
    }
}
impl<T: UnknownScopes> UnknownScopes for Vec<T> {
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
        for (i, v) in self.iter().enumerate() {
            v.unknown_scopes(&path.child(i.to_string()), out);
        }
    }
}
impl<T: UnknownScopes> UnknownScopes for BTreeMap<String, T> {
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
        for (k, v) in self {
            v.unknown_scopes(&path.child(k.clone()), out);
        }
    }
}

// One declaration and sealed codec per shared shape; workload import paths are aliases.
mod native_helpers;
mod native_time;
mod workload_specs;
pub use native_helpers::*;
pub use native_time::NativeTime;
pub use workload_specs::*;
