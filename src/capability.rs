//! Finite profiles and source-backed declarations, separate from delivered native codecs.
use crate::{
    diagnostic::{Finding, FindingCode, Phase},
    model::{GroupVersionKind, ResourceScope},
};
use std::collections::BTreeMap;
/// Reviewed Kubernetes minor, closed to 1.20–1.37.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct KubernetesVersion {
    minor: u8,
}
impl KubernetesVersion {
    /// Lowest reviewed minor.
    pub const MIN: Self = Self { minor: 20 };
    /// Highest reviewed minor.
    pub const MAX: Self = Self { minor: 37 };
    /// Construct a frozen reviewed minor.
    /// # Errors
    /// Rejects unsupported majors/minors.
    pub fn new(major: u8, minor: u8) -> Result<Self, Finding> {
        if major == 1 && (20..=37).contains(&minor) {
            Ok(Self { minor })
        } else {
            Err(invalid_profile())
        }
    }
    /// Frozen major.
    #[must_use]
    pub const fn major(self) -> u8 {
        1
    }
    /// Selected minor.
    #[must_use]
    pub const fn minor(self) -> u8 {
        self.minor
    }
}
/// Closed reviewed feature-gate vocabulary.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum FeatureGateId {
    /// Ledger identifier `AdmissionWebhookMatchConditions`.
    AdmissionWebhookMatchConditions,
    /// Ledger identifier `AnyVolumeDataSource`.
    AnyVolumeDataSource,
    /// Ledger identifier `CSIInlineVolume`.
    CSIInlineVolume,
    /// Ledger identifier `CSIMigrationPortworx`.
    CSIMigrationPortworx,
    /// Ledger identifier `CSIPersistentVolume`.
    CSIPersistentVolume,
    /// Ledger identifier `ConfigurableFSGroupPolicy`.
    ConfigurableFSGroupPolicy,
    /// Ledger identifier `CronJobTimeZone`.
    CronJobTimeZone,
    /// Ledger identifier `CustomResourceValidationExpressions`.
    CustomResourceValidationExpressions,
    /// Ledger identifier `DaemonSetUpdateSurge`.
    DaemonSetUpdateSurge,
    /// Ledger identifier `EndpointSliceNodeName`.
    EndpointSliceNodeName,
    /// Ledger identifier `EndpointSliceTerminatingCondition`.
    EndpointSliceTerminatingCondition,
    /// Ledger identifier `ExpandCSIVolumes`.
    ExpandCSIVolumes,
    /// Ledger identifier `GenericEphemeralVolume`.
    GenericEphemeralVolume,
    /// Ledger identifier `HPAContainerMetrics`.
    HPAContainerMetrics,
    /// Ledger identifier `HPAScaleToZero`.
    HPAScaleToZero,
    /// Ledger identifier `IPv6DualStack`.
    IPv6DualStack,
    /// Ledger identifier `ImmutableEphemeralVolumes`.
    ImmutableEphemeralVolumes,
    /// Ledger identifier `InPlacePodVerticalScaling`.
    InPlacePodVerticalScaling,
    /// Ledger identifier `IndexedJob`.
    IndexedJob,
    /// Ledger identifier `IngressClassNamespacedParams`.
    IngressClassNamespacedParams,
    /// Ledger identifier `JobBackoffLimitPerIndex`.
    JobBackoffLimitPerIndex,
    /// Ledger identifier `JobPodFailurePolicy`.
    JobPodFailurePolicy,
    /// Ledger identifier `JobSuccessPolicy`.
    JobSuccessPolicy,
    /// Ledger identifier `MountPropagation`.
    MountPropagation,
    /// Ledger identifier `NonPreemptingPriority`.
    NonPreemptingPriority,
    /// Ledger identifier `PDBUnhealthyPodEvictionPolicy`.
    PDBUnhealthyPodEvictionPolicy,
    /// Ledger identifier `PodAffinityNamespaceSelector`.
    PodAffinityNamespaceSelector,
    /// Ledger identifier `PodLevelResources`.
    PodLevelResources,
    /// Ledger identifier `PodOverhead`.
    PodOverhead,
    /// Ledger identifier `PodSecurity`.
    PodSecurity,
    /// Ledger identifier `ProcMountType`.
    ProcMountType,
    /// Ledger identifier `ResourceQuotaScopeSelectors`.
    ResourceQuotaScopeSelectors,
    /// Ledger identifier `RunAsGroup`.
    RunAsGroup,
    /// Ledger identifier `RuntimeClass`.
    RuntimeClass,
    /// Ledger identifier `ServiceAppProtocol`.
    ServiceAppProtocol,
    /// Ledger identifier `ServiceInternalTrafficPolicy`.
    ServiceInternalTrafficPolicy,
    /// Ledger identifier `ServiceLBNodePortControl`.
    ServiceLBNodePortControl,
    /// Ledger identifier `ServiceLoadBalancerClass`.
    ServiceLoadBalancerClass,
    /// Ledger identifier `ServiceTrafficDistribution`.
    ServiceTrafficDistribution,
    /// Ledger identifier `SetHostnameAsFQDN`.
    SetHostnameAsFQDN,
    /// Ledger identifier `SidecarContainers`.
    SidecarContainers,
    /// Ledger identifier `StatefulSetAutoDeletePVC`.
    StatefulSetAutoDeletePVC,
    /// Ledger identifier `StatefulSetMinReadySeconds`.
    StatefulSetMinReadySeconds,
    /// Ledger identifier `StatefulSetStartOrdinal`.
    StatefulSetStartOrdinal,
    /// Ledger identifier `SuspendJob`.
    SuspendJob,
    /// Ledger identifier `TTLAfterFinished`.
    TTLAfterFinished,
    /// Ledger identifier `TaintTolerationComparisonOperators`.
    TaintTolerationComparisonOperators,
    /// Ledger identifier `UserNamespacesSupport`.
    UserNamespacesSupport,
    /// Ledger identifier `VolumePVCDataSource`.
    VolumePVCDataSource,
    /// Ledger identifier `VolumeScheduling`.
    VolumeScheduling,
    /// Ledger identifier `VolumeSnapshotDataSource`.
    VolumeSnapshotDataSource,
}
impl FeatureGateId {
    /// Every declared identifier in deterministic order.
    pub const ALL: &'static [Self] = &[
        Self::AdmissionWebhookMatchConditions,
        Self::AnyVolumeDataSource,
        Self::CSIInlineVolume,
        Self::CSIMigrationPortworx,
        Self::CSIPersistentVolume,
        Self::ConfigurableFSGroupPolicy,
        Self::CronJobTimeZone,
        Self::CustomResourceValidationExpressions,
        Self::DaemonSetUpdateSurge,
        Self::EndpointSliceNodeName,
        Self::EndpointSliceTerminatingCondition,
        Self::ExpandCSIVolumes,
        Self::GenericEphemeralVolume,
        Self::HPAContainerMetrics,
        Self::HPAScaleToZero,
        Self::IPv6DualStack,
        Self::ImmutableEphemeralVolumes,
        Self::InPlacePodVerticalScaling,
        Self::IndexedJob,
        Self::IngressClassNamespacedParams,
        Self::JobBackoffLimitPerIndex,
        Self::JobPodFailurePolicy,
        Self::JobSuccessPolicy,
        Self::MountPropagation,
        Self::NonPreemptingPriority,
        Self::PDBUnhealthyPodEvictionPolicy,
        Self::PodAffinityNamespaceSelector,
        Self::PodLevelResources,
        Self::PodOverhead,
        Self::PodSecurity,
        Self::ProcMountType,
        Self::ResourceQuotaScopeSelectors,
        Self::RunAsGroup,
        Self::RuntimeClass,
        Self::ServiceAppProtocol,
        Self::ServiceInternalTrafficPolicy,
        Self::ServiceLBNodePortControl,
        Self::ServiceLoadBalancerClass,
        Self::ServiceTrafficDistribution,
        Self::SetHostnameAsFQDN,
        Self::SidecarContainers,
        Self::StatefulSetAutoDeletePVC,
        Self::StatefulSetMinReadySeconds,
        Self::StatefulSetStartOrdinal,
        Self::SuspendJob,
        Self::TTLAfterFinished,
        Self::TaintTolerationComparisonOperators,
        Self::UserNamespacesSupport,
        Self::VolumePVCDataSource,
        Self::VolumeScheduling,
        Self::VolumeSnapshotDataSource,
    ];
    /// Exact finite ledger spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::AdmissionWebhookMatchConditions => "AdmissionWebhookMatchConditions",
            Self::AnyVolumeDataSource => "AnyVolumeDataSource",
            Self::CSIInlineVolume => "CSIInlineVolume",
            Self::CSIMigrationPortworx => "CSIMigrationPortworx",
            Self::CSIPersistentVolume => "CSIPersistentVolume",
            Self::ConfigurableFSGroupPolicy => "ConfigurableFSGroupPolicy",
            Self::CronJobTimeZone => "CronJobTimeZone",
            Self::CustomResourceValidationExpressions => "CustomResourceValidationExpressions",
            Self::DaemonSetUpdateSurge => "DaemonSetUpdateSurge",
            Self::EndpointSliceNodeName => "EndpointSliceNodeName",
            Self::EndpointSliceTerminatingCondition => "EndpointSliceTerminatingCondition",
            Self::ExpandCSIVolumes => "ExpandCSIVolumes",
            Self::GenericEphemeralVolume => "GenericEphemeralVolume",
            Self::HPAContainerMetrics => "HPAContainerMetrics",
            Self::HPAScaleToZero => "HPAScaleToZero",
            Self::IPv6DualStack => "IPv6DualStack",
            Self::ImmutableEphemeralVolumes => "ImmutableEphemeralVolumes",
            Self::InPlacePodVerticalScaling => "InPlacePodVerticalScaling",
            Self::IndexedJob => "IndexedJob",
            Self::IngressClassNamespacedParams => "IngressClassNamespacedParams",
            Self::JobBackoffLimitPerIndex => "JobBackoffLimitPerIndex",
            Self::JobPodFailurePolicy => "JobPodFailurePolicy",
            Self::JobSuccessPolicy => "JobSuccessPolicy",
            Self::MountPropagation => "MountPropagation",
            Self::NonPreemptingPriority => "NonPreemptingPriority",
            Self::PDBUnhealthyPodEvictionPolicy => "PDBUnhealthyPodEvictionPolicy",
            Self::PodAffinityNamespaceSelector => "PodAffinityNamespaceSelector",
            Self::PodLevelResources => "PodLevelResources",
            Self::PodOverhead => "PodOverhead",
            Self::PodSecurity => "PodSecurity",
            Self::ProcMountType => "ProcMountType",
            Self::ResourceQuotaScopeSelectors => "ResourceQuotaScopeSelectors",
            Self::RunAsGroup => "RunAsGroup",
            Self::RuntimeClass => "RuntimeClass",
            Self::ServiceAppProtocol => "ServiceAppProtocol",
            Self::ServiceInternalTrafficPolicy => "ServiceInternalTrafficPolicy",
            Self::ServiceLBNodePortControl => "ServiceLBNodePortControl",
            Self::ServiceLoadBalancerClass => "ServiceLoadBalancerClass",
            Self::ServiceTrafficDistribution => "ServiceTrafficDistribution",
            Self::SetHostnameAsFQDN => "SetHostnameAsFQDN",
            Self::SidecarContainers => "SidecarContainers",
            Self::StatefulSetAutoDeletePVC => "StatefulSetAutoDeletePVC",
            Self::StatefulSetMinReadySeconds => "StatefulSetMinReadySeconds",
            Self::StatefulSetStartOrdinal => "StatefulSetStartOrdinal",
            Self::SuspendJob => "SuspendJob",
            Self::TTLAfterFinished => "TTLAfterFinished",
            Self::TaintTolerationComparisonOperators => "TaintTolerationComparisonOperators",
            Self::UserNamespacesSupport => "UserNamespacesSupport",
            Self::VolumePVCDataSource => "VolumePVCDataSource",
            Self::VolumeScheduling => "VolumeScheduling",
            Self::VolumeSnapshotDataSource => "VolumeSnapshotDataSource",
        }
    }
}
/// Declared built-in kinds; this is not a delivered-support claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum KindId {
    /// Ledger identifier `Pod`.
    Pod,
    /// Ledger identifier `Deployment`.
    Deployment,
    /// Ledger identifier `StatefulSet`.
    StatefulSet,
    /// Ledger identifier `DaemonSet`.
    DaemonSet,
    /// Ledger identifier `ReplicaSet`.
    ReplicaSet,
    /// Ledger identifier `ReplicationController`.
    ReplicationController,
    /// Ledger identifier `Job`.
    Job,
    /// Ledger identifier `CronJob`.
    CronJob,
    /// Ledger identifier `Service`.
    Service,
    /// Ledger identifier `Endpoints`.
    Endpoints,
    /// Ledger identifier `EndpointSlice`.
    EndpointSlice,
    /// Ledger identifier `Ingress`.
    Ingress,
    /// Ledger identifier `IngressClass`.
    IngressClass,
    /// Ledger identifier `NetworkPolicy`.
    NetworkPolicy,
    /// Ledger identifier `ConfigMap`.
    ConfigMap,
    /// Ledger identifier `Secret`.
    Secret,
    /// Ledger identifier `PersistentVolumeClaim`.
    PersistentVolumeClaim,
    /// Ledger identifier `PersistentVolume`.
    PersistentVolume,
    /// Ledger identifier `StorageClass`.
    StorageClass,
    /// Ledger identifier `Namespace`.
    Namespace,
    /// Ledger identifier `ServiceAccount`.
    ServiceAccount,
    /// Ledger identifier `Role`.
    Role,
    /// Ledger identifier `RoleBinding`.
    RoleBinding,
    /// Ledger identifier `ClusterRole`.
    ClusterRole,
    /// Ledger identifier `ClusterRoleBinding`.
    ClusterRoleBinding,
    /// Ledger identifier `HorizontalPodAutoscaler`.
    HorizontalPodAutoscaler,
    /// Ledger identifier `PodDisruptionBudget`.
    PodDisruptionBudget,
    /// Ledger identifier `ResourceQuota`.
    ResourceQuota,
    /// Ledger identifier `LimitRange`.
    LimitRange,
    /// Ledger identifier `PriorityClass`.
    PriorityClass,
    /// Ledger identifier `RuntimeClass`.
    RuntimeClass,
    /// Ledger identifier `PodSecurityPolicy`.
    PodSecurityPolicy,
    /// Ledger identifier `CustomResourceDefinition`.
    CustomResourceDefinition,
    /// Ledger identifier `MutatingWebhookConfiguration`.
    MutatingWebhookConfiguration,
    /// Ledger identifier `ValidatingWebhookConfiguration`.
    ValidatingWebhookConfiguration,
}
impl KindId {
    /// Every declared identifier in deterministic order.
    pub const ALL: &'static [Self] = &[
        Self::Pod,
        Self::Deployment,
        Self::StatefulSet,
        Self::DaemonSet,
        Self::ReplicaSet,
        Self::ReplicationController,
        Self::Job,
        Self::CronJob,
        Self::Service,
        Self::Endpoints,
        Self::EndpointSlice,
        Self::Ingress,
        Self::IngressClass,
        Self::NetworkPolicy,
        Self::ConfigMap,
        Self::Secret,
        Self::PersistentVolumeClaim,
        Self::PersistentVolume,
        Self::StorageClass,
        Self::Namespace,
        Self::ServiceAccount,
        Self::Role,
        Self::RoleBinding,
        Self::ClusterRole,
        Self::ClusterRoleBinding,
        Self::HorizontalPodAutoscaler,
        Self::PodDisruptionBudget,
        Self::ResourceQuota,
        Self::LimitRange,
        Self::PriorityClass,
        Self::RuntimeClass,
        Self::PodSecurityPolicy,
        Self::CustomResourceDefinition,
        Self::MutatingWebhookConfiguration,
        Self::ValidatingWebhookConfiguration,
    ];
    /// Exact finite ledger spelling.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Pod => "Pod",
            Self::Deployment => "Deployment",
            Self::StatefulSet => "StatefulSet",
            Self::DaemonSet => "DaemonSet",
            Self::ReplicaSet => "ReplicaSet",
            Self::ReplicationController => "ReplicationController",
            Self::Job => "Job",
            Self::CronJob => "CronJob",
            Self::Service => "Service",
            Self::Endpoints => "Endpoints",
            Self::EndpointSlice => "EndpointSlice",
            Self::Ingress => "Ingress",
            Self::IngressClass => "IngressClass",
            Self::NetworkPolicy => "NetworkPolicy",
            Self::ConfigMap => "ConfigMap",
            Self::Secret => "Secret",
            Self::PersistentVolumeClaim => "PersistentVolumeClaim",
            Self::PersistentVolume => "PersistentVolume",
            Self::StorageClass => "StorageClass",
            Self::Namespace => "Namespace",
            Self::ServiceAccount => "ServiceAccount",
            Self::Role => "Role",
            Self::RoleBinding => "RoleBinding",
            Self::ClusterRole => "ClusterRole",
            Self::ClusterRoleBinding => "ClusterRoleBinding",
            Self::HorizontalPodAutoscaler => "HorizontalPodAutoscaler",
            Self::PodDisruptionBudget => "PodDisruptionBudget",
            Self::ResourceQuota => "ResourceQuota",
            Self::LimitRange => "LimitRange",
            Self::PriorityClass => "PriorityClass",
            Self::RuntimeClass => "RuntimeClass",
            Self::PodSecurityPolicy => "PodSecurityPolicy",
            Self::CustomResourceDefinition => "CustomResourceDefinition",
            Self::MutatingWebhookConfiguration => "MutatingWebhookConfiguration",
            Self::ValidatingWebhookConfiguration => "ValidatingWebhookConfiguration",
        }
    }
}
/// Explicit gate state; unknown never authorizes emission.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureGateState {
    /// Explicit enabled state.
    Enabled,
    /// Explicit disabled state.
    Disabled,
    /// No established setting.
    Unknown,
}
/// Reviewed versioned documentation, never cluster observation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FeatureGateEvidenceId {
    /// Immutable issue-eight source records.
    Issue8Ledger,
}
/// Caller-selected gate resolution.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Default)]
pub enum FeatureGateResolution {
    /// Require every gate setting; unknown blocks.
    #[default]
    RequireExplicit,
    /// Explicitly opt into documented defaults.
    ResolveFromEvidence(FeatureGateEvidenceId),
}
/// Explicit settings independent of authored fields/source version.
#[derive(Clone, Debug, Default)]
pub struct FeatureGateProfile {
    /// Finite caller settings.
    pub states: BTreeMap<FeatureGateId, FeatureGateState>,
    /// Caller-selected evidence policy.
    pub resolution: FeatureGateResolution,
}
/// Finite renderer expectations only; no renderer invocation/execution API.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RendererProfile {
    /// Historical Helm profile.
    Helm3_22,
    /// Modern Helm profile.
    Helm4_3,
    /// Historical restricted Kustomize syntax.
    Kustomize2_0_3,
    /// Modern Kustomize syntax.
    Kustomize5_8_3,
}
/// Explicit output target.
#[derive(Clone, Debug)]
pub struct TargetProfile {
    /// Reviewed Kubernetes minor.
    pub kubernetes: KubernetesVersion,
    /// Optional finite renderer expectation.
    pub renderer: Option<RendererProfile>,
    /// Explicit feature-gate settings/default evidence.
    pub feature_gates: FeatureGateProfile,
}
impl TargetProfile {
    /// Select a version and explicitly opt into documented gate defaults.
    #[must_use]
    pub fn documented_defaults(kubernetes: KubernetesVersion) -> Self {
        Self {
            kubernetes,
            renderer: None,
            feature_gates: FeatureGateProfile {
                states: BTreeMap::new(),
                resolution: FeatureGateResolution::ResolveFromEvidence(FeatureGateEvidenceId::Issue8Ledger),
            },
        }
    }
    /// Check complete settings and removed gate configuration.
    #[must_use]
    pub fn findings(&self) -> Vec<Finding> {
        FeatureGateId::ALL
            .iter()
            .filter_map(|id| self.feature_gates.resolve(*id, self.kubernetes).err())
            .collect()
    }
}
#[derive(Clone, Copy)]
struct GateStage {
    first: u8,
    last: u8,
    enabled: bool,
    stable: bool,
}
const GATE_STAGES: &[(&[GateStage], bool)] = &[
    (
        &[
            GateStage {
                first: 27,
                last: 27,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 28,
                last: 29,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 30,
                last: 32,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // AdmissionWebhookMatchConditions
    (
        &[
            GateStage {
                first: 18,
                last: 23,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // AnyVolumeDataSource
    (
        &[
            GateStage {
                first: 15,
                last: 15,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 16,
                last: 24,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 26,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // CSIInlineVolume
    (
        &[
            GateStage {
                first: 23,
                last: 24,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 30,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 35,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // CSIMigrationPortworx
    (
        &[
            GateStage {
                first: 9,
                last: 9,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 10,
                last: 12,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 13,
                last: 16,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // CSIPersistentVolume
    (
        &[
            GateStage {
                first: 18,
                last: 19,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 20,
                last: 22,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ConfigurableFSGroupPolicy
    (
        &[
            GateStage {
                first: 24,
                last: 24,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 26,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 27,
                last: 28,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // CronJobTimeZone
    (
        &[
            GateStage {
                first: 23,
                last: 24,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 28,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 29,
                last: 30,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // CustomResourceValidationExpressions
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 24,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 26,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // DaemonSetUpdateSurge
    (
        &[
            GateStage {
                first: 20,
                last: 20,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // EndpointSliceNodeName
    (
        &[
            GateStage {
                first: 20,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 25,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 26,
                last: 27,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // EndpointSliceTerminatingCondition
    (
        &[
            GateStage {
                first: 14,
                last: 15,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 16,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 26,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ExpandCSIVolumes
    (
        &[
            GateStage {
                first: 19,
                last: 20,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 22,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // GenericEphemeralVolume
    (
        &[
            GateStage {
                first: 20,
                last: 26,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 27,
                last: 29,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 30,
                last: 31,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // HPAContainerMetrics
    (
        &[
            GateStage {
                first: 16,
                last: 36,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 37,
                last: 37,
                enabled: true,
                stable: false,
            },
        ],
        false,
    ), // HPAScaleToZero
    (
        &[
            GateStage {
                first: 15,
                last: 20,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 22,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // IPv6DualStack
    (
        &[
            GateStage {
                first: 18,
                last: 18,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 19,
                last: 20,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ImmutableEphemeralVolumes
    (
        &[
            GateStage {
                first: 27,
                last: 32,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 34,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 35,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // InPlacePodVerticalScaling
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // IndexedJob
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 22,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // IngressClassNamespacedParams
    (
        &[
            GateStage {
                first: 28,
                last: 28,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 29,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // JobBackoffLimitPerIndex
    (
        &[
            GateStage {
                first: 25,
                last: 25,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 26,
                last: 30,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // JobPodFailurePolicy
    (
        &[
            GateStage {
                first: 30,
                last: 30,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // JobSuccessPolicy
    (
        &[
            GateStage {
                first: 8,
                last: 9,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 10,
                last: 11,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 12,
                last: 14,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // MountPropagation
    (
        &[
            GateStage {
                first: 15,
                last: 18,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 19,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // NonPreemptingPriority
    (
        &[
            GateStage {
                first: 26,
                last: 26,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 27,
                last: 30,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // PDBUnhealthyPodEvictionPolicy
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // PodAffinityNamespaceSelector
    (
        &[
            GateStage {
                first: 32,
                last: 33,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 34,
                last: 37,
                enabled: true,
                stable: false,
            },
        ],
        false,
    ), // PodLevelResources
    (
        &[
            GateStage {
                first: 16,
                last: 17,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 18,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // PodOverhead
    (
        &[
            GateStage {
                first: 22,
                last: 22,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 27,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // PodSecurity
    (
        &[
            GateStage {
                first: 12,
                last: 30,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 35,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 36,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // ProcMountType
    (
        &[
            GateStage {
                first: 11,
                last: 11,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 12,
                last: 16,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 17,
                last: 18,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ResourceQuotaScopeSelectors
    (
        &[
            GateStage {
                first: 14,
                last: 20,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 22,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // RunAsGroup
    (
        &[
            GateStage {
                first: 12,
                last: 13,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 14,
                last: 19,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 20,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // RuntimeClass
    (
        &[
            GateStage {
                first: 18,
                last: 18,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 19,
                last: 19,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 20,
                last: 22,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ServiceAppProtocol
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 25,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 26,
                last: 27,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ServiceInternalTrafficPolicy
    (
        &[
            GateStage {
                first: 20,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ServiceLBNodePortControl
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // ServiceLoadBalancerClass
    (
        &[
            GateStage {
                first: 30,
                last: 30,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // ServiceTrafficDistribution
    (
        &[
            GateStage {
                first: 19,
                last: 19,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 20,
                last: 21,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // SetHostnameAsFQDN
    (
        &[
            GateStage {
                first: 28,
                last: 28,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 29,
                last: 32,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // SidecarContainers
    (
        &[
            GateStage {
                first: 23,
                last: 26,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 27,
                last: 31,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 32,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // StatefulSetAutoDeletePVC
    (
        &[
            GateStage {
                first: 22,
                last: 22,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 25,
                last: 26,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // StatefulSetMinReadySeconds
    (
        &[
            GateStage {
                first: 26,
                last: 26,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 27,
                last: 30,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 31,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // StatefulSetStartOrdinal
    (
        &[
            GateStage {
                first: 21,
                last: 21,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 22,
                last: 23,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 24,
                last: 25,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // SuspendJob
    (
        &[
            GateStage {
                first: 12,
                last: 20,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 21,
                last: 22,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 23,
                last: 24,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // TTLAfterFinished
    (
        &[GateStage {
            first: 35,
            last: 37,
            enabled: false,
            stable: false,
        }],
        false,
    ), // TaintTolerationComparisonOperators
    (
        &[
            GateStage {
                first: 28,
                last: 29,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 30,
                last: 32,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 33,
                last: 35,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 36,
                last: 37,
                enabled: true,
                stable: true,
            },
        ],
        false,
    ), // UserNamespacesSupport
    (
        &[
            GateStage {
                first: 15,
                last: 15,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 16,
                last: 17,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 18,
                last: 21,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // VolumePVCDataSource
    (
        &[
            GateStage {
                first: 9,
                last: 9,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 10,
                last: 12,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 13,
                last: 16,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // VolumeScheduling
    (
        &[
            GateStage {
                first: 12,
                last: 16,
                enabled: false,
                stable: false,
            },
            GateStage {
                first: 17,
                last: 19,
                enabled: true,
                stable: false,
            },
            GateStage {
                first: 20,
                last: 22,
                enabled: true,
                stable: true,
            },
        ],
        true,
    ), // VolumeSnapshotDataSource
];
fn gate_stages(id: FeatureGateId) -> (&'static [GateStage], bool) {
    GATE_STAGES[id as usize]
}
impl FeatureGateProfile {
    /// Resolve one explicit/versioned setting without inventing authored defaults.
    /// # Errors
    /// Rejects unknown settings and explicit toggles of removed stable gates.
    pub fn resolve(&self, id: FeatureGateId, version: KubernetesVersion) -> Result<FeatureGateState, Finding> {
        let (stages, removed) = gate_stages(id);
        let stage = stages
            .iter()
            .find(|stage| stage.first <= version.minor && version.minor <= stage.last);
        let locked = removed
            && stages
                .last()
                .is_some_and(|last| last.stable && version.minor > last.last);
        let explicit = self.states.get(&id).copied();
        if locked && explicit.is_some_and(|state| state != FeatureGateState::Unknown) {
            return Err(invalid_profile());
        }
        if let Some(state @ (FeatureGateState::Enabled | FeatureGateState::Disabled)) = explicit {
            return Ok(state);
        }
        if explicit == Some(FeatureGateState::Unknown) || self.resolution == FeatureGateResolution::RequireExplicit {
            return Err(invalid_profile());
        }
        let enabled = locked || stage.is_some_and(|stage| stage.enabled);
        Ok(if enabled {
            FeatureGateState::Enabled
        } else {
            FeatureGateState::Disabled
        })
    }
}
fn invalid_profile() -> Finding {
    Finding::error(FindingCode::InvalidTargetProfile, Phase::Validation)
}
/// Codec-declared structural delta policy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MergeStrategy {
    /// Scalar replacement.
    Scalar,
    /// Recursive object delta.
    Object,
    /// Recursive map delta.
    Map,
    /// Whole-list replacement, checked for unknown-data loss.
    AtomicList,
    /// Whole value-set semantics, checked for unknown-data loss.
    SetList,
    /// Match items by all declared keys.
    MapList {
        /// Exact scalar key names; never inferred.
        keys: &'static [&'static str],
    },
}
/// Delivered field admission, independent of schema existence.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FieldAdmission {
    /// Implemented/validated typed subset.
    Typed,
    /// Preservation only.
    PreserveOnly,
    /// Not representable.
    Unsupported,
}
/// Codec-owned field contract.
#[derive(Clone, Debug)]
pub struct FieldCapability {
    /// Exact schema pointer.
    pub path: &'static str,
    /// First reviewed minor.
    pub since: KubernetesVersion,
    /// Required gate.
    pub feature_gate: Option<FeatureGateId>,
    /// Exclusive removal minor.
    pub removed: Option<KubernetesVersion>,
    /// Deprecation evidence.
    pub deprecated: Option<KubernetesVersion>,
    /// Delivered field admission.
    pub admission: FieldAdmission,
    /// Declared list/object merge semantics.
    pub merge: MergeStrategy,
    /// Fixed semantic note.
    pub semantic_note: Option<&'static str>,
}
/// Delivered codec contract; declarations cannot self-admit a codec.
#[derive(Clone, Debug)]
pub struct KindCapability {
    /// Exact served GVK.
    pub gvk: GroupVersionKind,
    /// Native scope.
    pub scope: ResourceScope,
    /// First reviewed minor.
    pub api_since: KubernetesVersion,
    /// Exclusive API removal minor.
    pub api_removed: Option<KubernetesVersion>,
    /// Delivered field contracts.
    pub fields: &'static [FieldCapability],
}
/// Source-backed API descriptor, preservation-only until a codec is delivered.
#[derive(Clone, Copy, Debug)]
pub struct DeclaredApi {
    /// Exact API spelling.
    pub api_version: &'static str,
    /// Declared native kind.
    pub kind: KindId,
    /// Native scope.
    pub scope: ResourceScope,
    /// Inclusive first minor.
    pub first: u8,
    /// Inclusive last minor.
    pub last: u8,
}
/// Immutable reviewed API facts; not native conformance.
pub const DECLARED_APIS: &[DeclaredApi] = &[
    DeclaredApi {
        api_version: "v1",
        kind: KindId::Pod,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "apps/v1",
        kind: KindId::Deployment,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "apps/v1",
        kind: KindId::StatefulSet,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "apps/v1",
        kind: KindId::DaemonSet,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "apps/v1",
        kind: KindId::ReplicaSet,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::ReplicationController,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "batch/v1",
        kind: KindId::Job,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "batch/v1",
        kind: KindId::CronJob,
        scope: ResourceScope::Namespaced,
        first: 21,
        last: 37,
    },
    DeclaredApi {
        api_version: "batch/v1beta1",
        kind: KindId::CronJob,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::Service,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::Endpoints,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "discovery.k8s.io/v1",
        kind: KindId::EndpointSlice,
        scope: ResourceScope::Namespaced,
        first: 21,
        last: 37,
    },
    DeclaredApi {
        api_version: "discovery.k8s.io/v1beta1",
        kind: KindId::EndpointSlice,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "extensions/v1beta1",
        kind: KindId::Ingress,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 21,
    },
    DeclaredApi {
        api_version: "networking.k8s.io/v1",
        kind: KindId::Ingress,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "networking.k8s.io/v1beta1",
        kind: KindId::Ingress,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 21,
    },
    DeclaredApi {
        api_version: "networking.k8s.io/v1",
        kind: KindId::IngressClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "networking.k8s.io/v1beta1",
        kind: KindId::IngressClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 21,
    },
    DeclaredApi {
        api_version: "networking.k8s.io/v1",
        kind: KindId::NetworkPolicy,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::ConfigMap,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::Secret,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::PersistentVolumeClaim,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::PersistentVolume,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "storage.k8s.io/v1",
        kind: KindId::StorageClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::Namespace,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::ServiceAccount,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "rbac.authorization.k8s.io/v1",
        kind: KindId::Role,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "rbac.authorization.k8s.io/v1",
        kind: KindId::RoleBinding,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "rbac.authorization.k8s.io/v1",
        kind: KindId::ClusterRole,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "rbac.authorization.k8s.io/v1",
        kind: KindId::ClusterRoleBinding,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "autoscaling/v1",
        kind: KindId::HorizontalPodAutoscaler,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "autoscaling/v2",
        kind: KindId::HorizontalPodAutoscaler,
        scope: ResourceScope::Namespaced,
        first: 23,
        last: 37,
    },
    DeclaredApi {
        api_version: "autoscaling/v2beta1",
        kind: KindId::HorizontalPodAutoscaler,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "autoscaling/v2beta2",
        kind: KindId::HorizontalPodAutoscaler,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 25,
    },
    DeclaredApi {
        api_version: "policy/v1",
        kind: KindId::PodDisruptionBudget,
        scope: ResourceScope::Namespaced,
        first: 21,
        last: 37,
    },
    DeclaredApi {
        api_version: "policy/v1beta1",
        kind: KindId::PodDisruptionBudget,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::ResourceQuota,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "v1",
        kind: KindId::LimitRange,
        scope: ResourceScope::Namespaced,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "scheduling.k8s.io/v1",
        kind: KindId::PriorityClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "node.k8s.io/v1",
        kind: KindId::RuntimeClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "node.k8s.io/v1beta1",
        kind: KindId::RuntimeClass,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "policy/v1beta1",
        kind: KindId::PodSecurityPolicy,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 24,
    },
    DeclaredApi {
        api_version: "apiextensions.k8s.io/v1",
        kind: KindId::CustomResourceDefinition,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "apiextensions.k8s.io/v1beta1",
        kind: KindId::CustomResourceDefinition,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 21,
    },
    DeclaredApi {
        api_version: "admissionregistration.k8s.io/v1",
        kind: KindId::MutatingWebhookConfiguration,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "admissionregistration.k8s.io/v1beta1",
        kind: KindId::MutatingWebhookConfiguration,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 21,
    },
    DeclaredApi {
        api_version: "admissionregistration.k8s.io/v1",
        kind: KindId::ValidatingWebhookConfiguration,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 37,
    },
    DeclaredApi {
        api_version: "admissionregistration.k8s.io/v1beta1",
        kind: KindId::ValidatingWebhookConfiguration,
        scope: ResourceScope::Cluster,
        first: 20,
        last: 21,
    },
];
pub(crate) fn declaration(gvk: &GroupVersionKind) -> Option<&'static DeclaredApi> {
    DECLARED_APIS
        .iter()
        .find(|entry| entry.kind.as_str() == gvk.kind && entry.api_version == gvk.api_version())
}
/// Embedded immutable source facts retain attribution/license records.
#[must_use]
pub fn capability_ledger_bytes() -> &'static [u8] {
    include_bytes!("../schemas/capabilities/kubernetes-1.20-1.37.json")
}

/// Traverse source-ledger evidence directly into the caller's shared, charged sink.
pub(crate) fn source_field_findings(
    tree: &crate::syntax::TreeNode,
    gvk: &GroupVersionKind,
    target: &TargetProfile,
    processing: &crate::processing::NativeOperationBudget,
    phase: Phase,
    out: &mut dyn crate::registry::FindingSink,
) {
    use std::sync::OnceLock;
    static LEDGER: OnceLock<Option<serde_json::Value>> = OnceLock::new();
    if processing.exhausted() || out.exhausted() {
        return;
    }
    if let Err(finding) = processing.work(1, phase) {
        out.push(finding);
        return;
    }
    let Some(ledger) = LEDGER
        .get_or_init(|| serde_json::from_slice(capability_ledger_bytes()).ok())
        .as_ref()
    else {
        out.push(invalid_profile());
        return;
    };
    let mut session = SourceFieldSession {
        ledger,
        target,
        processing,
        phase,
        out,
        profile: format!("k8s-1.{}-0", target.kubernetes.minor()),
    };
    let Some(resource) = ledger["resources"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["kind"].as_str() == Some(gvk.kind.as_str())))
    else {
        return;
    };
    let api = gvk.api_version();
    let Some(profile) = resource["proposed_admitted_api_profiles"].as_array().and_then(|rows| {
        rows.iter()
            .find(|row| row["api_version"].as_str() == Some(api.as_str()))
    }) else {
        return;
    };
    if let Some(fields) = profile["typed_field_pointers"].as_array() {
        for field in fields {
            if !session.tick() {
                return;
            }
            let Some(pointer) = field["pointer"].as_str() else {
                continue;
            };
            let Ok(path) = crate::diagnostic::FieldPath::parse(pointer) else {
                continue;
            };
            if let Some(node) = source_node(tree, &path.0, &mut session) {
                source_field(node, field, (None, &path), &mut session, 0);
            }
        }
    }
    contextual_findings(tree, gvk, &mut session);
}

struct SourceFieldSession<'a> {
    ledger: &'a serde_json::Value,
    target: &'a TargetProfile,
    processing: &'a crate::processing::NativeOperationBudget,
    phase: Phase,
    out: &'a mut dyn crate::registry::FindingSink,
    profile: String,
}
impl SourceFieldSession<'_> {
    fn tick(&mut self) -> bool {
        if self.processing.exhausted() || self.out.exhausted() {
            return false;
        }
        match self.processing.work(1, self.phase) {
            Ok(()) => true,
            Err(finding) => {
                self.out.push(finding);
                false
            }
        }
    }
    fn depth(&mut self, depth: usize) -> bool {
        if !self.tick() {
            return false;
        }
        if depth > 128 {
            self.out.push(self.processing.fail(self.phase));
            return false;
        }
        true
    }
    fn finding(&mut self, code: FindingCode, path: &crate::diagnostic::FieldPath) {
        if self.tick() {
            self.out.push(Finding::error(code, self.phase).at_path(path.clone()));
        }
    }
}

// Exact source pointers allow sequence indices; contextual patterns use the existing
// field_nodes semantics (wildcards plus mapping-key lookup), without collecting nodes.
fn source_node<'a>(
    mut node: &'a crate::syntax::TreeNode,
    segments: &[String],
    session: &mut SourceFieldSession<'_>,
) -> Option<&'a crate::syntax::TreeNode> {
    for segment in segments {
        if !session.tick() {
            return None;
        }
        node = if let Some(entries) = node.as_mapping() {
            let mut found = None;
            for (key, value) in entries {
                if !session.tick() {
                    return None;
                }
                if key == segment {
                    found = Some(value);
                    break;
                }
            }
            found?
        } else {
            node.as_sequence()?.get(segment.parse::<usize>().ok()?)?
        };
    }
    Some(node)
}
fn contextual_present(
    node: &crate::syntax::TreeNode,
    segments: &[String],
    session: &mut SourceFieldSession<'_>,
) -> bool {
    if !session.tick() {
        return false;
    }
    let Some((segment, rest)) = segments.split_first() else {
        return true;
    };
    if segment == "*" {
        if let Some(items) = node.as_sequence() {
            for item in items {
                if !session.tick() {
                    return false;
                }
                if contextual_present(item, rest, session) {
                    return true;
                }
            }
        } else if let Some(entries) = node.as_mapping() {
            for (_, value) in entries {
                if !session.tick() {
                    return false;
                }
                if contextual_present(value, rest, session) {
                    return true;
                }
            }
        }
    } else if let Some(entries) = node.as_mapping() {
        for (name, value) in entries {
            if !session.tick() {
                return false;
            }
            if name == segment {
                return contextual_present(value, rest, session);
            }
        }
    }
    false
}
fn contextual_findings(tree: &crate::syntax::TreeNode, gvk: &GroupVersionKind, session: &mut SourceFieldSession<'_>) {
    let ledger = session.ledger;
    let Some(contexts) = ledger["contextual_typed_members"].as_array() else {
        return;
    };
    let Some(prefix) = ledger["template_context_bindings"]["PodSpec"][&gvk.kind].as_str() else {
        return;
    };
    for context in contexts {
        if !session.tick() {
            return;
        }
        let Some(suffix) = context["pointer_pattern"]
            .as_str()
            .and_then(|p| p.strip_prefix("/spec"))
        else {
            continue;
        };
        let pattern = format!("{prefix}{suffix}");
        let Ok(path) = crate::diagnostic::FieldPath::parse(&pattern) else {
            continue;
        };
        if contextual_present(tree, &path.0, session) {
            let available = context["schema_presence_ranges"].as_array().is_some_and(|ranges| {
                ranges.iter().any(|range| {
                    let minor = |name| {
                        range[name]
                            .as_str()
                            .and_then(|s| s.strip_prefix("1."))
                            .and_then(|s| s.parse::<u8>().ok())
                    };
                    minor("from")
                        .zip(minor("through"))
                        .is_some_and(|(first, last)| (first..=last).contains(&session.target.kubernetes.minor()))
                })
            });
            let code = if !available {
                Some(FindingCode::UnavailableField)
            } else if FeatureGateId::ALL
                .iter()
                .find(|id| Some(id.as_str()) == context["gate"].as_str())
                .is_some_and(|id| {
                    session.target.feature_gates.resolve(*id, session.target.kubernetes)
                        != Ok(FeatureGateState::Enabled)
                })
            {
                Some(FindingCode::FeatureGateRequired)
            } else {
                None
            };
            if let Some(code) = code {
                session.finding(code, &path);
            }
        }
        if !session.tick() {
            return;
        }
        let regular = pattern.replace("/initContainers/", "/containers/");
        if regular != pattern {
            if let Ok(path) = crate::diagnostic::FieldPath::parse(&regular) {
                if contextual_present(tree, &path.0, session) {
                    session.finding(FindingCode::NativeFieldInvalid, &path);
                }
            }
        }
    }
}
fn source_field(
    node: &crate::syntax::TreeNode,
    fact: &serde_json::Value,
    location: (Option<(&str, &str)>, &crate::diagnostic::FieldPath),
    session: &mut SourceFieldSession<'_>,
    depth: usize,
) {
    if !session.depth(depth) {
        return;
    }
    let (_, path) = location;
    let forms = fact["schema_forms"].as_array();
    let selected = forms.and_then(|forms| {
        forms.iter().find(|form| {
            form["source_schema_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(session.profile.as_str())))
        })
    });
    let form = selected.or_else(|| forms.and_then(|forms| forms.first()));
    source_enum(
        node,
        fact,
        form.and_then(|form| form.get("schema_shape")),
        path,
        session,
    );
    if !session.tick() {
        return;
    }
    if selected.is_none() {
        session.finding(FindingCode::UnavailableField, path);
    }
    if !session.tick() {
        return;
    }
    if let Some(constraints) = fact["native_constraints"].as_array() {
        for rule in constraints {
            if !session.tick() {
                return;
            }
            if rule["rule"].as_str() == Some("feature_gate")
                || rule["rule"].as_str() == Some("value_predicate") && rule["gate"].is_string()
            {
                source_gate_constraint(node, rule, path, session);
            }
        }
    }
    if let Some(shape) = form.and_then(|form| form.get("schema_shape")) {
        source_shape(node, shape, path, session, depth + 1);
    }
    // Root pointers are not prefix admission; only finite helper member facts are traversed.
}
/// Finite selection is separate from native shape validity and gate/version availability.
fn source_enum(
    node: &crate::syntax::TreeNode,
    fact: &serde_json::Value,
    shape: Option<&serde_json::Value>,
    path: &crate::diagnostic::FieldPath,
    session: &mut SourceFieldSession<'_>,
) {
    let Some(constraints) = fact["native_constraints"].as_array() else {
        return;
    };
    let mut has_enum = false;
    for constraint in constraints {
        if !session.tick() {
            return;
        }
        has_enum |= constraint["rule"].as_str() == Some("enum");
    }
    if !has_enum || matches!(node.value, crate::syntax::TreeValue::Null) {
        return;
    }
    let declared_type = shape.and_then(|shape| shape["type"].as_str());
    if declared_type == Some("array") && node.as_sequence().is_none()
        || declared_type == Some("string") && node.as_str().is_none()
    {
        session.finding(FindingCode::NativeFieldInvalid, path);
        return;
    }
    if let Some(items) = node.as_sequence() {
        for (index, item) in items.iter().enumerate() {
            if !session.tick() {
                return;
            }
            if item.as_str().is_none() {
                session.finding(FindingCode::NativeFieldInvalid, &path.child(index.to_string()));
            } else if enum_unselected(item, constraints, session) {
                session.finding(FindingCode::UnadmittedField, &path.child(index.to_string()));
            }
        }
    } else if enum_unselected(node, constraints, session) {
        session.finding(FindingCode::UnadmittedField, path);
    }
}
fn enum_unselected(
    node: &crate::syntax::TreeNode,
    constraints: &[serde_json::Value],
    session: &mut SourceFieldSession<'_>,
) -> bool {
    let Some(value) = node.as_str() else {
        return false;
    };
    for constraint in constraints {
        if !session.tick() {
            return false;
        }
        if constraint["rule"].as_str() != Some("enum") {
            continue;
        }
        let Some(values) = constraint["values"].as_array() else {
            continue;
        };
        let mut selected = false;
        for candidate in values {
            if !session.tick() {
                return false;
            }
            let Some(candidate) = candidate.as_str() else {
                continue;
            };
            if let Err(finding) = session
                .processing
                .work(value.len().saturating_add(candidate.len()), session.phase)
            {
                session.out.push(finding);
                return false;
            }
            if candidate == value {
                selected = true;
                break;
            }
        }
        if !selected {
            return true;
        }
    }
    false
}

// Binding variants are evidence samples, not the gated value set. Both roots and
// helper members evaluate their reviewed native predicate through the same budget.
fn source_gate_constraint(
    node: &crate::syntax::TreeNode,
    rule: &serde_json::Value,
    path: &crate::diagnostic::FieldPath,
    session: &mut SourceFieldSession<'_>,
) {
    if let Some(values) = rule["unconditional_values"].as_array() {
        for value in values {
            match source_gate_value_matches(node, value, session) {
                Some(true) | None => return,
                Some(false) => {}
            }
        }
    }
    if let Some(values) = rule["gated_values"].as_array() {
        let mut matched = false;
        for value in values {
            match source_gate_value_matches(node, value, session) {
                Some(true) => {
                    matched = true;
                    break;
                }
                None => return,
                Some(false) => {}
            }
        }
        if !matched {
            return;
        }
    }
    if !session.tick() {
        return;
    }
    let Some(gate) = FeatureGateId::ALL
        .iter()
        .find(|gate| Some(gate.as_str()) == rule["gate"].as_str())
    else {
        session.finding(FindingCode::UnadmittedField, path);
        return;
    };
    let (stages, removed) = gate_stages(*gate);
    let stage = stages.iter().find(|stage| {
        stage.first <= session.target.kubernetes.minor() && session.target.kubernetes.minor() <= stage.last
    });
    let stable = stage.is_some_and(|stage| stage.stable)
        || removed
            && stages
                .last()
                .is_some_and(|stage| stage.stable && session.target.kubernetes.minor() > stage.last);
    if session.target.feature_gates.resolve(*gate, session.target.kubernetes) != Ok(FeatureGateState::Enabled)
        || rule["selection"].as_str() == Some("stable_only") && !stable
    {
        session.finding(FindingCode::FeatureGateRequired, path);
    }
}
fn source_gate_value_matches(
    node: &crate::syntax::TreeNode,
    value: &serde_json::Value,
    session: &mut SourceFieldSession<'_>,
) -> Option<bool> {
    use crate::syntax::TreeValue;
    if !session.tick() {
        return None;
    }
    let bytes = match (&node.value, value) {
        (TreeValue::String(actual), serde_json::Value::String(expected)) => actual.len().checked_add(expected.len()),
        (TreeValue::Number(actual), _) => Some(actual.len()),
        _ => Some(0),
    };
    let result = bytes
        .ok_or_else(|| session.processing.fail(session.phase))
        .and_then(|bytes| session.processing.work(bytes, session.phase));
    if let Err(finding) = result {
        session.out.push(finding);
        return None;
    }
    Some(match (&node.value, value) {
        (TreeValue::String(actual), serde_json::Value::String(expected)) => actual == expected,
        (TreeValue::Number(actual), serde_json::Value::Number(expected)) => {
            expected
                .as_i64()
                .is_some_and(|expected| actual.parse::<i64>() == Ok(expected))
                || expected
                    .as_u64()
                    .is_some_and(|expected| actual.parse::<u64>() == Ok(expected))
        }
        (TreeValue::Bool(actual), serde_json::Value::Bool(expected)) => actual == expected,
        (TreeValue::Null, serde_json::Value::Null) => true,
        _ => false,
    })
}
fn source_shape(
    node: &crate::syntax::TreeNode,
    shape: &serde_json::Value,
    path: &crate::diagnostic::FieldPath,
    session: &mut SourceFieldSession<'_>,
    depth: usize,
) {
    let ledger = session.ledger;
    if !session.depth(depth) {
        return;
    }
    if let Some(reference) = shape["$ref"]
        .as_str()
        .and_then(|reference| reference.strip_prefix("#/definitions/"))
    {
        if let (Some(members), Some(entries)) = (
            ledger["typed_struct_inventory"][reference]["proposed_admitted_members"].as_object(),
            node.as_mapping(),
        ) {
            for (name, value) in entries {
                if !session.tick() {
                    return;
                }
                if let Some(fact) = members.get(name) {
                    source_field(
                        value,
                        fact,
                        (Some((reference, name)), &path.child(name)),
                        session,
                        depth + 1,
                    );
                }
            }
        }
    } else if let (Some(items), Some(shape)) = (node.as_sequence(), shape.get("items")) {
        for (index, item) in items.iter().enumerate() {
            if !session.tick() {
                return;
            }
            source_shape(item, shape, &path.child(index.to_string()), session, depth + 1);
        }
    } else if let (Some(entries), Some(shape)) = (
        node.as_mapping(),
        shape.get("additionalProperties").filter(|shape| shape.is_object()),
    ) {
        for (key, value) in entries {
            if !session.tick() {
                return;
            }
            source_shape(value, shape, &path.child(key), session, depth + 1);
        }
    }
}

pub(crate) fn builtin_scope(gvk: &GroupVersionKind) -> Option<ResourceScope> {
    DECLARED_APIS
        .iter()
        .find(|entry| {
            let group = entry.api_version.split_once('/').map(|(group, _)| group);
            group == gvk.group.as_deref() && entry.kind.as_str() == gvk.kind
        })
        .map(|entry| entry.scope)
}

#[cfg(test)]
mod finite_enum_tests {
    use super::*;
    use crate::{
        diagnostic::FieldPath,
        processing::{NativeOperationBudget, NativeProcessingLimits, ProcessingReport},
        syntax::{TreeNode, TreeValue},
    };
    fn findings(node: &TreeNode, limits: NativeProcessingLimits) -> Result<Vec<Finding>, Finding> {
        let target = TargetProfile::documented_defaults(KubernetesVersion::new(1, 37)?);
        let ledger = serde_json::json!({});
        // Repeated records must never manufacture duplicate rejection findings.
        let fact = serde_json::json!({"native_constraints":[
            {"rule":"enum","values":["ReadWriteOnce","ReadOnlyMany","ReadWriteMany"],"other_values":"preserve_only"},
            {"rule":"enum","values":["ReadWriteOnce","ReadOnlyMany","ReadWriteMany"],"other_values":"preserve_only"}
        ]});
        let processing = NativeOperationBudget::new(limits);
        let mut out = ProcessingReport::new(processing.clone(), Phase::Validation);
        source_enum(
            node,
            &fact,
            None,
            &FieldPath::parse("/modes")?,
            &mut SourceFieldSession {
                ledger: &ledger,
                target: &target,
                processing: &processing,
                phase: Phase::Validation,
                out: &mut out,
                profile: "k8s-1.37-0".into(),
            },
        );
        Ok(out.into_vec())
    }
    #[test]
    fn enums_keep_scalar_array_and_malformed_shape_evidence_distinct() -> Result<(), Finding> {
        let scalar = findings(&TreeNode::string("private"), NativeProcessingLimits::default())?;
        assert_eq!(scalar.len(), 1);
        assert_eq!(scalar[0].code, FindingCode::UnadmittedField);
        assert_eq!(scalar[0].path, Some(FieldPath::parse("/modes")?));
        let array = findings(
            &TreeNode::new(TreeValue::Sequence(vec![
                TreeNode::string("ReadWriteMany"),
                TreeNode::string("private"),
                TreeNode::string("ReadWriteOncePod"),
            ])),
            NativeProcessingLimits::default(),
        )?;
        assert_eq!(array.len(), 2);
        assert_eq!(array[0].path, Some(FieldPath::parse("/modes/1")?));
        assert_eq!(array[1].path, Some(FieldPath::parse("/modes/2")?));
        assert!(findings(&TreeNode::new(TreeValue::Null), NativeProcessingLimits::default())?.is_empty());
        Ok(())
    }
    #[test]
    fn enum_work_and_report_exhaustion_is_sticky_and_never_admits() -> Result<(), Finding> {
        let node = TreeNode::new(TreeValue::Sequence(vec![
            TreeNode::string("private"),
            TreeNode::string("private"),
        ]));
        for units in [0, 1] {
            let report = findings(
                &node,
                NativeProcessingLimits {
                    max_processing_units: units,
                    ..NativeProcessingLimits::default()
                },
            )?;
            assert_eq!(report.len(), 1);
            assert_eq!(report[0].code, FindingCode::LimitExceeded);
            assert!(report[0].path.is_none());
        }
        for entries in [0, 1] {
            let report = findings(
                &node,
                NativeProcessingLimits {
                    max_report_entries: entries,
                    ..NativeProcessingLimits::default()
                },
            )?;
            assert_eq!(report.len(), entries + 1);
            assert_eq!(report.last().map(|f| f.code), Some(FindingCode::LimitExceeded));
        }
        Ok(())
    }
}
