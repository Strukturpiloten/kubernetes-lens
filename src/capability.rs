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

pub(crate) fn source_field_findings(
    tree: &crate::syntax::TreeNode,
    gvk: &GroupVersionKind,
    target: &TargetProfile,
) -> Vec<Finding> {
    use std::sync::OnceLock;
    static LEDGER: OnceLock<Option<serde_json::Value>> = OnceLock::new();
    let Some(ledger) = LEDGER
        .get_or_init(|| serde_json::from_slice(capability_ledger_bytes()).ok())
        .as_ref()
    else {
        return vec![invalid_profile()];
    };
    let mut out = Vec::new();
    let Some(resource) = ledger["resources"]
        .as_array()
        .and_then(|rows| rows.iter().find(|row| row["kind"].as_str() == Some(gvk.kind.as_str())))
    else {
        return out;
    };
    let api = gvk.api_version();
    let Some(profile) = resource["proposed_admitted_api_profiles"].as_array().and_then(|rows| {
        rows.iter()
            .find(|row| row["api_version"].as_str() == Some(api.as_str()))
    }) else {
        return out;
    };
    if let Some(fields) = profile["typed_field_pointers"].as_array() {
        for field in fields {
            let Some(pointer) = field["pointer"].as_str() else {
                continue;
            };
            let Ok(path) = crate::diagnostic::FieldPath::parse(pointer) else {
                continue;
            };
            if let Some(node) = tree.get_path(&path) {
                source_field(node, field, (None, &path), ledger, target, &mut out, 0);
            }
        }
    }
    out.extend(contextual_findings(tree, gvk, target, ledger));
    out
}
fn contextual_findings(
    tree: &crate::syntax::TreeNode,
    gvk: &GroupVersionKind,
    target: &TargetProfile,
    ledger: &serde_json::Value,
) -> Vec<Finding> {
    let mut out = Vec::new();
    let Some(contexts) = ledger["contextual_typed_members"].as_array() else {
        return out;
    };
    let Some(prefix) = ledger["template_context_bindings"]["PodSpec"][&gvk.kind].as_str() else {
        return out;
    };
    for context in contexts {
        let Some(suffix) = context["pointer_pattern"]
            .as_str()
            .and_then(|p| p.strip_prefix("/spec"))
        else {
            continue;
        };
        let pattern = format!("{prefix}{suffix}");
        if !crate::generation::field_nodes(tree, &pattern).is_empty() {
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
                        .is_some_and(|(first, last)| (first..=last).contains(&target.kubernetes.minor()))
                })
            });
            let code = if !available {
                Some(FindingCode::UnavailableField)
            } else if FeatureGateId::ALL
                .iter()
                .find(|id| Some(id.as_str()) == context["gate"].as_str())
                .is_some_and(|id| target.feature_gates.resolve(*id, target.kubernetes) != Ok(FeatureGateState::Enabled))
            {
                Some(FindingCode::FeatureGateRequired)
            } else {
                None
            };
            if let Some(code) = code {
                let mut finding = Finding::error(code, Phase::Validation);
                finding.path = crate::diagnostic::FieldPath::parse(&pattern).ok();
                out.push(finding);
            }
        }
        let regular = pattern.replace("/initContainers/", "/containers/");
        if regular != pattern && !crate::generation::field_nodes(tree, &regular).is_empty() {
            let mut finding = Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation);
            finding.path = crate::diagnostic::FieldPath::parse(&regular).ok();
            out.push(finding);
        }
    }
    out
}
fn source_field(
    node: &crate::syntax::TreeNode,
    fact: &serde_json::Value,
    location: (Option<(&str, &str)>, &crate::diagnostic::FieldPath),
    ledger: &serde_json::Value,
    target: &TargetProfile,
    out: &mut Vec<Finding>,
    depth: usize,
) {
    let (owner, path) = location;
    if depth > 128 {
        out.push(Finding::error(FindingCode::LimitExceeded, Phase::Validation).at_path(path.clone()));
        return;
    }
    let profile = format!("k8s-1.{}-0", target.kubernetes.minor());
    let forms = fact["schema_forms"].as_array();
    let selected = forms.and_then(|forms| {
        forms.iter().find(|form| {
            form["source_schema_ids"]
                .as_array()
                .is_some_and(|ids| ids.iter().any(|id| id.as_str() == Some(profile.as_str())))
        })
    });
    if selected.is_none() {
        out.push(Finding::error(FindingCode::UnavailableField, Phase::Validation).at_path(path.clone()));
    }
    if let Some((definition, member)) = owner {
        if let Some(bindings) = ledger["feature_gate_bindings"].as_array() {
            for binding in bindings.iter().filter(|binding| {
                binding["definition"].as_str() == Some(definition) && binding["member"].as_str() == Some(member)
            }) {
                if let Some(gate) = FeatureGateId::ALL
                    .iter()
                    .find(|gate| Some(gate.as_str()) == binding["gate"].as_str())
                {
                    let (stages, removed) = gate_stages(*gate);
                    let stage = stages.iter().find(|stage| {
                        stage.first <= target.kubernetes.minor() && target.kubernetes.minor() <= stage.last
                    });
                    let stable = stage.is_some_and(|stage| stage.stable)
                        || removed
                            && stages
                                .last()
                                .is_some_and(|s| s.stable && target.kubernetes.minor() > s.last);
                    if target.feature_gates.resolve(*gate, target.kubernetes) != Ok(FeatureGateState::Enabled)
                        || binding["selection"].as_str() == Some("stable_only") && !stable
                    {
                        out.push(
                            Finding::error(FindingCode::FeatureGateRequired, Phase::Validation).at_path(path.clone()),
                        );
                    }
                }
            }
        }
    }
    let form = selected.or_else(|| forms.and_then(|forms| forms.first()));
    if let Some(shape) = form.and_then(|form| form.get("schema_shape")) {
        source_shape(node, shape, path, ledger, target, out, depth + 1);
    }
    // Root pointers are not prefix admission; only finite helper member facts are traversed.
}
fn source_shape(
    node: &crate::syntax::TreeNode,
    shape: &serde_json::Value,
    path: &crate::diagnostic::FieldPath,
    ledger: &serde_json::Value,
    target: &TargetProfile,
    out: &mut Vec<Finding>,
    depth: usize,
) {
    if depth > 128 {
        out.push(Finding::error(FindingCode::LimitExceeded, Phase::Validation).at_path(path.clone()));
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
                if let Some(fact) = members.get(name) {
                    source_field(
                        value,
                        fact,
                        (Some((reference, name)), &path.child(name)),
                        ledger,
                        target,
                        out,
                        depth + 1,
                    );
                }
            }
        }
    } else if let (Some(items), Some(shape)) = (node.as_sequence(), shape.get("items")) {
        for (index, item) in items.iter().enumerate() {
            source_shape(
                item,
                shape,
                &path.child(index.to_string()),
                ledger,
                target,
                out,
                depth + 1,
            );
        }
    } else if let (Some(entries), Some(shape)) = (
        node.as_mapping(),
        shape.get("additionalProperties").filter(|shape| shape.is_object()),
    ) {
        for (key, value) in entries {
            source_shape(value, shape, &path.child(key), ledger, target, out, depth + 1);
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
