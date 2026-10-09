//! Typed workload roots and semantics; shared passive helpers retain compatibility reexports.
pub use super::common::{
    Affinity, AzureFileVolumeSource, CSIVolumeSource, Capabilities, CephFSVolumeSource, CinderVolumeSource,
    ClaimTemplateCondition, ClaimTemplateStatus, ConfigMapEnvSource, ConfigMapKeySelector, ConfigMapProjection,
    ConfigMapVolumeSource, Container, ContainerPort, ContainerResizePolicy, CronJobV1Beta1Spec, CronJobV1Spec,
    DaemonSetSpec, DaemonSetUpdateStrategy, DeploymentSpec, DeploymentStrategy, DownwardAPIProjection,
    DownwardAPIVolumeFile, DownwardAPIVolumeSource, EmptyDirVolumeSource, EnvFromSource, EnvVar, EnvVarSource,
    EphemeralVolumeSource, ExecAction, FlexVolumeSource, GitRepoVolumeSource, GlusterfsVolumeSource, HTTPGetAction,
    HTTPHeader, Handler, HostAlias, ISCSIVolumeSource, JobSpec, JobTemplateV1, JobTemplateV1Beta1, KeyToPath,
    Lifecycle, LifecycleHandler, NativeTime, NodeAffinity, ObjectFieldSelector, PersistentVolumeClaimTemplate,
    PersistentVolumeClaimVolumeSource, PodAffinity, PodAffinityTerm, PodAntiAffinity, PodDNSConfig, PodDNSConfigOption,
    PodFailurePolicy, PodFailurePolicyOnExitCodesRequirement, PodFailurePolicyOnPodConditionsPattern,
    PodFailurePolicyRule, PodReadinessGate, PodSecurityContext, PodSpec, PodTemplateSpec, PreferredSchedulingTerm,
    Probe, ProjectedVolumeSource, RBDVolumeSource, ReplicaSetSpec, ReplicationControllerSpec, ResourceFieldSelector,
    RollingUpdateDaemonSet, RollingUpdateDeployment, RollingUpdateStatefulSetStrategy, ScaleIOVolumeSource,
    SeccompProfile, SecretEnvSource, SecretKeySelector, SecretProjection, SecretVolumeSource, SecurityContext,
    ServiceAccountTokenProjection, StatefulSetClaimTemplate, StatefulSetOrdinals,
    StatefulSetPersistentVolumeClaimRetentionPolicy, StatefulSetSpec, StatefulSetUpdateStrategy, StorageOSVolumeSource,
    SuccessPolicy, SuccessPolicyRule, Sysctl, TCPSocketAction, TopologySpreadConstraint, Volume, VolumeDevice,
    VolumeMount, VolumeProjection, WeightedPodAffinityTerm, WindowsSecurityContextOptions,
};
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    model::Metadata,
    registry::{EncodeContext, codec::FieldCodec},
    syntax::TreeNode,
    value::{LabelSelector, Presence},
};
use std::collections::BTreeMap;

pub(crate) mod roots;
pub use roots::*;
mod capabilities;
mod facts;
mod gates;
mod rules;
mod schedule;
mod validation;
