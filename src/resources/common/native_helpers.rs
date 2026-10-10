//! Shared passive native shapes with original symmetric codecs; no native registrations.
use super::NativeTime;
use super::{
    AWSElasticBlockStoreVolumeSource, AzureDiskVolumeSource, FCVolumeSource, FlockerVolumeSource,
    GCEPersistentDiskVolumeSource, HostPathVolumeSource, LocalObjectReference, NFSVolumeSource, NodeSelector,
    NodeSelectorTerm, PersistentVolumeClaimSpec, PhotonPersistentDiskVolumeSource, QuobyteVolumeSource,
    ResourceRequirements, SELinuxOptions, Toleration, VsphereVirtualDiskVolumeSource,
};
use crate::{
    model::Metadata,
    value::{AccessModes, IntOrString, LabelSelector, Protected, Quantity},
};
use std::collections::BTreeMap;

super::native_object! {
    /// Selected native `DaemonSetUpdateStrategy` members; unadmitted descendants remain private.
    pub struct DaemonSetUpdateStrategy {
    "rollingUpdate" => rolling_update: RollingUpdateDaemonSet,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `DeploymentStrategy` members; unadmitted descendants remain private.
    pub struct DeploymentStrategy {
    "rollingUpdate" => rolling_update: RollingUpdateDeployment,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `RollingUpdateDaemonSet` members; unadmitted descendants remain private.
    pub struct RollingUpdateDaemonSet {
    "maxSurge" => max_surge: IntOrString,
    "maxUnavailable" => max_unavailable: IntOrString,
    }
}

super::native_object! {
    /// Selected native `RollingUpdateDeployment` members; unadmitted descendants remain private.
    pub struct RollingUpdateDeployment {
    "maxSurge" => max_surge: IntOrString,
    "maxUnavailable" => max_unavailable: IntOrString,
    }
}

super::native_object! {
    /// Selected native `RollingUpdateStatefulSetStrategy` members; unadmitted descendants remain private.
    pub struct RollingUpdateStatefulSetStrategy {
    "partition" => partition: i32,
    }
}

super::native_object! {
    /// Selected native `StatefulSetOrdinals` members; unadmitted descendants remain private.
    pub struct StatefulSetOrdinals {
    "start" => start: i32,
    }
}

super::native_object! {
    /// Selected native `StatefulSetPersistentVolumeClaimRetentionPolicy` members; unadmitted descendants remain private.
    pub struct StatefulSetPersistentVolumeClaimRetentionPolicy {
    "whenDeleted" => when_deleted: String,
    "whenScaled" => when_scaled: String,
    }
}

super::native_object! {
    /// Selected native `StatefulSetUpdateStrategy` members; unadmitted descendants remain private.
    pub struct StatefulSetUpdateStrategy {
    "rollingUpdate" => rolling_update: RollingUpdateStatefulSetStrategy,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `JobSpec` members; unadmitted descendants remain private.
    pub struct JobSpec {
    "activeDeadlineSeconds" => active_deadline_seconds: i64,
    "backoffLimit" => backoff_limit: i32,
    "backoffLimitPerIndex" => backoff_limit_per_index: i32,
    "completionMode" => completion_mode: String,
    "completions" => completions: i32,
    "manualSelector" => manual_selector: bool,
    "maxFailedIndexes" => max_failed_indexes: i32,
    "parallelism" => parallelism: i32,
    "podFailurePolicy" => pod_failure_policy: PodFailurePolicy,
    "selector" => selector: LabelSelector,
    "successPolicy" => success_policy: SuccessPolicy,
    "suspend" => suspend: bool,
    "template" => template: PodTemplateSpec,
    "ttlSecondsAfterFinished" => ttl_seconds_after_finished: i32,
    }
}

super::native_object! {
    /// Selected native `JobTemplateV1` members; unadmitted descendants remain private.
    pub struct JobTemplateV1 {
    "metadata" => metadata: Metadata,
    "spec" => spec: JobSpec,
    }
}

super::native_object! {
    /// Selected native `PodFailurePolicy` members; unadmitted descendants remain private.
    pub struct PodFailurePolicy {
    "rules" => rules: Vec<PodFailurePolicyRule>,
    }
}

super::native_object! {
    /// Selected native `PodFailurePolicyOnExitCodesRequirement` members; unadmitted descendants remain private.
    pub struct PodFailurePolicyOnExitCodesRequirement {
    "containerName" => container_name: String,
    "operator" => operator: String,
    "values" => values: Vec<i32>,
    }
}

super::native_object! {
    /// Selected native `PodFailurePolicyOnPodConditionsPattern` members; unadmitted descendants remain private.
    pub struct PodFailurePolicyOnPodConditionsPattern {
    "status" => status: String,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `PodFailurePolicyRule` members; unadmitted descendants remain private.
    pub struct PodFailurePolicyRule {
    "action" => action: String,
    "onExitCodes" => on_exit_codes: PodFailurePolicyOnExitCodesRequirement,
    "onPodConditions" => on_pod_conditions: Vec<PodFailurePolicyOnPodConditionsPattern>,
    }
}

super::native_object! {
    /// Selected native `SuccessPolicy` members; unadmitted descendants remain private.
    pub struct SuccessPolicy {
    "rules" => rules: Vec<SuccessPolicyRule>,
    }
}

super::native_object! {
    /// Selected native `SuccessPolicyRule` members; unadmitted descendants remain private.
    pub struct SuccessPolicyRule {
    "succeededCount" => succeeded_count: i32,
    "succeededIndexes" => succeeded_indexes: String,
    }
}

super::native_object! {
    /// Selected native `JobTemplateV1Beta1` members; unadmitted descendants remain private.
    pub struct JobTemplateV1Beta1 {
    "metadata" => metadata: Metadata,
    "spec" => spec: JobSpec,
    }
}

super::native_object! {
    /// Selected native `Affinity` members; unadmitted descendants remain private.
    pub struct Affinity {
    "nodeAffinity" => node_affinity: NodeAffinity,
    "podAffinity" => pod_affinity: PodAffinity,
    "podAntiAffinity" => pod_anti_affinity: PodAntiAffinity,
    }
}

super::native_object! {
    /// Selected native `AzureFileVolumeSource` members; unadmitted descendants remain private.
    pub struct AzureFileVolumeSource {
    "readOnly" => read_only: bool,
    "secretName" => secret_name: String,
    "shareName" => share_name: String,
    }
}

super::native_object! {
    /// Selected native `CSIVolumeSource` members; unadmitted descendants remain private.
    pub struct CSIVolumeSource {
    "driver" => driver: String,
    "fsType" => fs_type: String,
    "nodePublishSecretRef" => node_publish_secret_ref: LocalObjectReference,
    "readOnly" => read_only: bool,
    "volumeAttributes" => volume_attributes: BTreeMap<String, String>,
    }
}

super::native_object! {
    /// Selected native `Capabilities` members; unadmitted descendants remain private.
    pub struct Capabilities {
    "add" => add: Vec<String>,
    "drop" => drop: Vec<String>,
    }
}

super::native_object! {
    /// Selected native `CephFSVolumeSource` members; unadmitted descendants remain private.
    pub struct CephFSVolumeSource {
    "monitors" => monitors: Vec<String>,
    "path" => path: String,
    "readOnly" => read_only: bool,
    "secretFile" => secret_file: String,
    "secretRef" => secret_ref: LocalObjectReference,
    "user" => user: String,
    }
}

super::native_object! {
    /// Selected native `CinderVolumeSource` members; unadmitted descendants remain private.
    pub struct CinderVolumeSource {
    "fsType" => fs_type: String,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    "volumeID" => volume_id: String,
    }
}

super::native_object! {
    /// Selected native `ConfigMapEnvSource` members; unadmitted descendants remain private.
    pub struct ConfigMapEnvSource {
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `ConfigMapKeySelector` members; unadmitted descendants remain private.
    pub struct ConfigMapKeySelector {
    "key" => key: String,
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `ConfigMapProjection` members; unadmitted descendants remain private.
    pub struct ConfigMapProjection {
    "items" => items: Vec<KeyToPath>,
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `ConfigMapVolumeSource` members; unadmitted descendants remain private.
    pub struct ConfigMapVolumeSource {
    "defaultMode" => default_mode: i32,
    "items" => items: Vec<KeyToPath>,
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `Container` members; unadmitted descendants remain private.
    pub struct Container {
    "args" => args: Protected<Vec<String>>,
    "command" => command: Protected<Vec<String>>,
    "env" => env: Vec<EnvVar>,
    "envFrom" => env_from: Vec<EnvFromSource>,
    "image" => image: String,
    "imagePullPolicy" => image_pull_policy: String,
    "lifecycle" => lifecycle: Lifecycle,
    "livenessProbe" => liveness_probe: Probe,
    "name" => name: String,
    "ports" => ports: Vec<ContainerPort>,
    "readinessProbe" => readiness_probe: Probe,
    "resizePolicy" => resize_policy: Vec<ContainerResizePolicy>,
    "resources" => resources: ResourceRequirements,
    "securityContext" => security_context: SecurityContext,
    "startupProbe" => startup_probe: Probe,
    "stdin" => stdin: bool,
    "stdinOnce" => stdin_once: bool,
    "terminationMessagePath" => termination_message_path: String,
    "terminationMessagePolicy" => termination_message_policy: String,
    "tty" => tty: bool,
    "volumeDevices" => volume_devices: Vec<VolumeDevice>,
    "volumeMounts" => volume_mounts: Vec<VolumeMount>,
    "workingDir" => working_dir: String,
    "restartPolicy" => restart_policy: String,
    }
}

super::native_object! {
    /// Selected native `ContainerPort` members; unadmitted descendants remain private.
    pub struct ContainerPort {
    "containerPort" => container_port: i32,
    "hostIP" => host_ip: String,
    "hostPort" => host_port: i32,
    "name" => name: String,
    "protocol" => protocol: String,
    }
}

super::native_object! {
    /// Selected native `ContainerResizePolicy` members; unadmitted descendants remain private.
    pub struct ContainerResizePolicy {
    "resourceName" => resource_name: String,
    "restartPolicy" => restart_policy: String,
    }
}

super::native_object! {
    /// Selected native `DownwardAPIProjection` members; unadmitted descendants remain private.
    pub struct DownwardAPIProjection {
    "items" => items: Vec<DownwardAPIVolumeFile>,
    }
}

super::native_object! {
    /// Selected native `DownwardAPIVolumeFile` members; unadmitted descendants remain private.
    pub struct DownwardAPIVolumeFile {
    "fieldRef" => field_ref: ObjectFieldSelector,
    "mode" => mode: i32,
    "path" => path: String,
    "resourceFieldRef" => resource_field_ref: ResourceFieldSelector,
    }
}

super::native_object! {
    /// Selected native `DownwardAPIVolumeSource` members; unadmitted descendants remain private.
    pub struct DownwardAPIVolumeSource {
    "defaultMode" => default_mode: i32,
    "items" => items: Vec<DownwardAPIVolumeFile>,
    }
}

super::native_object! {
    /// Selected native `EmptyDirVolumeSource` members; unadmitted descendants remain private.
    pub struct EmptyDirVolumeSource {
    "medium" => medium: String,
    "sizeLimit" => size_limit: Quantity,
    }
}

super::native_object! {
    /// Selected native `EnvFromSource` members; unadmitted descendants remain private.
    pub struct EnvFromSource {
    "configMapRef" => config_map_ref: ConfigMapEnvSource,
    "prefix" => prefix: String,
    "secretRef" => secret_ref: SecretEnvSource,
    }
}

super::native_object! {
    /// Selected native `EnvVar` members; unadmitted descendants remain private.
    pub struct EnvVar {
    "name" => name: String,
    "value" => value: Protected<String>,
    "valueFrom" => value_from: EnvVarSource,
    }
}

super::native_object! {
    /// Selected native `EnvVarSource` members; unadmitted descendants remain private.
    pub struct EnvVarSource {
    "configMapKeyRef" => config_map_key_ref: ConfigMapKeySelector,
    "fieldRef" => field_ref: ObjectFieldSelector,
    "resourceFieldRef" => resource_field_ref: ResourceFieldSelector,
    "secretKeyRef" => secret_key_ref: SecretKeySelector,
    }
}

super::native_object! {
    /// Selected native `EphemeralVolumeSource` members; unadmitted descendants remain private.
    pub struct EphemeralVolumeSource {
    "readOnly" => read_only: bool,
    "volumeClaimTemplate" => volume_claim_template: PersistentVolumeClaimTemplate,
    }
}

super::native_object! {
    /// Selected native `ExecAction` members; unadmitted descendants remain private.
    pub struct ExecAction {
    "command" => command: Protected<Vec<String>>,
    }
}

super::native_object! {
    /// Selected native `FlexVolumeSource` members; unadmitted descendants remain private.
    pub struct FlexVolumeSource {
    "driver" => driver: String,
    "fsType" => fs_type: String,
    "options" => options: BTreeMap<String, String>,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    }
}

super::native_object! {
    /// Selected native `GitRepoVolumeSource` members; unadmitted descendants remain private.
    pub struct GitRepoVolumeSource {
    "directory" => directory: String,
    "repository" => repository: String,
    "revision" => revision: String,
    }
}

super::native_object! {
    /// Selected native `GlusterfsVolumeSource` members; unadmitted descendants remain private.
    pub struct GlusterfsVolumeSource {
    "endpoints" => endpoints: String,
    "path" => path: String,
    "readOnly" => read_only: bool,
    }
}

super::native_object! {
    /// Selected native `HTTPGetAction` members; unadmitted descendants remain private.
    pub struct HTTPGetAction {
    "host" => host: String,
    "httpHeaders" => http_headers: Vec<HTTPHeader>,
    "path" => path: String,
    "port" => port: IntOrString,
    "scheme" => scheme: String,
    }
}

super::native_object! {
    /// Selected native `HTTPHeader` members; unadmitted descendants remain private.
    pub struct HTTPHeader {
    "name" => name: String,
    "value" => value: Protected<String>,
    }
}

super::native_object! {
    /// Selected native `Handler` members; unadmitted descendants remain private.
    pub struct Handler {
    "exec" => exec: ExecAction,
    "httpGet" => http_get: HTTPGetAction,
    "tcpSocket" => tcp_socket: TCPSocketAction,
    }
}

super::native_object! {
    /// Selected native `HostAlias` members; unadmitted descendants remain private.
    pub struct HostAlias {
    "hostnames" => hostnames: Vec<String>,
    "ip" => ip: String,
    }
}

super::native_object! {
    /// Selected native `ISCSIVolumeSource` members; unadmitted descendants remain private.
    pub struct ISCSIVolumeSource {
    "chapAuthDiscovery" => chap_auth_discovery: bool,
    "chapAuthSession" => chap_auth_session: bool,
    "fsType" => fs_type: String,
    "initiatorName" => initiator_name: String,
    "iqn" => iqn: String,
    "iscsiInterface" => iscsi_interface: String,
    "lun" => lun: i32,
    "portals" => portals: Vec<String>,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    "targetPortal" => target_portal: String,
    }
}

super::native_object! {
    /// Selected native `KeyToPath` members; unadmitted descendants remain private.
    pub struct KeyToPath {
    "key" => key: String,
    "mode" => mode: i32,
    "path" => path: String,
    }
}

super::native_object! {
    /// Selected native `Lifecycle` members; unadmitted descendants remain private.
    pub struct Lifecycle {
    "postStart" => post_start: LifecycleHandler,
    "preStop" => pre_stop: LifecycleHandler,
    }
}

super::native_object! {
    /// Selected native `LifecycleHandler` members; unadmitted descendants remain private.
    pub struct LifecycleHandler {
    "exec" => exec: ExecAction,
    "httpGet" => http_get: HTTPGetAction,
    "tcpSocket" => tcp_socket: TCPSocketAction,
    }
}

super::native_object! {
    /// Selected native `NodeAffinity` members; unadmitted descendants remain private.
    pub struct NodeAffinity {
    "preferredDuringSchedulingIgnoredDuringExecution" => preferred_during_scheduling_ignored_during_execution: Vec<PreferredSchedulingTerm>,
    "requiredDuringSchedulingIgnoredDuringExecution" => required_during_scheduling_ignored_during_execution: NodeSelector,
    }
}

super::native_object! {
    /// Selected native `ObjectFieldSelector` members; unadmitted descendants remain private.
    pub struct ObjectFieldSelector {
    "apiVersion" => api_version: String,
    "fieldPath" => field_path: String,
    }
}

super::native_object! {
    /// Selected native `StatefulSetClaimTemplate` members; unadmitted descendants remain private.
    pub struct StatefulSetClaimTemplate {
    "apiVersion" => api_version: String,
    "kind" => kind: String,
    "metadata" => metadata: Metadata,
    "spec" => spec: PersistentVolumeClaimSpec,
    "status" => status: ClaimTemplateStatus,
    }
}

super::native_object! {
    /// Selected native `ClaimTemplateCondition` members; unadmitted descendants remain private.
    pub struct ClaimTemplateCondition {
    "lastProbeTime" => last_probe_time: NativeTime,
    "lastTransitionTime" => last_transition_time: NativeTime,
    "message" => message: String,
    "reason" => reason: String,
    "status" => status: String,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `ClaimTemplateStatus` members; unadmitted descendants remain private.
    pub struct ClaimTemplateStatus {
    "accessModes" => access_modes: AccessModes,
    "capacity" => capacity: BTreeMap<String, Quantity>,
    "conditions" => conditions: Vec<ClaimTemplateCondition>,
    "phase" => phase: String,
    }
}

super::native_object! {
    /// Selected native `PersistentVolumeClaimTemplate` members; unadmitted descendants remain private.
    pub struct PersistentVolumeClaimTemplate {
    "metadata" => metadata: Metadata,
    "spec" => spec: PersistentVolumeClaimSpec,
    }
}

super::native_object! {
    /// Selected native `PersistentVolumeClaimVolumeSource` members; unadmitted descendants remain private.
    pub struct PersistentVolumeClaimVolumeSource {
    "claimName" => claim_name: String,
    "readOnly" => read_only: bool,
    }
}

super::native_object! {
    /// Selected native `PodAffinity` members; unadmitted descendants remain private.
    pub struct PodAffinity {
    "preferredDuringSchedulingIgnoredDuringExecution" => preferred_during_scheduling_ignored_during_execution: Vec<WeightedPodAffinityTerm>,
    "requiredDuringSchedulingIgnoredDuringExecution" => required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
    }
}

super::native_object! {
    /// Selected native `PodAffinityTerm` members; unadmitted descendants remain private.
    pub struct PodAffinityTerm {
    "labelSelector" => label_selector: LabelSelector,
    "namespaces" => namespaces: Vec<String>,
    "topologyKey" => topology_key: String,
    }
}

super::native_object! {
    /// Selected native `PodAntiAffinity` members; unadmitted descendants remain private.
    pub struct PodAntiAffinity {
    "preferredDuringSchedulingIgnoredDuringExecution" => preferred_during_scheduling_ignored_during_execution: Vec<WeightedPodAffinityTerm>,
    "requiredDuringSchedulingIgnoredDuringExecution" => required_during_scheduling_ignored_during_execution: Vec<PodAffinityTerm>,
    }
}

super::native_object! {
    /// Selected native `PodDNSConfig` members; unadmitted descendants remain private.
    pub struct PodDNSConfig {
    "nameservers" => nameservers: Vec<String>,
    "options" => options: Vec<PodDNSConfigOption>,
    "searches" => searches: Vec<String>,
    }
}

super::native_object! {
    /// Selected native `PodDNSConfigOption` members; unadmitted descendants remain private.
    pub struct PodDNSConfigOption {
    "name" => name: String,
    "value" => value: String,
    }
}

super::native_object! {
    /// Selected native `PodReadinessGate` members; unadmitted descendants remain private.
    pub struct PodReadinessGate {
    "conditionType" => condition_type: String,
    }
}

super::native_object! {
    /// Selected native `PodSecurityContext` members; unadmitted descendants remain private.
    pub struct PodSecurityContext {
    "fsGroup" => fs_group: i64,
    "fsGroupChangePolicy" => fs_group_change_policy: String,
    "runAsGroup" => run_as_group: i64,
    "runAsNonRoot" => run_as_non_root: bool,
    "runAsUser" => run_as_user: i64,
    "seLinuxOptions" => se_linux_options: SELinuxOptions,
    "seccompProfile" => seccomp_profile: SeccompProfile,
    "supplementalGroups" => supplemental_groups: Vec<i64>,
    "sysctls" => sysctls: Vec<Sysctl>,
    "windowsOptions" => windows_options: WindowsSecurityContextOptions,
    }
}

super::native_object! {
    /// Selected native `PodSpec` members; unadmitted descendants remain private.
    pub struct PodSpec {
    "activeDeadlineSeconds" => active_deadline_seconds: i64,
    "affinity" => affinity: Affinity,
    "automountServiceAccountToken" => automount_service_account_token: bool,
    "containers" => containers: Vec<Container>,
    "dnsConfig" => dns_config: PodDNSConfig,
    "dnsPolicy" => dns_policy: String,
    "enableServiceLinks" => enable_service_links: bool,
    "hostAliases" => host_aliases: Vec<HostAlias>,
    "hostIPC" => host_ipc: bool,
    "hostNetwork" => host_network: bool,
    "hostPID" => host_pid: bool,
    "hostname" => hostname: String,
    "imagePullSecrets" => image_pull_secrets: Vec<LocalObjectReference>,
    "initContainers" => init_containers: Vec<Container>,
    "nodeName" => node_name: String,
    "nodeSelector" => node_selector: BTreeMap<String, String>,
    "overhead" => overhead: BTreeMap<String, Quantity>,
    "preemptionPolicy" => preemption_policy: String,
    "priority" => priority: i32,
    "priorityClassName" => priority_class_name: String,
    "readinessGates" => readiness_gates: Vec<PodReadinessGate>,
    "restartPolicy" => restart_policy: String,
    "runtimeClassName" => runtime_class_name: String,
    "schedulerName" => scheduler_name: String,
    "securityContext" => security_context: PodSecurityContext,
    "serviceAccountName" => service_account_name: String,
    "setHostnameAsFQDN" => set_hostname_as_fqdn: bool,
    "shareProcessNamespace" => share_process_namespace: bool,
    "subdomain" => subdomain: String,
    "terminationGracePeriodSeconds" => termination_grace_period_seconds: i64,
    "tolerations" => tolerations: Vec<Toleration>,
    "topologySpreadConstraints" => topology_spread_constraints: Vec<TopologySpreadConstraint>,
    "volumes" => volumes: Vec<Volume>,
    }
}

super::native_object! {
    /// Selected native `PodTemplateSpec` members; unadmitted descendants remain private.
    pub struct PodTemplateSpec {
    "metadata" => metadata: Metadata,
    "spec" => spec: PodSpec,
    }
}

super::native_object! {
    /// Selected native `PreferredSchedulingTerm` members; unadmitted descendants remain private.
    pub struct PreferredSchedulingTerm {
    "preference" => preference: NodeSelectorTerm,
    "weight" => weight: i32,
    }
}

super::native_object! {
    /// Selected native `Probe` members; unadmitted descendants remain private.
    pub struct Probe {
    "exec" => exec: ExecAction,
    "failureThreshold" => failure_threshold: i32,
    "httpGet" => http_get: HTTPGetAction,
    "initialDelaySeconds" => initial_delay_seconds: i32,
    "periodSeconds" => period_seconds: i32,
    "successThreshold" => success_threshold: i32,
    "tcpSocket" => tcp_socket: TCPSocketAction,
    "timeoutSeconds" => timeout_seconds: i32,
    }
}

super::native_object! {
    /// Selected native `ProjectedVolumeSource` members; unadmitted descendants remain private.
    pub struct ProjectedVolumeSource {
    "defaultMode" => default_mode: i32,
    "sources" => sources: Vec<VolumeProjection>,
    }
}

super::native_object! {
    /// Selected native `RBDVolumeSource` members; unadmitted descendants remain private.
    pub struct RBDVolumeSource {
    "fsType" => fs_type: String,
    "image" => image: String,
    "keyring" => keyring: String,
    "monitors" => monitors: Vec<String>,
    "pool" => pool: String,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    "user" => user: String,
    }
}

super::native_object! {
    /// Selected native `ResourceFieldSelector` members; unadmitted descendants remain private.
    pub struct ResourceFieldSelector {
    "containerName" => container_name: String,
    "divisor" => divisor: Quantity,
    "resource" => resource: String,
    }
}

super::native_object! {
    /// Selected native `ScaleIOVolumeSource` members; unadmitted descendants remain private.
    pub struct ScaleIOVolumeSource {
    "fsType" => fs_type: String,
    "gateway" => gateway: String,
    "protectionDomain" => protection_domain: String,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    "sslEnabled" => ssl_enabled: bool,
    "storageMode" => storage_mode: String,
    "storagePool" => storage_pool: String,
    "system" => system: String,
    "volumeName" => volume_name: String,
    }
}

super::native_object! {
    /// Selected native `SeccompProfile` members; unadmitted descendants remain private.
    pub struct SeccompProfile {
    "localhostProfile" => localhost_profile: String,
    "type" => r#type: String,
    }
}

super::native_object! {
    /// Selected native `SecretEnvSource` members; unadmitted descendants remain private.
    pub struct SecretEnvSource {
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `SecretKeySelector` members; unadmitted descendants remain private.
    pub struct SecretKeySelector {
    "key" => key: String,
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `SecretProjection` members; unadmitted descendants remain private.
    pub struct SecretProjection {
    "items" => items: Vec<KeyToPath>,
    "name" => name: String,
    "optional" => optional: bool,
    }
}

super::native_object! {
    /// Selected native `SecretVolumeSource` members; unadmitted descendants remain private.
    pub struct SecretVolumeSource {
    "defaultMode" => default_mode: i32,
    "items" => items: Vec<KeyToPath>,
    "optional" => optional: bool,
    "secretName" => secret_name: String,
    }
}

super::native_object! {
    /// Selected native `SecurityContext` members; unadmitted descendants remain private.
    pub struct SecurityContext {
    "allowPrivilegeEscalation" => allow_privilege_escalation: bool,
    "capabilities" => capabilities: Capabilities,
    "privileged" => privileged: bool,
    "procMount" => proc_mount: String,
    "readOnlyRootFilesystem" => read_only_root_filesystem: bool,
    "runAsGroup" => run_as_group: i64,
    "runAsNonRoot" => run_as_non_root: bool,
    "runAsUser" => run_as_user: i64,
    "seLinuxOptions" => se_linux_options: SELinuxOptions,
    "seccompProfile" => seccomp_profile: SeccompProfile,
    "windowsOptions" => windows_options: WindowsSecurityContextOptions,
    }
}

super::native_object! {
    /// Selected native `ServiceAccountTokenProjection` members; unadmitted descendants remain private.
    pub struct ServiceAccountTokenProjection {
    "audience" => audience: String,
    "expirationSeconds" => expiration_seconds: i64,
    "path" => path: String,
    }
}

super::native_object! {
    /// Selected native `StorageOSVolumeSource` members; unadmitted descendants remain private.
    pub struct StorageOSVolumeSource {
    "fsType" => fs_type: String,
    "readOnly" => read_only: bool,
    "secretRef" => secret_ref: LocalObjectReference,
    "volumeName" => volume_name: String,
    "volumeNamespace" => volume_namespace: String,
    }
}

super::native_object! {
    /// Selected native `Sysctl` members; unadmitted descendants remain private.
    pub struct Sysctl {
    "name" => name: String,
    "value" => value: String,
    }
}

super::native_object! {
    /// Selected native `TCPSocketAction` members; unadmitted descendants remain private.
    pub struct TCPSocketAction {
    "host" => host: String,
    "port" => port: IntOrString,
    }
}

super::native_object! {
    /// Selected native `TopologySpreadConstraint` members; unadmitted descendants remain private.
    pub struct TopologySpreadConstraint {
    "labelSelector" => label_selector: LabelSelector,
    "maxSkew" => max_skew: i32,
    "topologyKey" => topology_key: String,
    "whenUnsatisfiable" => when_unsatisfiable: String,
    }
}

super::native_object! {
    /// Selected native `Volume` members; unadmitted descendants remain private.
    pub struct Volume {
    "awsElasticBlockStore" => aws_elastic_block_store: AWSElasticBlockStoreVolumeSource,
    "azureDisk" => azure_disk: AzureDiskVolumeSource,
    "azureFile" => azure_file: AzureFileVolumeSource,
    "cephfs" => cephfs: CephFSVolumeSource,
    "cinder" => cinder: CinderVolumeSource,
    "configMap" => config_map: ConfigMapVolumeSource,
    "csi" => csi: CSIVolumeSource,
    "downwardAPI" => downward_api: DownwardAPIVolumeSource,
    "emptyDir" => empty_dir: EmptyDirVolumeSource,
    "ephemeral" => ephemeral: EphemeralVolumeSource,
    "fc" => fc: FCVolumeSource,
    "flexVolume" => flex_volume: FlexVolumeSource,
    "flocker" => flocker: FlockerVolumeSource,
    "gcePersistentDisk" => gce_persistent_disk: GCEPersistentDiskVolumeSource,
    "gitRepo" => git_repo: GitRepoVolumeSource,
    "glusterfs" => glusterfs: GlusterfsVolumeSource,
    "hostPath" => host_path: HostPathVolumeSource,
    "iscsi" => iscsi: ISCSIVolumeSource,
    "name" => name: String,
    "nfs" => nfs: NFSVolumeSource,
    "persistentVolumeClaim" => persistent_volume_claim: PersistentVolumeClaimVolumeSource,
    "photonPersistentDisk" => photon_persistent_disk: PhotonPersistentDiskVolumeSource,
    "projected" => projected: ProjectedVolumeSource,
    "quobyte" => quobyte: QuobyteVolumeSource,
    "rbd" => rbd: RBDVolumeSource,
    "scaleIO" => scale_io: ScaleIOVolumeSource,
    "secret" => secret: SecretVolumeSource,
    "storageos" => storageos: StorageOSVolumeSource,
    "vsphereVolume" => vsphere_volume: VsphereVirtualDiskVolumeSource,
    }
}

super::native_object! {
    /// Selected native `VolumeDevice` members; unadmitted descendants remain private.
    pub struct VolumeDevice {
    "devicePath" => device_path: String,
    "name" => name: String,
    }
}

super::native_object! {
    /// Selected native `VolumeMount` members; unadmitted descendants remain private.
    pub struct VolumeMount {
    "mountPath" => mount_path: String,
    "mountPropagation" => mount_propagation: String,
    "name" => name: String,
    "readOnly" => read_only: bool,
    "subPath" => sub_path: String,
    "subPathExpr" => sub_path_expr: String,
    }
}

super::native_object! {
    /// Selected native `VolumeProjection` members; unadmitted descendants remain private.
    pub struct VolumeProjection {
    "configMap" => config_map: ConfigMapProjection,
    "downwardAPI" => downward_api: DownwardAPIProjection,
    "secret" => secret: SecretProjection,
    "serviceAccountToken" => service_account_token: ServiceAccountTokenProjection,
    }
}

super::native_object! {
    /// Selected native `WeightedPodAffinityTerm` members; unadmitted descendants remain private.
    pub struct WeightedPodAffinityTerm {
    "podAffinityTerm" => pod_affinity_term: PodAffinityTerm,
    "weight" => weight: i32,
    }
}

super::native_object! {
    /// Selected native `WindowsSecurityContextOptions` members; unadmitted descendants remain private.
    pub struct WindowsSecurityContextOptions {
    "gmsaCredentialSpec" => gmsa_credential_spec: Protected<String>,
    "gmsaCredentialSpecName" => gmsa_credential_spec_name: String,
    "runAsUserName" => run_as_user_name: String,
    }
}
