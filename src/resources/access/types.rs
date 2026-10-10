//! Access-owned passive native helpers; only frozen selected members are typed.
use crate::{
    resources::common::{SELinuxOptions, Toleration, native_object},
    value::{IntOrString, LabelSelector, Quantity},
};
use std::collections::BTreeMap;

native_object! {
    /// Selected native `CrossVersionObjectReference` members; unknown neighbors remain private.
    pub struct CrossVersionObjectReferenceV1 {
        "apiVersion" => api_version: String,
        "kind" => kind: String,
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `ContainerResourceMetricSource` members; unknown neighbors remain private.
    pub struct ContainerResourceMetricSourceV2 {
        "container" => container: String,
        "name" => name: String,
        "target" => target: MetricTargetV2,
    }
}

native_object! {
    /// Selected native `CrossVersionObjectReference` members; unknown neighbors remain private.
    pub struct CrossVersionObjectReferenceV2 {
        "apiVersion" => api_version: String,
        "kind" => kind: String,
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `ExternalMetricSource` members; unknown neighbors remain private.
    pub struct ExternalMetricSourceV2 {
        "metric" => metric: MetricIdentifierV2,
        "target" => target: MetricTargetV2,
    }
}

native_object! {
    /// Selected native `HPAScalingPolicy` members; unknown neighbors remain private.
    pub struct HPAScalingPolicyV2 {
        "periodSeconds" => period_seconds: i32,
        "type" => type_: String,
        "value" => value: i32,
    }
}

native_object! {
    /// Selected native `HPAScalingRules` members; unknown neighbors remain private.
    pub struct HPAScalingRulesV2 {
        "policies" => policies: Vec<HPAScalingPolicyV2>,
        "selectPolicy" => select_policy: String,
        "stabilizationWindowSeconds" => stabilization_window_seconds: i32,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerBehavior` members; unknown neighbors remain private.
    pub struct HorizontalPodAutoscalerBehaviorV2 {
        "scaleDown" => scale_down: HPAScalingRulesV2,
        "scaleUp" => scale_up: HPAScalingRulesV2,
    }
}

native_object! {
    /// Selected native `MetricIdentifier` members; unknown neighbors remain private.
    pub struct MetricIdentifierV2 {
        "name" => name: String,
        "selector" => selector: LabelSelector,
    }
}

native_object! {
    /// Selected native `MetricSpec` members; unknown neighbors remain private.
    pub struct MetricSpecV2 {
        "containerResource" => container_resource: ContainerResourceMetricSourceV2,
        "external" => external: ExternalMetricSourceV2,
        "object" => object: ObjectMetricSourceV2,
        "pods" => pods: PodsMetricSourceV2,
        "resource" => resource: ResourceMetricSourceV2,
        "type" => type_: String,
    }
}

native_object! {
    /// Selected native `MetricTarget` members; unknown neighbors remain private.
    pub struct MetricTargetV2 {
        "averageUtilization" => average_utilization: i32,
        "averageValue" => average_value: Quantity,
        "type" => type_: String,
        "value" => value: Quantity,
    }
}

native_object! {
    /// Selected native `ObjectMetricSource` members; unknown neighbors remain private.
    pub struct ObjectMetricSourceV2 {
        "describedObject" => described_object: CrossVersionObjectReferenceV2,
        "metric" => metric: MetricIdentifierV2,
        "target" => target: MetricTargetV2,
    }
}

native_object! {
    /// Selected native `PodsMetricSource` members; unknown neighbors remain private.
    pub struct PodsMetricSourceV2 {
        "metric" => metric: MetricIdentifierV2,
        "target" => target: MetricTargetV2,
    }
}

native_object! {
    /// Selected native `ResourceMetricSource` members; unknown neighbors remain private.
    pub struct ResourceMetricSourceV2 {
        "name" => name: String,
        "target" => target: MetricTargetV2,
    }
}

native_object! {
    /// Selected native `ContainerResourceMetricSource` members; unknown neighbors remain private.
    pub struct ContainerResourceMetricSourceV2Beta1 {
        "container" => container: String,
        "name" => name: String,
        "targetAverageUtilization" => target_average_utilization: i32,
        "targetAverageValue" => target_average_value: Quantity,
    }
}

native_object! {
    /// Selected native `CrossVersionObjectReference` members; unknown neighbors remain private.
    pub struct CrossVersionObjectReferenceV2Beta1 {
        "apiVersion" => api_version: String,
        "kind" => kind: String,
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `ExternalMetricSource` members; unknown neighbors remain private.
    pub struct ExternalMetricSourceV2Beta1 {
        "metricName" => metric_name: String,
        "metricSelector" => metric_selector: LabelSelector,
        "targetAverageValue" => target_average_value: Quantity,
        "targetValue" => target_value: Quantity,
    }
}

native_object! {
    /// Selected native `MetricSpec` members; unknown neighbors remain private.
    pub struct MetricSpecV2Beta1 {
        "containerResource" => container_resource: ContainerResourceMetricSourceV2Beta1,
        "external" => external: ExternalMetricSourceV2Beta1,
        "object" => object: ObjectMetricSourceV2Beta1,
        "pods" => pods: PodsMetricSourceV2Beta1,
        "resource" => resource: ResourceMetricSourceV2Beta1,
        "type" => type_: String,
    }
}

native_object! {
    /// Selected native `ObjectMetricSource` members; unknown neighbors remain private.
    pub struct ObjectMetricSourceV2Beta1 {
        "averageValue" => average_value: Quantity,
        "metricName" => metric_name: String,
        "selector" => selector: LabelSelector,
        "target" => target: CrossVersionObjectReferenceV2Beta1,
        "targetValue" => target_value: Quantity,
    }
}

native_object! {
    /// Selected native `PodsMetricSource` members; unknown neighbors remain private.
    pub struct PodsMetricSourceV2Beta1 {
        "metricName" => metric_name: String,
        "selector" => selector: LabelSelector,
        "targetAverageValue" => target_average_value: Quantity,
    }
}

native_object! {
    /// Selected native `ResourceMetricSource` members; unknown neighbors remain private.
    pub struct ResourceMetricSourceV2Beta1 {
        "name" => name: String,
        "targetAverageUtilization" => target_average_utilization: i32,
        "targetAverageValue" => target_average_value: Quantity,
    }
}

native_object! {
    /// Selected native `ContainerResourceMetricSource` members; unknown neighbors remain private.
    pub struct ContainerResourceMetricSourceV2Beta2 {
        "container" => container: String,
        "name" => name: String,
        "target" => target: MetricTargetV2Beta2,
    }
}

native_object! {
    /// Selected native `CrossVersionObjectReference` members; unknown neighbors remain private.
    pub struct CrossVersionObjectReferenceV2Beta2 {
        "apiVersion" => api_version: String,
        "kind" => kind: String,
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `ExternalMetricSource` members; unknown neighbors remain private.
    pub struct ExternalMetricSourceV2Beta2 {
        "metric" => metric: MetricIdentifierV2Beta2,
        "target" => target: MetricTargetV2Beta2,
    }
}

native_object! {
    /// Selected native `HPAScalingPolicy` members; unknown neighbors remain private.
    pub struct HPAScalingPolicyV2Beta2 {
        "periodSeconds" => period_seconds: i32,
        "type" => type_: String,
        "value" => value: i32,
    }
}

native_object! {
    /// Selected native `HPAScalingRules` members; unknown neighbors remain private.
    pub struct HPAScalingRulesV2Beta2 {
        "policies" => policies: Vec<HPAScalingPolicyV2Beta2>,
        "selectPolicy" => select_policy: String,
        "stabilizationWindowSeconds" => stabilization_window_seconds: i32,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerBehavior` members; unknown neighbors remain private.
    pub struct HorizontalPodAutoscalerBehaviorV2Beta2 {
        "scaleDown" => scale_down: HPAScalingRulesV2Beta2,
        "scaleUp" => scale_up: HPAScalingRulesV2Beta2,
    }
}

native_object! {
    /// Selected native `MetricIdentifier` members; unknown neighbors remain private.
    pub struct MetricIdentifierV2Beta2 {
        "name" => name: String,
        "selector" => selector: LabelSelector,
    }
}

native_object! {
    /// Selected native `MetricSpec` members; unknown neighbors remain private.
    pub struct MetricSpecV2Beta2 {
        "containerResource" => container_resource: ContainerResourceMetricSourceV2Beta2,
        "external" => external: ExternalMetricSourceV2Beta2,
        "object" => object: ObjectMetricSourceV2Beta2,
        "pods" => pods: PodsMetricSourceV2Beta2,
        "resource" => resource: ResourceMetricSourceV2Beta2,
        "type" => type_: String,
    }
}

native_object! {
    /// Selected native `MetricTarget` members; unknown neighbors remain private.
    pub struct MetricTargetV2Beta2 {
        "averageUtilization" => average_utilization: i32,
        "averageValue" => average_value: Quantity,
        "type" => type_: String,
        "value" => value: Quantity,
    }
}

native_object! {
    /// Selected native `ObjectMetricSource` members; unknown neighbors remain private.
    pub struct ObjectMetricSourceV2Beta2 {
        "describedObject" => described_object: CrossVersionObjectReferenceV2Beta2,
        "metric" => metric: MetricIdentifierV2Beta2,
        "target" => target: MetricTargetV2Beta2,
    }
}

native_object! {
    /// Selected native `PodsMetricSource` members; unknown neighbors remain private.
    pub struct PodsMetricSourceV2Beta2 {
        "metric" => metric: MetricIdentifierV2Beta2,
        "target" => target: MetricTargetV2Beta2,
    }
}

native_object! {
    /// Selected native `ResourceMetricSource` members; unknown neighbors remain private.
    pub struct ResourceMetricSourceV2Beta2 {
        "name" => name: String,
        "target" => target: MetricTargetV2Beta2,
    }
}

native_object! {
    /// Selected native `LimitRangeItem` members; unknown neighbors remain private.
    pub struct LimitRangeItem {
        "default" => default: BTreeMap<String, Quantity>,
        "defaultRequest" => default_request: BTreeMap<String, Quantity>,
        "max" => max: BTreeMap<String, Quantity>,
        "maxLimitRequestRatio" => max_limit_request_ratio: BTreeMap<String, Quantity>,
        "min" => min: BTreeMap<String, Quantity>,
        "type" => type_: String,
    }
}

native_object! {
    /// Selected native `ScopeSelector` members; unknown neighbors remain private.
    pub struct ScopeSelector {
        "matchExpressions" => match_expressions: Vec<ScopedResourceSelectorRequirement>,
    }
}

native_object! {
    /// Selected native `ScopedResourceSelectorRequirement` members; unknown neighbors remain private.
    pub struct ScopedResourceSelectorRequirement {
        "operator" => operator: String,
        "scopeName" => scope_name: String,
        "values" => values: Vec<String>,
    }
}

native_object! {
    /// Selected native `Overhead` members; unknown neighbors remain private.
    pub struct OverheadV1 {
        "podFixed" => pod_fixed: BTreeMap<String, Quantity>,
    }
}

native_object! {
    /// Selected native `Scheduling` members; unknown neighbors remain private.
    pub struct SchedulingV1 {
        "nodeSelector" => node_selector: BTreeMap<String, String>,
        "tolerations" => tolerations: Vec<Toleration>,
    }
}

native_object! {
    /// Selected native `Overhead` members; unknown neighbors remain private.
    pub struct OverheadV1Beta1 {
        "podFixed" => pod_fixed: BTreeMap<String, Quantity>,
    }
}

native_object! {
    /// Selected native `Scheduling` members; unknown neighbors remain private.
    pub struct SchedulingV1Beta1 {
        "nodeSelector" => node_selector: BTreeMap<String, String>,
        "tolerations" => tolerations: Vec<Toleration>,
    }
}

native_object! {
    /// Selected native `AllowedCSIDriver` members; unknown neighbors remain private.
    pub struct AllowedCSIDriver {
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `AllowedFlexVolume` members; unknown neighbors remain private.
    pub struct AllowedFlexVolume {
        "driver" => driver: String,
    }
}

native_object! {
    /// Selected native `AllowedHostPath` members; unknown neighbors remain private.
    pub struct AllowedHostPath {
        "pathPrefix" => path_prefix: String,
        "readOnly" => read_only: bool,
    }
}

native_object! {
    /// Selected native `FSGroupStrategyOptions` members; unknown neighbors remain private.
    pub struct FSGroupStrategyOptions {
        "ranges" => ranges: Vec<IDRange>,
        "rule" => rule: String,
    }
}

native_object! {
    /// Selected native `HostPortRange` members; unknown neighbors remain private.
    pub struct HostPortRange {
        "max" => max: i32,
        "min" => min: i32,
    }
}

native_object! {
    /// Selected native `IDRange` members; unknown neighbors remain private.
    pub struct IDRange {
        "max" => max: i64,
        "min" => min: i64,
    }
}

native_object! {
    /// Selected native `PodSecurityPolicySpec` members; unknown neighbors remain private.
    pub struct PodSecurityPolicySpec {
        "allowPrivilegeEscalation" => allow_privilege_escalation: bool,
        "allowedCSIDrivers" => allowed_csi_drivers: Vec<AllowedCSIDriver>,
        "allowedCapabilities" => allowed_capabilities: Vec<String>,
        "allowedFlexVolumes" => allowed_flex_volumes: Vec<AllowedFlexVolume>,
        "allowedHostPaths" => allowed_host_paths: Vec<AllowedHostPath>,
        "allowedProcMountTypes" => allowed_proc_mount_types: Vec<String>,
        "allowedUnsafeSysctls" => allowed_unsafe_sysctls: Vec<String>,
        "defaultAddCapabilities" => default_add_capabilities: Vec<String>,
        "defaultAllowPrivilegeEscalation" => default_allow_privilege_escalation: bool,
        "forbiddenSysctls" => forbidden_sysctls: Vec<String>,
        "fsGroup" => fs_group: FSGroupStrategyOptions,
        "hostIPC" => host_ipc: bool,
        "hostNetwork" => host_network: bool,
        "hostPID" => host_pid: bool,
        "hostPorts" => host_ports: Vec<HostPortRange>,
        "privileged" => privileged: bool,
        "readOnlyRootFilesystem" => read_only_root_filesystem: bool,
        "requiredDropCapabilities" => required_drop_capabilities: Vec<String>,
        "runAsGroup" => run_as_group: RunAsGroupStrategyOptions,
        "runAsUser" => run_as_user: RunAsUserStrategyOptions,
        "runtimeClass" => runtime_class: RuntimeClassStrategyOptions,
        "seLinux" => se_linux: SELinuxStrategyOptions,
        "supplementalGroups" => supplemental_groups: SupplementalGroupsStrategyOptions,
        "volumes" => volumes: Vec<String>,
    }
}

native_object! {
    /// Selected native `RunAsGroupStrategyOptions` members; unknown neighbors remain private.
    pub struct RunAsGroupStrategyOptions {
        "ranges" => ranges: Vec<IDRange>,
        "rule" => rule: String,
    }
}

native_object! {
    /// Selected native `RunAsUserStrategyOptions` members; unknown neighbors remain private.
    pub struct RunAsUserStrategyOptions {
        "ranges" => ranges: Vec<IDRange>,
        "rule" => rule: String,
    }
}

native_object! {
    /// Selected native `RuntimeClassStrategyOptions` members; unknown neighbors remain private.
    pub struct RuntimeClassStrategyOptions {
        "allowedRuntimeClassNames" => allowed_runtime_class_names: Vec<String>,
        "defaultRuntimeClassName" => default_runtime_class_name: String,
    }
}

native_object! {
    /// Selected native `SELinuxStrategyOptions` members; unknown neighbors remain private.
    pub struct SELinuxStrategyOptions {
        "rule" => rule: String,
        "seLinuxOptions" => se_linux_options: SELinuxOptions,
    }
}

native_object! {
    /// Selected native `SupplementalGroupsStrategyOptions` members; unknown neighbors remain private.
    pub struct SupplementalGroupsStrategyOptions {
        "ranges" => ranges: Vec<IDRange>,
        "rule" => rule: String,
    }
}

native_object! {
    /// Selected native `AggregationRule` members; unknown neighbors remain private.
    pub struct AggregationRule {
        "clusterRoleSelectors" => cluster_role_selectors: Vec<LabelSelector>,
    }
}

native_object! {
    /// Selected native `PolicyRule` members; unknown neighbors remain private.
    pub struct PolicyRule {
        "apiGroups" => api_groups: Vec<String>,
        "nonResourceURLs" => non_resource_ur_ls: Vec<String>,
        "resourceNames" => resource_names: Vec<String>,
        "resources" => resources: Vec<String>,
        "verbs" => verbs: Vec<String>,
    }
}

native_object! {
    /// Selected native `RoleRef` members; unknown neighbors remain private.
    pub struct RoleRef {
        "apiGroup" => api_group: String,
        "kind" => kind: String,
        "name" => name: String,
    }
}

native_object! {
    /// Selected native `Subject` members; unknown neighbors remain private.
    pub struct Subject {
        "apiGroup" => api_group: String,
        "kind" => kind: String,
        "name" => name: String,
        "namespace" => namespace: String,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerV1` specification; omitted fields are never defaulted.
    pub struct HorizontalPodAutoscalerV1Spec {
        "scaleTargetRef" => scale_target_ref: CrossVersionObjectReferenceV1,
        "minReplicas" => min_replicas: i32,
        "maxReplicas" => max_replicas: i32,
        "targetCPUUtilizationPercentage" => target_cpu_utilization_percentage: i32,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerV2` specification; omitted fields are never defaulted.
    pub struct HorizontalPodAutoscalerV2Spec {
        "scaleTargetRef" => scale_target_ref: CrossVersionObjectReferenceV2,
        "minReplicas" => min_replicas: i32,
        "maxReplicas" => max_replicas: i32,
        "metrics" => metrics: Vec<MetricSpecV2>,
        "behavior" => behavior: HorizontalPodAutoscalerBehaviorV2,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerV2Beta1` specification; omitted fields are never defaulted.
    pub struct HorizontalPodAutoscalerV2Beta1Spec {
        "scaleTargetRef" => scale_target_ref: CrossVersionObjectReferenceV2Beta1,
        "minReplicas" => min_replicas: i32,
        "maxReplicas" => max_replicas: i32,
        "metrics" => metrics: Vec<MetricSpecV2Beta1>,
    }
}

native_object! {
    /// Selected native `HorizontalPodAutoscalerV2Beta2` specification; omitted fields are never defaulted.
    pub struct HorizontalPodAutoscalerV2Beta2Spec {
        "scaleTargetRef" => scale_target_ref: CrossVersionObjectReferenceV2Beta2,
        "minReplicas" => min_replicas: i32,
        "maxReplicas" => max_replicas: i32,
        "metrics" => metrics: Vec<MetricSpecV2Beta2>,
        "behavior" => behavior: HorizontalPodAutoscalerBehaviorV2Beta2,
    }
}

native_object! {
    /// Selected native `PodDisruptionBudgetV1` specification; omitted fields are never defaulted.
    pub struct PodDisruptionBudgetV1Spec {
        "minAvailable" => min_available: IntOrString,
        "maxUnavailable" => max_unavailable: IntOrString,
        "selector" => selector: LabelSelector,
        "unhealthyPodEvictionPolicy" => unhealthy_pod_eviction_policy: String,
    }
}

native_object! {
    /// Selected native `PodDisruptionBudgetV1Beta1` specification; omitted fields are never defaulted.
    pub struct PodDisruptionBudgetV1Beta1Spec {
        "minAvailable" => min_available: IntOrString,
        "maxUnavailable" => max_unavailable: IntOrString,
        "selector" => selector: LabelSelector,
    }
}

native_object! {
    /// Selected native `ResourceQuota` specification; omitted fields are never defaulted.
    pub struct ResourceQuotaSpec {
        "hard" => hard: BTreeMap<String, Quantity>,
        "scopes" => scopes: Vec<String>,
        "scopeSelector" => scope_selector: ScopeSelector,
    }
}

native_object! {
    /// Selected native `LimitRange` specification; omitted fields are never defaulted.
    pub struct LimitRangeSpec {
        "limits" => limits: Vec<LimitRangeItem>,
    }
}
