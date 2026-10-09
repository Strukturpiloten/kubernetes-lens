//! Fixed enum domains from the finite reviewed workload/common inventory.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    registry::FindingSink,
    syntax::TreeNode,
};
type EnumRule = (&'static str, &'static [&'static str]);
const RULES_0: &[EnumRule] = &[
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    ("/spec/containers/*/livenessProbe/httpGet/scheme", &["HTTP", "HTTPS"]),
    ("/spec/containers/*/ports/*/protocol", &["TCP", "UDP", "SCTP"]),
    ("/spec/containers/*/readinessProbe/httpGet/scheme", &["HTTP", "HTTPS"]),
    ("/spec/containers/*/resizePolicy/*/resourceName", &["cpu", "memory"]),
    (
        "/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/containers/*/restartPolicy", &["Always"]),
    ("/spec/containers/*/securityContext/procMount", &["Default", "Unmasked"]),
    (
        "/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    ("/spec/containers/*/startupProbe/httpGet/scheme", &["HTTP", "HTTPS"]),
    (
        "/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    ("/spec/initContainers/*/ports/*/protocol", &["TCP", "UDP", "SCTP"]),
    (
        "/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    ("/spec/initContainers/*/resizePolicy/*/resourceName", &["cpu", "memory"]),
    (
        "/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    ("/spec/initContainers/*/startupProbe/httpGet/scheme", &["HTTP", "HTTPS"]),
    (
        "/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    ("/spec/preemptionPolicy", &["Never", "PreemptLowerPriority"]),
    ("/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_1: &[EnumRule] = &[
    (
        "/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    ("/spec/strategy/type", &["RollingUpdate", "Recreate"]),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_2: &[EnumRule] = &[
    (
        "/spec/persistentVolumeClaimRetentionPolicy/whenDeleted",
        &["Retain", "Delete"],
    ),
    (
        "/spec/persistentVolumeClaimRetentionPolicy/whenScaled",
        &["Retain", "Delete"],
    ),
    ("/spec/podManagementPolicy", &["OrderedReady", "Parallel"]),
    (
        "/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
    ("/spec/updateStrategy/type", &["RollingUpdate", "OnDelete"]),
    (
        "/spec/volumeClaimTemplates/*/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    ("/spec/volumeClaimTemplates/*/spec/volumeMode", &["Filesystem", "Block"]),
];
const RULES_3: &[EnumRule] = &[
    (
        "/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
    ("/spec/updateStrategy/type", &["RollingUpdate", "OnDelete"]),
];
const RULES_4: &[EnumRule] = &[
    (
        "/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_5: &[EnumRule] = &[
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_6: &[EnumRule] = &[
    ("/spec/completionMode", &["NonIndexed", "Indexed"]),
    (
        "/spec/podFailurePolicy/rules/*/action",
        &["FailJob", "FailIndex", "Ignore", "Count"],
    ),
    ("/spec/podFailurePolicy/rules/*/onExitCodes/operator", &["In", "NotIn"]),
    (
        "/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/containers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    ("/spec/template/spec/initContainers/*/restartPolicy", &["Always"]),
    (
        "/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    ("/spec/template/spec/restartPolicy", &["Always", "OnFailure", "Never"]),
    (
        "/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    ("/spec/template/spec/tolerations/*/operator", &["Equal", "Exists"]),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_7: &[EnumRule] = &[
    ("/spec/concurrencyPolicy", &["Allow", "Forbid", "Replace"]),
    ("/spec/jobTemplate/spec/completionMode", &["NonIndexed", "Indexed"]),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/action",
        &["FailJob", "FailIndex", "Ignore", "Count"],
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/operator",
        &["In", "NotIn"],
    ),
    (
        "/spec/jobTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/restartPolicy",
        &["Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/restartPolicy",
        &["Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/restartPolicy",
        &["Always", "OnFailure", "Never"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/tolerations/*/operator",
        &["Equal", "Exists"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
const RULES_8: &[EnumRule] = &[
    ("/spec/concurrencyPolicy", &["Allow", "Forbid", "Replace"]),
    ("/spec/jobTemplate/spec/completionMode", &["NonIndexed", "Indexed"]),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/action",
        &["FailJob", "FailIndex", "Ignore", "Count"],
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/operator",
        &["In", "NotIn"],
    ),
    (
        "/spec/jobTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist", "Gt", "Lt"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/restartPolicy",
        &["Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/dnsPolicy",
        &["ClusterFirstWithHostNet", "ClusterFirst", "Default", "None"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/imagePullPolicy",
        &["Always", "Never", "IfNotPresent"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/ports/*/protocol",
        &["TCP", "UDP", "SCTP"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        &["cpu", "memory"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        &["NotRequired", "RestartContainer"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/restartPolicy",
        &["Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/procMount",
        &["Default", "Unmasked"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/scheme",
        &["HTTP", "HTTPS"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/terminationMessagePolicy",
        &["File", "FallbackToLogsOnError"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/mountPropagation",
        &["None", "HostToContainer", "Bidirectional"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/preemptionPolicy",
        &["Never", "PreemptLowerPriority"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/restartPolicy",
        &["Always", "OnFailure", "Never"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/fsGroupChangePolicy",
        &["OnRootMismatch", "Always"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/seccompProfile/type",
        &["Localhost", "RuntimeDefault", "Unconfined"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/tolerations/*/effect",
        &["", "NoSchedule", "PreferNoSchedule", "NoExecute"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/tolerations/*/operator",
        &["Equal", "Exists"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        &["DoNotSchedule", "ScheduleAnyway"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        &["In", "NotIn", "Exists", "DoesNotExist"],
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/volumeMode",
        &["Filesystem", "Block"],
    ),
];
pub(super) fn validate(tree: &TreeNode, kind: &str, api: &str, minor: u8, out: &mut dyn FindingSink) {
    let rules = match (kind, api) {
        ("Pod", "v1") => RULES_0,
        ("Deployment", "apps/v1") => RULES_1,
        ("StatefulSet", "apps/v1") => RULES_2,
        ("DaemonSet", "apps/v1") => RULES_3,
        ("ReplicaSet", "apps/v1") => RULES_4,
        ("ReplicationController", "v1") => RULES_5,
        ("Job", "batch/v1") => RULES_6,
        ("CronJob", "batch/v1") => RULES_7,
        ("CronJob", "batch/v1beta1") => RULES_8,
        _ => return,
    };
    validate_required(tree, kind, api, minor, out);
    for (pointer, values) in rules {
        if let Ok(pattern) = FieldPath::parse(pointer) {
            visit(tree, &pattern.0, &FieldPath::default(), values, out);
        }
    }
}
fn visit(node: &TreeNode, remaining: &[String], path: &FieldPath, values: &[&str], out: &mut dyn FindingSink) {
    let Some((first, rest)) = remaining.split_first() else {
        if node.as_str().is_some_and(|value| !values.contains(&value)) {
            out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
        }
        return;
    };
    if first == "*" {
        if let Some(list) = node.as_sequence() {
            for (i, n) in list.iter().enumerate() {
                visit(n, rest, &path.child(i.to_string()), values, out);
            }
        } else if let Some(map) = node.as_mapping() {
            for (key, n) in map {
                visit(n, rest, &path.child(key.clone()), values, out);
            }
        }
    } else if let Some(n) = node.get(first) {
        visit(n, rest, &path.child(first.clone()), values, out);
    }
}
const REQUIRED_0: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/containers", 262_143),
    ("/spec/containers/*/env/*/name", 262_143),
    ("/spec/containers/*/env/*/valueFrom/configMapKeyRef/key", 262_143),
    ("/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath", 262_143),
    ("/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource", 262_143),
    ("/spec/containers/*/env/*/valueFrom/secretKeyRef/key", 262_143),
    (
        "/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/containers/*/lifecycle/postStart/httpGet/port", 262_143),
    ("/spec/containers/*/lifecycle/postStart/tcpSocket/port", 262_143),
    (
        "/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/containers/*/lifecycle/preStop/httpGet/port", 262_143),
    ("/spec/containers/*/lifecycle/preStop/tcpSocket/port", 262_143),
    ("/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name", 262_143),
    ("/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value", 262_143),
    ("/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/containers/*/name", 262_143),
    ("/spec/containers/*/ports/*/containerPort", 262_143),
    ("/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name", 262_143),
    ("/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value", 262_143),
    ("/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    ("/spec/containers/*/readinessProbe/tcpSocket/port", 262_143),
    ("/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    ("/spec/containers/*/securityContext/seccompProfile/type", 262_143),
    ("/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name", 262_143),
    ("/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value", 262_143),
    ("/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/hostAliases/*/ip", 260_096),
    ("/spec/initContainers/*/env/*/name", 262_143),
    ("/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key", 262_143),
    ("/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath", 262_143),
    (
        "/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    ("/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key", 262_143),
    (
        "/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/initContainers/*/lifecycle/postStart/httpGet/port", 262_143),
    ("/spec/initContainers/*/lifecycle/postStart/tcpSocket/port", 262_143),
    (
        "/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/initContainers/*/lifecycle/preStop/httpGet/port", 262_143),
    ("/spec/initContainers/*/lifecycle/preStop/tcpSocket/port", 262_143),
    (
        "/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/initContainers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/initContainers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/initContainers/*/name", 262_143),
    ("/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/initContainers/*/readinessProbe/httpGet/port", 262_143),
    ("/spec/initContainers/*/readinessProbe/tcpSocket/port", 262_143),
    ("/spec/initContainers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/initContainers/*/resizePolicy/*/restartPolicy", 262_016),
    ("/spec/initContainers/*/securityContext/seccompProfile/type", 262_143),
    (
        "/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/initContainers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/initContainers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/initContainers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    ("/spec/topologySpreadConstraints/*/whenUnsatisfiable", 262_143),
    ("/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/volumes/*/csi/driver", 262_143),
    ("/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath", 262_143),
    ("/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    ("/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource", 262_143),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    ("/spec/volumes/*/ephemeral/volumeClaimTemplate/spec", 262_143),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/volumes/*/name", 262_143),
    ("/spec/volumes/*/nfs/path", 262_143),
    ("/spec/volumes/*/nfs/server", 262_143),
    ("/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    ("/spec/volumes/*/projected/sources/*/configMap/items/*/key", 262_143),
    ("/spec/volumes/*/projected/sources/*/configMap/items/*/path", 262_143),
    (
        "/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    ("/spec/volumes/*/projected/sources/*/secret/items/*/key", 262_143),
    ("/spec/volumes/*/projected/sources/*/secret/items/*/path", 262_143),
    ("/spec/volumes/*/projected/sources/*/serviceAccountToken/path", 262_143),
    ("/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/volumes/*/rbd/image", 262_143),
    ("/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_1: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/selector", 262_143),
    ("/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/template", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_2: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/selector", 262_143),
    ("/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/serviceName", 8191),
    ("/spec/template", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
    (
        "/spec/volumeClaimTemplates/*/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    ("/spec/volumeClaimTemplates/*/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/volumeClaimTemplates/*/metadata/ownerReferences/*/name", 262_143),
    ("/spec/volumeClaimTemplates/*/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/volumeClaimTemplates/*/spec/dataSource/kind", 262_143),
    ("/spec/volumeClaimTemplates/*/spec/dataSource/name", 262_143),
    (
        "/spec/volumeClaimTemplates/*/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/volumeClaimTemplates/*/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/volumeClaimTemplates/*/status/conditions/*/status", 262_143),
    ("/spec/volumeClaimTemplates/*/status/conditions/*/type", 262_143),
];
const REQUIRED_3: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/selector", 262_143),
    ("/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/template", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_4: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/selector", 262_143),
    ("/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_5: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_6: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/podFailurePolicy/rules", 262_112),
    ("/spec/podFailurePolicy/rules/*/action", 262_112),
    ("/spec/podFailurePolicy/rules/*/onExitCodes/operator", 262_112),
    ("/spec/podFailurePolicy/rules/*/onExitCodes/values", 262_112),
    ("/spec/podFailurePolicy/rules/*/onPodConditions", 480),
    ("/spec/podFailurePolicy/rules/*/onPodConditions/*/status", 32_736),
    ("/spec/podFailurePolicy/rules/*/onPodConditions/*/type", 262_112),
    ("/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/successPolicy/rules", 261_120),
    ("/spec/template", 262_143),
    ("/spec/template/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/template/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/template/metadata/ownerReferences/*/name", 262_143),
    ("/spec/template/metadata/ownerReferences/*/uid", 262_143),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/template/spec/containers", 262_143),
    ("/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/livenessProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/livenessProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/name", 262_143),
    ("/spec/template/spec/containers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/readinessProbe/httpGet/port", 262_143),
    (
        "/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/containers/*/resizePolicy/*/resourceName", 262_016),
    ("/spec/template/spec/containers/*/resizePolicy/*/restartPolicy", 262_016),
    (
        "/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    ("/spec/template/spec/containers/*/startupProbe/httpGet/port", 262_143),
    ("/spec/template/spec/containers/*/startupProbe/tcpSocket/port", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/devicePath", 262_143),
    ("/spec/template/spec/containers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/containers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/hostAliases/*/ip", 260_096),
    ("/spec/template/spec/initContainers/*/env/*/name", 262_143),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/ports/*/containerPort", 262_143),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    ("/spec/template/spec/initContainers/*/volumeDevices/*/name", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/mountPath", 262_143),
    ("/spec/template/spec/initContainers/*/volumeMounts/*/name", 262_143),
    ("/spec/template/spec/readinessGates/*/conditionType", 262_143),
    ("/spec/template/spec/securityContext/seccompProfile/type", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/name", 262_143),
    ("/spec/template/spec/securityContext/sysctls/*/value", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/topologySpreadConstraints/*/maxSkew", 262_143),
    ("/spec/template/spec/topologySpreadConstraints/*/topologyKey", 262_143),
    (
        "/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskName", 262_143),
    ("/spec/template/spec/volumes/*/azureDisk/diskURI", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/secretName", 262_143),
    ("/spec/template/spec/volumes/*/azureFile/shareName", 262_143),
    ("/spec/template/spec/volumes/*/cephfs/monitors", 262_143),
    ("/spec/template/spec/volumes/*/cinder/volumeID", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/configMap/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/downwardAPI/items/*/path", 262_143),
    (
        "/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/flexVolume/driver", 262_143),
    ("/spec/template/spec/volumes/*/gcePersistentDisk/pdName", 262_143),
    ("/spec/template/spec/volumes/*/gitRepo/repository", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/endpoints", 262_143),
    ("/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    ("/spec/template/spec/volumes/*/iscsi/targetPortal", 262_143),
    ("/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/template/spec/volumes/*/nfs/server", 262_143),
    ("/spec/template/spec/volumes/*/persistentVolumeClaim/claimName", 262_143),
    ("/spec/template/spec/volumes/*/photonPersistentDisk/pdID", 262_143),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    ("/spec/template/spec/volumes/*/quobyte/registry", 262_143),
    ("/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/gateway", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/secretRef", 262_143),
    ("/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/key", 262_143),
    ("/spec/template/spec/volumes/*/secret/items/*/path", 262_143),
    ("/spec/template/spec/volumes/*/vsphereVolume/volumePath", 262_143),
];
const REQUIRED_7: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/jobTemplate", 262_142),
    ("/spec/jobTemplate/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/name", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules", 262_112),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules/*/action", 262_112),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/operator",
        262_112,
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/values",
        262_112,
    ),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions", 480),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions/*/status",
        32_736,
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions/*/type",
        262_112,
    ),
    ("/spec/jobTemplate/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/jobTemplate/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/jobTemplate/spec/successPolicy/rules", 261_120),
    ("/spec/jobTemplate/spec/template", 262_143),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/containers", 262_143),
    ("/spec/jobTemplate/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/containers/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/ports/*/containerPort",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeDevices/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/mountPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/name",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/hostAliases/*/ip", 260_096),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/initContainers/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/ports/*/containerPort",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeDevices/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/mountPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/readinessGates/*/conditionType",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/sysctls/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/sysctls/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/maxSkew",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureDisk/diskName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureDisk/diskURI",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureFile/secretName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureFile/shareName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/cephfs/monitors",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/cinder/volumeID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/configMap/items/*/path",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/flexVolume/driver",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/gcePersistentDisk/pdName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/gitRepo/repository",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/glusterfs/endpoints",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/targetPortal",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/nfs/server", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/persistentVolumeClaim/claimName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/photonPersistentDisk/pdID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/quobyte/registry",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/gateway",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/secretRef",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/vsphereVolume/volumePath",
        262_143,
    ),
    ("/spec/schedule", 262_142),
];
const REQUIRED_8: &[(&str, u32)] = &[
    ("/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/metadata/ownerReferences/*/kind", 262_143),
    ("/metadata/ownerReferences/*/name", 262_143),
    ("/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/jobTemplate", 31),
    ("/spec/jobTemplate/metadata/ownerReferences/*/apiVersion", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/kind", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/name", 262_143),
    ("/spec/jobTemplate/metadata/ownerReferences/*/uid", 262_143),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules", 262_112),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules/*/action", 262_112),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/operator",
        262_112,
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onExitCodes/values",
        262_112,
    ),
    ("/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions", 480),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions/*/status",
        32_736,
    ),
    (
        "/spec/jobTemplate/spec/podFailurePolicy/rules/*/onPodConditions/*/type",
        262_112,
    ),
    ("/spec/jobTemplate/spec/selector/matchExpressions/*/key", 262_143),
    ("/spec/jobTemplate/spec/selector/matchExpressions/*/operator", 262_143),
    ("/spec/jobTemplate/spec/successPolicy/rules", 261_120),
    ("/spec/jobTemplate/spec/template", 262_143),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/preference/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/nodeAffinity/requiredDuringSchedulingIgnoredDuringExecution/nodeSelectorTerms/*/matchFields/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/podAffinityTerm/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/preferredDuringSchedulingIgnoredDuringExecution/*/weight",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/affinity/podAntiAffinity/requiredDuringSchedulingIgnoredDuringExecution/*/topologyKey",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/containers", 262_143),
    ("/spec/jobTemplate/spec/template/spec/containers/*/env/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/containers/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/ports/*/containerPort",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeDevices/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/mountPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/containers/*/volumeMounts/*/name",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/hostAliases/*/ip", 260_096),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/configMapKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/env/*/valueFrom/secretKeyRef/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/postStart/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/lifecycle/preStop/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/livenessProbe/tcpSocket/port",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/initContainers/*/name", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/ports/*/containerPort",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/readinessProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/resourceName",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/resizePolicy/*/restartPolicy",
        262_016,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/httpHeaders/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/httpGet/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/startupProbe/tcpSocket/port",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeDevices/*/devicePath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeDevices/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/mountPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/initContainers/*/volumeMounts/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/readinessGates/*/conditionType",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/seccompProfile/type",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/sysctls/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/securityContext/sysctls/*/value",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/labelSelector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/maxSkew",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/topologyKey",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/topologySpreadConstraints/*/whenUnsatisfiable",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/awsElasticBlockStore/volumeID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureDisk/diskName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureDisk/diskURI",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureFile/secretName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/azureFile/shareName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/cephfs/monitors",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/cinder/volumeID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/configMap/items/*/path",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/csi/driver", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/apiVersion",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/metadata/ownerReferences/*/uid",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/kind",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/dataSource/name",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/ephemeral/volumeClaimTemplate/spec/selector/matchExpressions/*/operator",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/flexVolume/driver",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/gcePersistentDisk/pdName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/gitRepo/repository",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/glusterfs/endpoints",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/glusterfs/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/hostPath/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/iqn", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/lun", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/iscsi/targetPortal",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/name", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/nfs/path", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/nfs/server", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/persistentVolumeClaim/claimName",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/photonPersistentDisk/pdID",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/configMap/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/fieldRef/fieldPath",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/downwardAPI/items/*/resourceFieldRef/resource",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/projected/sources/*/serviceAccountToken/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/quobyte/registry",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/quobyte/volume", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/rbd/image", 262_143),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/rbd/monitors", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/gateway",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/secretRef",
        262_143,
    ),
    ("/spec/jobTemplate/spec/template/spec/volumes/*/scaleIO/system", 262_143),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/secret/items/*/key",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/secret/items/*/path",
        262_143,
    ),
    (
        "/spec/jobTemplate/spec/template/spec/volumes/*/vsphereVolume/volumePath",
        262_143,
    ),
    ("/spec/schedule", 31),
];
fn validate_required(tree: &TreeNode, kind: &str, api: &str, minor: u8, out: &mut dyn FindingSink) {
    let rules = match (kind, api) {
        ("Pod", "v1") => REQUIRED_0,
        ("Deployment", "apps/v1") => REQUIRED_1,
        ("StatefulSet", "apps/v1") => REQUIRED_2,
        ("DaemonSet", "apps/v1") => REQUIRED_3,
        ("ReplicaSet", "apps/v1") => REQUIRED_4,
        ("ReplicationController", "v1") => REQUIRED_5,
        ("Job", "batch/v1") => REQUIRED_6,
        ("CronJob", "batch/v1") => REQUIRED_7,
        ("CronJob", "batch/v1beta1") => REQUIRED_8,
        _ => return,
    };
    for (pointer, mask) in rules {
        if mask & (1_u32 << u32::from(minor - 20)) == 0 {
            continue;
        }
        if let Ok(pattern) = FieldPath::parse(pointer) {
            required_visit(tree, &pattern.0, &FieldPath::default(), out);
        }
    }
}
fn required_visit(node: &TreeNode, remaining: &[String], path: &FieldPath, out: &mut dyn FindingSink) {
    let Some((first, rest)) = remaining.split_first() else {
        return;
    };
    if rest.is_empty() {
        if node.as_mapping().is_some()
            && node
                .get(first)
                .is_none_or(|n| matches!(n.value, crate::syntax::TreeValue::Null))
        {
            out.push(
                Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.child(first.clone())),
            );
        }
    } else if first == "*" {
        if let Some(list) = node.as_sequence() {
            for (i, n) in list.iter().enumerate() {
                required_visit(n, rest, &path.child(i.to_string()), out);
            }
        } else if let Some(map) = node.as_mapping() {
            for (key, n) in map {
                required_visit(n, rest, &path.child(key.clone()), out);
            }
        }
    } else if let Some(n) = node.get(first) {
        required_visit(n, rest, &path.child(first.clone()), out);
    }
}
