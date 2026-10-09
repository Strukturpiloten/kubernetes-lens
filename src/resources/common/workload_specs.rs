//! Shared passive specification DTOs; concrete roots and semantics remain workloads-owned.
use super::{
    DaemonSetUpdateStrategy, DeploymentStrategy, JobTemplateV1, JobTemplateV1Beta1, PodTemplateSpec,
    StatefulSetClaimTemplate, StatefulSetOrdinals, StatefulSetPersistentVolumeClaimRetentionPolicy,
    StatefulSetUpdateStrategy,
};
use crate::value::LabelSelector;
use std::collections::BTreeMap;
super::native_object! {
    /// Explicit selected `DeploymentSpec` fields; no controller defaults are materialized.
    pub struct DeploymentSpec {
        "replicas" => replicas: i32,
        "selector" => selector: LabelSelector,
        "template" => template: PodTemplateSpec,
        "strategy" => strategy: DeploymentStrategy,
        "minReadySeconds" => min_ready_seconds: i32,
        "revisionHistoryLimit" => revision_history_limit: i32,
        "paused" => paused: bool,
        "progressDeadlineSeconds" => progress_deadline_seconds: i32,
    }
}

super::native_object! {
    /// Explicit selected `StatefulSetSpec` fields; no controller defaults are materialized.
    pub struct StatefulSetSpec {
        "replicas" => replicas: i32,
        "selector" => selector: LabelSelector,
        "template" => template: PodTemplateSpec,
        "volumeClaimTemplates" => volume_claim_templates: Vec<StatefulSetClaimTemplate>,
        "serviceName" => service_name: String,
        "podManagementPolicy" => pod_management_policy: String,
        "updateStrategy" => update_strategy: StatefulSetUpdateStrategy,
        "revisionHistoryLimit" => revision_history_limit: i32,
        "minReadySeconds" => min_ready_seconds: i32,
        "persistentVolumeClaimRetentionPolicy" => persistent_volume_claim_retention_policy: StatefulSetPersistentVolumeClaimRetentionPolicy,
        "ordinals" => ordinals: StatefulSetOrdinals,
    }
}

super::native_object! {
    /// Explicit selected `DaemonSetSpec` fields; no controller defaults are materialized.
    pub struct DaemonSetSpec {
        "selector" => selector: LabelSelector,
        "template" => template: PodTemplateSpec,
        "updateStrategy" => update_strategy: DaemonSetUpdateStrategy,
        "minReadySeconds" => min_ready_seconds: i32,
        "revisionHistoryLimit" => revision_history_limit: i32,
    }
}

super::native_object! {
    /// Explicit selected `ReplicaSetSpec` fields; no controller defaults are materialized.
    pub struct ReplicaSetSpec {
        "replicas" => replicas: i32,
        "minReadySeconds" => min_ready_seconds: i32,
        "selector" => selector: LabelSelector,
        "template" => template: PodTemplateSpec,
    }
}

super::native_object! {
    /// Explicit selected `ReplicationControllerSpec` fields; no controller defaults are materialized.
    pub struct ReplicationControllerSpec {
        "replicas" => replicas: i32,
        "minReadySeconds" => min_ready_seconds: i32,
        "selector" => selector: BTreeMap<String, String>,
        "template" => template: PodTemplateSpec,
    }
}

super::native_object! {
    /// Explicit selected `CronJobV1Spec` fields; no controller defaults are materialized.
    pub struct CronJobV1Spec {
        "schedule" => schedule: String,
        "timeZone" => time_zone: String,
        "startingDeadlineSeconds" => starting_deadline_seconds: i64,
        "concurrencyPolicy" => concurrency_policy: String,
        "suspend" => suspend: bool,
        "jobTemplate" => job_template: JobTemplateV1,
        "successfulJobsHistoryLimit" => successful_jobs_history_limit: i32,
        "failedJobsHistoryLimit" => failed_jobs_history_limit: i32,
    }
}

super::native_object! {
    /// Explicit selected `CronJobV1Beta1Spec` fields; no controller defaults are materialized.
    pub struct CronJobV1Beta1Spec {
        "schedule" => schedule: String,
        "startingDeadlineSeconds" => starting_deadline_seconds: i64,
        "concurrencyPolicy" => concurrency_policy: String,
        "suspend" => suspend: bool,
        "jobTemplate" => job_template: JobTemplateV1Beta1,
        "successfulJobsHistoryLimit" => successful_jobs_history_limit: i32,
        "failedJobsHistoryLimit" => failed_jobs_history_limit: i32,
    }
}
