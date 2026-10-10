//! Finite resource-name predicates from authenticated native specification facts.
use crate::value::label_key;

pub(super) fn standard_quota(name: &str) -> bool {
    matches!(
        name,
        "cpu"
            | "memory"
            | "ephemeral-storage"
            | "requests.cpu"
            | "requests.memory"
            | "requests.storage"
            | "requests.ephemeral-storage"
            | "limits.cpu"
            | "limits.memory"
            | "limits.ephemeral-storage"
            | "pods"
            | "resourcequotas"
            | "services"
            | "replicationcontrollers"
            | "secrets"
            | "persistentvolumeclaims"
            | "configmaps"
            | "services.nodeports"
            | "services.loadbalancers"
    ) || name.starts_with("hugepages-")
        || name.starts_with("requests.hugepages-")
}
pub(super) fn extended(name: &str) -> bool {
    !name.contains("kubernetes.io/")
        && !name.starts_with("requests.")
        && name
            .split_once('/')
            .is_some_and(|(prefix, _)| prefix.len().saturating_add(9) <= 253)
        && label_key(name)
}
pub(super) fn container(name: &str) -> bool {
    if !label_key(name) {
        return false;
    }
    if name.contains('/') {
        name.contains("kubernetes.io/") || extended(name)
    } else {
        matches!(name, "cpu" | "memory" | "ephemeral-storage") || name.starts_with("hugepages-")
    }
}
pub(super) fn quota(name: &str) -> bool {
    label_key(name) && (name.contains('/') || standard_quota(name))
}
pub(super) fn general(name: &str) -> bool {
    label_key(name) && (name.contains('/') || name == "storage" || standard_quota(name))
}
pub(super) fn integer(name: &str) -> bool {
    matches!(
        name,
        "pods"
            | "resourcequotas"
            | "services"
            | "replicationcontrollers"
            | "secrets"
            | "configmaps"
            | "persistentvolumeclaims"
            | "services.nodeports"
            | "services.loadbalancers"
    ) || extended(name)
}
