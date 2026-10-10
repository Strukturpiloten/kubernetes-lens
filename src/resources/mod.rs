//! Fixed codec aggregator. Cohort slots are declarations, not placeholder implementations.
pub mod access;
pub mod common;
pub mod configuration_storage;
pub mod networking;
pub mod workloads;
use crate::{
    capability::DECLARED_APIS,
    diagnostic::Finding,
    model::GroupVersionKind,
    registry::{RegistryBuilder, TypedListRegistration},
};

/// Fixed future file ownership boundaries; none is a delivered codec until registered.
pub const COHORT_SLOTS: &[&str] = &[
    "workloads",
    "networking",
    "configuration_storage",
    "identity_access",
    "extensions",
];
pub(crate) fn registry() -> Result<RegistryBuilder, Vec<Finding>> {
    let mut registry = RegistryBuilder::new();
    for entry in DECLARED_APIS {
        let item_gvk = GroupVersionKind::new(entry.api_version, entry.kind.as_str()).map_err(|e| vec![e])?;
        let gvk =
            GroupVersionKind::new(entry.api_version, &format!("{}List", entry.kind.as_str())).map_err(|e| vec![e])?;
        registry
            .register_list(TypedListRegistration { gvk, item_gvk })
            .map_err(|e| vec![e])?;
    }
    workloads::roots::register(&mut registry).map_err(|e| vec![e])?;
    access::roots::register(&mut registry).map_err(|e| vec![e])?;
    networking::roots::register(&mut registry).map_err(|e| vec![e])?;
    configuration_storage::register(&mut registry).map_err(|e| vec![e])?;
    Ok(registry)
}
