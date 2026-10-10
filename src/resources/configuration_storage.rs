//! Typed configuration and storage resources. Cohort registration is intentionally separate
//! from the fixed aggregator in `resources::mod`.
mod capabilities;
mod facts;
mod roots;
mod validation;

pub use roots::{ConfigMap, PersistentVolume, PersistentVolumeClaim, Secret, StorageClass};

pub(crate) use roots::register;
