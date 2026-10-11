//! Independent offline Kubernetes native-format foundation.
//!
//! Bounded syntax, private evidence, identities, explicit targets, supplied-only graphs and
//! deterministic private artifacts are implemented. Declared built-ins remain preservation-only
//! until independently reviewed native codecs are registered. Generation does not claim admission,
//! controller, renderer, runtime or `BoxFerry` conformance.
pub mod acquisition;
pub mod capability;
pub mod diagnostic;
pub mod formats;
pub mod generation;
pub mod graph;
pub mod model;
pub mod parser;
pub mod processing;
mod registry;
pub mod resources;
pub mod source;
mod syntax;
pub mod value;
pub use diagnostic::{FieldPath, Finding, FindingCode, ResourceId};
pub use generation::{
    NativeValidationIntent, generate, validate_for_target, validate_for_target_with_intent,
    validate_for_target_with_limits,
};
pub use parser::{ParsedInput, parse_source};
pub use syntax::UnknownFields;

#[cfg(test)]
#[path = "../tests/foundation/codec.rs"]
mod foundation_tests;
