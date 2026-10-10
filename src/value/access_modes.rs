//! Finite selected volume access modes and privately retained partial sequences.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode},
    registry::{EncodeContext, FieldDecodeContext, codec::FieldCodec},
    source::ExplicitSourceAccess,
    syntax::{NativeOccurrence, TreeNode},
};
use std::fmt;

/// The frozen selected volume access modes; this enum makes no binding/driver claim.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub enum EstablishedVolumeAccessMode {
    /// Native `ReadWriteOnce` spelling.
    ReadWriteOnce,
    /// Native `ReadOnlyMany` spelling.
    ReadOnlyMany,
    /// Native `ReadWriteMany` spelling.
    ReadWriteMany,
}
impl EstablishedVolumeAccessMode {
    /// Exact native spelling, without adding a default or sorting the collection.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::ReadWriteOnce => "ReadWriteOnce",
            Self::ReadOnlyMany => "ReadOnlyMany",
            Self::ReadWriteMany => "ReadWriteMany",
        }
    }
    pub(crate) fn selected(value: &str) -> Option<Self> {
        match value {
            "ReadWriteOnce" => Some(Self::ReadWriteOnce),
            "ReadOnlyMany" => Some(Self::ReadOnlyMany),
            "ReadWriteMany" => Some(Self::ReadWriteMany),
            _ => None,
        }
    }
}
/// Whether indexed finite inspection accounts for every retained sequence entry.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AccessModeCompleteness {
    /// Every entry is in the selected finite set (including the empty sequence).
    Complete,
    /// Unsupported strings remain private; selected entries are partial knowledge.
    Partial,
}
#[derive(Clone, Eq, PartialEq)]
enum Entry {
    Selected(EstablishedVolumeAccessMode),
    Unsupported(String),
}
impl Entry {
    fn spelling(&self) -> &str {
        match self {
            Self::Selected(value) => value.as_str(),
            Self::Unsupported(value) => value,
        }
    }
}
/// Ordered native access modes, retaining unsupported entries and duplicates privately.
///
/// Caller construction accepts only selected values. Decoded collections may be partial;
/// finite inspection returns completeness and original indexes together. Unsupported
/// strings never establish positive access, binding or driver facts.
#[derive(Clone, Default)]
pub struct AccessModes {
    entries: Vec<Entry>,
    occurrence: Option<NativeOccurrence>,
}
impl PartialEq for AccessModes {
    fn eq(&self, other: &Self) -> bool {
        self.entries == other.entries
    }
}
impl Eq for AccessModes {}
impl AccessModes {
    /// Construct selected modes in caller order, preserving every duplicate.
    #[must_use]
    pub fn new(values: Vec<EstablishedVolumeAccessMode>) -> Self {
        Self {
            entries: values.into_iter().map(Entry::Selected).collect(),
            occurrence: None,
        }
    }
    /// Whether the actual native sequence is empty; absence/null belong to `Presence`.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Number of actual native entries, including unsupported values and duplicates.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    /// Completeness plus finite selected values with their original native indexes.
    /// A partial result cannot establish a complete access-mode fact.
    pub fn selected(
        &self,
    ) -> (
        AccessModeCompleteness,
        impl Iterator<Item = (usize, EstablishedVolumeAccessMode)> + '_,
    ) {
        (
            self.completeness(),
            self.entries
                .iter()
                .enumerate()
                .filter_map(|(index, entry)| match entry {
                    Entry::Selected(value) => Some((index, *value)),
                    Entry::Unsupported(_) => None,
                }),
        )
    }
    /// Completeness does not establish native cardinality or owning-field requirements.
    #[must_use]
    pub fn completeness(&self) -> AccessModeCompleteness {
        if self.entries.iter().all(|entry| matches!(entry, Entry::Selected(_))) {
            AccessModeCompleteness::Complete
        } else {
            AccessModeCompleteness::Partial
        }
    }
    /// Reveal the exact ordered native string sequence only with explicit source access.
    pub fn original_values<'a>(&'a self, _access: &ExplicitSourceAccess) -> impl Iterator<Item = &'a str> {
        self.entries.iter().map(Entry::spelling)
    }
    /// Reveal unsupported strings and their original indexes only with explicit source access.
    pub fn unsupported<'a>(&'a self, _access: &ExplicitSourceAccess) -> impl Iterator<Item = (usize, &'a str)> {
        self.entries
            .iter()
            .enumerate()
            .filter_map(|(index, entry)| match entry {
                Entry::Unsupported(value) => Some((index, value.as_str())),
                Entry::Selected(_) => None,
            })
    }
}
impl fmt::Debug for AccessModes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("AccessModes(<private>)")
    }
}
impl FieldCodec for AccessModes {
    fn decode(node: &TreeNode, ctx: &FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        ctx.processing.work(1, ctx.phase)?;
        let items = node
            .as_sequence()
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.clone()))?;
        ctx.processing.payload_array::<Entry>(items.len(), ctx.phase)?;
        let mut values = Vec::with_capacity(items.len());
        for (index, node) in items.iter().enumerate() {
            ctx.processing.work(1, ctx.phase)?;
            let value = node.as_str().ok_or_else(|| {
                Finding::error(FindingCode::NativeFieldInvalid, ctx.phase).at_path(path.child(index.to_string()))
            })?;
            ctx.processing.work(value.len(), ctx.phase)?;
            let entry = if let Some(value) = EstablishedVolumeAccessMode::selected(value) {
                Entry::Selected(value)
            } else {
                ctx.processing.payload(value.len(), ctx.phase)?;
                Entry::Unsupported(value.to_owned())
            };
            values.push(entry);
        }
        Ok(Self {
            entries: values,
            occurrence: Some(NativeOccurrence::new_in(&ctx.processing, ctx.phase)?),
        })
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        ctx.check_sequence_len(self.entries.len(), path)?;
        ctx.observe(path, self.occurrence.as_ref())?;
        if ctx.authoring_snapshot {
            for (index, entry) in self.entries.iter().enumerate() {
                ctx.budget.processing().work(1, ctx.budget.phase())?;
                if matches!(entry, Entry::Unsupported(_)) {
                    return Err(Finding::error(FindingCode::UnadmittedField, ctx.budget.phase())
                        .at_path(path.child(index.to_string())));
                }
            }
        }
        ctx.budget
            .processing()
            .payload_array::<TreeNode>(self.entries.len(), ctx.budget.phase())?;
        let mut items = Vec::with_capacity(self.entries.len());
        for (index, entry) in self.entries.iter().enumerate() {
            ctx.budget.processing().work(1, ctx.budget.phase())?;
            items.push(ctx.string(entry.spelling(), &path.child(index.to_string()))?);
        }
        ctx.sequence(items, path)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{source::ParseLimits, syntax::TreeValue};
    #[test]
    fn authoring_snapshot_marker_is_independent_and_survives_context_clones() -> Result<(), Finding> {
        let path = FieldPath::parse("/accessModes")?;
        let modes = AccessModes::decode(
            &TreeNode::new(TreeValue::Sequence(vec![TreeNode::string("ReadWriteOncePod")])),
            &FieldDecodeContext::standalone(),
            &path,
        )?;
        let mut supplied = EncodeContext::new(None);
        supplied.include_unknown = true;
        assert!(
            modes
                .encode(&supplied.for_source(ParseLimits::default()), &path)
                .is_ok()
        );
        let mut authored = EncodeContext::new(None);
        authored.authoring_snapshot = true;
        // This guard is authoring intent, not whether unknown descendants serialize.
        assert!(!authored.include_unknown);
        let finding = modes
            .encode(&authored.for_source(ParseLimits::default()), &path)
            .err()
            .ok_or_else(|| Finding::error(FindingCode::NativeFieldInvalid, crate::diagnostic::Phase::Generation))?;
        assert_eq!(finding.code, FindingCode::UnadmittedField);
        assert_eq!(finding.path, Some(path.child("0")));
        Ok(())
    }
}

#[cfg(test)]
mod occurrence_equality_tests {
    use super::*;
    use crate::syntax::TreeValue;
    #[test]
    fn source_and_caller_collections_compare_only_native_entries() -> Result<(), Finding> {
        let modes = AccessModes::decode(
            &TreeNode::new(TreeValue::Sequence(vec![
                TreeNode::string("ReadWriteMany"),
                TreeNode::string("ReadWriteMany"),
            ])),
            &FieldDecodeContext::standalone(),
            &FieldPath::default(),
        )?;
        assert_eq!(
            modes,
            AccessModes::new(vec![
                EstablishedVolumeAccessMode::ReadWriteMany,
                EstablishedVolumeAccessMode::ReadWriteMany
            ])
        );
        assert_eq!(modes, modes.clone());
        Ok(())
    }
}
