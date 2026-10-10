//! Presence, protected values, exact quantities, and native selector primitives.
use crate::diagnostic::{Finding, FindingCode, Phase};
use crate::source::ExplicitSourceAccess;
use std::{collections::BTreeMap, fmt};
mod access_modes;
mod exact_json_number;
mod native_bytes;
mod native_quantity;
pub(crate) mod protected_json;
pub use access_modes::{AccessModeCompleteness, AccessModes, EstablishedVolumeAccessMode};
pub use exact_json_number::ExactJsonNumber;
pub use native_bytes::NativeBytes;
pub use native_quantity::{NativeQuantityDomain, SuppliedQuantityOrder};
pub use protected_json::{JsonNodeId, ProtectedJsonBuilder, ProtectedJsonValue};

/// Explicit authored presence; omission and explicit null remain different.
#[derive(Clone, Eq, PartialEq, Ord, PartialOrd, Hash, Default)]
pub enum Presence<T> {
    /// No authored field.
    #[default]
    Absent,
    /// Explicit authored null.
    Null,
    /// Explicit authored value.
    Value(T),
}
/// Shared field-presence spelling used by identity/evidence contracts.
pub type Field<T> = Presence<T>;
impl<T> Presence<T> {
    /// Borrow an explicit value without materializing a default.
    #[must_use]
    pub const fn value(&self) -> Option<&T> {
        if let Self::Value(value) = self {
            Some(value)
        } else {
            None
        }
    }
    /// Whether this field was omitted.
    #[must_use]
    pub const fn is_absent(&self) -> bool {
        matches!(self, Self::Absent)
    }
}
impl<T> fmt::Debug for Presence<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Absent => "Absent",
            Self::Null => "Null",
            Self::Value(_) => "Value(<private>)",
        })
    }
}

/// A protected native value; base64 encoding is not redaction.
#[derive(Clone, Eq, PartialEq)]
pub struct Protected<T>(T);
impl<T> Protected<T> {
    /// Mark caller-provided data as protected.
    #[must_use]
    pub const fn new(value: T) -> Self {
        Self(value)
    }
    /// Explicit private value access.
    #[must_use]
    pub const fn reveal(&self, _access: &ExplicitSourceAccess) -> &T {
        &self.0
    }
    pub(crate) const fn native_value(&self) -> &T {
        &self.0
    }
    /// Replace the actual native value without creating a placeholder.
    pub fn replace(&mut self, value: T) {
        self.0 = value;
    }
}
impl<T> fmt::Debug for Protected<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Protected(<private>)")
    }
}

/// General Kubernetes integer-or-string, including named ports such as `http`.
#[derive(Clone, Eq, PartialEq)]
pub enum IntOrString {
    /// Explicit native integer.
    Int(i64),
    /// Explicit native string; it is not assumed to be a percentage.
    String(String),
}
impl fmt::Debug for IntOrString {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Int(_) => "IntOrString::Int(<private>)",
            Self::String(_) => "IntOrString::String(<private>)",
        })
    }
}

/// Context-specific integer-or-percentage; distinct from named strings.
#[derive(Clone, Copy, Eq, PartialEq)]
pub enum IntOrPercent {
    /// Native integer; the owning field enforces its nonnegative/range rules.
    Int(i64),
    /// Whole percentage from zero through one hundred.
    Percent(u8),
}
impl IntOrPercent {
    /// Check directly constructed percentages without clamping caller values.
    /// # Errors
    /// Percentages greater than one hundred are invalid; integers need field-specific rules.
    pub fn validate(self) -> Result<(), Finding> {
        if matches!(self, Self::Percent(percent) if percent > 100) {
            Err(invalid_value())
        } else {
            Ok(())
        }
    }

    /// Parse an explicit percentage, without interpreting arbitrary strings.
    ///
    /// # Errors
    /// Rejects strings without a whole `0..=100` percent value.
    pub fn parse_percent(value: &str) -> Result<Self, Finding> {
        let Some(number) = value.strip_suffix('%') else {
            return Err(invalid_value());
        };
        if number.is_empty() || !number.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(invalid_value());
        }
        let percent: u8 = number.parse().map_err(|_| invalid_value())?;
        if percent > 100 {
            return Err(invalid_value());
        }
        Ok(Self::Percent(percent))
    }
}
impl fmt::Debug for IntOrPercent {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Int(_) => "IntOrPercent::Int(<private>)",
            Self::Percent(_) => "IntOrPercent::Percent(<private>)",
        })
    }
}

/// Exact decimal coefficient and scale, without floating-point rounding.
#[derive(Clone, Eq, PartialEq)]
pub struct ExactQuantity {
    sign: i8,
    digits: String,
    scale: i32,
}
impl ExactQuantity {
    /// Whether the exact value is below zero.
    #[must_use]
    pub const fn is_negative(&self) -> bool {
        self.sign < 0
    }
    /// Whether the exact value is zero.
    #[must_use]
    pub const fn is_zero(&self) -> bool {
        self.sign == 0
    }
    /// Borrow normalized base-ten coefficient digits under explicit access.
    #[must_use]
    pub fn digits(&self, _access: &ExplicitSourceAccess) -> &str {
        &self.digits
    }
    /// The value is `sign * digits * 10^(-scale)`.
    #[must_use]
    pub const fn scale(&self) -> i32 {
        self.scale
    }
}
impl fmt::Debug for ExactQuantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ExactQuantity(<private>)")
    }
}

/// Original quantity lexeme plus its independently parsed exact numeric value.
#[derive(Clone, Eq, PartialEq)]
pub struct Quantity {
    lexeme: String,
    value: ExactQuantity,
}
impl Quantity {
    /// Parse a finite Kubernetes decimal/binary quantity without normalizing its source spelling.
    ///
    /// # Errors
    /// Rejects invalid grammar, excessive scalar size, and exponent arithmetic overflow.
    pub fn parse(lexeme: &str) -> Result<Self, Finding> {
        let limits = crate::source::ParseLimits::default();
        Self::parse_in(
            lexeme,
            &crate::registry::FieldDecodeContext::new(
                limits,
                crate::processing::NativeOperationBudget::new(limits.processing),
                Phase::Validation,
            ),
        )
    }
    fn parse_unbudgeted(lexeme: &str) -> Result<Self, Finding> {
        if lexeme.is_empty() || lexeme.len() > 512 || !lexeme.is_ascii() {
            return Err(invalid_value());
        }
        let (sign, unsigned) = if let Some(value) = lexeme.strip_prefix('-') {
            (-1, value)
        } else {
            (1, lexeme.strip_prefix('+').unwrap_or(lexeme))
        };
        let mut index = 0;
        let bytes = unsigned.as_bytes();
        while index < bytes.len() && bytes[index].is_ascii_digit() {
            index += 1;
        }
        let whole = index;
        let mut fractional = 0;
        if bytes.get(index) == Some(&b'.') {
            index += 1;
            let start = index;
            while index < bytes.len() && bytes[index].is_ascii_digit() {
                index += 1;
            }
            fractional = index - start;
        }
        if whole + fractional == 0 {
            return Err(invalid_value());
        }
        let mut digits: String = unsigned[..index]
            .bytes()
            .filter(|byte| *byte != b'.')
            .map(char::from)
            .collect();
        let suffix = &unsigned[index..];
        let mut scale = i32::try_from(fractional).map_err(|_| invalid_value())?;
        let decimal_power = match suffix {
            "" => 0,
            "n" => -9,
            "u" => -6,
            "m" => -3,
            "k" | "K" => 3,
            "M" => 6,
            "G" => 9,
            "T" => 12,
            "P" => 15,
            "E" => 18,
            _ => {
                if let Some(exponent) = suffix.strip_prefix('e').or_else(|| suffix.strip_prefix('E')) {
                    if exponent.is_empty()
                        || !exponent
                            .trim_start_matches(['+', '-'])
                            .bytes()
                            .all(|byte| byte.is_ascii_digit())
                    {
                        return Err(invalid_value());
                    }
                    exponent.parse::<i32>().map_err(|_| invalid_value())?
                } else if let Some(power) = ["Ki", "Mi", "Gi", "Ti", "Pi", "Ei"]
                    .iter()
                    .position(|unit| *unit == suffix)
                {
                    for _ in 0..((power + 1) * 10) {
                        digits = twice(&digits);
                    }
                    0
                } else {
                    return Err(invalid_value());
                }
            }
        };
        scale = scale.checked_sub(decimal_power).ok_or_else(invalid_value)?;
        let normalized = digits.trim_start_matches('0');
        let mut value = ExactQuantity {
            sign,
            digits: if normalized.is_empty() {
                "0".to_owned()
            } else {
                normalized.to_owned()
            },
            scale,
        };
        if value.digits == "0" {
            value.sign = 0;
            value.scale = 0;
        } else {
            while value.digits.ends_with('0') {
                value.digits.pop();
                value.scale = value.scale.checked_sub(1).ok_or_else(invalid_value)?;
            }
        }
        Ok(Self {
            lexeme: lexeme.to_owned(),
            value,
        })
    }
    /// Borrow the exact numeric value; no defaulting/rounding occurs.
    #[must_use]
    pub const fn exact(&self) -> &ExactQuantity {
        &self.value
    }
    /// Original scalar spelling under explicit source access.
    #[must_use]
    pub fn lexeme(&self, _access: &ExplicitSourceAccess) -> &str {
        &self.lexeme
    }
    pub(crate) fn native_lexeme(&self) -> &str {
        &self.lexeme
    }
    /// Compare numeric equivalence while retaining separate source lexemes.
    #[must_use]
    pub fn equivalent_to(&self, other: &Self) -> bool {
        self.value == other.value
    }
}
impl fmt::Debug for Quantity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Quantity(<private>)")
    }
}
fn twice(value: &str) -> String {
    let mut carry = 0;
    let mut reversed = Vec::with_capacity(value.len() + 1);
    for digit in value.bytes().rev() {
        let number = (digit - b'0') * 2 + carry;
        reversed.push(char::from(b'0' + number % 10));
        carry = number / 10;
    }
    if carry != 0 {
        reversed.push(char::from(b'0' + carry));
    }
    reversed.into_iter().rev().collect()
}
fn invalid_value() -> Finding {
    Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation)
}

/// Finite admitted selector expression operators.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum SelectorOperator {
    /// Key must exist and match a nonempty value set.
    In,
    /// Missing keys or values outside a nonempty set match.
    NotIn,
    /// Key must exist; no values are allowed.
    Exists,
    /// Key must be absent; no values are allowed.
    DoesNotExist,
}
/// One native label selector requirement, with private default Debug.
#[derive(Clone, Eq, PartialEq)]
pub struct SelectorRequirement {
    /// Exact authored label key; never normalized.
    pub key: String,
    /// Finite operator.
    pub operator: SelectorOperator,
    /// Exact authored values.
    pub values: Presence<Vec<String>>,
    pub(crate) unknown: crate::syntax::UnknownFields,
}
impl SelectorRequirement {
    /// Retain the caller's exact key, operator and value presence without defaults.
    #[must_use]
    pub fn new(key: String, operator: SelectorOperator, values: Presence<Vec<String>>) -> Self {
        Self {
            key,
            operator,
            values,
            unknown: crate::syntax::UnknownFields::default(),
        }
    }
}
impl fmt::Debug for SelectorRequirement {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("SelectorRequirement")
            .field("operator", &self.operator)
            .field("value_count", &self.values.value().map_or(0, Vec::len))
            .finish_non_exhaustive()
    }
}
/// Native equality/set label selector; absence of a selector is represented separately.
#[derive(Clone, Eq, PartialEq, Default)]
pub struct LabelSelector {
    /// Exact equality keys and values.
    pub match_labels: Presence<BTreeMap<String, String>>,
    /// All expression requirements must match.
    pub match_expressions: Presence<Vec<SelectorRequirement>>,
    pub(crate) unknown: crate::syntax::UnknownFields,
}
impl LabelSelector {
    /// Author selector members with explicit absence/null/value semantics.
    #[must_use]
    pub fn new(
        match_labels: Presence<BTreeMap<String, String>>,
        match_expressions: Presence<Vec<SelectorRequirement>>,
    ) -> Self {
        Self {
            match_labels,
            match_expressions,
            unknown: crate::syntax::UnknownFields::default(),
        }
    }

    /// Author an explicit equality map; even an empty map remains present.
    #[must_use]
    pub fn from_match_labels(match_labels: BTreeMap<String, String>) -> Self {
        Self {
            match_labels: Presence::Value(match_labels),
            ..Self::default()
        }
    }

    /// Validate finite native label grammar and operator cardinalities.
    ///
    /// # Errors
    /// Reports fixed findings for invalid keys/values or operator/value combinations.
    pub fn validate(&self) -> Result<(), Finding> {
        if !self.unknown.is_empty()
            || self
                .match_expressions
                .value()
                .is_some_and(|items| items.iter().any(|item| !item.unknown.is_empty()))
        {
            return Err(Finding::error(FindingCode::UnadmittedField, Phase::Validation));
        }
        if matches!(self.match_labels, Presence::Null) || matches!(self.match_expressions, Presence::Null) {
            return Err(invalid_value());
        }
        if let Some(labels) = self.match_labels.value() {
            for (key, value) in labels {
                if !label_key(key) || !label_value(value) {
                    return Err(invalid_value());
                }
            }
        }
        if let Some(requirements) = self.match_expressions.value() {
            for requirement in requirements {
                if !label_key(&requirement.key) || matches!(requirement.values, Presence::Null) {
                    return Err(invalid_value());
                }
                let values = requirement.values.value().map_or(&[][..], Vec::as_slice);
                if values.iter().any(|value| !label_value(value)) {
                    return Err(invalid_value());
                }
                let expects = matches!(requirement.operator, SelectorOperator::In | SelectorOperator::NotIn);
                if expects == values.is_empty() {
                    return Err(invalid_value());
                }
            }
        }
        Ok(())
    }
    /// Match admitted supplied labels, preserving invalid/unadmitted selector outcomes.
    /// # Errors
    /// Null, unknown descendants, malformed keys and invalid operator cardinalities never match.
    pub fn matches(&self, labels: &BTreeMap<String, String>) -> Result<bool, Finding> {
        self.validate()?;
        if self
            .match_labels
            .value()
            .is_some_and(|required| required.iter().any(|(key, value)| labels.get(key) != Some(value)))
        {
            return Ok(false);
        }
        Ok(self.match_expressions.value().is_none_or(|requirements| {
            requirements.iter().all(|requirement| {
                let value = labels.get(&requirement.key);
                let values = requirement.values.value().map_or(&[][..], Vec::as_slice);
                match requirement.operator {
                    SelectorOperator::In => value.is_some_and(|value| values.contains(value)),
                    SelectorOperator::NotIn => value.is_none_or(|value| !values.contains(value)),
                    SelectorOperator::Exists => value.is_some(),
                    SelectorOperator::DoesNotExist => value.is_none(),
                }
            })
        }))
    }
}
impl fmt::Debug for LabelSelector {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LabelSelector")
            .field("equality_count", &self.match_labels.value().map_or(0, BTreeMap::len))
            .field("expression_count", &self.match_expressions.value().map_or(0, Vec::len))
            .finish_non_exhaustive()
    }
}
pub(crate) fn dns_subdomain(value: &str) -> bool {
    qualified_label_prefix(value)
}
pub(crate) fn dns_label(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
}
pub(crate) fn label_key(value: &str) -> bool {
    if let Some((prefix, name)) = value.split_once('/') {
        qualified_label_prefix(prefix) && label_name(name, false)
    } else {
        label_name(value, false)
    }
}
// Qualified label prefixes use the native DNS subdomain envelope: the total
// length is bounded, while individual components have no separate 63-byte cap.
fn qualified_label_prefix(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && part.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && part.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}
fn label_name(value: &str, empty: bool) -> bool {
    if value.is_empty() {
        return empty;
    }
    value.len() <= 63
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.'))
        && value.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
        && value.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
}
pub(crate) fn label_value(value: &str) -> bool {
    label_name(value, true)
}
