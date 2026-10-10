//! Shared retained timestamp lexemes with finite original calendar validation.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    registry::{EncodeContext, codec::FieldCodec},
    source::ExplicitSourceAccess,
    syntax::TreeNode,
};
use std::fmt;
/// Retained RFC3339 native timestamp; source spelling is never normalized or defaulted.
#[derive(Clone)]
pub struct NativeTime(String);
impl NativeTime {
    /// Validate a caller-supplied RFC3339 timestamp without ambient time or timezone access.
    /// # Errors
    /// Rejects invalid date/time/offset grammar and invalid Gregorian calendar components.
    pub fn parse(value: &str) -> Result<Self, Finding> {
        if valid_time(value) {
            Ok(Self(value.to_owned()))
        } else {
            Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation))
        }
    }
    /// Borrow the original timestamp spelling under explicit source access.
    #[must_use]
    pub fn lexeme(&self, _access: &ExplicitSourceAccess) -> &str {
        &self.0
    }
}
impl fmt::Debug for NativeTime {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeTime(<private>)")
    }
}
impl FieldCodec for NativeTime {
    fn decode(node: &TreeNode, ctx: &crate::registry::FieldDecodeContext, path: &FieldPath) -> Result<Self, Finding> {
        let value = String::decode(node, ctx, path)?;
        Self::parse(&value)
            .map_err(|_| Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding).at_path(path.clone()))
    }
    fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
        ctx.string(&self.0, path)
    }
}
fn valid_time(value: &str) -> bool {
    let bytes = value.as_bytes();
    if !value.is_ascii()
        || bytes.len() < 20
        || bytes.get(4) != Some(&b'-')
        || bytes.get(7) != Some(&b'-')
        || bytes.get(10) != Some(&b'T')
        || bytes.get(13) != Some(&b':')
        || bytes.get(16) != Some(&b':')
    {
        return false;
    }
    let number = |a: usize, b: usize| -> Option<u32> {
        let s = value.get(a..b)?;
        if !s.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        s.parse().ok()
    };
    let Some(year) = number(0, 4) else {
        return false;
    };
    let Some(month) = number(5, 7) else {
        return false;
    };
    let Some(day) = number(8, 10) else {
        return false;
    };
    let leap = year % 4 == 0 && (year % 100 != 0 || year % 400 == 0);
    let maximum = match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 => {
            if leap {
                29
            } else {
                28
            }
        }
        _ => return false,
    };
    if day == 0
        || day > maximum
        || number(11, 13).is_none_or(|n| n > 23)
        || number(14, 16).is_none_or(|n| n > 59)
        || number(17, 19).is_none_or(|n| n > 59)
    {
        return false;
    }
    let mut offset = 19;
    if bytes.get(offset) == Some(&b'.') {
        offset += 1;
        let first = offset;
        while bytes.get(offset).is_some_and(u8::is_ascii_digit) {
            offset += 1;
        }
        if offset == first {
            return false;
        }
    }
    if bytes.get(offset) == Some(&b'Z') {
        return offset + 1 == bytes.len();
    }
    matches!(bytes.get(offset), Some(b'+' | b'-'))
        && bytes.len() == offset + 6
        && bytes.get(offset + 3) == Some(&b':')
        && number(offset + 1, offset + 3).is_some_and(|n| n <= 23)
        && number(offset + 4, offset + 6).is_some_and(|n| n <= 59)
}

impl super::UnknownScopes for NativeTime {
    #[cfg(test)]
    fn unknown_scopes(&self, _: &FieldPath, _: &mut std::collections::BTreeSet<FieldPath>) {}
}
