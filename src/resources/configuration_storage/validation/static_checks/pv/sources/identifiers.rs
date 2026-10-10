//! Bounded declarative identifier predicates; no transport, date or target access.
use super::{Check, Finding};
pub(super) fn iscsi(value: &str, check: &Check<'_, '_>) -> Result<bool, Finding> {
    if let Some(suffix) = value.strip_prefix("eui") {
        return Ok(extended_id(suffix, 16));
    }
    if let Some(suffix) = value.strip_prefix("naa") {
        return Ok(extended_id(suffix, 32));
    }
    if !value.starts_with("iqn") {
        return Ok(false);
    }
    for (offset, _) in value.match_indices("iqn.") {
        let suffix = &value[offset + 4..];
        // Each candidate can scan its full suffix. Charge before touching it so repeated
        // source prefixes cannot turn a linear input charge into unbounded quadratic work.
        check.work(suffix.len().saturating_add(1))?;
        let bytes = suffix.as_bytes();
        if bytes.len() < 10
            || !bytes[..4].iter().all(u8::is_ascii_digit)
            || bytes[4] != b'-'
            || !bytes[5..7].iter().all(u8::is_ascii_digit)
            || bytes[7] != b'.'
        {
            continue;
        }
        let Some((domain, name)) = suffix[8..].split_once(':') else {
            continue;
        };
        if !domain.is_empty()
            && domain
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.'))
            && !name.is_empty()
            && !name.bytes().any(|byte| {
                matches!(
                    byte,
                    b',' | b';' | b'*' | b'&' | b'$' | b'|' | b' ' | b'\t' | b'\n' | b'\r' | 12
                )
            })
        {
            return Ok(true);
        }
    }
    Ok(false)
}
fn extended_id(suffix: &str, size: usize) -> bool {
    let Some(separator) = suffix.chars().next() else {
        return false;
    };
    separator != '\n'
        && suffix[separator.len_utf8()..].len() == size
        && suffix[separator.len_utf8()..]
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric())
}
/// Simple host:port structure. Bracket/Unicode/control edge cases require retained Go-parser context.
pub(super) fn host_port(value: &str) -> Option<bool> {
    if !value.is_ascii() || value.bytes().any(|byte| byte.is_ascii_control()) || value.contains(['[', ']']) {
        return None;
    }
    Some(value.bytes().filter(|byte| *byte == b':').count() == 1)
}
