//! Original five-field robfig v3 dialect validation, independent of host timezone state.
use crate::{
    capability::TargetProfile,
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    generation::NativeValidationIntent,
    registry::FindingSink,
};
fn invalid(path: &FieldPath, out: &mut dyn FindingSink) {
    out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
}
/// Validate complete inline-zone and body syntax before any operation-dependent
/// restriction. Unspecified intent never asserts historical-update conformance.
pub(super) fn validate_schedule(
    schedule: &str,
    zone: Option<&str>,
    target: &TargetProfile,
    intent: NativeValidationIntent,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    let mut body = schedule;
    let inline = body.starts_with("TZ=") || body.starts_with("CRON_TZ=");
    let mut inline_valid = true;
    if inline {
        let Some((prefix, rest)) = body.split_once(char::is_whitespace) else {
            invalid(path, out);
            return;
        };
        let zone = prefix.split_once('=').map_or("", |(_, zone)| zone);
        inline_valid = validate_zone(zone, path, out);
        body = rest.trim_start();
    }
    if !valid_body(body) {
        invalid(path, out);
        return;
    }
    if !inline_valid {
        return;
    }
    if inline && target.kubernetes.minor() >= 27 && zone.is_some() {
        invalid(path, out);
    } else if inline && target.kubernetes.minor() >= 37 {
        match intent {
            NativeValidationIntent::Create => invalid(path, out),
            NativeValidationIntent::Unspecified => {
                out.push(Finding::warning(FindingCode::NativeContextRequired, Phase::Validation).at_path(path.clone()));
            }
        }
    }
}
fn valid_body(body: &str) -> bool {
    if let Some(descriptor) = body.strip_prefix('@') {
        return ["yearly", "annually", "monthly", "weekly", "daily", "midnight", "hourly"].contains(&descriptor)
            || descriptor.strip_prefix("every ").is_some_and(valid_duration);
    }
    let fields = body.split_whitespace().collect::<Vec<_>>();
    let limits = [(0, 59), (0, 23), (1, 31), (1, 12), (0, 6)];
    fields.len() == 5
        && fields
            .iter()
            .zip(limits)
            .enumerate()
            .all(|(index, (field, (low, high)))| valid_field(field, low, high, index))
}

fn value(token: &str, field: usize) -> Option<u32> {
    if !token.is_empty() && token.bytes().all(|b| b.is_ascii_digit()) {
        return token.parse().ok();
    }
    let names = match field {
        3 => &[
            "JAN", "FEB", "MAR", "APR", "MAY", "JUN", "JUL", "AUG", "SEP", "OCT", "NOV", "DEC",
        ][..],
        4 => &["SUN", "MON", "TUE", "WED", "THU", "FRI", "SAT"][..],
        _ => &[],
    };
    names
        .iter()
        .position(|name| token.eq_ignore_ascii_case(name))
        .and_then(|i| u32::try_from(i).ok())
        .map(|i| if field == 3 { i + 1 } else { i })
}
fn valid_field(field: &str, low: u32, high: u32, index: usize) -> bool {
    field.split(',').all(|part| {
        let (range, step) = part.split_once('/').map_or((part, None), |(a, b)| (a, Some(b)));
        if step.is_some_and(|s| {
            s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) || s.parse::<u64>().ok().is_none_or(|n| n == 0)
        }) {
            return false;
        }
        if matches!(range, "*" | "?") {
            return true;
        }
        if let Some((a, b)) = range.split_once('-') {
            matches!((value(a,index),value(b,index)),(Some(a),Some(b)) if a>=low&&b<=high&&a<=b)
        } else {
            value(range, index).is_some_and(|n| n >= low && n <= high)
        }
    })
}
fn valid_duration(duration: &str) -> bool {
    let bytes = duration.as_bytes();
    let mut i = 0;
    let negative = bytes.first() == Some(&b'-');
    if matches!(bytes.first(), Some(b'+' | b'-')) {
        i = 1;
    }
    if duration.get(i..) == Some("0") {
        return true;
    }
    let limit = if negative {
        i64::MAX as u128 + 1
    } else {
        i64::MAX as u128
    };
    let mut total = 0_u128;
    let mut component = false;
    while i < bytes.len() {
        let start = i;
        while bytes.get(i).is_some_and(u8::is_ascii_digit) {
            i += 1;
        }
        let whole = &duration[start..i];
        let mut fraction = "";
        if bytes.get(i) == Some(&b'.') {
            i += 1;
            let first = i;
            while bytes.get(i).is_some_and(u8::is_ascii_digit) {
                i += 1;
            }
            fraction = &duration[first..i];
        }
        if whole.is_empty() && fraction.is_empty() {
            return false;
        }
        let Some(rest) = duration.get(i..) else {
            return false;
        };
        let units = [
            ("ns", 1_u128),
            ("us", 1_000),
            ("µs", 1_000),
            ("μs", 1_000),
            ("ms", 1_000_000),
            ("s", 1_000_000_000),
            ("m", 60_000_000_000),
            ("h", 3_600_000_000_000),
        ];
        let Some((unit, scale)) = units.iter().find(|(name, _)| rest.starts_with(name)) else {
            return false;
        };
        let integer = if whole.is_empty() {
            0
        } else {
            let Ok(n) = whole.parse::<u128>() else {
                return false;
            };
            n
        };
        let Some(mut amount) = integer.checked_mul(*scale) else {
            return false;
        };
        if amount > limit {
            return false;
        }
        if !fraction.is_empty() {
            let head = &fraction[..fraction.len().min(18)];
            let Ok(n) = head.parse::<u128>() else {
                return false;
            };
            let divisor = 10_u128.pow(u32::try_from(head.len()).unwrap_or(18));
            amount += n * scale / divisor;
        }
        let Some(sum) = total.checked_add(amount) else {
            return false;
        };
        if sum > limit {
            return false;
        }
        total = sum;
        i += unit.len();
        component = true;
    }
    component
}
pub(super) fn validate_zone(zone: &str, path: &FieldPath, out: &mut dyn FindingSink) -> bool {
    let lexical = !zone.is_empty()
        && !zone.eq_ignore_ascii_case("Local")
        && zone.split('/').all(|part| {
            !part.is_empty()
                && part.len() <= 14
                && part != "."
                && part != ".."
                && !part.starts_with('-')
                && part
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'+' | b'-'))
        });
    if !lexical {
        invalid(path, out);
        return false;
    }
    if !jiff_tzdb::available().any(|name| name == zone) {
        out.push(Finding::error(FindingCode::UnadmittedField, Phase::Validation).at_path(path.clone()));
        return false;
    }
    true
}
