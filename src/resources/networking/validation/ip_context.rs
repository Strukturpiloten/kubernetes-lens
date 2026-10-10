//! Bounded IP syntax checks with explicit gaps for unrepresented native parsing context.
use super::{Cidr, FieldPath, Finding, FindingCode, FindingSink, IpAddr, Phase, ValidationContext, invalid, scratch};
use std::net::Ipv4Addr;

pub(super) fn context(path: &FieldPath, out: &mut dyn FindingSink) {
    if !out.exhausted() {
        out.push(Finding::warning(FindingCode::NativeContextRequired, Phase::Validation).at_path(path.clone()));
    }
}
pub(super) fn decimal_ipv4(value: &str) -> Option<IpAddr> {
    let mut bytes = [0; 4];
    let mut parts = value.split('.');
    for byte in &mut bytes {
        let part = parts.next()?;
        if part.is_empty() || part.len() > 3 || !part.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        *byte = part.parse().ok()?;
    }
    parts.next().is_none().then_some(IpAddr::V4(Ipv4Addr::from(bytes)))
}
pub(super) fn ip(
    value: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) -> Option<IpAddr> {
    if out.exhausted() {
        return None;
    }
    if ctx.fields.processing.exhausted() {
        out.push(ctx.fields.processing.fail(Phase::Validation));
        return None;
    }
    let parsed = value.parse::<IpAddr>().ok();
    let Some(parsed) = parsed else {
        if let Some(parsed) = decimal_ipv4(value) {
            // Native sloppy parsing and the strict gate are not representable by this target.
            context(path, out);
            return Some(parsed);
        }
        if value.contains(['.', ':'])
            && value
                .bytes()
                .all(|byte| byte.is_ascii_hexdigit() || matches!(byte, b'.' | b':'))
        {
            // The retained witnesses do not establish an exhaustive native sloppy parser.
            context(path, out);
        } else {
            invalid(path, out);
        }
        return None;
    };
    if ctx.target.kubernetes.minor() >= 33 {
        if !scratch(ctx, out, 64) {
            return None;
        }
        if parsed.to_string() != value {
            context(path, out);
        }
    }
    if let IpAddr::V6(address) = parsed {
        if address.to_ipv4_mapped().is_some() {
            context(path, out);
            // No positive family/geometry authority from an unrepresented native parser variant.
            return None;
        }
    }
    Some(parsed)
}
pub(super) fn usable_ip(ip: IpAddr) -> bool {
    !ip.is_loopback()
        && !ip.is_unspecified()
        && match ip {
            IpAddr::V4(ip) => !ip.is_link_local() && ip.octets()[..3] != [224, 0, 0],
            IpAddr::V6(ip) => !ip.is_unicast_link_local() && (ip.segments()[0] & 0xff0f != 0xff02),
        }
}
pub(super) fn checked_cidr(
    value: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) -> Option<Cidr> {
    let Some((address, prefix)) = value.split_once('/') else {
        invalid(path, out);
        return None;
    };
    let address = ip(address, ctx, path, out)?;
    let Some(prefix_number) = prefix
        .parse::<u8>()
        .ok()
        .filter(|prefix| *prefix <= if address.is_ipv4() { 32 } else { 128 })
    else {
        invalid(path, out);
        return None;
    };
    let network = match address {
        IpAddr::V4(ip) => {
            u32::from(ip)
                & if prefix_number == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix_number)
                }
                == u32::from(ip)
        }
        IpAddr::V6(ip) => {
            u128::from(ip)
                & if prefix_number == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix_number)
                }
                == u128::from(ip)
        }
    };
    if !scratch(ctx, out, 3) {
        return None;
    }
    if prefix != prefix_number.to_string() || (ctx.target.kubernetes.minor() >= 33 && !network) {
        context(path, out);
    }
    Some(Cidr {
        address,
        prefix: prefix_number,
    })
}
