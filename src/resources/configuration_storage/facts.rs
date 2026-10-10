//! Supplied key names, never protected payloads or inferred storage behavior.
use crate::{
    diagnostic::{FieldPath, Finding, Phase},
    graph::{FactGap, FactState, KeyDomain, KeyNames, NativeFact},
    registry::ProjectionContext,
};
use std::collections::BTreeMap;

fn map_keys(
    ctx: &ProjectionContext<'_>,
    field: &str,
    names: &mut BTreeMap<String, FieldPath>,
    overlay: bool,
) -> Result<bool, Finding> {
    let fields = &ctx.fields;
    let parent = crate::resources::common::child_path(&FieldPath::default(), field, fields)?;
    if !matches!(ctx.state(&parent, FactState::Known(())), FactState::Known(())) {
        return Ok(false);
    }
    let Some(node) = ctx.tree.get(field) else {
        return Ok(true);
    };
    let Some(entries) = node.as_mapping() else {
        return Ok(false);
    };
    for (key, value) in entries {
        fields.processing.work(key.len().saturating_add(1), Phase::Analysis)?;
        let levels = names.len().saturating_add(1).ilog2() as usize + 1;
        fields.processing.work(
            key.len().saturating_add(1).saturating_mul(levels).saturating_mul(32),
            Phase::Analysis,
        )?;
        if key.is_empty()
            || key.len() > 253
            || !key
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            || value.as_str().is_none()
            || (!overlay && names.contains_key(key))
        {
            return Ok(false);
        }
        let path = crate::resources::common::child_path(&parent, key, fields)?;
        if !matches!(ctx.state(&path, FactState::Known(())), FactState::Known(())) {
            return Ok(false);
        }
        fields
            .processing
            .payload_array::<(String, FieldPath)>(1, Phase::Analysis)?;
        fields.processing.payload(key.len(), Phase::Analysis)?;
        names.insert(key.clone(), path);
    }
    Ok(true)
}
fn keys(ctx: &ProjectionContext<'_>, domain: KeyDomain, fields: &[&str]) -> Result<FactState<KeyNames>, Finding> {
    let mut names = BTreeMap::new();
    for field in fields {
        if !map_keys(ctx, field, &mut names, domain == KeyDomain::Secret)? {
            return Ok(FactState::Unknown(FactGap::IncompleteSuppliedEvidence));
        }
    }
    Ok(FactState::Known(KeyNames(names)))
}
fn emit_keys(ctx: &ProjectionContext<'_>, domain: KeyDomain, state: FactState<KeyNames>, out: &mut Vec<NativeFact>) {
    ctx.emit_fact(
        NativeFact::Keys {
            domain,
            state,
            path: FieldPath::default(),
        },
        out,
    );
}
pub(super) fn collect<T: super::validation::StaticChecks>(
    kind: &str,
    resource: &T,
    ctx: &ProjectionContext<'_>,
    out: &mut Vec<NativeFact>,
) {
    if !matches!(kind, "ConfigMap" | "Secret") {
        return;
    }
    let Some(target) = ctx.target else { return };
    let validation = crate::registry::ValidationContext {
        target,
        intent: crate::generation::NativeValidationIntent::Unspecified,
        fields: ctx.fields.clone(),
    };
    let mut report = crate::processing::ProcessingReport::new(ctx.fields.processing.clone(), Phase::Analysis);
    if let Err(finding) = resource.check(&validation, &mut report) {
        report.push(finding);
    }
    if report.failed() {
        return;
    }
    if !report.into_vec().is_empty() {
        let domains: &[KeyDomain] = if kind == "ConfigMap" {
            &[KeyDomain::ConfigMapText, KeyDomain::ConfigMapTextOrBinary]
        } else {
            &[KeyDomain::Secret]
        };
        for domain in domains {
            emit_keys(
                ctx,
                *domain,
                FactState::Unknown(FactGap::IncompleteSuppliedEvidence),
                out,
            );
        }
        return;
    }
    match kind {
        "ConfigMap" => {
            // Validate the disjoint union before claiming either supplier domain.
            let Ok(union) = keys(ctx, KeyDomain::ConfigMapTextOrBinary, &["data", "binaryData"]) else {
                return;
            };
            let text = if matches!(union, FactState::Known(_)) {
                let Ok(text) = keys(ctx, KeyDomain::ConfigMapText, &["data"]) else {
                    return;
                };
                text
            } else {
                FactState::Unknown(FactGap::IncompleteSuppliedEvidence)
            };
            emit_keys(ctx, KeyDomain::ConfigMapText, text, out);
            emit_keys(ctx, KeyDomain::ConfigMapTextOrBinary, union, out);
        }
        "Secret" => {
            let Ok(state) = keys(ctx, KeyDomain::Secret, &["data", "stringData"]) else {
                return;
            };
            emit_keys(ctx, KeyDomain::Secret, state, out);
        }
        _ => (),
    }
}
