//! Original finite static checks; no server, controller or credential operations.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    generation::NativeValidationIntent,
    registry::{FindingSink, ValidationContext},
    resources::configuration_storage::roots::{
        ConfigMap, PersistentVolume, PersistentVolumeClaim, Secret, StorageClass,
    },
    value::NativeBytes,
};
use std::collections::{BTreeMap, BTreeSet};
mod pv;

pub(crate) trait StaticChecks {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding>;
}
struct Check<'a, 'b> {
    ctx: &'a ValidationContext<'a>,
    out: &'b mut dyn FindingSink,
}
impl Check<'_, '_> {
    fn work(&self, units: usize) -> Result<(), Finding> {
        if self.out.exhausted() {
            return Err(self.ctx.fields.processing.fail(Phase::Validation));
        }
        self.ctx.fields.processing.work(units, Phase::Validation)
    }
    fn text(&self, value: &str) -> Result<(), Finding> {
        self.work(value.len().saturating_add(1))
    }
    fn lookup(&self, key: &str, members: usize) -> Result<(), Finding> {
        let levels = members.saturating_add(1).ilog2() as usize + 1;
        self.work(key.len().saturating_add(1).saturating_mul(levels).saturating_mul(32))
    }
    fn payload(&self, bytes: usize) -> Result<(), Finding> {
        if self.out.exhausted() {
            return Err(self.ctx.fields.processing.fail(Phase::Validation));
        }
        self.ctx.fields.processing.payload(bytes, Phase::Validation)
    }
    fn path(&self, parts: &[&str]) -> Result<FieldPath, Finding> {
        let mut path = FieldPath::default();
        for part in parts {
            path = crate::resources::common::child_path(&path, part, &self.ctx.fields)?;
        }
        Ok(path)
    }
    fn invalid(&mut self, parts: &[&str]) -> Result<(), Finding> {
        if !self.out.exhausted() {
            self.out
                .push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(self.path(parts)?));
        }
        Ok(())
    }
    fn add(&self, total: &mut usize, bytes: usize) -> Result<(), Finding> {
        self.work(bytes.saturating_add(1))?;
        *total = total
            .checked_add(bytes)
            .ok_or_else(|| self.ctx.fields.processing.fail(Phase::Validation))?;
        Ok(())
    }
    fn key(&mut self, field: &str, key: &str) -> Result<(), Finding> {
        self.text(key)?;
        if key.is_empty()
            || key.len() > 253
            || !key
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
        {
            self.invalid(&[field, key])?;
        }
        Ok(())
    }
}
impl StaticChecks for ConfigMap {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding> {
        let mut check = Check { ctx, out };
        let mut total = 0;
        if let Some(data) = self.data.value() {
            for (key, value) in data {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.key("data", key)?;
                check.add(&mut total, value.native_value().len())?;
                // Bound the borrowed-map lookup without retaining duplicate value maps.
                check.lookup(key, self.binary_data.value().map_or(0, BTreeMap::len))?;
                if self.binary_data.value().is_some_and(|map| map.contains_key(key)) {
                    check.invalid(&["data", key])?;
                }
            }
        }
        if let Some(data) = self.binary_data.value() {
            for (key, value) in data {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.key("binaryData", key)?;
                check.add(&mut total, value.native_bytes().len())?;
            }
        }
        if total > 1_048_576 {
            check.invalid(&[])?;
        }
        Ok(())
    }
}
impl Secret {
    fn effective_value(&self, key: &str) -> Option<&[u8]> {
        self.string_data
            .value()
            .and_then(|map| map.get(key))
            .map(|value| value.native_value().as_bytes())
            .or_else(|| {
                self.data
                    .value()
                    .and_then(|map| map.get(key))
                    .map(NativeBytes::native_bytes)
            })
    }
}
impl StaticChecks for Secret {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding> {
        let mut check = Check { ctx, out };
        let mut total = 0;
        if let Some(data) = self.data.value() {
            for (key, value) in data {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.text(key)?;
                check.lookup(key, self.string_data.value().map_or(0, BTreeMap::len))?;
                if self.string_data.value().is_some_and(|map| map.contains_key(key)) {
                    continue;
                }
                check.key("data", key)?;
                check.add(&mut total, value.native_bytes().len())?;
            }
        }
        if let Some(data) = self.string_data.value() {
            for (key, value) in data {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.key("stringData", key)?;
                check.add(&mut total, value.native_value().len())?;
            }
        }
        if total > 1_048_576 {
            check.invalid(&["data"])?;
        }
        if check.out.exhausted() {
            return Ok(());
        }
        let kind = self.r#type.value().map_or("", String::as_str);
        check.text(kind)?;
        // At most four effective-map lookups, each with a key shorter than this marker.
        for _ in 0..4 {
            check.lookup(
                "kubernetes.io/service-account.name",
                self.data.value().map_or(0, BTreeMap::len),
            )?;
            check.lookup(
                "kubernetes.io/service-account.name",
                self.string_data.value().map_or(0, BTreeMap::len),
            )?;
        }
        match kind {
            "kubernetes.io/service-account-token" => {
                check.lookup(
                    "kubernetes.io/service-account.name",
                    self.metadata
                        .value()
                        .and_then(|metadata| metadata.annotations.value())
                        .map_or(0, BTreeMap::len),
                )?;
                let annotated = self
                    .metadata
                    .value()
                    .and_then(|metadata| metadata.annotations.value())
                    .and_then(|map| map.get("kubernetes.io/service-account.name"));
                if annotated.is_none_or(String::is_empty) {
                    check.invalid(&["metadata", "annotations", "kubernetes.io/service-account.name"])?;
                }
            }
            "kubernetes.io/basic-auth" => {
                if self.effective_value("username").is_none() && self.effective_value("password").is_none() {
                    check.invalid(&["data"])?;
                }
            }
            "kubernetes.io/ssh-auth" => {
                if self.effective_value("ssh-privatekey").is_none_or(<[u8]>::is_empty) {
                    check.invalid(&["data", "ssh-privatekey"])?;
                }
            }
            "kubernetes.io/tls" => {
                for key in ["tls.crt", "tls.key"] {
                    if self.effective_value(key).is_none() {
                        check.invalid(&["data", key])?;
                    }
                }
            }
            "kubernetes.io/dockercfg" => {
                validate_private_map(self.effective_value(".dockercfg"), ".dockercfg", &mut check)?;
            }
            "kubernetes.io/dockerconfigjson" => validate_private_map(
                self.effective_value(".dockerconfigjson"),
                ".dockerconfigjson",
                &mut check,
            )?,
            _ => (),
        }
        Ok(())
    }
}
fn validate_private_map(value: Option<&[u8]>, key: &str, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let Some(bytes) = value else {
        return check.invalid(&["data", key]);
    };
    check.work(bytes.len().saturating_mul(8))?;
    // Conservative scratch bound before the private decoder can allocate any values.
    let scratch = bytes
        .len()
        .checked_mul(128)
        .ok_or_else(|| check.ctx.fields.processing.fail(Phase::Validation))?;
    check.payload(scratch)?;
    let valid =
        serde_json::from_slice::<serde_json::Value>(bytes).is_ok_and(|value| value.is_object() || value.is_null());
    if !valid {
        check.invalid(&["data", key])?;
    }
    Ok(())
}
// Kubernetes DNS-subdomain envelope: total bound, without a separate per-label length cap.
fn class_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.split('.').all(|part| {
            !part.is_empty()
                && part
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                && part.as_bytes().first().is_some_and(u8::is_ascii_alphanumeric)
                && part.as_bytes().last().is_some_and(u8::is_ascii_alphanumeric)
        })
}
impl StaticChecks for PersistentVolumeClaim {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding> {
        let mut check = Check { ctx, out };
        check.work(1)?;
        if ctx.intent != NativeValidationIntent::Create {
            if !check.out.exhausted() {
                check.out.push(
                    Finding::warning(FindingCode::NativeContextRequired, Phase::Validation)
                        .at_path(check.path(&["spec"])?),
                );
            }
            return Ok(());
        }
        let Some(spec) = self.spec.value() else {
            return check.invalid(&["spec"]);
        };
        if spec
            .access_modes
            .value()
            .is_none_or(crate::value::AccessModes::is_empty)
        {
            check.invalid(&["spec", "accessModes"])?;
        }
        let quantity = spec
            .resources
            .value()
            .and_then(|resources| resources.requests.value())
            .and_then(|map| map.get("storage"));
        if quantity.is_none_or(|quantity| quantity.exact().is_negative() || quantity.exact().is_zero()) {
            check.invalid(&["spec", "resources", "requests", "storage"])?;
        }
        if let Some(class) = spec.storage_class_name.value() {
            check.text(class)?;
            if !class.is_empty() && !class_name(class) {
                check.invalid(&["spec", "storageClassName"])?;
            }
        }
        if let Some(selector) = spec.selector.value() {
            if let Some(labels) = selector.match_labels.value() {
                for (key, value) in labels {
                    check.text(key)?;
                    check.text(value)?;
                }
            }
            if let Some(expressions) = selector.match_expressions.value() {
                for item in expressions {
                    check.text(&item.key)?;
                    if let Some(values) = item.values.value() {
                        for value in values {
                            check.text(value)?;
                        }
                    }
                }
            }
            if let Err(finding) = selector.validate() {
                check.out.push(finding.at_path(check.path(&["spec", "selector"])?));
            }
        }
        if let Some(source) = spec.data_source.value() {
            check.work(1)?;
            for (field, value) in [("name", source.name.value()), ("kind", source.kind.value())] {
                if value.is_none_or(String::is_empty) {
                    check.invalid(&["spec", "dataSource", field])?;
                }
                if let Some(value) = value {
                    check.text(value)?;
                }
            }
            match source.api_group.value().filter(|value| !value.is_empty()) {
                None if source.kind.value().is_some_and(|kind| kind != "PersistentVolumeClaim") => {
                    check.invalid(&["spec", "dataSource", "kind"])?;
                }
                Some(group) => {
                    check.text(group)?;
                    if ctx.target.kubernetes.minor() >= 29 && !class_name(group) {
                        check.invalid(&["spec", "dataSource", "apiGroup"])?;
                    }
                }
                _ => (),
            }
        }
        Ok(())
    }
}
impl StaticChecks for PersistentVolume {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding> {
        pv::check(self, ctx, out)
    }
}
impl StaticChecks for StorageClass {
    fn check(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) -> Result<(), Finding> {
        let mut check = Check { ctx, out };
        if let Some(provisioner) = self.provisioner.value() {
            check.text(provisioner)?;
            check.payload(provisioner.len())?;
            if !crate::value::label_key(&provisioner.to_ascii_lowercase()) {
                check.invalid(&["provisioner"])?;
            }
        }
        if let Some(parameters) = self.parameters.value() {
            if parameters.len() > 512 {
                check.invalid(&["parameters"])?;
            }
            let mut bytes = 0;
            for (key, value) in parameters {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.add(&mut bytes, key.len())?;
                check.add(&mut bytes, value.len())?;
                if key.is_empty() {
                    check.invalid(&["parameters", key])?;
                }
            }
            if bytes > 262_144 {
                check.invalid(&["parameters"])?;
            }
        }
        topologies(self, &mut check)
    }
}
fn topologies(class: &StorageClass, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let Some(terms) = class.allowed_topologies.value() else {
        return Ok(());
    };
    let mut signatures = BTreeSet::new();
    for (index, term) in terms.iter().enumerate() {
        if check.out.exhausted() {
            return Ok(());
        }
        check.work(1)?;
        check.payload(20)?;
        let index = index.to_string();
        let Some(expressions) = term.match_label_expressions.value().filter(|items| !items.is_empty()) else {
            check.invalid(&["allowedTopologies", &index])?;
            continue;
        };
        let mut keys = BTreeMap::new();
        let mut bytes: usize = 0;
        let mut valid = true;
        for expression in expressions {
            if check.out.exhausted() {
                return Ok(());
            }
            let Some(key) = expression.key.value() else {
                check.invalid(&["allowedTopologies", &index, "matchLabelExpressions"])?;
                valid = false;
                continue;
            };
            check.add(&mut bytes, key.len())?;
            if !crate::value::label_key(key) {
                check.invalid(&["allowedTopologies", &index, "matchLabelExpressions"])?;
                valid = false;
            }
            let mut values = BTreeSet::new();
            let Some(items) = expression.values.value().filter(|items| !items.is_empty()) else {
                check.invalid(&["allowedTopologies", &index, "matchLabelExpressions"])?;
                valid = false;
                continue;
            };
            for value in items {
                if check.out.exhausted() {
                    return Ok(());
                }
                check.add(&mut bytes, value.len())?;
                check.payload(size_of::<[usize; 8]>())?;
                check.lookup(value, values.len())?;
                if !values.insert(value.as_str()) {
                    check.invalid(&["allowedTopologies", &index, "matchLabelExpressions"])?;
                    valid = false;
                }
            }
            check.payload(size_of::<[usize; 8]>())?;
            check.lookup(key, keys.len())?;
            if keys.insert(key.as_str(), values).is_some() {
                check.invalid(&["allowedTopologies", &index, "matchLabelExpressions"])?;
                valid = false;
            }
        }
        if valid {
            check.payload(
                bytes
                    .checked_add(expressions.len().saturating_mul(64))
                    .ok_or_else(|| check.ctx.fields.processing.fail(Phase::Validation))?,
            )?;
            let signature: Vec<_> = keys
                .into_iter()
                .map(|(key, values)| (key, values.into_iter().collect::<Vec<_>>()))
                .collect();
            let levels = (signatures.len() + 1).ilog2() as usize + 1;
            check.work(
                bytes
                    .checked_mul(levels.saturating_mul(32))
                    .ok_or_else(|| check.ctx.fields.processing.fail(Phase::Validation))?,
            )?;
            if !signatures.insert(signature) {
                check.invalid(&["allowedTopologies", &index])?;
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
