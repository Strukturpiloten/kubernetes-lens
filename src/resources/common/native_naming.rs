//! Original finite naming predicates. Acquisition never normalizes these private values.
use crate::{
    capability::{DECLARED_APIS, KindId, TargetProfile},
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    generation::NativeValidationIntent,
    model::GroupVersionKind,
    processing::NativeOperationBudget,
    registry::FindingSink,
    syntax::TreeNode,
};

#[derive(Clone, Copy)]
enum Policy {
    Subdomain,
    Label,
    Service,
    Segment,
    Disruption,
    Crd,
}

// Exhaustiveness is deliberate: every admitted built-in receives a reviewed rule.
fn policy(kind: KindId, minor: u8) -> Policy {
    match kind {
        KindId::Namespace => Policy::Label,
        KindId::Service => Policy::Service,
        KindId::StatefulSet if minor >= 27 => Policy::Label,
        KindId::Role | KindId::RoleBinding | KindId::ClusterRole | KindId::ClusterRoleBinding => Policy::Segment,
        KindId::PodDisruptionBudget => Policy::Disruption,
        KindId::CustomResourceDefinition => Policy::Crd,
        KindId::Pod
        | KindId::Deployment
        | KindId::StatefulSet
        | KindId::DaemonSet
        | KindId::ReplicaSet
        | KindId::ReplicationController
        | KindId::Job
        | KindId::CronJob
        | KindId::Endpoints
        | KindId::EndpointSlice
        | KindId::Ingress
        | KindId::IngressClass
        | KindId::NetworkPolicy
        | KindId::ConfigMap
        | KindId::Secret
        | KindId::PersistentVolumeClaim
        | KindId::PersistentVolume
        | KindId::StorageClass
        | KindId::ServiceAccount
        | KindId::HorizontalPodAutoscaler
        | KindId::ResourceQuota
        | KindId::LimitRange
        | KindId::PriorityClass
        | KindId::RuntimeClass
        | KindId::PodSecurityPolicy
        | KindId::MutatingWebhookConfiguration
        | KindId::ValidatingWebhookConfiguration => Policy::Subdomain,
    }
}

/// Borrow a comparison view. The terminal native prefix operation consumes two
/// bytes; a historical one-byte dash has no safely witnessed validity outcome.
fn comparison(value: &str, prefix: bool, minor: u8) -> Result<(&str, bool), FindingCode> {
    if prefix && value.ends_with('-') {
        if value.len() == 1 {
            return if minor <= 21 {
                Err(FindingCode::NativeNamingUnverified)
            } else {
                Ok((value, false))
            };
        }
        return value
            .get(..value.len() - 2)
            .map(|head| (head, true))
            .ok_or(FindingCode::NativeFieldInvalid);
    }
    Ok((value, false))
}

fn dns(head: &str, suffix: bool, label: bool, alphabetic: bool) -> bool {
    let len = head.len().saturating_add(usize::from(suffix));
    if len == 0 || len > if label { 63 } else { 253 } {
        return false;
    }
    let mut start = true;
    let mut last_alphanumeric = false;
    for byte in head.bytes().chain(suffix.then_some(b'a')) {
        if byte == b'.' && !label {
            if !last_alphanumeric {
                return false;
            }
            start = true;
            last_alphanumeric = false;
            continue;
        }
        let alphanumeric = byte.is_ascii_lowercase() || byte.is_ascii_digit();
        if (!alphanumeric && byte != b'-') || (start && (!alphanumeric || (alphabetic && !byte.is_ascii_lowercase()))) {
            return false;
        }
        start = false;
        last_alphanumeric = alphanumeric;
    }
    last_alphanumeric
}

fn constraint(value: &str, policy: Policy, prefix: bool, minor: u8) -> Result<(), FindingCode> {
    if matches!(policy, Policy::Segment | Policy::Disruption) {
        return if !value.contains(['/', '%'])
            && (prefix && matches!(policy, Policy::Disruption) || !matches!(value, "." | ".."))
        {
            Ok(())
        } else {
            Err(FindingCode::NativeFieldInvalid)
        };
    }
    let (head, suffix) = comparison(value, prefix, minor)?;
    let label = matches!(policy, Policy::Label | Policy::Service);
    if dns(head, suffix, label, matches!(policy, Policy::Service)) {
        return Ok(());
    }
    // A native relaxed Service branch exists, but is outside frozen selection.
    if matches!(policy, Policy::Service) && minor >= 34 && dns(head, suffix, true, false) {
        return Err(FindingCode::UnadmittedField);
    }
    Err(FindingCode::NativeFieldInvalid)
}

fn member<'a>(
    node: &'a TreeNode,
    key: &str,
    budget: &NativeOperationBudget,
    phase: Phase,
) -> Result<Option<&'a TreeNode>, Finding> {
    let Some(entries) = node.as_mapping() else {
        return Ok(None);
    };
    for (name, value) in entries {
        budget.work(name.len().saturating_add(key.len()).saturating_add(1), phase)?;
        if name == key {
            return Ok(Some(value));
        }
    }
    Ok(None)
}

fn emit(
    code: FindingCode,
    field: &str,
    node: Option<&TreeNode>,
    budget: &NativeOperationBudget,
    phase: Phase,
    out: &mut dyn FindingSink,
) -> Result<(), Finding> {
    budget.payload(2 * size_of::<String>() + 8 + field.len(), phase)?;
    let path = FieldPath::default().child("metadata").child(field);
    let mut finding = if matches!(
        code,
        FindingCode::NativeContextRequired | FindingCode::NativeNamingUnverified
    ) {
        Finding::warning(code, phase)
    } else {
        Finding::error(code, phase)
    }
    .at_path(path);
    finding.source = node.and_then(|value| value.start);
    out.push(finding);
    Ok(())
}

/// Return whether selected naming is established, without claiming server admission.
/// Undeclared roots retain explicitly unverified naming; schema evidence stays separate.
pub(crate) fn validate(
    tree: &TreeNode,
    gvk: &GroupVersionKind,
    target: &TargetProfile,
    intent: NativeValidationIntent,
    budget: &NativeOperationBudget,
    phase: Phase,
    out: &mut dyn FindingSink,
) -> bool {
    if out.exhausted() {
        return false;
    }
    match check(tree, gvk, target, intent, budget, phase, out) {
        Ok(established) => established,
        Err(finding) => {
            out.push(finding);
            false
        }
    }
}

fn unavailable_api(budget: &NativeOperationBudget, phase: Phase, out: &mut dyn FindingSink) -> Result<bool, Finding> {
    // Validation already owns API findings; graph analysis must retain the same
    // fixed outcome without running naming predicates for an unavailable GVK.
    if phase == Phase::Analysis {
        budget.payload(size_of::<Finding>(), phase)?;
        out.push(Finding::error(FindingCode::UnavailableApi, phase));
    }
    Ok(false)
}

fn crd_name_matches(
    tree: &TreeNode,
    value: &str,
    budget: &NativeOperationBudget,
    phase: Phase,
) -> Result<bool, Finding> {
    let Some(spec) = member(tree, "spec", budget, phase)? else {
        return Ok(false);
    };
    let group = member(spec, "group", budget, phase)?.and_then(TreeNode::as_str);
    let plural = if let Some(names) = member(spec, "names", budget, phase)? {
        member(names, "plural", budget, phase)?.and_then(TreeNode::as_str)
    } else {
        None
    };
    let (Some(group), Some(plural)) = (group, plural) else {
        return Ok(false);
    };
    budget.work(
        value.len().saturating_add(group.len()).saturating_add(plural.len()),
        phase,
    )?;
    Ok(value.strip_suffix(group).and_then(|head| head.strip_suffix('.')) == Some(plural))
}

fn namespace_matches(
    node: Option<&TreeNode>,
    scope: crate::model::ResourceScope,
    budget: &NativeOperationBudget,
    phase: Phase,
    out: &mut dyn FindingSink,
) -> Result<bool, Finding> {
    let Some(namespace) = node.and_then(TreeNode::as_str) else {
        return Ok(true);
    };
    let code = if scope.namespaced() == Some(false) {
        Some(FindingCode::ScopeMismatch)
    } else if !crate::value::dns_label(namespace) {
        Some(FindingCode::NativeFieldInvalid)
    } else {
        None
    };
    if let Some(code) = code {
        emit(code, "namespace", node, budget, phase, out)?;
        return Ok(false);
    }
    Ok(true)
}

fn unverified_unknown_naming(
    tree: &TreeNode,
    budget: &NativeOperationBudget,
    phase: Phase,
    out: &mut dyn FindingSink,
) -> Result<bool, Finding> {
    let metadata = member(tree, "metadata", budget, phase)?;
    let name = if let Some(metadata) = metadata {
        member(metadata, "name", budget, phase)?
    } else {
        None
    };
    let prefix = if let Some(metadata) = metadata {
        member(metadata, "generateName", budget, phase)?
    } else {
        None
    };
    for node in [name, prefix].into_iter().flatten() {
        if let Some(value) = node.as_str() {
            budget.work(value.len(), phase)?;
        }
    }
    let prefix_only = name.and_then(TreeNode::as_str).is_none_or(str::is_empty)
        && prefix.and_then(TreeNode::as_str).is_some_and(|value| !value.is_empty());
    emit(
        FindingCode::NativeNamingUnverified,
        if prefix_only { "generateName" } else { "name" },
        if prefix_only { prefix } else { name },
        budget,
        phase,
        out,
    )?;
    Ok(false)
}

fn check(
    tree: &TreeNode,
    gvk: &GroupVersionKind,
    target: &TargetProfile,
    intent: NativeValidationIntent,
    budget: &NativeOperationBudget,
    phase: Phase,
    out: &mut dyn FindingSink,
) -> Result<bool, Finding> {
    budget.work(DECLARED_APIS.len(), phase)?;
    let declaration = DECLARED_APIS.iter().find(|entry| {
        let (group, version) = entry
            .api_version
            .split_once('/')
            .map_or((None, entry.api_version), |(group, version)| (Some(group), version));
        entry.kind.as_str() == gvk.kind && group == gvk.group.as_deref() && version == gvk.version
    });
    let Some(declaration) = declaration else {
        if crate::capability::builtin_scope(gvk).is_some() {
            return unavailable_api(budget, phase, out);
        }
        return unverified_unknown_naming(tree, budget, phase, out);
    };
    let minor = target.kubernetes.minor();
    if !(declaration.first..=declaration.last).contains(&minor) {
        return unavailable_api(budget, phase, out);
    }
    let selected = policy(declaration.kind, minor);
    let metadata = member(tree, "metadata", budget, phase)?;
    let Some(metadata) = metadata.filter(|metadata| metadata.as_mapping().is_some()) else {
        emit(FindingCode::NativeFieldInvalid, "name", metadata, budget, phase, out)?;
        return Ok(false);
    };
    let name_node = member(metadata, "name", budget, phase)?;
    let prefix_node = member(metadata, "generateName", budget, phase)?;
    let namespace_node = member(metadata, "namespace", budget, phase)?;
    for node in [name_node, prefix_node, namespace_node].into_iter().flatten() {
        if let Some(value) = node.as_str() {
            budget.work(value.len(), phase)?;
        }
    }
    let name = name_node.and_then(TreeNode::as_str).filter(|value| !value.is_empty());
    let prefix = prefix_node.and_then(TreeNode::as_str).filter(|value| !value.is_empty());
    let mut established = namespace_matches(namespace_node, declaration.scope, budget, phase, out)?;
    for (field, value, node, is_prefix) in [
        ("name", name, name_node, false),
        ("generateName", prefix, prefix_node, true),
    ] {
        if out.exhausted() {
            return Ok(false);
        }
        let Some(value) = value else {
            continue;
        };
        let skip_prefix = is_prefix && declaration.kind == KindId::ReplicationController && minor >= 35;
        if let Err(code) = if skip_prefix {
            Ok(())
        } else {
            constraint(value, selected, is_prefix, minor)
        } {
            emit(code, field, node, budget, phase, out)?;
            established = false;
        }
        if matches!(selected, Policy::Crd) && !crd_name_matches(tree, value, budget, phase)? {
            emit(FindingCode::NativeFieldInvalid, field, node, budget, phase, out)?;
            established = false;
        }
    }
    if name.is_none() {
        emit(
            if prefix.is_some() {
                FindingCode::NativeContextRequired
            } else {
                FindingCode::NativeFieldInvalid
            },
            if prefix.is_some() { "generateName" } else { "name" },
            prefix_node.or(name_node),
            budget,
            phase,
            out,
        )?;
        established = false;
    }
    if declaration.kind == KindId::CronJob && name.is_some_and(|name| name.len() > 52) {
        emit(
            if intent == NativeValidationIntent::Create {
                FindingCode::NativeFieldInvalid
            } else {
                FindingCode::NativeContextRequired
            },
            "name",
            name_node,
            budget,
            phase,
            out,
        )?;
        established = false;
    }
    Ok(established)
}

// Preserve earlier output eligibility separately from native validation. These
// borrowed lexical views never rewrite a retained or generated prefix.
fn previously_public_prefix(value: &str, gvk: &GroupVersionKind) -> bool {
    if value.is_empty() || value.len() > 253 {
        return false;
    }
    if gvk.group.is_none() && gvk.version == "v1" && gvk.kind == "Service" {
        if value.len() > 1 && value.ends_with('-') {
            return value.get(..value.len() - 2).is_some_and(|head| {
                head.bytes()
                    .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                    && head.as_bytes().first().is_none_or(u8::is_ascii_alphanumeric)
            });
        }
        return crate::value::dns_subdomain(value);
    }
    crate::value::dns_subdomain(value.trim_end_matches('-'))
}

/// Broader source spelling does not create an automatic private-output channel.
pub(crate) fn private_names(
    tree: &TreeNode,
    gvk: &GroupVersionKind,
    budget: &NativeOperationBudget,
    phase: Phase,
) -> Result<bool, Finding> {
    let Some(metadata) = member(tree, "metadata", budget, phase)? else {
        return Ok(false);
    };
    for field in ["name", "generateName", "namespace"] {
        if let Some(value) = member(metadata, field, budget, phase)?.and_then(TreeNode::as_str) {
            budget.work(value.len().saturating_mul(2), phase)?;
            let public = if field == "generateName" {
                previously_public_prefix(value, gvk)
            } else {
                crate::value::dns_subdomain(value)
            };
            if !public {
                return Ok(true);
            }
        }
    }
    if let Some(owners) = member(metadata, "ownerReferences", budget, phase)?.and_then(TreeNode::as_sequence) {
        for owner in owners {
            budget.work(1, phase)?;
            if let Some(value) = member(owner, "name", budget, phase)?.and_then(TreeNode::as_str) {
                budget.work(value.len(), phase)?;
                if !crate::value::dns_subdomain(value) {
                    return Ok(true);
                }
            }
        }
    }
    Ok(false)
}
