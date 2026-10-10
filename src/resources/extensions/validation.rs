//! Bounded local checks and explicit-reference extraction for extension roots.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase, ResourceId},
    graph::{ExternalRefKind, Reference, ReferenceScope, ReferenceSink, ReferenceTarget, RelationshipKind},
    registry::{EncodeContext, FindingSink, ValidationContext},
    syntax::{TreeNode, TreeValue},
    value::Presence,
};

fn invalid(path: &FieldPath, out: &mut dyn FindingSink) {
    if !out.exhausted() {
        out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
    }
}
fn object(node: &TreeNode) -> Option<&[(String, TreeNode)]> {
    node.as_mapping()
}
fn sequence(node: &TreeNode) -> Option<&[TreeNode]> {
    node.as_sequence()
}
fn string<'a>(node: &'a TreeNode, key: &str) -> Option<&'a str> {
    node.get(key).and_then(TreeNode::as_str)
}
fn int(node: &TreeNode, key: &str) -> Option<i64> {
    match node.get(key).map(|n| &n.value) {
        Some(TreeValue::Number(value)) => value.parse().ok(),
        _ => None,
    }
}
fn present(node: &TreeNode, key: &str) -> bool {
    node.get(key).is_some_and(|item| !matches!(item.value, TreeValue::Null))
}
fn one_of(node: &TreeNode, keys: &[&str], path: &FieldPath, out: &mut dyn FindingSink) {
    if !out.exhausted() && keys.iter().filter(|key| present(node, key)).count() != 1 {
        invalid(path, out);
    }
}

/// Keep only explicitly named webhook endpoint prerequisites; never infer certificates or callbacks.
pub(super) fn references(api: &str, kind: &str, tree: &TreeNode, ctx: &EncodeContext<'_>, out: &mut dyn ReferenceSink) {
    if kind == "CustomResourceDefinition" {
        if ctx.budget.processing().work(1, ctx.budget.phase()).is_err() {
            return;
        }
        let Some(conversion) = tree.get("spec").and_then(|spec| spec.get("conversion")) else {
            return;
        };
        if string(conversion, "strategy") != Some("Webhook") {
            return;
        }
        let (client, base) = if api == "apiextensions.k8s.io/v1beta1" {
            (
                conversion.get("webhookClientConfig"),
                FieldPath::default()
                    .child("spec")
                    .child("conversion")
                    .child("webhookClientConfig"),
            )
        } else {
            let base = FieldPath::default()
                .child("spec")
                .child("conversion")
                .child("webhook")
                .child("clientConfig");
            (
                conversion
                    .get("webhook")
                    .and_then(|webhook| webhook.get("clientConfig")),
                base,
            )
        };
        if let Some(client) = client {
            client_config_reference(client, &base, ResourceId(0), ctx, out);
        }
        return;
    }
    if !kind.ends_with("WebhookConfiguration") {
        return;
    }
    let Some(webhooks) = tree.get("webhooks").and_then(sequence) else {
        return;
    };
    for (index, webhook) in webhooks.iter().enumerate() {
        if out.exhausted() || ctx.budget.processing().work(1, ctx.budget.phase()).is_err() {
            return;
        }
        let Some(webhooks_path) = path_child(ctx, &FieldPath::default(), "webhooks") else {
            return;
        };
        let Some(index_path) = path_child(ctx, &webhooks_path, &index.to_string()) else {
            return;
        };
        let Some(base) = path_child(ctx, &index_path, "clientConfig") else {
            return;
        };
        let Some(config) = webhook.get("clientConfig") else {
            continue;
        };
        client_config_reference(config, &base, ResourceId(0), ctx, out);
    }
}

fn client_config_reference(
    config: &TreeNode,
    base: &FieldPath,
    from: ResourceId,
    ctx: &EncodeContext<'_>,
    out: &mut dyn ReferenceSink,
) {
    if out.exhausted() {
        return;
    }
    // Match the validation union's presence semantics: an explicit null Service
    // does not suppress an explicitly supplied remote URL prerequisite.
    if let Some(service) = config
        .get("service")
        .filter(|service| !matches!(service.value, TreeValue::Null))
    {
        let Some(name) = string(service, "name") else {
            return;
        };
        let Some(service_path) = path_child(ctx, base, "service") else {
            return;
        };
        let Some(reference_path) = path_child(ctx, &service_path, "name") else {
            return;
        };
        if ctx.budget.processing().payload(name.len(), ctx.budget.phase()).is_err()
            || ctx
                .budget
                .processing()
                .payload_array::<Reference>(1, ctx.budget.phase())
                .is_err()
        {
            return;
        }
        let Ok(gvk) = crate::model::GroupVersionKind::new("v1", "Service") else {
            return;
        };
        let scope = match string(service, "namespace") {
            Some(namespace) => {
                if ctx
                    .budget
                    .processing()
                    .payload(namespace.len(), ctx.budget.phase())
                    .is_err()
                {
                    return;
                }
                ReferenceScope::Namespace(Presence::Value(namespace.to_owned()))
            }
            None => ReferenceScope::Unknown,
        };
        out.push(Reference {
            from,
            path: reference_path,
            relation: RelationshipKind::Dependency,
            target: ReferenceTarget::CheckedObject {
                gvk,
                name: name.to_owned(),
                predicate: None,
                optional: Presence::Absent,
            },
            scope,
        });
    } else if present(config, "url") {
        let Some(reference_path) = path_child(ctx, base, "url") else {
            return;
        };
        if ctx
            .budget
            .processing()
            .payload_array::<Reference>(1, ctx.budget.phase())
            .is_err()
        {
            return;
        }
        out.push(Reference {
            from,
            path: reference_path,
            relation: RelationshipKind::Dependency,
            target: ReferenceTarget::External {
                kind: ExternalRefKind::Remote,
            },
            scope: ReferenceScope::Unknown,
        });
    }
}

// Reference extraction still needs owned child paths independently of the
// borrowed scratch traversal used for private payload discovery below.
fn path_child(ctx: &EncodeContext<'_>, path: &FieldPath, key: &str) -> Option<FieldPath> {
    let processing = ctx.budget.processing();
    let phase = ctx.budget.phase();
    let depth = path.0.len().checked_add(1)?;
    let bytes = path
        .0
        .iter()
        .try_fold(key.len(), |total, part| total.checked_add(part.len()))?;
    if processing.work(depth.saturating_add(1), phase).is_err()
        || processing.payload_array::<String>(depth, phase).is_err()
        || processing.payload(bytes, phase).is_err()
    {
        return None;
    }
    Some(path.child(key))
}
#[derive(Clone, Copy)]
enum ProtectedSegment<'a> {
    Key(&'a str),
    Index(usize),
}
impl ProtectedSegment<'_> {
    fn bytes(self) -> usize {
        match self {
            Self::Key(key) => key.len(),
            Self::Index(index) => index.checked_ilog10().map_or(1, |digits| digits as usize + 1),
        }
    }
    fn owned(self) -> String {
        match self {
            Self::Key(key) => key.to_owned(),
            Self::Index(index) => index.to_string(),
        }
    }
}
struct ProtectedFrame<'a> {
    node: &'a TreeNode,
    remaining: usize,
    in_schema: bool,
}

// Reuse depth-bounded scratch storage. Precharge growth and relocation before
// reserving; an allocation failure exhausts the same shared sticky budget.
fn protected_slot<T>(ctx: &EncodeContext<'_>, buffer: &mut Vec<T>) -> Result<(), Finding> {
    let processing = ctx.budget.processing();
    let phase = ctx.budget.phase();
    if buffer.len() == buffer.capacity() {
        let capacity = buffer
            .capacity()
            .max(1)
            .checked_mul(2)
            .ok_or_else(|| processing.fail(phase))?;
        processing.payload_array::<T>(capacity - buffer.capacity(), phase)?;
        processing.work(buffer.len(), phase)?;
        buffer
            .try_reserve_exact(capacity - buffer.len())
            .map_err(|_| processing.fail(phase))?;
    }
    Ok(())
}

fn emit_protected(
    ctx: &EncodeContext<'_>,
    path: &[ProtectedSegment<'_>],
    key: &str,
    out: &mut Vec<FieldPath>,
) -> Result<(), Finding> {
    let processing = ctx.budget.processing();
    let phase = ctx.budget.phase();
    let depth = path.len().checked_add(1).ok_or_else(|| processing.fail(phase))?;
    processing.work(depth, phase)?;
    let bytes = path
        .iter()
        .try_fold(key.len(), |total, part| total.checked_add(part.bytes()))
        .ok_or_else(|| processing.fail(phase))?;
    processing.payload_array::<String>(depth, phase)?;
    processing.payload(bytes, phase)?;
    processing.work(bytes, phase)?;
    protected_slot(ctx, out)?;
    let mut owned = Vec::new();
    owned.try_reserve_exact(depth).map_err(|_| processing.fail(phase))?;
    owned.extend(path.iter().map(|part| part.owned()));
    owned.push(key.to_owned());
    out.push(FieldPath(owned));
    Ok(())
}
/// Retain endpoint URLs, certificate bytes, and schema examples/enums, copying
/// only matched paths. Scratch capacity is proportional to traversal depth.
pub(super) fn protected_paths(_kind: &str, tree: &TreeNode, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) {
    fn enter<'a>(
        node: &'a TreeNode,
        path: &[ProtectedSegment<'a>],
        in_schema: bool,
        ctx: &EncodeContext<'_>,
        out: &mut Vec<FieldPath>,
    ) -> Result<ProtectedFrame<'a>, Finding> {
        let processing = ctx.budget.processing();
        let phase = ctx.budget.phase();
        processing.work(1, phase)?;
        let in_client_config = matches!(path.last(), Some(ProtectedSegment::Key("clientConfig")));
        if let Some(members) = object(node) {
            // Emit immediate matches left-to-right before visiting any subtree,
            // exactly as the previous pending-node traversal did.
            for (key, _) in members {
                processing.work(key.len().checked_add(1).ok_or_else(|| processing.fail(phase))?, phase)?;
                if (in_schema && matches!(key.as_str(), "enum" | "example"))
                    || (in_client_config && matches!(key.as_str(), "url" | "caBundle"))
                {
                    emit_protected(ctx, path, key, out)?;
                }
            }
        }
        Ok(ProtectedFrame {
            node,
            remaining: object(node).map_or_else(|| sequence(node).map_or(0, <[_]>::len), <[_]>::len),
            in_schema,
        })
    }
    fn walk(tree: &TreeNode, ctx: &EncodeContext<'_>, out: &mut Vec<FieldPath>) -> Result<(), Finding> {
        let mut path = Vec::new();
        let mut frames = Vec::new();
        protected_slot(ctx, &mut frames)?;
        frames.push(enter(tree, &path, false, ctx, out)?);
        while let Some(frame) = frames.last_mut() {
            ctx.budget.processing().work(1, ctx.budget.phase())?;
            if frame.remaining == 0 {
                frames.pop();
                if !frames.is_empty() {
                    path.pop();
                }
                continue;
            }
            frame.remaining -= 1;
            let node = frame.node;
            let index = frame.remaining;
            let parent_schema = frame.in_schema;
            let (segment, child) = match &node.value {
                TreeValue::Mapping(members) => {
                    let (key, child) = &members[index];
                    (ProtectedSegment::Key(key), child)
                }
                TreeValue::Sequence(items) => (ProtectedSegment::Index(index), &items[index]),
                _ => return Err(ctx.budget.processing().fail(ctx.budget.phase())),
            };
            ctx.budget.processing().work(segment.bytes(), ctx.budget.phase())?;
            let in_schema = parent_schema || matches!(segment, ProtectedSegment::Key("openAPIV3Schema"));
            protected_slot(ctx, &mut path)?;
            protected_slot(ctx, &mut frames)?;
            path.push(segment);
            frames.push(enter(child, &path, in_schema, ctx, out)?);
        }
        Ok(())
    }
    let _ = walk(tree, ctx, out);
}

pub(super) fn validate(api: &str, kind: &str, tree: &TreeNode, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
    if out.exhausted() {
        return;
    }
    let fields = &ctx.fields;
    if fields.processing.work(1, fields.phase).is_err() {
        return;
    }
    if kind.ends_with("WebhookConfiguration") {
        let Some(webhooks) = tree.get("webhooks").and_then(sequence) else {
            return;
        };
        for (index, webhook) in webhooks.iter().enumerate() {
            if out.exhausted() || fields.processing.work(1, fields.phase).is_err() {
                return;
            }
            let path = FieldPath::default().child("webhooks").child(index.to_string());
            if present(webhook, "timeoutSeconds")
                && int(webhook, "timeoutSeconds").is_some_and(|value| !(1..=30).contains(&value))
            {
                invalid(&path.child("timeoutSeconds"), out);
            }
            if string(webhook, "failurePolicy").is_some_and(|value| !matches!(value, "Ignore" | "Fail")) {
                invalid(&path.child("failurePolicy"), out);
            }
            if string(webhook, "matchPolicy").is_some_and(|value| !matches!(value, "Exact" | "Equivalent")) {
                invalid(&path.child("matchPolicy"), out);
            }
            if let Some(value) = string(webhook, "sideEffects") {
                if !matches!(value, "Unknown" | "None" | "Some" | "NoneOnDryRun") {
                    invalid(&path.child("sideEffects"), out);
                } else if api == "admissionregistration.k8s.io/v1" && matches!(value, "Unknown" | "Some") {
                    let side_effects_path = path.child("sideEffects");
                    // Existing v1 objects may retain values from beta creation.
                    // Source API alone cannot establish that historical origin.
                    match ctx.intent {
                        crate::generation::NativeValidationIntent::Create => invalid(&side_effects_path, out),
                        crate::generation::NativeValidationIntent::Unspecified => out.push(
                            Finding::warning(FindingCode::NativeContextRequired, Phase::Validation)
                                .at_path(side_effects_path),
                        ),
                    }
                }
            }
            if let Some(client) = webhook.get("clientConfig") {
                one_of(client, &["service", "url"], &path.child("clientConfig"), out);
            }
        }
    } else if kind == "CustomResourceDefinition" {
        let Some(spec) = tree.get("spec") else {
            return;
        };
        let Some(versions) = spec.get("versions").and_then(sequence) else {
            return;
        };
        let mut names = std::collections::BTreeSet::new();
        let mut storage = 0usize;
        for (index, version) in versions.iter().enumerate() {
            if out.exhausted() || fields.processing.work(1, fields.phase).is_err() {
                return;
            }
            let path = FieldPath::default()
                .child("spec")
                .child("versions")
                .child(index.to_string());
            if let Some(name) = string(version, "name") {
                if fields.processing.payload(name.len(), fields.phase).is_err()
                    || fields.processing.payload_array::<String>(1, fields.phase).is_err()
                {
                    return;
                }
                if !names.insert(name.to_owned()) {
                    invalid(&path.child("name"), out);
                }
            }
            if matches!(
                version.get("storage").map(|node| &node.value),
                Some(TreeValue::Bool(true))
            ) {
                storage += 1;
            }
        }
        if storage != 1 {
            invalid(&FieldPath::default().child("spec").child("versions"), out);
        }
    }
}

#[cfg(test)]
mod protected_path_scratch_tests {
    use super::*;
    use crate::{
        processing::{NativeOperationBudget, NativeProcessingLimits},
        source::ParseLimits,
    };

    type TestResult = Result<(), Box<dyn std::error::Error>>;

    fn mapping(entries: Vec<(&str, TreeNode)>) -> TreeNode {
        TreeNode::mapping(
            entries
                .into_iter()
                .map(|(key, value)| (key.to_owned(), value))
                .collect(),
        )
    }
    fn context(processing: &NativeOperationBudget) -> EncodeContext<'static> {
        EncodeContext::in_operation(None, ParseLimits::default(), processing.clone())
    }

    #[test]
    fn immediate_matches_then_reverse_subtrees_preserve_all_matching_rules() -> TestResult {
        let leaf = || TreeNode::string("private");
        let tree = mapping(vec![
            (
                "openAPIV3Schema",
                mapping(vec![
                    ("enum", leaf()),
                    ("example", mapping(vec![("example", leaf())])),
                    ("left", mapping(vec![("enum", leaf())])),
                    (
                        "right",
                        TreeNode::new(TreeValue::Sequence(vec![
                            mapping(vec![("example", leaf())]),
                            mapping(vec![("enum", leaf())]),
                        ])),
                    ),
                    ("examples", leaf()),
                ]),
            ),
            (
                "clientConfig",
                mapping(vec![
                    ("url", leaf()),
                    ("caBundle", leaf()),
                    ("nested", mapping(vec![("url", leaf())])),
                ]),
            ),
            ("openAPIV3Schemas", mapping(vec![("enum", leaf())])),
            ("enum", leaf()),
            (
                "tagged",
                TreeNode::new(TreeValue::Tagged(
                    "tag".into(),
                    Box::new(mapping(vec![("clientConfig", mapping(vec![("url", leaf())]))])),
                )),
            ),
        ]);
        let expected = [
            "/clientConfig/url",
            "/clientConfig/caBundle",
            "/openAPIV3Schema/enum",
            "/openAPIV3Schema/example",
            "/openAPIV3Schema/right/1/enum",
            "/openAPIV3Schema/right/0/example",
            "/openAPIV3Schema/left/enum",
            "/openAPIV3Schema/example/example",
        ]
        .into_iter()
        .map(FieldPath::parse)
        .collect::<Result<Vec<_>, _>>()?;
        let processing = NativeOperationBudget::new(NativeProcessingLimits::default());
        let mut out = Vec::new();
        protected_paths("irrelevant", &tree, &context(&processing), &mut out);
        assert_eq!(out, expected);
        assert!(!processing.exhausted());
        Ok(())
    }

    #[test]
    fn wide_deep_no_match_trees_reuse_the_same_charged_scratch_capacity() {
        let mut branch = TreeNode::string("leaf");
        for _ in 0..31 {
            branch = mapping(vec![("long-unprotected-prefix", branch)]);
        }
        let mut charged = Vec::new();
        for width in [1, 128] {
            let tree = TreeNode::mapping(
                (0..width)
                    .map(|index| (format!("branch{index}"), branch.clone()))
                    .collect(),
            );
            let processing = NativeOperationBudget::new(NativeProcessingLimits {
                max_payload_bytes: 4096,
                ..NativeProcessingLimits::default()
            });
            let mut out = Vec::new();
            protected_paths("", &tree, &context(&processing), &mut out);
            assert!(out.is_empty());
            assert!(!processing.exhausted());
            charged.push(processing.charged_payload_bytes());
        }
        assert_eq!(charged[0], charged[1]);
    }

    #[test]
    fn unicode_and_multi_digit_indexes_are_owned_only_for_retained_matches() -> TestResult {
        let tree = mapping(vec![(
            "openAPIV3Schema",
            mapping(vec![(
                "数",
                TreeNode::new(TreeValue::Sequence(
                    (0..13)
                        .map(|_| mapping(vec![("example", TreeNode::string("secret"))]))
                        .collect(),
                )),
            )]),
        )]);
        let processing = NativeOperationBudget::new(NativeProcessingLimits {
            max_payload_bytes: 4096,
            ..NativeProcessingLimits::default()
        });
        let mut out = Vec::new();
        protected_paths("", &tree, &context(&processing), &mut out);
        let expected = (0..13)
            .rev()
            .map(|index| FieldPath::parse(&format!("/openAPIV3Schema/数/{index}/example")))
            .collect::<Result<Vec<_>, _>>()?;
        assert_eq!(out, expected);
        assert!(!processing.exhausted());
        Ok(())
    }

    #[test]
    fn retained_path_storage_and_copies_are_precharged_and_exhaustion_is_shared() -> TestResult {
        let path = [ProtectedSegment::Key("数"), ProtectedSegment::Index(12)];
        let bytes = "数".len() + 2 + "example".len();
        let payload = 2 * size_of::<FieldPath>() + 3 * size_of::<String>() + bytes;
        let processing = NativeOperationBudget::new(NativeProcessingLimits {
            max_payload_bytes: payload,
            ..NativeProcessingLimits::default()
        });
        let ctx = context(&processing);
        let mut out = Vec::new();
        emit_protected(&ctx, &path, "example", &mut out)?;
        assert_eq!(processing.charged_payload_bytes(), payload);
        assert_eq!(out, vec![FieldPath::parse("/数/12/example")?]);
        assert!(emit_protected(&ctx, &path, "example", &mut out).is_err());
        assert!(processing.exhausted());
        let shared = context(&processing);
        protected_paths(
            "",
            &mapping(vec![("clientConfig", mapping(vec![("url", TreeNode::string("x"))]))]),
            &shared,
            &mut out,
        );
        assert_eq!(out.len(), 1);
        Ok(())
    }

    #[test]
    fn traversal_retains_earlier_matches_when_later_copy_work_exhausts() -> TestResult {
        let tree = mapping(vec![(
            "clientConfig",
            mapping(vec![
                ("url", TreeNode::string("x")),
                ("caBundle", TreeNode::string("certificate")),
            ]),
        )]);
        let processing = NativeOperationBudget::new(NativeProcessingLimits {
            max_processing_units: 64,
            ..NativeProcessingLimits::default()
        });
        let mut out = Vec::new();
        protected_paths("", &tree, &context(&processing), &mut out);
        assert_eq!(out, vec![FieldPath::parse("/clientConfig/url")?]);
        assert!(processing.exhausted());
        Ok(())
    }

    #[test]
    fn low_work_or_payload_stops_before_retaining_a_match() {
        let tree = mapping(vec![("clientConfig", mapping(vec![("url", TreeNode::string("x"))]))]);
        for limits in [
            NativeProcessingLimits {
                max_payload_bytes: 0,
                ..NativeProcessingLimits::default()
            },
            NativeProcessingLimits {
                max_processing_units: 1,
                ..NativeProcessingLimits::default()
            },
        ] {
            let processing = NativeOperationBudget::new(limits);
            let mut out = Vec::new();
            protected_paths("", &tree, &context(&processing), &mut out);
            assert!(out.is_empty());
            assert!(processing.exhausted());
            protected_paths("", &tree, &context(&processing), &mut out);
            assert!(out.is_empty());
        }
    }
}
