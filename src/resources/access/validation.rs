//! Finite offline native checks over selected, current values; server equivalence is not claimed.
use crate::{
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    model::GroupVersionKind,
    registry::{FieldDecodeContext, FindingSink, ValidationContext, codec::FieldCodec},
    resources::common::{UnknownScopeVisitor, UnknownScopes},
    syntax::{TreeNode, TreeValue},
};

pub(super) trait AccessSink {
    fn push(&mut self, finding: Finding);
    fn exhausted(&self) -> bool;
    fn fields(&self) -> &FieldDecodeContext;
    fn charge(&self, units: usize) -> bool {
        !self.exhausted() && self.fields().processing.work(units, self.fields().phase).is_ok()
    }
    fn admit_tree(&self, node: &TreeNode) -> bool {
        fn scan(node: &TreeNode, fields: &FieldDecodeContext) -> Result<(), Finding> {
            fields.processing.work(1, fields.phase)?;
            match &node.value {
                TreeValue::String(value) | TreeValue::Number(value) => {
                    fields.processing.work(value.len(), fields.phase)?;
                }
                TreeValue::Sequence(items) => {
                    for item in items {
                        scan(item, fields)?;
                    }
                }
                TreeValue::Mapping(items) => {
                    for (key, item) in items {
                        fields.processing.work(key.len(), fields.phase)?;
                        scan(item, fields)?;
                    }
                }
                TreeValue::Tagged(tag, item) => {
                    fields.processing.work(tag.len(), fields.phase)?;
                    scan(item, fields)?;
                }
                TreeValue::Null | TreeValue::Bool(_) => {}
            }
            Ok(())
        }
        !self.exhausted() && scan(node, self.fields()).is_ok()
    }
}
struct AccessReport<'a> {
    incoming: &'a mut dyn FindingSink,
    fields: &'a FieldDecodeContext,
}
impl AccessSink for AccessReport<'_> {
    fn push(&mut self, finding: Finding) {
        self.incoming.push(finding);
    }
    fn exhausted(&self) -> bool {
        self.incoming.exhausted() || self.fields.processing.work(1, self.fields.phase).is_err()
    }
    fn fields(&self) -> &FieldDecodeContext {
        self.fields
    }
}

pub(super) trait Profile: FieldCodec + UnknownScopes {
    const API: &'static str;
    const KIND: &'static str;
}
pub(super) fn invalid(path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
}
pub(super) fn unadmitted(path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    out.push(Finding::warning(FindingCode::UnadmittedField, Phase::Validation).at_path(path.clone()));
}
/// Preserve unsupported selector evidence separately from native invalidity and terminal budgets.
pub(super) fn selector(node: &TreeNode, path: &FieldPath, out: &mut dyn AccessSink) {
    use crate::value::LabelSelector;
    match LabelSelector::decode(node, out.fields(), path).and_then(|value| value.validate()) {
        Ok(()) => {}
        Err(finding) if finding.code == FindingCode::LimitExceeded => out.push(finding),
        Err(finding) if finding.code == FindingCode::UnadmittedField => unadmitted(path, out),
        Err(_) => invalid(path, out),
    }
}
pub(super) fn text<'a>(node: &'a TreeNode, key: &str) -> Option<&'a str> {
    node.get(key).and_then(TreeNode::as_str)
}
pub(super) fn integer(node: &TreeNode) -> Option<i64> {
    if let TreeValue::Number(value) = &node.value {
        value.parse().ok()
    } else {
        None
    }
}
pub(super) fn present(node: &TreeNode, key: &str) -> bool {
    node.get(key).is_some_and(|node| node.value != TreeValue::Null)
}
pub(super) fn require(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    if !present(node, key) {
        invalid(&path.child(key), out);
    }
}
pub(super) fn enumeration(node: &TreeNode, key: &str, values: &[&str], path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    if present(node, key) && !text(node, key).is_some_and(|value| values.contains(&value)) {
        invalid(&path.child(key), out);
    }
}
pub(super) fn number(node: &TreeNode, key: &str, first: i64, last: i64, path: &FieldPath, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    if present(node, key)
        && !node
            .get(key)
            .and_then(integer)
            .is_some_and(|value| (first..=last).contains(&value))
    {
        invalid(&path.child(key), out);
    }
}
pub(super) fn sequence<'a>(node: &'a TreeNode, key: &str) -> &'a [TreeNode] {
    node.get(key).and_then(TreeNode::as_sequence).unwrap_or(&[])
}
/// Match actual numeric/map paths against one finite declaration, without traversing arbitrary unknown trees.
pub(super) fn nodes<'a>(
    tree: &'a TreeNode,
    pointer: &str,
    fields: &FieldDecodeContext,
) -> Vec<(FieldPath, &'a TreeNode)> {
    fn push<'a>(
        out: &mut Vec<(FieldPath, &'a TreeNode)>,
        parent: &FieldPath,
        segment: &str,
        node: &'a TreeNode,
        fields: &FieldDecodeContext,
    ) -> Result<(), Finding> {
        let count = parent
            .0
            .len()
            .checked_add(1)
            .ok_or_else(|| fields.processing.fail(fields.phase))?;
        fields.processing.work(count, fields.phase)?;
        fields.processing.payload_array::<String>(count, fields.phase)?;
        fields
            .processing
            .payload_array::<(FieldPath, &TreeNode)>(1, fields.phase)?;
        fields
            .processing
            .payload_sizes(parent.0.iter().map(String::len).chain([segment.len()]), fields.phase)?;
        out.push((parent.child(segment), node));
        Ok(())
    }
    if fields
        .processing
        .work(pointer.len().saturating_add(1), fields.phase)
        .is_err()
        || fields.processing.payload(pointer.len(), fields.phase).is_err()
        || fields
            .processing
            .payload_array::<(FieldPath, &TreeNode)>(1, fields.phase)
            .is_err()
    {
        return Vec::new();
    }
    let Ok(pattern) = FieldPath::parse(pointer) else {
        return Vec::new();
    };
    let mut current = vec![(FieldPath::default(), tree)];
    for segment in pattern.0 {
        let mut next = Vec::new();
        for (path, node) in current {
            if fields.processing.work(1, fields.phase).is_err() {
                return Vec::new();
            }
            if segment == "*" {
                match &node.value {
                    TreeValue::Sequence(items) => {
                        for (index, node) in items.iter().enumerate() {
                            if fields.processing.payload(20, fields.phase).is_err()
                                || push(&mut next, &path, &index.to_string(), node, fields).is_err()
                            {
                                return Vec::new();
                            }
                        }
                    }
                    TreeValue::Mapping(items) => {
                        for (key, node) in items {
                            if push(&mut next, &path, key, node, fields).is_err() {
                                return Vec::new();
                            }
                        }
                    }
                    _ => {}
                }
            } else if let Some(items) = node.as_mapping() {
                for (key, child) in items {
                    if fields
                        .processing
                        .work(key.len().saturating_add(segment.len()).saturating_add(1), fields.phase)
                        .is_err()
                    {
                        return Vec::new();
                    }
                    if key == &segment {
                        if push(&mut next, &path, &segment, child, fields).is_err() {
                            return Vec::new();
                        }
                        break;
                    }
                }
            }
        }
        current = next;
    }
    current
}
fn selected_required<T: Profile>(tree: &TreeNode, minor: u8, out: &mut dyn AccessSink) {
    if out.exhausted() {
        return;
    }
    for &(kind, api, pointer, first, last) in super::required::REQUIRED {
        if out.exhausted() {
            return;
        }
        if kind != T::KIND || api != T::API || !(first..=last).contains(&minor) {
            continue;
        }
        let Some((parent, key)) = pointer.rsplit_once('/') else {
            continue;
        };
        for (path, node) in nodes(tree, parent, out.fields()) {
            if out.exhausted() {
                return;
            }
            // An optional null helper has no child obligations; a required parent is checked separately.
            if node.value != TreeValue::Null {
                require(node, key, &path, out);
            }
        }
    }
    for &(kind, api, pointer, values) in super::required::ENUMS {
        if out.exhausted() {
            return;
        }
        if kind != T::KIND || api != T::API {
            continue;
        }
        for (path, node) in nodes(tree, pointer, out.fields()) {
            if out.exhausted() {
                return;
            }
            if node.value != TreeValue::Null && !node.as_str().is_some_and(|value| values.contains(&value)) {
                invalid(&path, out);
            }
        }
    }
}
pub(super) fn validate<T: Profile>(resource: &T, ctx: &ValidationContext<'_>, incoming: &mut dyn FindingSink) {
    let mut report = AccessReport {
        incoming,
        fields: &ctx.fields,
    };
    let out: &mut dyn AccessSink = &mut report;
    let mut encoding = ctx.encoding();
    encoding.include_unknown = true;
    let tree = match resource.encode(&encoding, &FieldPath::default()) {
        Ok(tree) => tree,
        Err(finding) => {
            out.push(finding);
            return;
        }
    };
    let gvk = match GroupVersionKind::new(T::API, T::KIND) {
        Ok(gvk) => gvk,
        Err(finding) => {
            out.push(finding);
            return;
        }
    };
    let capability = match super::capabilities::for_api(gvk) {
        Ok(value) => value,
        Err(finding) => {
            out.push(finding);
            return;
        }
    };
    // API removal wins independently of fields, gates and source origins.
    if ctx.target.kubernetes < capability.api_since
        || capability
            .api_removed
            .is_some_and(|removed| ctx.target.kubernetes >= removed)
    {
        out.push(Finding::error(FindingCode::UnavailableApi, Phase::Validation));
        return;
    }
    selected_required::<T>(&tree, ctx.target.kubernetes.minor(), out);
    if out.exhausted() {
        return;
    }
    let fields = out.fields().clone();
    let mut emit = |path| {
        if out.exhausted() {
            return false;
        }
        out.push(Finding::warning(FindingCode::UnadmittedField, Phase::Validation).at_path(path));
        !out.exhausted()
    };
    if !resource.visit_unknown_scopes(&FieldPath::default(), &mut UnknownScopeVisitor::new(&fields, &mut emit)) {
        return;
    }
    match T::KIND {
        "Namespace" => super::policy::namespace(&tree, ctx.target.kubernetes.minor(), out),
        "ServiceAccount" => super::rbac::service_account(&tree, out),
        "Role" | "RoleBinding" | "ClusterRole" | "ClusterRoleBinding" => super::rbac::validate(&tree, T::KIND, out),
        "HorizontalPodAutoscaler" => super::hpa::validate(&tree, T::API, ctx, out),
        "PodDisruptionBudget" => super::policy::disruption(&tree, out),
        "ResourceQuota" => super::policy::quota(&tree, ctx.target, out),
        "LimitRange" => super::policy::limits(&tree, out),
        "PriorityClass" => super::policy::priority(&tree, out),
        "RuntimeClass" => super::policy::runtime(&tree, out),
        "PodSecurityPolicy" => super::policy::security(&tree, out),
        _ => {}
    }
}
