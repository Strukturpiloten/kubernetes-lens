//! Sealed codec interface and fixed cohort extension boundary.
use crate::{
    capability::{KindCapability, TargetProfile},
    diagnostic::{Finding, FindingCode, Phase},
    graph::ReferenceSink,
    model::{GroupVersionKind, ResourceScope},
    source::{AuthoringLimits, SourceEvidence},
    syntax::{EncodingBudget, SyntaxBuilder, TreeNode, TreeValue},
};
use std::{any::Any, collections::BTreeMap};

pub(crate) trait FindingSink {
    fn push(&mut self, finding: Finding);
}
impl FindingSink for Vec<Finding> {
    fn push(&mut self, finding: Finding) {
        Self::push(self, finding);
    }
}
pub(crate) struct DecodeContext<'a> {
    pub(crate) gvk: &'a GroupVersionKind,
    pub(crate) scope: ResourceScope,
}
pub(crate) struct EncodeContext<'a> {
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Target-aware sealed encoding extension exercised by foundation codecs"
        )
    )]
    pub(crate) target: Option<&'a TargetProfile>,
    pub(crate) include_unknown: bool,
    pub(crate) budget: EncodingBudget,
}
impl<'a> EncodeContext<'a> {
    pub(crate) fn new(target: Option<&'a TargetProfile>) -> Self {
        Self {
            target,
            include_unknown: false,
            budget: EncodingBudget::new(AuthoringLimits::default()),
        }
    }
    pub(crate) fn string(&self, value: &str, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        self.budget.scalar(value.len(), path)?;
        Ok(TreeNode::string(value))
    }
    pub(crate) fn integer(&self, value: i64, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        let digits = if value == 0 {
            1
        } else {
            value.unsigned_abs().ilog10() as usize + 1
        };
        self.budget.scalar(digits + usize::from(value < 0), path)?;
        Ok(TreeNode::new(TreeValue::Number(value.to_string())))
    }
    pub(crate) fn boolean(&self, value: bool, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        self.budget.node(path)?;
        Ok(TreeNode::new(TreeValue::Bool(value)))
    }
    pub(crate) fn null(&self, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        self.budget.node(path)?;
        Ok(TreeNode::new(TreeValue::Null))
    }
    pub(crate) fn object(
        &self,
        entries: Vec<(String, TreeNode)>,
        path: &crate::FieldPath,
    ) -> Result<TreeNode, Finding> {
        self.budget.node(path)?;
        Ok(TreeNode::mapping(entries))
    }
    pub(crate) fn sequence(&self, items: Vec<TreeNode>, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        self.budget.node(path)?;
        Ok(TreeNode::new(TreeValue::Sequence(items)))
    }
    pub(crate) fn clone_node(&self, node: &TreeNode, path: &crate::FieldPath) -> Result<TreeNode, Finding> {
        self.budget.clone_node(node, path)
    }
    pub(crate) fn check_sequence_len(&self, len: usize, path: &crate::FieldPath) -> Result<(), Finding> {
        self.budget.check_len(len.saturating_add(1), path)
    }
    pub(crate) fn key(&self, key: &str, path: &crate::FieldPath) -> Result<String, Finding> {
        self.budget.scalar(key.len(), path)?;
        Ok(key.to_owned())
    }
}
pub(crate) struct ValidationContext<'a> {
    pub(crate) intent: crate::generation::NativeValidationIntent,
    pub(crate) target: &'a TargetProfile,
}
pub(crate) trait NativeResource: Any + Send + Sync {
    fn as_any(&self) -> &dyn Any;
    fn as_any_mut(&mut self) -> &mut dyn Any;
    fn collect_references(&self, out: &mut dyn ReferenceSink);
    fn collect_protected_paths(&self, out: &mut Vec<crate::diagnostic::FieldPath>);
    fn collect_native_facts(&self, _ctx: &ProjectionContext<'_>, _out: &mut Vec<crate::graph::NativeFact>) {}
    fn collect_observation_paths(&self, _tree: &TreeNode, _out: &mut Vec<crate::source::ObservationPath>) {}
    fn validate(&self, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink);
    fn encode_known(&self, ctx: &EncodeContext<'_>, out: &mut SyntaxBuilder) -> Result<(), Finding>;
}
pub(crate) type DecodeFn =
    fn(&TreeNode, &SourceEvidence, &DecodeContext<'_>) -> Result<Box<dyn NativeResource>, Vec<Finding>>;
pub(crate) struct ResourceRegistration {
    pub(crate) gvk: GroupVersionKind,
    pub(crate) scope: ResourceScope,
    pub(crate) decode: DecodeFn,
    pub(crate) capability: KindCapability,
}
pub(crate) struct TypedListRegistration {
    pub(crate) gvk: GroupVersionKind,
    pub(crate) item_gvk: GroupVersionKind,
}
pub(crate) struct RegistryBuilder {
    pub(crate) entries: BTreeMap<GroupVersionKind, ResourceRegistration>,
    pub(crate) lists: BTreeMap<GroupVersionKind, GroupVersionKind>,
}
impl RegistryBuilder {
    pub(crate) fn new() -> Self {
        Self {
            entries: BTreeMap::new(),
            lists: BTreeMap::new(),
        }
    }
    pub(crate) fn register(&mut self, entry: ResourceRegistration) -> Result<(), Finding> {
        if entry.gvk != entry.capability.gvk
            || entry.scope != entry.capability.scope
            || self.entries.contains_key(&entry.gvk)
            || self.lists.contains_key(&entry.gvk)
            || crate::capability::declaration(&entry.gvk).is_none_or(|decl| decl.scope != entry.scope)
        {
            return Err(invalid());
        }
        self.entries.insert(entry.gvk.clone(), entry);
        Ok(())
    }
    pub(crate) fn register_list(&mut self, entry: TypedListRegistration) -> Result<(), Finding> {
        if self.lists.contains_key(&entry.gvk)
            || self.entries.contains_key(&entry.gvk)
            || entry.gvk.group != entry.item_gvk.group
            || entry.gvk.version != entry.item_gvk.version
            || entry.gvk.kind != format!("{}List", entry.item_gvk.kind)
            || crate::capability::declaration(&entry.item_gvk).is_none()
        {
            return Err(invalid());
        }
        self.lists.insert(entry.gvk, entry.item_gvk);
        Ok(())
    }
}
fn invalid() -> Finding {
    Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)
}
pub(crate) fn encode(resource: &dyn NativeResource, target: Option<&TargetProfile>) -> Result<TreeNode, Finding> {
    encode_in(resource, &EncodeContext::new(target))
}
pub(crate) fn encode_in(resource: &dyn NativeResource, ctx: &EncodeContext<'_>) -> Result<TreeNode, Finding> {
    let mut out = SyntaxBuilder::new();
    resource.encode_known(ctx, &mut out)?;
    let tree = out.finish()?;
    // Construction counters are shared across one graph operation; final shape is independently checked.
    ctx.budget.verify(&tree)?;
    Ok(tree)
}
pub(crate) mod codec {
    use super::EncodeContext;
    use crate::{
        diagnostic::{FieldPath, Finding, FindingCode, Phase},
        model::{Metadata, OwnerReference},
        syntax::{TreeNode, TreeValue, UnknownFields},
        value::{IntOrString, LabelSelector, Presence, Protected, Quantity, SelectorOperator, SelectorRequirement},
    };
    use std::collections::BTreeMap;
    pub(crate) trait FieldCodec: Sized {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding>;
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding>;
    }
    fn invalid(path: &FieldPath) -> Finding {
        Finding::error(FindingCode::NativeFieldInvalid, Phase::Decoding).at_path(path.clone())
    }
    pub(crate) fn object<'a>(node: &'a TreeNode, path: &FieldPath) -> Result<&'a [(String, TreeNode)], Finding> {
        node.as_mapping().ok_or_else(|| invalid(path))
    }
    pub(crate) fn read_presence<T: FieldCodec>(
        node: &TreeNode,
        key: &str,
        path: &FieldPath,
    ) -> Result<Presence<T>, Finding> {
        object(node, path)?;
        match node.get(key) {
            None => Ok(Presence::Absent),
            Some(TreeNode {
                value: TreeValue::Null, ..
            }) => Ok(Presence::Null),
            Some(value) => T::decode(value, &path.child(key))
                .map(Presence::Value)
                .map_err(|mut finding| {
                    if finding.source.is_none() {
                        finding.source = value.start;
                    }
                    finding
                }),
        }
    }
    pub(crate) fn write_presence<T: FieldCodec>(
        entries: &mut Vec<(String, TreeNode)>,
        key: &str,
        value: &Presence<T>,
        ctx: &EncodeContext<'_>,
        path: &FieldPath,
    ) -> Result<(), Finding> {
        let child = path.child(key);
        let node = match value {
            Presence::Absent => return Ok(()),
            Presence::Null => ctx.null(&child)?,
            Presence::Value(value) => value.encode(ctx, &child)?,
        };
        let key = ctx.key(key, &child)?;
        entries.push((key, node));
        Ok(())
    }
    pub(crate) fn append_unknown(
        unknown: &UnknownFields,
        entries: &mut Vec<(String, TreeNode)>,
        ctx: &EncodeContext<'_>,
        path: &FieldPath,
    ) -> Result<(), Finding> {
        if !ctx.include_unknown {
            return Ok(());
        }
        ctx.check_sequence_len(unknown.entries.len().saturating_mul(2), path)?;
        let mut names = entries
            .iter()
            .map(|(key, _)| key.clone())
            .collect::<std::collections::BTreeSet<_>>();
        for (key, value) in &unknown.entries {
            if !names.insert(ctx.key(key, &path.child(key))?) {
                return Err(Finding::error(FindingCode::MergeConflict, Phase::Generation).at_path(path.child(key)));
            }
            let child = path.child(key);
            entries.push((key.clone(), ctx.clone_node(&value.0, &child)?));
        }
        Ok(())
    }
    impl FieldCodec for String {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            node.as_str().map(str::to_owned).ok_or_else(|| invalid(path))
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.string(self, path)
        }
    }
    impl FieldCodec for bool {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            if let TreeValue::Bool(value) = node.value {
                Ok(value)
            } else {
                Err(invalid(path))
            }
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.boolean(*self, path)
        }
    }
    impl FieldCodec for i64 {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            if let TreeValue::Number(value) = &node.value {
                value.parse().map_err(|_| invalid(path))
            } else {
                Err(invalid(path))
            }
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.integer(*self, path)
        }
    }
    impl FieldCodec for i32 {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            i32::try_from(i64::decode(node, path)?).map_err(|_| invalid(path))
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.integer(i64::from(*self), path)
        }
    }
    impl<T: FieldCodec> FieldCodec for Vec<T> {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            node.as_sequence()
                .ok_or_else(|| invalid(path))?
                .iter()
                .enumerate()
                .map(|(index, node)| T::decode(node, &path.child(index.to_string())))
                .collect()
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.check_sequence_len(self.len(), path)?;
            let mut items = Vec::with_capacity(self.len());
            for (index, value) in self.iter().enumerate() {
                items.push(value.encode(ctx, &path.child(index.to_string()))?);
            }
            ctx.sequence(items, path)
        }
    }
    impl<T: FieldCodec> FieldCodec for BTreeMap<String, T> {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            object(node, path)?
                .iter()
                .map(|(key, value)| Ok((key.clone(), T::decode(value, &path.child(key))?)))
                .collect()
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.check_sequence_len(self.len().saturating_mul(2), path)?;
            let mut entries = Vec::with_capacity(self.len());
            for (key, value) in self {
                let child = path.child(key);
                entries.push((ctx.key(key, &child)?, value.encode(ctx, &child)?));
            }
            ctx.object(entries, path)
        }
    }
    impl<T: FieldCodec> FieldCodec for Protected<T> {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            T::decode(node, path).map(Self::new)
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            self.native_value().encode(ctx, path)
        }
    }
    impl FieldCodec for Quantity {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            Self::parse(node.as_str().ok_or_else(|| invalid(path))?).map_err(|finding| finding.at_path(path.clone()))
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            ctx.string(self.native_lexeme(), path)
        }
    }
    impl FieldCodec for IntOrString {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            match &node.value {
                TreeValue::String(value) => Ok(Self::String(value.clone())),
                TreeValue::Number(_) => i64::decode(node, path).map(Self::Int),
                _ => Err(invalid(path)),
            }
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            match self {
                Self::Int(value) => ctx.integer(*value, path),
                Self::String(value) => ctx.string(value, path),
            }
        }
    }
    pub(crate) fn nonnegative_integer_or_percentage(
        value: &IntOrString,
        maximum_percent: Option<u64>,
        path: &FieldPath,
    ) -> Result<(), Finding> {
        let valid = match value {
            IntOrString::Int(value) => *value >= 0,
            IntOrString::String(value) => value
                .strip_suffix('%')
                .filter(|digits| !digits.is_empty() && digits.bytes().all(|byte| byte.is_ascii_digit()))
                .and_then(|digits| digits.parse::<u64>().ok())
                .is_some_and(|value| maximum_percent.is_none_or(|maximum| value <= maximum)),
        };
        if valid {
            Ok(())
        } else {
            Err(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()))
        }
    }
    impl FieldCodec for Metadata {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            object(node, path)?;
            Ok(Self {
                name: read_presence(node, "name", path)?,
                generate_name: read_presence(node, "generateName", path)?,
                namespace: read_presence(node, "namespace", path)?,
                labels: read_presence(node, "labels", path)?,
                annotations: read_presence(node, "annotations", path)?,
                finalizers: read_presence(node, "finalizers", path)?,
                uid: read_presence(node, "uid", path)?,
                resource_version: read_presence(node, "resourceVersion", path)?,
                owner_references: read_presence(node, "ownerReferences", path)?,
                unknown: UnknownFields::capture(
                    node,
                    &[
                        "name",
                        "generateName",
                        "namespace",
                        "labels",
                        "annotations",
                        "finalizers",
                        "uid",
                        "resourceVersion",
                        "ownerReferences",
                    ],
                ),
            })
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            let mut entries = Vec::new();
            write_presence(&mut entries, "name", &self.name, ctx, path)?;
            write_presence(&mut entries, "generateName", &self.generate_name, ctx, path)?;
            write_presence(&mut entries, "namespace", &self.namespace, ctx, path)?;
            write_presence(&mut entries, "labels", &self.labels, ctx, path)?;
            write_presence(&mut entries, "annotations", &self.annotations, ctx, path)?;
            write_presence(&mut entries, "finalizers", &self.finalizers, ctx, path)?;
            write_presence(&mut entries, "uid", &self.uid, ctx, path)?;
            write_presence(&mut entries, "resourceVersion", &self.resource_version, ctx, path)?;
            write_presence(&mut entries, "ownerReferences", &self.owner_references, ctx, path)?;
            append_unknown(&self.unknown, &mut entries, ctx, path)?;
            ctx.object(entries, path)
        }
    }
    fn required<T: FieldCodec>(node: &TreeNode, key: &str, path: &FieldPath) -> Result<T, Finding> {
        T::decode(
            node.get(key).ok_or_else(|| invalid(&path.child(key)))?,
            &path.child(key),
        )
    }
    fn write_required<T: FieldCodec>(
        entries: &mut Vec<(String, TreeNode)>,
        key: &str,
        value: &T,
        ctx: &EncodeContext<'_>,
        path: &FieldPath,
    ) -> Result<(), Finding> {
        let child = path.child(key);
        entries.push((ctx.key(key, &child)?, value.encode(ctx, &child)?));
        Ok(())
    }
    impl FieldCodec for OwnerReference {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            object(node, path)?;
            Ok(Self {
                api_version: required(node, "apiVersion", path)?,
                kind: required(node, "kind", path)?,
                name: required(node, "name", path)?,
                uid: read_presence(node, "uid", path)?,
                controller: read_presence(node, "controller", path)?,
                block_owner_deletion: read_presence(node, "blockOwnerDeletion", path)?,
                unknown: UnknownFields::capture(
                    node,
                    &["apiVersion", "kind", "name", "uid", "controller", "blockOwnerDeletion"],
                ),
            })
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            let mut entries = Vec::new();
            write_required(&mut entries, "apiVersion", &self.api_version, ctx, path)?;
            write_required(&mut entries, "kind", &self.kind, ctx, path)?;
            write_required(&mut entries, "name", &self.name, ctx, path)?;
            write_presence(&mut entries, "uid", &self.uid, ctx, path)?;
            write_presence(&mut entries, "controller", &self.controller, ctx, path)?;
            write_presence(
                &mut entries,
                "blockOwnerDeletion",
                &self.block_owner_deletion,
                ctx,
                path,
            )?;
            append_unknown(&self.unknown, &mut entries, ctx, path)?;
            ctx.object(entries, path)
        }
    }
    impl FieldCodec for SelectorRequirement {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            object(node, path)?;
            let operator = match required::<String>(node, "operator", path)?.as_str() {
                "In" => SelectorOperator::In,
                "NotIn" => SelectorOperator::NotIn,
                "Exists" => SelectorOperator::Exists,
                "DoesNotExist" => SelectorOperator::DoesNotExist,
                _ => return Err(invalid(&path.child("operator"))),
            };
            Ok(Self {
                key: required(node, "key", path)?,
                operator,
                values: read_presence(node, "values", path)?,
                unknown: UnknownFields::capture(node, &["key", "operator", "values"]),
            })
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            let mut entries = Vec::new();
            write_required(&mut entries, "key", &self.key, ctx, path)?;
            let operator = match self.operator {
                SelectorOperator::In => "In",
                SelectorOperator::NotIn => "NotIn",
                SelectorOperator::Exists => "Exists",
                SelectorOperator::DoesNotExist => "DoesNotExist",
            };
            entries.push((
                ctx.key("operator", &path.child("operator"))?,
                ctx.string(operator, &path.child("operator"))?,
            ));
            write_presence(&mut entries, "values", &self.values, ctx, path)?;
            append_unknown(&self.unknown, &mut entries, ctx, path)?;
            ctx.object(entries, path)
        }
    }
    impl FieldCodec for LabelSelector {
        fn decode(node: &TreeNode, path: &FieldPath) -> Result<Self, Finding> {
            object(node, path)?;
            Ok(Self {
                match_labels: read_presence(node, "matchLabels", path)?,
                match_expressions: read_presence(node, "matchExpressions", path)?,
                unknown: UnknownFields::capture(node, &["matchLabels", "matchExpressions"]),
            })
        }
        fn encode(&self, ctx: &EncodeContext<'_>, path: &FieldPath) -> Result<TreeNode, Finding> {
            let mut entries = Vec::new();
            write_presence(&mut entries, "matchLabels", &self.match_labels, ctx, path)?;
            write_presence(&mut entries, "matchExpressions", &self.match_expressions, ctx, path)?;
            append_unknown(&self.unknown, &mut entries, ctx, path)?;
            ctx.object(entries, path)
        }
    }
}

/// Ephemeral exact native projection context. Codecs cannot manufacture provenance coordinates.
pub(crate) struct ProjectionContext<'a> {
    pub(crate) tree: &'a TreeNode,
    pub(crate) gvk: &'a GroupVersionKind,
    #[cfg_attr(
        not(test),
        expect(
            dead_code,
            reason = "Supplied source profile remains available to reviewed future facts and is exercised in context tests"
        )
    )]
    pub(crate) source: &'a SourceEvidence,
    pub(crate) target: Option<&'a TargetProfile>,
    pub(crate) capability: &'a KindCapability,
    operations: std::cell::Cell<usize>,
    findings: std::cell::RefCell<Vec<Finding>>,
    contextual: Vec<Finding>,
}
impl<'a> ProjectionContext<'a> {
    pub(crate) fn new(
        tree: &'a TreeNode,
        gvk: &'a GroupVersionKind,
        source: &'a SourceEvidence,
        target: Option<&'a TargetProfile>,
        capability: &'a KindCapability,
    ) -> Self {
        Self {
            tree,
            gvk,
            source,
            target,
            capability,
            operations: std::cell::Cell::new(0),
            findings: std::cell::RefCell::new(Vec::new()),
            contextual: if let Some(target) = target {
                crate::capability::source_field_findings(tree, gvk, target)
            } else {
                let mut probe = TargetProfile::documented_defaults(crate::capability::KubernetesVersion::MIN);
                for gate in crate::capability::FeatureGateId::ALL {
                    probe
                        .feature_gates
                        .states
                        .insert(*gate, crate::capability::FeatureGateState::Disabled);
                }
                crate::capability::source_field_findings(tree, gvk, &probe)
            },
        }
    }
    pub(crate) fn state<T>(
        &self,
        path: &crate::FieldPath,
        state: crate::graph::FactState<T>,
    ) -> crate::graph::FactState<T> {
        use crate::{
            capability::{FeatureGateState, FieldAdmission},
            graph::{FactGap, FactState},
        };
        if !self.tick(path) {
            return FactState::Unknown(FactGap::IncompleteSuppliedEvidence);
        }
        if self.target.is_some_and(|target| {
            target.kubernetes < self.capability.api_since
                || self
                    .capability
                    .api_removed
                    .is_some_and(|removed| target.kubernetes >= removed)
        }) {
            if !self
                .findings
                .borrow()
                .iter()
                .any(|finding| finding.code == FindingCode::UnavailableApi)
            {
                self.findings
                    .borrow_mut()
                    .push(Finding::error(FindingCode::UnavailableApi, Phase::Analysis));
            }
            return FactState::Unadmitted;
        }
        let field = self.capability.fields.iter().find(|field| {
            crate::FieldPath::parse(field.path).is_ok_and(|pattern| {
                pattern.0.len() == path.0.len()
                    && pattern
                        .0
                        .iter()
                        .zip(&path.0)
                        .all(|(expected, actual)| expected == actual || expected == "*")
            })
        });
        let Some(field) = field else {
            return FactState::Unadmitted;
        };
        if field.admission != FieldAdmission::Typed {
            return FactState::Unadmitted;
        }
        for ancestor in self.capability.fields.iter().filter(|ancestor| {
            crate::FieldPath::parse(ancestor.path).is_ok_and(|pattern| {
                pattern.0.len() <= path.0.len()
                    && pattern
                        .0
                        .iter()
                        .zip(&path.0)
                        .all(|(expected, actual)| expected == actual || expected == "*")
            })
        }) {
            if ancestor.admission != FieldAdmission::Typed {
                return FactState::Unadmitted;
            }
            if let Some(target) = self.target {
                if target.kubernetes < ancestor.since
                    || ancestor.removed.is_some_and(|removed| target.kubernetes >= removed)
                    || ancestor.feature_gate.is_some_and(|gate| {
                        target.feature_gates.resolve(gate, target.kubernetes) != Ok(FeatureGateState::Enabled)
                    })
                {
                    return FactState::Unadmitted;
                }
            } else if ancestor.feature_gate.is_some()
                || ancestor.since > self.capability.api_since
                || ancestor.removed.is_some()
            {
                return FactState::Unknown(FactGap::TargetProfileRequired);
            }
        }
        // Exact source-ledger contextual/union/value rules remain authoritative over codec shape.
        let invalid = self.contextual.iter().any(|finding| {
            finding
                .path
                .as_ref()
                .is_some_and(|affected| path.0.starts_with(&affected.0) || affected.0.starts_with(&path.0))
                && matches!(
                    finding.code,
                    FindingCode::UnadmittedField
                        | FindingCode::UnavailableField
                        | FindingCode::FeatureGateRequired
                        | FindingCode::NativeFieldInvalid
                )
        });
        if invalid {
            if self.target.is_some() {
                FactState::Unadmitted
            } else {
                FactState::Unknown(FactGap::TargetProfileRequired)
            }
        } else {
            state
        }
    }
    pub(crate) fn emit_fact(&self, fact: crate::graph::NativeFact, out: &mut Vec<crate::graph::NativeFact>) {
        if self.tick(&crate::FieldPath::default()) {
            out.push(fact);
        }
    }
    fn tick(&self, path: &crate::FieldPath) -> bool {
        let limit = crate::source::ParseLimits::default().max_nodes;
        if self.operations.get() >= limit {
            if self.findings.borrow().is_empty() {
                self.findings
                    .borrow_mut()
                    .push(Finding::error(FindingCode::LimitExceeded, Phase::Analysis).at_path(path.clone()));
            }
            false
        } else {
            self.operations.set(self.operations.get() + 1);
            true
        }
    }
    pub(crate) fn take_findings(&self) -> Vec<Finding> {
        self.findings.take()
    }
}
