use super::{
    ExecutionBounds, FormatCode, FormatError, HelmContext, LocalFile, ProjectLimits, ProjectSnapshot, RenderCommand,
    RenderProvenance, RenderRequest, Result, ToolSelection, input::lifecycle, json, ledger, yaml,
};
use crate::{
    ResourceId,
    capability::TargetProfile,
    diagnostic::{FieldPath, Phase},
    generation::{self, ExplicitArtifactAccess, GenerationOptions, OutputFormat},
    model::ResourceSet,
    processing::NativeOperationBudget,
    source::{AuthoringLimits, InputOrigin, ParseLimits, SourceId},
    syntax::{EncodingBudget, TreeNode, TreeValue},
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Finite generated-chart and overlay parameter families from the reviewed values contract.
#[derive(Clone, Eq, PartialEq)]
pub enum WorkloadField {
    /// Existing explicitly supplied replica count on a scalable delivered workload.
    Replicas,
    /// Image of an existing named ordinary container.
    Image {
        /// Protected native container name.
        container: String,
    },
    /// Existing request/limit quantity on an existing named ordinary container.
    Quantity {
        /// Protected native container name.
        container: String,
        /// Request or limit member.
        side: ResourceSide,
        /// Finite supported resource name.
        resource: ResourceQuantity,
    },
}
impl fmt::Debug for WorkloadField {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Replicas => "WorkloadField::Replicas",
            Self::Image { .. } => "WorkloadField::Image",
            Self::Quantity { .. } => "WorkloadField::Quantity",
        })
    }
}
/// Explicit resource quantity member, with no native default or arithmetic normalization.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceSide {
    /// Requests member.
    Requests,
    /// Limits member.
    Limits,
}
/// Restricted generated quantity names; broader native names remain static manifest values.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ResourceQuantity {
    /// CPU quantity.
    Cpu,
    /// Memory quantity.
    Memory,
    /// Ephemeral storage quantity.
    EphemeralStorage,
}
/// Private explicit overlay value; never a Go-template/string-command interface.
#[derive(Clone)]
pub enum NativeValue {
    /// Explicit bounded integer replica value.
    Replicas(u32),
    /// Explicit image string.
    Image(String),
    /// Exact quantity lexeme.
    Quantity(String),
}
impl fmt::Debug for NativeValue {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("NativeValue { protected }")
    }
}
impl NativeValue {
    fn tree(&self, field: &WorkloadField) -> Result<TreeNode> {
        match (self, field) {
            (Self::Replicas(n), WorkloadField::Replicas) if i32::try_from(*n).is_ok() => {
                Ok(TreeNode::new(TreeValue::Number(n.to_string())))
            }
            (Self::Image(v), WorkloadField::Image { .. }) | (Self::Quantity(v), WorkloadField::Quantity { .. })
                if !v.is_empty() && v.len() <= 1024 =>
            {
                Ok(TreeNode::string(v))
            }
            _ => Err(FormatError::new(FormatCode::UnsupportedVariation)),
        }
    }
}
/// An explicitly selected generated Helm values entry; default comes from existing native intent.
pub struct HelmParameter {
    /// Unique simple values key; arbitrary Go-template paths/code are not admitted.
    pub name: String,
    /// Input-local native resource identifier.
    pub resource: ResourceId,
    /// Existing admitted workload field.
    pub field: WorkloadField,
}
impl fmt::Debug for HelmParameter {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelmParameter")
            .field("resource", &self.resource)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}
/// Explicit generation policy; no hook is ever executed.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum HookPolicy {
    /// Refuse chart generation from annotated hook resources.
    #[default]
    Reject,
    /// Retain annotations with structured lifecycle finding.
    PreserveWithFinding,
}
/// New chart intent; never reconstruction of original charts/values/dependencies.
pub struct HelmChartOptions {
    /// Explicit safe chart name.
    pub name: String,
    /// Explicit semantic chart version with three numeric components.
    pub version: String,
    /// Finite explicitly selected values API, limited to 64 existing fields.
    pub parameters: Vec<HelmParameter>,
    /// Explicit hook retention policy.
    pub hooks: HookPolicy,
}
impl fmt::Debug for HelmChartOptions {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelmChartOptions")
            .field("parameter_count", &self.parameters.len())
            .field("hooks", &self.hooks)
            .finish_non_exhaustive()
    }
}
/// One explicit native variation; unselected fields remain in the generated base.
pub struct WorkloadVariation {
    /// Input-local resource ID in the supplied base.
    pub resource: ResourceId,
    /// Existing admitted native field.
    pub field: WorkloadField,
    /// Explicit private replacement value, validated against the target.
    pub value: NativeValue,
}
impl fmt::Debug for WorkloadVariation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("WorkloadVariation")
            .field("resource", &self.resource)
            .field("field", &self.field)
            .finish_non_exhaustive()
    }
}
/// Only caller-requested overlays are produced, with no inferred overlay organization.
pub struct KustomizeOverlay {
    /// Explicit safe directory name.
    pub name: String,
    /// Up to 64 explicitly selected existing native fields.
    pub variations: Vec<WorkloadVariation>,
}
impl fmt::Debug for KustomizeOverlay {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("KustomizeOverlay")
            .field("variation_count", &self.variations.len())
            .finish_non_exhaustive()
    }
}
/// Protected deterministic in-memory regular files. This type never writes or executes them.
pub struct ArtifactTree {
    files: BTreeMap<String, Vec<u8>>,
    findings: Vec<FormatCode>,
    native_findings: Vec<crate::Finding>,
    profile_ids: Vec<String>,
    chart: bool,
}
impl ArtifactTree {
    /// Native generation findings, including explicit opaque/observation outcomes.
    #[must_use]
    pub fn native_findings(&self) -> &[crate::Finding] {
        &self.native_findings
    }
    /// Safe format lifecycle/provenance findings.
    #[must_use]
    pub fn findings(&self) -> &[FormatCode] {
        &self.findings
    }
    /// Declared exact rendering profiles; native conformance remains pending.
    #[must_use]
    pub fn profile_ids(&self) -> &[String] {
        &self.profile_ids
    }
    /// Caller-authorized private regular files and their relative paths.
    pub fn files<'a>(&'a self, _access: &ExplicitArtifactAccess) -> impl Iterator<Item = (&'a str, &'a [u8])> {
        self.files.iter().map(|(p, b)| (p.as_str(), b.as_slice()))
    }
    fn snapshot(&self) -> Result<ProjectSnapshot> {
        let provenance = RenderProvenance::new(
            b"KubernetesLens native generated intent; source reconstruction and native execution not established",
        )?;
        ProjectSnapshot::new(
            self.files
                .iter()
                .map(|(p, b)| LocalFile::new(p.clone(), b.clone(), provenance.clone()))
                .collect(),
            ProjectLimits::default(),
        )
    }
    /// Plan strict lint or local packaging using exact ledger commands, without executing either.
    /// # Errors
    /// Rejects non-chart trees, undeclared profiles and other command classes.
    pub fn plan_chart_validation(
        &self,
        command: RenderCommand,
        tool: ToolSelection,
        bounds: ExecutionBounds,
    ) -> Result<RenderRequest> {
        if !self.chart
            || !self.profile_ids.contains(&tool.profile)
            || !matches!(command, RenderCommand::HelmLint | RenderCommand::HelmPackage)
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        RenderRequest::new(
            command,
            tool,
            self.snapshot()?,
            &BTreeMap::from([
                ("{GENERATED_CHART}", "./.".into()),
                ("{OWNED_PACKAGE_DIR}", "./packages".into()),
            ]),
            Vec::new(),
            bounds,
            self.findings.clone(),
        )
    }
    /// Plan generated chart rendering; values are this tree's finite values.yaml, not ambient input.
    /// # Errors
    /// Refuses mismatched chart/values paths, profiles or invalid capabilities.
    pub fn plan_chart_render(
        &self,
        tool: ToolSelection,
        context: &HelmContext,
        bounds: ExecutionBounds,
    ) -> Result<RenderRequest> {
        if !self.chart
            || !self.profile_ids.contains(&tool.profile)
            || context.chart != "."
            || context.values != "values.yaml"
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        let mut request = super::plan_helm(self.snapshot()?, tool, context, bounds)?;
        // Generated-template has the same reviewed literal arguments, with distinct evidence row.
        let generated = RenderCommand::HelmGeneratedTemplate.row()?;
        let source = RenderCommand::HelmTemplate.row()?;
        let args = |r: &serde_json::Value| {
            r["literal_argv"].as_array().map(|a| {
                a.iter()
                    .map(|s| {
                        s.as_str().map(|s| {
                            s.replace("GENERATED_CHART", "LOCAL_CHART")
                                .replace("GENERATED_VALUES", "LOCAL_VALUES")
                        })
                    })
                    .collect::<Vec<_>>()
            })
        };
        if args(generated) != args(source) {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        request.command = RenderCommand::HelmGeneratedTemplate;
        Ok(request)
    }
    /// Plan a generated base or explicit overlay build, without invocation or file writes.
    /// # Errors
    /// Rejects chart trees, undeclared renderer profiles and invalid local projects.
    pub fn plan_kustomize(&self, tool: ToolSelection, project: &str, bounds: ExecutionBounds) -> Result<RenderRequest> {
        if self.chart || !self.profile_ids.contains(&tool.profile) {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        super::plan_kustomize(self.snapshot()?, tool, project, bounds)
    }
}
impl fmt::Debug for ArtifactTree {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ArtifactTree")
            .field("file_count", &self.files.len())
            .field("profile_ids", &self.profile_ids)
            .field("findings", &self.findings)
            .field("native_findings", &self.native_findings)
            .finish_non_exhaustive()
    }
}
fn safe_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 63
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !value.starts_with('-')
        && !value.ends_with('-')
}
fn parameter_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 32
        && value.as_bytes()[0].is_ascii_lowercase()
        && value
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'_')
}
fn profiles(command: RenderCommand, ids: &[String]) -> Result<()> {
    if ids.is_empty() || ids.len() > 8 {
        return Err(FormatError::new(FormatCode::InvalidProfile));
    }
    let mut unique = BTreeSet::new();
    for id in ids {
        if !unique.insert(id)
            || !command.row()?["profile_ids"]
                .as_array()
                .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(id)))
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
    }
    Ok(())
}
fn trees(
    resources: &ResourceSet,
    target: &TargetProfile,
    options: &GenerationOptions,
    processing: &NativeOperationBudget,
) -> Result<(crate::parser::ParsedInput, Vec<ResourceId>, Vec<crate::Finding>)> {
    let (artifact, ids) =
        generation::generate_associated_in(resources, target, OutputFormat::Yaml, options, processing)
            .map_err(FormatError::native)?;
    let native_findings = artifact.findings().to_vec();
    let limits = inherited_limits(resources, processing);
    let input = parsed_in(
        artifact.reveal_bytes(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
        SourceId(0),
        &limits,
        processing,
    )?;
    if input.trees.len() != ids.len()
        || ids.len() != resources.documents().len()
        || !resources.lists().is_empty() && options.collections != generation::CollectionOutput::Flatten
    {
        return Err(FormatError::new(FormatCode::UnsupportedVariation));
    }
    Ok((input, ids, native_findings))
}
fn inherited_limits(resources: &ResourceSet, processing: &NativeOperationBudget) -> ParseLimits {
    let mut limits = ParseLimits::default();
    for source in resources.sources() {
        let source = source.limits();
        limits.max_input_bytes = limits.max_input_bytes.min(source.max_input_bytes);
        limits.max_documents = limits.max_documents.min(source.max_documents);
        limits.max_events = limits.max_events.min(source.max_events);
        limits.max_nodes = limits.max_nodes.min(source.max_nodes);
        limits.max_depth = limits.max_depth.min(source.max_depth);
        limits.max_scalar_bytes = limits.max_scalar_bytes.min(source.max_scalar_bytes);
        limits.max_aliases = limits.max_aliases.min(source.max_aliases);
        limits.max_alias_visits = limits.max_alias_visits.min(source.max_alias_visits);
    }
    limits.processing = processing.limits();
    limits
}
fn parsed_in(
    bytes: &[u8],
    id: SourceId,
    limits: &ParseLimits,
    processing: &NativeOperationBudget,
) -> Result<crate::parser::ParsedInput> {
    crate::parser::parse_source_in(
        crate::source::SourceInput {
            id,
            format: crate::source::DocumentFormat::YamlStream,
            origin: InputOrigin::Authored,
            source_version: None,
            bytes,
        },
        limits,
        processing,
    )
    .map_err(FormatError::native)
}
fn encoded(tree: &TreeNode, input: &crate::parser::ParsedInput) -> Result<Vec<u8>> {
    EncodingBudget::in_operation(
        AuthoringLimits {
            parser: input.limits,
            ..AuthoringLimits::default()
        },
        input.processing.clone(),
    )
    .snapshot(tree)
    .map_err(|e| FormatError::native(vec![e]))
}
fn typed_workload(api: Option<&str>, kind: &str, document: &crate::model::ResourceDocument) -> bool {
    use crate::resources::workloads::{
        CronJobV1, CronJobV1Beta1, DaemonSet, Deployment, Job, Pod, ReplicaSet, ReplicationController, StatefulSet,
    };
    match (api, kind) {
        (Some("v1"), "Pod") => document.resource::<Pod>().is_some(),
        (Some("v1"), "ReplicationController") => document.resource::<ReplicationController>().is_some(),
        (Some("apps/v1"), "Deployment") => document.resource::<Deployment>().is_some(),
        (Some("apps/v1"), "StatefulSet") => document.resource::<StatefulSet>().is_some(),
        (Some("apps/v1"), "DaemonSet") => document.resource::<DaemonSet>().is_some(),
        (Some("apps/v1"), "ReplicaSet") => document.resource::<ReplicaSet>().is_some(),
        (Some("batch/v1"), "Job") => document.resource::<Job>().is_some(),
        (Some("batch/v1"), "CronJob") => document.resource::<CronJobV1>().is_some(),
        (Some("batch/v1beta1"), "CronJob") => document.resource::<CronJobV1Beta1>().is_some(),
        _ => false,
    }
}
fn field_path(
    tree: &TreeNode,
    document: &crate::model::ResourceDocument,
    field: &WorkloadField,
) -> Result<Vec<String>> {
    let kind = tree
        .get("kind")
        .and_then(TreeNode::as_str)
        .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
    if !typed_workload(tree.get("apiVersion").and_then(TreeNode::as_str), kind, document) {
        return Err(FormatError::new(FormatCode::UnsupportedVariation));
    }
    if *field == WorkloadField::Replicas {
        if !["Deployment", "StatefulSet", "ReplicaSet", "ReplicationController"].contains(&kind) {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        return Ok(vec!["spec".into(), "replicas".into()]);
    }
    let prefix = match kind {
        "Pod" => "/spec",
        "CronJob" => "/spec/jobTemplate/spec/template/spec",
        "Deployment" | "StatefulSet" | "DaemonSet" | "ReplicaSet" | "ReplicationController" | "Job" => {
            "/spec/template/spec"
        }
        _ => return Err(FormatError::new(FormatCode::UnsupportedVariation)),
    };
    let mut parts: Vec<String> = prefix.trim_start_matches('/').split('/').map(str::to_string).collect();
    let container = match field {
        WorkloadField::Image { container } | WorkloadField::Quantity { container, .. } => container,
        WorkloadField::Replicas => return Err(FormatError::new(FormatCode::UnsupportedVariation)),
    };
    let mut node = tree;
    for p in &parts {
        node = node
            .get(p)
            .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
    }
    let containers = node
        .get("containers")
        .and_then(TreeNode::as_sequence)
        .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
    let matches: Vec<_> = containers
        .iter()
        .enumerate()
        .filter(|(_, c)| c.get("name").and_then(TreeNode::as_str) == Some(container))
        .collect();
    if matches.len() != 1 {
        return Err(FormatError::new(FormatCode::UnsupportedVariation));
    }
    parts.extend(["containers".into(), matches[0].0.to_string()]);
    match field {
        WorkloadField::Image { .. } => parts.push("image".into()),
        WorkloadField::Quantity { side, resource, .. } => parts.extend([
            "resources".into(),
            match side {
                ResourceSide::Requests => "requests",
                ResourceSide::Limits => "limits",
            }
            .into(),
            match resource {
                ResourceQuantity::Cpu => "cpu",
                ResourceQuantity::Memory => "memory",
                ResourceQuantity::EphemeralStorage => "ephemeral-storage",
            }
            .into(),
        ]),
        WorkloadField::Replicas => (),
    }
    Ok(parts)
}
fn at<'a>(mut node: &'a TreeNode, parts: &[String]) -> Result<&'a TreeNode> {
    for part in parts {
        node = if let Some(a) = node.as_sequence() {
            part.parse::<usize>().ok().and_then(|i| a.get(i))
        } else {
            node.get(part)
        }
        .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
    }
    Ok(node)
}
fn resource_index(resources: &ResourceSet, id: ResourceId) -> Result<usize> {
    resources
        .documents()
        .iter()
        .position(|d| d.id() == id)
        .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))
}
fn generated_index(ids: &[ResourceId], id: ResourceId, processing: &NativeOperationBudget) -> Result<usize> {
    processing
        .work(ids.len(), Phase::Generation)
        .map_err(|finding| FormatError::native(vec![finding]))?;
    ids.iter()
        .position(|candidate| *candidate == id)
        .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))
}
fn artifact(
    files: BTreeMap<String, Vec<u8>>,
    findings: Vec<FormatCode>,
    native_findings: Vec<crate::Finding>,
    profile_ids: Vec<String>,
    chart: bool,
) -> Result<ArtifactTree> {
    let total = files.values().try_fold(0usize, |v, b| {
        v.checked_add(b.len())
            .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))
    })?;
    if total > ProjectLimits::default().bytes || files.len() > ProjectLimits::default().files {
        return Err(FormatError::new(FormatCode::LimitExceeded));
    }
    Ok(ArtifactTree {
        files,
        findings,
        native_findings,
        profile_ids,
        chart,
    })
}
/// Generate a new chart with finite explicit values, safe literal data and separate CRD/hook policy.
/// # Errors
/// Propagates native target/privacy/unknown conflicts and rejects unsafe/unsupported selected values.
pub fn generate_chart(
    resources: &ResourceSet,
    target: &TargetProfile,
    options: &GenerationOptions,
    chart: &HelmChartOptions,
    profile_ids: Vec<String>,
) -> Result<ArtifactTree> {
    profiles(RenderCommand::HelmTemplate, &profile_ids)?;
    if !safe_name(&chart.name)
        || chart.version.split('.').count() != 3
        || chart.version.split('.').any(|p| {
            !p.bytes().all(|byte| byte.is_ascii_digit())
                || p.parse::<u32>().is_err()
                || p.len() > 1 && p.starts_with('0')
        })
        || chart.parameters.len() > 64
    {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    let processing = resources.operation(options.processing);
    let (input, ids, native_findings) = trees(resources, target, options, &processing)?;
    let mut selected = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut values = Vec::new();
    let mut properties = serde_json::Map::new();
    for parameter in &chart.parameters {
        if !parameter_name(&parameter.name) || !names.insert(&parameter.name) {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        let document_index = resource_index(resources, parameter.resource)?;
        let index = generated_index(&ids, parameter.resource, &processing)?;
        let path = field_path(
            &input.trees[index],
            &resources.documents()[document_index],
            &parameter.field,
        )?;
        let value = at(&input.trees[index], &path)?;
        if value.as_str().is_some_and(|v| v.is_empty() || v.len() > 1024) {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        match (&parameter.field, &value.value) {
            (WorkloadField::Replicas, TreeValue::Number(_))
            | (WorkloadField::Image { .. } | WorkloadField::Quantity { .. }, TreeValue::String(_)) => (),
            _ => return Err(FormatError::new(FormatCode::UnsupportedVariation)),
        }
        if selected.insert((index, path), parameter.name.clone()).is_some() {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        values.push((parameter.name.clone(), value.clone()));
        properties.insert(
            parameter.name.clone(),
            if parameter.field == WorkloadField::Replicas {
                serde_json::json!({"type":"integer","minimum":0,"maximum":i32::MAX})
            } else {
                serde_json::json!({"type":"string","minLength":1,"maxLength":1024})
            },
        );
    }
    let mut findings = vec![FormatCode::ProvenanceLimited];
    let mut files = BTreeMap::new();
    let api = ledger()?["input_output_contracts"]["helm_values_v1"]["chart_api_version"]
        .as_str()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?;
    files.insert(
        "Chart.yaml".into(),
        yaml(&serde_json::json!({"apiVersion":api,"name":chart.name,"version":chart.version,"type":"application"}))?,
    );
    files.insert("values.yaml".into(), {
        let mut out = b"---\n".to_vec();
        out.extend(encoded(&TreeNode::mapping(values), &input)?);
        out.push(b'\n');
        out
    });
    files.insert("values.schema.json".into(), json(&serde_json::json!({"$schema":"http://json-schema.org/draft-07/schema#","type":"object","additionalProperties":false,"required":names,"properties":properties}))?);
    for (index, tree) in input.trees.iter().enumerate() {
        lifecycle(tree, &mut findings);
        if findings.contains(&FormatCode::HookLifecycle) && chart.hooks == HookPolicy::Reject {
            return Err(FormatError::new(FormatCode::UnsupportedExtension));
        }
        let crd = tree.get("kind").and_then(TreeNode::as_str) == Some("CustomResourceDefinition");
        let mut out = b"---\n".to_vec();
        if crd {
            out.extend(encoded(tree, &input)?);
        } else {
            template(tree, index, &mut Vec::new(), &selected, &mut out, &input)?;
        }
        out.push(b'\n');
        files.insert(
            format!("{}/{index:04}.yaml", if crd { "crds" } else { "templates" }),
            out,
        );
    }
    artifact(files, findings, native_findings, profile_ids, true)
}
fn template(
    tree: &TreeNode,
    index: usize,
    path: &mut Vec<String>,
    selected: &BTreeMap<(usize, Vec<String>), String>,
    out: &mut Vec<u8>,
    input: &crate::parser::ParsedInput,
) -> Result<()> {
    if let Some(name) = selected.get(&(index, path.clone())) {
        out.extend(format!("{{{{ .Values.{name} | toJson }}}}").as_bytes());
        return Ok(());
    }
    match &tree.value {
        TreeValue::Mapping(entries) => {
            out.push(b'{');
            for (i, (key, value)) in entries.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                literal(&TreeNode::string(key), out, input)?;
                out.push(b':');
                path.push(key.clone());
                template(value, index, path, selected, out, input)?;
                path.pop();
            }
            out.push(b'}');
        }
        TreeValue::Sequence(items) => {
            out.push(b'[');
            for (i, value) in items.iter().enumerate() {
                if i > 0 {
                    out.push(b',');
                }
                path.push(i.to_string());
                template(value, index, path, selected, out, input)?;
                path.pop();
            }
            out.push(b']');
        }
        _ => literal(tree, out, input)?,
    }
    if out.len() > ProjectLimits::default().bytes {
        return Err(FormatError::new(FormatCode::LimitExceeded));
    }
    Ok(())
}
fn literal(tree: &TreeNode, out: &mut Vec<u8>, input: &crate::parser::ParsedInput) -> Result<()> {
    // Serialize JSON data first, then quote it as one Go string argument. Delimiters inside that
    // argument are data and cannot become directives, including keys and unknown private values.
    let raw = encoded(tree, input)?;
    let text = std::str::from_utf8(&raw).map_err(|_| FormatError::new(FormatCode::InvalidProject))?;
    let quoted = serde_json::to_string(text).map_err(|_| FormatError::new(FormatCode::InvalidProject))?;
    out.extend(format!("{{{{ print {quoted} }}}}").as_bytes());
    Ok(())
}
/// Generate a reusable local base and only explicitly requested finite native overlays.
/// # Errors
/// Refuses undeclared renderer profiles, unsupported field edits, invalid targets and privacy loss.
pub fn generate_kustomize(
    resources: &ResourceSet,
    target: &TargetProfile,
    options: &GenerationOptions,
    overlays: &[KustomizeOverlay],
    profile_ids: Vec<String>,
) -> Result<ArtifactTree> {
    if profile_ids.is_empty() || profile_ids.len() > 8 {
        return Err(FormatError::new(FormatCode::InvalidProfile));
    }
    let mut unique = BTreeSet::new();
    for profile in &profile_ids {
        if !unique.insert(profile)
            || profiles(
                if profile.starts_with("kubectl-") {
                    RenderCommand::KubectlKustomize
                } else {
                    RenderCommand::KustomizeBuild
                },
                std::slice::from_ref(profile),
            )
            .is_err()
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
    }
    if overlays.len() > 16 {
        return Err(FormatError::new(FormatCode::LimitExceeded));
    }
    let processing = resources.operation(options.processing);
    let (input, ids, mut native_findings) = trees(resources, target, options, &processing)?;
    let mut files = BTreeMap::new();
    let mut format_findings = vec![FormatCode::ProvenanceLimited];
    let mut base = b"---\n".to_vec();
    for (index, tree) in input.trees.iter().enumerate() {
        lifecycle(tree, &mut format_findings);
        if index > 0 {
            base.extend(b"---\n");
        }
        base.extend(encoded(tree, &input)?);
        base.push(b'\n');
    }
    processing
        .payload(base.len(), Phase::Generation)
        .map_err(|e| FormatError::native(vec![e]))?;
    files.insert("base/resources.yaml".into(), base.clone());
    files.insert("base/kustomization.yaml".into(), yaml(&serde_json::json!({"apiVersion":"kustomize.config.k8s.io/v1beta1","kind":"Kustomization","resources":["resources.yaml"]}))?);
    let mut names = BTreeSet::new();
    for overlay in overlays {
        if !safe_name(&overlay.name)
            || !names.insert(&overlay.name)
            || overlay.variations.is_empty()
            || overlay.variations.len() > 64
        {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        let (patches, outcomes) = overlay_patch(resources, target, options, overlay, &input, &ids, &base)?;
        native_findings.extend(outcomes);
        files.insert(format!("overlays/{}/patches.yaml", overlay.name), patches);
        files.insert(format!("overlays/{}/kustomization.yaml", overlay.name), yaml(&serde_json::json!({"apiVersion":"kustomize.config.k8s.io/v1beta1","kind":"Kustomization","resources":["../../base"],"patchesStrategicMerge":["patches.yaml"]}))?);
    }
    artifact(files, format_findings, native_findings, profile_ids, false)
}
fn overlay_patch(
    resources: &ResourceSet,
    target: &TargetProfile,
    options: &GenerationOptions,
    overlay: &KustomizeOverlay,
    input: &crate::parser::ParsedInput,
    ids: &[ResourceId],
    base: &[u8],
) -> Result<(Vec<u8>, Vec<crate::Finding>)> {
    let mut changed = parsed_in(base, SourceId(0), &input.limits, &input.processing)?
        .flatten_resources()
        .map_err(FormatError::native)?;
    let mut patch_by_resource: BTreeMap<usize, TreeNode> = BTreeMap::new();
    let mut selected = BTreeSet::new();
    for variation in &overlay.variations {
        let document_index = resource_index(resources, variation.resource)?;
        let index = generated_index(ids, variation.resource, &input.processing)?;
        let tree = &input.trees[index];
        let path = field_path(tree, &resources.documents()[document_index], &variation.field)?;
        at(tree, &path)?;
        if !selected.insert((index, path.clone())) {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        }
        let value = variation.value.tree(&variation.field)?;
        let raw = encoded(&value, input)?;
        let edit = parsed_in(&raw, SourceId(1), &input.limits, &input.processing)?;
        let pointer = path.iter().fold(String::new(), |mut pointer, component| {
            pointer.push('/');
            pointer.push_str(&component.replace('~', "~0").replace('/', "~1"));
            pointer
        });
        changed
            .documents_mut()
            .get_mut(index)
            .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?
            .set_field_from_source(
                FieldPath::parse(&pointer).map_err(|e| FormatError::native(vec![e]))?,
                edit,
            )
            .map_err(|e| FormatError::native(vec![e]))?;
        let delta = patch_by_resource.entry(index).or_insert_with(|| {
            let metadata = tree.get("metadata");
            let mut identity = Vec::new();
            for key in ["name", "namespace"] {
                if let Some(value) = metadata.and_then(|m| m.get(key)) {
                    identity.push((key.into(), value.clone()));
                }
            }
            TreeNode::mapping(vec![
                (
                    "apiVersion".into(),
                    tree.get("apiVersion").cloned().unwrap_or_else(|| TreeNode::string("")),
                ),
                (
                    "kind".into(),
                    tree.get("kind").cloned().unwrap_or_else(|| TreeNode::string("")),
                ),
                ("metadata".into(), TreeNode::mapping(identity)),
            ])
        });
        patch_field(delta, &path, &value, tree)?;
    }
    let checked = generation::generate_in(&changed, target, OutputFormat::Yaml, options, &input.processing)
        .map_err(FormatError::native)?;
    let native_findings = checked.findings().to_vec();
    let mut patches = b"---\n".to_vec();
    for (i, patch) in patch_by_resource.values().enumerate() {
        if i > 0 {
            patches.extend(b"---\n");
        }
        patches.extend(encoded(patch, input)?);
        patches.push(b'\n');
    }
    Ok((patches, native_findings))
}

fn patch_field(patch: &mut TreeNode, segments: &[String], value: &TreeNode, original: &TreeNode) -> Result<()> {
    let Some((first, rest)) = segments.split_first() else {
        *patch = value.clone();
        return Ok(());
    };
    if let Ok(index) = first.parse::<usize>() {
        let original_item = original
            .as_sequence()
            .and_then(|a| a.get(index))
            .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
        let name = original_item
            .get("name")
            .cloned()
            .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?;
        if !matches!(patch.value, TreeValue::Sequence(_)) {
            patch.value = TreeValue::Sequence(Vec::new());
        }
        let TreeValue::Sequence(items) = &mut patch.value else {
            return Err(FormatError::new(FormatCode::UnsupportedVariation));
        };
        let position = items
            .iter()
            .position(|n| n.get("name") == Some(&name))
            .unwrap_or(items.len());
        if position == items.len() {
            items.push(TreeNode::mapping(vec![("name".into(), name)]));
        }
        return patch_field(&mut items[position], rest, value, original_item);
    }
    if !matches!(patch.value, TreeValue::Mapping(_)) {
        patch.value = TreeValue::Mapping(Vec::new());
    }
    let TreeValue::Mapping(entries) = &mut patch.value else {
        return Err(FormatError::new(FormatCode::UnsupportedVariation));
    };
    let position = entries.iter().position(|(k, _)| k == first).unwrap_or(entries.len());
    if position == entries.len() {
        entries.push((first.clone(), TreeNode::mapping(Vec::new())));
    }
    patch_field(
        &mut entries[position].1,
        rest,
        value,
        original
            .get(first)
            .ok_or_else(|| FormatError::new(FormatCode::UnsupportedVariation))?,
    )
}
