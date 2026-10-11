use super::{
    ExecutionBounds, FormatCode, FormatError, OfflineRenderer, RenderCommand, RenderRequest, RendererStatus, Result,
    ToolSelection,
};
use crate::{
    model::ResourceSet,
    parser::{ParsedInput, parse_source},
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
    syntax::TreeNode,
};
use std::{
    collections::{BTreeMap, BTreeSet},
    fmt,
};

/// Opaque caller-supplied revision/digest/values/dependency evidence; never a verification boolean.
#[derive(Clone)]
pub struct RenderProvenance(pub(crate) Vec<u8>);
impl RenderProvenance {
    /// Retain a bounded caller evidence record. This does not authenticate its assertions.
    /// # Errors
    /// Rejects empty or oversized records.
    pub fn new(bytes: &[u8]) -> Result<Self> {
        if bytes.is_empty() || bytes.len() > 4096 {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        Ok(Self(bytes.to_vec()))
    }
    /// Reveal caller evidence only explicitly.
    #[must_use]
    pub fn reveal(&self, _access: &ExplicitSourceAccess) -> &[u8] {
        &self.0
    }
}
impl fmt::Debug for RenderProvenance {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderProvenance")
            .field("byte_len", &self.0.len())
            .finish_non_exhaustive()
    }
}
/// A caller-materialized regular file, never a symlink, remote acquisition or filesystem handle.
pub struct LocalFile {
    pub(crate) path: String,
    pub(crate) bytes: Vec<u8>,
    pub(crate) provenance: RenderProvenance,
}
impl LocalFile {
    /// Supply a private relative file and its independently supplied provenance.
    #[must_use]
    pub fn new(path: String, bytes: Vec<u8>, provenance: RenderProvenance) -> Self {
        Self {
            path,
            bytes,
            provenance,
        }
    }
}
impl fmt::Debug for LocalFile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("LocalFile")
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
/// Finite project snapshot ceilings; callers can lower but cannot raise default ceilings.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ProjectLimits {
    /// Total regular files, including dependencies and values.
    pub files: usize,
    /// Cumulative source, path and provenance bytes.
    pub bytes: usize,
    /// Maximum path bytes.
    pub path_bytes: usize,
    /// Cumulative dependency/reference traversal operations.
    pub references: usize,
}
impl Default for ProjectLimits {
    fn default() -> Self {
        Self {
            files: 256,
            bytes: 16 * 1024 * 1024,
            path_bytes: 1024,
            references: 4096,
        }
    }
}
/// Immutable private caller snapshot. Unused supplied files remain retained source evidence.
pub struct ProjectSnapshot {
    pub(crate) files: BTreeMap<String, LocalFile>,
    limits: ProjectLimits,
    processing: crate::processing::NativeOperationBudget,
}
impl ProjectSnapshot {
    /// Validate unique bounded relative regular-file entries without reading any filesystem.
    /// # Errors
    /// Rejects ambiguous/escaping paths, duplicate entries and cumulative budget exhaustion.
    pub fn new(files: Vec<LocalFile>, limits: ProjectLimits) -> Result<Self> {
        let ceiling = ProjectLimits::default();
        if limits.files == 0
            || limits.files > ceiling.files
            || limits.bytes == 0
            || limits.bytes > ceiling.bytes
            || limits.path_bytes == 0
            || limits.path_bytes > ceiling.path_bytes
            || limits.references == 0
            || limits.references > ceiling.references
            || files.is_empty()
            || files.len() > limits.files
        {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        let mut total = 0usize;
        let mut stored = BTreeMap::new();
        for file in files {
            if file.path.len() > limits.path_bytes {
                return Err(FormatError::new(FormatCode::LimitExceeded));
            }
            if normalize("", &file.path)? != file.path || file.path.split('/').any(|p| p.starts_with('-')) {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
            total = total
                .checked_add(file.bytes.len())
                .and_then(|v| v.checked_add(file.path.len()))
                .and_then(|v| v.checked_add(file.provenance.0.len()))
                .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
            if total > limits.bytes {
                return Err(FormatError::new(FormatCode::LimitExceeded));
            }
            if stored.insert(file.path.clone(), file).is_some() {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
        }
        for path in stored.keys() {
            let mut prefix = path.as_str();
            while let Some((parent, _)) = prefix.rsplit_once('/') {
                if stored.contains_key(parent) {
                    return Err(FormatError::new(FormatCode::InvalidProject));
                }
                prefix = parent;
            }
        }
        Ok(Self {
            files: stored,
            limits,
            processing: crate::processing::NativeOperationBudget::new(
                crate::processing::NativeProcessingLimits::default(),
            ),
        })
    }
    /// Retained relative paths, file bytes and per-file provenance require explicit private access.
    pub fn files<'a>(
        &'a self,
        _access: &ExplicitSourceAccess,
    ) -> impl Iterator<Item = (&'a str, &'a [u8], &'a RenderProvenance)> {
        self.files
            .values()
            .map(|f| (f.path.as_str(), f.bytes.as_slice(), &f.provenance))
    }
    pub(crate) fn get(&self, path: &str) -> Result<&LocalFile> {
        self.files
            .get(path)
            .ok_or_else(|| FormatError::new(FormatCode::MissingInput))
    }
    pub(crate) fn parsed(&self, path: &str) -> Result<ParsedInput> {
        crate::parser::parse_source_in(
            SourceInput {
                id: SourceId(0),
                format: DocumentFormat::YamlStream,
                origin: InputOrigin::CallerSupplied,
                source_version: None,
                bytes: &self.get(path)?.bytes,
            },
            &ParseLimits::default(),
            &self.processing,
        )
        .map_err(FormatError::native)
    }
}
impl fmt::Debug for ProjectSnapshot {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ProjectSnapshot")
            .field("file_count", &self.files.len())
            .field("limits", &self.limits)
            .finish_non_exhaustive()
    }
}
pub(crate) fn normalize(base: &str, path: &str) -> Result<String> {
    if path.contains("://") || path.starts_with("git@") {
        return Err(FormatError::new(FormatCode::NetworkRequired));
    }
    if path.is_empty() || path.starts_with('/') || path.contains(['\\', '\0', ':', '?', '#']) {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    let mut parts: Vec<&str> = if base.is_empty() {
        Vec::new()
    } else {
        base.split('/').collect()
    };
    for p in path.split('/') {
        match p {
            "." => (),
            ".." => {
                parts
                    .pop()
                    .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
            }
            "" => return Err(FormatError::new(FormatCode::InvalidProject)),
            _ => parts.push(p),
        }
    }
    Ok(parts.join("/"))
}
fn directory(path: &str) -> Result<String> {
    if path == "." {
        Ok(String::new())
    } else {
        normalize("", path)
    }
}
fn joined(base: &str, path: &str) -> Result<String> {
    normalize(base, path)
}
fn single(input: &ParsedInput) -> Result<&TreeNode> {
    if input.trees.len() != 1 {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    let tree = &input.trees[0];
    if tree.as_mapping().is_none() {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    Ok(tree)
}
fn texts(node: &TreeNode) -> Result<Vec<&str>> {
    node.as_sequence()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
        .iter()
        .map(|n| n.as_str().ok_or_else(|| FormatError::new(FormatCode::InvalidProject)))
        .collect()
}
/// Supplied producer category; Helm release exports remain caller-only artifacts.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderedKind {
    /// Ordinary native manifests.
    Manifest,
    /// Supplied local Helm template stdout.
    HelmTemplate,
    /// Supplied `helm get manifest` output, never acquired by this library.
    HelmReleaseManifest,
    /// Supplied `helm get hooks` output, never acquired or executed by this library.
    HelmReleaseHooks,
    /// Supplied standalone or embedded Kustomize build output.
    Kustomize,
}
/// Native resources plus immutable private producer/project evidence and explicit semantic limits.
pub struct ImportedManifest {
    resources: ResourceSet,
    provenance: RenderProvenance,
    kind: RenderedKind,
    findings: Vec<FormatCode>,
    request: Option<RenderRequest>,
    output: Option<super::RendererOutput>,
}
impl ImportedManifest {
    /// Existing native resources, with original parser evidence intact.
    #[must_use]
    pub const fn resources(&self) -> &ResourceSet {
        &self.resources
    }
    /// Mutate the native typed view without replacing producer/source evidence.
    pub fn resources_mut(&mut self) -> &mut ResourceSet {
        &mut self.resources
    }
    /// Protected caller producer provenance.
    #[must_use]
    pub const fn provenance(&self) -> &RenderProvenance {
        &self.provenance
    }
    /// Declared producer category, not inferred from annotations.
    #[must_use]
    pub const fn kind(&self) -> RenderedKind {
        self.kind
    }
    /// Safe lifecycle/provenance limitations, separate from native validation findings.
    #[must_use]
    pub fn findings(&self) -> &[FormatCode] {
        &self.findings
    }
    /// Retained invocation/snapshot if an executor was explicitly selected.
    #[must_use]
    pub const fn request(&self) -> Option<&RenderRequest> {
        self.request.as_ref()
    }
    /// Retained native stdout/stderr from explicit execution require private artifact access.
    #[must_use]
    pub fn renderer_output(
        &self,
        _access: &crate::generation::ExplicitArtifactAccess,
    ) -> Option<&super::RendererOutput> {
        self.output.as_ref()
    }
}
impl fmt::Debug for ImportedManifest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ImportedManifest")
            .field("resources", &self.resources)
            .field("kind", &self.kind)
            .field("findings", &self.findings)
            .finish_non_exhaustive()
    }
}
/// Import supplied rendered/native documents through the existing strict native resource model.
/// # Errors
/// Propagates bounded parsing, duplicate identity and malformed native-resource failures.
pub fn import_rendered(
    mut input: SourceInput<'_>,
    limits: &ParseLimits,
    kind: RenderedKind,
    provenance: RenderProvenance,
) -> Result<ImportedManifest> {
    input.origin = match kind {
        RenderedKind::HelmTemplate => InputOrigin::HelmRendered,
        RenderedKind::HelmReleaseManifest | RenderedKind::HelmReleaseHooks => InputOrigin::ClusterExport,
        _ => input.origin,
    };
    let parsed = parse_source(input, limits).map_err(FormatError::native)?;
    let mut findings = vec![FormatCode::ProvenanceLimited];
    if kind == RenderedKind::HelmReleaseHooks {
        findings.push(FormatCode::HookLifecycle);
    }
    for tree in &parsed.trees {
        lifecycle(tree, &mut findings);
    }
    let resources = ResourceSet::from_inputs(vec![parsed]).map_err(FormatError::native)?;
    Ok(ImportedManifest {
        resources,
        provenance,
        kind,
        findings,
        request: None,
        output: None,
    })
}
pub(crate) fn lifecycle(tree: &TreeNode, findings: &mut Vec<FormatCode>) {
    if tree
        .get("metadata")
        .and_then(|m| m.get("annotations"))
        .and_then(|a| a.get("helm.sh/hook"))
        .is_some()
        && !findings.contains(&FormatCode::HookLifecycle)
    {
        findings.push(FormatCode::HookLifecycle);
    }
    if tree.get("kind").and_then(TreeNode::as_str) == Some("CustomResourceDefinition")
        && !findings.contains(&FormatCode::CrdLifecycle)
    {
        findings.push(FormatCode::CrdLifecycle);
    }
    if tree
        .get("kind")
        .and_then(TreeNode::as_str)
        .is_some_and(|k| k.ends_with("List"))
    {
        if let Some(items) = tree.get("items").and_then(TreeNode::as_sequence) {
            for item in items {
                lifecycle(item, findings);
            }
        }
    }
}
/// Explicit local chart values/capabilities and install/upgrade rendering context.
pub struct HelmContext {
    /// Local chart directory relative to the snapshot; `.` selects its root.
    pub chart: String,
    /// Supplied local values file, even when empty.
    pub values: String,
    /// Explicit release name, never used to install a release.
    pub release: String,
    /// Explicit rendering namespace.
    pub namespace: String,
    /// Explicit exact Kubernetes patch capability.
    pub kubernetes_patch: String,
    /// Repeated explicit API capabilities; no live discovery.
    pub api_versions: Vec<String>,
    /// Select upgrade template context; never execute an upgrade.
    pub upgrade: bool,
}
impl fmt::Debug for HelmContext {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("HelmContext")
            .field("upgrade", &self.upgrade)
            .field("api_version_count", &self.api_versions.len())
            .finish_non_exhaustive()
    }
}
fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 253
        && value.bytes().all(|b| b.is_ascii_alphanumeric() || b"-._/".contains(&b))
        && !value.starts_with('-')
}
/// Construct the exact frozen Helm template command using only a supplied local snapshot.
/// # Errors
/// Rejects missing dependencies/values, external paths, invalid capabilities and profile/budget mismatch.
pub fn plan_helm(
    snapshot: ProjectSnapshot,
    tool: ToolSelection,
    context: &HelmContext,
    bounds: ExecutionBounds,
) -> Result<RenderRequest> {
    let chart = directory(&context.chart)?;
    let values = joined("", &context.values)?;
    if !identifier(&context.release)
        || context.release.len() > 53
        || !identifier(&context.namespace)
        || context.namespace.len() > 63
        || context.api_versions.len() > 256
        || context.api_versions.iter().any(|v| !identifier(v))
    {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    let patch: Vec<_> = context.kubernetes_patch.split('.').collect();
    if patch.len() != 3
        || patch[0] != "1"
        || patch[2].parse::<u16>().is_err()
        || patch[1]
            .parse::<u8>()
            .ok()
            .and_then(|m| crate::capability::KubernetesVersion::new(1, m).ok())
            .is_none()
    {
        return Err(FormatError::new(FormatCode::InvalidProfile));
    }
    let values_file = snapshot.get(&values)?;
    if !values_file.bytes.iter().all(u8::is_ascii_whitespace) {
        single(&snapshot.parsed(&values)?)?;
    }
    let mut findings = vec![
        FormatCode::ProvenanceLimited,
        FormatCode::HookLifecycle,
        FormatCode::LookupIncomplete,
        FormatCode::NondeterministicRendering,
    ];
    let mut active = BTreeSet::new();
    let mut completed = BTreeSet::new();
    let mut remaining = snapshot.limits.references;
    inspect_chart(
        &snapshot,
        &chart,
        &mut active,
        &mut completed,
        &mut remaining,
        &mut findings,
    )?;
    let substitutions = BTreeMap::from([
        ("{RELEASE}", context.release.clone()),
        (
            "{LOCAL_CHART}",
            format!("./{}", if chart.is_empty() { "." } else { &chart }),
        ),
        ("{NAMESPACE}", context.namespace.clone()),
        ("{LOCAL_VALUES}", format!("./{values}")),
        ("{TARGET_PATCH}", context.kubernetes_patch.clone()),
    ]);
    let variations = RenderCommand::HelmTemplate.row()?["permitted_explicit_variations"]
        .as_array()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?;
    let variation = |name: &str| -> Result<&serde_json::Value> {
        variations
            .iter()
            .find(|v| v["name"] == name)
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))
    };
    let api_flag = variation("api-capabilities")?["argv_append"][0]
        .as_str()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?;
    let upgrade_flag = variation("upgrade-context")?["argv_append"][0]
        .as_str()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?;
    let mut append = Vec::new();
    for version in &context.api_versions {
        append.push(api_flag.into());
        append.push(version.clone());
    }
    if context.upgrade {
        append.push(upgrade_flag.into());
    }
    RenderRequest::new(
        RenderCommand::HelmTemplate,
        tool,
        snapshot,
        &substitutions,
        append,
        bounds,
        findings,
    )
}
fn inspect_chart(
    snapshot: &ProjectSnapshot,
    chart: &str,
    active: &mut BTreeSet<String>,
    completed: &mut BTreeSet<String>,
    remaining: &mut usize,
    findings: &mut Vec<FormatCode>,
) -> Result<()> {
    charge(remaining)?;
    if active.contains(chart) {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    if completed.contains(chart) {
        return Ok(());
    }
    active.insert(chart.into());
    let input = snapshot.parsed(&joined(chart, "Chart.yaml")?)?;
    let tree = single(&input)?;
    if tree.get("apiVersion").and_then(TreeNode::as_str) != Some("v2")
        || tree.get("name").and_then(TreeNode::as_str).is_none()
        || tree.get("version").and_then(TreeNode::as_str).is_none()
    {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    if let Some(dependencies) = tree.get("dependencies") {
        for dependency in dependencies
            .as_sequence()
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
        {
            let name = dependency
                .get("name")
                .and_then(TreeNode::as_str)
                .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
            if !identifier(name) || name.contains('/') {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
            // Only pre-materialized unpacked dependencies are admitted. Repository metadata grants no fetch authority.
            inspect_chart(
                snapshot,
                &joined(chart, &format!("charts/{name}"))?,
                active,
                completed,
                remaining,
                findings,
            )?;
        }
    }
    let prefix = if chart.is_empty() {
        String::new()
    } else {
        format!("{chart}/")
    };
    if snapshot.files.keys().any(|p| p.starts_with(&format!("{prefix}crds/"))) {
        findings.push(FormatCode::CrdLifecycle);
    }
    active.remove(chart);
    completed.insert(chart.into());
    Ok(())
}
/// Construct a separate standalone/embedded Kustomize build after bounded local reference inspection.
/// # Errors
/// Rejects remote references, missing inputs, unsupported plugins/inflation and ambiguous project files.
pub fn plan_kustomize(
    snapshot: ProjectSnapshot,
    tool: ToolSelection,
    project: &str,
    bounds: ExecutionBounds,
) -> Result<RenderRequest> {
    let project = directory(project)?;
    let mut visited = BTreeSet::new();
    let mut remaining = snapshot.limits.references;
    inspect_kustomization(&snapshot, &project, &mut visited, &mut remaining)?;
    let command = if tool.profile.starts_with("kubectl-") {
        RenderCommand::KubectlKustomize
    } else {
        RenderCommand::KustomizeBuild
    };
    let substitutions = BTreeMap::from([(
        "{LOCAL_PROJECT}",
        format!("./{}", if project.is_empty() { "." } else { &project }),
    )]);
    RenderRequest::new(
        command,
        tool,
        snapshot,
        &substitutions,
        Vec::new(),
        bounds,
        vec![FormatCode::ProvenanceLimited],
    )
}
fn charge(remaining: &mut usize) -> Result<()> {
    *remaining = remaining
        .checked_sub(1)
        .ok_or_else(|| FormatError::new(FormatCode::LimitExceeded))?;
    Ok(())
}
fn reference(
    snapshot: &ProjectSnapshot,
    base: &str,
    path: &str,
    visited: &mut BTreeSet<String>,
    remaining: &mut usize,
    recurse: bool,
) -> Result<()> {
    charge(remaining)?;
    let path = joined(base, path)?;
    if snapshot.files.contains_key(&path) {
        snapshot.parsed(&path)?;
        Ok(())
    } else if recurse {
        inspect_kustomization(snapshot, &path, visited, remaining)
    } else {
        Err(FormatError::new(FormatCode::MissingInput))
    }
}
fn inspect_kustomization(
    snapshot: &ProjectSnapshot,
    project: &str,
    visited: &mut BTreeSet<String>,
    remaining: &mut usize,
) -> Result<()> {
    charge(remaining)?;
    if !visited.insert(project.into()) {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    let paths: Vec<_> = ["kustomization.yaml", "kustomization.yml", "Kustomization"]
        .iter()
        .map(|p| joined(project, p))
        .collect::<Result<Vec<_>>>()?
        .into_iter()
        .filter(|p| snapshot.files.contains_key(p))
        .collect();
    if paths.len() != 1 {
        return Err(FormatError::new(FormatCode::MissingInput));
    }
    let input = snapshot.parsed(&paths[0])?;
    let tree = single(&input)?;
    for (key, node) in tree
        .as_mapping()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
    {
        charge(remaining)?;
        match key.as_str() {
            "resources" | "bases" | "patchesStrategicMerge" | "configurations" => {
                for path in texts(node)? {
                    reference(
                        snapshot,
                        project,
                        path,
                        visited,
                        remaining,
                        matches!(key.as_str(), "resources" | "bases"),
                    )?;
                }
            }
            "patches" | "patchesJson6902" => {
                for patch in node
                    .as_sequence()
                    .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
                {
                    if let Some(path) = patch.get("path") {
                        reference(
                            snapshot,
                            project,
                            path.as_str()
                                .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?,
                            visited,
                            remaining,
                            false,
                        )?;
                    } else if patch.get("patch").and_then(TreeNode::as_str).is_none() {
                        return Err(FormatError::new(FormatCode::InvalidProject));
                    }
                }
            }
            "vars" => {
                if tree
                    .get("apiVersion")
                    .and_then(TreeNode::as_str)
                    .is_some_and(|version| version != "kustomize.config.k8s.io/v1beta1")
                {
                    return Err(FormatError::new(FormatCode::UnsupportedExtension));
                }
                inspect_vars(node, remaining)?;
            }
            "configMapGenerator" | "secretGenerator" => {
                inspect_generators(snapshot, project, node, remaining)?;
            }
            "apiVersion" | "kind" | "namespace" | "namePrefix" | "nameSuffix" | "commonLabels"
            | "commonAnnotations" | "labels" | "annotations" | "images" | "replicas" | "generatorOptions" => (),
            _ => return Err(FormatError::new(FormatCode::UnsupportedExtension)),
        }
    }
    // Shared bases may legitimately recur on different branches; only active recursion is rejected.
    visited.remove(project);
    Ok(())
}
// Inspect generator file references using the same cumulative project allowance.
fn inspect_generators(snapshot: &ProjectSnapshot, project: &str, node: &TreeNode, remaining: &mut usize) -> Result<()> {
    for generator in node
        .as_sequence()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
    {
        for (name, value) in generator
            .as_mapping()
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
        {
            charge(remaining)?;
            match name.as_str() {
                "files" | "envs" => {
                    for path in texts(value)? {
                        charge(remaining)?;
                        let path = if name == "files" {
                            path.split_once('=').map_or(path, |(_, p)| p)
                        } else {
                            path
                        };
                        snapshot.get(&joined(project, path)?)?;
                    }
                }
                "env" => {
                    charge(remaining)?;
                    snapshot.get(&joined(
                        project,
                        value
                            .as_str()
                            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?,
                    )?)?;
                }
                "name" | "namespace" | "type" | "behavior" | "literals" | "options" => (),
                _ => return Err(FormatError::new(FormatCode::UnsupportedExtension)),
            }
        }
    }
    Ok(())
}
// Inspect the finite local v1beta1 declaration only; official Kustomize performs substitution.
fn inspect_vars(node: &TreeNode, remaining: &mut usize) -> Result<()> {
    let vars = node
        .as_sequence()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
    let mut names = BTreeSet::new();
    for var in vars {
        charge(remaining)?;
        let fields = var
            .as_mapping()
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
        for (key, _) in fields {
            charge(remaining)?;
            if !matches!(key.as_str(), "name" | "objref" | "fieldref") {
                return Err(FormatError::new(FormatCode::UnsupportedExtension));
            }
        }
        let name = var
            .get("name")
            .and_then(TreeNode::as_str)
            .filter(|name| {
                !name.is_empty() && name.len() <= 253 && name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
            })
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
        if !names.insert(name) {
            return Err(FormatError::new(FormatCode::InvalidProject));
        }
        let object = var
            .get("objref")
            .and_then(TreeNode::as_mapping)
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
        if object.len() != 3
            || !["apiVersion", "kind", "name"]
                .iter()
                .all(|key| object.iter().any(|(name, _)| name.as_str() == *key))
        {
            return Err(FormatError::new(FormatCode::InvalidProject));
        }
        for (_, value) in object {
            charge(remaining)?;
            if !value.as_str().is_some_and(identifier) {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
        }
        if let Some(field) = var.get("fieldref") {
            charge(remaining)?;
            let fields = field
                .as_mapping()
                .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
            if fields.len() != 1 || !fields.iter().any(|(name, _)| name == "fieldpath") {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
            let path = field
                .get("fieldpath")
                .and_then(TreeNode::as_str)
                .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
            if path.is_empty()
                || path.len() > 1024
                || !path.bytes().all(|b| b.is_ascii_alphanumeric() || b"._-[]".contains(&b))
            {
                return Err(FormatError::new(FormatCode::InvalidProject));
            }
        }
    }
    Ok(())
}
/// Explicitly execute an admitted render/lint/local-package plan and validate its native reply.
/// This is an executor seam, not an official-tool or sandbox conformance claim.
/// # Errors
/// Preserves protected failure output and rejects failed status/profile/deadline/output bounds.
pub fn execute_with(request: &RenderRequest, renderer: &mut impl OfflineRenderer) -> Result<super::RendererOutput> {
    let reply = renderer.execute(request)?;
    if reply.profile != request.tool.profile
        || reply.status != RendererStatus::Success
        || reply.elapsed >= request.bounds.timeout
    {
        let mut error = FormatError::new(FormatCode::RendererFailed);
        error.renderer_output = Some(Box::new(reply));
        return Err(error);
    }
    if reply
        .stdout
        .len()
        .checked_add(reply.package.as_ref().map_or(0, |p| p.bytes.len()))
        .is_none_or(|n| n > request.bounds.stdout_bytes)
        || reply.stderr.len() > request.bounds.stderr_bytes
    {
        let mut error = FormatError::new(FormatCode::LimitExceeded);
        error.renderer_output = Some(Box::new(reply));
        return Err(error);
    }
    if (request.command == RenderCommand::HelmPackage) != reply.package.is_some() {
        let mut error = FormatError::new(FormatCode::RendererFailed);
        error.renderer_output = Some(Box::new(reply));
        return Err(error);
    }
    Ok(reply)
}

/// Explicitly execute a previously admitted render plan, then import bounded native stdout.
/// # Errors
/// Propagates unavailable/failure/profile mismatch/timeout/output bounds and native input errors.
pub fn render_with(
    request: RenderRequest,
    renderer: &mut impl OfflineRenderer,
    source_id: SourceId,
    limits: &ParseLimits,
) -> Result<ImportedManifest> {
    if !matches!(
        request.command,
        RenderCommand::HelmTemplate
            | RenderCommand::HelmGeneratedTemplate
            | RenderCommand::KustomizeBuild
            | RenderCommand::KubectlKustomize
    ) {
        return Err(FormatError::new(FormatCode::InvalidProfile));
    }
    let reply = execute_with(&request, renderer)?;
    let kind = if matches!(
        request.command,
        RenderCommand::HelmTemplate | RenderCommand::HelmGeneratedTemplate
    ) {
        RenderedKind::HelmTemplate
    } else {
        RenderedKind::Kustomize
    };
    let parsed = import_rendered(
        SourceInput {
            id: source_id,
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: &reply.stdout,
        },
        limits,
        kind,
        request.tool.provenance().clone(),
    );
    let mut imported = match parsed {
        Ok(imported) => imported,
        Err(mut error) => {
            error.renderer_output = Some(Box::new(reply));
            return Err(error);
        }
    };
    for finding in &request.findings {
        if !imported.findings.contains(finding) {
            imported.findings.push(*finding);
        }
    }
    imported.request = Some(request);
    imported.output = Some(reply);
    Ok(imported)
}

#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
pub(crate) fn expected_package(snapshot: &ProjectSnapshot) -> Result<String> {
    let parsed = snapshot.parsed("Chart.yaml")?;
    let chart = single(&parsed)?;
    let name = chart
        .get("name")
        .and_then(TreeNode::as_str)
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
    let version = chart
        .get("version")
        .and_then(TreeNode::as_str)
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?;
    if [name, version]
        .iter()
        .any(|v| v.is_empty() || v.len() > 253 || !v.bytes().all(|b| b.is_ascii_alphanumeric() || b"._+-".contains(&b)))
    {
        return Err(FormatError::new(FormatCode::InvalidProject));
    }
    Ok(format!("{name}-{version}.tgz"))
}
