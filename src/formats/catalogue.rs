use super::{FormatCode, FormatError, ProjectSnapshot, RenderProvenance, Result, ledger};
use crate::generation::ExplicitArtifactAccess;
use std::{collections::BTreeMap, fmt, path::Path, time::Duration};

/// Closed offline command classes; user-only release exports and cluster operations are absent.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RenderCommand {
    /// Caller-supplied local chart rendering.
    HelmTemplate,
    /// Generated chart strict lint.
    HelmLint,
    /// Generated chart rendering.
    HelmGeneratedTemplate,
    /// Local packaging, never publication.
    HelmPackage,
    /// Standalone Kustomize build.
    KustomizeBuild,
    /// Separately identified kubectl-bundled Kustomize build.
    KubectlKustomize,
}
impl RenderCommand {
    /// Canonical row identifier, with versions/argv/bounds supplied by the ledger.
    #[must_use]
    pub const fn ledger_id(self) -> &'static str {
        match self {
            Self::HelmTemplate => "helm-local-template",
            Self::HelmLint => "helm-generated-lint",
            Self::HelmGeneratedTemplate => "helm-generated-template",
            Self::HelmPackage => "helm-generated-package",
            Self::KustomizeBuild => "kustomize-build",
            Self::KubectlKustomize => "kubectl-kustomize",
        }
    }
    pub(crate) fn row(self) -> Result<&'static serde_json::Value> {
        ledger()?["command_catalogue"]
            .as_array()
            .and_then(|a| a.iter().find(|r| r["id"] == self.ledger_id()))
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))
    }
}
/// Exact caller-selected official executable identity. The executor must verify its actual image.
#[derive(Clone)]
pub struct ToolSelection {
    pub(crate) profile: String,
    pub(crate) executable: String,
    provenance: RenderProvenance,
}
impl ToolSelection {
    /// Select a ledger profile and an absolute executable, without acquiring or executing it.
    /// # Errors
    /// Rejects unknown profiles and relative/ambiguous executable paths.
    pub fn new(profile: &str, executable: &str, provenance: RenderProvenance) -> Result<Self> {
        let exists = ledger()?["tool_profiles"]
            .as_array()
            .is_some_and(|a| a.iter().any(|r| r["id"] == profile));
        if !exists
            || !Path::new(executable).is_absolute()
            || executable.contains('\0')
            || Path::new(executable)
                .components()
                .any(|c| matches!(c, std::path::Component::ParentDir | std::path::Component::CurDir))
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        Ok(Self {
            profile: profile.into(),
            executable: executable.into(),
            provenance,
        })
    }
    /// Exact profile identifier; embedded and standalone renderer profiles are distinct.
    #[must_use]
    pub fn profile_id(&self) -> &str {
        &self.profile
    }
    /// Protected caller-supplied executable provenance, not verification evidence by itself.
    #[must_use]
    pub const fn provenance(&self) -> &RenderProvenance {
        &self.provenance
    }
}
impl fmt::Debug for ToolSelection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ToolSelection")
            .field("profile", &self.profile)
            .finish_non_exhaustive()
    }
}
/// Explicit finite allowances, independently constrained by the selected command's ledger ceiling.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ExecutionBounds {
    /// Total execution deadline, including setup and output drain; never restarted.
    pub timeout: Duration,
    /// Maximum protected stdout bytes.
    pub stdout_bytes: usize,
    /// Maximum protected stderr bytes.
    pub stderr_bytes: usize,
    /// Aggregate memory ceiling that the executor must enforce.
    pub memory_bytes: usize,
}
impl ExecutionBounds {
    /// Read the canonical ceiling, without duplicating version/budget inventories.
    /// # Errors
    /// Refuses an invalid ledger row.
    pub fn ceiling(command: RenderCommand) -> Result<Self> {
        let row = &command.row()?["execution_bounds"];
        let get = |key: &str| {
            row[key]
                .as_u64()
                .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))
        };
        let size = |key| usize::try_from(get(key)?).map_err(|_| FormatError::new(FormatCode::InvalidProfile));
        Ok(Self {
            timeout: Duration::from_secs(get("timeout_seconds")?),
            stdout_bytes: size("stdout_limit_bytes")?,
            stderr_bytes: size("stderr_limit_bytes")?,
            memory_bytes: size("memory_limit_bytes")?,
        })
    }
    pub(crate) fn validate(self, command: RenderCommand) -> Result<()> {
        let max = Self::ceiling(command)?;
        if self.timeout.is_zero()
            || self.timeout > max.timeout
            || self.stdout_bytes == 0
            || self.stdout_bytes > max.stdout_bytes
            || self.stderr_bytes == 0
            || self.stderr_bytes > max.stderr_bytes
            || self.memory_bytes == 0
            || self.memory_bytes > max.memory_bytes
        {
            return Err(FormatError::new(FormatCode::LimitExceeded));
        }
        Ok(())
    }
}
/// Immutable protected invocation plan. It contains no shell, ambient environment or public permit.
pub struct RenderRequest {
    pub(crate) command: RenderCommand,
    pub(crate) tool: ToolSelection,
    pub(crate) argv: Vec<String>,
    pub(crate) snapshot: ProjectSnapshot,
    pub(crate) bounds: ExecutionBounds,
    pub(crate) findings: Vec<FormatCode>,
}
impl RenderRequest {
    pub(crate) fn new(
        command: RenderCommand,
        tool: ToolSelection,
        snapshot: ProjectSnapshot,
        substitutions: &BTreeMap<&str, String>,
        append: Vec<String>,
        bounds: ExecutionBounds,
        findings: Vec<FormatCode>,
    ) -> Result<Self> {
        bounds.validate(command)?;
        let row = command.row()?;
        if !row["profile_ids"]
            .as_array()
            .is_some_and(|a| a.iter().any(|v| v.as_str() == Some(&tool.profile)))
        {
            return Err(FormatError::new(FormatCode::InvalidProfile));
        }
        let mut argv = Vec::new();
        for token in row["literal_argv"]
            .as_array()
            .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?
            .iter()
            .skip(1)
        {
            let token = token
                .as_str()
                .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))?;
            argv.push(if token.starts_with('{') {
                substitutions
                    .get(token)
                    .cloned()
                    .ok_or_else(|| FormatError::new(FormatCode::InvalidProject))?
            } else {
                token.into()
            });
        }
        argv.extend(append);
        Ok(Self {
            command,
            tool,
            argv,
            snapshot,
            bounds,
            findings,
        })
    }
    /// Command class, never an implicit execution request.
    #[must_use]
    pub const fn command(&self) -> RenderCommand {
        self.command
    }
    /// Selected image identity that the executor must authenticate.
    #[must_use]
    pub const fn tool(&self) -> &ToolSelection {
        &self.tool
    }
    /// Original bounded local files, available only with explicit access.
    #[must_use]
    pub const fn snapshot(&self) -> &ProjectSnapshot {
        &self.snapshot
    }
    /// Effective execution ceilings.
    #[must_use]
    pub const fn bounds(&self) -> ExecutionBounds {
        self.bounds
    }
    /// Safe semantic limitations detected before rendering.
    #[must_use]
    pub fn findings(&self) -> &[FormatCode] {
        &self.findings
    }
    /// Protected executable and literal arguments; never a shell command.
    #[must_use]
    pub fn invocation(&self, _access: &ExplicitArtifactAccess) -> (&str, &[String]) {
        (&self.tool.executable, &self.argv)
    }
}
impl fmt::Debug for RenderRequest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RenderRequest")
            .field("command", &self.command)
            .field("tool", &self.tool)
            .field("bounds", &self.bounds)
            .field("findings", &self.findings)
            .finish_non_exhaustive()
    }
}
/// Exclusive native completion category; success/exit/signal cannot contradict one another.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RendererStatus {
    /// Native exit status zero.
    Success,
    /// Nonzero native exit status.
    Exit(i32),
    /// Native termination signal.
    Signal(i32),
    /// Original execution deadline expired.
    Timeout,
}
/// Protected executor reply; constructors do not establish actual host conformance.
pub struct RendererOutput {
    pub(crate) profile: String,
    pub(crate) status: RendererStatus,
    pub(crate) stdout: Vec<u8>,
    pub(crate) stderr: Vec<u8>,
    pub(crate) elapsed: Duration,
    pub(crate) package: Option<PackagedChart>,
    #[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
    pub(crate) failure_cause: Option<super::FailureCause>,
}
impl RendererOutput {
    /// Supply independently obtained native result and exact authenticated profile.
    #[must_use]
    pub fn new(profile: String, status: RendererStatus, stdout: Vec<u8>, stderr: Vec<u8>, elapsed: Duration) -> Self {
        Self {
            profile,
            status,
            stdout,
            stderr,
            elapsed,
            package: None,
            #[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
            failure_cause: None,
        }
    }
    /// Fixed supervised failure cause, separate from protected native diagnostics.
    #[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
    #[must_use]
    pub const fn failure_cause(&self) -> Option<super::FailureCause> {
        self.failure_cause
    }
    /// Attach a protected local package. The integration validator rejects unexpected artifacts.
    #[must_use]
    pub fn with_package(mut self, package: PackagedChart) -> Self {
        self.package = Some(package);
        self
    }
    /// Local package bytes and name remain protected by an explicit artifact-access token.
    #[must_use]
    pub fn package(&self, _access: &ExplicitArtifactAccess) -> Option<&PackagedChart> {
        self.package.as_ref()
    }
    /// Native completion category, never a success claim about sandbox cleanup.
    #[must_use]
    pub const fn status(&self) -> RendererStatus {
        self.status
    }
    /// Raw renderer stdout, including failed output, requires explicit private access.
    #[must_use]
    pub fn stdout(&self, _access: &ExplicitArtifactAccess) -> &[u8] {
        &self.stdout
    }
    /// Raw diagnostics require explicit private access.
    #[must_use]
    pub fn stderr(&self, _access: &ExplicitArtifactAccess) -> &[u8] {
        &self.stderr
    }
}
impl fmt::Debug for RendererOutput {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RendererOutput")
            .field("status", &self.status)
            .field("stdout_bytes", &self.stdout.len())
            .field("stderr_bytes", &self.stderr.len())
            .finish_non_exhaustive()
    }
}
/// Explicit execution seam, not a delivered sandbox or evidence of native tool support.
///
/// Implementations must authenticate exact official tool/version/images, snapshot only supplied
/// regular files, enforce original deadline/aggregate memory/output bounds, isolate network/IPC,
/// strip ambient kubeconfig/credentials/plugins, and reap/clean up before returning. Never apply,
/// install/upgrade, fetch dependencies, execute hooks or silently substitute profiles. A failed
/// sandbox/cleanup must return failure even if the native renderer exited zero.
pub trait OfflineRenderer {
    /// Execute only this immutable admitted plan in an independently verified offline sandbox.
    /// # Errors
    /// Categorize unavailable or failed execution without disclosing private native diagnostics.
    fn execute(&mut self, request: &RenderRequest) -> Result<RendererOutput>;
}

/// Protected local chart package; this artifact never authorizes publication.
pub struct PackagedChart {
    pub(crate) name: String,
    pub(crate) bytes: Vec<u8>,
}
impl PackagedChart {
    /// Retain an independently obtained regular `.tgz` artifact.
    /// # Errors
    /// Rejects path components, empty payloads and non-package suffixes.
    pub fn new(name: String, bytes: Vec<u8>) -> Result<Self> {
        if name.is_empty()
            || Path::new(&name).extension() != Some(std::ffi::OsStr::new("tgz"))
            || name.contains(['/', '\\', '\0'])
            || bytes.is_empty()
        {
            return Err(FormatError::new(FormatCode::InvalidProject));
        }
        Ok(Self { name, bytes })
    }
    /// Reveal the protected package basename explicitly.
    #[must_use]
    pub fn name(&self, _access: &ExplicitArtifactAccess) -> &str {
        &self.name
    }
    /// Reveal the protected package bytes explicitly.
    #[must_use]
    pub fn bytes(&self, _access: &ExplicitArtifactAccess) -> &[u8] {
        &self.bytes
    }
}
impl fmt::Debug for PackagedChart {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("PackagedChart")
            .field("byte_len", &self.bytes.len())
            .finish_non_exhaustive()
    }
}
