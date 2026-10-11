//! Explicit local Helm/Kustomize interfaces and protected generated projects.
//!
//! These APIs do not acquire files, invoke tools implicitly, apply resources, or claim native
//! conformance. A caller-selected executor must enforce the [`OfflineRenderer`] contract.
#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
mod broker_protocol;
mod catalogue;
mod input;
mod output;
#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
#[path = "../renderer_broker/mod.rs"]
pub mod renderer_broker;
#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
mod supervised;
#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
pub use broker_protocol::FailureCause;
#[cfg(all(feature = "supervised-renderer", target_os = "linux"))]
pub use supervised::{
    BrokerSelection, RegisteredTool, RendererCancellationToken, RendererOperationControl, RuntimeSelection,
    SupervisedRenderer,
};

pub use catalogue::{
    ExecutionBounds, OfflineRenderer, PackagedChart, RenderCommand, RenderRequest, RendererOutput, RendererStatus,
    ToolSelection,
};
pub use input::{
    HelmContext, ImportedManifest, LocalFile, ProjectLimits, ProjectSnapshot, RenderProvenance, RenderedKind,
    execute_with, import_rendered, plan_helm, plan_kustomize, render_with,
};
pub use output::{
    ArtifactTree, HelmChartOptions, HelmParameter, HookPolicy, KustomizeOverlay, NativeValue, ResourceQuantity,
    ResourceSide, WorkloadField, WorkloadVariation, generate_chart, generate_kustomize,
};

use crate::Finding;
use std::fmt;

/// Safe, actionable project/rendering outcome; arbitrary input is never included.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum FormatCode {
    /// A bounded input, output or work allowance was exhausted.
    LimitExceeded,
    /// The selected tool/command is not in the frozen ledger.
    InvalidProfile,
    /// A project path, file or native structure is invalid.
    InvalidProject,
    /// A supplied local reference is absent.
    MissingInput,
    /// A remote reference or network-dependent operation is forbidden.
    NetworkRequired,
    /// Plugins, Helm inflation, exec generators, decryption or other extensions are unsupported.
    UnsupportedExtension,
    /// The selected executor/tool was unavailable.
    RendererUnavailable,
    /// The tool failed, timed out or returned contradictory evidence.
    RendererFailed,
    /// Release hook semantics remain separate from ordinary resources.
    HookLifecycle,
    /// Offline lookups cannot establish cluster-dependent template completeness.
    LookupIncomplete,
    /// Template time/random/release state precludes a determinism claim.
    NondeterministicRendering,
    /// Transformations and generators cannot reconstruct original source associations.
    ProvenanceLimited,
    /// CRDs and their lifecycle are distinct from ordinary templated resources.
    CrdLifecycle,
    /// A selected value family or overlay cannot be admitted for the target.
    UnsupportedVariation,
}
impl FormatCode {
    /// Stable machine-readable category, independent of arbitrary protected evidence.
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::LimitExceeded => "limit-exceeded",
            Self::InvalidProfile => "invalid-target-profile",
            Self::InvalidProject => "invalid-local-project",
            Self::MissingInput => "unresolved-reference",
            Self::NetworkRequired => "renderer-network-required",
            Self::UnsupportedExtension => "unsupported-renderer-extension",
            Self::RendererUnavailable => "renderer-unavailable",
            Self::RendererFailed => "renderer-failed",
            Self::HookLifecycle => "helm-hook-lifecycle",
            Self::LookupIncomplete => "offline-lookup-incomplete",
            Self::NondeterministicRendering => "nondeterministic-rendering",
            Self::ProvenanceLimited => "render-provenance-limited",
            Self::CrdLifecycle => "crd-lifecycle",
            Self::UnsupportedVariation => "unsupported-semantic-conversion",
        }
    }
    /// Fixed remediation suitable for ordinary presentation.
    #[must_use]
    pub const fn remediation(self) -> &'static str {
        match self {
            Self::LimitExceeded => {
                "Reduce supplied files/output/work or select bounds within the frozen command ceiling."
            }
            Self::InvalidProfile => "Select an exact admitted command and tool profile from the compatibility ledger.",
            Self::InvalidProject => {
                "Supply a unique regular-file snapshot with bounded relative paths and valid native documents."
            }
            Self::MissingInput => {
                "Materialize every referenced local base, dependency, values file, patch and generator input."
            }
            Self::NetworkRequired => {
                "Materialize external inputs locally; network and live kubeconfig access are not admitted."
            }
            Self::UnsupportedExtension => {
                "Supply ordinary local inputs without plugins, exec/decryption generators or Helm inflation."
            }
            Self::RendererUnavailable => {
                "Supply an explicitly selected verified offline executor; no fallback is performed."
            }
            Self::RendererFailed => {
                "Inspect protected native stderr explicitly and correct the failed invocation within its original bounds."
            }
            Self::HookLifecycle => "Review hook annotations and release lifecycle separately; no hook is executed.",
            Self::LookupIncomplete => {
                "Supply independently expected resources; offline lookup cannot establish cluster state."
            }
            Self::NondeterministicRendering => {
                "Compare independently expected resources; time/random/release behavior remains unverified."
            }
            Self::ProvenanceLimited => {
                "Retain the supplied project snapshot; generated names and patches do not reconstruct source intent."
            }
            Self::CrdLifecycle => "Review CRD lifecycle separately and render with the ledger's include-crds policy.",
            Self::UnsupportedVariation => {
                "Select an existing admitted workload replica/image/resource field and validate explicit target intent."
            }
        }
    }
}
/// Categorized error with redacted native findings, never raw source or renderer diagnostics.
#[derive(Debug)]
pub struct FormatError {
    /// Safe primary category.
    pub code: FormatCode,
    /// Native parser/generator findings where applicable.
    pub native_findings: Vec<Finding>,
    pub(crate) renderer_output: Option<Box<RendererOutput>>,
}
impl FormatError {
    /// Create a safe categorized integration failure with no arbitrary diagnostic payload.
    #[must_use]
    pub fn new(code: FormatCode) -> Self {
        Self {
            code,
            native_findings: Vec::new(),
            renderer_output: None,
        }
    }
    pub(crate) fn native(findings: Vec<Finding>) -> Self {
        Self {
            code: FormatCode::InvalidProject,
            native_findings: findings,
            renderer_output: None,
        }
    }
    /// Native failure output remains available only through explicit private access.
    #[must_use]
    pub fn renderer_output(&self, _access: &crate::generation::ExplicitArtifactAccess) -> Option<&RendererOutput> {
        self.renderer_output.as_deref()
    }
}
impl fmt::Display for FormatError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.code.remediation())
    }
}
impl std::error::Error for FormatError {}
pub(crate) type Result<T> = std::result::Result<T, FormatError>;

pub(crate) fn ledger() -> Result<&'static serde_json::Value> {
    static LEDGER: std::sync::OnceLock<Option<serde_json::Value>> = std::sync::OnceLock::new();
    LEDGER
        .get_or_init(|| serde_json::from_slice(crate::capability::capability_ledger_bytes()).ok())
        .as_ref()
        .ok_or_else(|| FormatError::new(FormatCode::InvalidProfile))
}
pub(crate) fn json(bytes: &serde_json::Value) -> Result<Vec<u8>> {
    serde_json::to_vec(bytes).map_err(|_| FormatError::new(FormatCode::InvalidProject))
}
pub(crate) fn yaml(bytes: &serde_json::Value) -> Result<Vec<u8>> {
    let mut out = b"---\n".to_vec();
    out.extend(json(bytes)?);
    out.push(b'\n');
    Ok(out)
}
