//! Pure supervised selection/privacy tests; no broker, subprocess or native tool runs.
#![cfg(all(feature = "supervised-renderer", target_os = "linux"))]
use kubernetes_lens::formats::{
    self, BrokerSelection, ExecutionBounds, FailureCause, FormatCode, HelmContext, LocalFile, OfflineRenderer,
    PackagedChart, ProjectLimits, ProjectSnapshot, RegisteredTool, RenderCommand, RenderProvenance,
    RendererCancellationToken, RendererOperationControl, RuntimeSelection, SupervisedRenderer, ToolSelection,
};
use kubernetes_lens::generation::ExplicitArtifactAccess;
type TestResult = Result<(), Box<dyn std::error::Error>>;
fn provenance() -> Result<RenderProvenance, formats::FormatError> {
    RenderProvenance::new(b"private canonical official source receipt")
}
fn registration(profile: &str) -> Result<RegisteredTool, formats::FormatError> {
    RegisteredTool::new(
        profile.into(),
        "/root/preprovisioned/private-helm".into(),
        [1; 32],
        provenance()?,
    )
}
#[test]
fn explicit_configuration_rejects_ambiguous_paths_and_empty_digests() -> TestResult {
    for path in [
        "relative",
        "/run/../escape",
        "/run/./broker",
        "/run//broker",
        "/run/broker/",
    ] {
        assert!(BrokerSelection::new(path.into(), [1; 32]).is_err());
    }
    assert!(BrokerSelection::new("/run/private/broker".into(), [0; 32]).is_err());
    assert!(registration("helm-unknown").is_err());
    assert!(RegisteredTool::new("helm-4.3.0".into(), "/root/../helm".into(), [1; 32], provenance()?).is_err());
    assert!(RegisteredTool::new("helm-4.3.0".into(), "/root/helm".into(), [0; 32], provenance()?).is_err());
    Ok(())
}
#[test]
fn runtime_allowances_only_lower_and_duplicate_profiles_fail() -> TestResult {
    assert!(RuntimeSelection::new(vec![registration("helm-4.3.0")?], 1, 64).is_err());
    for pids in [0, 65, usize::MAX] {
        assert!(RuntimeSelection::new(vec![registration("helm-4.3.0")?], 0, pids).is_err());
    }
    assert!(RuntimeSelection::new(vec![registration("helm-4.3.0")?, registration("helm-4.3.0")?], 0, 32).is_err());
    RuntimeSelection::new(vec![registration("helm-3.22.0")?, registration("helm-4.3.0")?], 0, 16)?;
    Ok(())
}
#[test]
fn exact_historical_selection_never_falls_back_to_registered_modern_tool() -> TestResult {
    let snapshot = ProjectSnapshot::new(
        vec![
            LocalFile::new(
                "chart/Chart.yaml".into(),
                b"apiVersion: v2\nname: demo\nversion: 1.0.0\n".to_vec(),
                provenance()?,
            ),
            LocalFile::new("values.yaml".into(), b"{}".to_vec(), provenance()?),
        ],
        ProjectLimits::default(),
    )?;
    let request = formats::plan_helm(
        snapshot,
        ToolSelection::new("helm-3.22.0", "/root/preprovisioned/private-helm", provenance()?)?,
        &HelmContext {
            chart: "chart".into(),
            values: "values.yaml".into(),
            release: "demo".into(),
            namespace: "demo".into(),
            kubernetes_patch: "1.20.15".into(),
            api_versions: Vec::new(),
            upgrade: false,
        },
        ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?,
    )?;
    let mut renderer = SupervisedRenderer::new(
        BrokerSelection::new("/run/private/unavailable-broker".into(), [2; 32])?,
        RuntimeSelection::new(vec![registration("helm-4.3.0")?], 0, 64)?,
    )?;
    let result = renderer.execute(&request);
    assert!(matches!(result,Err(e) if e.code==FormatCode::RendererUnavailable));
    assert_eq!(renderer.last_failure(), Some(FailureCause::Unavailable));
    Ok(())
}
#[test]
fn selection_and_package_debug_are_redacted() -> TestResult {
    let registered = registration("helm-4.3.0")?;
    let text = format!("{registered:?}");
    assert!(!text.contains("private-helm"));
    assert!(!text.contains("canonical official"));
    let package = PackagedChart::new("protected-name-1.0.0.tgz".into(), b"protected package bytes".to_vec())?;
    let debug = format!("{package:?}");
    assert!(!debug.contains("protected"));
    let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    assert_eq!(package.name(&access), "protected-name-1.0.0.tgz");
    assert_eq!(package.bytes(&access), b"protected package bytes");
    for name in ["../chart.tgz", "chart.zip", "/chart.tgz", "chart\\other.tgz"] {
        assert!(PackagedChart::new(name.into(), vec![1]).is_err());
    }
    assert!(PackagedChart::new("chart.tgz".into(), Vec::new()).is_err());
    Ok(())
}

fn controlled_request() -> Result<formats::RenderRequest, formats::FormatError> {
    let snapshot = ProjectSnapshot::new(
        vec![
            LocalFile::new(
                "chart/Chart.yaml".into(),
                b"apiVersion: v2\nname: demo\nversion: 1.0.0\n".to_vec(),
                provenance()?,
            ),
            LocalFile::new("values.yaml".into(), b"{}".to_vec(), provenance()?),
        ],
        ProjectLimits::default(),
    )?;
    formats::plan_helm(
        snapshot,
        ToolSelection::new("helm-3.22.0", "/root/preprovisioned/private-helm", provenance()?)?,
        &HelmContext {
            chart: "chart".into(),
            values: "values.yaml".into(),
            release: "demo".into(),
            namespace: "demo".into(),
            kubernetes_patch: "1.20.15".into(),
            api_versions: Vec::new(),
            upgrade: false,
        },
        ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?,
    )
}
#[test]
fn explicit_cancelled_control_refuses_before_unavailable_socket_or_nonce_allocation() -> TestResult {
    let token = RendererCancellationToken::new();
    token.clone().cancel();
    let control = RendererOperationControl::new(std::time::Instant::now() + std::time::Duration::from_secs(40), token);
    let mut renderer = SupervisedRenderer::new(
        BrokerSelection::new("/run/private/must-not-connect".into(), [2; 32])?,
        RuntimeSelection::new(vec![registration("helm-3.22.0")?], 0, 64)?,
    )?;
    assert!(
        matches!(renderer.execute_with_control(&controlled_request()?, &control),
        Err(error) if error.code == FormatCode::RendererFailed)
    );
    assert_eq!(renderer.last_failure(), Some(FailureCause::Cancelled));
    Ok(())
}
#[test]
fn explicit_expired_or_insufficient_total_never_becomes_a_fresh_execution_timeout() -> TestResult {
    let request = controlled_request()?;
    let mut renderer = SupervisedRenderer::new(
        BrokerSelection::new("/run/private/must-not-connect".into(), [2; 32])?,
        RuntimeSelection::new(vec![registration("helm-3.22.0")?], 0, 64)?,
    )?;
    let now = std::time::Instant::now();
    for end in [
        now,
        now + std::time::Duration::from_secs(9),
        now + std::time::Duration::from_secs(10),
    ] {
        let control = RendererOperationControl::new(end, RendererCancellationToken::new());
        assert!(matches!(renderer.execute_with_control(&request, &control),
            Err(error) if error.code == FormatCode::LimitExceeded));
        assert_eq!(control.end(), end);
    }
    Ok(())
}
