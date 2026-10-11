//! Public local-project and generated-artifact behavior; no official renderer executes here.
use kubernetes_lens::{
    capability::{KubernetesVersion, TargetProfile},
    formats::{
        self, ExecutionBounds, FormatCode, FormatError, HelmChartOptions, HelmContext, HelmParameter, HookPolicy,
        KustomizeOverlay, LocalFile, NativeValue, OfflineRenderer, ProjectLimits, ProjectSnapshot, RenderCommand,
        RenderProvenance, RenderRequest, RenderedKind, RendererOutput, RendererStatus, ToolSelection, WorkloadField,
        WorkloadVariation,
    },
    generation::{ExplicitArtifactAccess, GenerationOptions, OpaqueFieldPolicy, ProtectedOutput},
    source::{DocumentFormat, ExplicitSourceAccess, InputOrigin, ParseLimits, SourceId, SourceInput},
};
use std::time::Duration;
type TestResult = Result<(), Box<dyn std::error::Error>>;

#[test]
fn custom_group_workload_names_never_admit_values_or_overlays() -> TestResult {
    for (source, field, value) in [
        (
            DEPLOYMENT.replace("apps/v1", "example.org/v1"),
            WorkloadField::Replicas,
            NativeValue::Replicas(3),
        ),
        (
            "apiVersion: example.org/v1\nkind: Pod\nmetadata: {name: custom}\nspec:\n  containers: [{name: main, image: example/app:v1}]\n".into(),
            WorkloadField::Image { container: "main".into() },
            NativeValue::Image("example/app:v2".into()),
        ),
    ] {
        let imported = import(&source, RenderedKind::Manifest)?;
        let resources = imported.resources();
        let id = resources.documents()[0].id();
        // Opaque resources may remain static protected data, but never become typed parameters.
        formats::generate_chart(resources, &target()?, &options(), &chart(), vec!["helm-4.3.0".into()])?;
        let mut selected = chart();
        selected.parameters.push(HelmParameter { name: "selected".into(), resource: id, field: field.clone() });
        assert_eq!(error(formats::generate_chart(resources, &target()?, &options(), &selected, vec!["helm-4.3.0".into()]))?.code, FormatCode::UnsupportedVariation);
        let overlays = [KustomizeOverlay { name: "selected".into(), variations: vec![WorkloadVariation { resource: id, field, value }] }];
        assert_eq!(error(formats::generate_kustomize(resources, &target()?, &options(), &overlays, vec!["kustomize-5.8.3".into()]))?.code, FormatCode::UnsupportedVariation);
    }
    Ok(())
}

#[test]
fn helm_shared_subchart_aliases_charge_every_dependency_visit() -> TestResult {
    let files = [
        (
            "chart/Chart.yaml",
            "apiVersion: v2\nname: parent\nversion: 1.0.0\ndependencies:\n- {name: child, alias: first}\n- {name: child, alias: second}\n",
        ),
        (
            "chart/charts/child/Chart.yaml",
            "apiVersion: v2\nname: child\nversion: 1.0.0\n",
        ),
        ("values.yaml", "{}"),
    ];
    let supplied = |references| -> Result<ProjectSnapshot, FormatError> {
        ProjectSnapshot::new(
            files
                .iter()
                .map(|(path, bytes)| Ok(LocalFile::new((*path).into(), bytes.as_bytes().to_vec(), provenance()?)))
                .collect::<Result<Vec<_>, FormatError>>()?,
            ProjectLimits {
                references,
                ..ProjectLimits::default()
            },
        )
    };
    let bounds = ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?;
    formats::plan_helm(supplied(3)?, tool("helm-4.3.0")?, &context(), bounds)?;
    assert_eq!(
        error(formats::plan_helm(
            supplied(2)?,
            tool("helm-4.3.0")?,
            &context(),
            bounds
        ))?
        .code,
        FormatCode::LimitExceeded
    );
    // Even a root-only project consumes a chart traversal reference.
    let mut root = context();
    root.chart = "chart/charts/child".into();
    formats::plan_helm(supplied(1)?, tool("helm-4.3.0")?, &root, bounds)?;
    Ok(())
}

#[test]
fn generated_projects_preserve_source_parser_byte_ceiling() -> TestResult {
    let source = b"apiVersion: v1\nkind: ConfigMap\nmetadata: {name: x}\ndata: {x: y}\n";
    let limits = ParseLimits {
        max_input_bytes: source.len(),
        ..ParseLimits::default()
    };
    let imported = formats::import_rendered(
        SourceInput {
            id: SourceId(0),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            bytes: source,
        },
        &limits,
        RenderedKind::Manifest,
        provenance()?,
    )?;
    for result in [
        formats::generate_chart(
            imported.resources(),
            &target()?,
            &options(),
            &chart(),
            vec!["helm-4.3.0".into()],
        ),
        formats::generate_kustomize(
            imported.resources(),
            &target()?,
            &options(),
            &[],
            vec!["kustomize-5.8.3".into()],
        ),
    ] {
        let rejected = error(result)?;
        assert!(
            rejected
                .native_findings
                .iter()
                .any(|finding| finding.code == kubernetes_lens::FindingCode::LimitExceeded)
        );
    }
    Ok(())
}

#[test]
fn chart_versions_require_unsigned_decimal_components() -> TestResult {
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    for version in ["+1.2.3", "1.+2.3", "1.2.+3", "01.2.3", "1.2.-3", "1.2.", "1.2.3.4"] {
        let mut selected = chart();
        selected.version = version.into();
        assert_eq!(
            error(formats::generate_chart(
                imported.resources(),
                &target()?,
                &options(),
                &selected,
                vec!["helm-4.3.0".into()]
            ))?
            .code,
            FormatCode::InvalidProject
        );
    }
    Ok(())
}

#[test]
fn multiple_overlays_share_one_cumulative_processing_allowance() -> TestResult {
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    let target = target()?;
    let id = imported.resources().documents()[0].id();
    let overlays = ["first", "second"].map(|name| KustomizeOverlay {
        name: name.into(),
        variations: vec![WorkloadVariation {
            resource: id,
            field: WorkloadField::Replicas,
            value: NativeValue::Replicas(3),
        }],
    });
    let generate = |allowance, selected: &[KustomizeOverlay]| {
        let mut policy = options();
        policy.processing = Some(kubernetes_lens::processing::NativeProcessingLimits {
            max_processing_units: allowance,
            ..kubernetes_lens::processing::NativeProcessingLimits::default()
        });
        formats::generate_kustomize(
            imported.resources(),
            &target,
            &policy,
            selected,
            vec!["kustomize-5.8.3".into()],
        )
    };
    // Find the allowance sufficient for exactly one independently validated candidate.
    let mut low = 0;
    let mut high = 1_000_000;
    assert!(generate(high, &overlays).is_ok());
    while low < high {
        let middle = low + (high - low) / 2;
        if generate(middle, &overlays[..1]).is_ok() {
            high = middle;
        } else {
            low = middle + 1;
        }
    }
    assert!(generate(low, &overlays[..1]).is_ok());
    let rejected = error(generate(low, &overlays))?;
    assert!(
        rejected
            .native_findings
            .iter()
            .any(|finding| finding.code == kubernetes_lens::FindingCode::LimitExceeded)
    );
    Ok(())
}
const PRIVATE: &str = "PRIVATE-format-token";
const DEPLOYMENT: &str = "apiVersion: apps/v1\nkind: Deployment\nmetadata: {name: app, namespace: ns}\nspec:\n  replicas: 2\n  selector: {matchLabels: {app: app}}\n  template:\n    metadata: {labels: {app: app}}\n    spec:\n      containers: [{name: main, image: example/app:v1}]\n";
fn provenance() -> Result<RenderProvenance, FormatError> {
    RenderProvenance::new(PRIVATE.as_bytes())
}
fn tool(id: &str) -> Result<ToolSelection, FormatError> {
    ToolSelection::new(id, "/explicit/official/tool", provenance()?)
}
fn snapshot(files: &[(&str, &str)]) -> Result<ProjectSnapshot, FormatError> {
    ProjectSnapshot::new(
        files
            .iter()
            .map(|(p, b)| Ok(LocalFile::new((*p).into(), b.as_bytes().to_vec(), provenance()?)))
            .collect::<Result<Vec<_>, FormatError>>()?,
        ProjectLimits::default(),
    )
}
fn import(text: &str, kind: RenderedKind) -> Result<formats::ImportedManifest, FormatError> {
    formats::import_rendered(
        SourceInput {
            id: SourceId(17),
            format: DocumentFormat::YamlStream,
            origin: InputOrigin::CallerSupplied,
            source_version: Some(
                KubernetesVersion::new(1, 20).map_err(|_| FormatError::new(FormatCode::InvalidProfile))?,
            ),
            bytes: text.as_bytes(),
        },
        &ParseLimits::default(),
        kind,
        provenance()?,
    )
}
fn target() -> Result<TargetProfile, kubernetes_lens::Finding> {
    Ok(TargetProfile::documented_defaults(KubernetesVersion::new(1, 37)?))
}
fn options() -> GenerationOptions {
    GenerationOptions {
        protected_output: ProtectedOutput::Include,
        opaque_fields: OpaqueFieldPolicy::PreserveWithFinding,
        ..GenerationOptions::default()
    }
}
fn chart() -> HelmChartOptions {
    HelmChartOptions {
        name: "intent".into(),
        version: "1.0.0".into(),
        parameters: Vec::new(),
        hooks: HookPolicy::Reject,
    }
}
fn context() -> HelmContext {
    HelmContext {
        chart: "chart".into(),
        values: "values.yaml".into(),
        release: "demo".into(),
        namespace: "ns".into(),
        kubernetes_patch: "1.20.15".into(),
        api_versions: vec!["example.org/v1".into(), "example.org/v1/Widget".into()],
        upgrade: true,
    }
}
fn file(tree: &formats::ArtifactTree, name: &str) -> Result<Vec<u8>, Box<dyn std::error::Error>> {
    tree.files(&ExplicitArtifactAccess::explicitly_allow_raw_artifact())
        .find(|(p, _)| *p == name)
        .map(|(_, b)| b.to_vec())
        .ok_or_else(|| "missing expected file".into())
}
fn error<T>(value: Result<T, FormatError>) -> Result<FormatError, Box<dyn std::error::Error>> {
    value.err().ok_or_else(|| "expected failure".into())
}
#[test]
fn rendered_import_retains_private_source_origin_and_hook_semantics() -> TestResult {
    let text = DEPLOYMENT.replace(
        "metadata: {name: app, namespace: ns}",
        &format!(
            "metadata: {{name: app, namespace: ns, annotations: {{helm.sh/hook: pre-install, private: {PRIVATE}}}}}"
        ),
    );
    let imported = import(&text, RenderedKind::HelmReleaseHooks)?;
    assert_eq!(imported.resources().documents().len(), 1);
    assert_eq!(
        imported.resources().sources()[0].origin,
        kubernetes_lens::source::EvidenceOrigin::Supplied(InputOrigin::ClusterExport)
    );
    assert!(imported.findings().contains(&FormatCode::HookLifecycle));
    assert!(!format!("{imported:?}").contains(PRIVATE));
    assert_eq!(
        imported
            .provenance()
            .reveal(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        PRIVATE.as_bytes()
    );
    assert_eq!(
        imported.resources().sources()[0].reveal_raw(&ExplicitSourceAccess::explicitly_allow_raw_source()),
        text.as_bytes()
    );
    Ok(())
}
#[test]
fn rendered_input_failure_preserves_native_structured_errors() -> TestResult {
    let malformed = error(import("apiVersion: v1\nkind: Pod\nkind: Pod\n", RenderedKind::Manifest))?;
    assert_eq!(
        malformed.native_findings[0].code,
        kubernetes_lens::FindingCode::DuplicateKey
    );
    assert!(import(&format!("{DEPLOYMENT}---\n{DEPLOYMENT}"), RenderedKind::Kustomize).is_err());
    Ok(())
}
#[test]
fn snapshot_rejects_escape_duplicate_prefix_and_cumulative_limits() -> TestResult {
    for paths in [
        vec![("../outside", "x")],
        vec![("/absolute", "x")],
        vec![("a", "x"), ("a", "y")],
        vec![("a", "x"), ("a/b", "y")],
        vec![("symlink/../x", "x")],
    ] {
        assert!(snapshot(&paths).is_err());
    }
    let local = LocalFile::new("safe".into(), PRIVATE.as_bytes().to_vec(), provenance()?);
    assert_eq!(
        error(ProjectSnapshot::new(
            vec![local],
            ProjectLimits {
                bytes: 4,
                ..ProjectLimits::default()
            }
        ))?
        .code,
        FormatCode::LimitExceeded
    );
    Ok(())
}
#[test]
fn helm_plan_uses_exact_ledger_argv_and_explicit_capabilities() -> TestResult {
    let request = formats::plan_helm(
        snapshot(&[
            ("chart/Chart.yaml", "apiVersion: v2\nname: chart\nversion: 1.0.0\n"),
            ("values.yaml", "private: PRIVATE-format-token"),
        ])?,
        tool("helm-3.22.0")?,
        &context(),
        ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?,
    )?;
    let (_, argv) = request.invocation(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
    assert_eq!(
        argv,
        &[
            "template",
            "demo",
            "./chart",
            "--namespace",
            "ns",
            "--values",
            "./values.yaml",
            "--kube-version",
            "1.20.15",
            "--include-crds",
            "--dry-run=client",
            "--api-versions",
            "example.org/v1",
            "--api-versions",
            "example.org/v1/Widget",
            "--is-upgrade"
        ]
    );
    assert!(!format!("{request:?}").contains(PRIVATE));
    assert!(request.findings().contains(&FormatCode::LookupIncomplete));
    assert!(request.findings().contains(&FormatCode::NondeterministicRendering));
    assert_eq!(
        request
            .snapshot()
            .files(&ExplicitSourceAccess::explicitly_allow_raw_source())
            .count(),
        2
    );
    Ok(())
}
#[test]
fn helm_values_alone_missing_dependency_and_unadmitted_profile_fail() -> TestResult {
    let ceiling = ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?;
    assert_eq!(
        error(formats::plan_helm(
            snapshot(&[("values.yaml", "{}")])?,
            tool("helm-3.22.0")?,
            &context(),
            ceiling
        ))?
        .code,
        FormatCode::MissingInput
    );
    assert!(ToolSelection::new("helm-latest", "/tool", provenance()?).is_err());
    let chart = "apiVersion: v2\nname: chart\nversion: 1.0.0\ndependencies: [{name: missing, version: 1.0.0, repository: https://remote}]\n";
    assert_eq!(
        error(formats::plan_helm(
            snapshot(&[("chart/Chart.yaml", chart), ("values.yaml", "{}")])?,
            tool("helm-4.3.0")?,
            &context(),
            ceiling
        ))?
        .code,
        FormatCode::MissingInput
    );
    let mut invalid = context();
    invalid.kubernetes_patch = "1.38.0".into();
    assert_eq!(
        error(formats::plan_helm(
            snapshot(&[
                ("chart/Chart.yaml", "apiVersion: v2\nname: chart\nversion: 1.0.0"),
                ("values.yaml", "{}")
            ])?,
            tool("helm-3.22.0")?,
            &invalid,
            ceiling
        ))?
        .code,
        FormatCode::InvalidProfile
    );
    Ok(())
}
#[test]
fn kustomize_local_references_generators_and_distinct_embedded_profiles() -> TestResult {
    for (profile, command) in [
        ("kustomize-5.8.3", RenderCommand::KustomizeBuild),
        ("kubectl-1.20.15-kustomize-2.0.3", RenderCommand::KubectlKustomize),
        ("kubectl-1.37.0-kustomize-5.8.1", RenderCommand::KubectlKustomize),
    ] {
        let project = snapshot(&[
            ("base/kustomization.yaml", "resources: [resource.yaml]"),
            ("base/resource.yaml", DEPLOYMENT),
            (
                "overlays/test/kustomization.yaml",
                "resources: [../../base]\nnamePrefix: explicit-\nconfigMapGenerator: [{name: inputs, files: [data=local.txt], envs: [vars.env]}]",
            ),
            ("overlays/test/local.txt", PRIVATE),
            ("overlays/test/vars.env", "token=private"),
        ])?;
        let request = formats::plan_kustomize(
            project,
            tool(profile)?,
            "overlays/test",
            ExecutionBounds::ceiling(command)?,
        )?;
        assert_eq!(request.command(), command);
        assert_eq!(request.tool().profile_id(), profile);
        let (_, argv) = request.invocation(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
        assert_eq!(argv.last().map(String::as_str), Some("./overlays/test"));
    }
    Ok(())
}
#[test]
fn kustomize_remote_missing_cycle_plugins_and_budget_are_closed() -> TestResult {
    for (body, expected) in [
        ("resources: [https://remote/base]", FormatCode::NetworkRequired),
        ("resources: [missing.yaml]", FormatCode::MissingInput),
        ("helmCharts: [{name: arbitrary}]", FormatCode::UnsupportedExtension),
        ("generators: [plugin.yaml]", FormatCode::UnsupportedExtension),
        ("resources: [.]", FormatCode::InvalidProject),
    ] {
        assert_eq!(
            error(formats::plan_kustomize(
                snapshot(&[("kustomization.yaml", body)])?,
                tool("kustomize-5.8.3")?,
                ".",
                ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?
            ))?
            .code,
            expected
        );
    }
    let small = ProjectSnapshot::new(
        vec![LocalFile::new(
            "kustomization.yaml".into(),
            b"resources: [missing]".to_vec(),
            provenance()?,
        )],
        ProjectLimits {
            references: 1,
            ..ProjectLimits::default()
        },
    )?;
    assert_eq!(
        error(formats::plan_kustomize(
            small,
            tool("kustomize-5.8.3")?,
            ".",
            ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?
        ))?
        .code,
        FormatCode::LimitExceeded
    );
    Ok(())
}
struct Mock {
    status: RendererStatus,
    profile: String,
    bytes: Vec<u8>,
    elapsed: Duration,
    calls: usize,
}
impl OfflineRenderer for Mock {
    fn execute(&mut self, request: &RenderRequest) -> Result<RendererOutput, FormatError> {
        self.calls += 1;
        let mut output = RendererOutput::new(
            self.profile.clone(),
            self.status,
            self.bytes.clone(),
            PRIVATE.as_bytes().to_vec(),
            self.elapsed,
        );
        if request.command() == RenderCommand::HelmPackage {
            output = output.with_package(formats::PackagedChart::new("demo-1.0.0.tgz".into(), vec![1])?);
        }
        Ok(output)
    }
}
fn request() -> Result<RenderRequest, FormatError> {
    formats::plan_kustomize(
        snapshot(&[
            ("kustomization.yaml", "resources: [resource.yaml]"),
            ("resource.yaml", DEPLOYMENT),
        ])?,
        tool("kustomize-5.8.3")?,
        ".",
        ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?,
    )
}
#[test]
fn explicit_executor_imports_only_success_and_retains_request() -> TestResult {
    let mut mock = Mock {
        status: RendererStatus::Success,
        profile: "kustomize-5.8.3".into(),
        bytes: DEPLOYMENT.as_bytes().to_vec(),
        elapsed: Duration::from_millis(1),
        calls: 0,
    };
    let imported = formats::render_with(request()?, &mut mock, SourceId(99), &ParseLimits::default())?;
    assert_eq!(mock.calls, 1);
    assert_eq!(imported.resources().sources()[0].id, SourceId(99));
    assert!(imported.request().is_some());
    assert!(!format!("{imported:?}").contains(PRIVATE));
    for status in [
        RendererStatus::Exit(23),
        RendererStatus::Signal(9),
        RendererStatus::Timeout,
    ] {
        mock.status = status;
        assert_eq!(
            error(formats::render_with(
                request()?,
                &mut mock,
                SourceId(99),
                &ParseLimits::default()
            ))?
            .code,
            FormatCode::RendererFailed
        );
    }
    mock.status = RendererStatus::Success;
    mock.profile = "kubectl-1.20.15-kustomize-2.0.3".into();
    assert!(formats::render_with(request()?, &mut mock, SourceId(99), &ParseLimits::default()).is_err());
    Ok(())
}
#[test]
fn executor_output_and_deadline_bounds_cannot_be_extended() -> TestResult {
    let mut request = request()?;
    let ceiling = request.bounds();
    let mut mock = Mock {
        status: RendererStatus::Success,
        profile: "kustomize-5.8.3".into(),
        bytes: DEPLOYMENT.as_bytes().to_vec(),
        elapsed: ceiling.timeout,
        calls: 0,
    };
    assert_eq!(
        error(formats::render_with(
            request,
            &mut mock,
            SourceId(0),
            &ParseLimits::default()
        ))?
        .code,
        FormatCode::RendererFailed
    );
    request = self::request()?;
    mock.elapsed = Duration::from_millis(1);
    mock.bytes = vec![b'x'; ceiling.stdout_bytes + 1];
    assert_eq!(
        error(formats::render_with(
            request,
            &mut mock,
            SourceId(0),
            &ParseLimits::default()
        ))?
        .code,
        FormatCode::LimitExceeded
    );
    let invalid = ExecutionBounds {
        memory_bytes: usize::MAX,
        ..ceiling
    };
    assert!(
        formats::plan_kustomize(
            snapshot(&[("kustomization.yaml", "{}")])?,
            tool("kustomize-5.8.3")?,
            ".",
            invalid
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn generated_chart_literals_are_quoted_and_values_are_finite_and_deterministic() -> TestResult {
    let source = DEPLOYMENT.replace(
        "image: example/app:v1",
        "image: '{{ lookup \"v1\" \"Secret\" \"ns\" \"token\" }}'",
    );
    let imported = import(&source, RenderedKind::Manifest)?;
    let id = imported.resources().documents()[0].id();
    let mut chart = chart();
    chart.parameters.push(HelmParameter {
        name: "replicas".into(),
        resource: id,
        field: WorkloadField::Replicas,
    });
    let tree = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &chart,
        vec!["helm-3.22.0".into(), "helm-4.3.0".into()],
    )?;
    let again = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &chart,
        vec!["helm-3.22.0".into(), "helm-4.3.0".into()],
    )?;
    let template = String::from_utf8(file(&tree, "templates/0000.yaml")?)?;
    assert!(template.contains("{{ .Values.replicas | toJson }}"));
    assert!(template.contains("{{ print \"\\\"{{ lookup"));
    assert_eq!(file(&tree, "values.yaml")?, b"---\n{\"replicas\":2}\n");
    assert_eq!(
        file(&tree, "templates/0000.yaml")?,
        file(&again, "templates/0000.yaml")?
    );
    let schema: serde_json::Value = serde_json::from_slice(&file(&tree, "values.schema.json")?)?;
    assert_eq!(schema["additionalProperties"], false);
    assert!(!format!("{tree:?}").contains("lookup"));
    Ok(())
}
#[test]
fn generation_defaults_deny_protected_payload_and_reject_template_keys() -> TestResult {
    let private = DEPLOYMENT.replace(
        "image: example/app:v1",
        "image: example/app:v1, env: [{name: TOKEN, value: PRIVATE-format-token}]",
    );
    let imported = import(&private, RenderedKind::Manifest)?;
    let id = imported.resources().documents()[0].id();
    assert!(
        formats::generate_chart(
            imported.resources(),
            &target()?,
            &GenerationOptions::default(),
            &chart(),
            vec!["helm-4.3.0".into()]
        )
        .is_err()
    );
    let mut invalid = chart();
    invalid.parameters.push(HelmParameter {
        name: "{{ injected }}".into(),
        resource: id,
        field: WorkloadField::Replicas,
    });
    assert_eq!(
        error(formats::generate_chart(
            imported.resources(),
            &target()?,
            &options(),
            &invalid,
            vec!["helm-4.3.0".into()]
        ))?
        .code,
        FormatCode::UnsupportedVariation
    );
    Ok(())
}
#[test]
fn generated_overlays_only_select_requested_native_edits_and_validate_values() -> TestResult {
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    let id = imported.resources().documents()[0].id();
    let overlays = vec![KustomizeOverlay {
        name: "test".into(),
        variations: vec![
            WorkloadVariation {
                resource: id,
                field: WorkloadField::Replicas,
                value: NativeValue::Replicas(3),
            },
            WorkloadVariation {
                resource: id,
                field: WorkloadField::Image {
                    container: "main".into(),
                },
                value: NativeValue::Image("example/app:v2".into()),
            },
        ],
    }];
    let tree = formats::generate_kustomize(
        imported.resources(),
        &target()?,
        &options(),
        &overlays,
        vec!["kustomize-5.8.3".into(), "kubectl-1.20.15-kustomize-2.0.3".into()],
    )?;
    let patch = String::from_utf8(file(&tree, "overlays/test/patches.yaml")?)?;
    assert!(patch.contains("\"replicas\":3"));
    assert!(patch.contains("\"name\":\"main\""));
    assert!(patch.contains("example/app:v2"));
    assert!(!patch.contains("selector"));
    assert!(file(&tree, "overlays/inferred/kustomization.yaml").is_err());
    let request = tree.plan_kustomize(
        tool("kubectl-1.20.15-kustomize-2.0.3")?,
        "overlays/test",
        ExecutionBounds::ceiling(RenderCommand::KubectlKustomize)?,
    )?;
    assert_eq!(request.command(), RenderCommand::KubectlKustomize);
    let invalid = vec![KustomizeOverlay {
        name: "test".into(),
        variations: vec![WorkloadVariation {
            resource: id,
            field: WorkloadField::Image {
                container: "absent".into(),
            },
            value: NativeValue::Image("example/app:v2".into()),
        }],
    }];
    assert!(
        formats::generate_kustomize(
            imported.resources(),
            &target()?,
            &options(),
            &invalid,
            vec!["kustomize-5.8.3".into()]
        )
        .is_err()
    );
    Ok(())
}
#[test]
fn generated_chart_validation_plans_never_apply_install_or_publish() -> TestResult {
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    let tree = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &chart(),
        vec!["helm-3.22.0".into()],
    )?;
    for command in [RenderCommand::HelmLint, RenderCommand::HelmPackage] {
        let request = tree.plan_chart_validation(command, tool("helm-3.22.0")?, ExecutionBounds::ceiling(command)?)?;
        let (_, argv) = request.invocation(&ExplicitArtifactAccess::explicitly_allow_raw_artifact());
        assert!(
            !argv
                .iter()
                .any(|s| matches!(s.as_str(), "install" | "upgrade" | "push" | "apply"))
        );
    }
    let mut context = context();
    context.chart = ".".into();
    context.values = "values.yaml".into();
    assert_eq!(
        tree.plan_chart_render(
            tool("helm-3.22.0")?,
            &context,
            ExecutionBounds::ceiling(RenderCommand::HelmGeneratedTemplate)?
        )?
        .command(),
        RenderCommand::HelmGeneratedTemplate
    );
    Ok(())
}

#[test]
fn native_render_failure_retains_stderr_only_with_explicit_access() -> TestResult {
    let mut mock = Mock {
        status: RendererStatus::Exit(42),
        profile: "kustomize-5.8.3".into(),
        bytes: PRIVATE.as_bytes().to_vec(),
        elapsed: Duration::from_millis(1),
        calls: 0,
    };
    let failure = error(formats::render_with(
        request()?,
        &mut mock,
        SourceId(0),
        &ParseLimits::default(),
    ))?;
    assert!(!format!("{failure:?}{failure}").contains(PRIVATE));
    let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
    let output = failure.renderer_output(&access).ok_or("native failure evidence lost")?;
    assert_eq!(output.stderr(&access), PRIVATE.as_bytes());
    Ok(())
}

#[test]
fn explicit_hook_policy_and_empty_values_are_supported_without_execution() -> TestResult {
    let body = DEPLOYMENT.replace(
        "metadata: {name: app, namespace: ns}",
        "metadata: {name: app, namespace: ns, annotations: {helm.sh/hook: pre-install}}",
    );
    let imported = import(&body, RenderedKind::HelmTemplate)?;
    assert!(
        formats::generate_chart(
            imported.resources(),
            &target()?,
            &options(),
            &chart(),
            vec!["helm-4.3.0".into()]
        )
        .is_err()
    );
    let mut intent = chart();
    intent.hooks = HookPolicy::PreserveWithFinding;
    let output = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &intent,
        vec!["helm-4.3.0".into()],
    )?;
    assert!(output.findings().contains(&FormatCode::HookLifecycle));
    let kustomized = formats::generate_kustomize(
        imported.resources(),
        &target()?,
        &options(),
        &[],
        vec!["kustomize-5.8.3".into()],
    )?;
    assert!(kustomized.findings().contains(&FormatCode::HookLifecycle));
    let plan = formats::plan_helm(
        snapshot(&[
            ("chart/Chart.yaml", "apiVersion: v2\nname: chart\nversion: 1.0.0"),
            ("values.yaml", ""),
        ])?,
        tool("helm-4.3.0")?,
        &context(),
        ExecutionBounds::ceiling(RenderCommand::HelmTemplate)?,
    )?;
    assert_eq!(plan.command(), RenderCommand::HelmTemplate);
    Ok(())
}

#[test]
fn generated_quantity_defaults_and_overlay_errors_preserve_native_lexemes() -> TestResult {
    let body = DEPLOYMENT.replace(
        "image: example/app:v1",
        "image: example/app:v1, resources: {requests: {cpu: '250m'}, limits: {cpu: '1'}}",
    );
    let imported = import(&body, RenderedKind::Manifest)?;
    let id = imported.resources().documents()[0].id();
    let field = WorkloadField::Quantity {
        container: "main".into(),
        side: formats::ResourceSide::Requests,
        resource: formats::ResourceQuantity::Cpu,
    };
    let mut intent = chart();
    intent.parameters.push(HelmParameter {
        name: "cpu".into(),
        resource: id,
        field: field.clone(),
    });
    let output = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &intent,
        vec!["helm-4.3.0".into()],
    )?;
    assert_eq!(file(&output, "values.yaml")?, b"---\n{\"cpu\":\"250m\"}\n");
    let invalid = vec![KustomizeOverlay {
        name: "test".into(),
        variations: vec![WorkloadVariation {
            resource: id,
            field,
            value: NativeValue::Quantity("not-a-quantity".into()),
        }],
    }];
    let failure = error(formats::generate_kustomize(
        imported.resources(),
        &target()?,
        &options(),
        &invalid,
        vec!["kustomize-5.8.3".into()],
    ))?;
    assert!(!failure.native_findings.is_empty());
    assert!(!format!("{failure:?}").contains("not-a-quantity"));
    Ok(())
}

#[test]
fn generated_resource_version_boundary_is_native_validation_not_renderer_success() -> TestResult {
    let body = "apiVersion: batch/v1\nkind: CronJob\nmetadata: {name: scheduled}\nspec:\n  schedule: '0 0 * * *'\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          restartPolicy: Never\n          containers: [{name: main, image: example/job:v1}]\n";
    let imported = import(body, RenderedKind::Manifest)?;
    let old = TargetProfile::documented_defaults(KubernetesVersion::new(1, 20)?);
    let failure = error(formats::generate_chart(
        imported.resources(),
        &old,
        &options(),
        &chart(),
        vec!["helm-3.22.0".into()],
    ))?;
    assert!(
        failure
            .native_findings
            .iter()
            .any(|f| f.code == kubernetes_lens::FindingCode::UnavailableApi)
    );
    assert!(
        formats::generate_chart(
            imported.resources(),
            &target()?,
            &options(),
            &chart(),
            vec!["helm-3.22.0".into()]
        )
        .is_ok()
    );
    Ok(())
}

#[test]
fn explicit_lint_and_package_validation_propagate_native_failure_without_manifest_import() -> TestResult {
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    let tree = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &chart(),
        vec!["helm-3.22.0".into()],
    )?;
    for command in [RenderCommand::HelmLint, RenderCommand::HelmPackage] {
        let request = tree.plan_chart_validation(command, tool("helm-3.22.0")?, ExecutionBounds::ceiling(command)?)?;
        let mut mock = Mock {
            status: RendererStatus::Success,
            profile: "helm-3.22.0".into(),
            bytes: PRIVATE.as_bytes().to_vec(),
            elapsed: Duration::from_millis(1),
            calls: 0,
        };
        let output = formats::execute_with(&request, &mut mock)?;
        assert_eq!(output.status(), RendererStatus::Success);
        assert_eq!(
            output.stdout(&ExplicitArtifactAccess::explicitly_allow_raw_artifact()),
            PRIVATE.as_bytes()
        );
        mock.status = RendererStatus::Exit(1);
        assert_eq!(
            error(formats::execute_with(&request, &mut mock))?.code,
            FormatCode::RendererFailed
        );
    }
    Ok(())
}

#[test]
fn package_reply_requires_an_artifact_and_shares_the_stdout_allowance() -> TestResult {
    struct Reply(Option<RendererOutput>);
    impl OfflineRenderer for Reply {
        fn execute(&mut self, _: &RenderRequest) -> Result<RendererOutput, FormatError> {
            self.0
                .take()
                .ok_or_else(|| FormatError::new(FormatCode::RendererFailed))
        }
    }
    let imported = import(DEPLOYMENT, RenderedKind::Manifest)?;
    let tree = formats::generate_chart(
        imported.resources(),
        &target()?,
        &options(),
        &chart(),
        vec!["helm-3.22.0".into()],
    )?;
    for (command, artifact, stdout, limit, expected) in [
        (RenderCommand::HelmPackage, true, 1, 2, None),
        (
            RenderCommand::HelmPackage,
            false,
            0,
            2,
            Some(FormatCode::RendererFailed),
        ),
        (RenderCommand::HelmLint, true, 0, 2, Some(FormatCode::RendererFailed)),
        (RenderCommand::HelmPackage, true, 2, 2, Some(FormatCode::LimitExceeded)),
    ] {
        let mut bounds = ExecutionBounds::ceiling(command)?;
        bounds.stdout_bytes = limit;
        let request = tree.plan_chart_validation(command, tool("helm-3.22.0")?, bounds)?;
        let mut output = RendererOutput::new(
            "helm-3.22.0".into(),
            RendererStatus::Success,
            vec![1; stdout],
            Vec::new(),
            Duration::from_millis(1),
        );
        if artifact {
            output = output.with_package(formats::PackagedChart::new("demo-1.0.0.tgz".into(), vec![1])?);
        }
        let result = formats::execute_with(&request, &mut Reply(Some(output)));
        if let Some(code) = expected {
            assert_eq!(error(result)?.code, code);
        } else {
            let access = ExplicitArtifactAccess::explicitly_allow_raw_artifact();
            assert_eq!(result?.package(&access).ok_or("missing package")?.bytes(&access), &[1]);
        }
    }
    Ok(())
}

#[test]
fn generated_parameters_and_overlays_bind_native_resource_ids_across_reordered_roots() -> TestResult {
    for (first_name, first_ns, second_name, second_ns, list) in [
        ("z", "ns", "a", "ns", false),
        ("app", "z", "app", "a", false),
        ("z", "z", "a", "a", true),
    ] {
        let make = |name: &str, namespace: &str, replicas: u32, image: &str| {
            serde_json::json!({
                "apiVersion":"apps/v1", "kind":"Deployment", "metadata":{"name":name,"namespace":namespace},
                "spec":{"replicas":replicas,"selector":{"matchLabels":{"app":name}},
                    "template":{"metadata":{"labels":{"app":name}},"spec":{"containers":[{"name":"main","image":image}]}}},
                "x-private":{"marker":image}
            })
        };
        let first = make(first_name, first_ns, 7, "example/selected:v7");
        let second = make(second_name, second_ns, 2, "example/other:v2");
        let source = if list {
            serde_json::json!({"apiVersion":"v1","kind":"List","items":[first,second]}).to_string()
        } else {
            format!("{first}\n---\n{second}")
        };
        let imported = import(&source, RenderedKind::Manifest)?;
        let selected = imported.resources().documents()[0].id();
        let identity = imported.resources().documents()[0].identity()?;
        assert_eq!(identity.name.value().map(String::as_str), Some(first_name));
        assert_eq!(identity.namespace.value().map(String::as_str), Some(first_ns));
        let mut generation = options();
        generation.collections = kubernetes_lens::generation::CollectionOutput::Flatten;
        let mut chart = chart();
        chart.parameters = vec![
            HelmParameter {
                name: "replicas".into(),
                resource: selected,
                field: WorkloadField::Replicas,
            },
            HelmParameter {
                name: "image".into(),
                resource: selected,
                field: WorkloadField::Image {
                    container: "main".into(),
                },
            },
        ];
        let helm = formats::generate_chart(
            imported.resources(),
            &target()?,
            &generation,
            &chart,
            vec!["helm-4.3.0".into()],
        )?;
        let defaults: serde_json::Value = serde_json::from_slice(&file(&helm, "values.yaml")?[4..])?;
        assert_eq!(defaults["replicas"], 7);
        assert_eq!(defaults["image"], "example/selected:v7");
        assert_selected_templates(&helm, first_name, first_ns)?;
        let overlay = KustomizeOverlay {
            name: "edit".into(),
            variations: vec![
                WorkloadVariation {
                    resource: selected,
                    field: WorkloadField::Replicas,
                    value: NativeValue::Replicas(77),
                },
                WorkloadVariation {
                    resource: selected,
                    field: WorkloadField::Image {
                        container: "main".into(),
                    },
                    value: NativeValue::Image("example/edited:v8".into()),
                },
            ],
        };
        let kustomize = formats::generate_kustomize(
            imported.resources(),
            &target()?,
            &generation,
            &[overlay],
            vec!["kustomize-5.8.3".into()],
        )?;
        let patch: serde_json::Value = serde_json::from_slice(&file(&kustomize, "overlays/edit/patches.yaml")?[4..])?;
        assert_eq!(patch["metadata"]["name"], first_name);
        assert_eq!(patch["metadata"]["namespace"], first_ns);
        assert_eq!(patch["spec"]["replicas"], 77);
        assert_eq!(
            patch["spec"]["template"]["spec"]["containers"][0]["image"],
            "example/edited:v8"
        );
        assert!(patch.get("x-private").is_none());
        assert_unselected_base(&kustomize, first_name, first_ns)?;
    }
    Ok(())
}

fn assert_selected_templates(helm: &formats::ArtifactTree, first_name: &str, first_ns: &str) -> TestResult {
    let mut seen = [0; 2];
    for index in 0..2 {
        let template = String::from_utf8(file(helm, &format!("templates/{index:04}.yaml"))?)?;
        let rendered = template
            .replace("{{ .Values.replicas | toJson }}", "77")
            .replace("{{ .Values.image | toJson }}", "\"example/edited:v8\"");
        let rendered = decode_template_literals(&rendered)?;
        let root: serde_json::Value = serde_json::from_str(&rendered[4..])?;
        let chosen = root["metadata"]["name"] == first_name && root["metadata"]["namespace"] == first_ns;
        seen[usize::from(chosen)] += 1;
        assert_eq!(root["spec"]["replicas"], if chosen { 77 } else { 2 });
        assert_eq!(
            root["spec"]["template"]["spec"]["containers"][0]["image"],
            if chosen {
                "example/edited:v8"
            } else {
                "example/other:v2"
            }
        );
        assert_eq!(
            root["x-private"]["marker"],
            if chosen {
                "example/selected:v7"
            } else {
                "example/other:v2"
            }
        );
    }
    assert_eq!(seen, [1, 1]);
    Ok(())
}

fn assert_unselected_base(kustomize: &formats::ArtifactTree, first_name: &str, first_ns: &str) -> TestResult {
    let mut seen = [0; 2];
    let base = String::from_utf8(file(kustomize, "base/resources.yaml")?)?;
    for text in base.split("---\n").filter(|text| !text.trim().is_empty()) {
        let root: serde_json::Value = serde_json::from_str(text)?;
        let chosen = root["metadata"]["name"] == first_name && root["metadata"]["namespace"] == first_ns;
        seen[usize::from(chosen)] += 1;
        assert_eq!(root["spec"]["replicas"], if chosen { 7 } else { 2 });
        assert_eq!(
            root["x-private"]["marker"],
            if chosen {
                "example/selected:v7"
            } else {
                "example/other:v2"
            }
        );
    }
    assert_eq!(seen, [1, 1]);
    Ok(())
}

// Interpret only the documented quoted `print` literals in these fixtures, not Helm.
fn decode_template_literals(template: &str) -> Result<String, Box<dyn std::error::Error>> {
    let mut remaining = template;
    let mut output = String::new();
    while let Some(start) = remaining.find("{{ print ") {
        output.push_str(&remaining[..start]);
        let quoted = &remaining[start + "{{ print ".len()..];
        let mut literal = serde_json::Deserializer::from_str(quoted).into_iter::<String>();
        output.push_str(&literal.next().ok_or("missing quoted print literal")??);
        let tail = &quoted[literal.byte_offset()..];
        remaining = tail.strip_prefix(" }}").ok_or("unexpected print suffix")?;
    }
    output.push_str(remaining);
    Ok(output)
}

#[test]
fn kustomize_local_v1beta1_vars_remain_supplied_and_bounded() -> TestResult {
    let declaration = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources: [manager.yaml]\nvars:\n- name: MANAGER_IMAGE\n  objref: {apiVersion: apps/v1, kind: Deployment, name: app}\n  fieldref: {fieldpath: 'spec.template.spec.containers[0].image'}\n- name: MANAGER_NAME\n  objref: {apiVersion: apps/v1, kind: Deployment, name: app}\n";
    for profile in ["kustomize-5.8.3", "kubectl-1.37.0-kustomize-5.8.1"] {
        let command = if profile.starts_with("kubectl") {
            RenderCommand::KubectlKustomize
        } else {
            RenderCommand::KustomizeBuild
        };
        formats::plan_kustomize(
            snapshot(&[("kustomization.yaml", declaration), ("manager.yaml", DEPLOYMENT)])?,
            tool(profile)?,
            ".",
            ExecutionBounds::ceiling(command)?,
        )?;
    }
    for body in [
        "vars: [{name: IMAGE, objref: {apiVersion: apps/v1, kind: Deployment}}]",
        "vars: [{name: IMAGE, objref: {apiVersion: apps/v1, kind: Deployment, name: app}, fieldref: {fieldpath: 1}}]",
        "vars: [{name: IMAGE, objref: {apiVersion: apps/v1, kind: Deployment, name: app}, fieldref: {fieldpath: 'https://remote/value'}}]",
        "vars: [{name: IMAGE, objref: {apiVersion: apps/v1, kind: Deployment, name: app}}, {name: IMAGE, objref: {apiVersion: apps/v1, kind: Deployment, name: app}}]",
    ] {
        assert_eq!(
            error(formats::plan_kustomize(
                snapshot(&[("kustomization.yaml", body)])?,
                tool("kustomize-5.8.3")?,
                ".",
                ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?
            ))?
            .code,
            FormatCode::InvalidProject
        );
    }
    let unsupported = declaration.replace("v1beta1", "v1");
    assert_eq!(
        error(formats::plan_kustomize(
            snapshot(&[("kustomization.yaml", &unsupported), ("manager.yaml", DEPLOYMENT)])?,
            tool("kustomize-5.8.3")?,
            ".",
            ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?
        ))?
        .code,
        FormatCode::UnsupportedExtension
    );
    let limited = ProjectSnapshot::new(
        vec![
            LocalFile::new(
                "kustomization.yaml".into(),
                declaration.as_bytes().to_vec(),
                provenance()?,
            ),
            LocalFile::new("manager.yaml".into(), DEPLOYMENT.as_bytes().to_vec(), provenance()?),
        ],
        ProjectLimits {
            references: 3,
            ..ProjectLimits::default()
        },
    )?;
    assert_eq!(
        error(formats::plan_kustomize(
            limited,
            tool("kustomize-5.8.3")?,
            ".",
            ExecutionBounds::ceiling(RenderCommand::KustomizeBuild)?
        ))?
        .code,
        FormatCode::LimitExceeded
    );
    Ok(())
}

// Unchanged CNPG declaration, Apache-2.0 redistributable configuration fixture.
// Revision 2a35abb4628f209d149825ef3c38011e0701ff2f; source/config/manager/kustomization.yaml.
// SHA256 28af10f1f0cb4d7472b045c7647414ef9dad020599c2d5b7c6eb6befb2848908 (657 bytes).
// Native payloads below are local test placeholders: this tests declaration admission only.
#[test]
fn unchanged_cnpg_vars_declaration_is_admitted_without_source_rewriting() -> TestResult {
    let declaration = "apiVersion: kustomize.config.k8s.io/v1beta1\nkind: Kustomization\nresources:\n- manager.yaml\n- default-monitoring.yaml\n\nvars:\n  - name: OPERATOR_IMAGE_NAME\n    objref:\n      kind: Deployment\n      name: controller-manager\n      apiVersion: apps/v1\n    fieldref:\n      fieldpath: spec.template.spec.containers[0].image\n  - name: OPERATOR_DEPLOYMENT_NAME\n    objref:\n      kind: Deployment\n      name: controller-manager\n      apiVersion: apps/v1\n    fieldref:\n      fieldpath: metadata.name\n  - name: DEFAULT_MONITORING_CONFIGMAP\n    objref:\n      kind: ConfigMap\n      name: default-monitoring\n      apiVersion: v1\n    fieldref:\n      fieldpath: metadata.name\n";
    for (profile, command) in [
        ("kustomize-5.8.3", RenderCommand::KustomizeBuild),
        ("kubectl-1.20.15-kustomize-2.0.3", RenderCommand::KubectlKustomize),
        ("kubectl-1.37.0-kustomize-5.8.1", RenderCommand::KubectlKustomize),
    ] {
        formats::plan_kustomize(
            snapshot(&[
                ("kustomization.yaml", declaration),
                ("manager.yaml", DEPLOYMENT),
                (
                    "default-monitoring.yaml",
                    "apiVersion: v1\nkind: ConfigMap\nmetadata: {name: default-monitoring}\n",
                ),
            ])?,
            tool(profile)?,
            ".",
            ExecutionBounds::ceiling(command)?,
        )?;
    }
    Ok(())
}

#[test]
fn absent_replica_and_container_fields_refuse_semantic_conversion() -> TestResult {
    for (source, field, value) in [
        (
            DEPLOYMENT.replace("  replicas: 2\n", ""),
            WorkloadField::Replicas,
            NativeValue::Replicas(3),
        ),
        (
            DEPLOYMENT.to_owned(),
            WorkloadField::Image {
                container: "absent".into(),
            },
            NativeValue::Image("example/app:v2".into()),
        ),
    ] {
        let imported = import(&source, RenderedKind::Manifest)?;
        let resources = imported.resources();
        let id = resources.documents()[0].id();
        let mut selection = chart();
        selection.parameters.push(HelmParameter {
            name: "selected".into(),
            resource: id,
            field: field.clone(),
        });
        let chart_error = error(formats::generate_chart(
            resources,
            &target()?,
            &options(),
            &selection,
            vec!["helm-4.3.0".into()],
        ))?;
        assert_eq!(chart_error.code, FormatCode::UnsupportedVariation);
        assert_eq!(chart_error.code.as_str(), "unsupported-semantic-conversion");
        let overlay = [KustomizeOverlay {
            name: "selected".into(),
            variations: vec![WorkloadVariation {
                resource: id,
                field,
                value,
            }],
        }];
        let overlay_error = error(formats::generate_kustomize(
            resources,
            &target()?,
            &options(),
            &overlay,
            vec!["kustomize-5.8.3".into()],
        ))?;
        assert_eq!(overlay_error.code, FormatCode::UnsupportedVariation);
        assert_eq!(overlay_error.code.as_str(), "unsupported-semantic-conversion");
    }
    Ok(())
}

#[test]
fn native_private_and_unverified_names_survive_explicit_renderer_artifacts_only() -> TestResult {
    let role_name = "system:reader Ω";
    let custom_name = "Private/Unknown Ω";
    let role = format!(
        "apiVersion: rbac.authorization.k8s.io/v1\nkind: Role\nmetadata: {{name: '{role_name}', namespace: ns}}\nrules: [{{apiGroups: [''], resources: [pods], verbs: [get]}}]\n"
    );
    let custom = DEPLOYMENT.replace("apps/v1", "example.test/v99").replace(
        "name: app, namespace: ns",
        &format!("name: '{custom_name}', namespace: ns"),
    );
    for (source, expected_name, unverified) in [(role, role_name, false), (custom, custom_name, true)] {
        let imported = import(&source, RenderedKind::Manifest)?;
        let resources = imported.resources();
        let mut deny = options();
        deny.protected_output = ProtectedOutput::Deny;
        for denied in [
            formats::generate_chart(resources, &target()?, &deny, &chart(), vec!["helm-4.3.0".into()]),
            formats::generate_kustomize(resources, &target()?, &deny, &[], vec!["kustomize-5.8.3".into()]),
        ] {
            let refusal = error(denied)?;
            assert_eq!(refusal.code, FormatCode::InvalidProject);
            assert!(
                refusal
                    .native_findings
                    .iter()
                    .any(|finding| finding.code == kubernetes_lens::FindingCode::ProtectedOutputDenied)
            );
            assert!(!format!("{refusal:?}").contains(expected_name));
        }
        let helm = formats::generate_chart(resources, &target()?, &options(), &chart(), vec!["helm-4.3.0".into()])?;
        let kustomize =
            formats::generate_kustomize(resources, &target()?, &options(), &[], vec!["kustomize-5.8.3".into()])?;
        for artifact in [&helm, &kustomize] {
            let warning = artifact
                .native_findings()
                .iter()
                .find(|finding| finding.code == kubernetes_lens::FindingCode::NativeNamingUnverified);
            assert_eq!(warning.is_some(), unverified);
            if let Some(warning) = warning {
                assert_eq!(warning.severity, kubernetes_lens::diagnostic::Severity::Warning);
                assert!(warning.source.is_some());
            }
            assert!(!format!("{artifact:?}").contains(expected_name));
        }
        // These checks inspect protected literal artifacts, never execute Helm or Kustomize.
        let template = String::from_utf8(file(&helm, "templates/0000.yaml")?)?;
        let decoded = decode_template_literals(&template)?;
        let helm_root: serde_json::Value =
            serde_json::from_str(decoded.strip_prefix("---\n").ok_or("template document marker")?)?;
        let base = String::from_utf8(file(&kustomize, "base/resources.yaml")?)?;
        let base_root: serde_json::Value =
            serde_json::from_str(base.strip_prefix("---\n").ok_or("base document marker")?)?;
        for root in [&helm_root, &base_root] {
            assert_eq!(root["metadata"]["name"].as_str(), Some(expected_name));
            assert_eq!(root["metadata"]["namespace"].as_str(), Some("ns"));
        }
        if unverified {
            let mut selected = chart();
            selected.parameters.push(HelmParameter {
                name: "replicas".into(),
                resource: resources.documents()[0].id(),
                field: WorkloadField::Replicas,
            });
            let refusal = error(formats::generate_chart(
                resources,
                &target()?,
                &options(),
                &selected,
                vec!["helm-4.3.0".into()],
            ))?;
            assert_eq!(refusal.code, FormatCode::UnsupportedVariation);
            assert_eq!(refusal.code.as_str(), "unsupported-semantic-conversion");
        }
    }
    Ok(())
}
