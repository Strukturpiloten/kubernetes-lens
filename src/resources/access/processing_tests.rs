//! Actual access roots under lower inherited sessions, without allocator/RSS claims.
use super::*;
use crate::{
    capability::{KubernetesVersion, TargetProfile},
    model::ResourceSet,
    processing::{NativeOperationBudget, NativeProcessingLimits},
    resources::{
        access::{Namespace, PodSecurityPolicy, RoleBinding, ServiceAccount},
        common::{UnknownScopeVisitor, UnknownScopes},
    },
    source::{DocumentFormat, InputOrigin, ParseLimits, SourceId, SourceInput},
};
use serde_json::{Value, json};
use std::collections::BTreeSet;
type TestResult<T = ()> = Result<T, String>;
fn require<T, E>(result: Result<T, E>) -> TestResult<T> {
    result.map_err(|_| "unexpected access fixture failure".into())
}
fn fixture(value: &Value) -> TestResult<ResourceSet> {
    let bytes = require(serde_json::to_vec(value))?;
    require(
        require(crate::parse_source(
            SourceInput {
                id: SourceId(812),
                format: DocumentFormat::Json,
                origin: InputOrigin::Authored,
                source_version: None,
                bytes: &bytes,
            },
            &ParseLimits::default(),
        ))?
        .flatten_resources(),
    )
}
fn target() -> TestResult<TargetProfile> {
    Ok(TargetProfile::documented_defaults(require(KubernetesVersion::new(
        1, 37,
    ))?))
}
fn sa(items: &Value) -> Value {
    json!({"apiVersion":"v1","kind":"ServiceAccount","metadata":{"name":"sa","namespace":"n"},"secrets":items})
}
struct StopAfterOne {
    values: Vec<Reference>,
}
impl ReferenceSink for StopAfterOne {
    fn exhausted(&self) -> bool {
        !self.values.is_empty()
    }
    fn push(&mut self, reference: Reference) {
        assert!(!self.exhausted());
        self.values.push(reference);
    }
}
#[test]
fn supplied_service_account_sink_exhaustion_stops_before_later_references() -> TestResult {
    let set = fixture(&sa(&json!([{"name":"first"},{"name":"second"},{"name":"third"}])))?;
    let resource = set.documents()[0]
        .resource::<ServiceAccount>()
        .ok_or("missing ServiceAccount")?;
    let target = target()?;
    let mut sink = StopAfterOne { values: Vec::new() };
    references(resource, &EncodeContext::new(Some(&target)), &mut sink);
    assert_eq!(sink.values.len(), 1);
    assert_eq!(sink.values[0].path.0, ["metadata", "namespace"]);
    Ok(())
}

#[test]
fn effective_psp_terminal_reference_sink_prevents_all_later_work_and_payload() -> TestResult {
    // First-push success measures the prefix, independent of whether later work
    // exhausts the operation. It does not inspect private budget counters.
    fn first_push_ceiling(mut first_push: impl FnMut(usize) -> bool, mut high: usize) -> usize {
        assert!(first_push(high));
        let mut low = 0;
        while low < high {
            let mid = low + (high - low) / 2;
            if first_push(mid) {
                high = mid;
            } else {
                low = mid + 1;
            }
        }
        low
    }
    let names = (0..64).map(|index| format!("runtime-{index}")).collect::<Vec<_>>();
    let set = fixture(&json!({"apiVersion":"policy/v1beta1","kind":"PodSecurityPolicy",
        "metadata":{"name":"policy"},
        "spec":{"runtimeClass":{"allowedRuntimeClassNames":names}}}))?;
    let resource = set.documents()[0]
        .resource::<PodSecurityPolicy>()
        .ok_or("missing PodSecurityPolicy")?;
    let mut resource = resource.clone();
    // A valid cluster-scoped source can be edited before validation. Collector
    // limits must still hold for this effective, scope-invalid metadata edit.
    let Presence::Value(metadata) = &mut resource.metadata else {
        return Err("missing metadata".into());
    };
    metadata.namespace = Presence::Value("n".into());
    let resource = &resource;
    let mut ordinary = Vec::new();
    references(resource, &EncodeContext::new(None), &mut ordinary);
    assert_eq!(ordinary.len(), 65);
    assert_eq!(ordinary[0].path.0, ["metadata", "namespace"]);
    assert_eq!(
        ordinary[1].path.0,
        ["spec", "runtimeClass", "allowedRuntimeClassNames", "0"]
    );
    assert_eq!(ordinary[1].relation, RelationshipKind::Identity);
    let defaults = NativeProcessingLimits::default();
    let work = first_push_ceiling(
        |units| {
            let budget = NativeOperationBudget::new(NativeProcessingLimits {
                max_processing_units: units,
                ..defaults
            });
            let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget);
            let mut sink = StopAfterOne { values: Vec::new() };
            references(resource, &ctx, &mut sink);
            sink.values.len() == 1
        },
        defaults.max_processing_units,
    );
    let payload = first_push_ceiling(
        |bytes| {
            let budget = NativeOperationBudget::new(NativeProcessingLimits {
                max_payload_bytes: bytes,
                ..defaults
            });
            let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget);
            let mut sink = StopAfterOne { values: Vec::new() };
            references(resource, &ctx, &mut sink);
            sink.values.len() == 1
        },
        defaults.max_payload_bytes,
    );
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_processing_units: work,
        max_payload_bytes: payload,
        ..defaults
    });
    let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
    let mut sink = StopAfterOne { values: Vec::new() };
    references(resource, &ctx, &mut sink);
    assert_eq!(sink.values.len(), 1);
    assert_eq!(sink.values[0].path.0, ["metadata", "namespace"]);
    // Both first-push allowances are exactly full but not exceeded. Any positive
    // post-push reservation would make exhaustion sticky, even without a callback.
    assert!(!budget.exhausted());
    assert!(budget.work(0, Phase::Analysis).is_ok());
    assert!(budget.payload(0, Phase::Analysis).is_ok());
    Ok(())
}
#[test]
fn already_exhausted_reference_sink_does_not_encode_or_spend_payload() -> TestResult {
    let set = fixture(&sa(&json!([{"name":"private"}])))?;
    let resource = set.documents()[0]
        .resource::<ServiceAccount>()
        .ok_or("missing ServiceAccount")?;
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_payload_bytes: 0,
        max_processing_units: 1,
        ..NativeProcessingLimits::default()
    });
    let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
    let mut sink = StopAfterOne {
        values: vec![Reference {
            from: ResourceId(0),
            path: FieldPath::default(),
            relation: RelationshipKind::Identity,
            target: ReferenceTarget::External {
                kind: ExternalRefKind::Other,
            },
            scope: ReferenceScope::Unknown,
        }],
    };
    references(resource, &ctx, &mut sink);
    assert!(!budget.exhausted());
    assert!(budget.work(1, Phase::Analysis).is_ok());
    Ok(())
}
#[test]
fn native_namespace_labels_cannot_clone_past_payload_ceiling() -> TestResult {
    let value =
        json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"n","labels":{"private":"x".repeat(4096)}}});
    let set = fixture(&value)?;
    let document = &set.documents()[0];
    let resource = document.resource::<Namespace>().ok_or("missing Namespace")?;
    let tree = require(resource.encode(&EncodeContext::new(None), &FieldPath::default()))?;
    let gvk = require(GroupVersionKind::new("v1", "Namespace"))?;
    let capability = require(crate::resources::access::capabilities::for_api(gvk.clone()))?;
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_payload_bytes: 256,
        ..NativeProcessingLimits::default()
    });
    let target = target()?;
    let ctx = ProjectionContext::new_in(
        &tree,
        &gvk,
        document.source_evidence(),
        Some(&target),
        &capability,
        budget.clone(),
    );
    let mut facts = Vec::new();
    native(&ctx, &mut facts);
    assert!(facts.is_empty());
    assert!(budget.exhausted());
    assert!(budget.work(0, Phase::Analysis).is_err());
    Ok(())
}
#[test]
fn malformed_or_empty_labels_never_reset_an_exhausted_operation() -> TestResult {
    for malformed in [false, true] {
        let set = fixture(&json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"n","labels":{}}}))?;
        let document = &set.documents()[0];
        let resource = document.resource::<Namespace>().ok_or("missing Namespace")?;
        let mut tree = require(resource.encode(&EncodeContext::new(None), &FieldPath::default()))?;
        if malformed {
            // Typed decoding rejects a boolean label. Exercise the fallible projection
            // boundary by replacing only that field of the actual encoded Namespace.
            let TreeValue::Mapping(root) = &mut tree.value else {
                return Err("missing root map".into());
            };
            let metadata = root
                .iter_mut()
                .find(|(key, _)| key == "metadata")
                .ok_or("missing metadata")?;
            let TreeValue::Mapping(entries) = &mut metadata.1.value else {
                return Err("missing metadata map".into());
            };
            let labels = entries
                .iter_mut()
                .find(|(key, _)| key == "labels")
                .ok_or("missing labels")?;
            labels.1 = TreeNode::mapping(vec![("private".into(), TreeNode::new(TreeValue::Bool(false)))]);
        }
        let gvk = require(GroupVersionKind::new("v1", "Namespace"))?;
        let capability = require(crate::resources::access::capabilities::for_api(gvk.clone()))?;
        let budget = NativeOperationBudget::new(NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        });
        let target = target()?;
        let ctx = ProjectionContext::new_in(
            &tree,
            &gvk,
            document.source_evidence(),
            Some(&target),
            &capability,
            budget.clone(),
        );
        let mut facts = Vec::new();
        native(&ctx, &mut facts);
        assert!(facts.is_empty());
        assert!(budget.exhausted());
        native(&ctx, &mut facts);
        assert!(facts.is_empty());
    }
    Ok(())
}
#[test]
fn actual_rbac_subject_scan_and_names_obey_inherited_limits() -> TestResult {
    let subjects = (0..100)
        .map(|_| json!({"kind":"Other","name":"private"}))
        .collect::<Vec<_>>();
    let set = fixture(
        &json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"r"},"subjects":subjects}),
    )?;
    let resource = set.documents()[0]
        .resource::<RoleBinding>()
        .ok_or("missing RoleBinding")?;
    let tree = require(resource.encode(&EncodeContext::new(None), &FieldPath::default()))?;
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_processing_units: 100,
        ..NativeProcessingLimits::default()
    });
    let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
    let mut values = Vec::new();
    binding(
        &tree,
        "RoleBinding",
        &mut References {
            fields: ctx.fields(Phase::Analysis),
            out: &mut values,
        },
    );
    assert!(values.is_empty());
    assert!(budget.exhausted());
    let set = fixture(
        &json!({"apiVersion":"rbac.authorization.k8s.io/v1","kind":"RoleBinding","metadata":{"name":"r"},
        "subjects":[{"kind":"ServiceAccount","namespace":"other","name":"x".repeat(4096)}]}),
    )?;
    let resource = set.documents()[0]
        .resource::<RoleBinding>()
        .ok_or("missing RoleBinding")?;
    let tree = require(resource.encode(&EncodeContext::new(None), &FieldPath::default()))?;
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_payload_bytes: 512,
        ..NativeProcessingLimits::default()
    });
    let ctx = EncodeContext::in_operation(None, ParseLimits::default(), budget.clone());
    binding(
        &tree,
        "RoleBinding",
        &mut References {
            fields: ctx.fields(Phase::Analysis),
            out: &mut values,
        },
    );
    assert!(values.is_empty());
    assert!(budget.exhausted());
    Ok(())
}
#[test]
fn protected_scan_reserves_patterns_and_paths_after_successful_encoding() -> TestResult {
    let set =
        fixture(&json!({"apiVersion":"v1","kind":"Namespace","metadata":{"name":"n"},"private":{"nested":"secret"}}))?;
    let resource = set.documents()[0].resource::<Namespace>().ok_or("missing Namespace")?;
    let limits = NativeProcessingLimits {
        max_payload_bytes: 2048,
        ..NativeProcessingLimits::default()
    };
    let target = target()?;
    let budget = NativeOperationBudget::new(limits);
    let mut ctx = EncodeContext::in_operation(Some(&target), ParseLimits::default(), budget);
    ctx.include_unknown = true;
    assert!(resource.encode(&ctx, &FieldPath::default()).is_ok());
    let budget = NativeOperationBudget::new(limits);
    let ctx = EncodeContext::in_operation(Some(&target), ParseLimits::default(), budget.clone());
    let mut paths = Vec::new();
    protected(resource, &ctx, &mut paths);
    assert!(budget.exhausted());
    assert!(paths.contains(&FieldPath::default()));
    let mut ordinary = Vec::new();
    protected(resource, &EncodeContext::new(Some(&target)), &mut ordinary);
    assert!(ordinary.contains(&FieldPath(vec!["private".into()])));
    Ok(())
}
#[test]
fn streamed_actual_unknown_helpers_preserve_scopes_and_stop_on_callback() -> TestResult {
    let value = sa(&json!([{"name":"first","private":1},{"name":"second","private":2}]));
    let set = fixture(&value)?;
    let resource = set.documents()[0]
        .resource::<ServiceAccount>()
        .ok_or("missing ServiceAccount")?;
    let mut expected = BTreeSet::new();
    resource.unknown_scopes(&FieldPath::default(), &mut expected);
    let fields = FieldDecodeContext::standalone();
    let mut actual = BTreeSet::new();
    assert!(resource.visit_unknown_scopes(
        &FieldPath::default(),
        &mut UnknownScopeVisitor::new(&fields, &mut |path| {
            actual.insert(path);
            true
        })
    ));
    assert_eq!(actual, expected);
    assert_eq!(actual.len(), 2);
    let mut emitted = Vec::new();
    assert!(!resource.visit_unknown_scopes(
        &FieldPath::default(),
        &mut UnknownScopeVisitor::new(&fields, &mut |path| {
            emitted.push(path);
            false
        })
    ));
    assert_eq!(emitted.len(), 1);
    Ok(())
}
#[test]
fn streamed_unknown_scopes_stop_on_work_payload_and_sticky_exhaustion() -> TestResult {
    let items = (0..100)
        .map(|index| json!({"name":format!("s{index}"),"private":index}))
        .collect::<Vec<_>>();
    let set = fixture(&sa(&json!(items)))?;
    let resource = set.documents()[0]
        .resource::<ServiceAccount>()
        .ok_or("missing ServiceAccount")?;
    for limits in [
        NativeProcessingLimits {
            max_processing_units: 100,
            ..NativeProcessingLimits::default()
        },
        NativeProcessingLimits {
            max_payload_bytes: 0,
            ..NativeProcessingLimits::default()
        },
    ] {
        let budget = NativeOperationBudget::new(limits);
        let fields = FieldDecodeContext::new(ParseLimits::default(), budget.clone(), Phase::Validation);
        let mut emitted = Vec::new();
        assert!(!resource.visit_unknown_scopes(
            &FieldPath::default(),
            &mut UnknownScopeVisitor::new(&fields, &mut |path| {
                emitted.push(path);
                true
            })
        ));
        assert!(budget.exhausted());
        assert!(emitted.len() < 100);
        let before = emitted.len();
        assert!(!resource.visit_unknown_scopes(
            &FieldPath::default(),
            &mut UnknownScopeVisitor::new(&fields, &mut |path| {
                emitted.push(path);
                true
            })
        ));
        assert_eq!(before, emitted.len());
    }
    Ok(())
}

#[test]
fn actual_limit_range_type_bookkeeping_reserves_copy_payload_before_insertion() {
    use crate::diagnostic::{Finding, FindingCode};
    use crate::registry::FieldDecodeContext;
    struct Report {
        fields: FieldDecodeContext,
        findings: Vec<Finding>,
    }
    impl crate::resources::access::validation::AccessSink for Report {
        fn push(&mut self, finding: Finding) {
            self.findings.push(finding);
        }
        fn exhausted(&self) -> bool {
            self.fields.processing.exhausted()
        }
        fn fields(&self) -> &FieldDecodeContext {
            &self.fields
        }
    }
    let item = TreeNode::mapping(vec![(
        "type".into(),
        TreeNode::string(format!("example.org/{}", "x".repeat(4096))),
    )]);
    let items = TreeNode::new(TreeValue::Sequence(vec![item]));
    let tree = TreeNode::mapping(vec![("spec".into(), TreeNode::mapping(vec![("limits".into(), items)]))]);
    let budget = NativeOperationBudget::new(NativeProcessingLimits {
        max_payload_bytes: 1024,
        ..NativeProcessingLimits::default()
    });
    let mut report = Report {
        fields: FieldDecodeContext::new(ParseLimits::default(), budget.clone(), Phase::Validation),
        findings: Vec::new(),
    };
    crate::resources::access::policy::limits(&tree, &mut report);
    assert!(budget.exhausted());
    assert!(
        report
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::LimitExceeded && finding.path.is_none())
    );
    assert!(
        !report
            .findings
            .iter()
            .any(|finding| finding.code == FindingCode::NativeFieldInvalid)
    );
    let count = report.findings.len();
    crate::resources::access::policy::limits(&tree, &mut report);
    assert_eq!(count, report.findings.len());
}
