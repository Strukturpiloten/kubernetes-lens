//! Exact selected extension paths and API-version boundaries.
use crate::{
    capability::{FeatureGateId, FieldAdmission, FieldCapability, KindCapability, KubernetesVersion, MergeStrategy},
    diagnostic::{Finding, FindingCode, Phase},
    model::{GroupVersionKind, ResourceScope},
};
use std::sync::LazyLock;

/// The exact `JSONSchemaProps` members retained as typed fields by the arena codec.
pub(super) const SCHEMA_FIELDS: &[&str] = &[
    "additionalItems",
    "additionalProperties",
    "allOf",
    "anyOf",
    "definitions",
    "dependencies",
    "description",
    "enum",
    "example",
    "exclusiveMaximum",
    "exclusiveMinimum",
    "externalDocs",
    "format",
    "id",
    "items",
    "maxItems",
    "maxLength",
    "maxProperties",
    "maximum",
    "minItems",
    "minLength",
    "minProperties",
    "minimum",
    "multipleOf",
    "not",
    "nullable",
    "oneOf",
    "pattern",
    "patternProperties",
    "properties",
    "required",
    "title",
    "type",
    "uniqueItems",
    "x-kubernetes-embedded-resource",
    "x-kubernetes-int-or-string",
    "x-kubernetes-list-map-keys",
    "x-kubernetes-list-type",
    "x-kubernetes-map-type",
    "x-kubernetes-preserve-unknown-fields",
];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum SchemaPathClass {
    Typed,
    ProtectedPayload,
}

fn is_index(segment: &str) -> bool {
    !segment.is_empty() && segment.bytes().all(|byte| byte.is_ascii_digit())
}

fn schema_relative_path(path: &[String]) -> Option<SchemaPathClass> {
    if path.is_empty() {
        return Some(SchemaPathClass::Typed);
    }
    let member = path[0].as_str();
    if !SCHEMA_FIELDS.contains(&member) {
        return None;
    }
    let rest = &path[1..];
    if matches!(member, "enum" | "example") {
        return Some(if rest.is_empty() {
            SchemaPathClass::Typed
        } else {
            SchemaPathClass::ProtectedPayload
        });
    }
    if rest.is_empty() {
        return Some(SchemaPathClass::Typed);
    }
    match member {
        "properties" | "definitions" | "patternProperties" => schema_relative_path(&rest[1..]),
        "items" | "additionalItems" | "additionalProperties" | "not" => {
            if is_index(&rest[0]) {
                schema_relative_path(&rest[1..])
            } else {
                schema_relative_path(rest)
            }
        }
        "allOf" | "anyOf" | "oneOf" => is_index(&rest[0]).then(|| schema_relative_path(&rest[1..])).flatten(),
        "dependencies" => {
            if rest.len() == 1 || (rest.len() == 2 && is_index(&rest[1])) {
                Some(SchemaPathClass::Typed)
            } else {
                schema_relative_path(&rest[1..])
            }
        }
        "required" | "x-kubernetes-list-map-keys" => {
            (rest.len() == 1 && is_index(&rest[0])).then_some(SchemaPathClass::Typed)
        }
        "externalDocs" => {
            (rest.len() == 1 && matches!(rest[0].as_str(), "description" | "url")).then_some(SchemaPathClass::Typed)
        }
        _ => None,
    }
}

/// Classify exact recursive `JSONSchemaProps` paths for the default generation policy.
pub(crate) fn schema_path_class(
    gvk: &GroupVersionKind,
    path: &crate::diagnostic::FieldPath,
) -> Option<SchemaPathClass> {
    if gvk.group.as_deref() != Some("apiextensions.k8s.io") || gvk.kind != "CustomResourceDefinition" {
        return None;
    }
    let parts = &path.0;
    let stable_or_beta = gvk.version == "v1" || gvk.version == "v1beta1";
    if !stable_or_beta {
        return None;
    }
    let versions_schema = parts.len() >= 5
        && parts[0] == "spec"
        && parts[1] == "versions"
        && is_index(&parts[2])
        && parts[3] == "schema"
        && parts[4] == "openAPIV3Schema";
    let beta_legacy_schema = gvk.version == "v1beta1"
        && parts.len() >= 3
        && parts[0] == "spec"
        && parts[1] == "validation"
        && parts[2] == "openAPIV3Schema";
    if versions_schema {
        schema_relative_path(&parts[5..])
    } else if beta_legacy_schema {
        schema_relative_path(&parts[3..])
    } else {
        None
    }
}

fn version(minor: u8) -> Result<KubernetesVersion, Finding> {
    KubernetesVersion::new(1, minor)
}
fn field(path: &'static str, since: u8, gate: Option<FeatureGateId>, merge: MergeStrategy) -> FieldCapability {
    FieldCapability {
        path,
        since: version(since).unwrap_or(KubernetesVersion::MAX),
        feature_gate: gate,
        removed: None,
        deprecated: None,
        admission: FieldAdmission::Typed,
        merge,
        semantic_note: None,
    }
}
macro_rules! f {
    ($path:literal, $merge:ident) => { field($path, 20, None, MergeStrategy::$merge) };
    ($path:literal, MapList [$($key:literal),* $(,)?]) => {
        field($path, 20, None, MergeStrategy::MapList { keys: &[$($key),*] })
    };
    ($path:literal, $since:literal, $gate:expr, $merge:ident) => {
        field($path, $since, $gate, MergeStrategy::$merge)
    };
}

static COMMON: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    vec![
        f!("/metadata", Object),
        f!("/metadata/name", Scalar),
        f!("/metadata/generateName", Scalar),
        f!("/metadata/namespace", Scalar),
        f!("/metadata/labels", Map),
        f!("/metadata/labels/*", Scalar),
        f!("/metadata/annotations", Map),
        f!("/metadata/annotations/*", Scalar),
        f!("/metadata/finalizers", AtomicList),
        f!("/metadata/finalizers/*", Scalar),
        f!("/metadata/ownerReferences", MapList["uid"]),
        f!("/metadata/ownerReferences/*", Object),
        f!("/metadata/ownerReferences/*/apiVersion", Scalar),
        f!("/metadata/ownerReferences/*/kind", Scalar),
        f!("/metadata/ownerReferences/*/name", Scalar),
        f!("/metadata/ownerReferences/*/uid", Scalar),
        f!("/metadata/ownerReferences/*/controller", Scalar),
        f!("/metadata/ownerReferences/*/blockOwnerDeletion", Scalar),
    ]
});
static CRD_V1: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    let mut fields = COMMON.clone();
    fields.extend([
        f!("/spec", Object),
        f!("/spec/group", Scalar),
        f!("/spec/names", Object),
        f!("/spec/names/categories", AtomicList),
        f!("/spec/names/categories/*", Scalar),
        f!("/spec/names/kind", Scalar),
        f!("/spec/names/listKind", Scalar),
        f!("/spec/names/plural", Scalar),
        f!("/spec/names/shortNames", AtomicList),
        f!("/spec/names/shortNames/*", Scalar),
        f!("/spec/names/singular", Scalar),
        f!("/spec/scope", Scalar),
        f!("/spec/versions", MapList["name"]),
        f!("/spec/versions/*", Object),
        f!("/spec/versions/*/name", Scalar),
        f!("/spec/versions/*/served", Scalar),
        f!("/spec/versions/*/storage", Scalar),
        f!("/spec/versions/*/deprecated", Scalar),
        f!("/spec/versions/*/deprecationWarning", Scalar),
        f!("/spec/versions/*/schema", Object),
        f!("/spec/versions/*/schema/openAPIV3Schema", Object),
        f!("/spec/versions/*/subresources", Object),
        f!("/spec/versions/*/subresources/status", Object),
        f!("/spec/versions/*/subresources/scale", Object),
        f!("/spec/versions/*/subresources/scale/specReplicasPath", Scalar),
        f!("/spec/versions/*/subresources/scale/statusReplicasPath", Scalar),
        f!("/spec/versions/*/subresources/scale/labelSelectorPath", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns", AtomicList),
        f!("/spec/versions/*/additionalPrinterColumns/*", Object),
        f!("/spec/versions/*/additionalPrinterColumns/*/description", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns/*/format", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns/*/jsonPath", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns/*/name", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns/*/priority", Scalar),
        f!("/spec/versions/*/additionalPrinterColumns/*/type", Scalar),
        f!("/spec/conversion", Object),
        f!("/spec/conversion/strategy", Scalar),
        f!("/spec/conversion/webhook", Object),
        f!("/spec/conversion/webhook/conversionReviewVersions", AtomicList),
        f!("/spec/conversion/webhook/conversionReviewVersions/*", Scalar),
        f!("/spec/conversion/webhook/clientConfig", Object),
        f!("/spec/conversion/webhook/clientConfig/service", Object),
        f!("/spec/conversion/webhook/clientConfig/service/name", Scalar),
        f!("/spec/conversion/webhook/clientConfig/service/namespace", Scalar),
        f!("/spec/conversion/webhook/clientConfig/service/path", Scalar),
        f!("/spec/conversion/webhook/clientConfig/service/port", Scalar),
        f!("/spec/conversion/webhook/clientConfig/url", Scalar),
        f!("/spec/conversion/webhook/clientConfig/caBundle", Scalar),
        f!("/spec/preserveUnknownFields", Scalar),
    ]);
    add_schema_admission(&mut fields, "/spec/versions/*/schema/openAPIV3Schema");
    fields
});
static CRD_BETA: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    let mut fields = COMMON.clone();
    fields.extend([
        f!("/spec", Object),
        f!("/spec/group", Scalar),
        f!("/spec/names", Object),
        f!("/spec/scope", Scalar),
        f!("/spec/version", Scalar),
        f!("/spec/versions", MapList["name"]),
        f!("/spec/versions/*", Object),
        f!("/spec/versions/*/name", Scalar),
        f!("/spec/versions/*/served", Scalar),
        f!("/spec/versions/*/storage", Scalar),
        f!("/spec/versions/*/schema", Object),
        f!("/spec/versions/*/schema/openAPIV3Schema", Object),
        f!("/spec/validation", Object),
        f!("/spec/validation/openAPIV3Schema", Object),
        f!("/spec/subresources", Object),
        f!("/spec/subresources/status", Object),
        f!("/spec/subresources/scale", Object),
        f!("/spec/subresources/scale/specReplicasPath", Scalar),
        f!("/spec/subresources/scale/statusReplicasPath", Scalar),
        f!("/spec/subresources/scale/labelSelectorPath", Scalar),
        f!("/spec/additionalPrinterColumns", AtomicList),
        f!("/spec/additionalPrinterColumns/*", Object),
        f!("/spec/additionalPrinterColumns/*/description", Scalar),
        f!("/spec/additionalPrinterColumns/*/format", Scalar),
        f!("/spec/additionalPrinterColumns/*/JSONPath", Scalar),
        f!("/spec/additionalPrinterColumns/*/name", Scalar),
        f!("/spec/additionalPrinterColumns/*/priority", Scalar),
        f!("/spec/additionalPrinterColumns/*/type", Scalar),
        f!("/spec/conversion", Object),
        f!("/spec/conversion/strategy", Scalar),
        f!("/spec/conversion/conversionReviewVersions", AtomicList),
        f!("/spec/conversion/webhookClientConfig", Object),
        f!("/spec/conversion/webhookClientConfig/service", Object),
        f!("/spec/conversion/webhookClientConfig/service/name", Scalar),
        f!("/spec/conversion/webhookClientConfig/service/namespace", Scalar),
        f!("/spec/conversion/webhookClientConfig/service/path", Scalar),
        f!("/spec/conversion/webhookClientConfig/service/port", Scalar),
        f!("/spec/conversion/webhookClientConfig/url", Scalar),
        f!("/spec/conversion/webhookClientConfig/caBundle", Scalar),
        f!("/spec/preserveUnknownFields", Scalar),
    ]);
    add_schema_admission(&mut fields, "/spec/versions/*/schema/openAPIV3Schema");
    add_schema_admission(&mut fields, "/spec/validation/openAPIV3Schema");
    fields.extend([
        f!("/spec/names/categories", AtomicList),
        f!("/spec/names/categories/*", Scalar),
        f!("/spec/names/kind", Scalar),
        f!("/spec/names/listKind", Scalar),
        f!("/spec/names/plural", Scalar),
        f!("/spec/names/shortNames", AtomicList),
        f!("/spec/names/shortNames/*", Scalar),
        f!("/spec/names/singular", Scalar),
    ]);
    fields
});

/// Admit only the selected typed `JSONSchemaProps` members. Property recursion is explicitly
/// bounded to the parser's public maximum schema depth used by this cohort, and arbitrary
/// extension keys remain opaque. This does not admit every path below the schema root.
fn add_schema_admission(fields: &mut Vec<FieldCapability>, root: &str) {
    const MAX_ADMITTED_PROPERTY_DEPTH: usize = 16;
    const MEMBERS: &[(&str, MergeStrategy)] = &[
        ("type", MergeStrategy::Scalar),
        ("description", MergeStrategy::Scalar),
        ("title", MergeStrategy::Scalar),
        ("format", MergeStrategy::Scalar),
        ("pattern", MergeStrategy::Scalar),
        ("required", MergeStrategy::AtomicList),
        ("properties", MergeStrategy::Object),
        ("items", MergeStrategy::Object),
        ("additionalProperties", MergeStrategy::Object),
        ("allOf", MergeStrategy::AtomicList),
        ("anyOf", MergeStrategy::AtomicList),
        ("oneOf", MergeStrategy::AtomicList),
        ("not", MergeStrategy::Object),
        ("definitions", MergeStrategy::Object),
        ("enum", MergeStrategy::AtomicList),
        ("minimum", MergeStrategy::Scalar),
        ("maximum", MergeStrategy::Scalar),
        ("minLength", MergeStrategy::Scalar),
        ("maxLength", MergeStrategy::Scalar),
        ("x-kubernetes-embedded-resource", MergeStrategy::Scalar),
        ("x-kubernetes-list-map-keys", MergeStrategy::AtomicList),
        ("x-kubernetes-list-type", MergeStrategy::Scalar),
        ("x-kubernetes-map-type", MergeStrategy::Scalar),
    ];
    let mut node = root.to_owned();
    for depth in 0..=MAX_ADMITTED_PROPERTY_DEPTH {
        for (member, merge) in MEMBERS {
            let path = format!("{node}/{member}");
            let path = Box::leak(path.into_boxed_str());
            fields.push(field(path, 20, None, *merge));
            if *member == "required" || *member == "x-kubernetes-list-map-keys" {
                let item = Box::leak(format!("{node}/{member}/*").into_boxed_str());
                fields.push(field(item, 20, None, MergeStrategy::Scalar));
            }
        }
        if depth < MAX_ADMITTED_PROPERTY_DEPTH {
            node.push_str("/properties/*");
        }
    }
    for edge in [
        "items",
        "additionalProperties",
        "not",
        "definitions/*",
        "allOf/*",
        "anyOf/*",
        "oneOf/*",
    ] {
        let child_root = Box::leak(format!("{root}/{edge}").into_boxed_str());
        for (member, merge) in MEMBERS {
            let path = Box::leak(format!("{child_root}/{member}").into_boxed_str());
            fields.push(field(path, 20, None, *merge));
        }
    }
}
static WEBHOOK_V1: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    let mut fields = COMMON.clone();
    fields.extend([
        f!("/webhooks", MapList["name"]),
        f!("/webhooks/*", Object),
        f!("/webhooks/*/name", Scalar),
        f!("/webhooks/*/clientConfig", Object),
        f!("/webhooks/*/clientConfig/service", Object),
        f!("/webhooks/*/clientConfig/service/name", Scalar),
        f!("/webhooks/*/clientConfig/service/namespace", Scalar),
        f!("/webhooks/*/clientConfig/service/path", Scalar),
        f!("/webhooks/*/clientConfig/service/port", Scalar),
        f!("/webhooks/*/clientConfig/url", Scalar),
        f!("/webhooks/*/clientConfig/caBundle", Scalar),
        f!("/webhooks/*/rules", AtomicList),
        f!("/webhooks/*/rules/*", Object),
        f!("/webhooks/*/rules/*/apiGroups", AtomicList),
        f!("/webhooks/*/rules/*/apiVersions", AtomicList),
        f!("/webhooks/*/rules/*/operations", AtomicList),
        f!("/webhooks/*/rules/*/resources", AtomicList),
        f!("/webhooks/*/rules/*/scope", Scalar),
        f!("/webhooks/*/failurePolicy", Scalar),
        f!("/webhooks/*/matchPolicy", Scalar),
        f!("/webhooks/*/namespaceSelector", Object),
        f!("/webhooks/*/namespaceSelector/matchLabels", Map),
        f!("/webhooks/*/namespaceSelector/matchLabels/*", Scalar),
        f!("/webhooks/*/namespaceSelector/matchExpressions", AtomicList),
        f!("/webhooks/*/namespaceSelector/matchExpressions/*", Object),
        f!("/webhooks/*/namespaceSelector/matchExpressions/*/key", Scalar),
        f!("/webhooks/*/namespaceSelector/matchExpressions/*/operator", Scalar),
        f!("/webhooks/*/namespaceSelector/matchExpressions/*/values", AtomicList),
        f!("/webhooks/*/namespaceSelector/matchExpressions/*/values/*", Scalar),
        f!("/webhooks/*/objectSelector", Object),
        f!("/webhooks/*/objectSelector/matchLabels", Map),
        f!("/webhooks/*/objectSelector/matchLabels/*", Scalar),
        f!("/webhooks/*/objectSelector/matchExpressions", AtomicList),
        f!("/webhooks/*/objectSelector/matchExpressions/*", Object),
        f!("/webhooks/*/objectSelector/matchExpressions/*/key", Scalar),
        f!("/webhooks/*/objectSelector/matchExpressions/*/operator", Scalar),
        f!("/webhooks/*/objectSelector/matchExpressions/*/values", AtomicList),
        f!("/webhooks/*/objectSelector/matchExpressions/*/values/*", Scalar),
        f!("/webhooks/*/sideEffects", Scalar),
        f!("/webhooks/*/timeoutSeconds", Scalar),
        f!("/webhooks/*/admissionReviewVersions", AtomicList),
        f!("/webhooks/*/admissionReviewVersions/*", Scalar),
        f!("/webhooks/*/reinvocationPolicy", Scalar),
        f!(
            "/webhooks/*/matchConditions",
            27,
            Some(FeatureGateId::AdmissionWebhookMatchConditions),
            AtomicList
        ),
        f!(
            "/webhooks/*/matchConditions/*",
            27,
            Some(FeatureGateId::AdmissionWebhookMatchConditions),
            Object
        ),
        f!(
            "/webhooks/*/matchConditions/*/name",
            27,
            Some(FeatureGateId::AdmissionWebhookMatchConditions),
            Scalar
        ),
        f!(
            "/webhooks/*/matchConditions/*/expression",
            27,
            Some(FeatureGateId::AdmissionWebhookMatchConditions),
            Scalar
        ),
    ]);
    fields
});
static WEBHOOK_BETA: LazyLock<Vec<FieldCapability>> = LazyLock::new(|| {
    WEBHOOK_V1
        .iter()
        .filter(|field| !field.path.contains("matchConditions"))
        .cloned()
        .collect()
});

pub(super) fn for_api(gvk: GroupVersionKind) -> Result<KindCapability, Finding> {
    let api = gvk.api_version();
    let (fields, first, removed) = match (gvk.kind.as_str(), api.as_str()) {
        ("CustomResourceDefinition", "apiextensions.k8s.io/v1") => (CRD_V1.as_slice(), 20, None),
        ("CustomResourceDefinition", "apiextensions.k8s.io/v1beta1") => (CRD_BETA.as_slice(), 20, Some(version(22)?)),
        ("MutatingWebhookConfiguration" | "ValidatingWebhookConfiguration", "admissionregistration.k8s.io/v1") => {
            (WEBHOOK_V1.as_slice(), 20, None)
        }
        ("MutatingWebhookConfiguration" | "ValidatingWebhookConfiguration", "admissionregistration.k8s.io/v1beta1") => {
            (WEBHOOK_BETA.as_slice(), 20, Some(version(22)?))
        }
        _ => return Err(Finding::error(FindingCode::InvalidRegistration, Phase::Decoding)),
    };
    Ok(KindCapability {
        gvk,
        scope: ResourceScope::Cluster,
        api_since: version(first)?,
        api_removed: removed,
        fields,
    })
}
