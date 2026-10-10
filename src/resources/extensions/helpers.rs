//! Finite extension helper wire shapes. Names remain API-version-specific where wire contracts differ.
use super::extension_object;
use crate::value::{LabelSelector, NativeBytes};

// Admission webhooks.
extension_object! {
    /// One stored admission match condition; expressions are preserved, never evaluated.
    pub struct MatchConditionAdmissionV1 {
        "expression" => expression: String,
        "name" => name: String,
    }
}
extension_object! {
    /// Stable mutating webhook helper fields selected by the frozen inventory.
    pub struct MutatingWebhookAdmissionV1 {
        "admissionReviewVersions" => admission_review_versions: Vec<String>,
        "clientConfig" => client_config: WebhookClientConfigAdmissionV1,
        "failurePolicy" => failure_policy: String,
        "matchConditions" => match_conditions: Vec<MatchConditionAdmissionV1>,
        "matchPolicy" => match_policy: String,
        "name" => name: String,
        "namespaceSelector" => namespace_selector: LabelSelector,
        "objectSelector" => object_selector: LabelSelector,
        "reinvocationPolicy" => reinvocation_policy: String,
        "rules" => rules: Vec<RuleWithOperationsAdmissionV1>,
        "sideEffects" => side_effects: String,
        "timeoutSeconds" => timeout_seconds: i32,
    }
}
extension_object! {
    /// Stable validating webhook helper fields selected by the frozen inventory.
    pub struct ValidatingWebhookAdmissionV1 {
        "admissionReviewVersions" => admission_review_versions: Vec<String>,
        "clientConfig" => client_config: WebhookClientConfigAdmissionV1,
        "failurePolicy" => failure_policy: String,
        "matchConditions" => match_conditions: Vec<MatchConditionAdmissionV1>,
        "matchPolicy" => match_policy: String,
        "name" => name: String,
        "namespaceSelector" => namespace_selector: LabelSelector,
        "objectSelector" => object_selector: LabelSelector,
        "rules" => rules: Vec<RuleWithOperationsAdmissionV1>,
        "sideEffects" => side_effects: String,
        "timeoutSeconds" => timeout_seconds: i32,
    }
}
extension_object! {
    /// Stable admission webhook rule selector.
    pub struct RuleWithOperationsAdmissionV1 {
        "apiGroups" => api_groups: Vec<String>,
        "apiVersions" => api_versions: Vec<String>,
        "operations" => operations: Vec<String>,
        "resources" => resources: Vec<String>,
        "scope" => scope: String,
    }
}
extension_object! {
    /// Stable admission webhook Service reference.
    pub struct ServiceReferenceAdmissionV1 {
        "name" => name: String,
        "namespace" => namespace: String,
        "path" => path: String,
        "port" => port: i32,
    }
}
extension_object! {
    /// Stable admission webhook endpoint configuration; CA bytes remain protected.
    pub struct WebhookClientConfigAdmissionV1 {
        "caBundle" => ca_bundle: NativeBytes,
        "service" => service: ServiceReferenceAdmissionV1,
        "url" => url: String,
    }
}
extension_object! {
    /// Historical beta mutating webhook shape; no stable-only matchConditions member.
    pub struct MutatingWebhookAdmissionV1beta1 {
        "admissionReviewVersions" => admission_review_versions: Vec<String>,
        "clientConfig" => client_config: WebhookClientConfigAdmissionV1beta1,
        "failurePolicy" => failure_policy: String,
        "matchPolicy" => match_policy: String,
        "name" => name: String,
        "namespaceSelector" => namespace_selector: LabelSelector,
        "objectSelector" => object_selector: LabelSelector,
        "reinvocationPolicy" => reinvocation_policy: String,
        "rules" => rules: Vec<RuleWithOperationsAdmissionV1beta1>,
        "sideEffects" => side_effects: String,
        "timeoutSeconds" => timeout_seconds: i32,
    }
}
extension_object! {
    /// Historical beta validating webhook shape.
    pub struct ValidatingWebhookAdmissionV1beta1 {
        "admissionReviewVersions" => admission_review_versions: Vec<String>,
        "clientConfig" => client_config: WebhookClientConfigAdmissionV1beta1,
        "failurePolicy" => failure_policy: String,
        "matchPolicy" => match_policy: String,
        "name" => name: String,
        "namespaceSelector" => namespace_selector: LabelSelector,
        "objectSelector" => object_selector: LabelSelector,
        "rules" => rules: Vec<RuleWithOperationsAdmissionV1beta1>,
        "sideEffects" => side_effects: String,
        "timeoutSeconds" => timeout_seconds: i32,
    }
}
extension_object! {
    /// Historical beta admission webhook rule selector.
    pub struct RuleWithOperationsAdmissionV1beta1 {
        "apiGroups" => api_groups: Vec<String>,
        "apiVersions" => api_versions: Vec<String>,
        "operations" => operations: Vec<String>,
        "resources" => resources: Vec<String>,
        "scope" => scope: String,
    }
}
extension_object! {
    /// Historical beta admission webhook Service reference.
    pub struct ServiceReferenceAdmissionV1beta1 {
        "name" => name: String,
        "namespace" => namespace: String,
        "path" => path: String,
        "port" => port: i32,
    }
}
extension_object! {
    /// Historical beta admission webhook endpoint configuration.
    pub struct WebhookClientConfigAdmissionV1beta1 {
        "caBundle" => ca_bundle: NativeBytes,
        "service" => service: ServiceReferenceAdmissionV1beta1,
        "url" => url: String,
    }
}

// CRD v1.
extension_object! {
    pub struct CustomResourceColumnDefinitionCrdV1 {
        "description" => description: String,
        "format" => format: String,
        "jsonPath" => json_path: String,
        "name" => name: String,
        "priority" => priority: i32,
        "type" => r#type: String,
    }
}
extension_object! {
    pub struct CustomResourceConversionCrdV1 {
        "strategy" => strategy: String,
        "webhook" => webhook: WebhookConversionCrdV1,
    }
}
extension_object! {
    pub struct CustomResourceDefinitionNamesCrdV1 {
        "categories" => categories: Vec<String>,
        "kind" => kind: String,
        "listKind" => list_kind: String,
        "plural" => plural: String,
        "shortNames" => short_names: Vec<String>,
        "singular" => singular: String,
    }
}
extension_object! {
    pub struct CustomResourceDefinitionVersionCrdV1 {
        "additionalPrinterColumns" => additional_printer_columns: Vec<CustomResourceColumnDefinitionCrdV1>,
        "deprecated" => deprecated: bool,
        "deprecationWarning" => deprecation_warning: String,
        "name" => name: String,
        "schema" => schema: CustomResourceValidationCrdV1,
        "served" => served: bool,
        "storage" => storage: bool,
        "subresources" => subresources: CustomResourceSubresourcesCrdV1,
    }
}
extension_object! {
    pub struct CustomResourceSubresourceScaleCrdV1 {
        "labelSelectorPath" => label_selector_path: String,
        "specReplicasPath" => spec_replicas_path: String,
        "statusReplicasPath" => status_replicas_path: String,
    }
}
/// The status subresource marker is a real empty object, distinct from absence and null.
/// Empty beta status objects have the same marker semantics but remain a separate wire type.
#[derive(Clone, Default)]
pub struct CustomResourceSubresourceStatusCrdV1 {
    pub(crate) unknown: crate::syntax::UnknownFields,
}
impl CustomResourceSubresourceStatusCrdV1 {
    pub(crate) const NATIVE_FIELDS: &'static [&'static str] = &[];
}
impl crate::resources::common::UnknownScopes for CustomResourceSubresourceStatusCrdV1 {
    #[cfg(test)]
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
        if !self.unknown.is_empty() {
            out.insert(path.clone());
        }
    }
    fn visit_unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>,
    ) -> bool {
        visitor.step() && (self.unknown.is_empty() || visitor.found(path))
    }
}
impl crate::registry::codec::FieldCodec for CustomResourceSubresourceStatusCrdV1 {
    fn decode(
        node: &crate::syntax::TreeNode,
        ctx: &crate::registry::FieldDecodeContext,
        path: &crate::diagnostic::FieldPath,
    ) -> Result<Self, crate::diagnostic::Finding> {
        crate::registry::codec::object(node, path)?;
        ctx.processing.work(1, ctx.phase)?;
        Ok(Self {
            unknown: crate::syntax::UnknownFields::capture_in(node, Self::NATIVE_FIELDS, ctx)?,
        })
    }
    fn encode(
        &self,
        ctx: &crate::registry::EncodeContext<'_>,
        path: &crate::diagnostic::FieldPath,
    ) -> Result<crate::syntax::TreeNode, crate::diagnostic::Finding> {
        let mut entries = Vec::new();
        crate::registry::codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
        ctx.object(entries, path)
    }
}
extension_object! {
    pub struct CustomResourceSubresourcesCrdV1 {
        "scale" => scale: CustomResourceSubresourceScaleCrdV1,
        "status" => status: CustomResourceSubresourceStatusCrdV1,
    }
}
extension_object! {
    pub struct CustomResourceValidationCrdV1 {
        "openAPIV3Schema" => open_api_v3_schema: super::schema::JSONSchemaPropsCrdV1,
    }
}
extension_object! {
    pub struct ExternalDocumentationCrdV1 {
        "description" => description: String,
        "url" => url: String,
    }
}
extension_object! {
    pub struct WebhookClientConfigCrdV1 {
        "caBundle" => ca_bundle: NativeBytes,
        "service" => service: ServiceReferenceCrdV1,
        "url" => url: String,
    }
}
extension_object! {
    pub struct ServiceReferenceCrdV1 {
        "name" => name: String,
        "namespace" => namespace: String,
        "path" => path: String,
        "port" => port: i32,
    }
}
extension_object! {
    pub struct WebhookConversionCrdV1 {
        "clientConfig" => client_config: WebhookClientConfigCrdV1,
        "conversionReviewVersions" => conversion_review_versions: Vec<String>,
    }
}

// CRD v1beta1 retains the historical top-level compatibility fields and wire spellings.
extension_object! {
    pub struct CustomResourceColumnDefinitionCrdV1beta1 {
        "JSONPath" => json_path: String,
        "description" => description: String,
        "format" => format: String,
        "name" => name: String,
        "priority" => priority: i32,
        "type" => r#type: String,
    }
}
extension_object! {
    pub struct CustomResourceConversionCrdV1beta1 {
        "conversionReviewVersions" => conversion_review_versions: Vec<String>,
        "strategy" => strategy: String,
        "webhookClientConfig" => webhook_client_config: WebhookClientConfigCrdV1beta1,
    }
}
extension_object! {
    pub struct CustomResourceDefinitionNamesCrdV1beta1 {
        "categories" => categories: Vec<String>,
        "kind" => kind: String,
        "listKind" => list_kind: String,
        "plural" => plural: String,
        "shortNames" => short_names: Vec<String>,
        "singular" => singular: String,
    }
}
extension_object! {
    pub struct CustomResourceDefinitionVersionCrdV1beta1 {
        "additionalPrinterColumns" => additional_printer_columns: Vec<CustomResourceColumnDefinitionCrdV1beta1>,
        "deprecated" => deprecated: bool,
        "deprecationWarning" => deprecation_warning: String,
        "name" => name: String,
        "schema" => schema: CustomResourceValidationCrdV1beta1,
        "served" => served: bool,
        "storage" => storage: bool,
        "subresources" => subresources: CustomResourceSubresourcesCrdV1beta1,
    }
}
extension_object! {
    pub struct CustomResourceSubresourceScaleCrdV1beta1 {
        "labelSelectorPath" => label_selector_path: String,
        "specReplicasPath" => spec_replicas_path: String,
        "statusReplicasPath" => status_replicas_path: String,
    }
}
#[derive(Clone, Default)]
/// Historical beta status-subresource marker object.
pub struct CustomResourceSubresourceStatusCrdV1beta1 {
    pub(crate) unknown: crate::syntax::UnknownFields,
}
impl CustomResourceSubresourceStatusCrdV1beta1 {
    pub(crate) const NATIVE_FIELDS: &'static [&'static str] = &[];
}
impl crate::resources::common::UnknownScopes for CustomResourceSubresourceStatusCrdV1beta1 {
    #[cfg(test)]
    fn unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        out: &mut std::collections::BTreeSet<crate::diagnostic::FieldPath>,
    ) {
        if !self.unknown.is_empty() {
            out.insert(path.clone());
        }
    }
    fn visit_unknown_scopes(
        &self,
        path: &crate::diagnostic::FieldPath,
        visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>,
    ) -> bool {
        visitor.step() && (self.unknown.is_empty() || visitor.found(path))
    }
}
impl crate::registry::codec::FieldCodec for CustomResourceSubresourceStatusCrdV1beta1 {
    fn decode(
        node: &crate::syntax::TreeNode,
        ctx: &crate::registry::FieldDecodeContext,
        path: &crate::diagnostic::FieldPath,
    ) -> Result<Self, crate::diagnostic::Finding> {
        crate::registry::codec::object(node, path)?;
        ctx.processing.work(1, ctx.phase)?;
        Ok(Self {
            unknown: crate::syntax::UnknownFields::capture_in(node, Self::NATIVE_FIELDS, ctx)?,
        })
    }
    fn encode(
        &self,
        ctx: &crate::registry::EncodeContext<'_>,
        path: &crate::diagnostic::FieldPath,
    ) -> Result<crate::syntax::TreeNode, crate::diagnostic::Finding> {
        let mut entries = Vec::new();
        crate::registry::codec::append_unknown(&self.unknown, &mut entries, ctx, path)?;
        ctx.object(entries, path)
    }
}
extension_object! {
    pub struct CustomResourceSubresourcesCrdV1beta1 {
        "scale" => scale: CustomResourceSubresourceScaleCrdV1beta1,
        "status" => status: CustomResourceSubresourceStatusCrdV1beta1,
    }
}
extension_object! {
    pub struct CustomResourceValidationCrdV1beta1 {
        "openAPIV3Schema" => open_api_v3_schema: super::schema::JSONSchemaPropsCrdV1beta1,
    }
}
extension_object! {
    pub struct ExternalDocumentationCrdV1beta1 {
        "description" => description: String,
        "url" => url: String,
    }
}
extension_object! {
    pub struct WebhookClientConfigCrdV1beta1 {
        "caBundle" => ca_bundle: NativeBytes,
        "service" => service: ServiceReferenceCrdV1beta1,
        "url" => url: String,
    }
}
extension_object! {
    pub struct ServiceReferenceCrdV1beta1 {
        "name" => name: String,
        "namespace" => namespace: String,
        "path" => path: String,
        "port" => port: i32,
    }
}
