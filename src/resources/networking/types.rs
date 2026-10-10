//! Networking-owned finite helper codecs; common/foundation declarations are reused.
use crate::resources::common::{ObjectReference, TypedLocalObjectReference, native_object};
use crate::value::{IntOrString, LabelSelector};
use std::collections::BTreeMap;
native_object! {
    /// Selected native `ClientIPConfig` members of `v1`; unknown values stay private.
    pub struct ClientIPConfig {
        "timeoutSeconds" => timeout_seconds: i32,
    }
}
native_object! {
    /// Selected native `EndpointAddress` members of `v1`; unknown values stay private.
    pub struct EndpointAddress {
        "hostname" => hostname: String,
        "ip" => ip: String,
        "nodeName" => node_name: String,
        "targetRef" => target_ref: ObjectReference,
    }
}
native_object! {
    /// Selected native `EndpointPort` members of `v1`; unknown values stay private.
    pub struct EndpointPort {
        "appProtocol" => app_protocol: String,
        "name" => name: String,
        "port" => port: i32,
        "protocol" => protocol: String,
    }
}
native_object! {
    /// Selected native `EndpointSubset` members of `v1`; unknown values stay private.
    pub struct EndpointSubset {
        "addresses" => addresses: Vec<EndpointAddress>,
        "notReadyAddresses" => not_ready_addresses: Vec<EndpointAddress>,
        "ports" => ports: Vec<EndpointPort>,
    }
}
native_object! {
    /// Selected native `ServicePort` members of `v1`; unknown values stay private.
    pub struct ServicePort {
        "appProtocol" => app_protocol: String,
        "name" => name: String,
        "nodePort" => node_port: i32,
        "port" => port: i32,
        "protocol" => protocol: String,
        "targetPort" => target_port: IntOrString,
    }
}
native_object! {
    /// Selected native `SessionAffinityConfig` members of `v1`; unknown values stay private.
    pub struct SessionAffinityConfig {
        "clientIP" => client_ip: ClientIPConfig,
    }
}
native_object! {
    /// Selected native `Endpoint` members of `v1`; unknown values stay private.
    pub struct EndpointDiscoveryV1 {
        "addresses" => addresses: Vec<String>,
        "conditions" => conditions: EndpointConditionsDiscoveryV1,
        "deprecatedTopology" => deprecated_topology: BTreeMap<String, String>,
        "hostname" => hostname: String,
        "nodeName" => node_name: String,
        "targetRef" => target_ref: ObjectReference,
        "zone" => zone: String,
    }
}
native_object! {
    /// Selected native `EndpointConditions` members of `v1`; unknown values stay private.
    pub struct EndpointConditionsDiscoveryV1 {
        "ready" => ready: bool,
        "serving" => serving: bool,
        "terminating" => terminating: bool,
    }
}
native_object! {
    /// Selected native `EndpointPort` members of `v1`; unknown values stay private.
    pub struct EndpointPortDiscoveryV1 {
        "appProtocol" => app_protocol: String,
        "name" => name: String,
        "port" => port: i32,
        "protocol" => protocol: String,
    }
}
native_object! {
    /// Selected native `Endpoint` members of `v1beta1`; unknown values stay private.
    pub struct EndpointDiscoveryV1beta1 {
        "addresses" => addresses: Vec<String>,
        "conditions" => conditions: EndpointConditionsDiscoveryV1beta1,
        "hostname" => hostname: String,
        "nodeName" => node_name: String,
        "targetRef" => target_ref: ObjectReference,
        "topology" => topology: BTreeMap<String, String>,
    }
}
native_object! {
    /// Selected native `EndpointConditions` members of `v1beta1`; unknown values stay private.
    pub struct EndpointConditionsDiscoveryV1beta1 {
        "ready" => ready: bool,
        "serving" => serving: bool,
        "terminating" => terminating: bool,
    }
}
native_object! {
    /// Selected native `EndpointPort` members of `v1beta1`; unknown values stay private.
    pub struct EndpointPortDiscoveryV1beta1 {
        "appProtocol" => app_protocol: String,
        "name" => name: String,
        "port" => port: i32,
        "protocol" => protocol: String,
    }
}
native_object! {
    /// Selected native `HTTPIngressPath` members of `v1beta1`; unknown values stay private.
    pub struct HTTPIngressPathExtensionsV1beta1 {
        "backend" => backend: IngressBackendExtensionsV1beta1,
        "path" => path: String,
        "pathType" => path_type: String,
    }
}
native_object! {
    /// Selected native `HTTPIngressRuleValue` members of `v1beta1`; unknown values stay private.
    pub struct HTTPIngressRuleValueExtensionsV1beta1 {
        "paths" => paths: Vec<HTTPIngressPathExtensionsV1beta1>,
    }
}
native_object! {
    /// Selected native `IngressBackend` members of `v1beta1`; unknown values stay private.
    pub struct IngressBackendExtensionsV1beta1 {
        "resource" => resource: TypedLocalObjectReference,
        "serviceName" => service_name: String,
        "servicePort" => service_port: IntOrString,
    }
}
native_object! {
    /// Selected native `IngressRule` members of `v1beta1`; unknown values stay private.
    pub struct IngressRuleExtensionsV1beta1 {
        "host" => host: String,
        "http" => http: HTTPIngressRuleValueExtensionsV1beta1,
    }
}
native_object! {
    /// Selected native `IngressTLS` members of `v1beta1`; unknown values stay private.
    pub struct IngressTLSExtensionsV1beta1 {
        "hosts" => hosts: Vec<String>,
        "secretName" => secret_name: String,
    }
}
native_object! {
    /// Selected native `HTTPIngressPath` members of `v1`; unknown values stay private.
    pub struct HTTPIngressPathNetworkingV1 {
        "backend" => backend: IngressBackendNetworkingV1,
        "path" => path: String,
        "pathType" => path_type: String,
    }
}
native_object! {
    /// Selected native `HTTPIngressRuleValue` members of `v1`; unknown values stay private.
    pub struct HTTPIngressRuleValueNetworkingV1 {
        "paths" => paths: Vec<HTTPIngressPathNetworkingV1>,
    }
}
native_object! {
    /// Selected native `IPBlock` members of `v1`; unknown values stay private.
    pub struct IPBlockNetworkingV1 {
        "cidr" => cidr: String,
        "except" => r#except: Vec<String>,
    }
}
native_object! {
    /// Selected native `IngressBackend` members of `v1`; unknown values stay private.
    pub struct IngressBackendNetworkingV1 {
        "resource" => resource: TypedLocalObjectReference,
        "service" => service: IngressServiceBackendNetworkingV1,
    }
}
native_object! {
    /// Selected native `IngressClassParametersReference` members of `v1`; unknown values stay private.
    pub struct IngressClassParametersReferenceNetworkingV1 {
        "apiGroup" => api_group: String,
        "kind" => kind: String,
        "name" => name: String,
        "namespace" => namespace: String,
        "scope" => scope: String,
    }
}
native_object! {
    /// Selected native `IngressRule` members of `v1`; unknown values stay private.
    pub struct IngressRuleNetworkingV1 {
        "host" => host: String,
        "http" => http: HTTPIngressRuleValueNetworkingV1,
    }
}
native_object! {
    /// Selected native `IngressServiceBackend` members of `v1`; unknown values stay private.
    pub struct IngressServiceBackendNetworkingV1 {
        "name" => name: String,
        "port" => port: ServiceBackendPortNetworkingV1,
    }
}
native_object! {
    /// Selected native `IngressTLS` members of `v1`; unknown values stay private.
    pub struct IngressTLSNetworkingV1 {
        "hosts" => hosts: Vec<String>,
        "secretName" => secret_name: String,
    }
}
native_object! {
    /// Selected native `NetworkPolicyEgressRule` members of `v1`; unknown values stay private.
    pub struct NetworkPolicyEgressRuleNetworkingV1 {
        "ports" => ports: Vec<NetworkPolicyPortNetworkingV1>,
        "to" => to: Vec<NetworkPolicyPeerNetworkingV1>,
    }
}
native_object! {
    /// Selected native `NetworkPolicyIngressRule` members of `v1`; unknown values stay private.
    pub struct NetworkPolicyIngressRuleNetworkingV1 {
        "from" => r#from: Vec<NetworkPolicyPeerNetworkingV1>,
        "ports" => ports: Vec<NetworkPolicyPortNetworkingV1>,
    }
}
native_object! {
    /// Selected native `NetworkPolicyPeer` members of `v1`; unknown values stay private.
    pub struct NetworkPolicyPeerNetworkingV1 {
        "ipBlock" => ip_block: IPBlockNetworkingV1,
        "namespaceSelector" => namespace_selector: LabelSelector,
        "podSelector" => pod_selector: LabelSelector,
    }
}
native_object! {
    /// Selected native `NetworkPolicyPort` members of `v1`; unknown values stay private.
    pub struct NetworkPolicyPortNetworkingV1 {
        "port" => port: IntOrString,
        "protocol" => protocol: String,
    }
}
native_object! {
    /// Selected native `ServiceBackendPort` members of `v1`; unknown values stay private.
    pub struct ServiceBackendPortNetworkingV1 {
        "name" => name: String,
        "number" => number: i32,
    }
}
native_object! {
    /// Selected native `HTTPIngressPath` members of `v1beta1`; unknown values stay private.
    pub struct HTTPIngressPathNetworkingV1beta1 {
        "backend" => backend: IngressBackendNetworkingV1beta1,
        "path" => path: String,
        "pathType" => path_type: String,
    }
}
native_object! {
    /// Selected native `HTTPIngressRuleValue` members of `v1beta1`; unknown values stay private.
    pub struct HTTPIngressRuleValueNetworkingV1beta1 {
        "paths" => paths: Vec<HTTPIngressPathNetworkingV1beta1>,
    }
}
native_object! {
    /// Selected native `IngressBackend` members of `v1beta1`; unknown values stay private.
    pub struct IngressBackendNetworkingV1beta1 {
        "resource" => resource: TypedLocalObjectReference,
        "serviceName" => service_name: String,
        "servicePort" => service_port: IntOrString,
    }
}
native_object! {
    /// Selected native `IngressClassParametersReference` members of `v1beta1`; unknown values stay private.
    pub struct IngressClassParametersReferenceNetworkingV1beta1 {
        "apiGroup" => api_group: String,
        "kind" => kind: String,
        "name" => name: String,
        "namespace" => namespace: String,
        "scope" => scope: String,
    }
}
native_object! {
    /// Selected native `IngressRule` members of `v1beta1`; unknown values stay private.
    pub struct IngressRuleNetworkingV1beta1 {
        "host" => host: String,
        "http" => http: HTTPIngressRuleValueNetworkingV1beta1,
    }
}
native_object! {
    /// Selected native `IngressTLS` members of `v1beta1`; unknown values stay private.
    pub struct IngressTLSNetworkingV1beta1 {
        "hosts" => hosts: Vec<String>,
        "secretName" => secret_name: String,
    }
}
native_object! {
    /// Explicit native `v1` `Service` specification.
    pub struct ServiceSpec {
        "ports" => ports: Vec<ServicePort>,
        "selector" => selector: BTreeMap<String, String>,
        "clusterIP" => cluster_ip: String,
        "clusterIPs" => cluster_i_ps: Vec<String>,
        "type" => r#type: String,
        "externalIPs" => external_i_ps: Vec<String>,
        "sessionAffinity" => session_affinity: String,
        "loadBalancerIP" => load_balancer_ip: String,
        "loadBalancerSourceRanges" => load_balancer_source_ranges: Vec<String>,
        "externalName" => external_name: String,
        "externalTrafficPolicy" => external_traffic_policy: String,
        "healthCheckNodePort" => health_check_node_port: i32,
        "publishNotReadyAddresses" => publish_not_ready_addresses: bool,
        "sessionAffinityConfig" => session_affinity_config: SessionAffinityConfig,
        "ipFamilies" => ip_families: Vec<String>,
        "ipFamilyPolicy" => ip_family_policy: String,
        "allocateLoadBalancerNodePorts" => allocate_load_balancer_node_ports: bool,
        "loadBalancerClass" => load_balancer_class: String,
        "internalTrafficPolicy" => internal_traffic_policy: String,
        "trafficDistribution" => traffic_distribution: String,
    }
}
native_object! {
    /// Explicit native `extensions/v1beta1` `Ingress` specification.
    pub struct IngressExtensionsV1Beta1Spec {
        "backend" => backend: IngressBackendExtensionsV1beta1,
        "tls" => tls: Vec<IngressTLSExtensionsV1beta1>,
        "rules" => rules: Vec<IngressRuleExtensionsV1beta1>,
        "ingressClassName" => ingress_class_name: String,
    }
}
native_object! {
    /// Explicit native `networking.k8s.io/v1` `Ingress` specification.
    pub struct IngressV1Spec {
        "defaultBackend" => default_backend: IngressBackendNetworkingV1,
        "tls" => tls: Vec<IngressTLSNetworkingV1>,
        "rules" => rules: Vec<IngressRuleNetworkingV1>,
        "ingressClassName" => ingress_class_name: String,
    }
}
native_object! {
    /// Explicit native `networking.k8s.io/v1beta1` `Ingress` specification.
    pub struct IngressV1Beta1Spec {
        "backend" => backend: IngressBackendNetworkingV1beta1,
        "tls" => tls: Vec<IngressTLSNetworkingV1beta1>,
        "rules" => rules: Vec<IngressRuleNetworkingV1beta1>,
        "ingressClassName" => ingress_class_name: String,
    }
}
native_object! {
    /// Explicit native `networking.k8s.io/v1` `IngressClass` specification.
    pub struct IngressClassV1Spec {
        "controller" => controller: String,
        "parameters" => parameters: IngressClassV1Parameters,
    }
}
native_object! {
    /// Explicit native `networking.k8s.io/v1beta1` `IngressClass` specification.
    pub struct IngressClassV1Beta1Spec {
        "controller" => controller: String,
        "parameters" => parameters: IngressClassV1Beta1Parameters,
    }
}
native_object! {
    /// Explicit native `networking.k8s.io/v1` `NetworkPolicy` specification.
    pub struct NetworkPolicySpec {
        "podSelector" => pod_selector: LabelSelector,
        "ingress" => ingress: Vec<NetworkPolicyIngressRuleNetworkingV1>,
        "egress" => egress: Vec<NetworkPolicyEgressRuleNetworkingV1>,
        "policyTypes" => policy_types: Vec<String>,
    }
}

macro_rules! class_parameters {
    ($name:ident,$scoped:ty) => {
        /// A finite native parameter shape; baseline fields alone do not establish a source minor.
        #[derive(Clone, Debug)]
        pub enum $name {
            /// Shared baseline fields available from 1.20.
            Legacy(TypedLocalObjectReference),
            /// API-specific shape selected by explicit scope/namespace presence.
            Scoped($scoped),
        }
        impl crate::resources::common::UnknownScopes for $name {
            #[cfg(test)]
            fn unknown_scopes(&self, path: &crate::FieldPath, out: &mut std::collections::BTreeSet<crate::FieldPath>) {
                match self {
                    Self::Legacy(value) => value.unknown_scopes(path, out),
                    Self::Scoped(value) => value.unknown_scopes(path, out),
                }
            }
            fn visit_unknown_scopes(
                &self,
                path: &crate::FieldPath,
                visitor: &mut crate::resources::common::UnknownScopeVisitor<'_>,
            ) -> bool {
                if !visitor.step() {
                    return false;
                }
                match self {
                    Self::Legacy(value) => value.visit_unknown_scopes(path, visitor),
                    Self::Scoped(value) => value.visit_unknown_scopes(path, visitor),
                }
            }
        }
        impl crate::registry::codec::FieldCodec for $name {
            fn decode(
                node: &crate::syntax::TreeNode,
                ctx: &crate::registry::FieldDecodeContext,
                path: &crate::FieldPath,
            ) -> Result<Self, crate::Finding> {
                if node.get("scope").is_some() || node.get("namespace").is_some() {
                    <$scoped>::decode(node, ctx, path).map(Self::Scoped)
                } else {
                    TypedLocalObjectReference::decode(node, ctx, path).map(Self::Legacy)
                }
            }
            fn encode(
                &self,
                ctx: &crate::registry::EncodeContext<'_>,
                path: &crate::FieldPath,
            ) -> Result<crate::syntax::TreeNode, crate::Finding> {
                match self {
                    Self::Legacy(value) => value.encode(ctx, path),
                    Self::Scoped(value) => value.encode(ctx, path),
                }
            }
        }
    };
}
class_parameters!(IngressClassV1Parameters, IngressClassParametersReferenceNetworkingV1);
class_parameters!(
    IngressClassV1Beta1Parameters,
    IngressClassParametersReferenceNetworkingV1beta1
);
