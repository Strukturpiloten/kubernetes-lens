//! Original offline native checks over the finite networking bindings.
mod ip_context;
use crate::{
    capability::{KindCapability, MergeStrategy},
    diagnostic::{FieldPath, Finding, FindingCode, Phase},
    model::GroupVersionKind,
    registry::{FindingSink, ValidationContext, codec::FieldCodec},
    resources::common::UnknownScopes,
    syntax::{TreeNode, TreeValue},
    value::{LabelSelector, dns_label, dns_subdomain, label_key, label_value},
};
use ip_context::{checked_cidr, context, ip, usable_ip};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::IpAddr,
};

pub(super) trait Profile: FieldCodec + UnknownScopes {
    const API: &'static str;
    const KIND: &'static str;
}
pub(super) fn profile<T: Profile>() -> Result<KindCapability, Finding> {
    super::capabilities::for_api(GroupVersionKind::new(T::API, T::KIND)?)
}
pub(super) fn invalid(path: &FieldPath, out: &mut dyn FindingSink) {
    out.push(Finding::error(FindingCode::NativeFieldInvalid, Phase::Validation).at_path(path.clone()));
}
pub(super) fn text<'a>(node: &'a TreeNode, key: &str) -> Option<&'a str> {
    node.get(key).and_then(TreeNode::as_str)
}
fn integer(node: &TreeNode) -> Option<i64> {
    match &node.value {
        TreeValue::Number(value) => value.parse().ok(),
        _ => None,
    }
}
pub(super) fn present(node: &TreeNode, key: &str) -> bool {
    node.get(key).is_some_and(|n| !matches!(n.value, TreeValue::Null))
}
fn require(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    if !present(node, key) {
        invalid(&path.child(key), out);
    }
}
fn number(node: &TreeNode, key: &str, lower: i64, upper: i64, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(value) = node.get(key) {
        if !integer(value).is_some_and(|value| (lower..=upper).contains(&value)) {
            invalid(&path.child(key), out);
        }
    }
}
pub(super) fn port_name(value: &str) -> bool {
    value.len() <= 15
        && dns_label(value)
        && value.bytes().any(|byte| byte.is_ascii_lowercase())
        && !value.contains("--")
}
fn int_or_port(node: &TreeNode, key: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(value) = node.get(key) {
        let valid =
            integer(value).is_some_and(|value| (1..=65535).contains(&value)) || value.as_str().is_some_and(port_name);
        if !valid {
            invalid(&path.child(key), out);
        }
    }
}
fn named(node: &TreeNode, key: &str, check: fn(&str) -> bool, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(value) = node.get(key) {
        if !value.as_str().is_some_and(check) {
            invalid(&path.child(key), out);
        }
    }
}
fn nullable_named(node: &TreeNode, key: &str, check: fn(&str) -> bool, path: &FieldPath, out: &mut dyn FindingSink) {
    if !node
        .get(key)
        .is_some_and(|value| matches!(value.value, TreeValue::Null))
    {
        named(node, key, check, path, out);
    }
}
fn defaulted_nullable_enum(node: &TreeNode, key: &str, values: &[&str], path: &FieldPath, out: &mut dyn FindingSink) {
    if node
        .get(key)
        .is_some_and(|value| matches!(value.value, TreeValue::Null))
    {
        context(&path.child(key), out);
    } else {
        enum_value(node, key, values, path, out);
    }
}
fn enum_value(node: &TreeNode, key: &str, values: &[&str], path: &FieldPath, out: &mut dyn FindingSink) {
    if node.get(key).is_some() && !text(node, key).is_some_and(|value| values.contains(&value)) {
        invalid(&path.child(key), out);
    }
}
fn labels(node: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(entries) = node.as_mapping() {
        for (key, value) in entries {
            if out.exhausted() {
                break;
            }
            if !label_key(key) || !value.as_str().is_some_and(label_value) {
                invalid(&path.child(key.clone()), out);
            }
        }
    } else {
        invalid(path, out);
    }
}
pub(super) fn charge_path(fields: &crate::registry::FieldDecodeContext, path: &FieldPath) -> Result<(), Finding> {
    fields.processing.payload_array::<String>(path.0.len(), fields.phase)?;
    fields
        .processing
        .payload_sizes(path.0.iter().map(String::len), fields.phase)
}
fn semantic_preflight(
    node: &TreeNode,
    factor: usize,
    fields: &crate::registry::FieldDecodeContext,
) -> Result<(), Finding> {
    fields.processing.work(factor, fields.phase)?;
    match &node.value {
        TreeValue::String(value) | TreeValue::Number(value) => {
            fields.processing.work(value.len().saturating_mul(32), fields.phase)?;
        }
        TreeValue::Mapping(entries) => {
            for (key, value) in entries {
                fields.processing.work(key.len().saturating_mul(32), fields.phase)?;
                semantic_preflight(value, factor, fields)?;
            }
        }
        TreeValue::Sequence(items) => {
            for item in items {
                semantic_preflight(item, factor, fields)?;
            }
        }
        TreeValue::Tagged(tag, value) => {
            fields.processing.work(tag.len().saturating_mul(32), fields.phase)?;
            semantic_preflight(value, factor, fields)?;
        }
        TreeValue::Bool(_) | TreeValue::Null => {}
    }
    Ok(())
}
/// Traverse only exact native bindings, charging lookup work and copied paths before allocation.
pub(super) fn walk(
    tree: &TreeNode,
    capability: &KindCapability,
    fields: &crate::registry::FieldDecodeContext,
    visitor: &mut impl FnMut(&TreeNode, &FieldPath, &FieldPath),
) -> Result<(), Finding> {
    fn visit(
        node: &TreeNode,
        path: &FieldPath,
        pattern: &FieldPath,
        bindings: &BTreeMap<FieldPath, MergeStrategy>,
        fields: &crate::registry::FieldDecodeContext,
        visitor: &mut impl FnMut(&TreeNode, &FieldPath, &FieldPath),
    ) -> Result<(), Finding> {
        fields.processing.work(bindings.len().saturating_add(1), fields.phase)?;
        let strategy = if pattern.0.is_empty() {
            MergeStrategy::Object
        } else {
            let Some(strategy) = bindings.get(pattern) else {
                return Ok(());
            };
            *strategy
        };
        visitor(node, path, pattern);
        fields.processing.work(0, fields.phase)?;
        match strategy {
            MergeStrategy::Object => {
                if let Some(entries) = node.as_mapping() {
                    for (key, child) in entries {
                        for base in [path, pattern] {
                            charge_path(fields, base)?;
                        }
                        fields.processing.payload_sizes([key.len(), key.len()], fields.phase)?;
                        visit(
                            child,
                            &path.child(key.clone()),
                            &pattern.child(key.clone()),
                            bindings,
                            fields,
                            visitor,
                        )?;
                    }
                }
            }
            MergeStrategy::AtomicList | MergeStrategy::SetList | MergeStrategy::MapList { .. } => {
                if let Some(items) = node.as_sequence() {
                    for (index, child) in items.iter().enumerate() {
                        for base in [path, pattern] {
                            charge_path(fields, base)?;
                        }
                        fields.processing.payload(21, fields.phase)?;
                        visit(
                            child,
                            &path.child(index.to_string()),
                            &pattern.child("*"),
                            bindings,
                            fields,
                            visitor,
                        )?;
                    }
                }
            }
            _ => {}
        }
        Ok(())
    }
    let mut bindings = BTreeMap::new();
    for field in capability.fields {
        fields
            .processing
            .work(field.path.len().saturating_add(1), fields.phase)?;
        fields
            .processing
            .payload_array::<String>(field.path.split('/').count(), fields.phase)?;
        fields.processing.payload(field.path.len(), fields.phase)?;
        bindings.insert(FieldPath::parse(field.path)?, field.merge);
    }
    visit(
        tree,
        &FieldPath::default(),
        &FieldPath::default(),
        &bindings,
        fields,
        visitor,
    )
}
fn required_path(tree: &TreeNode, parts: &[String], path: &FieldPath, out: &mut dyn FindingSink) {
    let Some((first, rest)) = parts.split_first() else {
        return;
    };
    if first == "*" {
        if let Some(items) = tree.as_sequence() {
            for (index, item) in items.iter().enumerate() {
                if out.exhausted() {
                    break;
                }
                required_path(item, rest, &path.child(index.to_string()), out);
            }
        }
    } else if rest.is_empty() {
        require(tree, first, path, out);
    } else if let Some(child) = tree.get(first) {
        let child_path = path.child(first.clone());
        // Optional native pointers carry no required descendants when nil.
        let nullable_pointer = child_path.0 == ["spec", "parameters"]
            || child_path.0 == ["spec", "defaultBackend", "service"]
            || child_path.0 == ["spec", "defaultBackend", "resource"]
            || child_path.0 == ["spec", "backend", "resource"]
            || matches!(child_path.0.as_slice(), [spec, rules, _, http, paths, _, backend, pointer]
                if spec == "spec" && rules == "rules" && http == "http" && paths == "paths"
                    && backend == "backend" && matches!(pointer.as_str(), "service" | "resource"));
        if !(nullable_pointer && matches!(child.value, TreeValue::Null)) {
            required_path(child, rest, &child_path, out);
        }
    }
}
fn semantic_work_factor(capability: &KindCapability) -> usize {
    capability
        .fields
        .iter()
        .try_fold(super::required::REQUIRED.len(), |sum, field| {
            sum.checked_add(field.path.len().saturating_add(1))
        })
        .unwrap_or(usize::MAX)
}
pub(super) fn validate<T: Profile>(value: &T, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
    if out.exhausted() || ctx.fields.processing.exhausted() {
        return;
    }
    let mut encoding = ctx.encoding();
    encoding.include_unknown = true;
    let tree = match value.encode(&encoding, &FieldPath::default()) {
        Ok(tree) => tree,
        Err(error) => {
            out.push(error);
            return;
        }
    };
    let capability = match profile::<T>() {
        Ok(profile) => profile,
        Err(error) => {
            out.push(error);
            return;
        }
    };
    let factor = semantic_work_factor(&capability);
    if let Err(error) = semantic_preflight(&tree, factor, &ctx.fields) {
        out.push(error);
        return;
    }
    let root = FieldPath::default();
    if matches!(T::KIND, "Service" | "Ingress" | "IngressClass" | "NetworkPolicy") {
        require(&tree, "spec", &root, out);
    }
    for (kind, api, pointer, first, last) in super::required::REQUIRED {
        if out.exhausted() {
            break;
        }
        if *kind == T::KIND && *api == T::API && (*first..=*last).contains(&ctx.target.kubernetes.minor()) {
            if let Ok(path) = FieldPath::parse(pointer) {
                required_path(&tree, &path.0, &root, out);
            }
        }
    }
    match T::KIND {
        "Service" => {
            if let Some(metadata) = tree.get("metadata") {
                service_metadata(metadata, ctx, &root.child("metadata"), out);
            }
            if let Some(spec) = tree.get("spec") {
                service(spec, ctx, &root.child("spec"), out);
            }
        }
        "Endpoints" => endpoints(&tree, ctx, &root, out),
        "EndpointSlice" => slice(&tree, ctx, &root, out),
        "Ingress" => {
            if let Some(spec) = tree.get("spec") {
                ingress(spec, T::API, &root.child("spec"), out);
            }
        }
        "IngressClass" => {
            if let Some(spec) = tree.get("spec") {
                class(spec, &root.child("spec"), out);
            }
        }
        "NetworkPolicy" => {
            if let Some(spec) = tree.get("spec") {
                policy(spec, &root.child("spec"), out);
            }
        }
        _ => (),
    }
    if let Err(error) = walk(&tree, &capability, &ctx.fields, &mut |node, path, pattern| {
        bound_node(node, path, pattern, T::KIND, T::API, (&tree, ctx), out);
        let is_object = pattern.0.is_empty()
            || capability.fields.iter().any(|field| {
                field.path.split('/').skip(1).eq(pattern.0.iter().map(String::as_str))
                    && field.merge == MergeStrategy::Object
            });
        if is_object {
            if let Some(entries) = node.as_mapping() {
                for (key, _) in entries {
                    if out.exhausted() {
                        break;
                    }
                    if pattern.0.is_empty() && matches!(key.as_str(), "apiVersion" | "kind") {
                        continue;
                    }
                    let child = pattern.child(key.clone());
                    if !capability
                        .fields
                        .iter()
                        .any(|field| field.path.split('/').skip(1).eq(child.0.iter().map(String::as_str)))
                    {
                        out.push(
                            Finding::warning(FindingCode::UnadmittedField, Phase::Validation)
                                .at_path(path.child(key.clone())),
                        );
                    }
                }
            }
        }
    }) {
        out.push(error);
    }
}
/// Service-only prefix lexical precheck; no concrete generated name is constructed.
pub(crate) fn service_generate_name_identity_envelope(prefix: &str) -> bool {
    if prefix.len() > 1 && prefix.ends_with('-') {
        prefix.get(..prefix.len() - 2).is_some_and(|value| {
            value
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
                && value.as_bytes().first().is_none_or(u8::is_ascii_alphanumeric)
        })
    } else {
        dns_subdomain(prefix)
    }
}
fn service_metadata(node: &TreeNode, ctx: &ValidationContext<'_>, path: &FieldPath, out: &mut dyn FindingSink) {
    backend_service_name(node, "name", ctx, path, out);
    let Some(prefix) = text(node, "generateName") else {
        return;
    };
    if prefix.len() > 1 && prefix.ends_with('-') {
        // Check the witnessed native prefix callback's effective label without
        // allocating or fabricating a generated concrete name.
        let retained = prefix.get(..prefix.len() - 2);
        if prefix.len() > 64 || !service_generate_name_identity_envelope(prefix) {
            invalid(&path.child("generateName"), out);
        } else if retained
            .and_then(|value| value.as_bytes().first())
            .is_some_and(u8::is_ascii_digit)
        {
            match ctx.target.kubernetes.minor() {
                20..=33 => invalid(&path.child("generateName"), out),
                34..=36 => context(&path.child("generateName"), out),
                _ => (),
            }
        }
    } else {
        backend_service_name(node, "generateName", ctx, path, out);
    }
}
fn service(spec: &TreeNode, ctx: &ValidationContext<'_>, path: &FieldPath, out: &mut dyn FindingSink) {
    let kind = text(spec, "type")
        .filter(|value| !value.is_empty())
        .unwrap_or("ClusterIP");
    for field in ["type", "sessionAffinity"] {
        if text(spec, field) == Some("") {
            context(&path.child(field), out);
        }
    }
    enum_value(
        spec,
        "type",
        &["", "ClusterIP", "NodePort", "LoadBalancer", "ExternalName"],
        path,
        out,
    );
    enum_value(spec, "sessionAffinity", &["", "None", "ClientIP"], path, out);
    enum_value(spec, "externalTrafficPolicy", &["Cluster", "Local"], path, out);
    defaulted_nullable_enum(spec, "internalTrafficPolicy", &["Cluster", "Local"], path, out);
    if !spec
        .get("ipFamilyPolicy")
        .is_some_and(|node| matches!(node.value, TreeValue::Null))
    {
        enum_value(
            spec,
            "ipFamilyPolicy",
            &["SingleStack", "PreferDualStack", "RequireDualStack"],
            path,
            out,
        );
    }
    if kind == "ExternalName" {
        require(spec, "externalName", path, out);
        named(
            spec,
            "externalName",
            |value| dns_subdomain(value.strip_suffix('.').unwrap_or(value)),
            path,
            out,
        );
    } else if text(spec, "clusterIP") != Some("None")
        && spec
            .get("ports")
            .and_then(TreeNode::as_sequence)
            .is_none_or(<[TreeNode]>::is_empty)
    {
        invalid(&path.child("ports"), out);
    }
    if let Some(ip) = text(spec, "clusterIP") {
        if !ip.is_empty() && ip != "None" {
            ip_context::ip(ip, ctx, &path.child("clusterIP"), out);
        }
        if ip == "None" && matches!(kind, "NodePort" | "LoadBalancer") {
            invalid(&path.child("clusterIP"), out);
        }
    }
    service_ports(spec, kind, ctx, path, out);
    if out.exhausted() || ctx.fields.processing.exhausted() {
        return;
    }
    load_balancer_class(spec, kind, ctx, path, out);
    if present(spec, "allocateLoadBalancerNodePorts") && kind != "LoadBalancer" {
        invalid(&path.child("allocateLoadBalancerNodePorts"), out);
    }
    number(spec, "healthCheckNodePort", 0, 65535, path, out);
    if spec
        .get("healthCheckNodePort")
        .and_then(integer)
        .is_some_and(|port| port != 0)
        && (kind != "LoadBalancer" || text(spec, "externalTrafficPolicy") != Some("Local"))
    {
        invalid(&path.child("healthCheckNodePort"), out);
    }
    if present(spec, "sessionAffinityConfig") && text(spec, "sessionAffinity") != Some("ClientIP") {
        // Native None/default-None clears any nonnil configuration, including an empty object.
        context(&path.child("sessionAffinityConfig"), out);
    } else if let Some(config) = spec
        .get("sessionAffinityConfig")
        .and_then(|value| value.get("clientIP"))
    {
        number(
            config,
            "timeoutSeconds",
            1,
            86400,
            &path.child("sessionAffinityConfig").child("clientIP"),
            out,
        );
    }
    if let Some(distribution) = text(spec, "trafficDistribution") {
        if distribution != "PreferClose" {
            out.push(
                Finding::warning(FindingCode::UnadmittedField, Phase::Validation)
                    .at_path(path.child("trafficDistribution")),
            );
        }
    }
    service_addresses(spec, kind, ctx, path, out);
}
fn service_ports(
    spec: &TreeNode,
    kind: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    if let Some(items) = spec.get("ports").and_then(TreeNode::as_sequence) {
        if !scratch(ctx, out, items.len().saturating_mul(128)) {
            return;
        }
        let mut names = BTreeSet::new();
        let mut node_ports = BTreeSet::new();
        for (index, item) in items.iter().enumerate() {
            if out.exhausted() {
                break;
            }
            let port_path = path.child("ports").child(index.to_string());
            if items.len() > 1 {
                require(item, "name", &port_path, out);
                if text(item, "name") == Some("") {
                    invalid(&port_path.child("name"), out);
                }
            }
            if let Some(name) = text(item, "name") {
                if !names.insert(name) {
                    invalid(&port_path.child("name"), out);
                }
            }
            if let Some(node_port) = item.get("nodePort").and_then(integer) {
                let protocol = text(item, "protocol")
                    .filter(|value| !value.is_empty())
                    .unwrap_or("TCP");
                if node_port != 0
                    && (!matches!(kind, "NodePort" | "LoadBalancer") || !node_ports.insert((protocol, node_port)))
                {
                    invalid(&port_path.child("nodePort"), out);
                }
            }
            if kind == "LoadBalancer"
                && ctx.target.kubernetes.minor() <= 32
                && item.get("port").and_then(integer) == Some(10250)
            {
                invalid(&port_path.child("port"), out);
            }
        }
    }
}
fn load_balancer_class(
    spec: &TreeNode,
    kind: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    if present(spec, "loadBalancerClass") {
        if kind != "LoadBalancer" {
            invalid(&path.child("loadBalancerClass"), out);
        }
        named(spec, "loadBalancerClass", label_key, path, out);
        if ctx.intent == crate::generation::NativeValidationIntent::Unspecified {
            out.push(
                Finding::warning(FindingCode::NativeContextRequired, Phase::Validation)
                    .at_path(path.child("loadBalancerClass")),
            );
        }
    }
}
fn scratch(ctx: &ValidationContext<'_>, out: &mut dyn FindingSink, bytes: usize) -> bool {
    if out.exhausted() {
        return false;
    }
    match ctx.fields.processing.payload(bytes, Phase::Validation) {
        Ok(()) => true,
        Err(finding) => {
            out.push(finding);
            false
        }
    }
}
fn service_addresses(
    spec: &TreeNode,
    kind: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    for key in ["externalIPs", "clusterIPs"] {
        if out.exhausted() {
            return;
        }
        if let Some(items) = spec.get(key).and_then(TreeNode::as_sequence) {
            let mut first_family = None;
            for (index, item) in items.iter().enumerate() {
                if out.exhausted() {
                    return;
                }
                let p = path.child(key).child(index.to_string());
                let Some(value) = item.as_str() else {
                    invalid(&p, out);
                    continue;
                };
                if key == "clusterIPs" && value == "None" {
                    continue;
                }
                if let Some(parsed) = ip(value, ctx, &p, out) {
                    if key == "externalIPs" && !usable_ip(parsed) {
                        invalid(&p, out);
                    }
                    if key == "clusterIPs" {
                        if first_family == Some(parsed.is_ipv4()) {
                            invalid(&p, out);
                        }
                        first_family = Some(parsed.is_ipv4());
                        if let Some(families) = spec.get("ipFamilies").and_then(TreeNode::as_sequence) {
                            let family = if parsed.is_ipv4() { "IPv4" } else { "IPv6" };
                            if families.get(index).and_then(TreeNode::as_str) != Some(family) {
                                invalid(&path.child("ipFamilies").child(index.to_string()), out);
                            }
                        }
                    }
                }
            }
            if key == "clusterIPs" {
                if items.len() > 2 {
                    invalid(&path.child(key), out);
                }
                if !items.is_empty() && kind == "ExternalName" {
                    invalid(&path.child(key), out);
                }
                if !items.is_empty() && text(spec, "clusterIP").is_none_or(str::is_empty) {
                    context(&path.child(key), out);
                } else if !items.is_empty() && text(spec, "clusterIP") != items.first().and_then(TreeNode::as_str) {
                    invalid(&path.child(key), out);
                }
                if items.len() == 2 && items.iter().any(|item| item.as_str() == Some("None")) {
                    invalid(&path.child(key), out);
                }
            }
        }
    }
    if let Some(value) = text(spec, "loadBalancerIP").filter(|value| !value.is_empty()) {
        ip(value, ctx, &path.child("loadBalancerIP"), out);
    }
    if let Some(items) = spec.get("loadBalancerSourceRanges").and_then(TreeNode::as_sequence) {
        if !items.is_empty() && kind != "LoadBalancer" {
            invalid(&path.child("loadBalancerSourceRanges"), out);
        }
        for (index, item) in items.iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let p = path.child("loadBalancerSourceRanges").child(index.to_string());
            if let Some(value) = item.as_str() {
                checked_cidr(value, ctx, &p, out);
            } else {
                invalid(&p, out);
            }
        }
    }
    if let Some(items) = spec.get("ipFamilies").and_then(TreeNode::as_sequence) {
        if items.len() > 2 || (kind == "ExternalName" && !items.is_empty()) {
            invalid(&path.child("ipFamilies"), out);
        }
        let mut first = None;
        for (index, item) in items.iter().enumerate() {
            if out.exhausted() {
                return;
            }
            if !matches!(item.as_str(), Some("IPv4" | "IPv6")) || first == item.as_str() {
                invalid(&path.child("ipFamilies").child(index.to_string()), out);
            }
            first = item.as_str();
        }
        if let Some(ips) = spec.get("clusterIPs").and_then(TreeNode::as_sequence) {
            if ips.first().and_then(TreeNode::as_str) != Some("None")
                && !ips.is_empty()
                && !items.is_empty()
                && ips.len() != items.len()
            {
                invalid(&path.child("ipFamilies"), out);
            }
        }
    }
    if kind == "ExternalName" && present(spec, "ipFamilyPolicy") {
        invalid(&path.child("ipFamilyPolicy"), out);
    }
}
fn endpoints(tree: &TreeNode, ctx: &ValidationContext<'_>, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(subsets) = tree.get("subsets").and_then(TreeNode::as_sequence) {
        for (index, subset) in subsets.iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let p = path.child("subsets").child(index.to_string());
            if ["addresses", "notReadyAddresses"].iter().all(|key| {
                subset
                    .get(key)
                    .and_then(TreeNode::as_sequence)
                    .is_none_or(<[TreeNode]>::is_empty)
            }) {
                invalid(&p, out);
            }
            if let Some(ports) = subset.get("ports").and_then(TreeNode::as_sequence) {
                distinct_port_names(ports, ports.len() > 1, ctx, &p.child("ports"), out);
            }
        }
    }
}
fn distinct_port_names(
    ports: &[TreeNode],
    require_names: bool,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    if !scratch(ctx, out, ports.len().saturating_mul(64)) {
        return;
    }
    let mut names = BTreeSet::new();
    for (index, port) in ports.iter().enumerate() {
        if out.exhausted() {
            return;
        }
        let name = text(port, "name").unwrap_or("");
        if (require_names && name.is_empty()) || !names.insert(name) {
            invalid(&path.child(index.to_string()).child("name"), out);
        }
    }
}
fn slice(tree: &TreeNode, ctx: &ValidationContext<'_>, path: &FieldPath, out: &mut dyn FindingSink) {
    if !matches!(text(tree, "addressType"), Some("IPv4" | "IPv6")) {
        out.push(Finding::warning(FindingCode::UnadmittedField, Phase::Validation).at_path(path.child("addressType")));
    }
    if let Some(ports) = tree.get("ports").and_then(TreeNode::as_sequence) {
        if ports.len() > 100 {
            invalid(&path.child("ports"), out);
        }
        distinct_port_names(ports, false, ctx, &path.child("ports"), out);
    }
    if let Some(endpoints) = tree.get("endpoints").and_then(TreeNode::as_sequence) {
        if endpoints.len() > 1000 {
            invalid(&path.child("endpoints"), out);
        }
        for (index, endpoint) in endpoints.iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let p = path.child("endpoints").child(index.to_string());
            if text(tree, "apiVersion") == Some("discovery.k8s.io/v1beta1") {
                if let Some(topology_node) = endpoint.get("topology") {
                    if topology_node.as_mapping().is_some_and(|labels| labels.len() > 16) {
                        invalid(&p.child("topology"), out);
                    }
                    labels(topology_node, &p.child("topology"), out);
                }
            }
            if let Some(addresses) = endpoint.get("addresses").and_then(TreeNode::as_sequence) {
                let p = p.child("addresses");
                if addresses.is_empty() || addresses.len() > 100 {
                    invalid(&p, out);
                }
                for (offset, address) in addresses.iter().enumerate() {
                    if out.exhausted() {
                        return;
                    }
                    if !matches!(text(tree, "addressType"), Some("IPv4" | "IPv6")) {
                        continue;
                    }
                    let p = p.child(offset.to_string());
                    let Some(value) = address.as_str() else {
                        invalid(&p, out);
                        continue;
                    };
                    let Some(parsed) = ip(value, ctx, &p, out) else {
                        continue;
                    };
                    if matches!(text(tree, "addressType"), Some("IPv4" | "IPv6")) {
                        if (text(tree, "addressType") == Some("IPv4")) != parsed.is_ipv4() {
                            invalid(&p, out);
                        }
                        if !usable_ip(parsed) {
                            if matches!(ctx.target.kubernetes.minor(), 20 | 21) {
                                context(&p, out);
                            } else {
                                invalid(&p, out);
                            }
                        }
                    }
                }
            }
        }
    }
}
fn ingress(spec: &TreeNode, api: &str, path: &FieldPath, out: &mut dyn FindingSink) {
    let backend = if api == "networking.k8s.io/v1" {
        "defaultBackend"
    } else {
        "backend"
    };
    if !present(spec, backend)
        && spec
            .get("rules")
            .and_then(TreeNode::as_sequence)
            .is_none_or(<[TreeNode]>::is_empty)
    {
        invalid(path, out);
    }
    nullable_named(spec, "ingressClassName", dns_subdomain, path, out);
}
fn class(spec: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    require(spec, "controller", path, out);
    if let Some(controller) = text(spec, "controller") {
        if controller.len() > 250
            || !controller.split_once('/').is_some_and(|(domain, path)| {
                dns_subdomain(domain)
                    && !path.is_empty()
                    && path.bytes().all(|byte| {
                        byte.is_ascii_alphanumeric()
                            || matches!(
                                byte,
                                b'/' | b'-'
                                    | b'_'
                                    | b'.'
                                    | b'~'
                                    | b'%'
                                    | b'!'
                                    | b'$'
                                    | b'&'
                                    | b'\''
                                    | b'('
                                    | b')'
                                    | b'*'
                                    | b'+'
                                    | b','
                                    | b';'
                                    | b'='
                                    | b':'
                            )
                    })
            })
        {
            invalid(&path.child("controller"), out);
        }
    }
    if let Some(parameters) = spec
        .get("parameters")
        .filter(|value| !matches!(value.value, TreeValue::Null))
    {
        let p = path.child("parameters");
        require(parameters, "kind", &p, out);
        require(parameters, "name", &p, out);
        reference_segments(parameters, &p, out);
        defaulted_nullable_enum(parameters, "scope", &["Cluster", "Namespace"], &p, out);
        if text(parameters, "scope") == Some("Namespace") {
            require(parameters, "namespace", &p, out);
            named(parameters, "namespace", dns_label, &p, out);
        } else if present(parameters, "namespace") {
            invalid(&p.child("namespace"), out);
        }
    }
}
fn policy(spec: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    if let Some(items) = spec.get("policyTypes").and_then(TreeNode::as_sequence) {
        if items.len() > 2 {
            invalid(&path.child("policyTypes"), out);
        }
        for (index, item) in items.iter().enumerate() {
            if out.exhausted() {
                break;
            }
            if !matches!(item.as_str(), Some("Ingress" | "Egress")) {
                invalid(&path.child("policyTypes").child(index.to_string()), out);
            }
        }
    }
}
fn backend(node: &TreeNode, path: &FieldPath, stable: bool, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
    let resource = present(node, "resource");
    let service = if stable {
        present(node, "service")
    } else {
        present(node, "serviceName") || present(node, "servicePort")
    };
    if resource == service {
        invalid(path, out);
    }
    if stable {
        if let Some(service) = node
            .get("service")
            .filter(|value| !matches!(value.value, TreeValue::Null))
        {
            let p = path.child("service");
            require(service, "name", &p, out);
            require(service, "port", &p, out);
            backend_service_name(service, "name", ctx, &p, out);
        }
    } else if service {
        require(node, "serviceName", path, out);
        require(node, "servicePort", path, out);
        backend_service_name(node, "serviceName", ctx, path, out);
        int_or_port(node, "servicePort", path, out);
    }
    if let Some(resource) = node
        .get("resource")
        .filter(|value| !matches!(value.value, TreeValue::Null))
    {
        let p = path.child("resource");
        require(resource, "kind", &p, out);
        require(resource, "name", &p, out);
        reference_segments(resource, &p, out);
    }
}
fn selector(node: &TreeNode, path: &FieldPath, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
    match LabelSelector::decode(node, &ctx.fields, path).and_then(|selector| selector.validate()) {
        Ok(()) => (),
        Err(mut finding) => {
            if finding.code == FindingCode::UnadmittedField {
                finding.severity = crate::diagnostic::Severity::Warning;
            }
            finding.path = Some(path.clone());
            out.push(finding);
        }
    }
}
fn peer(node: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    let ip = present(node, "ipBlock");
    let namespace = present(node, "namespaceSelector");
    let pod = present(node, "podSelector");
    if (!ip && !namespace && !pod) || (ip && (namespace || pod)) {
        invalid(path, out);
    }
}
fn ingress_path(node: &TreeNode, path: &FieldPath, stable: bool, out: &mut dyn FindingSink) {
    require(node, "backend", path, out);
    if stable {
        require(node, "pathType", path, out);
    }
    enum_value(
        node,
        "pathType",
        &["Exact", "Prefix", "ImplementationSpecific"],
        path,
        out,
    );
    if matches!(text(node, "pathType"), Some("Exact" | "Prefix")) {
        if !text(node, "path").is_some_and(|value| {
            value.starts_with('/')
                && !["//", "/./", "/../", "%2f", "%2F"]
                    .iter()
                    .any(|bad| value.contains(bad))
                && !value.ends_with("/.")
                && !value.ends_with("/..")
        }) {
            invalid(&path.child("path"), out);
        }
    } else if let Some(value) = text(node, "path") {
        if !value.is_empty() && !value.starts_with('/') {
            invalid(&path.child("path"), out);
        }
    }
}
fn tls_host(value: &str) -> bool {
    value.len() <= 253 && dns_subdomain(value.strip_prefix("*.").unwrap_or(value))
}
fn host(value: &str) -> bool {
    value.parse::<IpAddr>().is_err() && ip_context::decimal_ipv4(value).is_none() && tls_host(value)
}
fn path_segment(value: &str) -> bool {
    !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '%'])
}
fn reference_segments(node: &TreeNode, path: &FieldPath, out: &mut dyn FindingSink) {
    for field in ["kind", "name"] {
        named(node, field, path_segment, path, out);
    }
    nullable_named(node, "apiGroup", dns_subdomain, path, out);
}
fn backend_service_name(
    node: &TreeNode,
    field: &str,
    ctx: &ValidationContext<'_>,
    path: &FieldPath,
    out: &mut dyn FindingSink,
) {
    if let Some(name) = text(node, field) {
        if !dns_label(name) {
            invalid(&path.child(field), out);
        } else if !name.as_bytes().first().is_some_and(u8::is_ascii_lowercase) {
            match ctx.target.kubernetes.minor() {
                20..=33 => invalid(&path.child(field), out),
                34..=36 => context(&path.child(field), out),
                _ => (),
            }
        }
    }
}
fn wildcard_http(
    tree: &TreeNode,
    path: &FieldPath,
    api: &str,
    ctx: &ValidationContext<'_>,
    out: &mut dyn FindingSink,
) -> bool {
    if path.0.len() < 4 || path.0[0] != "spec" || path.0[1] != "rules" || path.0[3] != "http" {
        return false;
    }
    let wildcard = tree
        .get("spec")
        .and_then(|spec| spec.get("rules"))
        .and_then(TreeNode::as_sequence)
        .and_then(|rules| path.0[2].parse::<usize>().ok().and_then(|index| rules.get(index)))
        .and_then(|rule| text(rule, "host"))
        .is_some_and(|host| host.contains('*'));
    if wildcard
        && (api != "networking.k8s.io/v1" || ctx.intent == crate::generation::NativeValidationIntent::Unspecified)
    {
        if api == "networking.k8s.io/v1" && path.0.len() == 4 {
            context(path, out);
        }
        true
    } else {
        false
    }
}
fn bound_node(
    node: &TreeNode,
    path: &FieldPath,
    pattern: &FieldPath,
    kind: &str,
    api: &str,
    (tree, ctx): (&TreeNode, &ValidationContext<'_>),
    out: &mut dyn FindingSink,
) {
    if out.exhausted() {
        return;
    }
    if kind == "Ingress" && wildcard_http(tree, path, api, ctx, out) {
        return;
    }
    let segments = &pattern.0;
    let last = segments.last().map_or("", String::as_str);
    let peer_selector = segments.len() == 6
        && segments[0] == "spec"
        && matches!(
            (segments[1].as_str(), segments[3].as_str()),
            ("ingress", "from") | ("egress", "to")
        );
    if matches!(last, "podSelector" | "namespaceSelector") && !(peer_selector && matches!(node.value, TreeValue::Null))
    {
        selector(node, path, ctx, out);
    }
    if matches!(last, "labels" | "selector") && (last == "labels" || kind == "Service") {
        labels(node, path, out);
    }
    if matches!(last, "defaultBackend" | "backend") {
        backend(node, path, api == "networking.k8s.io/v1", ctx, out);
    }
    if last == "*" && segments.iter().any(|part| part == "paths") {
        ingress_path(node, path, api == "networking.k8s.io/v1", out);
    }
    if last == "*" && segments.len() >= 2 && matches!(segments[segments.len() - 2].as_str(), "from" | "to") {
        peer(node, path, out);
    }
    if last == "ipBlock" {
        ip_block(node, path, ctx, out);
    }
    if last == "*" && segments.len() >= 2 && segments[segments.len() - 2] == "ports" {
        port_object(node, path, kind, out);
    }
    if last == "*"
        && segments
            .iter()
            .any(|part| part == "addresses" || part == "notReadyAddresses")
        && kind == "Endpoints"
    {
        require(node, "ip", path, out);
        if let Some(value) = text(node, "ip") {
            if ip(value, ctx, &path.child("ip"), out).is_some_and(|ip| !usable_ip(ip)) {
                invalid(&path.child("ip"), out);
            }
        }
        if text(node, "hostname") != Some("") {
            named(node, "hostname", dns_label, path, out);
        }
        named(node, "nodeName", dns_subdomain, path, out);
    }
    if last == "*" && segments.len() == 2 && segments[0] == "endpoints" {
        named(node, "hostname", dns_label, path, out);
        named(node, "nodeName", dns_subdomain, path, out);
        if api == "discovery.k8s.io/v1" && node.get("deprecatedTopology").is_some() {
            out.push(
                Finding::warning(FindingCode::UnadmittedField, Phase::Validation)
                    .at_path(path.child("deprecatedTopology")),
            );
        }
    }
    if kind == "Ingress" {
        ingress_hosts(node, path, segments, api, ctx, out);
    }
}
fn ingress_hosts(
    node: &TreeNode,
    path: &FieldPath,
    segments: &[String],
    api: &str,
    ctx: &ValidationContext<'_>,
    out: &mut dyn FindingSink,
) {
    let last = segments.last().map_or("", String::as_str);
    if last == "*" && segments.iter().any(|part| part == "rules") {
        if let Some(value) = text(node, "host") {
            if !value.is_empty() && !host(value) {
                if ctx.target.kubernetes.minor() <= 22
                    && value.parse::<IpAddr>().is_err()
                    && ip_context::decimal_ipv4(value).is_some()
                    && tls_host(value)
                {
                    // These witnesses use Go's compiler-dependent net.ParseIP;
                    // the target has no historical Go parser/version evidence.
                    context(&path.child("host"), out);
                } else {
                    invalid(&path.child("host"), out);
                }
            }
        }
    }
    if last == "http"
        && node
            .get("paths")
            .and_then(TreeNode::as_sequence)
            .is_none_or(<[TreeNode]>::is_empty)
    {
        invalid(&path.child("paths"), out);
    }
    if last == "hosts" {
        if let Some(items) = node.as_sequence() {
            for (index, item) in items.iter().enumerate() {
                if out.exhausted() {
                    break;
                }
                if !item.as_str().is_some_and(tls_host) {
                    invalid(&path.child(index.to_string()), out);
                }
            }
        }
    }
    if api == "networking.k8s.io/v1"
        && last == "secretName"
        && !node
            .as_str()
            .is_some_and(|value| value.is_empty() || dns_subdomain(value))
    {
        if ctx.intent == crate::generation::NativeValidationIntent::Unspecified {
            context(path, out);
        } else {
            invalid(path, out);
        }
    }
    if last == "port" && segments.iter().any(|part| part == "service") {
        let has_name = text(node, "name").is_some_and(|value| !value.is_empty());
        let has_number = node.get("number").and_then(integer).is_some_and(|value| value != 0);
        if has_name == has_number {
            invalid(path, out);
        } else if has_name {
            named(node, "name", port_name, path, out);
        } else {
            number(node, "number", 1, 65535, path, out);
        }
    }
}
fn port_object(node: &TreeNode, path: &FieldPath, kind: &str, out: &mut dyn FindingSink) {
    let defaults = matches!(kind, "Service" | "Endpoints");
    let nil_protocol = kind == "EndpointSlice"
        && node
            .get("protocol")
            .is_some_and(|node| matches!(node.value, TreeValue::Null));
    if nil_protocol {
        context(&path.child("protocol"), out);
    } else {
        enum_value(
            node,
            "protocol",
            if defaults {
                &["", "TCP", "UDP", "SCTP"]
            } else {
                &["TCP", "UDP", "SCTP"]
            },
            path,
            out,
        );
    }
    if defaults && text(node, "protocol") == Some("") {
        context(&path.child("protocol"), out);
    }
    if kind != "NetworkPolicy" && (kind != "EndpointSlice" || present(node, "port")) {
        number(node, "port", 1, 65535, path, out);
    }
    if kind == "Service" || kind == "Endpoints" {
        require(node, "port", path, out);
    }
    if kind == "NetworkPolicy" {
        int_or_port(node, "port", path, out);
    } // Numeric and named policy ports have a distinct native union.
    if kind == "Service" {
        if node
            .get("targetPort")
            .is_some_and(|value| integer(value) == Some(0) || value.as_str() == Some(""))
        {
            context(&path.child("targetPort"), out);
        } else {
            int_or_port(node, "targetPort", path, out);
        }
        number(node, "nodePort", 0, 65535, path, out);
    }
    if let Some(name) = text(node, "name") {
        if !name.is_empty()
            && !(if matches!(kind, "Service" | "Endpoints" | "EndpointSlice") {
                dns_label(name)
            } else {
                port_name(name)
            })
        {
            invalid(&path.child("name"), out);
        }
    }
    if matches!(kind, "Service" | "EndpointSlice") {
        nullable_named(node, "appProtocol", label_key, path, out);
    } else {
        named(node, "appProtocol", label_key, path, out);
    }
}
#[derive(Clone, Copy)]
struct Cidr {
    address: IpAddr,
    prefix: u8,
}
fn contains(parent: Cidr, child: Cidr) -> bool {
    if parent.prefix >= child.prefix {
        return false;
    }
    match (parent.address, child.address) {
        (IpAddr::V4(parent_ip), IpAddr::V4(child_ip)) => {
            let mask = if parent.prefix == 0 {
                0
            } else {
                u32::MAX << (32 - parent.prefix)
            };
            (u32::from(parent_ip) & mask) == (u32::from(child_ip) & mask)
        }
        (IpAddr::V6(parent_ip), IpAddr::V6(child_ip)) => {
            let mask = if parent.prefix == 0 {
                0
            } else {
                u128::MAX << (128 - parent.prefix)
            };
            (u128::from(parent_ip) & mask) == (u128::from(child_ip) & mask)
        }
        _ => false,
    }
}
fn ip_block(node: &TreeNode, path: &FieldPath, ctx: &ValidationContext<'_>, out: &mut dyn FindingSink) {
    require(node, "cidr", path, out);
    let parent = text(node, "cidr").and_then(|value| checked_cidr(value, ctx, &path.child("cidr"), out));
    if ctx.fields.processing.exhausted() || out.exhausted() {
        return;
    }
    if let Some(items) = node.get("except").and_then(TreeNode::as_sequence) {
        for (index, item) in items.iter().enumerate() {
            if out.exhausted() {
                break;
            }
            let child = item
                .as_str()
                .and_then(|value| checked_cidr(value, ctx, &path.child("except").child(index.to_string()), out));
            if !out.exhausted()
                && parent
                    .zip(child)
                    .is_some_and(|(parent, child)| !contains(parent, child))
            {
                invalid(&path.child("except").child(index.to_string()), out);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        generation::NativeValidationIntent,
        resources::networking::{Service, ServicePort, ServiceSpec},
        value::Presence,
    };
    #[test]
    fn malformed_native_port_keys_still_have_exact_scalar_validation_paths() -> Result<(), Finding> {
        let port = ServicePort {
            port: Presence::Value(0),
            protocol: Presence::Value("INVALID".to_owned()),
            ..ServicePort::default()
        };
        let spec = ServiceSpec {
            ports: Presence::Value(vec![port]),
            ..ServiceSpec::default()
        };
        let mut service = Service::default();
        service.spec = Presence::Value(spec);
        let target =
            crate::capability::TargetProfile::documented_defaults(crate::capability::KubernetesVersion::new(1, 37)?);
        let mut findings = Vec::new();
        validate(
            &service,
            &ValidationContext {
                target: &target,
                intent: NativeValidationIntent::Unspecified,
                fields: crate::registry::FieldDecodeContext::standalone(),
            },
            &mut findings,
        );
        for pointer in ["/spec/ports/0/port", "/spec/ports/0/protocol"] {
            let path = FieldPath::parse(pointer)?;
            assert!(
                findings
                    .iter()
                    .any(|finding| finding.code == FindingCode::NativeFieldInvalid
                        && finding.path.as_ref() == Some(&path))
            );
        }
        Ok(())
    }
}

#[cfg(test)]
mod processing_tests;
