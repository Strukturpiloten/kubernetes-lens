//! Original finite RBAC/ServiceAccount structural checks, without effective-permission inference.
use super::validation::{enumeration, invalid, present, require, sequence, text, unadmitted};
use crate::{
    diagnostic::FieldPath,
    syntax::{TreeNode, TreeValue},
    value::dns_subdomain,
};

fn rule(node: &TreeNode, cluster: bool, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    if sequence(node, "verbs").is_empty() {
        invalid(&path.child("verbs"), out);
    }
    // An empty API group is the exact core group, and is valid.
    if sequence(node, "apiGroups").iter().any(|value| value.as_str().is_none()) {
        invalid(&path.child("apiGroups"), out);
    }
    let urls = sequence(node, "nonResourceURLs");
    if !urls.is_empty() {
        if !cluster
            || !sequence(node, "resources").is_empty()
            || !sequence(node, "apiGroups").is_empty()
            || !sequence(node, "resourceNames").is_empty()
        {
            invalid(path, out);
        }
    } else if sequence(node, "resources").is_empty() || sequence(node, "apiGroups").is_empty() {
        invalid(path, out);
    }
}
fn subject(node: &TreeNode, cluster: bool, path: &FieldPath, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(node) {
        return;
    }
    if out.exhausted() {
        return;
    }
    require(node, "kind", path, out);
    require(node, "name", path, out);
    if text(node, "name") == Some("") {
        invalid(&path.child("name"), out);
    }
    match text(node, "kind") {
        Some("ServiceAccount") => {
            if !text(node, "name").is_some_and(dns_subdomain) {
                invalid(&path.child("name"), out);
            }
            if text(node, "apiGroup").is_some_and(|value| !value.is_empty()) {
                invalid(&path.child("apiGroup"), out);
            }
            if cluster && text(node, "namespace").is_none_or(str::is_empty) {
                invalid(&path.child("namespace"), out);
            }
        }
        Some("User" | "Group") => {
            if text(node, "apiGroup") != Some("rbac.authorization.k8s.io") {
                invalid(&path.child("apiGroup"), out);
            }
        }
        _ => invalid(&path.child("kind"), out),
    }
}
pub(super) fn validate(tree: &TreeNode, kind: &str, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let cluster = kind.starts_with("Cluster");
    let path = FieldPath::default();
    for (index, item) in sequence(tree, "rules").iter().enumerate() {
        if out.exhausted() {
            return;
        }
        rule(item, cluster, &path.child("rules").child(index.to_string()), out);
    }
    if kind.ends_with("Binding") {
        require(tree, "roleRef", &path, out);
        if let Some(role) = tree.get("roleRef") {
            let role_path = path.child("roleRef");
            if text(role, "apiGroup") != Some("rbac.authorization.k8s.io") {
                invalid(&role_path.child("apiGroup"), out);
            }
            let allowed = if cluster {
                &["ClusterRole"][..]
            } else {
                &["Role", "ClusterRole"][..]
            };
            enumeration(role, "kind", allowed, &role_path, out);
            if !text(role, "name")
                .is_some_and(|value| !value.is_empty() && value != "." && value != ".." && !value.contains(['/', '%']))
            {
                invalid(&role_path.child("name"), out);
            }
        }
        for (index, item) in sequence(tree, "subjects").iter().enumerate() {
            if out.exhausted() {
                return;
            }
            subject(item, cluster, &path.child("subjects").child(index.to_string()), out);
        }
    }
    if let Some(aggregation) = tree.get("aggregationRule").filter(|node| node.value != TreeValue::Null) {
        if sequence(aggregation, "clusterRoleSelectors").is_empty() {
            invalid(&path.child("aggregationRule").child("clusterRoleSelectors"), out);
        }
        for (index, item) in sequence(aggregation, "clusterRoleSelectors").iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let path = path
                .child("aggregationRule")
                .child("clusterRoleSelectors")
                .child(index.to_string());
            super::validation::selector(item, &path, out);
        }
        // Supplied rules remain desired/source data; controller reconciliation is not modeled.
        unadmitted(&path.child("aggregationRule"), out);
    }
}
pub(super) fn service_account(tree: &TreeNode, out: &mut dyn super::validation::AccessSink) {
    if !out.admit_tree(tree) {
        return;
    }
    if out.exhausted() {
        return;
    }
    let namespace = tree.get("metadata").and_then(|meta| text(meta, "namespace"));
    for key in ["secrets", "imagePullSecrets"] {
        if out.exhausted() {
            return;
        }
        for (index, reference) in sequence(tree, key).iter().enumerate() {
            if out.exhausted() {
                return;
            }
            let path = FieldPath(vec![key.into(), index.to_string()]);
            if text(reference, "kind").is_some_and(|kind| kind != "Secret")
                || text(reference, "apiVersion").is_some_and(|api| api != "v1")
            {
                unadmitted(&path, out);
            }
            if text(reference, "namespace").is_some_and(|value| !value.is_empty() && Some(value) != namespace) {
                unadmitted(&path.child("namespace"), out);
            }
            if present(reference, "uid") || present(reference, "resourceVersion") || present(reference, "fieldPath") {
                unadmitted(&path, out);
            }
        }
    }
}
