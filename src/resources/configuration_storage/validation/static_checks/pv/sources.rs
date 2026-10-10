//! Selected source-specific syntax. No backing storage is opened or inspected.
use super::{
    Check, Finding, PersistentVolume, TreeNode, TreeValue, bounded_integer, context, get, label, nonempty_list,
    required, text,
};
mod identifiers;
const SOURCES: &[&str] = &[
    "gcePersistentDisk",
    "awsElasticBlockStore",
    "hostPath",
    "glusterfs",
    "nfs",
    "rbd",
    "iscsi",
    "cinder",
    "cephfs",
    "fc",
    "flocker",
    "flexVolume",
    "azureFile",
    "vsphereVolume",
    "quobyte",
    "azureDisk",
    "photonPersistentDisk",
    "portworxVolume",
    "scaleIO",
    "local",
    "storageos",
    "csi",
];
pub(super) fn check(spec: &TreeNode, volume: &PersistentVolume, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let mut count = 0;
    for branch in SOURCES {
        if check.out.exhausted() {
            return Ok(());
        }
        if let Some(node) = get(spec, branch, check)? {
            count += 1;
            if *branch == "portworxVolume" {
                if !check.out.exhausted() {
                    check.out.push(
                        Finding::warning(
                            crate::diagnostic::FindingCode::UnadmittedField,
                            crate::diagnostic::Phase::Validation,
                        )
                        .at_path(check.path(&["spec", branch])?),
                    );
                }
                continue;
            }
            source(node, branch, volume, check)?;
        }
    }
    if count != 1 {
        check.invalid(&["spec"])?;
    }
    Ok(())
}
fn source(node: &TreeNode, branch: &str, volume: &PersistentVolume, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let names: &[&str] = match branch {
        "gcePersistentDisk" => &["pdName"],
        "awsElasticBlockStore" | "cinder" => &["volumeID"],
        "hostPath" | "local" => &["path"],
        "glusterfs" => &["endpoints", "path"],
        "nfs" => &["server", "path"],
        "rbd" => &["image"],
        "iscsi" => &["targetPortal", "iqn"],
        "flexVolume" => &["driver"],
        "azureFile" => &["secretName", "shareName"],
        "vsphereVolume" => &["volumePath"],
        "quobyte" => &["registry", "volume"],
        "azureDisk" => &["diskName", "diskURI"],
        "photonPersistentDisk" => &["pdID"],
        "scaleIO" => &["gateway", "system", "volumeName"],
        "storageos" => &["volumeName"],
        "csi" => &["driver", "volumeHandle"],
        _ => &[],
    };
    required(node, branch, names, check)?;
    match branch {
        "gcePersistentDisk" | "awsElasticBlockStore" => bounded_integer(node, branch, "partition", check)?,
        "hostPath" | "local" => path_source(node, branch, volume, check)?,
        "nfs" => {
            if text(node, "path", check)?.is_some_and(|path| !path.starts_with('/')) {
                check.invalid(&["spec", branch, "path"])?;
            }
        }
        "rbd" | "cephfs" => {
            if !nonempty_list(node, "monitors", check)? {
                check.invalid(&["spec", branch, "monitors"])?;
            }
        }
        "glusterfs" => namespace(node, branch, "endpointsNamespace", false, check)?,
        "cinder" => secret(node, branch, "secretRef", false, check)?,
        "iscsi" => iscsi(node, volume, check)?,
        "fc" => fibre_channel(node, check)?,
        "flocker" => flocker(node, check)?,
        "flexVolume" => flex(node, check)?,
        "azureFile" => namespace(node, branch, "secretNamespace", true, check)?,
        "azureDisk" => azure(node, check)?,
        "quobyte" => quobyte(node, check)?,
        "storageos" => storageos(node, check)?,
        "csi" => csi(node, check)?,
        _ => (),
    }
    Ok(())
}
fn namespace(
    node: &TreeNode,
    branch: &str,
    field: &str,
    arbitrary: bool,
    check: &mut Check<'_, '_>,
) -> Result<(), Finding> {
    if let Some(value) = text(node, field, check)? {
        if value.is_empty() || !arbitrary && !label(value) {
            check.invalid(&["spec", branch, field])?;
        }
    }
    Ok(())
}
fn path_source(
    node: &TreeNode,
    branch: &str,
    volume: &PersistentVolume,
    check: &mut Check<'_, '_>,
) -> Result<(), Finding> {
    if let Some(path) = text(node, "path", check)? {
        if path.split('/').any(|part| part == "..") {
            check.invalid(&["spec", branch, "path"])?;
        }
        if path.contains('\\') {
            context(check, &["spec", branch, "path"])?;
        }
        if branch == "hostPath"
            && path.starts_with('/')
            && path.split('/').all(|part| part.is_empty() || part == ".")
            && volume
                .spec
                .value()
                .and_then(|spec| spec.persistent_volume_reclaim_policy.value())
                .is_some_and(|policy| policy == "Recycle")
        {
            check.invalid(&["spec", "persistentVolumeReclaimPolicy"])?;
        }
    }
    if branch == "hostPath" {
        if let Some(value) = text(node, "type", check)? {
            if !matches!(
                value,
                "" | "DirectoryOrCreate"
                    | "Directory"
                    | "FileOrCreate"
                    | "File"
                    | "Socket"
                    | "CharDevice"
                    | "BlockDevice"
            ) {
                check.invalid(&["spec", branch, "type"])?;
            }
        }
    }
    Ok(())
}
fn secret(
    node: &TreeNode,
    branch: &str,
    field: &str,
    name_only: bool,
    check: &mut Check<'_, '_>,
) -> Result<(), Finding> {
    if let Some(secret) = get(node, field, check)? {
        for member in if name_only {
            &["name"][..]
        } else {
            &["name", "namespace"][..]
        } {
            if text(secret, member, check)?.is_none_or(str::is_empty) {
                check.invalid(&["spec", branch, field, member])?;
            }
        }
    }
    Ok(())
}
fn fibre_channel(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let targets = nonempty_list(node, "targetWWNs", check)?;
    let ids = nonempty_list(node, "wwids", check)?;
    if targets == ids {
        check.invalid(&["spec", "fc"])?;
    }
    if targets {
        if get(node, "lun", check)?.is_none() {
            check.invalid(&["spec", "fc", "lun"])?;
        }
        bounded_integer(node, "fc", "lun", check)?;
    }
    Ok(())
}
fn flocker(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    let name = text(node, "datasetName", check)?.filter(|name| !name.is_empty());
    let id = text(node, "datasetUUID", check)?.filter(|name| !name.is_empty());
    if name.is_some() == id.is_some() {
        check.invalid(&["spec", "flocker"])?;
    }
    if name.is_some_and(|name| name.contains('/')) {
        check.invalid(&["spec", "flocker", "datasetName"])?;
    }
    Ok(())
}
fn flex(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    if let Some(options) = get(node, "options", check)?.and_then(TreeNode::as_mapping) {
        for (key, _) in options {
            check.text(key)?;
            let namespace = key.split('/').next().unwrap_or("");
            check.payload(namespace.len())?;
            let namespace = namespace.to_ascii_lowercase();
            if ["kubernetes.io", "k8s.io"].iter().any(|reserved| {
                namespace == *reserved
                    || namespace
                        .strip_suffix(reserved)
                        .is_some_and(|prefix| prefix.ends_with('.'))
            }) {
                check.invalid(&["spec", "flexVolume", "options", key])?;
            }
        }
    }
    Ok(())
}
fn azure(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    if text(node, "cachingMode", check)?.is_some_and(|mode| !matches!(mode, "None" | "ReadOnly" | "ReadWrite")) {
        check.invalid(&["spec", "azureDisk", "cachingMode"])?;
    }
    let kind = text(node, "kind", check)?;
    if kind.is_some_and(|kind| !matches!(kind, "Shared" | "Dedicated" | "Managed")) {
        check.invalid(&["spec", "azureDisk", "kind"])?;
    }
    if let (Some(kind), Some(uri)) = (kind, text(node, "diskURI", check)?) {
        let prefix = if kind == "Managed" {
            "/subscriptions/"
        } else {
            "https://"
        };
        if !uri.starts_with(prefix) {
            check.invalid(&["spec", "azureDisk", "diskURI"])?;
        }
    }
    Ok(())
}
fn storageos(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    for field in ["volumeName", "volumeNamespace"] {
        if text(node, field, check)?.is_some_and(|value| !value.is_empty() && !label(value)) {
            check.invalid(&["spec", "storageos", field])?;
        }
    }
    secret(node, "storageos", "secretRef", false, check)
}
fn csi(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    if let Some(driver) = text(node, "driver", check)? {
        check.payload(driver.len())?;
        if driver.len() > 63
            || !crate::resources::configuration_storage::validation::static_checks::class_name(
                &driver.to_ascii_lowercase(),
            )
        {
            check.invalid(&["spec", "csi", "driver"])?;
        }
    }
    for field in [
        "controllerPublishSecretRef",
        "nodePublishSecretRef",
        "controllerExpandSecretRef",
    ] {
        secret(node, "csi", field, false, check)?;
        let Some(reference) = get(node, field, check)? else {
            continue;
        };
        if let Some(name) = text(reference, "name", check)? {
            let subdomain = crate::resources::configuration_storage::validation::static_checks::class_name(name);
            let minor = check.ctx.target.kubernetes.minor();
            if minor <= 24 && !label(name) || minor >= 27 && !subdomain || (25..=26).contains(&minor) && !subdomain {
                check.invalid(&["spec", "csi", field, "name"])?;
            } else if (25..=26).contains(&minor) && !label(name) {
                context(check, &["spec", "csi", field, "name"])?;
            }
        }
        if text(reference, "namespace", check)?.is_some_and(|namespace| !label(namespace)) {
            check.invalid(&["spec", "csi", field, "namespace"])?;
        }
    }
    Ok(())
}
fn iscsi(node: &TreeNode, volume: &PersistentVolume, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    bounded_integer(node, "iscsi", "lun", check)?;
    for field in ["iqn", "initiatorName"] {
        if let Some(value) = text(node, field, check)? {
            if !identifiers::iscsi(value, check)? {
                check.invalid(&["spec", "iscsi", field])?;
            }
        }
    }
    if get(node, "initiatorName", check)?.is_some() {
        let name = volume
            .metadata
            .value()
            .and_then(|metadata| metadata.name.value())
            .map_or("", String::as_str);
        let target = text(node, "targetPortal", check)?.unwrap_or("");
        check.text(name)?;
        if name.len().saturating_add(1).saturating_add(target.len()) > 64 {
            check.invalid(&["spec", "iscsi", "initiatorName"])?;
        }
    }
    let chap = ["chapAuthDiscovery", "chapAuthSession"]
        .iter()
        .try_fold(false, |value, field| {
            Ok::<_, Finding>(
                value || get(node, field, check)?.is_some_and(|node| matches!(node.value, TreeValue::Bool(true))),
            )
        })?;
    if chap && get(node, "secretRef", check)?.is_none() {
        check.invalid(&["spec", "iscsi", "secretRef"])?;
    }
    secret(node, "iscsi", "secretRef", true, check)
}
fn quobyte(node: &TreeNode, check: &mut Check<'_, '_>) -> Result<(), Finding> {
    if let Some(tenant) = text(node, "tenant", check)? {
        if tenant.len() > 64 {
            check.invalid(&["spec", "quobyte", "tenant"])?;
        }
    }
    if let Some(registry) = text(node, "registry", check)? {
        for address in registry.split(',') {
            match identifiers::host_port(address) {
                Some(false) => check.invalid(&["spec", "quobyte", "registry"])?,
                None => context(check, &["spec", "quobyte", "registry"])?,
                Some(true) => (),
            }
        }
    }
    Ok(())
}
