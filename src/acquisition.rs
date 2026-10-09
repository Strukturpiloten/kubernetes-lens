//! Explicit bounded regular-file acquisition. No ambient discovery, renderer, or cluster calls.
use crate::{
    capability::KubernetesVersion,
    diagnostic::{Finding, FindingCode, Phase},
    parser::ParsedInput,
    source::{InputOrigin, ParseLimits, SourceId},
};
#[cfg(target_os = "linux")]
use crate::{
    parser::parse_source,
    source::{DocumentFormat, SourceInput},
};
#[cfg(target_os = "linux")]
use std::{
    collections::BTreeSet,
    fs::{self, Metadata, OpenOptions},
    io::Read,
    path::PathBuf,
};
use std::{fmt, path::Path};
/// Explicit finite file/directory read policy.
#[derive(Clone, Debug)]
pub struct AcquisitionOptions {
    /// Maximum selected regular files.
    pub max_files: usize,
    /// Maximum encountered files/directories, including rejected extension candidates.
    pub max_entries: usize,
    /// Maximum aggregate acquired bytes.
    pub max_total_bytes: usize,
    /// Maximum directory traversal depth.
    pub max_directory_depth: usize,
    /// Select YAML extensions (`yaml`, `yml`).
    pub yaml: bool,
    /// Select JSON extension (`json`).
    pub json: bool,
    /// Independent parser limits per file.
    pub parse_limits: ParseLimits,
    /// Explicit caller origin.
    pub origin: InputOrigin,
    /// Optional caller-declared source version.
    pub source_version: Option<KubernetesVersion>,
    /// First deterministic input-local source ID.
    pub first_source_id: SourceId,
}
impl Default for AcquisitionOptions {
    fn default() -> Self {
        Self {
            max_files: 256,
            max_entries: 4096,
            max_total_bytes: 32 * 1024 * 1024,
            max_directory_depth: 16,
            yaml: true,
            json: true,
            parse_limits: ParseLimits::default(),
            origin: InputOrigin::CallerSupplied,
            source_version: None,
            first_source_id: SourceId(0),
        }
    }
}
/// Private acquired inputs; Debug reveals only counts and source summaries.
pub struct AcquiredInputs {
    inputs: Vec<ParsedInput>,
}
impl AcquiredInputs {
    /// Borrow explicit parsed inputs.
    #[must_use]
    pub fn inputs(&self) -> &[ParsedInput] {
        &self.inputs
    }
    /// Consume acquired syntax inputs for native resource materialization.
    #[must_use]
    pub fn into_inputs(self) -> Vec<ParsedInput> {
        self.inputs
    }
}
impl fmt::Debug for AcquiredInputs {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcquiredInputs").field("inputs", &self.inputs).finish()
    }
}
/// Acquire exactly one caller-selected regular file or directory tree.
///
/// Symlinks, duplicate inode identities, unsupported extensions, special files and races fail
/// closed. Linux verifies opened descriptors through procfs before and after bounded reads.
/// Other platforms refuse this acquisition boundary; byte parsing remains portable.
/// # Errors
/// Returns fixed private-safe findings for unsafe inputs, races, policy/budget or syntax failure.
pub fn acquire(path: &Path, options: &AcquisitionOptions) -> Result<AcquiredInputs, Vec<Finding>> {
    acquire_inner(path, options).map_err(|f| vec![f])
}
#[cfg(not(target_os = "linux"))]
fn acquire_inner(_path: &Path, _options: &AcquisitionOptions) -> Result<AcquiredInputs, Finding> {
    Err(failed())
}
#[cfg(target_os = "linux")]
fn acquire_inner(path: &Path, options: &AcquisitionOptions) -> Result<AcquiredInputs, Finding> {
    use std::os::{fd::AsRawFd, unix::fs::OpenOptionsExt};
    if options.max_files == 0
        || options.max_entries == 0
        || options.max_total_bytes == 0
        || options.max_directory_depth > 64
        || !options.yaml && !options.json
        || !options.parse_limits.valid()
    {
        return Err(failed());
    }
    let selected = fs::symlink_metadata(path).map_err(|_| failed())?;
    if selected.file_type().is_symlink() {
        return Err(failed());
    }
    let canonical = fs::canonicalize(path).map_err(|_| failed())?;
    let root = if selected.is_dir() {
        canonical.clone()
    } else {
        canonical.parent().ok_or_else(failed)?.to_owned()
    };
    reject_symlink_components(path)?;
    let root_metadata = fs::symlink_metadata(&root).map_err(|_| failed())?;
    let root_handle = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_DIRECTORY)
        .open(&root)
        .map_err(|_| failed())?;
    let root_descriptor = PathBuf::from(format!("/proc/self/fd/{}", root_handle.as_raw_fd()));
    if !same(&root_metadata, &root_handle.metadata().map_err(|_| failed())?)
        || fs::canonicalize(&root_descriptor).map_err(|_| failed())? != root
    {
        return Err(failed());
    }

    let mut files = Vec::new();
    let mut identities = BTreeSet::new();
    walk(&canonical, &root, 0, options, &mut identities, &mut files)?;
    let mut total = 0usize;
    let mut inputs = Vec::new();
    for (index, (path, before, format)) in files.into_iter().enumerate() {
        if fs::canonicalize(&root_descriptor).map_err(|_| failed())? != root
            || !same(&root_metadata, &root_handle.metadata().map_err(|_| failed())?)
        {
            return Err(failed());
        }
        let cap = options
            .parse_limits
            .max_input_bytes
            .min(options.max_total_bytes.saturating_sub(total));
        let bytes = read_regular(&path, &root, &before, cap)?;
        total = total.checked_add(bytes.len()).ok_or_else(failed)?;
        let id = SourceId(
            options
                .first_source_id
                .0
                .checked_add(u64::try_from(index).map_err(|_| failed())?)
                .ok_or_else(failed)?,
        );
        let parsed = parse_source(
            SourceInput {
                id,
                format,
                origin: options.origin,
                source_version: options.source_version,
                bytes: &bytes,
            },
            &options.parse_limits,
        )
        .map_err(|findings| findings.into_iter().next().unwrap_or_else(failed))?;
        inputs.push(parsed);
    }
    if fs::canonicalize(&root_descriptor).map_err(|_| failed())? != root
        || !same(&root_metadata, &root_handle.metadata().map_err(|_| failed())?)
    {
        return Err(failed());
    }
    Ok(AcquiredInputs { inputs })
}

#[cfg(target_os = "linux")]
fn read_regular(path: &Path, root: &Path, before: &Metadata, cap: usize) -> Result<Vec<u8>, Finding> {
    use std::os::{
        fd::AsRawFd,
        unix::fs::{MetadataExt, OpenOptionsExt},
    };
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)
        .map_err(|_| failed())?;
    let opened = file.metadata().map_err(|_| failed())?;
    if !same(before, &opened) {
        return Err(failed());
    }
    let descriptor = PathBuf::from(format!("/proc/self/fd/{}", file.as_raw_fd()));
    if fs::canonicalize(&descriptor).map_err(|_| failed())? != path || !path.starts_with(root) {
        return Err(failed());
    }
    let mut bytes = Vec::new();
    (&file)
        .take(u64::try_from(cap).map_err(|_| failed())?.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|_| failed())?;
    if bytes.len() > cap {
        return Err(Finding::error(FindingCode::LimitExceeded, Phase::Acquisition));
    }
    let after = file.metadata().map_err(|_| failed())?;
    if !same(&opened, &after)
        || fs::canonicalize(&descriptor).map_err(|_| failed())? != path
        || after.size() != u64::try_from(bytes.len()).map_err(|_| failed())?
    {
        return Err(failed());
    }
    Ok(bytes)
}
#[cfg(target_os = "linux")]
fn walk(
    path: &Path,
    root: &Path,
    depth: usize,
    options: &AcquisitionOptions,
    identities: &mut BTreeSet<(u64, u64)>,
    files: &mut Vec<(PathBuf, Metadata, DocumentFormat)>,
) -> Result<(), Finding> {
    use std::os::unix::fs::MetadataExt;
    if depth > options.max_directory_depth {
        return Err(Finding::error(FindingCode::LimitExceeded, Phase::Acquisition));
    }
    if identities.len() >= options.max_entries {
        return Err(Finding::error(FindingCode::LimitExceeded, Phase::Acquisition));
    }
    let metadata = fs::symlink_metadata(path).map_err(|_| failed())?;
    if metadata.file_type().is_symlink()
        || !path.starts_with(root)
        || fs::canonicalize(path).map_err(|_| failed())? != path
        || !identities.insert((metadata.dev(), metadata.ino()))
    {
        return Err(failed());
    }
    if metadata.is_dir() {
        let mut entries = Vec::new();
        for entry in fs::read_dir(path).map_err(|_| failed())? {
            if entries.len().saturating_add(identities.len()) >= options.max_entries {
                return Err(Finding::error(FindingCode::LimitExceeded, Phase::Acquisition));
            }
            entries.push(entry.map_err(|_| failed())?.path());
        }
        entries.sort();
        for entry in entries {
            walk(&entry, root, depth + 1, options, identities, files)?;
        }
        if !same(&metadata, &fs::symlink_metadata(path).map_err(|_| failed())?) {
            return Err(failed());
        }
    } else if metadata.is_file() {
        let format = match path.extension().and_then(|v| v.to_str()) {
            Some("yaml" | "yml") if options.yaml => DocumentFormat::YamlStream,
            Some("json") if options.json => DocumentFormat::Json,
            _ => {
                return Err(Finding::error(
                    FindingCode::UnsupportedInputExtension,
                    Phase::Acquisition,
                ));
            }
        };
        if files.len() >= options.max_files {
            return Err(Finding::error(FindingCode::LimitExceeded, Phase::Acquisition));
        }
        files.push((path.to_owned(), metadata, format));
    } else {
        return Err(failed());
    }
    Ok(())
}
#[cfg(target_os = "linux")]
fn same(a: &Metadata, b: &Metadata) -> bool {
    use std::os::unix::fs::MetadataExt;
    a.file_type() == b.file_type()
        && a.dev() == b.dev()
        && a.ino() == b.ino()
        && a.size() == b.size()
        && a.mtime() == b.mtime()
        && a.mtime_nsec() == b.mtime_nsec()
        && a.ctime() == b.ctime()
        && a.ctime_nsec() == b.ctime_nsec()
}
#[cfg(target_os = "linux")]
fn reject_symlink_components(path: &Path) -> Result<(), Finding> {
    let absolute = if path.is_absolute() {
        path.to_owned()
    } else {
        std::env::current_dir().map_err(|_| failed())?.join(path)
    };
    let mut prefix = PathBuf::new();
    for component in absolute.components() {
        prefix.push(component);
        if fs::symlink_metadata(&prefix)
            .map_err(|_| failed())?
            .file_type()
            .is_symlink()
        {
            return Err(failed());
        }
    }
    Ok(())
}
fn failed() -> Finding {
    Finding::error(FindingCode::AcquisitionFailed, Phase::Acquisition)
}
