//! Where a path read from another server's configuration may point.
//!
//! A configuration names the files it uses: Mox's `PrivateKeyFile` and
//! Stalwart's `%{file:...}%`. Those names are relative to the directory
//! the configuration sits in, and to nothing else. A configuration is not
//! trusted to name a file anywhere on the machine, so an absolute name, a
//! name that climbs out with `..`, and a link that points outside the
//! directory are all refused, by the name of the setting they came from.
//!
//! The path that is read is the one
//! [`contained`](crate::util::path_containment::contained) resolved: every
//! part of it that exists is resolved, so reading it cannot walk out of the
//! directory through a link.

use std::path::{Component, Path, PathBuf};

use crate::util::path_containment::contained;

/// The file a configuration points at, when it stays inside `dir`.
///
/// `setting` is the name of the setting the value came from. A refusal
/// names the setting and not the path the value would have resolved to:
/// the value belongs to the configuration, the resolved path to the
/// machine.
pub(crate) fn inside(dir: &Path, setting: &str, value: &str) -> Result<PathBuf, String> {
	let relative = Path::new(value);
	if relative.as_os_str().is_empty() || relative.is_absolute() {
		return Err(refused(setting));
	}
	if relative.components().any(|component| {
		matches!(
			component,
			Component::ParentDir | Component::RootDir | Component::Prefix(_)
		)
	}) {
		return Err(refused(setting));
	}
	contained(dir, &dir.join(relative)).map_err(|_| refused(setting))
}

/// Why a path was refused.
fn refused(setting: &str) -> String {
	format!("{setting} must be a relative path inside the configuration directory, without `..`")
}
