//! Filesystem path checks for setup answers.

use super::Invalid;
use std::path::{Path, PathBuf};

/// A character that must never reach a terminal as itself: a control
/// character moves the cursor or repaints the screen, and an invisible
/// formatting character reorders or hides the text around it. Both are
/// what [`crate::cli::term::sanitize`] escapes before printing.
fn control_or_invisible(c: char) -> bool {
	c.is_control() || crate::cli::term::is_invisible_format(c)
}

pub(super) fn check_absolute_paths(data_dir: &Path, config_path: &Path, errors: &mut Vec<Invalid>) {
	// Compose interpolates `$VAR` (and `${VAR}`) inside any value
	// it parses, including path-shaped strings. The compose file
	// we emit mounts `data_dir` and `config_path.parent()` on
	// both sides of the colon, so a `$VAR` in the source path
	// resolves at `podup config` time (to the empty string when
	// the variable is unset, or to whatever the host environment
	// happens to carry) while the rendered `mail.toml` keeps
	// the literal `$VAR` in its `data` and key paths. The
	// container then cannot find the keys the host generated.
	// The validator refuses the shape before any effect so the
	// operator has to write the resolved path directly. The
	// check walks the path as a string (not a `Path` slice) so
	// it catches a `$` in any component, including one that
	// `Path::components` would already have collapsed away.
	if let Some(text) = data_dir.to_str()
		&& text.contains('$')
	{
		errors.push(Invalid::PathInterpolated {
			field: "data_dir".to_string(),
			value: text.to_string(),
		});
		return;
	}
	// The plan and the report print both paths on the terminal, so a
	// control or invisible formatting character in one would move the
	// cursor, clear the screen or hide text in what the operator is
	// reading. A path never needs one, so the validator refuses the
	// shape before any effect instead of escaping it at print time.
	for (field, path) in [("data_dir", data_dir), ("config_path", config_path)] {
		if let Some(text) = path.to_str()
			&& text.chars().any(control_or_invisible)
		{
			errors.push(Invalid::PathControl {
				field: field.to_string(),
				value: text.to_string(),
			});
		}
	}
	if let Some(text) = config_path.to_str()
		&& text.contains('$')
	{
		errors.push(Invalid::PathInterpolated {
			field: "config_path".to_string(),
			value: text.to_string(),
		});
		return;
	}
	if !data_dir.is_absolute() {
		errors.push(Invalid::DataDirNotAbsolute);
	}
	if !config_path.is_absolute() {
		errors.push(Invalid::ConfigPathNotAbsolute);
		return;
	}
	// `config_path = "/"` is absolute, so the check above accepts it,
	// but the apply phase rejects it at the staging step (no file
	// name to stage next to). By then the data directory and every
	// key have already been written. The validator catches the same
	// shape earlier so nothing is touched.
	if !path_has_a_file_name(config_path) {
		errors.push(Invalid::ConfigPathNoFileName);
	}
	// Writing the config into the data directory would overwrite a
	// key with the staging temp or the renamed config. The validator
	// catches the equality before any effect, so the operator can
	// fix the answer and rerun.
	if data_dir == config_path {
		errors.push(Invalid::ConfigPathEqualsDataDir);
	}
	// `init` owns `<data_dir>/keys` and lands the staging step
	// inside `config_path.parent()`. A `config_path` that resolves
	// inside the keys directory would race the staging temp against
	// a key the same run is about to write. The component comparison
	// keeps a path whose name only *starts* with `keys` (a
	// sibling directory the operator owns) accepted.
	if path_is_inside_keys_dir(data_dir, config_path) {
		errors.push(Invalid::ConfigPathInsideKeysDir);
	}
	// The compose file mounts `data_dir` and `config_path.parent()`
	// (the directory holding `mail.toml`) at the same path on both
	// sides of the colon. When the two paths overlap, the rendered
	// compose file carries two volumes with the same destination and
	// podman refuses the container. Catching both directions here
	// keeps the apply phase from ever landing that file on disk.
	//
	// The comparison lexically normalises `.` and `..` first, so
	// `data_dir = "/srv/epistle/data"` and
	// `config_path = "/srv/epistle/spare/../data/mail.toml"` are
	// caught even though the textual forms look disjoint. When
	// both paths resolve to something on disk, the helper also
	// canonicalises them so a symlink at one of the components
	// (e.g. `/var/run` -> `/run`) is followed to the same
	// underlying directory. A `..` that cannot be resolved
	// lexically (the path tries to escape its own root, e.g.
	// `data_dir = "/../foo"`) is refused separately so the
	// operator sees the shape of the mistake rather than a
	// silent rewrite to a path they did not type.
	let normalised_data_dir = match lexically_normalised(data_dir) {
		Ok(path) => path,
		Err(()) => {
			errors.push(Invalid::PathParentEscapesRoot {
				field: "data_dir".to_string(),
				value: data_dir.display().to_string(),
			});
			return;
		}
	};
	let normalised_config_dir = match config_path
		.parent()
		.and_then(|dir| lexically_normalised(dir).ok())
	{
		Some(path) => path,
		None => {
			errors.push(Invalid::PathParentEscapesRoot {
				field: "config_path".to_string(),
				value: config_path.display().to_string(),
			});
			return;
		}
	};
	let (left, right) = if normalised_data_dir.exists() && normalised_config_dir.exists() {
		match (
			normalised_data_dir.canonicalize(),
			normalised_config_dir.canonicalize(),
		) {
			(Ok(l), Ok(r)) => (l, r),
			// A canonicalisation failure on a path that exists
			// is rare (an unreadable parent on Linux), and the
			// apply phase will surface it with its own
			// diagnostic. The lexical comparison is still the
			// correct verdict in the meantime.
			_ => (normalised_data_dir, normalised_config_dir),
		}
	} else {
		(normalised_data_dir, normalised_config_dir)
	};
	if paths_overlap(&left, &right) {
		errors.push(Invalid::ConfigMountsOverlap {
			data_dir: left.display().to_string(),
			config_dir: right.display().to_string(),
		});
	}
}

/// Lexically normalise `path` by resolving `.` and `..` components
/// without touching the filesystem. Returns `Err(())` when a `..`
/// cannot pop a `Normal` component (i.e. the path tries to climb
/// above its own root, as in `data_dir = "/../foo"` or
/// `"/a/../../b"`). Silently rewriting the path would land a
/// file at a location the operator did not type, and the operator
/// almost certainly meant to write the normalised form
/// directly. `Path::components` exposes `..` as
/// `Component::ParentDir` and `.` as `Component::CurDir`; the
/// algorithm pushes `Normal` components onto a stack, pops on
/// `ParentDir`, ignores `CurDir`, and resets the stack on
/// `RootDir` / `Prefix` so a Windows drive letter followed by
/// `..` does not consume the drive.
pub(super) fn lexically_normalised(path: &Path) -> Result<PathBuf, ()> {
	let mut stack: Vec<std::path::Component<'_>> = Vec::new();
	for component in path.components() {
		match component {
			std::path::Component::RootDir | std::path::Component::Prefix(_) => {
				stack.clear();
				stack.push(component);
			}
			std::path::Component::CurDir => {}
			std::path::Component::ParentDir => {
				let can_pop = matches!(stack.last(), Some(std::path::Component::Normal(_)));
				if can_pop {
					stack.pop();
				} else {
					// Either the stack is empty (a relative path
					// that climbs above its starting directory,
					// which the absolute-path check has already
					// rejected) or the top is a RootDir / Prefix
					// (a parent_dir at the root, which would
					// resolve to the root itself). Either way,
					// the operator wrote a parent component the
					// normalisation cannot apply, and silently
					// dropping it would rewrite the path to a
					// location the operator did not type.
					return Err(());
				}
			}
			std::path::Component::Normal(_) => stack.push(component),
		}
	}
	let mut out = PathBuf::new();
	for component in stack {
		out.push(component.as_os_str());
	}
	Ok(out)
}

/// True when `a` and `b` refer to the same directory or one is a
/// strict componentwise prefix of the other. The componentwise
/// comparison keeps a path whose name only *starts* with a
/// component of the other (a sibling the operator owns) accepted.
/// The inputs are expected to have been lexically normalised
/// (and, where they exist on disk, canonicalised) by the caller;
/// raw operator paths with `.` or `..` components are not safe to
/// compare here.
fn paths_overlap(a: &Path, b: &Path) -> bool {
	let mut ac = a.components();
	let mut bc = b.components();
	loop {
		match (ac.next(), bc.next()) {
			(Some(x), Some(y)) if x == y => continue,
			(Some(_), Some(_)) => return false,
			(None, Some(_)) | (Some(_), None) => return true,
			(None, None) => return true,
		}
	}
}

/// True when `path` ends with a normal file-name component: not the
/// root, not `.` or `..`, not an empty string, not a trailing
/// separator or a separator followed by `.` or `..`. The apply
/// phase requires the same shape to find a sibling staging file; the
/// validator catches the missing piece earlier. `Path::components()`
/// silently elides a trailing `/.` to its parent, so the textual check
/// below is what surfaces that shape.
fn path_has_a_file_name(path: &Path) -> bool {
	if let Some(text) = path.as_os_str().to_str()
		&& (text.ends_with('/') || text.ends_with("/.") || text.ends_with("/.."))
	{
		return false;
	}
	matches!(
		path.components().next_back(),
		Some(std::path::Component::Normal(_))
	)
}

/// True when `<data_dir>/keys` is a strict componentwise prefix of
/// `config_path`. The comparison walks `Path::components` so a path
/// like `<data_dir>/keysfoo/mail.toml` does not match: `keys` is a
/// sibling directory, not a prefix component.
fn path_is_inside_keys_dir(data_dir: &Path, config_path: &Path) -> bool {
	let keys_dir = data_dir.join("keys");
	let mut kc = keys_dir.components();
	let mut cc = config_path.components();
	loop {
		match (kc.next(), cc.next()) {
			(Some(a), Some(b)) if a == b => continue,
			(Some(_), _) => return false,
			(None, Some(_)) => return true,
			(None, None) => return false,
		}
	}
}
