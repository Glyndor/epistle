//! Operator-facing descriptions of credential changes.

use std::path::Path;

use super::TokenSource;

/// What the change means for the container that holds the credential: the
/// file it mounts, and the variable it forwards.
pub(super) fn holder_lines(
	compose: &Path,
	holder: &str,
	previous_file: Option<&Path>,
	previous_env: Option<&str>,
	source: Option<TokenSource<'_>>,
) -> Vec<String> {
	let mut lines = Vec::new();
	let (after_file, after_env) = match source {
		Some(TokenSource::File(file)) => (Some(file), None),
		Some(TokenSource::Env(name)) => (None, Some(name)),
		None => (None, None),
	};
	match (previous_file, after_file) {
		(None, Some(after)) => {
			lines.push(format!(
				"{}: {holder} mounts {} read-only",
				compose.display(),
				after.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: {holder} no longer mounts {}",
				compose.display(),
				before.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: {holder} mounts {} read-only instead of {}",
				compose.display(),
				after.display(),
				before.display()
			));
		}
		_ => {}
	}
	match (previous_env, after_env) {
		(None, Some(after)) => {
			lines.push(format!(
				"{}: {holder} forwards {after} to the container",
				compose.display()
			));
		}
		(Some(before), None) => {
			lines.push(format!(
				"{}: {holder} no longer forwards {before} to the container",
				compose.display()
			));
		}
		(Some(before), Some(after)) if before != after => {
			lines.push(format!(
				"{}: {holder} forwards {after} to the container instead of {before}",
				compose.display()
			));
		}
		_ => {}
	}
	lines
}

/// What the change means for the service the split took the credential away
/// from: the operator has to know the token left the container that takes
/// SMTP.
pub(super) fn other_lines(
	compose: &Path,
	other: &str,
	removed: &[&Path],
	forwarded: &[&str],
) -> Vec<String> {
	let mut lines = Vec::new();
	for path in removed {
		lines.push(format!(
			"{}: {other} no longer mounts {}",
			compose.display(),
			path.display()
		));
	}
	for name in forwarded {
		lines.push(format!(
			"{}: {other} no longer forwards {name} to the container",
			compose.display()
		));
	}
	lines
}
