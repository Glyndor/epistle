//! The panel's key file as `epistle rotate --all` uses it.
//!
//! The rotation gives the `panel` key a new secret like every other API key.
//! The file the panel reads has to change with it: a file left with the old
//! secret is refused by the API until a `stack update` finds that it does not
//! match and replaces it.

use std::path::{Path, PathBuf};

use super::super::super::apply::ApplyError;
use super::held::{self, Held};

/// Look at the panel's key file. A link, a directory, an empty file or one
/// that cannot be read is an error that names the path and never the content.
fn look(path: &Path) -> Result<Held, String> {
	held::read(path).map_err(|error| match error {
		ApplyError::ExistingSecretUnreadable(path, why) => format!(
			"the panel's key file {} cannot be used ({why}); nothing was written over it",
			path.display()
		),
		other => other.to_string(),
	})
}

/// The panel's key file, when this install has one: `None` when nothing is at
/// its path, which is an install without the panel.
pub(crate) fn held_api_token(data_dir: &Path) -> Result<Option<PathBuf>, String> {
	let path = super::api_token_path(data_dir);
	Ok(match look(&path)? {
		Held::Missing => None,
		Held::Present(_) => Some(path),
	})
}

/// Put `secret` in the panel's key file, written the way [`super::ensure`]
/// writes it. What is at the path is looked at first, so a link or a
/// directory put there since is refused and not written over.
pub(crate) fn replace_api_token(data_dir: &Path, secret: &str) -> Result<(), String> {
	let path = super::api_token_path(data_dir);
	look(&path)?;
	super::key::write_token(&path, secret)
		.map_err(|error| format!("cannot write {}: {error}", path.display()))
}

/// Lay the panel's files down as `init` does, for the tests of the commands
/// that find them there.
#[cfg(test)]
pub(crate) fn install_for_tests(data_dir: &Path, now: u64) {
	let mut report = super::super::super::apply::Report::default();
	super::ensure(data_dir, now, &mut report).expect("the panel's files");
}

/// Whether [`super::ensure`] would keep the panel's key as it is at `now`: the
/// file holds the secret of the stored key.
#[cfg(test)]
pub(crate) fn key_is_kept_for_tests(data_dir: &Path, now: u64) -> bool {
	matches!(super::decide(data_dir, now), Ok(decision) if decision.key == super::KeyAction::Reuse)
}
