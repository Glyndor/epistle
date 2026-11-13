//! The web panel's API key: its secret is also in a file the panel reads.
//!
//! The run rotates the `panel` key like any other. On an install that holds
//! the panel's key file, the step also puts the new secret in that file, and
//! the last step of the run makes the `panel` container again when the stack
//! runs one: podup hands a container its file secrets when it creates it, so
//! a restart would keep the old key. It is last because a run stops at the
//! first failure, and a panel that cannot be made again must not keep any
//! secret from being rotated. The new secret is not printed, because the file
//! is where the panel reads it and nobody has to carry it there.

use std::path::Path;

use crate::cli::init::{PANEL_KEY_LABEL, compose_file_path, panel_key_file, replace_panel_key};
use crate::config::Config;

use super::super::journal::{Kind, Step};
use super::super::secrets::Secrets;

/// The compose service that reads the key file.
pub(in crate::cli::rotate) const SERVICE: &str = "panel";

/// Turn the `panel` key's step into the one that also writes the file, and
/// say whether the run has to end by making the panel's container again,
/// which is when the stack runs the panel. An install without the file keeps
/// an ordinary API key step: a key the operator labelled `panel` is theirs,
/// and no file is made for it.
///
/// What is at the file's path and the compose file are both looked at here,
/// so a refusal comes before the run changes anything.
pub(super) fn plan(config: &Config, steps: &mut [Step]) -> Result<bool, String> {
	let Some(step) = steps
		.iter_mut()
		.find(|step| step.kind == Kind::ApiKey && step.item == PANEL_KEY_LABEL)
	else {
		return Ok(false);
	};
	if panel_key_file(&config.data_dir)?.is_none() {
		return Ok(false);
	}
	step.kind = Kind::PanelApiKey;
	runs_panel(&compose_file_path(&config.data_dir))
}

/// Put the step's new secret in the panel's key file. It runs before the
/// store takes the new hash, so a run cut between the two finds the store
/// unchanged and does both again with the same secret.
pub(super) fn write(config: &Config, step: &Step, secrets: &Secrets) -> Result<(), String> {
	let secret = secrets
		.get(&step.secret_key())
		.ok_or("the new secret of the panel's key is not in the secrets file")?;
	replace_panel_key(&config.data_dir, secret)
}

/// Whether the generated compose file runs the panel. No compose file is a
/// host install, which runs none. A file that cannot be read is an error and
/// never a "no": a panel left with the old key is refused by the API.
fn runs_panel(compose: &Path) -> Result<bool, String> {
	let Some(bytes) = crate::cli::init::compose_read::read(compose)? else {
		return Ok(false);
	};
	let document: serde_json::Value = serde_json::from_slice(&bytes).map_err(|error| {
		format!(
			"{} is not the JSON epistle init writes ({error}); it says whether the panel \
			 container has to be made again",
			compose.display()
		)
	})?;
	Ok(document["services"].get(SERVICE).is_some())
}
