//! The container images a verified `stack update` leaves unused.
//!
//! A release can move the image a service runs: a new PostgreSQL or ClamAV
//! digest, or, for a stack created before the default `mail` image became the
//! distroless base, the version-tagged epistle image. `podup up -d` starts the
//! new one and the old one stays in the account's storage, tens or hundreds
//! of megabytes each, until somebody removes it by hand.
//!
//! What goes is decided from the references, not from the storage. The
//! candidates are the images the compose file named before the update and
//! does not name after it ([`Change::retired`]). Each one is resolved to the
//! image it is in this account's storage and removed only when no container
//! of any kind uses that image and the new compose file does not name it
//! under another reference. Anything else in the storage, a tag another
//! project put on the same image included, is not looked at.

use std::collections::BTreeSet;

use serde_json::Value;

mod podman;
pub(super) use podman::Podman;

/// Which references an update stopped naming.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(in crate::cli::stack) struct Change {
	/// Named by the compose file before the update and not after it.
	pub(in crate::cli::stack) retired: Vec<String>,
	/// Named by the compose file after the update.
	pub(in crate::cli::stack) current: Vec<String>,
}

/// What discarding the retired images did, one line per image.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(in crate::cli::stack) struct Outcome {
	/// The references whose image was removed.
	pub(in crate::cli::stack) removed: Vec<String>,
	/// The references whose image stayed, with the reason.
	pub(in crate::cli::stack) kept: Vec<String>,
}

/// What the container engine of the service account answers.
pub(in crate::cli::stack) trait Engine {
	/// The full id of the image `reference` names, `None` when the storage
	/// has no such image.
	fn image_id(&mut self, reference: &str) -> Result<Option<String>, String>;
	/// The ids of the images every container in the storage was created
	/// from, stopped and foreign ones included.
	fn used_image_ids(&mut self) -> Result<BTreeSet<String>, String>;
	/// Remove the image with `id` without forcing: an engine that still
	/// finds a container or another name on it refuses.
	fn remove(&mut self, id: &str) -> Result<(), String>;
}

/// The image of every service in a compose document.
pub(in crate::cli::stack) fn references(compose: &Value) -> BTreeSet<String> {
	compose["services"]
		.as_object()
		.into_iter()
		.flatten()
		.filter_map(|(_, service)| service["image"].as_str())
		.filter(|image| usable(image))
		.map(str::to_string)
		.collect()
}

/// A reference that can be handed to the engine as one argument: no
/// whitespace, and not an option.
fn usable(reference: &str) -> bool {
	!reference.is_empty()
		&& !reference.starts_with('-')
		&& !reference
			.chars()
			.any(|c| c.is_whitespace() || c.is_control())
}

/// The references `old` named and `new` does not.
pub(in crate::cli::stack) fn change(old: &Value, new: &Value) -> Change {
	let current = references(new);
	Change {
		retired: references(old).difference(&current).cloned().collect(),
		current: current.into_iter().collect(),
	}
}

/// Remove the retired images nothing uses. `Err` when the engine cannot say
/// what is in use or what the new compose file runs: nothing is removed
/// then, since an image cannot be proved unused.
pub(in crate::cli::stack) fn discard(
	engine: &mut impl Engine,
	change: &Change,
) -> Result<Outcome, String> {
	let mut outcome = Outcome::default();
	if change.retired.is_empty() {
		return Ok(outcome);
	}
	let used = engine.used_image_ids()?;
	let mut current = BTreeSet::new();
	for reference in &change.current {
		current.extend(engine.image_id(reference)?);
	}
	for reference in &change.retired {
		let Some(id) = engine.image_id(reference)? else {
			continue;
		};
		if current.contains(&id) {
			outcome
				.kept
				.push(format!("{reference}: the new compose file runs this image"));
		} else if used.contains(&id) {
			outcome
				.kept
				.push(format!("{reference}: a container still uses it"));
		} else {
			match engine.remove(&id) {
				Ok(()) => outcome.removed.push(reference.clone()),
				Err(error) => outcome.kept.push(format!("{reference}: {error}")),
			}
		}
	}
	Ok(outcome)
}

#[cfg(test)]
mod tests;
