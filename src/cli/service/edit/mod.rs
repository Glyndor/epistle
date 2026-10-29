use crate::cli::config_edit::ConfigDocument;
use crate::config::{Config, ListenerKind};
use std::path::Path;

/// The document to commit, and the state it read before the edit. The caller
/// holds the common lock and needs that state to say whether the generated
/// file and `mail.toml` disagree, so it comes from the one verified read of
/// the file rather than from a second one that could wait.
pub(super) fn listener_document(
	path: &Path,
	kind: ListenerKind,
	enabled: bool,
) -> Result<(ConfigDocument, Config), String> {
	if kind == ListenerKind::Smtp && !enabled {
		return Err("smtp cannot be disabled: inbound mail needs it".into());
	}
	let mut document = ConfigDocument::open(path)?;
	let current = document.config()?;
	if current
		.listeners
		.iter()
		.any(|listener| listener.kind == kind)
		== enabled
	{
		return Ok((document, current));
	}
	if enabled {
		let addr = super::default_bind(&current, kind).to_string();
		document.upsert_element("listeners", "kind", kind.as_str(), &[("addr", addr.into())])?;
	} else {
		document.remove_elements("listeners", "kind", kind.as_str())?;
	}
	Ok((document, current))
}

#[cfg(test)]
fn set_listener_enabled(path: &Path, kind: ListenerKind, enabled: bool) -> Result<bool, String> {
	listener_document(path, kind, enabled)
		.map(|(document, _)| document)
		.and_then(ConfigDocument::commit)
		.map(|outcome| outcome == crate::cli::config_edit::Outcome::Changed)
		.map_err(|error| format!("the candidate config is invalid: {error}"))
}

#[cfg(test)]
mod tests;
