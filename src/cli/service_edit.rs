use super::config_edit::ConfigDocument;
use crate::config::ListenerKind;
use std::path::Path;

pub(super) fn listener_document(
	path: &Path,
	kind: ListenerKind,
	enabled: bool,
) -> Result<ConfigDocument, String> {
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
		return Ok(document);
	}
	if enabled {
		let addr = super::service::default_bind(&current, kind).to_string();
		document.upsert_element("listeners", "kind", kind.as_str(), &[("addr", addr.into())])?;
	} else {
		document.remove_elements("listeners", "kind", kind.as_str())?;
	}
	Ok(document)
}

#[cfg(test)]
fn set_listener_enabled(path: &Path, kind: ListenerKind, enabled: bool) -> Result<bool, String> {
	listener_document(path, kind, enabled)
		.and_then(ConfigDocument::commit)
		.map(|outcome| outcome == super::config_edit::Outcome::Changed)
		.map_err(|error| format!("the candidate config is invalid: {error}"))
}

#[cfg(test)]
#[path = "service_tests_edit.rs"]
mod tests;
