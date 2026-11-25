use crate::api::{Surface, Surfaces};
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
	let present = current
		.listeners
		.iter()
		.any(|listener| listener.kind == kind);
	// A surface with no listener of its own can still be on: the `api` listener
	// serves it. Turning it off is then a change, though there is no listener to
	// remove.
	let served_by_api = !enabled
		&& current
			.listeners
			.iter()
			.any(|listener| listener.kind == ListenerKind::Api)
		&& Surface::of_listener(kind).is_some_and(|surface| {
			Surfaces::for_listener(&current, ListenerKind::Api).contains(surface)
		});
	if present == enabled && !served_by_api {
		return Ok((document, current));
	}
	if enabled {
		if kind.serves_api() && current.api.is_none() {
			document.set_table_fields(&["api"], &[])?;
		}
		if let Some(surface) = Surface::of_listener(kind) {
			unlist_surface(&mut document, &current, surface)?;
		}
		let addr = super::default_bind(&current, kind).to_string();
		document.upsert_element("listeners", "kind", kind.as_str(), &[("addr", addr.into())])?;
	} else {
		document.remove_elements("listeners", "kind", kind.as_str())?;
		if let Some(surface) = Surface::of_listener(kind) {
			keep_surfaces_but(&mut document, &current, surface)?;
		}
	}
	Ok((document, current))
}

/// A surface that gets a listener of its own leaves `[api] surfaces`: it is
/// served in one place, and the configuration refuses it in two.
fn unlist_surface(
	document: &mut ConfigDocument,
	current: &Config,
	surface: Surface,
) -> Result<(), String> {
	let Some(listed) = current.api.as_ref().and_then(|api| api.surfaces.as_ref()) else {
		return Ok(());
	};
	if !listed.iter().any(|name| name == surface.name()) {
		return Ok(());
	}
	let rest: Vec<&str> = listed
		.iter()
		.map(String::as_str)
		.filter(|name| *name != surface.name())
		.collect();
	set_surfaces(document, &rest)
}

/// A surface whose listener goes is off, not handed back to the `api`
/// listener, which would serve it again with `surfaces` absent. So the others
/// the `api` listener serves are written down and this one is left out.
fn keep_surfaces_but(
	document: &mut ConfigDocument,
	current: &Config,
	surface: Surface,
) -> Result<(), String> {
	let served = Surfaces::for_listener(current, ListenerKind::Api);
	let keep: Vec<&str> = served
		.iter()
		.filter(|other| *other != Surface::Manage && *other != surface)
		.map(Surface::name)
		.collect();
	set_surfaces(document, &keep)
}

fn set_surfaces(document: &mut ConfigDocument, names: &[&str]) -> Result<(), String> {
	let array: toml_edit::Array = names.iter().copied().collect();
	document.set_table_key(&["api"], "surfaces", array)
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
