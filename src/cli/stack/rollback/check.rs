//! Refuse a rollback that 0.14.0 could not read the configuration of.
//!
//! 0.14.0 reads a listener of an unknown kind and an unknown key of `[api]` as
//! an error, and stops. Taking them out of `mail.toml` would not make it a
//! configuration with the same meaning: 0.14.0 serves JMAP, SCIM and the OAuth
//! grants on the `api` listener whatever the file says, so a surface that was
//! turned off or given a listener of its own would come back on the management
//! port. `stack rollback` therefore stops before it changes anything, names what
//! it found, and leaves the choice to the operator, who removes it knowing that.

use toml_edit::{DocumentMut, Item, Value};

/// The listener kinds added after 0.14.0.
const ADDED_KINDS: [&str; 3] = ["jmap", "scim", "oauth"];

/// The first release that reads these options.
const SINCE: [u64; 3] = [0, 15, 0];

/// The listener kind, when it is one added after 0.14.0.
fn added_kind(kind: Option<&str>) -> Option<&str> {
	kind.filter(|kind| ADDED_KINDS.contains(kind))
}

/// What of `text` a release older than 0.15.0 cannot read: the listeners of the
/// new kinds and `[api] surfaces`, each named once.
fn unknown_to_v014(text: &str) -> Result<Vec<String>, String> {
	let document: DocumentMut = text
		.parse()
		.map_err(|_| "cannot parse configuration TOML".to_string())?;
	let mut found: Vec<String> = Vec::new();
	let mut note = |what: String| {
		if !found.contains(&what) {
			found.push(what);
		}
	};
	if let Some(item) = document.get("listeners") {
		if let Some(tables) = item.as_array_of_tables() {
			for table in tables.iter() {
				if let Some(kind) = added_kind(table.get("kind").and_then(Item::as_str)) {
					note(format!("a `{kind}` listener"));
				}
			}
		} else if let Some(array) = item.as_array() {
			for value in array.iter() {
				let kind = value
					.as_inline_table()
					.and_then(|table| table.get("kind"))
					.and_then(Value::as_str);
				if let Some(kind) = added_kind(kind) {
					note(format!("a `{kind}` listener"));
				}
			}
		}
	}
	if document
		.get("api")
		.and_then(Item::as_table_like)
		.is_some_and(|api| api.contains_key("surfaces"))
	{
		note("`[api] surfaces`".to_string());
	}
	Ok(found)
}

/// `Ok` when 0.14.0 can read `text`, and otherwise an error that names what it
/// cannot and says why nothing is removed for the operator.
pub(in crate::cli) fn check_for_v014(text: &str) -> Result<(), String> {
	let found = unknown_to_v014(text)?;
	if found.is_empty() {
		return Ok(());
	}
	Err(format!(
		"mail.toml has {}, which releases before 0.15.0 cannot read. They are not removed for \
		 you: 0.14.0 serves JMAP, SCIM and the OAuth grants on the api listener whatever the \
		 file says, so a surface that is off or has a listener of its own would be on the \
		 management port again. Remove them yourself if you accept that, and run the rollback \
		 again; nothing was changed",
		found.join(", ")
	))
}

/// Whether rolling back to `version` needs [`check_for_v014`]: it is older than
/// 0.15.0, or a version this cannot read, which is treated as older.
fn predates_surfaces(version: &str) -> bool {
	super::numbers(version).is_none_or(|numbers| numbers.as_slice() < SINCE.as_slice())
}

/// The check `stack rollback` runs before it touches anything: `Ok` for a
/// target that reads the options, or a configuration that has none.
pub(in crate::cli) fn refuse_unreadable_config(version: &str, text: &str) -> Result<(), String> {
	if predates_surfaces(version) {
		check_for_v014(text)
	} else {
		Ok(())
	}
}
