//! Edits to the keys of one named table, and removal of a whole table.
//!
//! Provider-style sections (`[dns]`, `[webhook]`, `[storage.blobs]`) are
//! rewritten as a group: every key is either set or cleared, so switching from
//! one provider to another cannot leave a stale credential behind.

use toml_edit::Value;

use super::{
	ConfigDocument,
	comments::remove,
	edits::table_at,
	rules::{FieldChange, apply},
};

impl ConfigDocument {
	/// Set or clear each field of the table at `path`, creating the table when
	/// it is absent. Existing keys keep their position and comments; cleared
	/// keys leave their comments behind.
	pub fn set_table_fields(
		&mut self,
		path: &[&str],
		fields: &[FieldChange],
	) -> Result<(), String> {
		let table = table_at(self.document.as_table_mut(), path, true)?.ok_or("missing table")?;
		let comments = apply(table, fields)?;
		self.keep_comments(&comments);
		Ok(())
	}

	/// Remove the table at `path` and keep its comments. Returns whether a
	/// table was present.
	pub fn remove_table(&mut self, path: &[&str]) -> Result<bool, String> {
		let Some((last, parent)) = path.split_last() else {
			return Err("missing table path".into());
		};
		let Some(table) = table_at(self.document.as_table_mut(), parent, false)? else {
			return Ok(false);
		};
		if table.get(last).is_none() {
			return Ok(false);
		}
		let comments = remove(table, last);
		self.keep_comments(&comments);
		Ok(true)
	}

	/// Set or clear a single field on the entry of `array_path` whose
	/// `name` field equals `name`. Used by the per-tenant CLI so the
	/// operator can edit one tenant without rewriting the whole array.
	/// Returns whether an entry was found and edited. Handles both
	/// `Item::Value(Value::Array(...))` (an inline array of tables) and
	/// `Item::ArrayOfTables` (a `[[name]]` block of tables); both
	/// produce the table-by-table list this helper walks.
	pub fn edit_array_entry_field(
		&mut self,
		array_path: &[&str],
		name: &str,
		name_field: &str,
		field: &str,
		value: Option<Value>,
	) -> Result<bool, String> {
		let Some(array_item) = self
			.document
			.get_mut(array_path.first().copied().unwrap_or(""))
		else {
			return Ok(false);
		};
		let mut current = array_item;
		for segment in array_path.iter().skip(1) {
			let Some(next_item) = current.get_mut(segment) else {
				return Ok(false);
			};
			current = next_item;
		}
		let mut edited = false;
		match current {
			toml_edit::Item::ArrayOfTables(array) => {
				for table in array.iter_mut() {
					let entry_name = entry_name_of(table, name_field);
					if entry_name != name {
						continue;
					}
					apply_field(table, field, value.as_ref());
					edited = true;
				}
			}
			toml_edit::Item::Value(value) => {
				let cloned_value = value.clone();
				let Some(array) = value.as_array_mut() else {
					return Ok(false);
				};
				for value_ref in array.iter_mut() {
					let Some(table) = value_ref.as_inline_table_mut() else {
						continue;
					};
					let entry_name = entry_name_of_inline(name_field, table);
					if entry_name != name {
						continue;
					}
					apply_field_inline(table, field, Some(&cloned_value));
					edited = true;
				}
			}
			_ => {}
		}
		Ok(edited)
	}
}

fn apply_field(table: &mut toml_edit::Table, field: &str, value: Option<&Value>) {
	match value {
		Some(value) => {
			table.insert(field, toml_edit::Item::Value(value.clone()));
		}
		None => {
			table.remove(field);
		}
	}
}

fn apply_field_inline(table: &mut toml_edit::InlineTable, field: &str, value: Option<&Value>) {
	match value {
		Some(value) => {
			table.insert(field, value.clone());
		}
		None => {
			table.remove(field);
		}
	}
}

fn entry_name_of(table: &toml_edit::Table, name_field: &str) -> String {
	table
		.get(name_field)
		.and_then(toml_edit::Item::as_value)
		.and_then(Value::as_str)
		.unwrap_or("")
		.to_string()
}

fn entry_name_of_inline(name_field: &str, table: &toml_edit::InlineTable) -> String {
	table
		.get(name_field)
		.and_then(Value::as_str)
		.unwrap_or("")
		.to_string()
}
