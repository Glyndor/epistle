//! Edits to the keys of one named table, and removal of a whole table.
//!
//! Provider-style sections (`[dns]`, `[webhook]`, `[storage.blobs]`) are
//! rewritten as a group: every key is either set or cleared, so switching from
//! one provider to another cannot leave a stale credential behind.

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
}
