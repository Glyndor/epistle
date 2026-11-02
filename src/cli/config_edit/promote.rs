//! Turning a single table into the first element of an array of tables.
//!
//! `[dns]` is one table until the second provider arrives, when it has to
//! become `[[dns]]`. The table keeps its keys, order and comments.

use toml_edit::{ArrayOfTables, Item};

use super::ConfigDocument;

impl ConfigDocument {
	/// Whether `name` is a single table, as opposed to absent or an array.
	pub fn is_table(&self, name: &str) -> bool {
		self.document.get(name).is_some_and(Item::is_table)
	}

	/// Make the table `name` the only element of an array of tables with the
	/// same name. Does nothing when `name` is absent or already an array.
	pub fn promote_table_to_array(&mut self, name: &str) -> Result<(), String> {
		let Some(item) = self.document.as_table_mut().get_mut(name) else {
			return Ok(());
		};
		let Item::Table(table) = item else {
			return Ok(());
		};
		let first = std::mem::take(table);
		let mut array = ArrayOfTables::new();
		array.push(first);
		*item = Item::ArrayOfTables(array);
		Ok(())
	}
}
