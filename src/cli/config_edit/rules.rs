//! Edits to array elements that are selected by a predicate instead of one key.
//!
//! Outbound transport rules are identified by which of `account` and `domain`
//! are present, and the catch-all rule has neither, so a single matching key
//! cannot address them.

use toml_edit::{ArrayOfTables, InlineTable, Item, Table, TableLike, Value};

use super::{
	ConfigDocument,
	comments::{remove, table_comments, value_comments},
	edits::set,
};

/// Decides whether an array element is the one an edit targets.
pub type Matcher<'a> = &'a dyn Fn(&dyn TableLike) -> bool;

/// Set a field to a value, or clear it when the value is `None`.
pub type FieldChange<'a> = (&'a str, Option<Value>);

fn apply(table: &mut dyn TableLike, fields: &[FieldChange]) -> Result<String, String> {
	let mut comments = String::new();
	for (key, value) in fields {
		match value {
			Some(value) => set(table, key, value.clone())?,
			None => comments.push_str(&remove(table, key)),
		}
	}
	Ok(comments)
}

fn only(indices: Vec<usize>) -> Result<Option<usize>, String> {
	match indices.as_slice() {
		[] => Ok(None),
		[index] => Ok(Some(*index)),
		_ => Err("multiple array elements match the selector".into()),
	}
}

impl ConfigDocument {
	/// Update the single element accepted by `matches`, or append a new one.
	/// The fields are applied in order, so a new element keeps that key order.
	/// More than one match is rejected so a change never edits an arbitrary rule.
	pub fn upsert_where(
		&mut self,
		array: &str,
		matches: Matcher,
		fields: &[FieldChange],
	) -> Result<(), String> {
		let item = self
			.document
			.as_table_mut()
			.entry(array)
			.or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
		let comments = if let Some(values) = item.as_array_mut() {
			if values.iter().any(|value| value.as_inline_table().is_none()) {
				return Err("expected an array of tables".into());
			}
			let found = values
				.iter()
				.enumerate()
				.filter(|(_, value)| value.as_inline_table().is_some_and(|t| matches(t)))
				.map(|(index, _)| index)
				.collect();
			let index = match only(found)? {
				Some(index) => index,
				None => {
					values.push(Value::InlineTable(InlineTable::new()));
					values.len() - 1
				}
			};
			let table = values
				.get_mut(index)
				.and_then(Value::as_inline_table_mut)
				.ok_or("missing array element")?;
			apply(table, fields)?
		} else {
			let tables = item
				.as_array_of_tables_mut()
				.ok_or("expected an array of tables")?;
			let found = tables
				.iter()
				.enumerate()
				.filter(|(_, table)| matches(*table))
				.map(|(index, _)| index)
				.collect();
			let index = match only(found)? {
				Some(index) => index,
				None => {
					tables.push(Table::new());
					tables.len() - 1
				}
			};
			apply(
				tables.get_mut(index).ok_or("missing array element")?,
				fields,
			)?
		};
		self.keep_comments(&comments);
		Ok(())
	}

	/// Remove every element accepted by `matches`, keeping their comments.
	/// Returns how many elements were removed.
	pub fn remove_where(&mut self, array: &str, matches: Matcher) -> Result<usize, String> {
		let Some(item) = self.document.get_mut(array) else {
			return Ok(0);
		};
		let mut comments = String::new();
		let removed = if let Some(values) = item.as_array_mut() {
			if values.iter().any(|value| value.as_inline_table().is_none()) {
				return Err("expected an array of tables".into());
			}
			let found: Vec<usize> = values
				.iter()
				.enumerate()
				.filter(|(_, value)| value.as_inline_table().is_some_and(|t| matches(t)))
				.map(|(index, value)| {
					comments.push_str(&value_comments(value));
					index
				})
				.collect();
			for index in found.iter().rev() {
				values.remove(*index);
			}
			found.len()
		} else {
			let tables = item
				.as_array_of_tables_mut()
				.ok_or("expected an array of tables")?;
			let found: Vec<usize> = tables
				.iter()
				.enumerate()
				.filter(|(_, table)| matches(*table))
				.map(|(index, table)| {
					comments.push_str(&table_comments(table));
					index
				})
				.collect();
			for index in found.iter().rev() {
				tables.remove(*index);
			}
			found.len()
		};
		self.keep_comments(&comments);
		Ok(removed)
	}
}
