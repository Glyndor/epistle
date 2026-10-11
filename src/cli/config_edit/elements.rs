use super::{
	ConfigDocument,
	comments::{table_comments, value_comments},
	edits::set,
};
use toml_edit::{ArrayOfTables, InlineTable, Item, Table, Value};

impl ConfigDocument {
	/// Insert or update fields on the uniquely matched array-of-tables element.
	/// Multiple matches are rejected so an update cannot silently edit one relay.
	pub fn upsert_element(
		&mut self,
		array: &str,
		match_key: &str,
		match_value: &str,
		fields: &[(&str, Value)],
	) -> Result<(), String> {
		if fields
			.iter()
			.any(|(key, value)| *key == match_key && value.as_str() != Some(match_value))
		{
			return Err("updated fields cannot change the matching key".into());
		}
		let item = self
			.document
			.as_table_mut()
			.entry(array)
			.or_insert(Item::ArrayOfTables(ArrayOfTables::new()));
		if let Some(array) = item.as_array_mut() {
			if array.iter().any(|value| value.as_inline_table().is_none()) {
				return Err("expected an array of tables".into());
			}
			let matches: Vec<_> = array
				.iter()
				.enumerate()
				.filter(|(_, value)| {
					value
						.as_inline_table()
						.and_then(|table| table.get(match_key))
						.and_then(Value::as_str)
						== Some(match_value)
				})
				.map(|(index, _)| index)
				.collect();
			let index = match matches.as_slice() {
				[index] => *index,
				[] => {
					let mut table = InlineTable::new();
					table.insert(match_key, Value::from(match_value));
					array.push(Value::InlineTable(table));
					array.len() - 1
				}
				_ => return Err("multiple array elements match the key".into()),
			};
			let table = array
				.get_mut(index)
				.and_then(Value::as_inline_table_mut)
				.ok_or("missing array element")?;
			for (key, value) in fields {
				set(table, key, value.clone())?;
			}
			return Ok(());
		}

		let tables = item
			.as_array_of_tables_mut()
			.ok_or("expected an array of tables")?;
		let matches: Vec<_> = tables
			.iter()
			.enumerate()
			.filter(|(_, table)| table.get(match_key).and_then(Item::as_str) == Some(match_value))
			.map(|(index, _)| index)
			.collect();
		let index = match matches.as_slice() {
			[index] => *index,
			[] => {
				let mut table = Table::new();
				table.insert(match_key, toml_edit::value(match_value));
				tables.push(table);
				tables.len() - 1
			}
			_ => return Err("multiple array elements match the key".into()),
		};
		let table = tables.get_mut(index).ok_or("missing array element")?;
		for (key, value) in fields {
			set(table, key, value.clone())?;
		}
		Ok(())
	}

	/// Remove every array-of-tables element with the matching key value.
	pub fn remove_elements(
		&mut self,
		array: &str,
		match_key: &str,
		match_value: &str,
	) -> Result<(), String> {
		let Some(item) = self.document.get_mut(array) else {
			return Ok(());
		};
		if let Some(array) = item.as_array_mut() {
			if array.iter().any(|value| value.as_inline_table().is_none()) {
				return Err("expected an array of tables".into());
			}
			let mut comments = String::new();
			let indices: Vec<_> = array
				.iter()
				.enumerate()
				.filter(|(_, value)| {
					value
						.as_inline_table()
						.and_then(|table| table.get(match_key))
						.and_then(Value::as_str)
						== Some(match_value)
				})
				.map(|(index, value)| {
					comments.push_str(&value_comments(value));
					index
				})
				.collect();
			for index in indices.into_iter().rev() {
				array.remove(index);
			}
			self.keep_comments(&comments);
			return Ok(());
		}

		let tables = item
			.as_array_of_tables_mut()
			.ok_or("expected an array of tables")?;
		let mut comments = String::new();
		let indices: Vec<_> = tables
			.iter()
			.enumerate()
			.filter(|(_, table)| table.get(match_key).and_then(Item::as_str) == Some(match_value))
			.map(|(index, table)| {
				comments.push_str(&table_comments(table));
				index
			})
			.collect();
		for index in indices.into_iter().rev() {
			tables.remove(index);
		}
		self.keep_comments(&comments);
		Ok(())
	}
}
