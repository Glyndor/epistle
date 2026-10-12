//! Read-only lookups on the raw document, for edits that must address an
//! element by the value written in the file rather than by the normalized
//! value the loaded configuration carries.

use toml_edit::{Item, Value};

use super::ConfigDocument;

impl ConfigDocument {
	/// The string value of `key` on the first `[[array]]` element whose value
	/// `matches` accepts, exactly as the file spells it.
	pub fn element_value(
		&self,
		array: &str,
		key: &str,
		matches: impl Fn(&str) -> bool,
	) -> Option<String> {
		let item = self.document.get(array)?;
		if let Some(tables) = item.as_array_of_tables() {
			return tables
				.iter()
				.filter_map(|table| table.get(key).and_then(Item::as_str))
				.find(|value| matches(value))
				.map(str::to_string);
		}
		item.as_array()?
			.iter()
			.filter_map(|value| value.as_inline_table()?.get(key).and_then(Value::as_str))
			.find(|value| matches(value))
			.map(str::to_string)
	}

	/// The key of the first `[map]` entry `matches` accepts, exactly as the
	/// file spells it.
	pub fn map_key(&self, map: &str, matches: impl Fn(&str) -> bool) -> Option<String> {
		self.document
			.get(map)?
			.as_table_like()?
			.iter()
			.map(|(key, _)| key)
			.find(|key| matches(key))
			.map(str::to_string)
	}
}
