use toml_edit::{Array, Item, Table, TableLike, Value};

use super::ConfigDocument;
use super::comments::{decor_comments, remove};

impl ConfigDocument {
	/// Set a top-level value, keeping its existing key and value decoration.
	pub fn set_scalar(&mut self, key: &str, value: impl Into<Value>) -> Result<(), String> {
		set(self.document.as_table_mut(), key, value.into())
	}

	/// Remove a top-level value and retain any attached comments.
	pub fn remove_scalar(&mut self, key: &str) {
		let comments = remove(self.document.as_table_mut(), key);
		self.keep_comments(&comments);
	}

	/// Set a table key, creating missing tables along the supplied path.
	pub fn set_table_key(
		&mut self,
		path: &[&str],
		key: &str,
		value: impl Into<Value>,
	) -> Result<(), String> {
		let table = table_at(self.document.as_table_mut(), path, true)?.ok_or("missing table")?;
		set(table, key, value.into())
	}

	/// Remove a table key without creating an absent table.
	pub fn remove_table_key(&mut self, path: &[&str], key: &str) -> Result<(), String> {
		if let Some(table) = table_at(self.document.as_table_mut(), path, false)? {
			let comments = remove(table, key);
			self.keep_comments(&comments);
		}
		Ok(())
	}

	/// Set a literal map key, including domains containing dots.
	pub fn set_map_entry(
		&mut self,
		map: &str,
		key: &str,
		value: impl Into<Value>,
	) -> Result<(), String> {
		self.set_table_key(&[map], key, value)
	}

	/// Remove a literal map key without changing other entries.
	pub fn remove_map_entry(&mut self, map: &str, key: &str) -> Result<(), String> {
		self.remove_table_key(&[map], key)
	}

	/// Replace a top-level array wholesale, preserving the existing
	/// key's decoration when the key is already present.
	pub fn replace_top_array(&mut self, key: &str, values: toml_edit::Array) -> Result<(), String> {
		let mut value = toml_edit::Value::Array(values);
		if let Some(existing) = self.document.get_mut(key) {
			if !existing.is_array() {
				return Err(format!("{key} is not a top-level array"));
			}
			let old = existing
				.as_value()
				.ok_or("expected a top-level array value")?;
			*value.decor_mut() = old.decor().clone();
			*existing = toml_edit::Item::Value(value);
		} else {
			self.document.insert(key, toml_edit::Item::Value(value));
		}
		Ok(())
	}

	/// Add a string if it is absent from a top-level string array.
	pub fn add_string(&mut self, key: &str, value: &str) -> Result<(), String> {
		let item = self
			.document
			.as_table_mut()
			.entry(key)
			.or_insert(Item::Value(Value::Array(Array::new())));
		let array = string_array(item)?;
		if !array.iter().any(|entry| entry.as_str() == Some(value)) {
			let mut added = Value::from(value);
			if let Some(last) = array.iter_mut().last() {
				let suffix = last
					.decor()
					.suffix()
					.and_then(|raw| raw.as_str())
					.unwrap_or("")
					.to_string();
				if suffix.chars().all(char::is_whitespace) {
					last.decor_mut().set_suffix("");
					added.decor_mut().set_suffix(suffix);
				}
				added.decor_mut().set_prefix(" ");
			}
			array.push_formatted(added);
		}
		Ok(())
	}

	/// Remove every matching string, retaining array comments and layout.
	pub fn remove_string(&mut self, key: &str, value: &str) -> Result<(), String> {
		let Some(item) = self.document.get_mut(key) else {
			return Ok(());
		};
		let array = string_array(item)?;
		for index in (0..array.len()).rev() {
			if array.get(index).and_then(Value::as_str) != Some(value) {
				continue;
			}
			let removed = array.remove(index);
			let mut comments = decor_comments(removed.decor());
			if comments.is_empty() {
				continue;
			}
			if let Some(next) = array.get_mut(index) {
				comments.push_str(next.decor().prefix().and_then(|r| r.as_str()).unwrap_or(""));
				next.decor_mut().set_prefix(comments);
			} else {
				comments.push_str(array.trailing().as_str().unwrap_or(""));
				array.set_trailing(comments);
			}
		}
		Ok(())
	}

	pub(super) fn keep_comments(&mut self, comments: &str) {
		if !comments.is_empty() {
			// Orphaned comments remain visible even when their last key disappears.
			self.document.set_trailing(format!(
				"{}{}",
				self.document.trailing().as_str().unwrap_or(""),
				comments
			));
		}
	}
}

pub(super) fn set(table: &mut dyn TableLike, key: &str, mut value: Value) -> Result<(), String> {
	if let Some(item) = table.get_mut(key) {
		let old = item.as_value().ok_or("expected a scalar or inline value")?;
		if same_value(old, &value) {
			return Ok(());
		}
		*value.decor_mut() = old.decor().clone();
		*item = Item::Value(value);
	} else {
		table.insert(key, Item::Value(value));
	}
	Ok(())
}

pub(super) fn table_at<'a>(
	table: &'a mut dyn TableLike,
	path: &[&str],
	create: bool,
) -> Result<Option<&'a mut dyn TableLike>, String> {
	let Some((key, rest)) = path.split_first() else {
		return Ok(Some(table));
	};
	if table.get(key).is_none() {
		if !create {
			return Ok(None);
		}
		table.insert(key, Item::Table(Table::new()));
	}
	let next = table
		.get_mut(key)
		.and_then(Item::as_table_like_mut)
		.ok_or("expected a table")?;
	table_at(next, rest, create)
}

fn string_array(item: &mut Item) -> Result<&mut Array, String> {
	let array = item.as_array_mut().ok_or("expected a string array")?;
	if array.iter().any(|entry| entry.as_str().is_none()) {
		return Err("expected a string array".into());
	}
	Ok(array)
}

fn same_value(a: &Value, b: &Value) -> bool {
	match (a, b) {
		(Value::String(a), Value::String(b)) => a.value() == b.value(),
		(Value::Integer(a), Value::Integer(b)) => a.value() == b.value(),
		(Value::Float(a), Value::Float(b)) => a.value() == b.value(),
		(Value::Boolean(a), Value::Boolean(b)) => a.value() == b.value(),
		(Value::Datetime(a), Value::Datetime(b)) => a.value() == b.value(),
		(Value::Array(a), Value::Array(b)) => {
			a.len() == b.len() && a.iter().zip(b.iter()).all(|(a, b)| same_value(a, b))
		}
		(Value::InlineTable(a), Value::InlineTable(b)) => {
			a.len() == b.len()
				&& a.iter()
					.all(|(key, value)| b.get(key).is_some_and(|other| same_value(value, other)))
		}
		_ => false,
	}
}
