//! Retain comments orphaned by removing configuration entries.
use toml_edit::{Decor, Item, Table, TableLike, Value};

pub(super) fn remove(table: &mut dyn TableLike, key: &str) -> String {
	let mut comments = table
		.key(key)
		.map(|k| decor_comments(k.leaf_decor()))
		.unwrap_or_default();
	let Some(item) = table.remove(key) else {
		return String::new();
	};
	comments.push_str(&item_comments(&item));
	comments
}

pub(super) fn table_comments(table: &Table) -> String {
	let mut comments = decor_comments(table.decor());
	for (key, item) in table.iter() {
		if let Some(key) = table.key(key) {
			comments.push_str(&decor_comments(key.leaf_decor()));
		}
		comments.push_str(&item_comments(item));
	}
	comments
}

fn item_comments(item: &Item) -> String {
	match item {
		Item::Value(value) => value_comments(value),
		Item::Table(table) => table_comments(table),
		Item::ArrayOfTables(tables) => tables.iter().map(table_comments).collect(),
		Item::None => String::new(),
	}
}

pub(super) fn value_comments(value: &Value) -> String {
	let mut comments = decor_comments(value.decor());
	match value {
		Value::Array(array) => {
			for value in array.iter() {
				comments.push_str(&value_comments(value));
			}
			comments.push_str(&raw_comments(array.trailing().as_str().unwrap_or("")));
		}
		Value::InlineTable(table) => {
			for (key, value) in table.iter() {
				if let Some(key) = table.key(key) {
					comments.push_str(&decor_comments(key.leaf_decor()));
				}
				comments.push_str(&value_comments(value));
			}
			comments.push_str(&raw_comments(table.trailing().as_str().unwrap_or("")));
		}
		_ => {}
	}
	comments
}

pub(super) fn decor_comments(decor: &Decor) -> String {
	[decor.prefix(), decor.suffix()]
		.into_iter()
		.flatten()
		.filter_map(|raw| raw.as_str())
		.map(raw_comments)
		.collect()
}

fn raw_comments(raw: &str) -> String {
	raw.lines()
		.filter_map(|line| line.find('#').map(|index| format!("{}\n", &line[index..])))
		.collect()
}
