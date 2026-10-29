//! A reader for Mox's `sconf` configuration format.
//!
//! sconf is indentation-structured: one tab per level, `Key: value` for a
//! value, `Key:` for a nested block, `- value` or a lone `-` for list items,
//! and `#` at the start of a line for a comment. Values are raw text with no
//! quoting. (Format as documented for Mox v0.0.17, `config/doc.go`.)
//!
//! The file is read into a flat map from paths to values, built with an
//! explicit stack of open blocks, so nesting never recurses and each line is
//! handled once. Sizes are capped because the file decides how much memory
//! the reader spends.

use std::collections::BTreeMap;

/// The largest file read.
pub(crate) const MAX_BYTES: usize = 16 * 1024 * 1024;
/// The deepest nesting accepted; Mox's own files go eight levels deep.
pub(crate) const MAX_DEPTH: usize = 32;

/// One step of a path: a map key or a list index.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) enum Seg {
	/// A map key.
	Key(String),
	/// A list position.
	Index(usize),
}

/// A parsed file: every value by its path. Blocks with no value of their
/// own appear as paths with an empty value, so an empty block still exists.
#[derive(Debug, Default)]
pub(crate) struct Doc {
	values: BTreeMap<Vec<Seg>, String>,
}

/// Why a file could not be read.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum SconfError {
	/// Over [`MAX_BYTES`].
	#[error("the file is larger than {MAX_BYTES} bytes")]
	TooLarge,
	/// A line indented with spaces, or deeper than its parent allows.
	#[error("line {0}: bad indentation (sconf indents with one tab per level)")]
	Indentation(usize),
	/// Over [`MAX_DEPTH`].
	#[error("line {0}: nested too deeply")]
	TooDeep(usize),
	/// A line that is neither `Key: value`, `Key:` nor a list item.
	#[error("line {0}: expected \"Key: value\", \"Key:\" or a list item")]
	Syntax(usize),
}

/// A block whose children are being read.
struct Open {
	/// The indentation (tabs) of its children.
	indent: usize,
	path: Vec<Seg>,
	next_index: usize,
}

impl Doc {
	/// Parse `text`.
	pub(crate) fn parse(text: &str) -> Result<Self, SconfError> {
		if text.len() > MAX_BYTES {
			return Err(SconfError::TooLarge);
		}
		let mut doc = Doc::default();
		let mut stack = vec![Open {
			indent: 0,
			path: Vec::new(),
			next_index: 0,
		}];
		for (number, line) in text.lines().enumerate() {
			let number = number + 1;
			let content = line.trim_start_matches('\t');
			let indent = line.len() - content.len();
			if content.trim().is_empty() || content.starts_with('#') {
				continue;
			}
			if content.starts_with(' ') {
				return Err(SconfError::Indentation(number));
			}
			// Close every block whose children sit deeper than this line.
			while stack.last().is_some_and(|open| open.indent > indent) {
				stack.pop();
			}
			let parent = stack.last_mut().ok_or(SconfError::Indentation(number))?;
			if parent.indent != indent {
				return Err(SconfError::Indentation(number));
			}
			let mut path = parent.path.clone();
			let value = if let Some(item) = content.strip_prefix('-') {
				path.push(Seg::Index(parent.next_index));
				parent.next_index += 1;
				item.trim_start().to_string()
			} else if let Some((key, value)) = content.split_once(": ") {
				path.push(Seg::Key(key.to_string()));
				value.to_string()
			} else if let Some(key) = content.strip_suffix(':') {
				path.push(Seg::Key(key.to_string()));
				String::new()
			} else {
				return Err(SconfError::Syntax(number));
			};
			if path.len() > MAX_DEPTH {
				return Err(SconfError::TooDeep(number));
			}
			if value.is_empty() {
				stack.push(Open {
					indent: indent + 1,
					path: path.clone(),
					next_index: 0,
				});
			}
			doc.values.insert(path, value);
		}
		Ok(doc)
	}

	/// The value at `path`.
	pub(crate) fn get(&self, path: &[Seg]) -> Option<&str> {
		self.values.get(path).map(String::as_str)
	}

	/// The keys directly under the block at `path`, in file order of their
	/// sorted form (sconf maps are unordered).
	pub(crate) fn keys(&self, path: &[Seg]) -> Vec<String> {
		let mut keys = Vec::new();
		for (child, _) in self.under(path) {
			if child.len() == path.len() + 1
				&& let Seg::Key(key) = &child[path.len()]
			{
				keys.push(key.clone());
			}
		}
		keys
	}

	/// The values of the list at `path`.
	pub(crate) fn list(&self, path: &[Seg]) -> Vec<String> {
		self.under(path)
			.filter(|(child, _)| child.len() == path.len() + 1)
			.filter(|(child, _)| matches!(child[path.len()], Seg::Index(_)))
			.map(|(_, value)| value.clone())
			.collect()
	}

	fn under<'a>(&'a self, path: &'a [Seg]) -> impl Iterator<Item = (&'a Vec<Seg>, &'a String)> {
		self.values
			.range(path.to_vec()..)
			.take_while(move |(child, _)| child.starts_with(path))
			.filter(move |(child, _)| child.len() > path.len())
	}
}

/// Build a path from keys.
pub(crate) fn path(keys: &[&str]) -> Vec<Seg> {
	keys.iter()
		.map(|key| Seg::Key((*key).to_string()))
		.collect()
}

#[cfg(test)]
mod tests;
