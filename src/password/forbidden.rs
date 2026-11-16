//! The operator's own list of forbidden passwords (`[auth]
//! forbidden_passwords_file`), checked next to the bundled one.
//!
//! The file has one password per line; blank lines and lines starting with `#`
//! are ignored, and the comparison ignores ASCII case like the bundled list.
//! It is read when the configuration is loaded, so a file that cannot be read
//! stops the server instead of quietly leaving the list empty.

use std::collections::HashSet;
use std::path::Path;
use std::sync::RwLock;

/// The most bytes the file may have; a larger one is a mistake, not a list.
pub const MAX_FILE_BYTES: u64 = 16 * 1024 * 1024;

static OPERATOR: RwLock<Option<&'static HashSet<String>>> = RwLock::new(None);

/// Read the list at `path`: a regular file of at most [`MAX_FILE_BYTES`].
pub fn load(path: &Path) -> std::io::Result<HashSet<String>> {
	use std::io::Read;
	let file = std::fs::File::open(path)?;
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(std::io::Error::other("it is not a regular file"));
	}
	if metadata.len() > MAX_FILE_BYTES {
		return Err(std::io::Error::other(format!(
			"it is larger than {MAX_FILE_BYTES} bytes"
		)));
	}
	let mut text = String::new();
	file.take(MAX_FILE_BYTES).read_to_string(&mut text)?;
	Ok(parse(&text))
}

/// The entries of a list, lowercased.
pub(super) fn parse(text: &str) -> HashSet<String> {
	text.lines()
		.map(str::trim)
		.filter(|line| !line.is_empty() && !line.starts_with('#'))
		.map(str::to_ascii_lowercase)
		.collect()
}

/// Put `list` in force, or take the operator's list out with `None`. The set
/// is kept for the life of the process, like the bundled one.
pub fn install(list: Option<HashSet<String>>) {
	*OPERATOR.write().unwrap_or_else(|p| p.into_inner()) =
		list.map(|set| &*Box::leak(Box::new(set)));
}

#[cfg(test)]
thread_local! {
	static SCOPED: std::cell::RefCell<Option<HashSet<String>>> = const { std::cell::RefCell::new(None) };
}

/// Run `body` with `list` as the operator's list on this thread only, so a
/// test of a list cannot reach the tests that run beside it.
#[cfg(test)]
pub(crate) fn scoped<R>(list: HashSet<String>, body: impl FnOnce() -> R) -> R {
	struct Restore(Option<HashSet<String>>);
	impl Drop for Restore {
		fn drop(&mut self) {
			SCOPED.with(|cell| *cell.borrow_mut() = self.0.take());
		}
	}
	let _restore = Restore(SCOPED.with(|cell| cell.replace(Some(list))));
	body()
}

/// Whether the operator's list in force holds `lowered`.
pub(super) fn contains(lowered: &str) -> bool {
	#[cfg(test)]
	if let Some(set) = SCOPED.with(|cell| cell.borrow().clone()) {
		return set.contains(lowered);
	}
	OPERATOR
		.read()
		.unwrap_or_else(|p| p.into_inner())
		.is_some_and(|set| set.contains(lowered))
}
