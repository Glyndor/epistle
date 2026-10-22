//! Shared scaffolding for the validation matrix.
//!
//! The matrix is written as assertions, so a failure has to say which cell
//! moved: every test builds one `Row` per input and renders the whole table
//! into the assertion message. That is the same few helpers in both halves, so
//! they live here rather than in either.

pub use epistle::directory_store::AccountStore;

/// One row of a boundary table: what the input is, and what every path
/// answered for it.
pub struct Row {
	pub what: &'static str,
	pub value: String,
	/// One `true` per path, in the order the test names them.
	pub accepted: Vec<bool>,
}

/// Render a matrix as `input -> path results`, so a failure says which cell
/// moved rather than only that a boolean differed.
pub fn matrix(rows: &[Row], paths: &[&str]) -> String {
	let mut out = String::new();
	for row in rows {
		out.push_str(&format!("\n  {:<34}", row.what));
		for (index, accepted) in row.accepted.iter().enumerate() {
			out.push_str(&format!(
				" {}={}",
				paths[index],
				if *accepted { "yes" } else { "NO " }
			));
		}
	}
	out
}

/// A store over a scratch directory, serving the domains the tables below
/// name. It stands for the paths that reach a rule through the account store:
/// CLI `account-add`, the management API `POST /accounts` and SCIM `POST /Users`
/// all land here.
pub fn store() -> (tempfile::TempDir, AccountStore) {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = AccountStore::open(
		dir.path(),
		vec![
			"example.org".to_string(),
			"xn--bcher-kva.example".to_string(),
			format!("{}.example", "a".repeat(63)),
			format!("{}.{}.{}", "b".repeat(63), "c".repeat(63), "d".repeat(62)),
			format!("{}.{}.{}", "b".repeat(63), "c".repeat(63), "d".repeat(63)),
		],
		std::collections::HashMap::new(),
		Vec::new(),
	)
	.expect("open account store");
	(dir, store)
}

/// Assert one cell of the table, naming the row and printing the whole matrix
/// so the reader can see which cell moved rather than one boolean.
pub fn cell(rows: &[Row], paths: &[&str], what: &str, path: usize, expected: bool) {
	let row = rows
		.iter()
		.find(|row| row.what == what)
		.expect("row in the table");
	assert_eq!(
		row.accepted[path],
		expected,
		"{:?} ({what}) through {}: observed {}, this table says the opposite{}",
		row.value,
		paths[path],
		row.accepted[path],
		matrix(rows, paths)
	);
}
/// `len` printable-ASCII characters drawn from the process, so a candidate
/// is never one of the memorable strings the breached list holds and no
/// literal credential is written in this file.
pub fn fixture_password(len: usize) -> String {
	use std::collections::hash_map::RandomState;
	use std::hash::{BuildHasher, Hasher};
	const ALPHABET: &[u8] = b"abcdefghijkmnpqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789";
	let mut out = String::with_capacity(len);
	for index in 0..len {
		let mut hasher = RandomState::new().build_hasher();
		hasher.write_usize(index);
		out.push(ALPHABET[(hasher.finish() as usize) % ALPHABET.len()] as char);
	}
	out
}
