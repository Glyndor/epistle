//! A copy of every file under a directory, to compare a directory before and
//! after a command that was meant to leave it alone.

use std::collections::BTreeMap;
use std::path::Path;

/// Every regular file under `dir` with its bytes, by path under `dir`.
pub fn snapshot(dir: &Path) -> BTreeMap<String, Vec<u8>> {
	fn walk(root: &Path, dir: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
		for entry in std::fs::read_dir(dir).expect("read dir").flatten() {
			let path = entry.path();
			if path.is_dir() {
				walk(root, &path, out);
			} else if path.is_file() {
				let name = path.strip_prefix(root).expect("under root");
				out.insert(
					name.to_string_lossy().into_owned(),
					std::fs::read(&path).expect("read file"),
				);
			}
		}
	}
	let mut out = BTreeMap::new();
	walk(dir, dir, &mut out);
	out
}

/// What differs between two snapshots, one line per path.
pub fn changes(
	before: &BTreeMap<String, Vec<u8>>,
	after: &BTreeMap<String, Vec<u8>>,
) -> Vec<String> {
	let mut found = Vec::new();
	for (name, bytes) in before {
		match after.get(name) {
			None => found.push(format!("removed {name}")),
			Some(now) if now != bytes => found.push(format!("changed {name}")),
			Some(_) => {}
		}
	}
	for name in after.keys().filter(|name| !before.contains_key(*name)) {
		found.push(format!("added {name}"));
	}
	found
}
