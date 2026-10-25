//! Script names too long to be a file name.
//!
//! RFC 5804 section 1.6 makes a server accept names of up to 128 characters,
//! which are up to 512 octets in UTF-8, and a file name holds 255 octets at
//! most on the common filesystems. A name past [`FILE_NAME_BYTES`] is kept in
//! a file named after its SHA-256 digest, and a `.name` file beside it holds
//! the name itself, so the listing finds it again without the index. Shorter
//! names stay the file name, as they always were.

use std::fs;
use std::path::Path;

use ring::digest;

use crate::util::path_containment::contained_child;

/// The longest name kept as the file name. The atomic write stages a
/// `.<name>.sieve.<uuid>.tmp` file next to it, which has to stay under the
/// 255 octets a file name may have; 200 leaves room for that staging name.
pub(super) const FILE_NAME_BYTES: usize = 200;

/// What a hashed file name starts with. No script name may start with it, so
/// a file that does is never mistaken for one named like that.
const PREFIX: &str = "~sha256-";

/// The most a `.name` file may hold: the longest name there is.
const MAX_SIDECAR_BYTES: u64 = 4096;

/// Whether `name` starts with the prefix of a hashed file name.
pub(super) fn is_reserved(name: &str) -> bool {
	name.starts_with(PREFIX)
}

/// The file name, without `.sieve`, that holds the script `name`.
pub(super) fn stem(name: &str) -> String {
	if name.len() <= FILE_NAME_BYTES {
		return name.to_string();
	}
	let hash = digest::digest(&digest::SHA256, name.as_bytes());
	let hex: String = hash.as_ref().iter().map(|b| format!("{b:02x}")).collect();
	format!("{PREFIX}{hex}")
}

/// Record the name of a script whose file name is hashed. A name that is its
/// own file name needs nothing.
pub(super) fn record(dir: &Path, name: &str) -> std::io::Result<()> {
	if name.len() <= FILE_NAME_BYTES {
		return Ok(());
	}
	let path = contained_child(dir, &format!("{}.name", stem(name)))?;
	crate::storage::write_secret(&path, name.as_bytes())
}

/// Forget the name of a script that is gone.
pub(super) fn forget(dir: &Path, name: &str) {
	if name.len() > FILE_NAME_BYTES
		&& let Ok(path) = contained_child(dir, &format!("{}.name", stem(name)))
	{
		let _ = fs::remove_file(path);
	}
}

/// The name behind a hashed file name, when the `.name` file beside it is
/// there and agrees with the hash.
pub(super) fn original(dir: &Path, stem_of_file: &str) -> Option<String> {
	if !is_reserved(stem_of_file) {
		return None;
	}
	let path = contained_child(dir, &format!("{stem_of_file}.name")).ok()?;
	if fs::metadata(&path).ok()?.len() > MAX_SIDECAR_BYTES {
		return None;
	}
	let name = fs::read_to_string(path).ok()?;
	(name.len() > FILE_NAME_BYTES && stem(&name) == stem_of_file).then_some(name)
}
