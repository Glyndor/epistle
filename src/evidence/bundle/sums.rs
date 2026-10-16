//! `SHA256SUMS`: one line per file, in the format `sha256sum -c` reads.

use std::path::Path;

use super::export::relative_files;
use crate::evidence::record::{sha256, to_hex};

/// The checksum file's name.
pub(super) const FILE: &str = "SHA256SUMS";

/// Write `SHA256SUMS` for every file under `out`.
pub(super) fn write(out: &Path) -> std::io::Result<()> {
	let mut text = String::new();
	for relative in relative_files(out)? {
		let Some(name) = relative.to_str() else {
			continue;
		};
		if name == FILE {
			continue;
		}
		let bytes =
			crate::evidence::checkpoint::read_bounded(&out.join(&relative), super::MAX_FILE)?
				.ok_or_else(|| std::io::Error::from(std::io::ErrorKind::NotFound))?;
		text.push_str(&format!("{}  {name}\n", to_hex(&sha256(&bytes))));
	}
	super::write_file(&out.join(FILE), text.as_bytes())
}
