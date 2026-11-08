pub use super::*;

pub(super) mod debug;
pub(super) mod env;
pub(super) mod hold_outbound;
pub(super) mod load;
pub(super) mod permissions;

pub(super) fn write_temp(content: &str) -> tempfile::NamedTempFile {
	use std::io::Write;
	let mut file = tempfile::NamedTempFile::new().expect("create temp file");
	file.write_all(content.as_bytes()).expect("write temp file");
	file
}
