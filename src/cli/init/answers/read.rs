//! Reading the `--answers` file: a regular file, never a link, and one only
//! its owner can read when it carries a credential.

use std::io::Read;
use std::path::Path;

use super::super::apply::ApplyError;

/// The text of the answers file at `path`. It is opened without following a
/// link and without waiting on a fifo, so only a regular file is read. When
/// group or others can read it and it holds an inline `dns.token`, it is
/// refused: the token is a credential and the file would be its only copy
/// anyone can reach. A file without one keeps whatever mode it has.
pub(in crate::cli::init) fn read_file(path: &Path) -> Result<String, ApplyError> {
	let refused = |why: String| ApplyError::AnswersFile(path.to_path_buf(), why);
	let mut file = open(path).map_err(|error| {
		if error.raw_os_error() == Some(libc::ELOOP) {
			return refused("is a symlink; pass the file itself".to_string());
		}
		ApplyError::ConfigRead(path.to_path_buf(), error)
	})?;
	let metadata = file
		.metadata()
		.map_err(|error| ApplyError::ConfigRead(path.to_path_buf(), error))?;
	if !metadata.is_file() {
		return Err(refused("must be a regular file".to_string()));
	}
	let mut raw = String::new();
	file.read_to_string(&mut raw)
		.map_err(|error| ApplyError::ConfigRead(path.to_path_buf(), error))?;
	let mode = mode_of(&metadata);
	if mode & 0o077 != 0 && has_inline_token(&raw) {
		return Err(refused(format!(
			"holds an inline dns.token and is group/world-accessible (mode {mode:#o}); restrict it to 0600 or use dns.token_file"
		)));
	}
	Ok(raw)
}

fn open(path: &Path) -> std::io::Result<std::fs::File> {
	use std::os::unix::fs::OpenOptionsExt;
	std::fs::OpenOptions::new()
		.read(true)
		.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
		.open(path)
}

fn mode_of(metadata: &std::fs::Metadata) -> u32 {
	use std::os::unix::fs::PermissionsExt;
	metadata.permissions().mode() & 0o777
}

/// Whether `raw` sets `[dns] token` to something. A file that does not parse
/// has none to find; the parser reports it afterwards.
fn has_inline_token(raw: &str) -> bool {
	raw.parse::<toml::Table>().is_ok_and(|table| {
		table
			.get("dns")
			.and_then(|dns| dns.get("token"))
			.and_then(toml::Value::as_str)
			.is_some_and(|token| !token.trim().is_empty())
	})
}
