use std::fs::{self, File};
use std::io::Read;
use std::path::Path;

use crate::cli::init::apply::ApplyError;
use crate::config::{Config, ConfigError};

pub(crate) struct ExistingConfig {
	pub(crate) text: String,
	metadata: fs::Metadata,
}

impl ExistingConfig {
	pub(crate) fn validate(&self, path: &Path) -> Result<Config, ConfigError> {
		#[cfg(unix)]
		{
			use std::os::unix::fs::PermissionsExt;
			let mode = self.metadata.permissions().mode() & 0o777;
			if mode & 0o077 != 0 {
				return Err(ConfigError::InsecurePermissions {
					path: path.to_path_buf(),
					mode,
					kind: "config file",
				});
			}
		}
		Config::parse_text(&self.text, path)
	}
}

pub(crate) fn read_config(path: &Path) -> Result<Option<ExistingConfig>, ApplyError> {
	read_config_with(path, |_| {})
}

fn read_config_with(
	path: &Path,
	after_check: impl FnOnce(&File),
) -> Result<Option<ExistingConfig>, ApplyError> {
	let mut options = fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		// Refuse leaf symlinks atomically and never wait for a FIFO writer.
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let mut file = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		#[cfg(unix)]
		Err(error) if error.raw_os_error() == Some(libc::ELOOP) => {
			return Err(ApplyError::ConfigSymlink(path.to_path_buf()));
		}
		Err(error) => {
			// Some non-regular files, such as sockets, cannot be opened at all.
			if fs::symlink_metadata(path).is_ok_and(|metadata| !metadata.file_type().is_file()) {
				return Err(ApplyError::ConfigNotAFile(path.to_path_buf()));
			}
			return Err(ApplyError::ConfigRead(path.to_path_buf(), error));
		}
	};
	let metadata = file
		.metadata()
		.map_err(|error| ApplyError::ConfigRead(path.to_path_buf(), error))?;
	if !metadata.is_file() {
		return Err(ApplyError::ConfigNotAFile(path.to_path_buf()));
	}
	after_check(&file);
	let mut text = String::new();
	file.read_to_string(&mut text)
		.map_err(|error| ApplyError::ConfigRead(path.to_path_buf(), error))?;
	Ok(Some(ExistingConfig { text, metadata }))
}

#[cfg(all(test, unix))]
#[path = "apply_config_read_tests.rs"]
mod tests;
