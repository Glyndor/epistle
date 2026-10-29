//! Private checkpoints for ordinary guided answers. Credentials never enter this file.

use std::fs::{self, File, OpenOptions};
use std::io::{self, Read, Write};
use std::os::fd::AsRawFd;
use std::os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt};
use std::path::PathBuf;

use crate::cli::ui::prompt::Answers;

const NAME: &str = "init-draft.json";
const MAX_BYTES: u64 = 64 * 1024;

pub(super) struct Store {
	directory: PathBuf,
}

impl Store {
	pub fn process() -> io::Result<Self> {
		let root = std::env::var_os("XDG_STATE_HOME")
			.map(PathBuf::from)
			.filter(|p| p.is_absolute())
			.or_else(|| std::env::var_os("HOME").map(|p| PathBuf::from(p).join(".local/state")))
			.ok_or_else(|| io::Error::other("cannot locate the state directory"))?;
		Ok(Self {
			directory: root.join("epistle"),
		})
	}

	fn directory(&self) -> io::Result<File> {
		fs::DirBuilder::new()
			.recursive(true)
			.mode(0o700)
			.create(&self.directory)?;
		let directory = OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW)
			.open(&self.directory)?;
		let meta = directory.metadata()?;
		// SAFETY: geteuid has no preconditions.
		if !meta.is_dir() || meta.uid() != unsafe { libc::geteuid() } || meta.mode() & 0o077 != 0 {
			return Err(io::Error::other(
				"draft directory must be owned by this user with mode 0700",
			));
		}
		Ok(directory)
	}

	pub fn load(&self) -> io::Result<Answers> {
		if !self.directory.exists() {
			return Ok(Answers::new());
		}
		let directory = self.directory()?;
		let base = anchored(&directory);
		let file = match OpenOptions::new()
			.read(true)
			.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
			.open(base.join(NAME))
		{
			Ok(file) => file,
			Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Answers::new()),
			Err(e) => return Err(e),
		};
		let meta = file.metadata()?;
		// SAFETY: geteuid has no preconditions.
		if !meta.is_file()
			|| meta.uid() != unsafe { libc::geteuid() }
			|| meta.mode() & 0o077 != 0
			|| meta.len() > MAX_BYTES
		{
			return Err(io::Error::other(
				"draft must be a private regular file no larger than 64 KiB",
			));
		}
		let mut bytes = Vec::new();
		file.take(MAX_BYTES + 1).read_to_end(&mut bytes)?;
		if bytes.len() > MAX_BYTES as usize {
			return Err(io::Error::other("init draft exceeds 64 KiB"));
		}
		let answers: Answers =
			serde_json::from_slice(&bytes).map_err(|_| io::Error::other("invalid init draft"))?;
		if answers.keys().any(|key| !allowed(key)) {
			return Err(io::Error::other("unknown field in init draft"));
		}
		Ok(answers)
	}

	pub fn save(&self, answers: &Answers) -> io::Result<()> {
		if answers.keys().any(|key| !allowed(key)) {
			return Err(io::Error::other(
				"only ordinary answers may be checkpointed",
			));
		}
		let directory = self.directory()?;
		let base = anchored(&directory);
		let bytes = serde_json::to_vec(answers)?;
		if bytes.len() > MAX_BYTES as usize {
			return Err(io::Error::other("init draft exceeds 64 KiB"));
		}
		let temporary = base.join(format!(".init-{}", uuid::Uuid::now_v7()));
		let result = (|| {
			let mut file = OpenOptions::new()
				.write(true)
				.create_new(true)
				.mode(0o600)
				.open(&temporary)?;
			file.write_all(&bytes)?;
			file.sync_all()?;
			fs::rename(&temporary, base.join(NAME))?;
			directory.sync_all()
		})();
		if result.is_err() {
			let _ = fs::remove_file(&temporary);
		}
		result
	}

	pub fn remove(&self) -> io::Result<()> {
		let directory = self.directory()?;
		match fs::remove_file(anchored(&directory).join(NAME)) {
			Err(e) if e.kind() != io::ErrorKind::NotFound => Err(e),
			_ => Ok(()),
		}
	}

	pub fn path(&self) -> PathBuf {
		self.directory.join(NAME)
	}
}

/// Keep all operations on the validated directory even if its name is replaced.
fn anchored(directory: &File) -> PathBuf {
	PathBuf::from(format!("/proc/self/fd/{}", directory.as_raw_fd()))
}

fn allowed(key: &str) -> bool {
	matches!(
		key,
		"mode"
			| "hostname"
			| "domains"
			| "address"
			| "display name"
			| "role aliases"
			| "public IPv4"
			| "public IPv6"
			| "data_dir"
			| "config_path"
			| "DNS provider"
			| "DNS zone"
			| "DNS credential source"
			| "IMAP" | "submission"
			| "POP3" | "ManageSieve"
			| "WebDAV"
			| "API" | "PostgreSQL"
			| "image"
	)
}

#[cfg(test)]
mod tests;
