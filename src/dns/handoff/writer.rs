//! The asking side: write the request, wait for the answer.
//!
//! The request is written with the repository's safe-write helper, so it is
//! `0600` from creation and lands whole: the serving side never reads half
//! a request. The answer is read without following a link and with a bound
//! on its size, because it comes from another container.
//!
//! When the answer does not come in time the request is taken back: the
//! serving side must not write a record the rotation has already given up
//! on, or a rotation that withdrew would see its record published behind
//! its back.

use std::path::{Path, PathBuf};
use std::time::Duration;

use super::{Outcome, Write, requests_dir, results_dir, valid_id};
use uuid::Uuid;

/// How often the asking side looks for the answer.
const POLL: Duration = Duration::from_millis(50);

/// The asking side of the hand-off.
#[derive(Debug, Clone)]
pub struct Writer {
	/// The hand-off directory.
	root: PathBuf,
	/// How long one request waits for its answer.
	timeout: Duration,
}

impl Writer {
	/// The writer for the hand-off directory under `data_dir`.
	pub fn new(data_dir: &Path) -> Self {
		Writer::at(super::dir(data_dir))
	}

	/// The writer for a hand-off directory.
	pub fn at(root: PathBuf) -> Self {
		Writer {
			root,
			timeout: super::RESULT_TIMEOUT,
		}
	}

	/// Wait at most `timeout` for the answer of one request.
	pub fn with_timeout(mut self, timeout: Duration) -> Self {
		self.timeout = timeout;
		self
	}

	/// Ask the other container to perform `write` and wait for its answer.
	///
	/// `Ok(())` when the write happened and the reason when it did not: the
	/// same shape a provider error has, so the caller reads the same
	/// message it would read without the split.
	pub async fn perform(&self, write: Write) -> Result<(), String> {
		self.prepare()?;
		self.sweep();
		let id = Uuid::now_v7().to_string();
		let request = write.request(&id, now());
		let bytes = serde_json::to_vec(&request)
			.map_err(|error| format!("cannot encode the DNS request: {error}"))?;
		let path = requests_dir(&self.root).join(&id);
		crate::storage::write_secret(&path, &bytes)
			.map_err(|error| format!("cannot write the DNS request: {error}"))?;
		match self.wait(&id, &write).await {
			Ok(outcome) => outcome.answer(),
			Err(error) => {
				// The request is not wanted any more: the rotation is
				// taking the write back, and the serving side must not
				// perform it later.
				let _ = std::fs::remove_file(&path);
				Err(error)
			}
		}
	}

	/// Make the two directories the hand-off uses, owner-only.
	fn prepare(&self) -> Result<(), String> {
		for dir in [requests_dir(&self.root), results_dir(&self.root)] {
			std::fs::create_dir_all(&dir)
				.map_err(|error| format!("cannot create {}: {error}", dir.display()))?;
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700))
					.map_err(|error| format!("cannot restrict {}: {error}", dir.display()))?;
			}
		}
		Ok(())
	}

	/// Wait for the answer of the request `id`.
	async fn wait(&self, id: &str, write: &Write) -> Result<Outcome, String> {
		let deadline = tokio::time::Instant::now() + self.timeout;
		loop {
			match self.read_answer(id) {
				Ok(Some(outcome)) => return Ok(outcome),
				Ok(None) => {}
				Err(error) => return Err(error),
			}
			if tokio::time::Instant::now() >= deadline {
				return Err(format!(
					"the certificates container did not answer the {} of {} within {}s",
					match write.operation {
						super::Operation::Publish => "publication",
						super::Operation::Withdraw => "withdrawal",
					},
					write.name,
					self.timeout.as_secs()
				));
			}
			tokio::time::sleep(POLL).await;
		}
	}

	/// The answer of the request `id`, `None` when it has not arrived.
	fn read_answer(&self, id: &str) -> Result<Option<Outcome>, String> {
		let path = results_dir(&self.root).join(id);
		let bytes = match read_bounded(&path, super::MAX_RESULT_BYTES) {
			Ok(Some(bytes)) => bytes,
			Ok(None) => return Ok(None),
			Err(error) => {
				return Err(format!(
					"the answer of the certificates container is not readable: {error}"
				));
			}
		};
		let outcome: Outcome = serde_json::from_slice(&bytes).map_err(|error| {
			format!("the answer of the certificates container is not readable: {error}")
		})?;
		if outcome.id != id {
			return Err(
				"the answer of the certificates container names another request".to_string(),
			);
		}
		let _ = std::fs::remove_file(&path);
		Ok(Some(outcome))
	}

	/// Remove what an earlier run left behind: the answers nobody read and
	/// the temporary files of a request that was killed mid-write. The
	/// requests themselves are the serving side's to remove.
	fn sweep(&self) {
		let old = (self.timeout * 2).as_secs();
		for (dir, answers) in [
			(results_dir(&self.root), true),
			(requests_dir(&self.root), false),
		] {
			let Ok(entries) = std::fs::read_dir(&dir) else {
				continue;
			};
			for entry in entries.flatten() {
				let name = entry.file_name().to_string_lossy().into_owned();
				// In the results the stale ones are the answers nobody read;
				// in the requests they are the temporary files of a write
				// that was killed. A request of its own is left to the
				// serving side, which answers it or refuses it.
				let stale = if answers {
					valid_id(&name)
				} else {
					!valid_id(&name)
				};
				if !stale {
					continue;
				}
				let Ok(metadata) = entry.metadata() else {
					continue;
				};
				let age = metadata
					.modified()
					.ok()
					.and_then(|modified| modified.duration_since(std::time::UNIX_EPOCH).ok())
					.map(|since| since.as_secs())
					.unwrap_or(0);
				if age < old {
					continue;
				}
				if let Err(error) = std::fs::remove_file(entry.path())
					&& error.kind() != std::io::ErrorKind::NotFound
				{
					tracing::warn!(%error, path = %entry.path().display(), "cannot remove a stale DNS hand-off file");
				}
			}
		}
	}
}

/// The bytes of the file at `path`, `None` when there is none.
///
/// Refused when the entry is a symlink (the open does not follow it), is
/// not a regular file, has a second name, or is longer than `max`: the
/// content comes from another container.
pub(crate) fn read_bounded(path: &Path, max: usize) -> std::io::Result<Option<Vec<u8>>> {
	use std::io::Read;
	let mut options = std::fs::OpenOptions::new();
	options.read(true);
	#[cfg(unix)]
	{
		use std::os::unix::fs::OpenOptionsExt;
		options.custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK);
	}
	let file = match options.open(path) {
		Ok(file) => file,
		Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
		Err(error) => return Err(error),
	};
	let metadata = file.metadata()?;
	if !metadata.is_file() {
		return Err(std::io::Error::other("not a regular file"));
	}
	if metadata.len() > max as u64 {
		return Err(std::io::Error::other(format!(
			"the file is longer than {max} bytes"
		)));
	}
	#[cfg(unix)]
	{
		use std::os::unix::fs::MetadataExt;
		if metadata.nlink() != 1 {
			return Err(std::io::Error::other("the file has more than one name"));
		}
	}
	let mut bytes = Vec::new();
	file.take(max as u64 + 1).read_to_end(&mut bytes)?;
	if bytes.len() > max {
		return Err(std::io::Error::other(format!(
			"the file is longer than {max} bytes"
		)));
	}
	Ok(Some(bytes))
}

/// The current time in epoch seconds.
pub(crate) fn now() -> u64 {
	std::time::SystemTime::now()
		.duration_since(std::time::UNIX_EPOCH)
		.map(|since| since.as_secs())
		.unwrap_or(0)
}
