//! The serving side: take the requests, perform the writes, answer.
//!
//! The writes go through the provider the role already holds, the same one
//! the ACME challenge and the TLSA refresh use, so the provider's own locks
//! and its credential scope apply. One write at a time: a provider that
//! rewrites a whole record set could lose one of two concurrent changes.
//!
//! The requests are taken in the order they were made, so a publication and
//! the withdrawal that follows it are performed in that order.

use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use super::{Outcome, Request, requests_dir, results_dir, valid_id};
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

/// How often the serving side looks for requests.
const POLL: Duration = Duration::from_secs(1);

/// The serving side of the hand-off.
pub struct Server {
	/// The hand-off directory.
	root: PathBuf,
	/// The provider the writes go through.
	provider: Arc<dyn DnsProvider>,
	/// The zones the `[dns]` configuration publishes.
	zones: Vec<String>,
	/// The domains this installation serves.
	domains: Vec<String>,
	/// The selectors this installation uses besides the ones a rotation
	/// makes: the ones the operator configured. A rotation publishes and
	/// retires those too, so a request for any other selector is refused.
	selectors: Vec<String>,
	/// The lock every write holds, so two of them never interleave.
	writes: Arc<tokio::sync::Mutex<()>>,
	/// How often the requests are looked for.
	poll: Duration,
}

impl Server {
	/// The server for the hand-off directory `root`.
	pub fn new(
		root: PathBuf,
		provider: Arc<dyn DnsProvider>,
		zones: Vec<String>,
		domains: Vec<String>,
		selectors: Vec<String>,
	) -> Self {
		Server {
			root,
			provider,
			zones,
			domains,
			selectors,
			writes: Arc::new(tokio::sync::Mutex::new(())),
			poll: POLL,
		}
	}

	/// Look for requests every `poll` instead of every second.
	pub fn with_poll(mut self, poll: Duration) -> Self {
		self.poll = poll;
		self
	}

	/// Serve the requests that are waiting, once. Returns how many were
	/// taken.
	pub async fn serve_once(&self) -> usize {
		self.prepare();
		let mut taken = 0;
		for pending in self.pending() {
			self.serve_one(pending).await;
			taken += 1;
		}
		taken
	}

	/// Make the two directories the hand-off uses, owner-only. The asking
	/// side makes them too; a container that starts first makes them
	/// itself.
	fn prepare(&self) {
		for dir in [requests_dir(&self.root), results_dir(&self.root)] {
			// The other container writes in the same tree: a link planted
			// where a directory belongs must not be followed or chmodded.
			if is_link(&self.root) || is_link(&dir) || std::fs::create_dir_all(&dir).is_err() {
				continue;
			}
			if is_link(&dir) {
				continue;
			}
			#[cfg(unix)]
			{
				use std::os::unix::fs::PermissionsExt;
				let _ = std::fs::set_permissions(&dir, std::fs::Permissions::from_mode(0o700));
			}
		}
	}

	/// Serve the requests until the task is dropped.
	pub async fn run(self) {
		loop {
			self.serve_once().await;
			tokio::time::sleep(self.poll).await;
		}
	}

	/// The requests that are waiting, oldest first.
	fn pending(&self) -> Vec<Pending> {
		if is_link(&self.root) || is_link(&requests_dir(&self.root)) {
			return Vec::new();
		}
		let Ok(entries) = std::fs::read_dir(requests_dir(&self.root)) else {
			return Vec::new();
		};
		let mut found: Vec<Pending> = entries
			.flatten()
			.filter_map(|entry| {
				let name = entry.file_name().to_string_lossy().into_owned();
				// A name this hand-off does not use is not a request: it is
				// the temporary file of a write in flight, or something
				// else wrote there. Either way it is left alone.
				if !valid_id(&name) {
					return None;
				}
				Some(Pending {
					id: name,
					path: entry.path(),
					request: read_request(&entry.path()).ok(),
				})
			})
			.collect();
		found.sort_by(|left, right| {
			let left_at = left.created_at();
			let right_at = right.created_at();
			left_at.cmp(&right_at).then_with(|| left.id.cmp(&right.id))
		});
		found
	}

	/// Take one request: check it, perform the write, answer it and remove
	/// it.
	async fn serve_one(&self, pending: Pending) {
		let Some(request) = pending.request else {
			self.answer(
				&pending.id,
				Outcome::failed(&pending.id, "the request is not readable"),
			);
			self.remove(&pending.path);
			return;
		};
		if request.id != pending.id {
			self.answer(
				&pending.id,
				Outcome::failed(&pending.id, "the request names another id"),
			);
			self.remove(&pending.path);
			return;
		}
		if let Err(reason) = super::check(
			&request,
			&self.zones,
			&self.domains,
			&self.selectors,
			super::writer::now(),
		) {
			self.answer(&pending.id, Outcome::failed(&pending.id, reason));
			self.remove(&pending.path);
			return;
		}
		let outcome = self.write(&request, &pending.path).await;
		self.answer(&pending.id, outcome);
		self.remove(&pending.path);
	}

	/// Perform the write the request asks for.
	async fn write(&self, request: &Request, path: &std::path::Path) -> Outcome {
		let Some(zone) = self.zone_for(&request.name) else {
			return Outcome::failed(
				&request.id,
				format!("{} is in none of the [dns] zones", request.name),
			);
		};
		let record = DnsRecord {
			name: request.name.clone(),
			kind: RecordKind::Txt,
			value: request.value.clone(),
			ttl: request.ttl,
			proxied: None,
		};
		let _write = self.writes.lock().await;
		// The wait for the lock can outlast the asking side: it takes the
		// request back when its own wait ends, and a write nobody is waiting
		// for any more must not happen.
		if !path.exists()
			|| super::check(
				request,
				&self.zones,
				&self.domains,
				&self.selectors,
				super::writer::now(),
			)
			.is_err()
		{
			return Outcome::failed(&request.id, "the request was taken back or has expired");
		}
		let result = match request.operation {
			super::Operation::Publish => {
				crate::dkim::domain_rotate::publish_key(self.provider.as_ref(), &zone, record).await
			}
			super::Operation::Withdraw => {
				crate::dkim::domain_rotate::withdraw_key(
					self.provider.as_ref(),
					&zone,
					&record.name,
				)
				.await
			}
		};
		match result {
			Ok(()) => Outcome::ok(&request.id),
			Err(error) => {
				// The provider's own text can carry what its API answered:
				// the log keeps it, the answer carries the category only.
				tracing::warn!(%error, name = %request.name, "a DNS hand-off write failed");
				Outcome::failed(&request.id, category(&error))
			}
		}
	}

	/// The longest zone that contains `name`.
	fn zone_for(&self, name: &str) -> Option<String> {
		let name = name.to_ascii_lowercase();
		self.zones
			.iter()
			.filter(|zone| crate::dns::router::contains(&zone.to_ascii_lowercase(), &name))
			.max_by_key(|zone| zone.len())
			.cloned()
	}

	/// Write the answer to the request and remove the request.
	fn answer(&self, id: &str, outcome: Outcome) {
		let bytes = match serde_json::to_vec(&outcome) {
			Ok(bytes) => bytes,
			Err(error) => {
				tracing::warn!(%error, "cannot encode the answer to a DNS request");
				return;
			}
		};
		let path = results_dir(&self.root).join(id);
		if let Err(error) = crate::storage::write_secret(&path, &bytes) {
			tracing::warn!(%error, path = %path.display(), "cannot write the answer to a DNS request");
		}
	}

	/// Remove a request that was answered. Best effort: a request that stays
	/// is answered again, and the write it asks for is the same one.
	fn remove(&self, path: &Path) {
		if let Err(error) = std::fs::remove_file(path)
			&& error.kind() != std::io::ErrorKind::NotFound
		{
			tracing::warn!(%error, path = %path.display(), "cannot remove an answered DNS request");
		}
	}
}

/// A request that is waiting to be served.
struct Pending {
	/// The id: the name of the file.
	id: String,
	/// The file it was read from.
	path: PathBuf,
	/// What it says, `None` when it could not be read.
	request: Option<Request>,
}

impl Pending {
	/// When the request was made, zero when it could not be read.
	fn created_at(&self) -> u64 {
		self.request
			.as_ref()
			.map_or(0, |request| request.created_at)
	}
}

/// The request a file holds. `Err` when the file is not a request this
/// hand-off wrote.
fn read_request(path: &Path) -> Result<Request, String> {
	let bytes = super::writer::read_bounded(path, super::MAX_REQUEST_BYTES)
		.map_err(|error| format!("the request is not readable: {error}"))?
		.ok_or_else(|| "the request is not there".to_string())?;
	serde_json::from_slice(&bytes).map_err(|error| format!("the request is not readable: {error}"))
}

/// Whether `path` is a symbolic link, which is never followed here.
fn is_link(path: &std::path::Path) -> bool {
	std::fs::symlink_metadata(path).is_ok_and(|meta| meta.file_type().is_symlink())
}

/// What the answer to a failed write says: the category of the failure, never
/// the text the provider answered.
fn category(error: &crate::dns::publish::write::WriteError) -> String {
	use crate::dns::publish::write::WriteError;
	match error {
		WriteError::Provider(error) => {
			crate::dns::providers::check::failure_cause(error).to_string()
		}
		WriteError::Rejected(_) => "the provider refused the change".to_string(),
		other => other.to_string(),
	}
}
