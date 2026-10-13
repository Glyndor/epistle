//! Leftovers of rotations that ran before rotations were journaled: key
//! files `dkim-ed<day>.key` and TXT records `ed<day>._domainkey.<domain>`
//! that neither the active, the previous nor a pending rotation names.
//!
//! They are logged when the rotation task starts and never removed on the
//! server's own initiative: a key file or record the state does not name
//! may still be something the operator relies on. `epistle dkim cleanup`
//! lists them, asks, and drops a request file; the server then removes
//! what is still unnamed at that moment, so the CLI never races a rotation.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};

use super::{RotateError, RotationState, Rotator, read_state, txt_record};
use crate::dns::provider::{DnsProvider, DnsRecord, RecordKind};

/// Cleanup request file name inside the data directory.
pub const CLEANUP_FILE: &str = "dkim-cleanup.request";

/// Key files and TXT records no rotation names.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Orphans {
	/// Key files in the data directory, sorted.
	pub key_files: Vec<PathBuf>,
	/// TXT record names, lowercase and without a trailing dot, sorted.
	pub records: Vec<String>,
	/// Why the zone could not be listed, when it could not: only key files
	/// were looked at then.
	pub unlisted: Option<String>,
}

impl Orphans {
	/// Whether nothing was found.
	pub fn is_empty(&self) -> bool {
		self.key_files.is_empty() && self.records.is_empty()
	}
}

/// Whether `selector` has the shape the rotator gives its selectors.
fn rotated_selector(selector: &str) -> bool {
	selector
		.strip_prefix("ed")
		.is_some_and(|day| !day.is_empty() && day.bytes().all(|b| b.is_ascii_digit()))
}

/// The selectors the state names (active, previous, pending) plus `keep`.
fn named_selectors(state: Option<&RotationState>, keep: &[String]) -> BTreeSet<String> {
	let mut named: BTreeSet<String> = keep.iter().map(|s| s.to_ascii_lowercase()).collect();
	if let Some(state) = state {
		named.insert(state.selector.to_ascii_lowercase());
		named.extend(
			state
				.previous
				.iter()
				.map(|p| p.selector.to_ascii_lowercase()),
		);
		named.extend(
			state
				.pending
				.iter()
				.map(|p| p.selector.to_ascii_lowercase()),
		);
	}
	named
}

/// `dkim-ed<day>.key` files in `data_dir` that no named selector owns.
pub fn orphan_key_files(
	data_dir: &Path,
	state: Option<&RotationState>,
	keep: &[String],
) -> Vec<PathBuf> {
	let named = named_selectors(state, keep);
	let Ok(entries) = std::fs::read_dir(data_dir) else {
		return Vec::new();
	};
	let mut found: Vec<PathBuf> = entries
		.flatten()
		.filter(|entry| {
			let name = entry.file_name();
			let selector = name
				.to_str()
				.and_then(|n| n.strip_prefix("dkim-"))
				.and_then(|n| n.strip_suffix(".key"));
			selector.is_some_and(|s| rotated_selector(s) && !named.contains(s))
		})
		.map(|entry| entry.path())
		.collect();
	found.sort();
	found
}

/// TXT records `ed<day>._domainkey.<domain>` for a signing domain whose
/// selector nothing names.
pub fn orphan_records(
	records: &[DnsRecord],
	domains: &[String],
	state: Option<&RotationState>,
	keep: &[String],
) -> Vec<String> {
	let named = named_selectors(state, keep);
	let found: BTreeSet<String> = records
		.iter()
		.filter(|record| record.kind == RecordKind::Txt)
		.map(|record| record.name.trim_end_matches('.').to_ascii_lowercase())
		.filter(|name| {
			name.split_once("._domainkey.")
				.is_some_and(|(selector, domain)| {
					rotated_selector(selector)
						&& !named.contains(selector)
						&& domains.iter().any(|d| d.eq_ignore_ascii_case(domain))
				})
		})
		.collect();
	found.into_iter().collect()
}

/// Look for orphans against the current state. An unreadable state is an
/// error: without it nothing can be told apart from a key in service.
pub async fn find_orphans(
	data_dir: &Path,
	provider: Option<&dyn DnsProvider>,
	zone: &str,
	domains: &[String],
	keep: &[String],
) -> Result<Orphans, RotateError> {
	let state = read_state(data_dir)?;
	let key_files = orphan_key_files(data_dir, state.as_ref(), keep);
	let (records, unlisted) = match provider {
		None => (
			Vec::new(),
			Some("no [dns] provider is configured".to_string()),
		),
		Some(provider) => match provider.list(zone).await {
			Ok(listed) => (orphan_records(&listed, domains, state.as_ref(), keep), None),
			Err(error) => (Vec::new(), Some(format!("cannot list {zone}: {error}"))),
		},
	};
	Ok(Orphans {
		key_files,
		records,
		unlisted,
	})
}

/// Ask the server to remove the orphans it finds. Asking twice keeps one
/// request.
pub fn request_cleanup(data_dir: &Path) -> std::io::Result<()> {
	crate::storage::write_secret(&data_dir.join(CLEANUP_FILE), b"")
}

impl Rotator {
	/// Selectors outside the state that must never count as orphans: the
	/// configured ed25519 and RSA selectors.
	pub fn keeping(mut self, selectors: Vec<String>) -> Self {
		self.keep = selectors;
		self
	}

	async fn orphans(&self) -> Result<Orphans, RotateError> {
		find_orphans(
			&self.data_dir,
			Some(self.provider.as_ref()),
			&self.zone,
			&self.signing_domains,
			&self.keep,
		)
		.await
	}

	/// Log every orphan once, naming the command that removes them.
	pub async fn report_orphans(&self) {
		let orphans = match self.orphans().await {
			Ok(orphans) => orphans,
			Err(error) => {
				tracing::warn!(%error, "cannot look for leftover DKIM keys and records");
				return;
			}
		};
		for path in &orphans.key_files {
			tracing::warn!(path = %path.display(), "DKIM key file no rotation uses; remove it with `epistle dkim cleanup`");
		}
		for name in &orphans.records {
			tracing::warn!(%name, "DKIM TXT record no rotation uses; remove it with `epistle dkim cleanup`");
		}
	}

	/// Remove the orphans if the operator asked. Returns whether a request
	/// was served. The request is consumed first, whatever happens next:
	/// a failure is logged, and what is left shows again in
	/// `epistle dkim cleanup`.
	pub async fn serve_cleanup(&self) -> Result<bool, RotateError> {
		let request = self.data_dir.join(CLEANUP_FILE);
		if !request.exists() {
			return Ok(false);
		}
		let _ = std::fs::remove_file(&request);
		let orphans = self.orphans().await?;
		let mut failed = Vec::new();
		for name in &orphans.records {
			if let Err(error) = self.provider.delete(&self.zone, txt_record(name, "")).await {
				failed.push(format!("delete {name}: {error}"));
			}
		}
		for path in &orphans.key_files {
			if let Err(error) = std::fs::remove_file(path)
				&& error.kind() != std::io::ErrorKind::NotFound
			{
				failed.push(format!("remove {}: {error}", path.display()));
			}
		}
		tracing::info!(
			key_files = orphans.key_files.len(),
			records = orphans.records.len(),
			"DKIM cleanup done"
		);
		if failed.is_empty() {
			Ok(true)
		} else {
			Err(RotateError(format!("DKIM cleanup: {}", failed.join("; "))))
		}
	}
}
