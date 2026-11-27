//! The hosted domains the account store builds every directory with, and
//! their replacement when the domain state file is reloaded.

use std::collections::HashMap;

use super::{AccountStore, DynamicFile, StoreError};
use crate::domain::state::DomainsFile;
use crate::storage::lock::FileLock;
use crate::storage::locked::lock_path;

/// The hosted domains, the domain aliases and the domains that are switched
/// off or only receive, as the directory needs them.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct HostedDomains {
	/// The hosted domains.
	pub domains: Vec<String>,
	/// The server's own name, which need not be a hosted domain.
	pub hostname: String,
	/// Alias domain to hosted domain.
	pub domain_aliases: HashMap<String, String>,
	/// Hosted domains that are switched off.
	pub disabled: Vec<String>,
	/// Hosted domains nobody may send as (`receive_only_domains`).
	pub send_off: Vec<String>,
	/// Per-domain storage quota overrides, reloaded with the domains.
	pub domain_quotas: HashMap<String, u64>,
	/// Per-domain submission-rate overrides, reloaded with the domains.
	pub domain_submission_limits: HashMap<String, u32>,
}

impl HostedDomains {
	/// The hosted domains of `config`.
	pub fn of(config: &crate::config::Config) -> Self {
		HostedDomains {
			domains: config.domains.clone(),
			hostname: config.hostname.clone(),
			domain_aliases: config.domain_aliases.clone(),
			disabled: config.disabled_domains.clone(),
			send_off: config.receive_only_domains.clone(),
			domain_quotas: config.domain_quotas.clone(),
			domain_submission_limits: config.domain_submission_limits.clone(),
		}
	}
}

impl AccountStore {
	/// The hosted domains the store builds the directory with now.
	pub fn hosted_domains(&self) -> HostedDomains {
		self.hosted.read().expect("hosted lock").clone()
	}

	/// Whether `domain` is hosted, without regard to ASCII case.
	pub(super) fn hosts(&self, domain: &str) -> bool {
		self.hosted
			.read()
			.expect("hosted lock")
			.domains
			.iter()
			.any(|hosted| hosted.eq_ignore_ascii_case(domain))
	}

	/// Replace the hosted domains with `hosted` and rebuild the directory, so
	/// the next recipient, sender or login check sees them. Called when the
	/// domain state file changes; nothing is written.
	pub fn reload_domains(&self, hosted: HostedDomains) {
		{
			let mut current = self.hosted.write().expect("hosted lock");
			if *current == hosted {
				return;
			}
			*current = hosted;
		}
		self.rebuild_directory();
	}

	/// Whether `domain` is hosted according to `domains.toml` as it is on
	/// disk, which is where a removal decides. The running snapshot only
	/// follows that file when the watcher reloads it, so a write that
	/// admits an address by the snapshot can admit a domain a removal has
	/// already taken out. Without the file the snapshot is the seed and
	/// answers. A file that cannot be read refuses the write.
	pub(super) fn hosts_on_disk(&self, domain: &str) -> Result<bool, StoreError> {
		let path = crate::domain::state::path(self.data_dir());
		match DomainsFile::read(&path) {
			Ok(Some(file)) => Ok(file.domain(domain).is_some()),
			Ok(None) => Ok(self.hosts(domain)),
			Err(error) => Err(StoreError::Io(std::io::Error::new(
				error.kind(),
				format!("{}: {error}", path.display()),
			))),
		}
	}

	/// [`AccountStore::mutate_store`] under the lock of `domains.toml`, the
	/// one a domain removal holds while it checks that no account uses the
	/// domain and while it writes the file without it. A write that checks
	/// its addresses with [`AccountStore::hosts_on_disk`] takes this first,
	/// so the removal either sees the account or the account sees the
	/// removal. Always this lock before the lock of `accounts.toml`: a
	/// removal never takes the second while it holds the first.
	pub(super) fn mutate_store_hosted<F>(&self, mutate: F) -> Result<(), StoreError>
	where
		F: FnOnce(&mut DynamicFile) -> Result<(), StoreError>,
	{
		let path = crate::domain::state::path(self.data_dir());
		let _domains = FileLock::acquire(&lock_path(&path)).map_err(StoreError::Io)?;
		self.mutate_store(mutate)
	}

	/// The data directory the account file lives in.
	pub(super) fn data_dir(&self) -> &std::path::Path {
		self.path
			.parent()
			.filter(|parent| !parent.as_os_str().is_empty())
			.unwrap_or(std::path::Path::new("."))
	}
}
