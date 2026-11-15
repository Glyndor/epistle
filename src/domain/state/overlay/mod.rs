//! Laying `<data_dir>/domains.toml` over the configuration file.
//!
//! While the state file exists, the hosted domains, their roles, their
//! switches and the domain aliases are the file's, whatever `domains`,
//! `domain_aliases` and the role lists of the configuration file say. The
//! per-domain entries of the configuration file (`[[dkim.domain]]`,
//! `[[srs_domain]]`, `domain_quotas`, `domain_submission_limits`) keep
//! applying to the domains the file hosts, and an entry naming a domain the
//! file does not host is left out, the way removing the domain used to
//! remove the entry. A domain added through the file brings the DKIM key and
//! the SRS secret it was given, unless the configuration file already names
//! one for it. A present `limits` table replaces the configuration's two
//! per-domain limit overrides, including an explicit clearing of either.

use crate::config::{Config, DkimDomain, SrsDomain};

use super::file::{DomainsFile, StoredRole};
use super::seed::{DomainSeed, listed};

impl Config {
	/// Take the seed of a configuration loaded from `path`'s file and lay the
	/// state file of its data directory over it. A missing state file leaves
	/// the configuration as the file declared it. A state file that cannot be
	/// read or parsed is an error: the server must not start with a domain
	/// list it did not mean.
	pub(crate) fn overlay_domains_file(&mut self) -> Result<(), String> {
		self.domain_seed = DomainSeed::capture(self);
		if !self.data_dir.is_absolute() {
			return Ok(());
		}
		let path = super::path(&self.data_dir);
		let file = DomainsFile::read(&path).map_err(|error| {
			format!(
				"{}: {error}; fix the file, or move it away and run `epistle domain import`",
				path.display()
			)
		})?;
		let Some(file) = file else {
			return Ok(());
		};
		if !file.seed_digest.is_empty() && file.seed_digest != self.domain_seed.digest() {
			self.adjusted.push(format!(
				"the domain lists of the configuration file (`domains`, `domain_aliases` and \
				 the role lists) changed after {} was made from them; the server uses {}, and \
				 `epistle domain import` copies the configuration file's lists into it again",
				path.display(),
				path.display()
			));
		}
		self.apply_domains_file(&file);
		Ok(())
	}

	/// This configuration with `file` as its domain state: the configuration
	/// file's own lists and entries are restored from the seed first, so the
	/// result is the one a fresh load with `file` on disk would give.
	pub fn with_domains_file(&self, file: &DomainsFile) -> Config {
		let mut next = self.clone();
		if !next.domain_seed.captured {
			next.domain_seed = DomainSeed::capture(&next);
		}
		next.restore_domain_seed();
		next.apply_domains_file(file);
		next
	}

	/// This configuration with the state file that is on disk now: what a
	/// long-running task that has no file watcher of its own (the DNS
	/// reconcile loop, which also runs in the certificates container) reads
	/// at the start of each run. A file that cannot be read keeps the
	/// domains this configuration has, and says so.
	pub fn with_current_domains_file(&self) -> Config {
		let path = super::path(&self.data_dir);
		match DomainsFile::read(&path) {
			Ok(Some(file)) => self.with_domains_file(&file),
			Ok(None) if self.domain_seed.captured => {
				self.with_domains_file(&self.domain_seed.file())
			}
			Ok(None) => self.clone(),
			Err(error) => {
				tracing::warn!(
					file = %path.display(),
					%error,
					"cannot read the domain state file; the hosted domains stay as they were"
				);
				self.clone()
			}
		}
	}

	/// The domain state the configuration holds now, as a state file: what
	/// the first write starts from when no file exists.
	pub fn domains_file(&self) -> DomainsFile {
		let mut seed = DomainSeed::capture(self);
		seed.captured = true;
		let mut file = seed.file();
		if self.domain_seed.captured {
			file.seed_digest = self.domain_seed.digest();
		}
		file
	}

	fn restore_domain_seed(&mut self) {
		let seed = self.domain_seed.clone();
		self.domains = seed.domains;
		self.domain_aliases = seed.domain_aliases;
		self.disabled_domains = seed.disabled_domains;
		self.send_only_domains = seed.send_only_domains;
		self.receive_only_domains = seed.receive_only_domains;
		if let Some(dkim) = &mut self.dkim {
			dkim.domain = seed.dkim_domains;
		}
		self.srs_domain = seed.srs_domain;
		self.domain_quotas = seed.domain_quotas;
		self.domain_submission_limits = seed.domain_submission_limits;
	}

	fn apply_domains_file(&mut self, file: &DomainsFile) {
		let seed = self.domain_seed.clone();
		let with_role = |role: StoredRole| -> Vec<String> {
			file.domains
				.iter()
				.filter(|domain| domain.role == role)
				.map(|domain| domain.name.clone())
				.collect()
		};
		self.domains = file.names();
		self.domain_aliases = file.aliases.clone().into_iter().collect();
		self.send_only_domains = with_role(StoredRole::SendOnly);
		self.receive_only_domains = with_role(StoredRole::ReceiveOnly);
		self.disabled_domains = file
			.domains
			.iter()
			.filter(|domain| !domain.enabled)
			.map(|domain| domain.name.clone())
			.collect();
		let domains = self.domains.clone();
		let aliases: Vec<String> = self.domain_aliases.keys().cloned().collect();
		let hosted = |name: &str| listed(&domains, name);
		let signs = |name: &str| hosted(name) || listed(&aliases, name);
		if let Some(dkim) = &mut self.dkim {
			dkim.domain = seed
				.dkim_domains
				.into_iter()
				.filter(|entry| signs(&entry.name))
				.collect();
			for domain in &file.domains {
				let Some(key) = &domain.dkim else { continue };
				if dkim.override_for(&domain.name).is_some() {
					continue;
				}
				dkim.domain.push(DkimDomain {
					name: domain.name.clone(),
					selector: key.selector.clone(),
					key_file: key.key_file.clone(),
					rsa_selector: key.rsa_selector.clone(),
					rsa_key_file: key.rsa_key_file.clone(),
				});
			}
		}
		self.srs_domain = seed
			.srs_domain
			.into_iter()
			.filter(|entry| hosted(&entry.name))
			.collect();
		for domain in &file.domains {
			let Some(secret) = &domain.srs_secret else {
				continue;
			};
			if self.srs_domain(&domain.name).is_some() {
				continue;
			}
			self.srs_domain.push(SrsDomain {
				name: domain.name.clone(),
				secret: secret.clone(),
				previous_secret: None,
			});
		}
		self.domain_quotas = seed
			.domain_quotas
			.into_iter()
			.filter(|(name, _)| hosted(name))
			.collect();
		self.domain_submission_limits = seed
			.domain_submission_limits
			.into_iter()
			.filter(|(name, _)| hosted(name))
			.collect();
		for domain in &file.domains {
			let Some(limits) = &domain.limits else {
				continue;
			};
			self.domain_quotas.remove(&domain.name);
			self.domain_submission_limits.remove(&domain.name);
			if let Some(quota) = limits.quota {
				self.domain_quotas.insert(domain.name.clone(), quota);
			}
			if let Some(rate) = limits.submission_rate {
				self.domain_submission_limits
					.insert(domain.name.clone(), rate);
			}
		}
	}
}

#[cfg(test)]
mod tests;
