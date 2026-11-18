//! Automatic suppression: which lists a permanent bounce writes to, for how
//! long, and after how many bounces.
//!
//! A bounce that proves an address does not exist used to suppress it for
//! every sender and for ever, so one customer's typo blocked everyone on the
//! server. The operator now chooses the scopes ([`Rules`]), a lifetime after
//! which the address is tried again, and a threshold of bounces before it is
//! suppressed at all. Entries added by hand never carry a lifetime and are
//! never replaced by an automatic one.
//!
//! The tenant scope is kept under the tenant's name, never under a domain: a
//! domain that is removed or moves to another tenant must not hand the entries
//! of its old tenant to whoever owns it next. Which tenant a sender's domain
//! belongs to now is read, at the check, from `tenants/map`, which the server
//! writes at start from its configuration ([`SuppressionList::publish_tenants`]);
//! a domain it does not list has no tenant scope, and a tenant that is gone has
//! its entries removed.

use std::io;
use std::path::PathBuf;

use super::{
	Suppressed, SuppressionList, digest_name, make_dir, parse_marker, read_entries, remove_marker,
	write_marker,
};
use crate::config::{Config, SuppressionScope};

/// What the operator chose for automatic suppression, from `[queue]`.
#[derive(Debug, Clone)]
pub struct Rules {
	scopes: Vec<SuppressionScope>,
	window_secs: u64,
	threshold: u32,
	/// Each named tenant with its domains, lower case.
	tenants: Vec<(String, Vec<String>)>,
}

impl Default for Rules {
	fn default() -> Self {
		Rules {
			scopes: vec![SuppressionScope::Account, SuppressionScope::Tenant],
			window_secs: 0,
			threshold: 1,
			tenants: Vec::new(),
		}
	}
}

impl Rules {
	/// The rules `config` asks for.
	pub fn from_config(config: &Config) -> Rules {
		Rules {
			scopes: config.queue.suppression_scopes.clone(),
			window_secs: config.queue.suppression_days.saturating_mul(86_400),
			threshold: config.queue.suppression_threshold,
			tenants: config
				.tenants
				.iter()
				.filter_map(|tenant| {
					Some((
						tenant.name.as_ref()?.to_ascii_lowercase(),
						tenant
							.domains
							.iter()
							.map(|domain| domain.to_ascii_lowercase())
							.collect(),
					))
				})
				.collect(),
		}
	}

	/// These rules with automatic entries that last `days` days.
	pub fn lasting(mut self, days: u64) -> Rules {
		self.window_secs = days.saturating_mul(86_400);
		self
	}

	/// Seconds an automatic entry lives, and the window bounces are counted
	/// in. `0` is for ever.
	pub fn window_secs(&self) -> u64 {
		self.window_secs
	}

	/// The tenant that owns `domain` now, lower case.
	pub fn tenant_of(&self, domain: &str) -> Option<&str> {
		self.tenants
			.iter()
			.find(|(_, domains)| domains.iter().any(|candidate| candidate == domain))
			.map(|(tenant, _)| tenant.as_str())
	}
}

/// The list an entry was found in.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Origin {
	/// The shared list.
	Server,
	/// The list of the sender's tenant.
	Tenant,
	/// The list of the sending account.
	Account,
}

fn domain_of(sender: &str) -> Option<String> {
	sender
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_ascii_lowercase())
}

impl Suppressed {
	/// Whether the entry still blocks at `now`: one with no lifetime always
	/// does.
	pub fn active_at(&self, now: u64) -> bool {
		self.until.is_none_or(|until| now < until)
	}
}

/// The content of a marker an automatic suppression writes: the usual two
/// lines and a third saying it is automatic and when it ends (`0` never).
fn automatic_marker(address: &str, reason: &str, now: u64, until: u64) -> String {
	format!("{}auto\t{until}\n", super::marker(address, reason, now))
}

impl SuppressionList {
	fn tenant_dir(&self, tenant: &str) -> PathBuf {
		self.dir.join("tenants").join(digest_name(tenant))
	}

	fn membership_file(&self) -> PathBuf {
		self.dir.join("tenants").join("map")
	}

	/// The tenant `domain` belongs to according to the last
	/// [`SuppressionList::publish_tenants`]; none when it is not listed.
	fn tenant_of_domain(&self, domain: &str) -> Option<String> {
		std::fs::read_to_string(self.membership_file())
			.ok()?
			.lines()
			.filter_map(|line| line.split_once('\t'))
			.find(|(listed, _)| *listed == domain)
			.map(|(_, tenant)| tenant.to_string())
	}

	/// Record which tenant owns which domain, from the configuration, and
	/// remove the entries of every tenant that no longer exists. The check
	/// trusts this map, so a domain that left a tenant stops reaching that
	/// tenant's entries at once.
	pub fn publish_tenants(&self, rules: &Rules) -> io::Result<()> {
		let text: String = rules
			.tenants
			.iter()
			.flat_map(|(tenant, domains)| {
				domains
					.iter()
					.map(move |domain| format!("{domain}\t{tenant}\n"))
			})
			.collect();
		make_dir(&self.dir.join("tenants"))?;
		let staged = self
			.dir
			.join("tenants")
			.join(format!("map.{}.tmp", std::process::id()));
		write_marker(&staged, text)?;
		std::fs::rename(&staged, self.membership_file()).inspect_err(|_| {
			let _ = std::fs::remove_file(&staged);
		})?;
		let kept: Vec<String> = rules
			.tenants
			.iter()
			.map(|(tenant, _)| digest_name(tenant))
			.collect();
		if let Ok(entries) =
			crate::util::fs_walk::rooted::read_dir(&self.data_dir, self.dir.join("tenants"))
		{
			for entry in entries.flatten() {
				let gone = entry
					.file_name()
					.to_str()
					.is_some_and(|name| !kept.iter().any(|digest| digest == name));
				if gone && entry.file_type().is_ok_and(|kind| kind.is_dir()) {
					let _ = std::fs::remove_dir_all(entry.path());
				}
			}
		}
		Ok(())
	}

	/// The bounce counts of one sender, one file per address.
	fn pending_dir(&self, sender: &str) -> PathBuf {
		self.dir.join("pending").join(digest_name(sender))
	}

	/// The entry that stops mail from `sender` to `address` at `now`, and the
	/// list it is in: the shared list, the sender's tenant (through its
	/// domain) or the sender's account. An entry past its lifetime does not
	/// block, whatever is still on disk.
	pub fn blocking(&self, sender: &str, address: &str, now: u64) -> Option<(Origin, Suppressed)> {
		let file = digest_name(address);
		let read = |path: PathBuf| {
			std::fs::read_to_string(path)
				.ok()
				.as_deref()
				.and_then(parse_marker)
				.filter(|entry| entry.active_at(now))
		};
		if let Some(entry) = read(self.path(address)) {
			return Some((Origin::Server, entry));
		}
		if let Some(entry) = domain_of(sender)
			.and_then(|domain| self.tenant_of_domain(&domain))
			.and_then(|tenant| read(self.tenant_dir(&tenant).join(&file)))
		{
			return Some((Origin::Tenant, entry));
		}
		if !sender.is_empty()
			&& let Some(entry) = read(self.account_dir(sender).join(&file))
		{
			return Some((Origin::Account, entry));
		}
		None
	}

	/// Whether mail from `sender` to `address` is stopped at `now`. The one
	/// answer every sending path uses, so the scopes and the lifetime cannot
	/// differ between them.
	pub fn is_blocked(&self, sender: &str, address: &str, now: u64) -> bool {
		self.blocking(sender, address, now).is_some()
	}

	/// Record a permanent bounce of mail from `sender` to `address`, with the
	/// remote reply that proved the address bad. Below the threshold it only
	/// counts; at it, the address is suppressed in each scope of `rules` with
	/// the lifetime of `rules`. Returns whether the address was suppressed.
	pub fn record_bounce(
		&self,
		rules: &Rules,
		sender: &str,
		address: &str,
		reason: &str,
		now: u64,
	) -> io::Result<bool> {
		if !self.threshold_reached(rules, sender, address, now)? {
			return Ok(false);
		}
		let until = match rules.window_secs {
			0 => 0,
			window => now.saturating_add(window),
		};
		let content = automatic_marker(address, reason, now, until);
		for scope in &rules.scopes {
			match scope {
				SuppressionScope::Server => self.write_automatic(&self.path(address), &content)?,
				SuppressionScope::Account if !sender.is_empty() => {
					let dir = self.account_dir(sender);
					make_dir(&dir)?;
					self.write_automatic(&dir.join(digest_name(address)), &content)?;
				}
				SuppressionScope::Tenant => {
					let Some(tenant) = domain_of(sender)
						.as_deref()
						.and_then(|domain| rules.tenant_of(domain))
					else {
						continue;
					};
					let dir = self.tenant_dir(tenant);
					make_dir(&dir)?;
					self.write_automatic(&dir.join(digest_name(address)), &content)?;
				}
				SuppressionScope::Account => {}
			}
		}
		Ok(true)
	}

	/// Write an automatic marker unless the address was put there by hand: a
	/// manual entry never expires, and a bounce must not give it a lifetime.
	fn write_automatic(&self, path: &std::path::Path, content: &str) -> io::Result<()> {
		let manual = std::fs::read_to_string(path)
			.ok()
			.as_deref()
			.and_then(parse_marker)
			.is_some_and(|existing| !existing.automatic);
		if manual {
			return Ok(());
		}
		write_marker(path, content)
	}

	/// Count this bounce and say whether the threshold is reached. The counts
	/// live apart from the entries, per sender and address, and only bounces
	/// inside the window count when the operator set one.
	fn threshold_reached(
		&self,
		rules: &Rules,
		sender: &str,
		address: &str,
		now: u64,
	) -> io::Result<bool> {
		let threshold = usize::try_from(rules.threshold).unwrap_or(usize::MAX);
		if threshold <= 1 {
			return Ok(true);
		}
		let dir = self.pending_dir(sender);
		make_dir(&dir)?;
		let file = dir.join(digest_name(address));
		let mut times: Vec<u64> = std::fs::read_to_string(&file)
			.unwrap_or_default()
			.lines()
			.filter_map(|line| line.trim().parse().ok())
			.collect();
		if rules.window_secs > 0 {
			times.retain(|time| now.saturating_sub(*time) < rules.window_secs);
		}
		times.push(now);
		if times.len() >= threshold {
			return remove_marker(&file).map(|()| true);
		}
		let text: String = times.iter().map(|time| format!("{time}\n")).collect();
		write_marker(&file, text).map(|()| false)
	}

	/// Remove the automatic entries whose lifetime ended and the bounce counts
	/// that fell out of the window, at most `cap` of them, and return how many.
	/// The caller owns the clock: this deletes, so `now` must be one the time
	/// reference believes.
	pub fn sweep_expired(&self, rules: &Rules, now: u64, cap: usize) -> usize {
		let mut removed = 0;
		let mut lists = vec![self.dir.clone()];
		for parent in ["accounts", "tenants"] {
			if let Ok(entries) =
				crate::util::fs_walk::rooted::read_dir(&self.data_dir, self.dir.join(parent))
			{
				lists.extend(
					entries
						.flatten()
						.filter(|entry| entry.file_type().is_ok_and(|kind| kind.is_dir()))
						.map(|entry| entry.path()),
				);
			}
		}
		for list in lists {
			let Ok(entries) = crate::util::fs_walk::rooted::read_dir(&self.data_dir, &list) else {
				continue;
			};
			for entry in entries.flatten() {
				if removed >= cap {
					return removed;
				}
				if !entry.file_type().is_ok_and(|kind| kind.is_file()) {
					continue;
				}
				let expired = std::fs::read_to_string(entry.path())
					.ok()
					.as_deref()
					.and_then(parse_marker)
					.is_some_and(|parsed| parsed.automatic && !parsed.active_at(now));
				if expired && remove_marker(&entry.path()).is_ok() {
					removed += 1;
				}
			}
		}
		if rules.window_secs > 0
			&& let Ok(senders) =
				crate::util::fs_walk::rooted::read_dir(&self.data_dir, self.dir.join("pending"))
		{
			for sender in senders.flatten() {
				let Ok(entries) =
					crate::util::fs_walk::rooted::read_dir(&self.data_dir, sender.path())
				else {
					continue;
				};
				for entry in entries.flatten() {
					if removed >= cap {
						return removed;
					}
					let newest = std::fs::read_to_string(entry.path())
						.unwrap_or_default()
						.lines()
						.filter_map(|line| line.trim().parse::<u64>().ok())
						.max()
						.unwrap_or(0);
					if now.saturating_sub(newest) >= rules.window_secs
						&& remove_marker(&entry.path()).is_ok()
					{
						removed += 1;
					}
				}
				// An emptied sender directory goes too; one that still holds
				// counts refuses and stays.
				let _ = std::fs::remove_dir(sender.path());
			}
		}
		removed
	}

	/// Every entry of the tenant `tenant`, with its date, reason and end, sorted.
	pub fn entries_for_tenant(&self, tenant: &str) -> Vec<Suppressed> {
		read_entries(
			&self.data_dir,
			&self.tenant_dir(&tenant.to_ascii_lowercase()),
		)
	}

	/// Every suppressed address of the tenant, sorted.
	pub fn list_for_tenant(&self, tenant: &str) -> Vec<String> {
		self.entries_for_tenant(tenant)
			.into_iter()
			.map(|entry| entry.address)
			.collect()
	}

	/// Remove an address from a tenant's list (idempotent).
	pub fn remove_for_tenant(&self, tenant: &str, address: &str) -> io::Result<()> {
		remove_marker(
			&self
				.tenant_dir(&tenant.to_ascii_lowercase())
				.join(digest_name(address)),
		)
	}
}

#[cfg(test)]
mod tests;
