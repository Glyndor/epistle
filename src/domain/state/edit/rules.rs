//! The rules each [`Change`] follows. `current` is the configuration the
//! server runs with the state as it is on disk; `file` is that state, which
//! the change edits.

use crate::config::Config;

use super::super::blockers::removal_blockers;
use super::super::file::{DomainsFile, HostedDomain};
use super::{Change, EditError};

/// Apply `change` to `file`.
pub fn apply(current: &Config, file: &mut DomainsFile, change: &Change) -> Result<(), EditError> {
	match change {
		Change::Add {
			name,
			role,
			dkim,
			srs_secret,
		} => {
			let name = check_new_domain(current, name)?;
			file.domains.push(HostedDomain {
				role: *role,
				dkim: dkim.clone(),
				srs_secret: srs_secret.clone(),
				..HostedDomain::new(&name)
			});
			Ok(())
		}
		Change::Remove { name } => {
			let hosted = hosted(file, name)?;
			removal_blockers(current, &hosted).map_err(EditError::InUse)?;
			file.domains
				.retain(|domain| !domain.name.eq_ignore_ascii_case(&hosted));
			Ok(())
		}
		Change::SetRole { name, role } => {
			let hosted = hosted(file, name)?;
			if let Some(domain) = file.domain_mut(&hosted) {
				domain.role = *role;
			}
			Ok(())
		}
		Change::Set {
			name,
			role,
			quota,
			submission_rate,
		} => super::limits::apply(current, file, name, *role, *quota, *submission_rate),
		Change::SetEnabled { name, enabled } => {
			let hosted = hosted(file, name)?;
			if !enabled {
				refuse_last_enabled(current, file, &hosted)?;
			}
			if let Some(domain) = file.domain_mut(&hosted) {
				domain.enabled = *enabled;
			}
			Ok(())
		}
		Change::AliasAdd { alias, target } => {
			let (alias, target) = check_new_alias(file, alias, target)?;
			file.aliases.insert(alias, target);
			Ok(())
		}
		Change::AliasRemove { alias } => {
			canonical("domain alias", alias)?;
			let Some((key, _)) = file.alias(alias) else {
				return Err(EditError::NotFound(format!(
					"domain alias {alias} is not declared"
				)));
			};
			let key = key.clone();
			file.aliases.remove(&key);
			Ok(())
		}
		Change::Import => import(current, file),
	}
}

/// The canonical form of a domain name the caller gave: the configuration
/// file's rule for a domain name, then trimmed and lowercased the way every
/// list of the configuration stores it.
pub fn canonical(field: &str, raw: &str) -> Result<String, EditError> {
	crate::config::validate_dns_name(field, raw)
		.map_err(|error| EditError::Invalid(error.to_string()))?;
	Ok(raw.trim().to_ascii_lowercase())
}

/// The stored name of the hosted domain `name`.
fn hosted(file: &DomainsFile, name: &str) -> Result<String, EditError> {
	canonical("domain", name)?;
	file.domain(name)
		.map(|domain| domain.name.clone())
		.ok_or_else(|| EditError::NotFound(format!("domain {name} is not configured")))
}

/// A new domain must be a valid name the server does not host, and must not
/// be an alias or the target of one: allowing it would silently re-route
/// mail that resolves through the aliases.
pub fn check_new_domain(current: &Config, raw: &str) -> Result<String, EditError> {
	let name = canonical("domain", raw)?;
	if current
		.domains
		.iter()
		.any(|existing| existing.eq_ignore_ascii_case(&name))
	{
		return Err(EditError::Exists(format!(
			"domain {raw} is already configured"
		)));
	}
	for (alias, target) in &current.domain_aliases {
		if alias.eq_ignore_ascii_case(&name) {
			return Err(EditError::Exists(format!(
				"domain {raw} is already declared as a domain alias (target {target})"
			)));
		}
		if target.eq_ignore_ascii_case(&name) {
			return Err(EditError::Exists(format!(
				"domain {raw} is already targeted by the domain alias {alias}"
			)));
		}
	}
	Ok(name)
}

fn check_new_alias(
	file: &DomainsFile,
	alias: &str,
	target: &str,
) -> Result<(String, String), EditError> {
	let alias_name = canonical("domain alias", alias)?;
	let target_name = canonical("domain alias target", target)?;
	if file.domain(&target_name).is_none() {
		return Err(EditError::NotFound(format!(
			"domain alias target {target} is not a configured domain"
		)));
	}
	if file.alias(&alias_name).is_some() {
		return Err(EditError::Exists(format!(
			"domain alias {alias} is already declared"
		)));
	}
	if file.domain(&alias_name).is_some() {
		return Err(EditError::Exists(format!(
			"domain alias {alias} collides with a configured domain"
		)));
	}
	Ok((alias_name, target_name))
}

/// A server with listeners keeps one enabled domain: with none it would keep
/// accepting connections and reject every recipient.
fn refuse_last_enabled(current: &Config, file: &DomainsFile, name: &str) -> Result<(), EditError> {
	let remaining = file
		.domains
		.iter()
		.filter(|domain| !domain.name.eq_ignore_ascii_case(name))
		.filter(|domain| domain.enabled)
		.count();
	if remaining == 0 && !current.listeners.is_empty() {
		return Err(EditError::Policy(format!(
			"cannot disable {name}: it is the last enabled domain and the server has \
			 listeners; keep one domain enabled"
		)));
	}
	Ok(())
}

/// Replace the state with the configuration file's lists. A domain that stays
/// keeps the key and the secret it was given; a domain that goes is refused
/// while something still uses it, as `domain remove` is.
fn import(current: &Config, file: &mut DomainsFile) -> Result<(), EditError> {
	let mut seeded = current.domain_seed.file();
	if !current.domain_seed.captured {
		seeded = current.domains_file();
	}
	let mut blocked = Vec::new();
	for domain in &file.domains {
		if seeded.domain(&domain.name).is_none()
			&& let Err(why) = removal_blockers(current, &domain.name)
		{
			blocked.push(why);
		}
	}
	if !blocked.is_empty() {
		return Err(EditError::InUse(blocked.join("; ")));
	}
	for domain in &mut seeded.domains {
		if let Some(kept) = file.domain(&domain.name) {
			domain.dkim = kept.dkim.clone();
			domain.srs_secret = kept.srs_secret.clone();
		}
	}
	*file = seeded;
	Ok(())
}
