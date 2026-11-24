//! The caps on aliases, lists and their members (#1830), checked against the
//! state the change starts from, under the lock of its file, so two writers
//! racing for the last place cannot both take it.

use crate::config::{Alias, Config};
use crate::limits::{Kind, Limits, Target};
use crate::util::address::normalize;

use super::AliasError;

/// The domain of an alias address, as the scopes see it.
fn domain_of(limits: &Limits, address: &str) -> String {
	let domain = normalize(address)
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_string())
		.unwrap_or_default();
	limits.scope_domain(&domain)
}

/// How many of `aliases` live in `domain`, and how many of them are lists.
fn held(limits: &Limits, aliases: &[Alias], domain: &str) -> (usize, usize) {
	let in_domain = aliases
		.iter()
		.filter(|alias| domain_of(limits, &alias.address) == domain);
	let all = in_domain.clone().count();
	let lists = in_domain.filter(|alias| alias.list_id.is_some()).count();
	(all, lists)
}

/// Refuse an add when the domain is at its cap of aliases or lists, or the
/// new alias has more members than one may.
pub(super) fn check_add(current: &Config, new: &Alias) -> Result<(), AliasError> {
	let limits = Limits::from_config(current);
	let domain = domain_of(&limits, &new.address);
	let target = Target::domain(&domain);
	let subject = format!("domain {domain}");
	let (aliases, lists) = held(&limits, &current.alias, &domain);
	let admit = |kind: Kind, total: usize| {
		limits
			.admit_total(kind, &target, total, &subject)
			.map_err(AliasError::Capped)
	};
	admit(Kind::Aliases, aliases + 1)?;
	if new.list_id.is_some() {
		admit(Kind::Lists, lists + 1)?;
	}
	limits
		.admit_total(
			Kind::ListMembers,
			&target,
			new.members.len(),
			&format!("alias {}", normalize(&new.address)),
		)
		.map_err(AliasError::Capped)
}

/// Refuse a member add when the alias already has as many as one may.
pub(super) fn check_member_add(current: &Config, address: &str) -> Result<(), AliasError> {
	let limits = Limits::from_config(current);
	let Some(alias) = current
		.alias
		.iter()
		.find(|alias| normalize(&alias.address) == normalize(address))
	else {
		return Ok(());
	};
	let target = Target::domain(&domain_of(&limits, &alias.address));
	limits
		.admit(
			Kind::ListMembers,
			&target,
			alias.members.len(),
			&format!("alias {}", normalize(address)),
		)
		.map_err(AliasError::Capped)
}
