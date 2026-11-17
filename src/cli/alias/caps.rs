//! The caps on aliases, lists and their members, checked against the
//! document that is about to be written. The count comes from the same text
//! the commit compares and replaces, so two commands racing for the last place
//! cannot both take it: the second finds the file changed and writes nothing.

use super::{AddArgs, normalized};
use crate::cli::config_edit::ConfigDocument;
use crate::config::{Alias, Config};
use crate::limits::{Kind, Limits, Target};
use crate::util::address::normalize;

/// The domain of an alias address, as the scopes see it.
fn domain_of(limits: &Limits, address: &str) -> String {
	let domain = normalize(address)
		.rsplit_once('@')
		.map(|(_, domain)| domain.to_string())
		.unwrap_or_default();
	limits.scope_domain(&domain)
}

/// How many of `aliases` live in the domain of `domain`, and how many of
/// them are lists.
fn held(limits: &Limits, aliases: &[Alias], domain: &str) -> (usize, usize) {
	let in_domain = aliases
		.iter()
		.filter(|alias| domain_of(limits, &alias.address) == domain);
	let all = in_domain.clone().count();
	let lists = in_domain.filter(|alias| alias.list_id.is_some()).count();
	(all, lists)
}

/// Refuse `alias add` when the domain is at its cap of aliases or lists, or
/// the new alias has more members than one may.
pub(super) fn check_add(document: &ConfigDocument, args: &AddArgs) -> Result<(), String> {
	let current = document.config()?;
	let limits = Limits::from_config(&current);
	let domain = domain_of(&limits, &args.address);
	let target = Target::domain(&domain);
	let subject = format!("domain {domain}");
	let (aliases, lists) = held(&limits, &current.alias, &domain);
	let admit = |kind: Kind, total: usize| {
		limits
			.admit_total(kind, &target, total, &subject)
			.map_err(|reached| reached.to_string())
	};
	admit(Kind::Aliases, aliases + 1)?;
	if args.list_id.is_some() {
		admit(Kind::Lists, lists + 1)?;
	}
	let members = normalized(&args.members).len();
	limits
		.admit_total(
			Kind::ListMembers,
			&target,
			members,
			&format!("alias {}", normalize(&args.address)),
		)
		.map_err(|reached| reached.to_string())
}

/// Refuse `alias member add` when the alias already has as many members as
/// one may.
pub(super) fn check_member_add(document: &ConfigDocument, address: &str) -> Result<(), String> {
	let current: Config = document.config()?;
	let limits = Limits::from_config(&current);
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
		.map_err(|reached| reached.to_string())
}
