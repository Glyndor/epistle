//! The changes of one alias: its removal, its members and its senders.

use crate::util::address::normalize;

use super::super::collide::Known;
use super::super::{AliasError, Origin, caps};
use super::guard::{api_member, domain_of, find, member_or_sender};
use super::{invalid, outside};
use crate::aliases::file::AliasesFile;
use crate::config::Config;

pub(super) fn remove(
	file: &mut AliasesFile,
	address: &str,
	origin: &Origin,
	known: Option<&Known>,
) -> Result<(), AliasError> {
	find(file, address, origin, known)?;
	let wanted = normalize(address);
	file.aliases
		.retain(|alias| normalize(&alias.address) != wanted);
	Ok(())
}

pub(super) fn member_add(
	current: &Config,
	file: &mut AliasesFile,
	address: &str,
	member: &str,
	origin: &Origin,
	known: Option<&Known>,
) -> Result<(), AliasError> {
	find(file, address, origin, known)?;
	member_or_sender("member", member)?;
	if origin.is_api() {
		let known = Known::open(current).map_err(AliasError::Io)?;
		api_member(&known, origin, member)?;
	}
	let member = normalize(member);
	caps::check_member_add(current, address)?;
	let alias = find(file, address, origin, known)?;
	if alias
		.members
		.iter()
		.any(|existing| normalize(existing) == member)
	{
		return Err(AliasError::Exists(format!(
			"alias {address} already has member {member}"
		)));
	}
	alias.members.push(member);
	Ok(())
}

pub(super) fn member_remove(
	file: &mut AliasesFile,
	address: &str,
	member: &str,
	origin: &Origin,
	known: Option<&Known>,
) -> Result<(), AliasError> {
	let alias = find(file, address, origin, known)?;
	if alias.members.len() == 1 {
		return Err(invalid(format!(
			"alias {address} would have no members; use `alias remove` instead"
		)));
	}
	let wanted = normalize(member);
	let before = alias.members.len();
	alias
		.members
		.retain(|existing| normalize(existing) != wanted);
	if alias.members.len() == before {
		return Err(invalid(format!("alias {address} has no member {member}")));
	}
	alias.members.sort();
	Ok(())
}

pub(super) fn sender_add(
	file: &mut AliasesFile,
	address: &str,
	sender: &str,
	origin: &Origin,
	known: Option<&Known>,
) -> Result<(), AliasError> {
	member_or_sender("sender", sender)?;
	if !domain_of(sender).is_some_and(|domain| origin.admits_domain(&domain)) {
		return Err(outside("sender"));
	}
	let sender = normalize(sender);
	let alias = find(file, address, origin, known)?;
	if alias
		.senders
		.iter()
		.any(|existing| normalize(existing) == sender)
	{
		return Err(AliasError::Exists(format!(
			"alias {address} already allows sender {sender}"
		)));
	}
	alias.senders.push(sender);
	Ok(())
}

pub(super) fn sender_remove(
	file: &mut AliasesFile,
	address: &str,
	sender: &str,
	origin: &Origin,
	known: Option<&Known>,
) -> Result<(), AliasError> {
	let alias = find(file, address, origin, known)?;
	let wanted = normalize(sender);
	let before = alias.senders.len();
	alias
		.senders
		.retain(|existing| normalize(existing) != wanted);
	if alias.senders.len() == before {
		return Err(invalid(format!("alias {address} has no sender {sender}")));
	}
	Ok(())
}
