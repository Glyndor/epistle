//! The rules of the alias state: what a [`Change`] may do to an
//! [`AliasesFile`], for the operator and for a key of the API.
//!
//! The operator's messages are the ones `epistle alias` has always printed.
//! A key of the API gets the same messages, with two differences that are the
//! point of it: where a message would tell a confined key something about
//! what lies outside its domains (that a domain is hosted, that an address
//! belongs to an account), the answer is one message for "it does not exist"
//! and "it is not yours"; and the members are checked against the accounts
//! that exist.

use crate::config::{Alias, Config};
use crate::util::address::normalize;
use crate::util::address_reason;

use super::collide::Known;
use super::{AliasError, Change, NewAlias, Origin, caps};
use crate::aliases::file::AliasesFile;

/// The role addresses RFC 2142 and RFC 5321 name. An operator may point them
/// at an alias; a key of the API may not, since the mail of a role address is
/// the first thing a hijack of a domain would want.
const ROLE_LOCAL_PARTS: &[&str] = &[
	"postmaster",
	"abuse",
	"hostmaster",
	"webmaster",
	"security",
	"noc",
];

/// The most members one request may name, whatever the caps say.
pub const MAX_MEMBERS: usize = 100;

fn invalid(message: impl Into<String>) -> AliasError {
	AliasError::Invalid(message.into())
}

/// The one message a confined key gets for an address outside its domains.
fn outside(label: &str) -> AliasError {
	invalid(format!(
		"{label} is not an address of the domains this key may use"
	))
}

/// Apply `change` to `file` for `origin`. `current` is the configuration the
/// server runs with `file`.
pub fn apply(
	current: &Config,
	file: &mut AliasesFile,
	change: &Change,
	origin: &Origin,
) -> Result<(), AliasError> {
	match change {
		Change::Add(new) => add(current, file, new, origin),
		Change::Remove { address } => remove(file, address, origin),
		Change::MemberAdd { address, member } => member_add(current, file, address, member, origin),
		Change::MemberRemove { address, member } => member_remove(file, address, member, origin),
		Change::SenderAdd { address, sender } => sender_add(file, address, sender, origin),
		Change::SenderRemove { address, sender } => sender_remove(file, address, sender, origin),
	}
}

/// The domain of `address` when it parses.
fn domain_of(address: &str) -> Option<String> {
	address_reason::parse(address)
		.ok()
		.map(|parsed| parsed.domain().to_ascii_lowercase())
}

/// A member or sender address: it parses and is not empty.
fn member_or_sender(label: &str, raw: &str) -> Result<(), AliasError> {
	let parsed =
		address_reason::parse(raw).map_err(|why| invalid(format!("{label} address: {why}")))?;
	if parsed.local_part().is_empty() || parsed.domain().is_empty() {
		return Err(invalid(format!("{label} address {raw} is empty")));
	}
	Ok(())
}

/// A member of a key's alias: the address of an account that exists, inside
/// the domains the key may use. Both reasons give the same answer.
fn api_member(known: &Known, origin: &Origin, raw: &str) -> Result<(), AliasError> {
	let label = format!("member {}", address_reason::shorten(raw));
	let normalized = normalize(raw);
	let domain = domain_of(&normalized);
	let in_scope = domain
		.as_deref()
		.is_some_and(|domain| origin.admits_domain(domain));
	if in_scope && known.is_account_address(&normalized) {
		Ok(())
	} else {
		Err(invalid(format!(
			"{label} is not an address of a local account"
		)))
	}
}

fn add(
	current: &Config,
	file: &mut AliasesFile,
	new: &NewAlias,
	origin: &Origin,
) -> Result<(), AliasError> {
	let parsed = address_reason::parse(&new.address)
		.map_err(|why| invalid(format!("alias address: {why}")))?;
	let domain = parsed.domain().to_ascii_lowercase();
	let hosted = current
		.domains
		.iter()
		.any(|configured| configured.eq_ignore_ascii_case(&domain));
	let confined = matches!(
		origin,
		Origin::Api {
			confined_to: Some(_)
		}
	);
	if !hosted || !origin.admits_domain(&domain) {
		return Err(if confined {
			outside("alias address")
		} else {
			invalid(format!(
				"alias address: {}",
				address_reason::not_handled(&domain)
			))
		});
	}
	if origin.is_api()
		&& ROLE_LOCAL_PARTS
			.iter()
			.any(|role| parsed.local_part().eq_ignore_ascii_case(role))
	{
		return Err(invalid(format!(
			"alias address {} is a role address and is not available to the API",
			normalize(&new.address)
		)));
	}
	if file.alias(&new.address).is_some() {
		return Err(AliasError::Exists(format!(
			"alias {} already exists",
			new.address
		)));
	}
	let known = Known::open(current).map_err(AliasError::Io)?;
	let address = normalize(&new.address);
	if let Some(why) = known.holder_of(&address) {
		return Err(invalid(why));
	}
	if new.members.is_empty() {
		return Err(invalid(format!("alias {} has no members", new.address)));
	}
	if new.members.len() > MAX_MEMBERS {
		return Err(invalid(format!(
			"alias {} names more than {MAX_MEMBERS} members",
			new.address
		)));
	}
	for member in &new.members {
		if origin.is_api() {
			api_member(&known, origin, member)?;
		}
		member_or_sender("member", member)?;
	}
	for sender in &new.senders {
		member_or_sender("sender", sender)?;
	}
	let mut members: Vec<String> = Vec::with_capacity(new.members.len());
	for member in &new.members {
		let member = normalize(member);
		if !members.contains(&member) {
			members.push(member);
		}
	}
	let alias = Alias {
		address,
		members,
		senders: dedup(&new.senders),
		hidden: new.hidden,
		list_id: new.list_id.clone(),
	};
	alias.validate().map_err(AliasError::Invalid)?;
	caps::check_add(current, &alias)?;
	file.aliases.push(alias);
	Ok(())
}

fn dedup(addresses: &[String]) -> Vec<String> {
	let mut out: Vec<String> = Vec::with_capacity(addresses.len());
	for address in addresses {
		let address = normalize(address);
		if !out.contains(&address) {
			out.push(address);
		}
	}
	out
}

/// The alias `address` of `file` for a change by `origin`: an alias outside
/// the domains of a confined key is as absent as one that does not exist.
fn find<'a>(
	file: &'a mut AliasesFile,
	address: &str,
	origin: &Origin,
) -> Result<&'a mut Alias, AliasError> {
	let absent = || AliasError::NotFound(format!("alias {address} not found"));
	if !domain_of(address).is_some_and(|domain| origin.admits_domain(&domain)) {
		return Err(absent());
	}
	file.alias_mut(address).ok_or_else(absent)
}

fn remove(file: &mut AliasesFile, address: &str, origin: &Origin) -> Result<(), AliasError> {
	find(file, address, origin)?;
	let wanted = normalize(address);
	file.aliases
		.retain(|alias| normalize(&alias.address) != wanted);
	Ok(())
}

fn member_add(
	current: &Config,
	file: &mut AliasesFile,
	address: &str,
	member: &str,
	origin: &Origin,
) -> Result<(), AliasError> {
	find(file, address, origin)?;
	member_or_sender("member", member)?;
	if origin.is_api() {
		let known = Known::open(current).map_err(AliasError::Io)?;
		api_member(&known, origin, member)?;
	}
	let member = normalize(member);
	caps::check_member_add(current, address)?;
	let alias = find(file, address, origin)?;
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

fn member_remove(
	file: &mut AliasesFile,
	address: &str,
	member: &str,
	origin: &Origin,
) -> Result<(), AliasError> {
	let alias = find(file, address, origin)?;
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

fn sender_add(
	file: &mut AliasesFile,
	address: &str,
	sender: &str,
	origin: &Origin,
) -> Result<(), AliasError> {
	member_or_sender("sender", sender)?;
	let sender = normalize(sender);
	let alias = find(file, address, origin)?;
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

fn sender_remove(
	file: &mut AliasesFile,
	address: &str,
	sender: &str,
	origin: &Origin,
) -> Result<(), AliasError> {
	let alias = find(file, address, origin)?;
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
