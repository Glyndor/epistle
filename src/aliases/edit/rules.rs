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
///
/// It holds the ones RFC 2142 names and the ones a certificate authority or an
/// ACME client mails to prove control of a domain (`admin`, `administrator`,
/// `hostmaster`, `postmaster`, `webmaster`), with the other names a report or
/// a bounce goes to.
const ROLE_LOCAL_PARTS: &[&str] = &[
	"postmaster",
	"abuse",
	"hostmaster",
	"webmaster",
	"security",
	"noc",
	"admin",
	"administrator",
	"root",
	"ssladmin",
	"tlsrpt",
	"mailer-daemon",
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
	refuse_role_address(change.address(), origin)?;
	// What a confined key may reach depends on the accounts as they are now.
	let known = if origin.is_confined() && !matches!(change, Change::Add(_)) {
		Some(Known::open(current).map_err(AliasError::Io)?)
	} else {
		None
	};
	let known = known.as_ref();
	match change {
		Change::Add(new) => add(current, file, new, origin),
		Change::Remove { address } => remove(file, address, origin, known),
		Change::MemberAdd { address, member } => {
			member_add(current, file, address, member, origin, known)
		}
		Change::MemberRemove { address, member } => {
			member_remove(file, address, member, origin, known)
		}
		Change::SenderAdd { address, sender } => sender_add(file, address, sender, origin, known),
		Change::SenderRemove { address, sender } => {
			sender_remove(file, address, sender, origin, known)
		}
	}
}

/// The local part of `local` before the first sub-address separator, as the
/// directory strips it: `postmaster+x` is `postmaster` for delivery. A local
/// part that starts with a separator has no base and stays as it is.
fn base_local(local: &str) -> &str {
	let cut = crate::smtp::directory::DEFAULT_SUBADDRESS_SEPARATORS
		.iter()
		.filter_map(|separator| local.find(*separator))
		.min();
	match cut {
		Some(cut) if cut > 0 => &local[..cut],
		_ => local,
	}
}

/// Whether `address` is a role address, with or without a sub-address tag.
fn is_role_address(address: &str) -> bool {
	let Ok(parsed) = address_reason::parse(address) else {
		return false;
	};
	let base = base_local(parsed.local_part());
	ROLE_LOCAL_PARTS
		.iter()
		.any(|role| base.eq_ignore_ascii_case(role))
}

/// The one refusal of a role address for every change a key makes: making an
/// alias on one, and also removing or editing one the operator made, since
/// the mail of a role address is the first thing a hijack would want.
fn refuse_role_address(address: &str, origin: &Origin) -> Result<(), AliasError> {
	if origin.is_api() && is_role_address(address) {
		return Err(invalid(format!(
			"alias address {} is a role address and is not available to the API",
			normalize(address)
		)));
	}
	Ok(())
}

/// Whether every address in `addresses` is inside the reach of `admits`, and
/// so is every other address of the account that holds it: an address in an
/// admitted domain whose account also has one outside is not inside. An
/// address no account holds is judged by its own domain.
pub fn all_inside<'a>(
	addresses: impl IntoIterator<Item = &'a String>,
	admits: &dyn Fn(&str) -> bool,
	account_of: &dyn Fn(&str) -> Option<Vec<String>>,
) -> bool {
	let inside = |address: &str| domain_of(address).is_some_and(|domain| admits(&domain));
	addresses.into_iter().all(|address| {
		inside(address)
			&& account_of(&normalize(address))
				.is_none_or(|siblings| siblings.iter().all(|sibling| inside(sibling)))
	})
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
	// The account must lie entirely inside the key's domains, as it must to
	// be seen or changed through the accounts routes: an address of one of
	// its that is inside is not enough when another is not.
	let whole_account = known
		.addresses_of_account_holding(&normalized)
		.is_some_and(|addresses| {
			addresses.iter().all(|address| {
				domain_of(address).is_some_and(|domain| origin.admits_domain(&domain))
			})
		});
	if in_scope && whole_account {
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
	if origin.is_api() {
		refuse_tagged(&address)?;
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

/// An alias is looked up before the sub-address tag of a recipient is
/// stripped, so an alias on `bob+x@d` takes what would go to `bob@d`, and one
/// made before the account `bob` exists takes its mail once it does. A key
/// may not make an alias address with a tag at all, whether or not an account
/// of that base exists; the command keeps the choice.
fn refuse_tagged(address: &str) -> Result<(), AliasError> {
	let tagged = address_reason::parse(address).is_ok_and(|parsed| {
		parsed
			.local_part()
			.contains(crate::smtp::directory::DEFAULT_SUBADDRESS_SEPARATORS.as_slice())
	});
	if tagged {
		return Err(invalid(format!(
			"alias address {} is a tagged form of another address, which is not available to the API",
			normalize(address)
		)));
	}
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
	known: Option<&Known>,
) -> Result<&'a mut Alias, AliasError> {
	let absent = || AliasError::NotFound(format!("alias {address} not found"));
	if !domain_of(address).is_some_and(|domain| origin.admits_domain(&domain)) {
		return Err(absent());
	}
	let alias = file.alias_mut(address).ok_or_else(absent)?;
	// An alias with a member or a sender outside the key's domains, or whose
	// account reaches outside them, is another tenant's as far as the key can
	// tell.
	let admits = |domain: &str| origin.admits_domain(domain);
	let account_of =
		|address: &str| known.and_then(|known| known.addresses_of_account_holding(address));
	if !all_inside(&alias.members, &admits, &account_of)
		|| !all_inside(&alias.senders, &admits, &account_of)
	{
		return Err(absent());
	}
	Ok(alias)
}

fn remove(
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

fn member_add(
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

fn member_remove(
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

fn sender_add(
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

fn sender_remove(
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
