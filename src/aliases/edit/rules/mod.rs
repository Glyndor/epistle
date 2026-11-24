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

mod guard;
mod members;

pub use guard::all_inside;
use guard::{api_member, member_or_sender, refuse_role_address, refuse_tagged};
use members::{member_add, member_remove, remove, sender_add, sender_remove};

/// The most members one request may name, whatever the caps say.
pub const MAX_MEMBERS: usize = 100;

pub(super) fn invalid(message: impl Into<String>) -> AliasError {
	AliasError::Invalid(message.into())
}

/// The one message a confined key gets for an address outside its domains.
pub(super) fn outside(label: &str) -> AliasError {
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

pub(super) fn dedup(addresses: &[String]) -> Vec<String> {
	let mut out: Vec<String> = Vec::with_capacity(addresses.len());
	for address in addresses {
		let address = normalize(address);
		if !out.contains(&address) {
			out.push(address);
		}
	}
	out
}
