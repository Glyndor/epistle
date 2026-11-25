//! What a key may name or reach: role addresses, sub-address tags, the whole
//! account of a member, and the alias a confined key can find.

use crate::config::Alias;
use crate::util::address::normalize;
use crate::util::address_reason;

use super::super::collide::Known;
use super::super::{AliasError, Origin};
use super::invalid;
use crate::aliases::file::AliasesFile;

/// The role addresses RFC 2142 and RFC 5321 name. An operator may point them
/// at an alias; a key of the API may not, since the mail of a role address is
/// the first thing a hijack of a domain would want.
///
/// It holds the ones RFC 2142 names and the ones a certificate authority or an
/// ACME client mails to prove control of a domain (`admin`, `administrator`,
/// `hostmaster`, `postmaster`, `webmaster`), with the other names a report or
/// a bounce goes to.
pub(super) const ROLE_LOCAL_PARTS: &[&str] = &[
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

/// The local part of `local` before the first sub-address separator, as the
/// directory strips it: `postmaster+x` is `postmaster` for delivery. A local
/// part that starts with a separator has no base and stays as it is.
pub(super) fn base_local(local: &str) -> &str {
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
pub(super) fn is_role_address(address: &str) -> bool {
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
pub(super) fn refuse_role_address(address: &str, origin: &Origin) -> Result<(), AliasError> {
	if origin.is_api() && is_role_address(address) {
		return Err(invalid(format!(
			"alias address {} is a role address and is not available to the API",
			normalize(address)
		)));
	}
	Ok(())
}

/// An alias is looked up before the sub-address tag of a recipient is
/// stripped, so an alias on `bob+x@d` takes what would go to `bob@d`, and one
/// made before the account `bob` exists takes its mail once it does. A key
/// may not make an alias address with a tag at all, whether or not an account
/// of that base exists; the command keeps the choice.
pub(super) fn refuse_tagged(address: &str) -> Result<(), AliasError> {
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
pub(super) fn domain_of(address: &str) -> Option<String> {
	address_reason::parse(address)
		.ok()
		.map(|parsed| parsed.domain().to_ascii_lowercase())
}

/// A member or sender address: it parses and is not empty.
pub(super) fn member_or_sender(label: &str, raw: &str) -> Result<(), AliasError> {
	let parsed =
		address_reason::parse(raw).map_err(|why| invalid(format!("{label} address: {why}")))?;
	if parsed.local_part().is_empty() || parsed.domain().is_empty() {
		return Err(invalid(format!("{label} address {raw} is empty")));
	}
	Ok(())
}

/// A member of a key's alias: the address of an account that exists, inside
/// the domains the key may use. Both reasons give the same answer.
pub(super) fn api_member(known: &Known, origin: &Origin, raw: &str) -> Result<(), AliasError> {
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

/// The alias `address` of `file` for a change by `origin`: an alias outside
/// the domains of a confined key is as absent as one that does not exist.
pub(super) fn find<'a>(
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
