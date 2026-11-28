//! What a key reaches, and whether one reach holds another.

use super::World;
use crate::api::api_keys::{ApiKey, Scope};
use crate::cidr::Cidr;

/// What a key may do and where. `None` is the whole of it: every scope, every
/// domain, any network, no expiry.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Reach {
	/// The scopes held; `None` holds every one.
	pub scopes: Option<Vec<Scope>>,
	/// The domains it is confined to, lowercased; `None` reaches every one.
	pub domains: Option<Vec<String>>,
	/// Every address of the account it is bound to, when it is bound to one.
	pub account_addresses: Option<Vec<String>>,
	/// The one network it must come from; `None` is any.
	pub ip_cidr: Option<Cidr>,
	/// When it stops working; `None` never does.
	pub expires_at: Option<u64>,
}

impl Reach {
	/// The reach of `key`. A scope the build cannot read is no scope at all,
	/// and a network it cannot read is no network: the reach is never wider
	/// than the file says. `account_addresses` are those of its account.
	pub fn of_key(key: &ApiKey, account_addresses: Option<Vec<String>>) -> Self {
		Reach {
			scopes: key.reach(),
			domains: (!key.domains.is_empty())
				.then(|| key.domains.iter().map(|d| d.to_ascii_lowercase()).collect()),
			account_addresses,
			ip_cidr: key.ip_cidr.as_deref().and_then(Cidr::parse),
			expires_at: key.expires_at,
		}
	}

	/// The reach of a key that is asking to make or revoke keys, from the key as
	/// the file holds it at `now`, or `None` when it may no longer do either: it
	/// has expired, is bound to an account or no longer holds the `key` scope.
	pub fn of_maker(key: &ApiKey, now: u64) -> Option<Self> {
		let holds = key.reach().is_none_or(|held| held.contains(&Scope::Key));
		let live = key.expires_at.is_none_or(|expiry| now < expiry);
		(holds && live && key.account.is_none()).then(|| Reach::of_key(key, None))
	}

	/// This reach with the facts of the world read again, for the key `key`
	/// that is about to be written: whether the account it is bound to is
	/// still there, the addresses that account has now, and whether its
	/// domains are still hosted. An error names the fact that no longer holds.
	pub fn refreshed(&self, key: &ApiKey, world: &dyn World) -> Result<Reach, String> {
		let mut fresh = self.clone();
		if let Some(name) = key.account.as_deref() {
			if !world.account_known(name) {
				return Err(format!("--account {name}: no such account"));
			}
			fresh.account_addresses = Some(world.account_addresses(name));
		}
		if let Some(domain) = key
			.domains
			.iter()
			.find(|domain| !world.hosts(&domain.to_ascii_lowercase()))
		{
			return Err(format!("{domain} is not a domain this server hosts"));
		}
		Ok(fresh)
	}

	/// Whether this reach holds `other`: `other` has no scope this one lacks,
	/// no domain outside it, no address outside it, a network inside it and
	/// an expiry that comes first. The answer says what is wider when not.
	pub fn covers(&self, other: &Reach) -> Result<(), String> {
		match (&self.scopes, &other.scopes) {
			(Some(own), Some(wanted)) => {
				if let Some(scope) = wanted.iter().find(|scope| !own.contains(scope)) {
					return Err(format!(
						"the key does not hold the {} scope",
						scope.as_str()
					));
				}
			}
			(Some(_), None) => {
				return Err("the key asked for holds every scope".to_string());
			}
			(None, _) => {}
		}
		if let Some(own) = &self.domains {
			match &other.domains {
				// A key bound to an account reaches that account and no
				// domain, and the account is checked below.
				None if other.account_addresses.is_some() => {}
				None => {
					return Err("the key asked for reaches every domain".to_string());
				}
				Some(wanted) => {
					if let Some(domain) = wanted.iter().find(|domain| !own.contains(domain)) {
						return Err(format!("{domain} is not a domain of the key"));
					}
				}
			}
			if let Some(addresses) = &other.account_addresses
				&& !crate::api::authorization::within_domains(own, addresses)
			{
				return Err("the account is not inside the domains of the key".to_string());
			}
		}
		if let Some(own) = &self.ip_cidr {
			match &other.ip_cidr {
				Some(wanted) if own.covers(wanted) => {}
				_ => {
					return Err(format!(
						"the key is limited to {own}, and the key asked for is not limited to a network inside it"
					));
				}
			}
		}
		if let Some(own) = self.expires_at {
			match other.expires_at {
				Some(wanted) if wanted <= own => {}
				_ => {
					return Err(
						"the key expires, and the key asked for expires later or never".to_string(),
					);
				}
			}
		}
		Ok(())
	}
}

/// The key that makes a request: what it reaches and which key it is, so that
/// the store can check it is still there when the new key is written.
#[derive(Debug, Clone)]
pub struct Caller {
	reach: Reach,
	label: String,
	hash: String,
	client_ip: Option<std::net::IpAddr>,
}

impl Caller {
	/// A caller with `reach`, named `label`, whose secret hashes to `hash`,
	/// that came from `client_ip`.
	pub fn new(
		reach: Reach,
		label: String,
		hash: String,
		client_ip: Option<std::net::IpAddr>,
	) -> Self {
		Caller {
			reach,
			label,
			hash,
			client_ip,
		}
	}

	/// What the caller reaches.
	pub fn reach(&self) -> &Reach {
		&self.reach
	}

	/// The label of the caller's key.
	pub fn label(&self) -> &str {
		&self.label
	}

	/// The digest of the caller's key.
	pub fn hash(&self) -> &str {
		&self.hash
	}

	/// The peer IP the request came from, `None` when the listener did not
	/// report one: a key pinned to a network then admits nothing.
	pub fn client_ip(&self) -> Option<std::net::IpAddr> {
		self.client_ip
	}
}
