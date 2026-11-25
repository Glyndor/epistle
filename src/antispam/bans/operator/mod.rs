//! What an operator does to the ban store: list the bans, ban an address or
//! a network, lift a ban, and keep the allow list.
//!
//! `epistle ban` and the `/api/v1/bans` routes both run this code, so a ban
//! made by one is the ban the other makes. The store behind it is
//! [`BanAdmin`]; [`PgBanStore`](super::PgBanStore) is the one that runs in
//! production, and the tests use an in-memory one.
//!
//! The rules of an operation live here and not in either caller: which
//! durations a ban may last, that an allow-listed address cannot be banned,
//! how many bans and allow-list entries there may be, and what a caller that
//! is not the operator at a terminal may not do ([`Limits`]).

use std::future::Future;
use std::net::IpAddr;
use std::pin::Pin;

use crate::cidr::Cidr;

use super::{BanRow, BanTarget, UnbanTarget};

mod pg;

/// Default length of a manual ban when no duration is given.
pub const DEFAULT_BAN_SECS: u64 = 24 * 3600;
/// Longest manual ban accepted: keeps the end time far from timestamp limits.
pub const MAX_BAN_SECS: u64 = 10 * 365 * 24 * 3600;
/// Most manual bans a key may have in force at once. The bans the listeners
/// raise on their own do not count: they cannot use up this room.
pub const API_MAX_MANUAL_BANS: usize = 10_000;
/// Most network bans (a block of addresses, not one) a key may have in force.
pub const API_MAX_BAN_NETWORKS: usize = 100;
/// Most entries a key may leave on the allow list.
pub const API_MAX_ALLOW_ENTRIES: usize = 1_000;
/// Most network blocks (not one address) a key may leave on the allow list.
pub const API_MAX_ALLOW_NETWORKS: usize = 100;

/// A failure of the store itself. The text is for a log or a terminal and
/// can name the database; a caller that answers a network client does not
/// repeat it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreError(pub String);

impl std::fmt::Display for StoreError {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		f.write_str(&self.0)
	}
}

impl std::error::Error for StoreError {}

/// A boxed answer of the store, so the trait can be used as an object.
pub type Answer<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// The operator side of the ban store.
pub trait BanAdmin: std::fmt::Debug + Send + Sync {
	/// Every ban in force at `now`, ordered by subject.
	fn list_bans(&self, now: u64) -> Answer<'_, Vec<BanRow>>;
	/// Ban `target` until `until`, unless `room` is used up. The count and the
	/// write are one step the store makes atomically, so requests that arrive
	/// together cannot all pass a count they would each have left room in. A
	/// manual ban of the same subject being renewed needs no room; a ban the
	/// listeners raised that becomes manual does.
	fn add_ban_within(
		&self,
		target: BanTarget,
		now: u64,
		until: u64,
		room: BanRoom,
	) -> Answer<'_, Placed>;
	/// Lift the ban on `target` and clear its failures: `(bans, failures)`.
	fn remove_ban(&self, target: UnbanTarget) -> Answer<'_, (u64, u64)>;
	/// The allow list, canonical and sorted.
	fn allow_list(&self) -> Answer<'_, Vec<String>>;
	/// Add a block to the allow list unless `room` is used up, counting and
	/// writing as one atomic step like [`BanAdmin::add_ban_within`].
	fn allow_add_within(&self, cidr: Cidr, room: AllowRoom) -> Answer<'_, AllowPlaced>;
	/// Take a block off the allow list; false when it was not there.
	fn allow_remove(&self, cidr: Cidr) -> Answer<'_, bool>;
}

/// The room a manual ban may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BanRoom {
	/// Most manual bans in force.
	pub max_manual: usize,
	/// Most manual bans of a network in force.
	pub max_networks: usize,
}

/// What the store did with a ban.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Placed {
	/// The ban is in force.
	Done,
	/// Nothing was written: the named count was reached.
	Full(&'static str),
}

/// The room an allow-list entry may take.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AllowRoom {
	/// Most entries on the list.
	pub max_entries: usize,
	/// Most entries that are networks and not one address.
	pub max_networks: usize,
}

/// What the store did with an allow-list entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AllowPlaced {
	/// The block joined the list.
	Added,
	/// The block was there.
	Already,
	/// Nothing was written: the named count was reached.
	Full(&'static str),
}

/// What the caller of an operation may not do. The operator at a terminal
/// has the widest reach; a key on the management API is held to a narrower
/// one, because a leaked key must not be able to lock out a whole network, to
/// exempt one from every ban, to fill the store, or to lift what it could not
/// have made.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Limits {
	/// The shortest prefix of an IPv4 network that may be banned or lifted.
	pub ban_min_v4: u8,
	/// The shortest prefix of an IPv6 network that may be banned or lifted.
	pub ban_min_v6: u8,
	/// The shortest prefix of an IPv4 block that may join or leave the allow list.
	pub allow_min_v4: u8,
	/// The shortest prefix of an IPv6 block that may join or leave the allow list.
	pub allow_min_v6: u8,
	/// Most manual bans in force; the automatic ones are not counted.
	pub max_manual_bans: usize,
	/// Most manual bans of a network (not of one address) in force.
	pub max_ban_networks: usize,
	/// Most entries on the allow list.
	pub max_allow_entries: usize,
	/// Most network blocks (not single addresses) on the allow list.
	pub max_allow_networks: usize,
}

impl Limits {
	/// The operator at a terminal: any network but the whole internet can be
	/// banned (see [`BanTarget::parse`]), any block can be allowed, and no
	/// count stops the operator.
	pub const fn operator() -> Self {
		Limits {
			ban_min_v4: 1,
			ban_min_v6: 1,
			allow_min_v4: 0,
			allow_min_v6: 0,
			max_manual_bans: usize::MAX,
			max_ban_networks: usize::MAX,
			max_allow_entries: usize::MAX,
			max_allow_networks: usize::MAX,
		}
	}

	/// A key on the management API: nothing wider than a /16 of IPv4 or a /32
	/// of IPv6, a network a provider hands one customer, can be banned,
	/// allowed or lifted, and the counts above are its room.
	pub const fn api() -> Self {
		Limits {
			ban_min_v4: 16,
			ban_min_v6: 32,
			allow_min_v4: 16,
			allow_min_v6: 32,
			max_manual_bans: API_MAX_MANUAL_BANS,
			max_ban_networks: API_MAX_BAN_NETWORKS,
			max_allow_entries: API_MAX_ALLOW_ENTRIES,
			max_allow_networks: API_MAX_ALLOW_NETWORKS,
		}
	}
}

/// Why an operation was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Refusal {
	/// The address is on the allow list, which overrides every ban.
	AllowListed(IpAddr),
	/// The block is wider than the caller may name.
	TooWide(String),
	/// The subject has no ban and no failure record.
	NoBan(String),
	/// The block is not on the allow list.
	NotAllowed(String),
	/// A count the caller may not pass is reached.
	Full(&'static str),
	/// The store failed.
	Store(StoreError),
}

impl std::fmt::Display for Refusal {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Refusal::AllowListed(ip) => write!(
				f,
				"{ip} is on the allow list, which overrides every ban; remove it there first"
			),
			Refusal::TooWide(what) => f.write_str(what),
			Refusal::NoBan(target) => write!(f, "{target} has no ban or failure record"),
			Refusal::NotAllowed(cidr) => write!(f, "{cidr} is not on the allow list"),
			Refusal::Full(what) => write!(
				f,
				"there are already as many {what} as this caller may keep"
			),
			Refusal::Store(error) => error.fmt(f),
		}
	}
}

impl From<StoreError> for Refusal {
	fn from(error: StoreError) -> Self {
		Refusal::Store(error)
	}
}

/// Parse `<number><unit>` into seconds (`s`, `m`, `h`, `d`, `w`; a bare number
/// is seconds). Zero and anything above ten years are refused.
pub fn parse_duration(text: &str) -> Result<u64, String> {
	let text = text.trim();
	let split = text
		.find(|c: char| !c.is_ascii_digit())
		.unwrap_or(text.len());
	let (digits, unit) = text.split_at(split);
	let count: u64 = digits
		.parse()
		.map_err(|_| format!("{text:?} is not a duration; use a number and a unit, like 24h"))?;
	let unit_secs = match unit {
		"" | "s" => 1,
		"m" => 60,
		"h" => 3600,
		"d" => 86_400,
		"w" => 604_800,
		other => {
			return Err(format!(
				"unknown duration unit {other:?}; use s, m, h, d or w"
			));
		}
	};
	let secs = count.saturating_mul(unit_secs);
	if secs == 0 || secs > MAX_BAN_SECS {
		return Err("a ban lasts between 1 second and 10 years".to_string());
	}
	Ok(secs)
}

/// The prefix `cidr` has to have to be no wider than `limits` allow.
fn too_wide(cidr: &Cidr, v4: u8, v6: u8, what: &str) -> Option<Refusal> {
	let least = if cidr.network().is_ipv4() { v4 } else { v6 };
	(cidr.prefix() < least).then(|| {
		Refusal::TooWide(format!(
			"{cidr} is wider than this caller may {what}: the prefix is at least /{least}"
		))
	})
}

/// A ban made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Banned {
	/// What was banned, as the listing prints it.
	pub target: String,
	/// Unix seconds the ban ends.
	pub until: u64,
}

/// Ban `target` for `duration` seconds (a day when none), as of `now`.
pub async fn ban(
	store: &dyn BanAdmin,
	target: BanTarget,
	duration: Option<u64>,
	now: u64,
	limits: Limits,
) -> Result<Banned, Refusal> {
	if let BanTarget::Cidr(cidr) = &target
		&& let Some(refusal) = too_wide(cidr, limits.ban_min_v4, limits.ban_min_v6, "ban")
	{
		return Err(refusal);
	}
	if let BanTarget::Ip(ip) = target
		&& store
			.allow_list()
			.await?
			.iter()
			.any(|entry| Cidr::parse(entry).is_some_and(|cidr| cidr.contains(ip)))
	{
		return Err(Refusal::AllowListed(ip));
	}
	let until = now.saturating_add(duration.unwrap_or(DEFAULT_BAN_SECS));
	let room = BanRoom {
		max_manual: limits.max_manual_bans,
		max_networks: limits.max_ban_networks,
	};
	if let Placed::Full(what) = store.add_ban_within(target, now, until, room).await? {
		return Err(Refusal::Full(what));
	}
	Ok(Banned {
		target: target.to_string(),
		until,
	})
}

/// A ban lifted.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Unbanned {
	/// What was named, as the listing prints it.
	pub target: String,
	/// Bans removed.
	pub bans: u64,
	/// Failure records cleared.
	pub failures: u64,
}

/// Lift the ban on `target` and clear its failures. A caller may lift a
/// network only if it could have banned one that wide.
pub async fn unban(
	store: &dyn BanAdmin,
	target: UnbanTarget,
	limits: Limits,
) -> Result<Unbanned, Refusal> {
	if let UnbanTarget::Address(BanTarget::Cidr(cidr)) = &target
		&& let Some(refusal) = too_wide(cidr, limits.ban_min_v4, limits.ban_min_v6, "lift")
	{
		return Err(refusal);
	}
	let name = target.to_string();
	let (bans, failures) = store.remove_ban(target).await?;
	if bans == 0 && failures == 0 {
		return Err(Refusal::NoBan(name));
	}
	Ok(Unbanned {
		target: name,
		bans,
		failures,
	})
}

/// Add `cidr` to the allow list: true when it was not there.
pub async fn allow(store: &dyn BanAdmin, cidr: Cidr, limits: Limits) -> Result<bool, Refusal> {
	if let Some(refusal) = too_wide(&cidr, limits.allow_min_v4, limits.allow_min_v6, "allow") {
		return Err(refusal);
	}
	let room = AllowRoom {
		max_entries: limits.max_allow_entries,
		max_networks: limits.max_allow_networks,
	};
	match store.allow_add_within(cidr, room).await? {
		AllowPlaced::Added => Ok(true),
		AllowPlaced::Already => Ok(false),
		AllowPlaced::Full(what) => Err(Refusal::Full(what)),
	}
}

/// Take `cidr` off the allow list. A caller may remove a block only if it
/// could have added one that wide.
pub async fn disallow(store: &dyn BanAdmin, cidr: Cidr, limits: Limits) -> Result<(), Refusal> {
	if let Some(refusal) = too_wide(
		&cidr,
		limits.allow_min_v4,
		limits.allow_min_v6,
		"remove from the allow list",
	) {
		return Err(refusal);
	}
	if store.allow_remove(cidr).await? {
		Ok(())
	} else {
		Err(Refusal::NotAllowed(cidr.to_string()))
	}
}

#[cfg(test)]
pub(crate) mod tests;
