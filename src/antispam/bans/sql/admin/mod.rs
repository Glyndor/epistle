//! Operator side of the ban store: list, add and remove bans, and manage the
//! allow list. The CLI uses these, and the check path in `src/antispam/bans/sql/mod.rs` uses the
//! allow-list helpers so an allow-listed client is never banned.
//!
//! Unlike the listener-facing [`BanStore`] methods, which fail open, these
//! return the database error: an operator who types `ban add` must be told
//! when nothing was written.

use super::*;
use crate::antispam::bans::operator::{AllowPlaced, AllowRoom, BanRoom, Placed};
use crate::cidr::Cidr;

/// Subject prefix for a ban on a whole network.
const CIDR_PREFIX: &str = "cidr:";

/// Reason stored on a ban the operator created by hand.
pub const MANUAL_REASON: &str = "manual ban";

/// What a manual ban applies to: one address or a network.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum BanTarget {
	/// A single client address, stored as the same `ip:<addr>` subject the
	/// listeners use, so an automatic and a manual ban share one row.
	Ip(IpAddr),
	/// A network, stored as `cidr:<network>/<prefix>` and matched against
	/// every client address on each check.
	Cidr(Cidr),
}

impl BanTarget {
	/// Parse an address or CIDR. A `/32` or `/128` is the single address.
	/// A zero-length prefix is refused: it would ban every client, the
	/// operator's own session included.
	pub fn parse(spec: &str) -> Result<Self, String> {
		let cidr = Cidr::parse(spec).ok_or_else(|| Cidr::refusal(spec))?;
		if cidr.is_host() {
			return Ok(Self::Ip(cidr.network()));
		}
		if cidr.prefix() == 0 {
			return Err("refusing to ban every address (prefix length 0)".to_string());
		}
		Ok(Self::Cidr(cidr))
	}

	/// The `auth_ban.subject` this target is stored under.
	pub fn subject(&self) -> String {
		match self {
			Self::Ip(ip) => subject_ip(*ip),
			Self::Cidr(cidr) => format!("{CIDR_PREFIX}{cidr}"),
		}
	}
}

impl std::fmt::Display for BanTarget {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Ip(ip) => write!(f, "{ip}"),
			Self::Cidr(cidr) => write!(f, "{cidr}"),
		}
	}
}

/// The advisory lock every write that counts before it writes takes, so two
/// of them never count the same room.
const ADMIN_WRITE_LOCK: i64 = 0x6570_6973_7462_616e;

/// A cap as the signed number the database counts in.
fn count_of(cap: usize) -> i64 {
	i64::try_from(cap).unwrap_or(i64::MAX)
}

/// Subject prefix for a ban on one account as seen from one client.
const PAIR_PREFIX: &str = "pair:";
/// Subject prefix for a ban on one account from every client.
const ACCOUNT_PREFIX: &str = "account:";

/// What `ban remove` lifts: an address or network, or one of the subjects the
/// listeners ban on their own, written as `ban list` prints it. Lifting a ban
/// clears that subject's rows and nothing else.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UnbanTarget {
	/// An address or network, as `ban add` takes it.
	Address(BanTarget),
	/// One account as seen from one client: a `pair:<login>|<client>` subject.
	Pair(String),
	/// One account from every client: an `account:<login>` subject.
	Account(String),
}

impl UnbanTarget {
	/// Parse an address or network, or a subject exactly as `ban list` prints
	/// it: `ip:<addr>`, `cidr:<net>`, `pair:<login>|<client>` (the client is an
	/// address or `unknown`) or `account:<login>`.
	pub fn parse(spec: &str) -> Result<Self, String> {
		if let Some(rest) = spec.strip_prefix(PAIR_PREFIX) {
			let malformed = || {
				format!(
					"{:?} is not a pair; write it as `ban list` prints it, for example \
					 \"pair:alice@example.org|203.0.113.9\"",
					crate::util::address_reason::shorten(spec)
				)
			};
			let (login, client) = rest.rsplit_once('|').ok_or_else(malformed)?;
			let ip = match client {
				"unknown" => None,
				client => Some(client.parse().map_err(|_| malformed())?),
			};
			return Self::pair(login, ip);
		}
		if let Some(login) = spec.strip_prefix(ACCOUNT_PREFIX) {
			return Ok(Self::Account(subject_account(&parse_login(login)?)));
		}
		let address = spec
			.strip_prefix("ip:")
			.or_else(|| spec.strip_prefix(CIDR_PREFIX))
			.unwrap_or(spec);
		if Cidr::parse(address).is_none() {
			return Err(format!(
				"{}; or name an account ban as `ban list` prints it, for example \
				 \"pair:alice@example.org|203.0.113.9\" or \"account:alice@example.org\"",
				Cidr::refusal(spec)
			));
		}
		BanTarget::parse(address).map(Self::Address)
	}

	/// The pair ban on `login` as seen from `ip`. An IPv6 address names the
	/// /64 its failures are counted under (see [`subject_pair`]).
	pub fn pair(login: &str, ip: Option<IpAddr>) -> Result<Self, String> {
		Ok(Self::Pair(subject_pair(&parse_login(login)?, ip)))
	}

	/// The `auth_ban` and `auth_failure` subjects this target clears. For an
	/// address that includes the /64 an IPv6 client is counted under (see
	/// [`subject_client`]).
	pub(crate) fn subjects(&self) -> Vec<String> {
		match self {
			Self::Address(target @ BanTarget::Ip(ip)) => {
				vec![target.subject(), subject_client(*ip)]
			}
			Self::Address(target) => vec![target.subject()],
			Self::Pair(subject) | Self::Account(subject) => vec![subject.clone()],
		}
	}
}

impl From<BanTarget> for UnbanTarget {
	fn from(target: BanTarget) -> Self {
		Self::Address(target)
	}
}

impl std::fmt::Display for UnbanTarget {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
		match self {
			Self::Address(target) => write!(f, "{target}"),
			Self::Pair(subject) | Self::Account(subject) => f.write_str(subject),
		}
	}
}

/// Check a login named on the command line and return it lowercased, the
/// spelling ban subjects use. Empty logins and logins with whitespace or
/// control characters are refused: no account has one.
pub fn parse_login(login: &str) -> Result<String, String> {
	if login.is_empty() {
		return Err("the login is empty".to_string());
	}
	if login.chars().any(|c| c.is_whitespace() || c.is_control()) {
		return Err(format!(
			"{:?} is not a login: it contains whitespace or a control character",
			crate::util::address_reason::shorten(login)
		));
	}
	Ok(login.to_ascii_lowercase())
}

/// Parse one allow-list entry into its canonical `network/prefix` form.
pub fn parse_allow(spec: &str) -> Result<Cidr, String> {
	Cidr::parse(spec).ok_or_else(|| Cidr::refusal(spec))
}

/// One active ban, as `ban list` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRow {
	/// `ip:<addr>` (the /64 for IPv6 clients), `cidr:<net>/<prefix>`,
	/// `pair:<login>|<client>` or `account:<login>`.
	pub subject: String,
	/// The rule that fired the ban, or [`MANUAL_REASON`].
	pub reason: String,
	/// Unix seconds the ban ends.
	pub until_secs: u64,
}

/// The address a `ip:<addr>` subject names, `None` for any other subject.
pub(super) fn ip_of_subject(subject: &str) -> Option<IpAddr> {
	subject.strip_prefix("ip:")?.parse().ok()
}

/// Whether `ip` falls inside any allow-list entry. Entries that do not parse
/// are skipped, never treated as matching.
pub(super) fn is_allowed(ip: IpAddr, entries: &[String]) -> bool {
	entries
		.iter()
		.filter_map(|entry| Cidr::parse(entry))
		.any(|cidr| cidr.contains(ip))
}

/// Whether the ban row `subject` applies to `ip`: the exact address, or a
/// network ban that contains it.
pub(super) fn ban_applies(subject: &str, ip: IpAddr) -> bool {
	if let Some(rest) = subject.strip_prefix(CIDR_PREFIX) {
		return Cidr::parse(rest).is_some_and(|cidr| cidr.contains(ip));
	}
	ip_of_subject(subject) == Some(ip)
}

impl PgBanStore {
	/// Every active ban, soonest subject first.
	pub async fn list_bans(&self, now_secs: u64) -> Result<Vec<BanRow>, sqlx::Error> {
		let rows: Vec<(String, i64, String)> = sqlx::query_as(
			"SELECT subject, EXTRACT(EPOCH FROM until)::BIGINT, reason \
			 FROM auth_ban WHERE until > to_timestamp($1) ORDER BY subject",
		)
		.bind(now_secs as i64)
		.fetch_all(&self.pool)
		.await?;
		Ok(rows
			.into_iter()
			.map(|(subject, until, reason)| BanRow {
				subject,
				reason,
				until_secs: until.max(0) as u64,
			})
			.collect())
	}

	/// Ban `target` until `until_secs`. An existing row for the same subject
	/// is moved to the new end time and reason, keeping its strike count.
	pub async fn add_ban(
		&self,
		target: BanTarget,
		now_secs: u64,
		until_secs: u64,
	) -> Result<(), sqlx::Error> {
		sqlx::query(
			"INSERT INTO auth_ban (subject, strikes, until, reason, created_at, updated_at) \
			 VALUES ($1, 1, to_timestamp($2), $3, to_timestamp($4), to_timestamp($4)) \
			 ON CONFLICT (subject) DO UPDATE SET \
			 until = EXCLUDED.until, reason = EXCLUDED.reason, \
			 updated_at = EXCLUDED.updated_at",
		)
		.bind(target.subject())
		.bind(until_secs as i64)
		.bind(MANUAL_REASON)
		.bind(now_secs as i64)
		.execute(&self.pool)
		.await?;
		Ok(())
	}

	/// Ban `target` until `until_secs` unless `room` is used up. The counts
	/// and the write are one transaction under a lock every such write
	/// takes, so requests that arrive together cannot each pass a count
	/// the others fill. A manual ban being renewed needs no room; a ban the
	/// listeners raised that this makes manual counts against it.
	pub async fn add_ban_within(
		&self,
		target: BanTarget,
		now_secs: u64,
		until_secs: u64,
		room: BanRoom,
	) -> Result<Placed, sqlx::Error> {
		let mut tx = self.pool.begin().await?;
		sqlx::query("SELECT pg_advisory_xact_lock($1)")
			.bind(ADMIN_WRITE_LOCK)
			.execute(&mut *tx)
			.await?;
		let renews: Option<bool> = sqlx::query_scalar(
			"SELECT reason = $2 FROM auth_ban WHERE subject = $1 AND until > to_timestamp($3)",
		)
		.bind(target.subject())
		.bind(MANUAL_REASON)
		.bind(now_secs as i64)
		.fetch_optional(&mut *tx)
		.await?;
		if renews != Some(true) {
			let (manual, networks): (i64, i64) = sqlx::query_as(
				"SELECT count(*) FILTER (WHERE reason = $1), \
				 count(*) FILTER (WHERE reason = $1 AND subject LIKE 'cidr:%') \
				 FROM auth_ban WHERE until > to_timestamp($2)",
			)
			.bind(MANUAL_REASON)
			.bind(now_secs as i64)
			.fetch_one(&mut *tx)
			.await?;
			if manual >= count_of(room.max_manual) {
				return Ok(Placed::Full("manual bans"));
			}
			if matches!(target, BanTarget::Cidr(_)) && networks >= count_of(room.max_networks) {
				return Ok(Placed::Full("banned networks"));
			}
		}
		sqlx::query(
			"INSERT INTO auth_ban (subject, strikes, until, reason, created_at, updated_at) \
			 VALUES ($1, 1, to_timestamp($2), $3, to_timestamp($4), to_timestamp($4)) \
			 ON CONFLICT (subject) DO UPDATE SET \
			 until = EXCLUDED.until, reason = EXCLUDED.reason, \
			 updated_at = EXCLUDED.updated_at",
		)
		.bind(target.subject())
		.bind(until_secs as i64)
		.bind(MANUAL_REASON)
		.bind(now_secs as i64)
		.execute(&mut *tx)
		.await?;
		tx.commit().await?;
		Ok(Placed::Done)
	}

	/// Add a block to the allow list unless `room` is used up, counting and
	/// writing in one transaction under the lock of
	/// [`PgBanStore::add_ban_within`].
	pub async fn allow_add_within(
		&self,
		cidr: Cidr,
		room: AllowRoom,
	) -> Result<AllowPlaced, sqlx::Error> {
		let mut tx = self.pool.begin().await?;
		sqlx::query("SELECT pg_advisory_xact_lock($1)")
			.bind(ADMIN_WRITE_LOCK)
			.execute(&mut *tx)
			.await?;
		let held: bool =
			sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM auth_allow WHERE cidr = $1)")
				.bind(cidr.to_string())
				.fetch_one(&mut *tx)
				.await?;
		if held {
			return Ok(AllowPlaced::Already);
		}
		let (entries, networks): (i64, i64) = sqlx::query_as(
			"SELECT count(*), \
			 count(*) FILTER (WHERE NOT ((cidr NOT LIKE '%:%' AND cidr LIKE '%/32') \
			 OR cidr LIKE '%/128')) FROM auth_allow",
		)
		.fetch_one(&mut *tx)
		.await?;
		if entries >= count_of(room.max_entries) {
			return Ok(AllowPlaced::Full("allow-list entries"));
		}
		if !cidr.is_host() && networks >= count_of(room.max_networks) {
			return Ok(AllowPlaced::Full("allowed networks"));
		}
		let result =
			sqlx::query("INSERT INTO auth_allow (cidr) VALUES ($1) ON CONFLICT DO NOTHING")
				.bind(cidr.to_string())
				.execute(&mut *tx)
				.await?;
		tx.commit().await?;
		Ok(if result.rows_affected() > 0 {
			AllowPlaced::Added
		} else {
			AllowPlaced::Already
		})
	}

	/// Lift the ban on `target` and forget its failure counter, so the next
	/// failure starts from zero. For an IPv6 address that includes the /64 its
	/// failures are counted under (see [`subject_client`]). A pair or account
	/// target clears that one subject only: the address and the other
	/// subjects keep their bans and counters. Returns
	/// `(bans removed, failures cleared)`.
	pub async fn remove_ban(
		&self,
		target: impl Into<UnbanTarget>,
	) -> Result<(u64, u64), sqlx::Error> {
		let subjects = target.into().subjects();
		let mut tx = self.pool.begin().await?;
		let bans = sqlx::query("DELETE FROM auth_ban WHERE subject = ANY($1)")
			.bind(&subjects)
			.execute(&mut *tx)
			.await?
			.rows_affected();
		let failures = sqlx::query("DELETE FROM auth_failure WHERE subject = ANY($1)")
			.bind(&subjects)
			.execute(&mut *tx)
			.await?
			.rows_affected();
		tx.commit().await?;
		Ok((bans, failures))
	}

	/// The allow list, in canonical form, sorted.
	pub async fn allow_list(&self) -> Result<Vec<String>, sqlx::Error> {
		sqlx::query_scalar("SELECT cidr FROM auth_allow ORDER BY cidr")
			.fetch_all(&self.pool)
			.await
	}

	/// Add a block to the allow list. `false` when it was already there.
	pub async fn allow_add(&self, cidr: Cidr) -> Result<bool, sqlx::Error> {
		let result =
			sqlx::query("INSERT INTO auth_allow (cidr) VALUES ($1) ON CONFLICT DO NOTHING")
				.bind(cidr.to_string())
				.execute(&self.pool)
				.await?;
		Ok(result.rows_affected() > 0)
	}

	/// Remove a block from the allow list. `false` when it was not there.
	pub async fn allow_remove(&self, cidr: Cidr) -> Result<bool, sqlx::Error> {
		let result = sqlx::query("DELETE FROM auth_allow WHERE cidr = $1")
			.bind(cidr.to_string())
			.execute(&self.pool)
			.await?;
		Ok(result.rows_affected() > 0)
	}

	/// Whether `ip` is on the allow list. A database error counts as "not
	/// allowed" (and is logged), the same fail-open posture as the checks: the
	/// ban policy keeps running rather than guessing.
	pub(super) async fn ip_allowed(&self, ip: IpAddr) -> bool {
		match self.allow_list().await {
			Ok(entries) => is_allowed(ip, &entries),
			Err(error) => {
				self.record_db_error(&error).await;
				false
			}
		}
	}
}

#[cfg(test)]
mod tests;
