//! Operator side of the ban store: list, add and remove bans, and manage the
//! allow list. The CLI uses these, and the check path in `bans_sql.rs` uses the
//! allow-list helpers so an allow-listed client is never banned.
//!
//! Unlike the listener-facing [`BanStore`] methods, which fail open, these
//! return the database error: an operator who types `ban add` must be told
//! when nothing was written.

use super::*;
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
		let cidr = Cidr::parse(spec)
			.ok_or_else(|| format!("{spec:?} is not an IP address or CIDR block"))?;
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

/// Parse one allow-list entry into its canonical `network/prefix` form.
pub fn parse_allow(spec: &str) -> Result<Cidr, String> {
	Cidr::parse(spec).ok_or_else(|| format!("{spec:?} is not an IP address or CIDR block"))
}

/// One active ban, as `ban list` prints it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanRow {
	/// `ip:<addr>`, `cidr:<net>/<prefix>` or `account:<login>`.
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

	/// Lift the ban on `target` and forget its failure counter, so the next
	/// failure starts from zero. Returns `(bans removed, failures cleared)`.
	pub async fn remove_ban(&self, target: BanTarget) -> Result<(u64, u64), sqlx::Error> {
		let subject = target.subject();
		let mut tx = self.pool.begin().await?;
		let bans = sqlx::query("DELETE FROM auth_ban WHERE subject = $1")
			.bind(&subject)
			.execute(&mut *tx)
			.await?
			.rows_affected();
		let failures = sqlx::query("DELETE FROM auth_failure WHERE subject = $1")
			.bind(&subject)
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
#[path = "bans_admin_tests.rs"]
mod tests;
