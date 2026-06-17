//! Sender reputation: ham/spam tallies keyed by a verified identity.
//!
//! The engine consults reputation before heavier analysis: a sender we have
//! reliably accepted from before passes quickly, and one we have repeatedly
//! rejected is treated with suspicion. Tallies are stored in PostgreSQL.

use sqlx::PgPool;

/// The kind of identity a reputation row tracks.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scope {
	/// Reverse-DNS / EHLO host.
	Host,
	/// Organizational domain.
	Domain,
	/// Full sender address.
	Sender,
	/// Source IP literal.
	Ip,
}

impl Scope {
	/// The stable string stored in the `scope` column.
	fn as_str(self) -> &'static str {
		match self {
			Scope::Host => "host",
			Scope::Domain => "domain",
			Scope::Sender => "sender",
			Scope::Ip => "ip",
		}
	}
}

/// Accumulated ham/spam counts for one identity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReputationScore {
	pub ham: i64,
	pub spam: i64,
}

/// What reputation says about an identity, independent of storage.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
	/// Too little history to judge.
	Unknown,
	/// More accepted than rejected: let it pass quickly.
	Trusted,
	/// More rejected than accepted: scrutinize or reject.
	Suspect,
}

/// Minimum observations before reputation is meaningful.
const MIN_OBSERVATIONS: i64 = 3;

impl ReputationScore {
	/// Interpret the tallies. Pure: no storage, fully unit-testable.
	pub fn verdict(self) -> Verdict {
		if self.ham + self.spam < MIN_OBSERVATIONS {
			return Verdict::Unknown;
		}
		if self.spam > self.ham {
			Verdict::Suspect
		} else {
			Verdict::Trusted
		}
	}
}

/// Record one observation for `value`, incrementing the ham or spam tally and
/// creating the row on first sight. `value` must already be normalized
/// (lowercased) by the caller.
pub async fn record(
	pool: &PgPool,
	scope: Scope,
	value: &str,
	spam: bool,
) -> Result<(), sqlx::Error> {
	let ham_inc: i64 = if spam { 0 } else { 1 };
	let spam_inc: i64 = if spam { 1 } else { 0 };
	sqlx::query!(
		"INSERT INTO reputation (id, scope, value, ham_count, spam_count) \
		 VALUES ($1, $2, $3, $4, $5) \
		 ON CONFLICT (scope, value) DO UPDATE SET \
		     ham_count = reputation.ham_count + $4, \
		     spam_count = reputation.spam_count + $5, \
		     last_seen = now(), updated_at = now()",
		uuid::Uuid::now_v7(),
		scope.as_str(),
		value,
		ham_inc,
		spam_inc,
	)
	.execute(pool)
	.await?;
	Ok(())
}

/// Look up the tallies for `value`, or `None` if it has no history.
pub async fn lookup(
	pool: &PgPool,
	scope: Scope,
	value: &str,
) -> Result<Option<ReputationScore>, sqlx::Error> {
	let row = sqlx::query!(
		"SELECT ham_count, spam_count FROM reputation WHERE scope = $1 AND value = $2",
		scope.as_str(),
		value,
	)
	.fetch_optional(pool)
	.await?;
	Ok(row.map(|row| ReputationScore {
		ham: row.ham_count,
		spam: row.spam_count,
	}))
}

#[cfg(test)]
mod tests {
	use super::*;

	#[test]
	fn verdict_unknown_below_threshold() {
		assert_eq!(
			ReputationScore { ham: 1, spam: 1 }.verdict(),
			Verdict::Unknown
		);
	}

	#[test]
	fn verdict_trusted_when_ham_leads() {
		assert_eq!(
			ReputationScore { ham: 5, spam: 1 }.verdict(),
			Verdict::Trusted
		);
		// Ties favor trust (benefit of the doubt above the threshold).
		assert_eq!(
			ReputationScore { ham: 2, spam: 2 }.verdict(),
			Verdict::Trusted
		);
	}

	#[test]
	fn verdict_suspect_when_spam_leads() {
		assert_eq!(
			ReputationScore { ham: 1, spam: 5 }.verdict(),
			Verdict::Suspect
		);
	}
}
