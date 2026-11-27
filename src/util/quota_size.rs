//! The size of a storage quota as a person writes it: `500M`, `10G`, `1T`,
//! or `none` for the server default. `epistle account quota` and the
//! `/api/v1/accounts/{name}/quota` routes read it the same way.

/// The most a quota can be: what the account file, a TOML integer, holds. A
/// bigger number could not be written back, and a file nothing can read is a
/// file nobody can tell is in use.
pub const MAX_QUOTA_BYTES: u64 = i64::MAX as u64;

/// A byte suffix (K, M, G, T) parsed from the operator's quota string.
/// Stored as the multiplicative factor so the parser can be reused for
/// any case-sensitive unit without an extra lookup table.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum QuotaUnit {
	/// 2^10 bytes.
	K,
	/// 2^20 bytes.
	M,
	/// 2^30 bytes.
	G,
	/// 2^40 bytes.
	T,
}

impl QuotaUnit {
	fn factor(self) -> u64 {
		match self {
			QuotaUnit::K => 1024,
			QuotaUnit::M => 1024 * 1024,
			QuotaUnit::G => 1024 * 1024 * 1024,
			QuotaUnit::T => 1024 * 1024 * 1024 * 1024,
		}
	}
}

/// Parse a quota argument (`500M`, `10G`, `1T`, `none`) into bytes or
/// `None` for the server-default fallback. Rejects empty strings,
/// negative numbers and unknown suffixes so a typo never lands on disk.
pub fn parse_quota_size(raw: &str) -> Result<Option<u64>, String> {
	let trimmed = raw.trim();
	if trimmed.is_empty() {
		return Err("quota size is empty (expected 500M, 10G, 1T or none)".to_string());
	}
	if trimmed.eq_ignore_ascii_case("none") {
		return Ok(None);
	}
	let split_at = trimmed
		.find(|c: char| !c.is_ascii_digit())
		.ok_or_else(|| format!("quota size {raw:?} needs a K/M/G/T suffix or 'none'"))?;
	let (number, suffix) = trimmed.split_at(split_at);
	if number.is_empty() {
		return Err(format!("quota size {raw:?} starts with a non-digit"));
	}
	let multiplier: u64 = number
		.parse()
		.map_err(|error| format!("quota size {raw:?}: {error}"))?;
	let unit_char = suffix
		.chars()
		.next()
		.ok_or_else(|| format!("quota size {raw:?} is missing a unit"))?;
	let unit = match unit_char {
		'K' | 'k' => QuotaUnit::K,
		'M' | 'm' => QuotaUnit::M,
		'G' | 'g' => QuotaUnit::G,
		'T' | 't' => QuotaUnit::T,
		other => {
			return Err(format!(
				"quota size {raw:?}: unknown unit {other:?} (expected K, M, G or T)"
			));
		}
	};
	if !suffix.chars().skip(1).all(|c| c.is_whitespace()) {
		return Err(format!(
			"quota size {raw:?}: trailing characters after unit"
		));
	}
	multiplier
		.checked_mul(unit.factor())
		.filter(|bytes| *bytes <= MAX_QUOTA_BYTES)
		.map(Some)
		.ok_or_else(|| format!("quota size {raw:?} is larger than the most a quota can be (8191P)"))
}
