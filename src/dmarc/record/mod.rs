//! DMARC record parsing (RFC 7489 section 6.3).

/// Requested policy.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Policy {
	None,
	Quarantine,
	Reject,
}

/// Alignment mode for SPF/DKIM identifiers (RFC 7489 section 3.1).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Alignment {
	Relaxed,
	Strict,
}

/// A parsed `_dmarc` record.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Record {
	pub policy: Policy,
	/// Subdomain policy; defaults to `policy`.
	pub subdomain_policy: Policy,
	pub dkim_alignment: Alignment,
	pub spf_alignment: Alignment,
	/// Percentage of messages subject to the policy (0–100, default 100).
	pub pct: u8,
	/// Aggregate report recipients parsed from `rua=` (RFC 7489 §6.3).
	/// Each element is a URI scheme and address (e.g. `mailto:dmarc@example.org`).
	/// `!maxsize` suffixes are stripped; empty if the tag was absent.
	pub rua: Vec<String>,
}

/// Parse a `v=DMARC1` TXT record. Returns `None` for records that are not
/// DMARC at all; `Err` for DMARC records that are malformed (permerror).
pub fn parse(text: &str) -> Option<Result<Record, ()>> {
	let mut tags = text.split(';').map(str::trim);
	if tags.next() != Some("v=DMARC1") {
		return None;
	}

	let mut policy = None;
	let mut subdomain_policy = None;
	let mut dkim_alignment = Alignment::Relaxed;
	let mut spf_alignment = Alignment::Relaxed;
	let mut pct: u8 = 100;
	let mut rua: Vec<String> = Vec::new();

	for tag in tags {
		if tag.is_empty() {
			continue;
		}
		let Some((name, value)) = tag.split_once('=') else {
			return Some(Err(()));
		};
		let value = value.trim();
		match name.trim() {
			"p" => match parse_policy(value) {
				Some(parsed) => policy = Some(parsed),
				None => return Some(Err(())),
			},
			"sp" => match parse_policy(value) {
				Some(parsed) => subdomain_policy = Some(parsed),
				None => return Some(Err(())),
			},
			"adkim" => match parse_alignment(value) {
				Some(parsed) => dkim_alignment = parsed,
				None => return Some(Err(())),
			},
			"aspf" => match parse_alignment(value) {
				Some(parsed) => spf_alignment = parsed,
				None => return Some(Err(())),
			},
			"pct" => match value.parse::<u8>() {
				Ok(v) => pct = v.min(100),
				Err(_) => return Some(Err(())),
			},
			"rua" => rua = parse_duri_list(value),
			// ruf/fo/rf/ri and unknown tags are ignored.
			_ => {}
		}
	}

	let Some(policy) = policy else {
		// p= is required (section 6.3).
		return Some(Err(()));
	};
	Some(Ok(Record {
		policy,
		subdomain_policy: subdomain_policy.unwrap_or(policy),
		dkim_alignment,
		spf_alignment,
		pct,
		rua,
	}))
}

fn parse_policy(value: &str) -> Option<Policy> {
	match value.to_ascii_lowercase().as_str() {
		"none" => Some(Policy::None),
		"quarantine" => Some(Policy::Quarantine),
		"reject" => Some(Policy::Reject),
		_ => None,
	}
}

fn parse_alignment(value: &str) -> Option<Alignment> {
	match value.to_ascii_lowercase().as_str() {
		"r" => Some(Alignment::Relaxed),
		"s" => Some(Alignment::Strict),
		_ => None,
	}
}

/// Parse a DURI list (`rua=`/`ruf=`) into a list of URI strings.
/// Strips optional `!maxsize` suffixes (RFC 7489 §6.3) and ignores blanks.
fn parse_duri_list(value: &str) -> Vec<String> {
	value
		.split(',')
		.filter_map(|uri| {
			let uri = uri.trim();
			if uri.is_empty() {
				return None;
			}
			// Strip optional `!NNNk`/`!NNNm`/`!NNN` max-size suffix.
			let uri = match uri.rfind('!') {
				Some(bang) => uri[..bang].trim_end(),
				None => uri,
			};
			if uri.is_empty() {
				None
			} else {
				Some(uri.to_ascii_lowercase())
			}
		})
		.collect()
}

#[cfg(test)]
mod tests;
