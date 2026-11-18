//! Who a feedback report really came from.
//!
//! The server stamps its own `Authentication-Results` on every message it
//! accepts from a peer, after removing any other that names it as the
//! authority (and refusing the message if one survives). What that field
//! says is what this hop checked, with no organizational relaxation: SPF for
//! the exact domain of the envelope sender, and DKIM signatures by the exact
//! domain that signed. The receiver trusts a report only through those two
//! results, never through the looser `sender_verified` flag, which also
//! accepts a signature by another domain of the same organization.

/// What this server's own `Authentication-Results` says passed.
#[derive(Debug, Default, PartialEq, Eq)]
pub(super) struct Passed {
	/// The `smtp.mailfrom` domain of an `spf=pass`.
	pub spf_domain: Option<String>,
	/// The `header.d` domain of every `dkim=pass`.
	pub dkim_domains: Vec<String>,
}

/// Read the first `Authentication-Results` whose authserv-id is `hostname`.
pub(super) fn stamped(data: &[u8], hostname: &str) -> Passed {
	let block = crate::util::header_block::split_at_blank_line(data).0;
	let text = String::from_utf8_lossy(block);
	let mut fields: Vec<String> = Vec::new();
	for line in text.lines() {
		if line.starts_with([' ', '\t']) {
			if let Some(last) = fields.last_mut() {
				last.push(' ');
				last.push_str(line.trim());
			}
		} else {
			fields.push(line.to_string());
		}
	}
	for field in fields {
		let Some((name, value)) = field.split_once(':') else {
			continue;
		};
		if !name.trim().eq_ignore_ascii_case("authentication-results") {
			continue;
		}
		let mut parts = value.split(';');
		let id = parts.next().unwrap_or("").trim();
		if !id
			.split_whitespace()
			.next()
			.is_some_and(|id| id.eq_ignore_ascii_case(hostname))
		{
			continue;
		}
		return results(parts);
	}
	Passed::default()
}

fn results<'a>(parts: impl Iterator<Item = &'a str>) -> Passed {
	let mut passed = Passed::default();
	for part in parts {
		let mut words = part.split_whitespace();
		let Some((method, result)) = words.next().and_then(|first| first.split_once('=')) else {
			continue;
		};
		if !result.eq_ignore_ascii_case("pass") {
			continue;
		}
		let property = |key: &str| {
			part.split_whitespace()
				.find_map(|word| word.strip_prefix(key))
				.map(str::to_ascii_lowercase)
		};
		match method.to_ascii_lowercase().as_str() {
			"spf" => passed.spf_domain = passed.spf_domain.take().or(property("smtp.mailfrom=")),
			"dkim" => passed.dkim_domains.extend(property("header.d=")),
			_ => {}
		}
	}
	passed
}

/// Whether `passed` proves the envelope sender `sender` is the enrolled
/// provider `entry`: SPF passed for exactly the domain of `sender`, or a DKIM
/// signature passed whose `d=` is exactly that domain or, for an entry that
/// names a domain, exactly that domain.
pub(super) fn proves(passed: &Passed, sender: &str, entry: &str) -> bool {
	let Some((_, domain)) = sender.rsplit_once('@') else {
		return false;
	};
	let domain = domain.to_ascii_lowercase();
	if passed.spf_domain.as_deref() == Some(domain.as_str()) {
		return true;
	}
	let entry = entry.to_ascii_lowercase();
	passed
		.dkim_domains
		.iter()
		.any(|d| *d == domain || (!entry.contains('@') && *d == entry))
}
