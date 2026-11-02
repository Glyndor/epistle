//! A DMARC record is never replaced by a weaker one.
//!
//! The record epistle computes is a protective default. The zone may already
//! carry a stricter policy: one the operator wrote, or one `dns lockdown`
//! moved to `p=reject`. Writing the default over it would loosen the domain,
//! so the publisher compares the two tag by tag and writes only when the
//! record in place is weaker in none of them.

use crate::dns::lockdown::{DmarcStep, DmarcTags, parse_dmarc};

/// How the DMARC record in place compares with the one epistle needs.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum Strength {
	/// The record in place is at least as strict in every tag: it stays.
	AtLeast,
	/// The record in place is weaker in the tag this names.
	Weaker(String),
	/// The record in place cannot be read, for the reason this names.
	Unreadable(String),
}

/// Compare the DMARC value in place with the one epistle needs.
pub(super) fn compare(in_place: &str, needed: &str) -> Strength {
	let current = match parse_dmarc(in_place) {
		Ok(tags) => tags,
		Err(reason) => return Strength::Unreadable(reason),
	};
	// The needed record is epistle's own; one it cannot read is a defect in
	// the builder, and nothing is compared against it.
	let Ok(wanted) = parse_dmarc(needed) else {
		return Strength::Unreadable("the record epistle computed does not parse".into());
	};
	for (tag, have, want) in [
		("p", current.policy(), wanted.policy()),
		("sp", subdomains(&current), subdomains(&wanted)),
		("np", nonexistent(&current), nonexistent(&wanted)),
	] {
		if have < want {
			return Strength::Weaker(format!(
				"{tag}={} is weaker than {tag}={}",
				have.as_str(),
				want.as_str()
			));
		}
	}
	for tag in ["adkim", "aspf"] {
		if strict(&wanted, tag) && !strict(&current, tag) {
			return Strength::Weaker(format!("{tag} is relaxed and epistle publishes {tag}=s"));
		}
	}
	Strength::AtLeast
}

/// The `sp=` policy, which defaults to `p=` (RFC 7489 section 6.3).
fn subdomains(tags: &DmarcTags) -> DmarcStep {
	tags.get("sp")
		.and_then(DmarcStep::parse)
		.unwrap_or_else(|| tags.policy())
}

/// The `np=` policy (DMARCbis), which defaults to `sp=`.
fn nonexistent(tags: &DmarcTags) -> DmarcStep {
	tags.get("np")
		.and_then(DmarcStep::parse)
		.unwrap_or_else(|| subdomains(tags))
}

/// Whether the alignment `tag` is strict. Relaxed is the default.
fn strict(tags: &DmarcTags, tag: &str) -> bool {
	tags.get(tag)
		.is_some_and(|mode| mode.eq_ignore_ascii_case("s"))
}
