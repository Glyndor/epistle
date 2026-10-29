//! Record tags for the Cloudflare provider.
//!
//! A Cloudflare tag is a `name:value` string. epistle owns the tag named
//! `epistle` and sets it to the server hostname, so a zone shared by several
//! servers shows which one wrote each record. Tags are not available on the
//! Free plan; the provider drops them for good after the first refusal.
//! Limits come from
//! <https://developers.cloudflare.com/dns/manage-dns-records/reference/record-attributes/>:
//! the name holds letters, digits, `-` and `_` (32 characters at most), the
//! value follows the comment rules (graphic characters, no line breaks, 100
//! characters at most).

/// The tag name epistle owns.
pub(super) const TAG_NAME: &str = "epistle";

/// Longest tag value Cloudflare accepts.
const MAX_VALUE: usize = 100;

/// The `epistle:<hostname>` tag for a server hostname, or `None` when nothing
/// usable remains after dropping whitespace and control characters. A value
/// longer than 100 characters is cut.
pub(super) fn host_tag(hostname: &str) -> Option<String> {
	let value: String = hostname
		.chars()
		.filter(|c| !c.is_whitespace() && !c.is_control())
		.take(MAX_VALUE)
		.collect();
	if value.is_empty() {
		None
	} else {
		Some(format!("{TAG_NAME}:{value}"))
	}
}

/// Whether `tag` is one of epistle's own (name `epistle`, case-insensitive).
fn is_own(tag: &str) -> bool {
	tag.split_once(':')
		.map_or(tag, |(name, _)| name)
		.eq_ignore_ascii_case(TAG_NAME)
}

/// The tags to write: the operator's tags from `existing` untouched, with
/// epistle's own replaced by `own` (when given).
pub(super) fn merge(existing: &[String], own: Option<&str>) -> Vec<String> {
	existing
		.iter()
		.filter(|t| !is_own(t))
		.cloned()
		.chain(own.map(str::to_string))
		.collect()
}

#[cfg(test)]
mod tests;
