//! Parsing of SELECT/EXAMINE parameter groups: CONDSTORE and QRESYNC (RFC 7162).

/// `(uidvalidity, modseq)` from `(QRESYNC (uidvalidity modseq ...))` (RFC 7162).
pub(super) fn parse_qresync(args: &str) -> Option<(u32, u64)> {
	let pos = args.to_ascii_uppercase().find("QRESYNC")?;
	let rest = &args[pos..];
	let mut nums = rest[rest.find('(')? + 1..]
		.split(|c: char| !c.is_ascii_digit())
		.filter(|token| !token.is_empty());
	Some((nums.next()?.parse().ok()?, nums.next()?.parse().ok()?))
}

/// Drop a trailing parenthesized SELECT/EXAMINE parameter group, e.g. `INBOX
/// (CONDSTORE)` (RFC 7162). The first `(` opens it (mailbox names have none);
/// `rfind` would mis-split a nested `(QRESYNC (uidvalidity modseq))`.
pub(super) fn strip_select_params(args: &str) -> &str {
	let trimmed = args.trim_end();
	if trimmed.ends_with(')')
		&& let Some(open) = trimmed.find('(')
	{
		return trimmed[..open].trim_end();
	}
	trimmed
}
