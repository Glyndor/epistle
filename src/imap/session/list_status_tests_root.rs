use super::super::tests::{logged_in, text};

/// `LIST "" ""` is the canonical hierarchy-separator discovery call
/// (RFC 3501 §6.3.8). The server must answer with the root of the
/// hierarchy and its delimiter so a client that knows neither can
/// discover both in one round trip.
///
/// Before the fix, the response was a bare `OK LIST completed` with
/// no untagged `LIST` line, because the empty pattern matched no
/// mailbox name. After the fix, the root is emitted with `\Noselect`
/// (the root itself is not selectable) and the same delimiter the
/// regular mailboxes use.
#[test]
fn empty_pattern_returns_root_hierarchy() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line(r#"l LIST "" """#);
	assert_eq!(
		text(&output),
		"* LIST (\\Noselect) \"/\" \"\"\r\nl OK LIST completed\r\n",
		"empty pattern must reply with the root mailbox, not just OK"
	);
}

/// `LIST "" ""` keeps returning the root when no mailbox exists at
/// all. A fresh account starts with no user mailboxes (INBOX is
/// created lazily, so even INBOX may be absent), and a hierarchy
/// discovery call must still succeed.
#[test]
fn empty_pattern_returns_root_even_when_no_mailboxes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	// No CREATE, no SELECT, no mailboxes at all.
	let output = session.command_line(r#"l LIST "" """#);
	assert!(
		text(&output).starts_with("* LIST ("),
		"empty pattern with no mailboxes must still report the root, got: {}",
		text(&output)
	);
}

/// The root reply is suppressed when the caller asks for
/// `SUBSCRIBED` or `SPECIAL-USE` only: the root is not subscribed
/// and has no special-use role, so a subscription-focused or
/// special-use-focused LIST would have nothing to add. Keeping
/// the root in those responses would surprise callers that
/// treat empty selection as "no matches".
#[test]
fn empty_pattern_skips_root_when_subscribed_or_special_use_only() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	let output = session.command_line(r#"l LIST (SUBSCRIBED) "" """#);
	assert_eq!(
		text(&output),
		"l OK LIST completed\r\n",
		"SUBSCRIBED-only LIST must skip the unsubscribed root"
	);
}

/// imaptest starts every scripted test with `LIST "" "imaptest*"` and
/// creates the mailbox only when the listing is empty. LIST knew only `*`,
/// `%` and exact names, so a mailbox left by an earlier run was never
/// listed and every following CREATE failed with "already exists".
#[test]
fn a_partial_wildcard_lists_the_mailbox_it_names() {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut session = logged_in(dir.path());
	session.command_line("c CREATE imaptest");
	let listed = text(&session.command_line(r#"l LIST "" "imaptest*""#));
	assert!(listed.contains("\"/\" \"imaptest\"\r\n"), "{listed}");
	let subscribed = text(&session.command_line(r#"s LSUB "" "imaptest*""#));
	assert!(
		subscribed.ends_with("s OK LSUB completed\r\n"),
		"{subscribed}"
	);
}
