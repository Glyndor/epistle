use super::matches;

#[test]
fn a_trailing_star_matches_the_prefix_itself_and_longer_names() {
	assert!(matches("", "imaptest*", "imaptest"));
	assert!(matches("", "imaptest*", "imaptest2"));
	assert!(!matches("", "imaptest*", "imap"));
	assert!(!matches("", "imaptest*", "Imaptest"));
}

#[test]
fn star_and_percent_alone_match_every_flat_name() {
	for pattern in ["*", "%"] {
		assert!(matches("", pattern, "Archive"));
		assert!(matches("", pattern, "INBOX"));
	}
}

#[test]
fn percent_does_not_cross_the_hierarchy_delimiter() {
	assert!(matches("", "a/*", "a/b/c"));
	assert!(matches("", "a/%", "a/b"));
	assert!(!matches("", "a/%", "a/b/c"));
}

#[test]
fn wildcards_match_in_the_middle_and_at_the_start() {
	assert!(matches("", "S*t", "Sent"));
	assert!(matches("", "*nt", "Sent"));
	assert!(!matches("", "S*x", "Sent"));
}

#[test]
fn the_reference_is_prepended() {
	assert!(matches("imap", "test*", "imaptest"));
	assert!(!matches("other", "test*", "imaptest"));
}

#[test]
fn inbox_matches_in_any_case_and_other_names_exactly() {
	assert!(matches("", "inbox", "INBOX"));
	assert!(matches("", "InBoX*", "INBOX"));
	assert!(!matches("", "sent", "Sent"));
	assert!(!matches("", "inboxes", "INBOX"));
}

#[test]
fn an_encoded_pattern_matches_the_stored_name() {
	let stored = crate::util::mutf7::encode("Año");
	assert!(matches("", &crate::util::mutf7::encode("Añ*"), &stored));
}

#[test]
fn many_stars_stay_cheap() {
	let pattern = "*a".repeat(200);
	let name = "a".repeat(4000) + "b";
	assert!(!matches("", &pattern, &name));
}

#[test]
fn runs_of_wildcards_match_like_one() {
	assert!(matches("", "*%*", "a/b"));
	assert!(matches("", "%%", "ab"));
	assert!(!matches("", "%%", "a/b"));
	assert!(matches("", "a%*%b", "a/x/b"));
	assert!(!matches("", "a%%b", "a/b"));
}

#[test]
fn a_pattern_as_long_as_a_command_line_is_cheap() {
	// The match table is pattern by name; a long pattern of wildcards or of
	// literals the name cannot hold must not cost that product.
	let wild = "*%".repeat(16 * 1024);
	let literal = format!("{wild}x{wild}");
	let name = "n".repeat(200);
	let started = std::time::Instant::now();
	for _ in 0..100 {
		assert!(matches("", &wild, &name));
		assert!(!matches("", &literal, &name));
		assert!(!matches("", &"a*".repeat(16 * 1024), &name));
	}
	assert!(
		started.elapsed() < std::time::Duration::from_secs(1),
		"{:?}",
		started.elapsed()
	);
}
