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

/// The time to match long patterns of wildcards and literals against a
/// name, for patterns of `units` repetitions and a name of `name_len`.
fn long_pattern_cost(units: usize, name_len: usize) -> std::time::Duration {
	let wild = "*%".repeat(units);
	let literal = format!("{wild}x{wild}");
	let ending = "a*".repeat(units);
	let name = "n".repeat(name_len);
	let started = std::time::Instant::now();
	for _ in 0..20 {
		assert!(matches("", &wild, &name));
		assert!(!matches("", &literal, &name));
		assert!(!matches("", &ending, &name));
	}
	started.elapsed()
}

#[test]
fn a_pattern_as_long_as_a_command_line_is_cheap() {
	// The match table is pattern by name; a long pattern of wildcards or of
	// literals the name cannot hold must not cost that product. Growth, not
	// wall clock: eight times the pattern and the name must cost about eight
	// times the work, and the product costs about sixty-four. The two sizes
	// are timed interleaved, fastest of five each, with the short side
	// floored at 5 ms, so a loaded machine slows both alike.
	let (mut short, mut long) = (std::time::Duration::MAX, std::time::Duration::MAX);
	for _ in 0..5 {
		short = short.min(long_pattern_cost(2 * 1024, 100));
		long = long.min(long_pattern_cost(16 * 1024, 800));
	}
	let short = short.max(std::time::Duration::from_millis(5));
	assert!(
		long < short * 24,
		"eight times the pattern and name went from {short:?} to {long:?}"
	);
}
