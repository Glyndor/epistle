use super::{CHANGELOG, Change, Log, MAX_ENTRIES, load, record};

fn collection() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

fn sequence_of(token: &str) -> u64 {
	token
		.rsplit('-')
		.next()
		.expect("sequence")
		.parse()
		.expect("number")
}

#[tokio::test]
async fn a_new_log_starts_at_zero_and_counts_every_change() {
	let dir = collection();
	let empty = load(dir.path()).await.expect("log");
	assert_eq!(empty.highest(), 0);
	assert!(empty.token().starts_with("urn:epistle:sync:"));
	record(
		dir.path(),
		&[("a.ics".into(), false), ("b.ics".into(), false)],
	)
	.await;
	record(dir.path(), &[("a.ics".into(), true)]).await;
	let log = load(dir.path()).await.expect("log");
	assert_eq!(sequence_of(&log.token()), 3);
	assert_eq!(
		log.token().rsplit_once('-').map(|t| t.0),
		empty.token().rsplit_once('-').map(|t| t.0)
	);
}

#[tokio::test]
async fn changed_since_keeps_the_latest_change_per_member() {
	let dir = collection();
	record(
		dir.path(),
		&[("a.ics".into(), false), ("b.ics".into(), false)],
	)
	.await;
	let log = load(dir.path()).await.expect("log");
	let position = log.position_of(&log.token()).expect("own token");
	record(
		dir.path(),
		&[
			("a.ics".into(), true),
			("c.ics".into(), false),
			("a.ics".into(), false),
		],
	)
	.await;
	let log = load(dir.path()).await.expect("log");
	let names: Vec<(String, bool)> = log
		.changed_since(position)
		.into_iter()
		.map(|Change { name, deleted, .. }| (name, deleted))
		.collect();
	assert_eq!(
		names,
		[("c.ics".to_string(), false), ("a.ics".to_string(), false)]
	);
	assert!(log.changed_since(log.highest()).is_empty());
}

#[tokio::test]
async fn trimming_invalidates_exactly_the_tokens_it_can_no_longer_answer() {
	let dir = collection();
	let first = load(dir.path()).await.expect("log").token();
	for i in 0..MAX_ENTRIES {
		record(dir.path(), &[(format!("{i}.ics"), false)]).await;
	}
	let log = load(dir.path()).await.expect("log");
	assert!(log.position_of(&first).is_some(), "nothing dropped yet");
	record(dir.path(), &[("last.ics".into(), false)]).await;
	let log = load(dir.path()).await.expect("log");
	assert!(log.position_of(&first).is_none(), "change 1 was dropped");
	let epoch = first.rsplit_once('-').expect("epoch").0;
	assert!(
		log.position_of(&format!("{epoch}-1")).is_some(),
		"everything after 1 is kept"
	);
	assert!(
		log.position_of(&format!("{epoch}-{}", MAX_ENTRIES + 2))
			.is_none(),
		"future"
	);
	let lines = std::fs::read_to_string(dir.path().join(CHANGELOG)).expect("log");
	assert_eq!(
		lines.lines().count(),
		MAX_ENTRIES + 1,
		"header plus the kept changes"
	);
}

#[tokio::test]
async fn tokens_from_another_log_or_malformed_are_unknown() {
	let one = collection();
	let other = collection();
	let token = load(one.path()).await.expect("log").token();
	let log = load(other.path()).await.expect("log");
	for bad in [
		token.as_str(),
		"",
		"urn:epistle:sync:",
		"urn:epistle:sync:x-1",
		"0",
	] {
		assert!(log.position_of(bad).is_none(), "accepted {bad:?}");
	}
}

#[test]
fn a_damaged_log_is_not_parsed() {
	assert!(Log::parse("not a header\n").is_none());
	assert!(Log::parse("#epistle-sync e 0\n1\ta.ics\n").is_none());
	let log = Log::parse("#epistle-sync e 4\n5\ta.ics\t1\n").expect("valid");
	assert_eq!(log.highest(), 5);
	assert_eq!(Log::parse(&log.render()), Some(log));
}
