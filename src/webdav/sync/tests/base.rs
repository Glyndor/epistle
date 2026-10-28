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

#[tokio::test]
async fn one_collections_log_lock_does_not_hold_up_another() {
	use std::time::Duration;
	let busy = collection();
	let other = collection();
	let held = super::lock_for_tests(busy.path()).await;
	tokio::time::timeout(
		Duration::from_secs(5),
		record(other.path(), &[("a.ics".into(), false)]),
	)
	.await
	.expect("another collection's log is not blocked");
	let same = tokio::time::timeout(
		Duration::from_millis(150),
		record(busy.path(), &[("a.ics".into(), false)]),
	)
	.await;
	assert!(same.is_err(), "writers of one log stay serialised");
	drop(held);
	record(busy.path(), &[("b.ics".into(), false)]).await;
	let log = load(busy.path()).await.expect("log");
	assert_eq!(sequence_of(&log.token()), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_records_get_distinct_sequences() {
	let dir = collection();
	let path = std::sync::Arc::new(dir.path().to_path_buf());
	let mut writes = tokio::task::JoinSet::new();
	for n in 0..24 {
		let path = std::sync::Arc::clone(&path);
		writes.spawn(async move { record(&path, &[(format!("{n}.ics"), false)]).await });
	}
	while let Some(done) = writes.join_next().await {
		done.expect("write task");
	}
	let log = load(dir.path()).await.expect("log");
	assert_eq!(sequence_of(&log.token()), 24, "no write overwrote another");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_loads_of_a_new_log_agree_on_it() {
	let dir = collection();
	let path = std::sync::Arc::new(dir.path().to_path_buf());
	let mut reads = tokio::task::JoinSet::new();
	for _ in 0..16 {
		let path = std::sync::Arc::clone(&path);
		reads.spawn(async move { load(&path).await.expect("log").token() });
	}
	let mut tokens = std::collections::BTreeSet::new();
	while let Some(done) = reads.join_next().await {
		tokens.insert(done.expect("read task"));
	}
	assert_eq!(tokens.len(), 1, "one log was created, not one per reader");
}

#[tokio::test]
async fn load_waits_for_a_writer_of_the_same_collection() {
	use std::time::Duration;
	let dir = collection();
	let held = super::lock_for_tests(dir.path()).await;
	let waiting = tokio::time::timeout(Duration::from_millis(150), load(dir.path())).await;
	assert!(waiting.is_err(), "load takes the collection's lock");
	drop(held);
	assert!(load(dir.path()).await.is_some());
}
