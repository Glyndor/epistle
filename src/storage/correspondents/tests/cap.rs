use super::*;

#[test]
fn full_daily_cap_rejects_ten_fresh_recipients() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = CorrespondentStore::open(dir.path()).expect("store");
	let known: Vec<String> = (0..10).map(|n| format!("known{n}@example.net")).collect();
	store
		.record(
			"alice",
			&known.iter().map(String::as_str).collect::<Vec<_>>(),
		)
		.expect("record");
	let fresh: Vec<String> = (0..10).map(|n| format!("fresh{n}@example.net")).collect();
	let outcome = store
		.enforce_new_recipient_cap(
			"alice",
			&fresh.iter().map(String::as_str).collect::<Vec<_>>(),
			Some(10),
		)
		.expect("cap");
	assert_eq!(
		outcome,
		CapOutcome::Limited {
			new: 10,
			already: 10,
			limit: 10
		},
		"fresh recipients must be added to the existing daily total"
	);
	assert_eq!(
		store.new_in_last_day("alice").expect("count"),
		10,
		"refused recipients must leave the daily baseline unchanged"
	);
}

#[test]
fn concurrent_submissions_reserve_one_shared_allowance() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = CorrespondentStore::open(dir.path()).expect("store");
	let checked = std::sync::Arc::new(std::sync::Barrier::new(3));
	let results = std::thread::scope(|scope| {
		let handles: Vec<_> = (0..3)
			.map(|n| {
				let store = if n == 0 {
					store.clone()
				} else {
					CorrespondentStore::open(dir.path()).expect("independent store")
				};
				let checked = checked.clone();
				scope.spawn(move || {
					let recipient = format!("fresh{n}@example.net");
					let outcome = store
						.enforce_new_recipient_cap("ALICE", &[&recipient], Some(1))
						.expect("cap");
					checked.wait();
					if matches!(outcome, CapOutcome::Allowed { .. }) {
						store.record("alice", &[&recipient]).expect("record");
					}
					outcome
				})
			})
			.collect();
		handles
			.into_iter()
			.map(|h| h.join().expect("join"))
			.collect::<Vec<_>>()
	});
	assert_eq!(
		results
			.iter()
			.filter(|o| matches!(o, CapOutcome::Allowed { new: 1 }))
			.count(),
		1,
		"concurrent submissions must reserve exactly one daily allowance"
	);
	assert_eq!(
		store.new_in_last_day("alice").expect("count"),
		1,
		"concurrent submissions must create exactly one fresh marker"
	);
}

#[test]
fn cap_counts_case_insensitive_unique_recipients() {
	let dir = tempfile::tempdir().expect("tempdir");
	let store = CorrespondentStore::open(dir.path()).expect("store");
	assert_eq!(
		store
			.enforce_new_recipient_cap("alice", &["Bob@example.net", "bob@example.net"], Some(1))
			.expect("cap"),
		CapOutcome::Allowed { new: 1 },
		"duplicate recipient spellings must reserve one marker"
	);
	assert!(
		store.knows("alice", "bob@example.net"),
		"allowed recipients must be reserved before returning"
	);
}
