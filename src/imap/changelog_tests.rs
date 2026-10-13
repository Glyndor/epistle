use super::*;

fn root() -> tempfile::TempDir {
	tempfile::tempdir().expect("tempdir")
}

fn email(op: Op) -> Change {
	Change::email(op, uuid::Uuid::now_v7())
}

#[test]
fn every_change_gets_the_next_position() {
	let dir = root();
	let start = current(dir.path()).expect("current");
	assert_eq!(start.current, 0);
	let end = record(dir.path(), &[email(Op::Created), email(Op::Updated)]).expect("record");
	assert_eq!(end, 2);
	let (position, entries) = since(dir.path(), start.epoch, 0).expect("since");
	assert_eq!(position.current, 2);
	assert_eq!(position.epoch, start.epoch, "the epoch is stable");
	let positions: Vec<u64> = entries.iter().map(|e| e.position).collect();
	assert_eq!(positions, vec![1, 2]);
	assert_eq!(current(dir.path()).expect("current").current, 2);
}

#[test]
fn mailbox_ids_keep_spaces_and_normalise_inbox() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	record(
		dir.path(),
		&[
			Change::mailbox(Op::Created, "Old Receipts"),
			Change::mailbox(Op::Updated, "inbox"),
		],
	)
	.expect("record");
	let (_, entries) = since(dir.path(), epoch, 0).expect("since");
	let ids: Vec<&str> = entries.iter().map(|e| e.change.id.as_str()).collect();
	assert_eq!(ids, vec!["Old Receipts", "INBOX"]);
}

/// Writers in parallel (IMAP sessions, SMTP delivery, JMAP) never reuse a
/// position: no increment is lost and every line is readable.
#[test]
fn concurrent_writers_never_share_a_position() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	let threads: Vec<_> = (0..8)
		.map(|_| {
			let path = dir.path().to_path_buf();
			std::thread::spawn(move || {
				for _ in 0..50 {
					record(&path, &[email(Op::Updated)]).expect("record");
				}
			})
		})
		.collect();
	for thread in threads {
		thread.join().expect("join");
	}
	let (position, entries) = since(dir.path(), epoch, 0).expect("since");
	let positions: Vec<u64> = entries.iter().map(|e| e.position).collect();
	assert_eq!(
		positions,
		(1..=400).collect::<Vec<u64>>(),
		"400 records must hold positions 1..=400, each once"
	);
	assert_eq!(position.current, 400);
}

#[test]
fn since_refuses_other_epochs_and_future_positions() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	record(dir.path(), &[email(Op::Created)]).expect("record");
	assert!(matches!(
		since(dir.path(), epoch.wrapping_add(1), 0),
		Err(SinceError::Unknown)
	));
	assert!(matches!(
		since(dir.path(), epoch, 2),
		Err(SinceError::Unknown)
	));
	assert!(since(dir.path(), epoch, 1).expect("current").1.is_empty());
}

#[test]
fn a_trimmed_journal_refuses_positions_below_its_floor() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	for _ in 0..10 {
		record_with_limit(dir.path(), &[email(Op::Created)], 200).expect("record");
	}
	let position = current(dir.path()).expect("current");
	assert_eq!(position.current, 10, "trimming keeps the position");
	assert!(position.floor > 0, "the trim raised the floor");
	assert!(matches!(
		since(dir.path(), epoch, position.floor - 1),
		Err(SinceError::Unknown)
	));
	let (_, entries) = since(dir.path(), epoch, position.floor).expect("at the floor");
	assert_eq!(
		entries.first().map(|e| e.position),
		Some(position.floor + 1),
		"every line above the floor is kept"
	);
}

/// A crash mid-append leaves an unterminated line; it is never read and the
/// next record does not glue onto it.
#[test]
fn an_unterminated_line_is_ignored_and_repaired() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	record(dir.path(), &[email(Op::Created)]).expect("record");
	let journal = dir.path().join(".jmap_changes");
	let mut file = std::fs::OpenOptions::new()
		.append(true)
		.open(&journal)
		.expect("open");
	file.write_all(b"2 E C 0189").expect("partial");
	drop(file);
	let (position, entries) = since(dir.path(), epoch, 0).expect("since");
	assert_eq!(position.current, 1, "the partial line is not committed");
	assert_eq!(entries.len(), 1);
	let id = uuid::Uuid::now_v7();
	record(dir.path(), &[Change::email(Op::Updated, id)]).expect("record");
	let (_, entries) = since(dir.path(), epoch, 1).expect("since");
	assert_eq!(
		entries,
		vec![Entry {
			position: 2,
			change: Change::email(Op::Updated, id)
		}]
	);
}

/// A lost header means positions can no longer be trusted: a new epoch
/// starts and every old state is refused.
#[test]
fn a_lost_header_starts_a_new_epoch() {
	let dir = root();
	let epoch = current(dir.path()).expect("current").epoch;
	record(dir.path(), &[email(Op::Created)]).expect("record");
	std::fs::remove_file(dir.path().join(".jmap_state")).expect("remove header");
	let fresh = current(dir.path()).expect("current");
	assert_ne!(fresh.epoch, epoch);
	assert_eq!(fresh.current, 0);
	assert!(matches!(
		since(dir.path(), epoch, 1),
		Err(SinceError::Unknown)
	));
}
