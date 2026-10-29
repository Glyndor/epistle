//! Second-review regression scenarios, using in-memory IMAP transports.

use super::*;

#[tokio::test]
async fn confirmed_recovery_messages_are_not_synchronized_again() {
	let dir = tempfile::tempdir().expect("dir");
	for _ in 0..40 {
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			b"a",
			&target(dir.path()).crypto,
		)
		.expect("confirmed message");
	}
	let states =
		super::super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.unwrap();
	states
		.save(
			b"INBOX",
			&super::super::super::super::state::FolderState {
				folder: "INBOX".into(),
				uid_validity: 6,
				last_uid: 40,
				in_progress: false,
				copied: 40,
			},
		)
		.unwrap();
	let _guard = super::super::super::super::durability::tests::begin(None);
	let (summary, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "recovery failed: {error:?}");
	assert_eq!(summary.folders[0].duplicates, 2);
	let events = super::super::super::super::durability::tests::events();
	assert_eq!(
		events.iter().filter(|event| **event == "message").count(),
		0,
		"confirmed messages already passed their durability barriers"
	);
}

#[tokio::test]
async fn inconsistent_exists_stops_with_a_resumable_error() {
	use super::super::super::super::{Filter, Settings, run_with_connection};
	let dir = tempfile::tempdir().expect("dir");
	let states =
		super::super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.unwrap();
	let mut previous = 0;
	for attempt in 0..2 {
		let (stream, peer) = tokio::io::duplex(4096);
		let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
		let server = tokio::spawn(migration_peer(peer, false, 20_001, commands.clone(), 1));
		let mut settings = Settings::new(Filter::default(), false);
		settings.batch_messages = 1;
		let (_, error) = run_with_connection(
			&source(),
			&mut target(dir.path()),
			&settings,
			&mut Quiet::default(),
			std::future::ready(Ok(tests::memory_client(stream))),
		)
		.await;
		server.abort();
		if attempt == 0 {
			assert!(
				matches!(error, Some(super::super::super::super::MigrateError::Client(ClientError::Protocol(ref message)))
				if message.contains("exceeds EXISTS") && message.contains("resume")),
				"expected resumable count error: {error:?}"
			);
		} else {
			assert!(error.is_none(), "resume failed: {error:?}");
		}
		let commands = commands.lock().unwrap();
		let ranges: Vec<_> = commands
			.iter()
			.filter(|line| line.contains("RFC822.SIZE)"))
			.collect();
		assert!(
			ranges.len() <= 40,
			"bound listing round trips: {}",
			ranges.len()
		);
		assert!(
			ranges[0].contains(&format!("UID FETCH {}:", previous + 1)),
			"resume after the last completed window"
		);
		let saved = states.load(b"INBOX").unwrap().unwrap();
		assert!(saved.last_uid > previous && saved.last_uid <= 20_001);
		previous = saved.last_uid;
	}
}

#[tokio::test]
async fn hostile_uidnext_uses_a_bounded_number_of_round_trips_during_replay() {
	use super::super::super::super::{Filter, Settings, run_with_connection};
	for second_uid in [1_000_001, u32::MAX - 1] {
		for pending in [false, true] {
			let dir = tempfile::tempdir().unwrap();
			let states = super::super::super::super::state::StateDir::open(
				dir.path(),
				"alice",
				"alice@old.example",
			)
			.unwrap();
			states
				.save(
					b"INBOX",
					&super::super::super::super::state::FolderState {
						folder: "INBOX".into(),
						uid_validity: if pending { 7 } else { 6 },
						last_uid: 0,
						in_progress: pending,
						copied: 0,
					},
				)
				.unwrap();
			let (stream, peer) = tokio::io::duplex(4096);
			let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
			let server = tokio::spawn(migration_peer(peer, false, second_uid, commands.clone(), 2));
			let (_, error) = run_with_connection(
				&source(),
				&mut target(dir.path()),
				&Settings::new(Filter::default(), false),
				&mut Quiet::default(),
				std::future::ready(Ok(tests::memory_client(stream))),
			)
			.await;
			server.abort();
			assert!(error.is_none(), "sparse recovery must finish: {error:?}");
			let count = commands
				.lock()
				.unwrap()
				.iter()
				.filter(|line| line.contains("RFC822.SIZE)"))
				.count();
			assert!(count <= 64, "bound the UIDNEXT walk: {count}");
			assert!(!states.load(b"INBOX").unwrap().unwrap().in_progress);
		}
	}
}

#[tokio::test]
async fn an_empty_recovery_window_keeps_the_replay_marker() {
	use super::super::super::super::{Filter, Settings, run_with_connection};
	let dir = tempfile::tempdir().unwrap();
	let states =
		super::super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.unwrap();
	states
		.save(
			b"INBOX",
			&super::super::super::super::state::FolderState {
				folder: "INBOX".into(),
				uid_validity: 6,
				last_uid: 0,
				in_progress: false,
				copied: 0,
			},
		)
		.unwrap();
	let replies = vec![
		b"M1 OK login\r\n".to_vec(),
		b"M2 OK capabilities\r\n".to_vec(),
		b"* LIST () \"/\" \"INBOX\"\r\nM3 OK list\r\n".to_vec(),
		b"* 1 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT 40002] next\r\nM4 OK examine\r\n".to_vec(),
		b"M5 OK empty\r\n".to_vec(),
		b"M999 OK wrong tag\r\n".to_vec(),
	];
	let (client, server) = tests::scripted_client(replies).await;
	let (_, error) = run_with_connection(
		&source(),
		&mut target(dir.path()),
		&Settings::new(Filter::default(), false),
		&mut Quiet::default(),
		std::future::ready(Ok(client)),
	)
	.await;
	server.abort();
	assert!(matches!(
		error,
		Some(super::super::super::super::MigrateError::Client(
			ClientError::Protocol(_)
		))
	));
	let saved = states.load(b"INBOX").unwrap().unwrap();
	assert_eq!(saved.last_uid, 10000);
	assert!(
		saved.in_progress,
		"empty windows must not confirm an unfinished replay"
	);
}
