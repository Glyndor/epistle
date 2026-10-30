//! In-memory migration runs that stop after a stored batch and then resume.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::super::super::tests::run::{Quiet, local, target};
use super::*;

async fn migration_peer(
	peer: tokio::io::DuplexStream,
	stall: bool,
	second_uid: u32,
	commands: std::sync::Arc<std::sync::Mutex<Vec<String>>>,
	exists: u32,
) {
	let mut peer = BufReader::new(peer);
	loop {
		let mut line = String::new();
		if peer.read_line(&mut line).await.expect("command") == 0 {
			return;
		}
		commands.lock().expect("log").push(line.clone());
		let (tag, command) = line.split_once(' ').expect("tag");
		let data = if command.starts_with("LIST ") {
			"* LIST () \"/\" \"INBOX\"\r\n".to_string()
		} else if command.starts_with("EXAMINE ") {
			format!(
				"* {exists} EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT {}] next\r\n",
				second_uid + 1
			)
		} else if command.contains("RFC822.SIZE)") {
			let set = command.split_ascii_whitespace().nth(2).expect("range");
			let (from, to) = set.split_once(':').expect("range");
			let from = from.parse::<u32>().expect("from");
			let to = to.parse::<u32>().unwrap_or(u32::MAX);
			[1, second_uid]
				.into_iter()
				.filter(|uid| *uid >= from && *uid <= to)
				.map(|uid| format!("* {uid} FETCH (UID {uid} RFC822.SIZE 1)\r\n"))
				.collect::<String>()
		} else if command.contains("BODY.PEEK[]") {
			if command.starts_with(&format!("UID FETCH {second_uid} ")) && stall {
				loop {
					tokio::time::sleep(Duration::from_millis(500)).await;
					if peer.get_mut().write_all(b"* OK alive\r\n").await.is_err() {
						return;
					}
				}
			}
			let uid = if command.starts_with(&format!("UID FETCH {second_uid} ")) {
				second_uid
			} else {
				1
			};
			format!(
				"* {uid} FETCH (UID {uid} FLAGS ({}) INTERNALDATE \"17-Jul-2024 02:44:25 -0700\" RFC822.SIZE 1 BODY[] {{1}}\r\na)\r\n",
				"keyword ".repeat(12)
			)
		} else {
			String::new()
		};
		if peer
			.get_mut()
			.write_all(format!("{data}{tag} OK done\r\n").as_bytes())
			.await
			.is_err()
		{
			return;
		}
		if command.starts_with("LOGOUT") {
			return;
		}
	}
}

fn source() -> super::super::super::Source {
	super::super::super::Source {
		endpoint: Endpoint {
			host: "old.example".into(),
			port: 993,
			address: None,
			security: Security::Tls,
			verify: super::super::super::Verify::Skip,
		},
		user: "alice".into(),
		password: Zeroizing::new(crate::test_fixtures::password().into()),
	}
}

async fn migrate_memory(
	dir: &std::path::Path,
	stall: bool,
	metadata_limit: Option<usize>,
) -> (
	super::super::super::Summary,
	Option<super::super::super::MigrateError>,
) {
	let limits = metadata_limit.map(|limit| (limit, usize::MAX));
	migrate_with_budget(dir, stall, limits).await
}

async fn migrate_with_budget(
	dir: &std::path::Path,
	stall: bool,
	limits: Option<(usize, usize)>,
) -> (
	super::super::super::Summary,
	Option<super::super::super::MigrateError>,
) {
	use super::super::super::{Filter, Settings, run_with_connection};
	let (stream, peer) = tokio::io::duplex(4096);
	let mut client = tests::memory_client(stream);
	client.limits.response = Duration::from_secs(10);
	if let Some((mailbox, total)) = limits {
		client.metadata.mailbox_limit = mailbox;
		client.metadata.total_limit = total;
	}
	let server = tokio::spawn(migration_peer(peer, stall, 2, Default::default(), 2));
	let mut settings = Settings::new(Filter::default(), false);
	settings.total_timeout = Duration::from_secs(3);
	settings.batch_messages = 1;
	let result = run_with_connection(
		&source(),
		&mut target(dir),
		&settings,
		&mut Quiet::default(),
		std::future::ready(Ok(client)),
	)
	.await;
	server.abort();
	result
}

#[tokio::test(start_paused = true)]
async fn the_total_deadline_preserves_partial_summary_and_resumes() {
	let dir = tempfile::tempdir().expect("dir");
	let (summary, error) = migrate_memory(dir.path(), true, None).await;
	assert!(matches!(
		error,
		Some(super::super::super::MigrateError::Timeout)
	));
	assert_eq!(
		summary.copied, 1,
		"include the completed batch in the partial report"
	);
	assert_eq!(local(dir.path(), "INBOX").len(), 1);
	let states =
		super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.expect("states");
	assert_eq!(
		states
			.load(b"INBOX")
			.expect("load")
			.expect("saved")
			.last_uid,
		1
	);
	let (summary, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "resume failed: {error:?}");
	assert_eq!(summary.copied, 1);
	assert_eq!(local(dir.path(), "INBOX").len(), 2);
}

#[tokio::test]
async fn a_metadata_stop_keeps_the_previous_checkpoint() {
	let dir = tempfile::tempdir().expect("dir");
	let states =
		super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.expect("states");
	let saved = super::super::super::state::FolderState {
		folder: "INBOX".into(),
		uid_validity: 7,
		last_uid: 1,
		in_progress: false,
		copied: 1,
	};
	states.save(b"INBOX", &saved).expect("save");
	// Enough for LIST and one UID, too little for retained FETCH metadata.
	let (_, error) = migrate_memory(dir.path(), false, Some(512)).await;
	assert!(matches!(
		error,
		Some(super::super::super::MigrateError::Client(
			ClientError::Metadata { .. }
		))
	));
	assert_eq!(states.load(b"INBOX").expect("load"), Some(saved));
	let (summary, error) = migrate_memory(dir.path(), false, None).await;
	assert!(error.is_none(), "resume failed: {error:?}");
	assert_eq!(summary.copied, 1);
}

#[tokio::test]
async fn sparse_uid_windows_are_checkpointed_without_collecting_the_mailbox() {
	use super::super::super::{Filter, Settings, run_with_connection};
	let dir = tempfile::tempdir().expect("dir");
	let (stream, peer) = tokio::io::duplex(4096);
	let commands = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
	let server = tokio::spawn(migration_peer(peer, false, 20001, commands.clone(), 2));
	let mut settings = Settings::new(Filter::default(), false);
	settings.batch_messages = 1;
	let (summary, error) = run_with_connection(
		&source(),
		&mut target(dir.path()),
		&settings,
		&mut Quiet::default(),
		std::future::ready(Ok(tests::memory_client(stream))),
	)
	.await;
	server.abort();
	assert!(error.is_none(), "migration failed: {error:?}");
	assert_eq!(summary.copied, 2);
	let commands = commands.lock().expect("log");
	for range in ["1:10000", "10001:20000", "20001:20001"] {
		assert!(
			commands
				.iter()
				.any(|line| line.contains(&format!("UID FETCH {range} (UID RFC822.SIZE)"))),
			"missing bounded range {range}"
		);
	}
	let states =
		super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.expect("states");
	assert_eq!(
		states
			.load(b"INBOX")
			.expect("load")
			.expect("saved")
			.last_uid,
		20001
	);
}

#[tokio::test]
async fn an_empty_uid_window_is_checkpointed_before_a_later_failure() {
	use super::super::super::{Filter, Settings, run_with_connection};
	let dir = tempfile::tempdir().expect("dir");
	let states =
		super::super::super::state::StateDir::open(dir.path(), "alice", "alice@old.example")
			.expect("states");
	let saved = super::super::super::state::FolderState {
		folder: "INBOX".into(),
		uid_validity: 7,
		last_uid: 1,
		in_progress: false,
		copied: 1,
	};
	states.save(b"INBOX", &saved).expect("save");
	let replies = vec![
		b"M1 OK login\r\n".to_vec(),
		b"M2 OK capabilities\r\n".to_vec(),
		b"* LIST () \"/\" \"INBOX\"\r\nM3 OK list\r\n".to_vec(),
		b"* 1 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT 40002] next\r\nM4 OK examine\r\n".to_vec(),
		b"M5 OK empty\r\n".to_vec(),
		b"M6 OK empty\r\n".to_vec(),
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
		Some(super::super::super::MigrateError::Client(
			ClientError::Protocol(_)
		))
	));
	assert_eq!(
		states
			.load(b"INBOX")
			.expect("load")
			.expect("saved")
			.last_uid,
		30001
	);
}

mod interrupted;

mod recovery;

mod final_review;

#[allow(unused_imports)]
use super::base as tests;
