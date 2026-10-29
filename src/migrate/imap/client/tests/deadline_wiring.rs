//! The run's total deadline has to reach the scan of the local mailbox, which
//! never awaits and so is out of the timeout's reach.

use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

use super::super::super::state::{FolderState, StateDir};
use super::super::super::tests::run::{Quiet, target};
use super::super::super::{
	Filter, MigrateError, Settings, Source, Verify, durability, run_with_connection,
};
use super::base::memory_client;
use super::{Endpoint, Security};
use zeroize::Zeroizing;

/// A server that goes quiet for `pause` with a blocking sleep right before it
/// answers the UID listing, so that the deadline passes while the client has
/// no await left before it scans the local mailbox.
async fn slow_listing_peer(peer: tokio::io::DuplexStream, pause: Duration) {
	let mut peer = BufReader::new(peer);
	loop {
		let mut line = String::new();
		if peer.read_line(&mut line).await.expect("command") == 0 {
			return;
		}
		let (tag, command) = line.split_once(' ').expect("tag");
		let data = if command.starts_with("LIST ") {
			"* LIST () \"/\" \"INBOX\"\r\n".to_string()
		} else if command.starts_with("EXAMINE ") {
			"* 2 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT 3] next\r\n".to_string()
		} else if command.contains("RFC822.SIZE)") {
			std::thread::sleep(pause);
			(1..=2)
				.map(|uid| format!("* {uid} FETCH (UID {uid} RFC822.SIZE 1)\r\n"))
				.collect()
		} else {
			String::new()
		};
		let reply = format!("{data}{tag} OK done\r\n");
		if peer.get_mut().write_all(reply.as_bytes()).await.is_err()
			|| command.starts_with("LOGOUT")
		{
			return;
		}
	}
}

#[tokio::test]
async fn the_total_deadline_stops_the_scan_of_the_local_mailbox() {
	let dir = tempfile::tempdir().expect("dir");
	let crypto = target(dir.path()).crypto;
	for _ in 0..30 {
		crate::imap::mailbox::append(dir.path(), "alice", "INBOX", &[], b"a", &crypto)
			.expect("local message");
	}
	// A copy that stopped part way: the folder is replayed and every local
	// message goes through the recovery scan.
	StateDir::open(dir.path(), "alice", "alice@old.example")
		.expect("states")
		.save(
			b"INBOX",
			&FolderState {
				folder: "INBOX".into(),
				uid_validity: 7,
				last_uid: 0,
				in_progress: true,
				copied: 0,
			},
		)
		.expect("save");
	let (stream, peer) = tokio::io::duplex(4096);
	let server = tokio::spawn(slow_listing_peer(peer, Duration::from_millis(500)));
	let mut settings = Settings::new(Filter::default(), false);
	settings.total_timeout = Duration::from_millis(300);
	let source = Source {
		endpoint: Endpoint {
			host: "old.example".into(),
			port: 993,
			address: None,
			security: Security::Tls,
			verify: Verify::Skip,
		},
		user: "alice".into(),
		password: Zeroizing::new(crate::test_fixtures::password().into()),
	};
	let _guard = durability::tests::base::begin(None);
	let (_, error) = run_with_connection(
		&source,
		&mut target(dir.path()),
		&settings,
		&mut Quiet::default(),
		std::future::ready(Ok(memory_client(stream))),
	)
	.await;
	server.abort();
	assert!(matches!(error, Some(MigrateError::Timeout)), "{error:?}");
	let synchronized = durability::tests::base::events()
		.iter()
		.filter(|event| **event == "message")
		.count();
	assert_eq!(
		synchronized, 0,
		"the scan stopped at the first message instead of running to its end"
	);
}
