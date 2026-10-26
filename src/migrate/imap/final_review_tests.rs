//! Final-review regressions over in-memory IMAP connections.

use super::*;
use crate::migrate::imap::{Filter, MigrateError, Settings, run_with_connection};

#[tokio::test]
async fn an_underestimated_uidnext_does_not_omit_the_tail() {
	for dry_run in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let mut replies = vec![
			b"M1 OK login\r\n".to_vec(),
			b"M2 OK capabilities\r\n".to_vec(),
			b"* LIST () \"/\" \"INBOX\"\r\nM3 OK list\r\n".to_vec(),
			b"* 2 EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\n* OK [UIDNEXT 2] next\r\nM4 OK examine\r\n".to_vec(),
			b"* 1 FETCH (UID 1 RFC822.SIZE 1)\r\nM5 OK list\r\n".to_vec(),
		];
		let mut tag = 6;
		if !dry_run {
			replies.push(body_reply(1, tag));
			tag += 1;
		}
		replies.push(format!("* 2 FETCH (UID 3 RFC822.SIZE 1)\r\nM{tag} OK tail\r\n").into_bytes());
		tag += 1;
		if !dry_run {
			replies.push(body_reply(3, tag));
			tag += 1;
		}
		replies.push(format!("M{tag} OK logout\r\n").into_bytes());
		let (client, server) = tests::scripted_client(replies).await;
		let (summary, error) = run_with_connection(
			&source(),
			&mut target(dir.path()),
			&Settings::new(Filter::default(), dry_run),
			&mut Quiet::default(),
			std::future::ready(Ok(client)),
		)
		.await;
		server.abort();
		assert!(error.is_none(), "tail query must finish: {error:?}");
		assert_eq!(
			summary.folders[0].messages, 2,
			"include UIDs at and above UIDNEXT"
		);
		assert_eq!(summary.copied, if dry_run { 0 } else { 2 });
		assert_eq!(
			local(dir.path(), "INBOX").len(),
			if dry_run { 0 } else { 2 }
		);
	}
}

fn body_reply(uid: u32, tag: u32) -> Vec<u8> {
	format!("* {uid} FETCH (UID {uid} FLAGS () INTERNALDATE \"17-Jul-2024 02:44:25 -0700\" RFC822.SIZE 1 BODY[] {{1}}\r\na)\r\nM{tag} OK body\r\n").into_bytes()
}

#[tokio::test]
async fn missing_uidnext_tolerates_only_bounded_mailbox_growth() {
	for (exists, listed, accepted) in [(1, 2, true), (1, 17, true), (1, 18, false), (0, 1, true)] {
		let dir = tempfile::tempdir().unwrap();
		let log_path = dir.path().join("log");
		let subscriber = tracing_subscriber::fmt()
			.with_ansi(false)
			.without_time()
			.with_writer(std::fs::File::create(&log_path).unwrap())
			.finish();
		let _subscriber = tracing::subscriber::set_default(subscriber);
		let listing = (1..=listed)
			.map(|uid| format!("* {uid} FETCH (UID {uid} RFC822.SIZE 1)\r\n"))
			.collect::<String>();
		let replies = vec![
			b"M1 OK login\r\n".to_vec(),
			b"M2 OK capabilities\r\n".to_vec(),
			b"* LIST () \"/\" \"INBOX\"\r\nM3 OK list\r\n".to_vec(),
			format!("* {exists} EXISTS\r\n* OK [UIDVALIDITY 7] stable\r\nM4 OK examine\r\n")
				.into_bytes(),
			format!("{listing}M5 OK list\r\n").into_bytes(),
			b"M6 OK logout\r\n".to_vec(),
		];
		let (client, server) = tests::scripted_client(replies).await;
		let (summary, error) = run_with_connection(
			&source(),
			&mut target(dir.path()),
			&Settings::new(Filter::default(), true),
			&mut Quiet::default(),
			std::future::ready(Ok(client)),
		)
		.await;
		server.abort();
		if accepted {
			assert!(
				error.is_none(),
				"accept bounded arrivals without UIDNEXT: {error:?}"
			);
			assert_eq!(summary.folders[0].messages, listed);
			let log = std::fs::read_to_string(&log_path).unwrap();
			assert!(
				log.contains("IMAP mailbox grew") && log.contains(&format!("listed={listed}")),
				"record the bounded discrepancy: {log}"
			);
		} else {
			assert!(
				matches!(error, Some(MigrateError::Client(ClientError::Protocol(_)))),
				"reject unbounded growth: {error:?}"
			);
		}
	}
}

#[tokio::test]
async fn recovery_accepts_a_local_body_above_the_source_literal_limit() {
	for encrypted in [false, true] {
		let dir = tempfile::tempdir().unwrap();
		let mut local_target = target(dir.path());
		if encrypted {
			local_target.crypto = crate::storage::MessageCrypto::for_test(&[9; 32]);
		}
		let body = vec![b'a'; crate::imap::command::DEFAULT_APPEND_LIMIT + 1];
		local_target.max_message_size = body.len();
		crate::imap::mailbox::append(
			dir.path(),
			"alice",
			"INBOX",
			&[],
			&body,
			&local_target.crypto,
		)
		.unwrap();
		let states =
			crate::migrate::imap::state::StateDir::open(dir.path(), "alice", "alice@old.example")
				.unwrap();
		states
			.save(
				b"INBOX",
				&crate::migrate::imap::state::FolderState {
					folder: "INBOX".into(),
					uid_validity: 7,
					last_uid: 0,
					in_progress: true,
					copied: 0,
				},
			)
			.unwrap();
		let (stream, peer) = tokio::io::duplex(4096);
		let server = tokio::spawn(migration_peer(peer, false, 2, Default::default(), 2));
		let mut settings = Settings::new(Filter::default(), false);
		settings.batch_messages = 1;
		let (summary, error) = run_with_connection(
			&source(),
			&mut local_target,
			&settings,
			&mut Quiet::default(),
			std::future::ready(Ok(tests::memory_client(stream))),
		)
		.await;
		server.abort();
		assert!(
			error.is_none(),
			"recover a body allowed by the local configuration: {error:?}"
		);
		assert_eq!(summary.copied, 2);
		assert!(!states.load(b"INBOX").unwrap().unwrap().in_progress);
	}
}
