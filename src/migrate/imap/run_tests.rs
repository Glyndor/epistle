//! End-to-end tests of `migrate imap` against the in-process fake server.

use std::time::{Duration, SystemTime};

use zeroize::Zeroizing;

use super::fake_server::{FakeServer, Fault, Folder, Message, Mode, USER};
use super::*;
use crate::imap::mailbox::{Flag, Snapshot};
use crate::storage::MessageCrypto;

pub(super) const DATE_1: &str = "17-Jul-2024 02:44:25 -0700";
pub(super) const DATE_2: &str = " 3-Feb-2021 23:00:00 +0200";

/// A message body with a Message-ID.
pub(super) fn mail(id: &str, text: &str) -> Vec<u8> {
	format!("Message-ID: <{id}@old.example>\r\nSubject: {text}\r\n\r\n{text}\r\n").into_bytes()
}

/// A 3 MiB message without a Message-ID.
pub(super) fn large() -> Vec<u8> {
	let mut body = b"Subject: large\r\n\r\n".to_vec();
	for line in 0..(3 * 1024 * 1024 / 64) {
		body.extend(format!("{line:062}\r\n").bytes());
	}
	body
}

/// The mailbox every test starts from, with `.` as the delimiter.
pub(super) fn folders() -> Vec<Folder> {
	vec![
		Folder::new(
			"INBOX",
			"\\HasNoChildren",
			vec![
				Message::new(1, "\\Seen", DATE_1, &mail("1", "one")),
				Message::new(2, "\\Flagged $Custom \\Recent", DATE_2, &mail("2", "two")),
				Message::new(3, "\\Deleted \\Seen", DATE_1, &mail("3", "gone")),
				Message::new(7, "", DATE_2, &large()),
			],
		),
		Folder::new(
			"Sent Items",
			"\\HasNoChildren \\Sent",
			vec![Message::new(4, "\\Seen", DATE_1, &mail("4", "sent"))],
		),
		Folder::new(
			"Spam",
			"\\HasNoChildren \\Junk",
			vec![Message::new(9, "", DATE_1, &mail("9", "spam"))],
		),
		Folder::new(
			"Work",
			"\\HasChildren",
			vec![Message::new(5, "", DATE_1, &mail("5", "work"))],
		),
		Folder::new(
			"Work.Projects",
			"\\HasNoChildren",
			vec![Message::new(6, "\\Answered", DATE_1, &mail("6", "project"))],
		),
		Folder::new("Shelf", "\\Noselect \\HasChildren", vec![]),
		Folder::new(
			"All Mail",
			"\\All \\HasNoChildren",
			vec![Message::new(1, "", DATE_1, &mail("1", "one"))],
		),
	]
}

/// Progress that only records what it was told.
#[derive(Default)]
pub(super) struct Quiet {
	pub(super) done: Vec<String>,
}

impl Progress for Quiet {
	fn folder_start(&mut self, _: &FolderReport) {}
	fn folder_progress(&mut self, _: &FolderReport) {}
	fn folder_done(&mut self, report: &FolderReport) {
		self.done.push(report.remote.clone());
	}
	fn skipped(&mut self, _: &Skipped) {}
}

pub(super) fn settings() -> Settings {
	let mut settings = Settings::new(Filter::default(), false);
	settings.limits.idle = Duration::from_secs(5);
	settings.limits.response = Duration::from_secs(30);
	settings.batch_messages = 2;
	settings.batch_bytes = 1024 * 1024;
	settings
}

pub(super) fn source(server: &FakeServer, security: Security) -> Source {
	Source {
		endpoint: server.endpoint(security),
		user: USER.to_string(),
		password: Zeroizing::new(crate::test_fixtures::password().to_string()),
	}
}

pub(super) fn target(dir: &std::path::Path) -> Target {
	Target {
		data_dir: dir.to_path_buf(),
		account: "alice".to_string(),
		crypto: MessageCrypto::disabled(),
		quota: None,
		usage: 0,
	}
}

/// `(flags, internal date, body)` of every message in a local mailbox.
pub(super) fn local(dir: &std::path::Path, mailbox: &str) -> Vec<(Vec<Flag>, SystemTime, Vec<u8>)> {
	if !crate::imap::mailbox::exists(dir, "alice", mailbox) {
		return Vec::new();
	}
	let Ok(snapshot) = Snapshot::open(dir, "alice", mailbox, &MessageCrypto::disabled()) else {
		return Vec::new();
	};
	snapshot
		.messages()
		.map(|m| {
			(
				m.flags.clone(),
				m.internal_date,
				snapshot.read(m).expect("read"),
			)
		})
		.collect()
}

fn date(text: &str) -> SystemTime {
	crate::imap::command::parse_date_time(text).expect("date")
}

pub(super) async fn migrate(
	server: &FakeServer,
	dir: &std::path::Path,
	settings: &Settings,
) -> (Summary, Option<MigrateError>) {
	let mut target = target(dir);
	run(
		&source(server, Security::Tls),
		&mut target,
		settings,
		&mut Quiet::default(),
	)
	.await
}

#[tokio::test]
async fn copies_every_folder_with_flags_and_dates() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");

	let inbox = local(dir.path(), "INBOX");
	assert_eq!(inbox.len(), 3, "the \\Deleted message is not carried over");
	assert_eq!(inbox[0].0, vec![Flag::Seen]);
	assert_eq!(inbox[0].1, date(DATE_1));
	assert_eq!(inbox[0].2, mail("1", "one"));
	assert_eq!(
		inbox[1].0,
		vec![Flag::Flagged, Flag::parse("$Custom").expect("keyword")],
		"\\Recent is dropped, the keyword kept"
	);
	assert_eq!(inbox[1].1, date(DATE_2));
	assert_eq!(inbox[2].2, large(), "the large message arrives intact");

	assert_eq!(local(dir.path(), "Sent")[0].2, mail("4", "sent"));
	assert_eq!(local(dir.path(), "Junk")[0].2, mail("9", "spam"));
	assert_eq!(local(dir.path(), "Work")[0].2, mail("5", "work"));

	let inbox_report = &summary.folders[0];
	assert_eq!(
		(inbox_report.remote.as_str(), inbox_report.local.as_str()),
		("INBOX", "INBOX")
	);
	assert_eq!((inbox_report.copied, inbox_report.deleted), (3, 1));
	let skipped: Vec<&str> = summary.skipped.iter().map(|s| s.folder.as_str()).collect();
	assert!(skipped.contains(&"Shelf"), "{skipped:?}");
	assert!(
		skipped.contains(&"All Mail"),
		"the virtual \\All folder is not copied: {skipped:?}"
	);

	// The nested folder lands under the local separator when the local
	// store accepts nested names, and is reported, not mangled, when not.
	if crate::imap::mailbox::valid_name("Work/Projects") {
		assert_eq!(
			local(dir.path(), "Work/Projects")[0].0,
			vec![Flag::Answered]
		);
	} else {
		assert!(skipped.contains(&"Work.Projects"), "{skipped:?}");
		assert!(!crate::imap::mailbox::exists(
			dir.path(),
			"alice",
			"Work.Projects"
		));
	}
	assert_eq!(
		summary.copied,
		6 + u64::from(crate::imap::mailbox::valid_name("Work/Projects"))
	);
}

#[tokio::test]
async fn a_second_run_copies_nothing_and_a_third_only_what_is_new() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let (first, _) = migrate(&server, dir.path(), &settings()).await;
	assert!(first.copied > 0);

	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.copied, 0);
	assert_eq!(local(dir.path(), "INBOX").len(), 3);

	server.edit(|folders| {
		folders[0]
			.messages
			.push(Message::new(8, "", DATE_1, &mail("8", "new")));
	});
	let (third, _) = migrate(&server, dir.path(), &settings()).await;
	assert_eq!(third.copied, 1);
	let inbox = local(dir.path(), "INBOX");
	assert_eq!(inbox.len(), 4);
	assert_eq!(inbox[3].2, mail("8", "new"));
}

#[tokio::test]
async fn a_run_cut_mid_batch_resumes_without_duplicates() {
	let mut folders = folders();
	folders[0].messages = (1..=5)
		.map(|uid| Message::new(uid, "", DATE_1, &mail(&uid.to_string(), "n")))
		.collect();
	let server = FakeServer::start(Mode::Tls, '.', folders).await;
	let dir = tempfile::tempdir().expect("tempdir");
	// Batches of two: the second batch is cut after one body.
	server.set_fault(Fault::DropDuringFetch { fetch: 2, after: 1 });
	let (first, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_some(), "the cut must stop the run");
	assert_eq!(first.copied, 2);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"only the whole first batch is stored"
	);

	let (second, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(second.folders[0].copied, 3);
	let bodies: Vec<Vec<u8>> = local(dir.path(), "INBOX")
		.into_iter()
		.map(|m| m.2)
		.collect();
	let expected: Vec<Vec<u8>> = (1..=5).map(|uid| mail(&uid.to_string(), "n")).collect();
	assert_eq!(bodies, expected);
}

#[tokio::test]
async fn a_run_killed_while_storing_checks_before_storing_again() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	migrate(&server, dir.path(), &settings()).await;
	// What a kill between storing and recording leaves: the messages are
	// stored, the state still says the batch was in progress before them.
	let key = format!("{USER}@mail.example.org");
	let states = state::StateDir::open(dir.path(), "alice", &key).expect("state");
	let mut saved = states.load(b"INBOX").expect("load").expect("saved");
	saved.last_uid = 0;
	saved.in_progress = true;
	states.save(b"INBOX", &saved).expect("save");

	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.folders[0].copied, 0);
	assert_eq!(summary.folders[0].duplicates, 3);
	assert_eq!(local(dir.path(), "INBOX").len(), 3);
}

#[tokio::test]
async fn a_uidvalidity_change_copies_again_without_duplicates() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	migrate(&server, dir.path(), &settings()).await;
	server.edit(|folders| {
		let inbox = &mut folders[0];
		inbox.uid_validity += 1;
		for (index, message) in inbox.messages.iter_mut().enumerate() {
			message.uid = 100 + index as u32;
		}
		inbox
			.messages
			.push(Message::new(200, "", DATE_1, &mail("200", "after")));
	});
	let (summary, error) = migrate(&server, dir.path(), &settings()).await;
	assert!(error.is_none(), "{error:?}");
	let inbox = &summary.folders[0];
	assert!(inbox.restarted);
	assert_eq!((inbox.copied, inbox.duplicates, inbox.deleted), (1, 3, 1));
	assert_eq!(local(dir.path(), "INBOX").len(), 4);
}

#[tokio::test]
async fn the_quota_stops_the_run_and_a_rerun_continues() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut target = target(dir.path());
	target.quota = Some(1024);
	let (summary, error) = run(
		&source(&server, Security::Tls),
		&mut target,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(
		matches!(error, Some(MigrateError::Quota { limit: 1024, .. })),
		"{error:?}"
	);
	assert!(error.expect("quota").to_string().contains("quota"));
	assert_eq!(
		summary.copied, 2,
		"the summary counts what was stored before the stop"
	);
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		2,
		"the two small messages fit"
	);

	let mut target = self::target(dir.path());
	target.usage = 0;
	let (_, error) = run(
		&source(&server, Security::Tls),
		&mut target,
		&settings(),
		&mut Quiet::default(),
	)
	.await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(
		local(dir.path(), "INBOX").len(),
		3,
		"the rest arrives, nothing twice"
	);
}

#[tokio::test]
async fn a_dry_run_lists_and_writes_nothing() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut settings = settings();
	settings.dry_run = true;
	let (summary, error) = migrate(&server, dir.path(), &settings).await;
	assert!(error.is_none(), "{error:?}");
	assert_eq!(summary.copied, 0);
	assert_eq!(summary.folders[0].messages, 4);
	assert!(
		!dir.path().join("accounts").exists(),
		"no mailbox was created"
	);
	assert!(
		!dir.path().join("migrate").exists(),
		"no progress was recorded"
	);
}

#[tokio::test]
async fn folders_filters_by_name() {
	let server = FakeServer::start(Mode::Tls, '.', folders()).await;
	let dir = tempfile::tempdir().expect("tempdir");
	let mut settings = settings();
	settings.filter = Filter::new(&["*".to_string(), "!Work*".to_string(), "!Spam".to_string()]);
	let (summary, _) = migrate(&server, dir.path(), &settings).await;
	let copied: Vec<&str> = summary.folders.iter().map(|f| f.remote.as_str()).collect();
	assert_eq!(copied, ["INBOX", "Sent Items"]);
}
