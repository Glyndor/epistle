use super::*;
use epistle::imap::mailbox::{self, Snapshot};
use epistle::storage::{FsSpool, MessageCrypto};

fn check_verify_skips(kind: &str) {
	let root = tempfile::tempdir().unwrap();
	let data = root.path().join("data");
	mailbox::append(
		&data,
		"alice",
		"INBOX",
		&[],
		b"Subject: x\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.unwrap();
	let outside = root.path().join("outside");
	std::fs::write(&outside, "Subject: outside\r\n\r\nbody").unwrap();
	let skipped = data.join("accounts/alice/new/00000000-0000-0000-0000-000000000001.eml");
	special(&skipped, kind, &outside);
	let config = config(root.path(), &data);
	let output = run(&["verify", "--config", config.to_str().unwrap()]);
	assert_eq!(
		output
			.as_ref()
			.map(|out| String::from_utf8_lossy(&out.stdout).into_owned()),
		Some("checked 1 accounts, 1 messages: 0 problems\n".to_string()),
		"verify must count only the regular message and report zero problems"
	);
	let output = output.unwrap();
	assert_eq!(
		output.status.code(),
		Some(0),
		"skipped special files must not fail verify"
	);
	assert_warning_once(&output, &skipped);
}

#[test]
fn verify_skips_non_regular_message_files_socket() {
	check_verify_skips("socket");
}

#[test]
fn verify_skips_non_regular_message_files_fifo() {
	check_verify_skips("fifo");
}

#[test]
fn verify_skips_non_regular_message_files_symlink() {
	check_verify_skips("symlink");
}

#[test]
fn mailbox_and_spool_walkers_collect_only_regular_files() {
	for kind in ["socket", "fifo", "symlink"] {
		let root = tempfile::tempdir().unwrap();
		let mailbox_dir = root.path().join("accounts/alice/new");
		std::fs::create_dir_all(&mailbox_dir).unwrap();
		let outside = root.path().join("outside");
		std::fs::write(&outside, "outside").unwrap();
		special(
			&mailbox_dir.join("00000000-0000-0000-0000-000000000001.eml"),
			kind,
			&outside,
		);
		let snapshot =
			Snapshot::open(root.path(), "alice", "INBOX", &MessageCrypto::disabled()).unwrap();
		assert_eq!(
			snapshot.messages().count(),
			0,
			"mailbox snapshots must exclude non-regular message files"
		);
		assert_eq!(
			mailbox::account_usage(root.path(), "alice", &MessageCrypto::disabled()),
			0,
			"non-regular message files must consume no mail quota"
		);
		let spool = FsSpool::open(root.path()).unwrap();
		special(
			&root
				.path()
				.join("spool/new/00000000-0000-0000-0000-000000000001.json"),
			kind,
			&outside,
		);
		assert_eq!(
			spool.list().unwrap().len(),
			0,
			"spool listings must exclude non-regular envelope files"
		);
	}
}

#[test]
fn verify_skips_symlinked_accounts() {
	let root = tempfile::tempdir().unwrap();
	let outside = tempfile::tempdir().unwrap();
	mailbox::append(
		outside.path(),
		"alice",
		"INBOX",
		&[],
		b"Subject: outside\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.unwrap();
	std::fs::create_dir(root.path().join("accounts")).unwrap();
	let skipped = root.path().join("accounts/alice");
	symlink(outside.path().join("accounts/alice"), &skipped).unwrap();
	let config_root = tempfile::tempdir().unwrap();
	let config = config(config_root.path(), root.path());
	let output = run(&["verify", "--config", config.to_str().unwrap()]).unwrap();
	assert_eq!(
		String::from_utf8_lossy(&output.stdout),
		"checked 0 accounts, 0 messages: 0 problems\n",
		"verify must not descend into symlinked accounts"
	);
	assert_warning_once(&output, &skipped);
}

#[test]
fn export_skips_special_files_and_warns_once() {
	let root = tempfile::tempdir().unwrap();
	let data = root.path().join("data");
	mailbox::append(
		&data,
		"alice",
		"INBOX",
		&[],
		b"Subject: x\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.unwrap();
	let outside = root.path().join("outside");
	std::fs::write(&outside, "Subject: outside\r\n\r\nbody").unwrap();
	let mut skipped = Vec::new();
	for (id, kind) in [(1, "socket"), (2, "fifo"), (3, "symlink")] {
		let path = data.join(format!(
			"accounts/alice/new/00000000-0000-0000-0000-{id:012}.eml"
		));
		special(&path, kind, &outside);
		skipped.push(path);
	}
	let config = config(root.path(), &data);
	let output = run(&[
		"export",
		"--account",
		"alice",
		"--config",
		config.to_str().unwrap(),
	]);
	assert_eq!(
		output
			.as_ref()
			.map(|out| String::from_utf8_lossy(&out.stdout)
				.matches("From MAILER-DAEMON@localhost\r\n")
				.count()),
		Some(1),
		"export must emit exactly the one regular message"
	);
	let output = output.unwrap();
	assert_eq!(
		output.status.code(),
		Some(0),
		"export must succeed with special files present"
	);
	for path in skipped {
		assert_warning_once(&output, &path);
	}
}

#[test]
fn export_warns_once_for_a_skipped_flags_sidecar() {
	let root = tempfile::tempdir().unwrap();
	let data = root.path().join("data");
	let id = mailbox::append(
		&data,
		"alice",
		"INBOX",
		&[],
		b"Subject: x\r\n\r\nbody",
		&MessageCrypto::disabled(),
	)
	.unwrap();
	let skipped = data.join(format!("accounts/alice/new/{id}.flags"));
	special(&skipped, "socket", root.path());
	let config = config(root.path(), &data);
	let output = run(&[
		"export",
		"--account",
		"alice",
		"--config",
		config.to_str().unwrap(),
	])
	.unwrap();
	assert_eq!(
		String::from_utf8_lossy(&output.stdout)
			.matches("From MAILER-DAEMON@localhost\r\n")
			.count(),
		1,
		"a skipped flags sidecar must preserve the regular message in export"
	);
	assert_warning_once(&output, &skipped);
}
