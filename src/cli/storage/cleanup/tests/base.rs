use super::*;
use crate::imap::mailbox;
use crate::storage::MessageCrypto;

fn config(dir: &std::path::Path, extra: &str) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(
		&path,
		format!(
			"hostname = 'mail.example.org'\ndata_dir = {:?}\ndomains = ['example.org']\n{extra}",
			dir.join("data")
		),
	)
	.expect("config");
	use std::os::unix::fs::PermissionsExt;
	std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).expect("mode");
	path
}

fn run_it(path: &Path, json: bool) -> (ExitCode, String, String) {
	let (mut out, mut status) = (Vec::new(), Vec::new());
	let code = run(path, json, &mut out, &mut status);
	(
		code,
		String::from_utf8(out).expect("utf8"),
		String::from_utf8(status).expect("utf8"),
	)
}

#[test]
fn without_the_section_it_says_nothing_is_removed() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("data")).expect("data");
	let path = config(dir.path(), "");
	let (code, out, status) = run_it(&path, false);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(out.is_empty());
	assert!(status.contains("nothing is removed"), "{status}");
}

#[test]
fn it_lists_what_is_due_and_removes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data = dir.path().join("data");
	std::fs::create_dir_all(&data).expect("data");
	mailbox::ensure_defaults(&data, "alice").expect("defaults");
	for _ in 0..2 {
		mailbox::append(
			&data,
			"alice",
			"Trash",
			&[],
			b"Subject: x\r\n\r\nb\r\n",
			&MessageCrypto::disabled(),
		)
		.expect("append");
	}
	// One day: the messages arrived a moment ago, so none is due yet.
	let path = config(
		dir.path(),
		"[storage.cleanup]\n[[storage.cleanup.rule]]\nscope = 'server'\nfolder = 'trash'\ndays = 1\n",
	);
	let (code, out, status) = run_it(&path, true);
	assert_eq!(code, ExitCode::SUCCESS);
	assert!(
		out.contains("\"messages\": 0") || out.contains("\"messages\":0"),
		"{out}"
	);
	assert!(status.contains("this machine's clock"), "{status}");
	let held = mailbox::Snapshot::open(&data, "alice", "Trash", &MessageCrypto::disabled())
		.expect("snapshot")
		.len();
	assert_eq!(held, 2, "a listing removes nothing");
}
