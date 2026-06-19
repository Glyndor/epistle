//! CLI command-dispatch tests (Cli::run over real temp configs).

use super::*;
use std::io::Write;

fn config_at(data_dir: &std::path::Path) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	write!(
		file,
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		data_dir
	)
	.expect("write");
	file
}

fn run(args: &[&str]) -> ExitCode {
	Cli::try_parse_from(args).expect("parses").run()
}

#[test]
fn export_dispatch_succeeds_for_existing_account() {
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(
		run(&["mail", "export", "--config", path, "--account", "alice"]),
		ExitCode::SUCCESS
	);
}

#[test]
fn queue_dispatch_succeeds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(run(&["mail", "queue", "--config", path]), ExitCode::SUCCESS);
}

#[test]
fn accounts_dispatch_succeeds() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = config_at(dir.path());
	let path = cfg.path().to_str().expect("utf8");
	assert_eq!(
		run(&["mail", "accounts", "--config", path]),
		ExitCode::SUCCESS
	);
}

#[test]
fn dispatch_reports_config_load_failure() {
	// A nonexistent config file makes every config-taking command fail.
	for args in [
		vec!["mail", "export", "--config", "/nope.toml", "--account", "a"],
		vec!["mail", "queue", "--config", "/nope.toml"],
		vec!["mail", "accounts", "--config", "/nope.toml"],
		vec!["mail", "config-check", "--config", "/nope.toml"],
	] {
		assert_eq!(run(&args), ExitCode::FAILURE, "{args:?}");
	}
}
#[test]
fn parses_import_command() {
	let cli = Cli::try_parse_from([
		"mail",
		"import",
		"--config",
		"/etc/mail.toml",
		"--account",
		"alice",
	])
	.expect("import parses");
	assert!(matches!(cli.command, Command::Import { .. }));
}

#[test]
fn import_delivers_mbox_messages_to_inbox() {
	use std::io::Cursor;
	let dir = tempfile::tempdir().expect("tempdir");
	std::fs::create_dir_all(dir.path().join("accounts").join("alice")).expect("mkdir");
	let mbox = "From MAILER-DAEMON@localhost\r\nX-Mailbox: INBOX\r\nSubject: one\r\n\r\nbody1\r\n\r\nFrom MAILER-DAEMON@localhost\r\nSubject: two\r\n\r\n>From the desk\r\n\r\n";
	assert_eq!(
		import::run(dir.path(), "alice", Cursor::new(mbox)),
		ExitCode::SUCCESS
	);
	let snapshot =
		crate::imap::mailbox::Snapshot::open(dir.path(), "alice", "INBOX").expect("snapshot");
	assert_eq!(snapshot.len(), 2);
	let bodies: Vec<String> = snapshot
		.messages()
		.map(|m| String::from_utf8_lossy(&snapshot.read(m).expect("read")).into_owned())
		.collect();
	let joined = bodies.join("\n");
	assert!(!joined.contains("X-Mailbox"), "{joined}");
	assert!(joined.contains("From the desk"), "{joined}");
	assert!(!joined.contains(">From the desk"), "{joined}");
}

#[test]
fn import_maildir_delivers_to_inbox_and_nested_folders_with_flags() {
	use crate::imap::mailbox::{Flag, Snapshot};
	let dir = tempfile::tempdir().expect("tempdir");
	let src = dir.path().join("maildir");
	// Root maildir: one unseen (new), one seen (cur).
	std::fs::create_dir_all(src.join("new")).expect("mkdir");
	std::fs::create_dir_all(src.join("cur")).expect("mkdir");
	std::fs::write(src.join("new").join("a"), "Subject: unseen\n\nbody-a\n").expect("write");
	std::fs::write(src.join("cur").join("b:2,S"), "Subject: seen\n\nbody-b\n").expect("write");
	// Nested Dovecot folder .Sent with a replied+seen message.
	std::fs::create_dir_all(src.join(".Sent").join("cur")).expect("mkdir");
	std::fs::write(
		src.join(".Sent").join("cur").join("c:2,RS"),
		"Subject: sent\n\nbody-c\n",
	)
	.expect("write");

	assert_eq!(
		import::run_maildir(dir.path(), "alice", &src),
		ExitCode::SUCCESS
	);

	let inbox = Snapshot::open(dir.path(), "alice", "INBOX").expect("inbox");
	assert_eq!(inbox.len(), 2);
	// LF was normalized to CRLF on import.
	let inbox_bodies: Vec<String> = inbox
		.messages()
		.map(|m| String::from_utf8_lossy(&inbox.read(m).expect("read")).into_owned())
		.collect();
	assert!(
		inbox_bodies.iter().any(|b| b.contains("body-a\r\n")),
		"CRLF"
	);
	// The cur message kept its \Seen flag; the new message did not.
	let seen_count = inbox
		.messages()
		.filter(|m| m.flags.contains(&Flag::Seen))
		.count();
	assert_eq!(seen_count, 1);

	let sent = Snapshot::open(dir.path(), "alice", "Sent").expect("sent");
	assert_eq!(sent.len(), 1);
	let sent_msg = sent.messages().next().expect("sent msg");
	assert!(sent_msg.flags.contains(&Flag::Seen));
	assert!(sent_msg.flags.contains(&Flag::Answered));
}
