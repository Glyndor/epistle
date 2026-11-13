//! Parsing and running the accounts, account add and queue commands.

use super::*;
use std::collections::BTreeMap;
use std::io::Write;

#[test]
fn parses_accounts_command() {
	let cli = Cli::try_parse_from(["epistle", "accounts", "--config", "/etc/mail.toml"])
		.expect("accounts parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::Accounts { .. })
	));
}

fn write_config(toml: &str) -> tempfile::NamedTempFile {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(toml.as_bytes()).expect("write");
	file
}

#[test]
fn accounts_list_prints_configured_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n\n\
[[accounts]]\nname = \"alice\"\naddresses = [\"alice@example.org\", \"postmaster@example.org\"]\n",
		dir.path()
	));
	let config = crate::config::Config::load(cfg.path()).expect("config");
	let mut out = Vec::new();
	assert_eq!(accounts::list(&config, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("alice\tstatic\talice@example.org"), "{text}");
	assert!(text.contains("1 accounts"), "{text}");

	let file = tempfile::NamedTempFile::new().expect("file");
	let bad = write_config(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		file.path()
	));
	let config = crate::config::Config::load(bad.path()).expect("config");
	let mut out = Vec::new();
	assert_eq!(accounts::list(&config, &mut out), ExitCode::FAILURE);
}

#[test]
fn parses_account_add_command() {
	let cli = Cli::try_parse_from([
		"epistle",
		"account-add",
		"--config",
		"/etc/mail.toml",
		"--name",
		"bob",
		"--address",
		"bob@example.org",
	])
	.expect("account-add parses");
	assert!(matches!(
		cli.command,
		Command::Legacy(crate::cli::legacy::Legacy::AccountAdd { .. })
	));
}

#[test]
fn account_add_creates_and_validates() {
	use std::io::Cursor;
	let dir = tempfile::tempdir().expect("tempdir");
	let cfg = write_config(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		dir.path()
	));
	let config = crate::config::Config::load(cfg.path()).expect("config");

	assert_eq!(
		accounts::add(
			&config,
			"bob",
			vec!["bob@example.org".into()],
			Cursor::new("\n")
		),
		ExitCode::from(2)
	);
	assert_eq!(
		accounts::add(
			&config,
			"bob",
			vec!["bob@example.org".into()],
			Cursor::new("short")
		),
		ExitCode::from(2)
	);
	assert_eq!(
		accounts::add(
			&config,
			"bob",
			vec!["bob@example.org".into()],
			Cursor::new("a-long-password")
		),
		ExitCode::SUCCESS
	);
	let mut out = Vec::new();
	let _ = accounts::list(&config, &mut out);
	assert!(String::from_utf8_lossy(&out).contains("bob\tdynamic\tbob@example.org"));
	assert_eq!(
		accounts::add(
			&config,
			"bob",
			vec!["bob2@example.org".into()],
			Cursor::new("a-long-password")
		),
		ExitCode::from(2)
	);

	let file = tempfile::NamedTempFile::new().expect("file");
	let bad = write_config(&format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n",
		file.path()
	));
	let bad = crate::config::Config::load(bad.path()).expect("config");
	assert_eq!(
		accounts::add(
			&bad,
			"eve",
			vec!["eve@example.org".into()],
			Cursor::new("a-long-password")
		),
		ExitCode::FAILURE
	);
}

#[test]
fn parses_queue_command() {
	let cli = Cli::try_parse_from(["epistle", "queue", "--config", "/etc/mail.toml"])
		.expect("queue parses");
	assert!(matches!(cli.command, Command::Queue { .. }));
}

#[test]
fn queue_list_reports_and_handles_edge_cases() {
	use crate::smtp::session::AcceptedMessage;
	use crate::storage::FsSpool;
	let dir = tempfile::tempdir().expect("tempdir");
	// Empty spool: only the total line.
	let mut out = Vec::new();
	assert_eq!(queue::list(dir.path(), None, &mut out), ExitCode::SUCCESS);
	assert!(String::from_utf8_lossy(&out).contains("0 queued"));

	let spool = FsSpool::open(dir.path()).expect("spool");
	spool
		.store(
			&AcceptedMessage {
				reverse_path: "bob@example.org".into(),
				recipients: vec!["carol@elsewhere.example".into()],
				data: b"Subject: x\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	// A bounce uses the null reverse-path, shown as <>.
	spool
		.store(
			&AcceptedMessage {
				reverse_path: String::new(),
				recipients: vec!["dave@elsewhere.example".into()],
				data: b"x\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&BTreeMap::new(),
		)
		.expect("store");
	// A corrupt entry is listed but skipped on load.
	std::fs::write(
		dir.path()
			.join("spool")
			.join("new")
			.join(format!("{}.json", uuid::Uuid::now_v7())),
		b"not json",
	)
	.expect("write");
	let mut out = Vec::new();
	assert_eq!(queue::list(dir.path(), None, &mut out), ExitCode::SUCCESS);
	let text = String::from_utf8(out).expect("utf8");
	assert!(text.contains("from=bob@example.org"), "{text}");
	assert!(text.contains("from=<>"), "{text}");
	assert!(text.contains("3 queued"), "{text}");

	// An unavailable spool (data_dir is a file) reports failure.
	let file = tempfile::NamedTempFile::new().expect("file");
	let mut out = Vec::new();
	assert_eq!(queue::list(file.path(), None, &mut out), ExitCode::FAILURE);

	// An unreadable spool directory makes the listing itself fail.
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let dir = tempfile::tempdir().expect("tempdir");
		FsSpool::open(dir.path()).expect("spool");
		let new = dir.path().join("spool").join("new");
		std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o000)).expect("chmod");
		// A process holding CAP_DAC_OVERRIDE - root, which is what
		// dpkg-buildpackage runs the suite as - reads the directory anyway, so
		// there is no denial to observe and the assertion below would be
		// asserting the opposite of what it says. Probe the precondition
		// directly rather than checking the uid: the capability, not the uid,
		// is what decides, and a non-root process can hold it too.
		let denied = std::fs::read_dir(&new).is_err();
		let mut out = Vec::new();
		let result = queue::list(dir.path(), None, &mut out);
		// Restore permissions so the tempdir can be cleaned up.
		let _ = std::fs::set_permissions(&new, std::fs::Permissions::from_mode(0o755));
		if denied {
			assert_eq!(result, ExitCode::FAILURE);
		}
	}
}
