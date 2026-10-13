//! Every destructive command honours the same four answers: piped without
//! `--yes` it refuses with exit code 2 and a message naming `--yes`; on a
//! terminal it asks, and `n` cancels while `y` goes ahead; `--yes` goes ahead
//! without asking. The handlers run unchanged; only the console under them
//! is scripted (`prompt::script`).

use std::collections::BTreeMap;
use std::path::Path;
use std::process::ExitCode;

use crate::cli::prompt::script::scripted;
use crate::cli::prompt::{cancelled_message, refused_message};
use crate::cli::queue::QueueCli;
use crate::cli::{accounts, api_keys, app_passwords, archive, queue};
use crate::config::Config;
use crate::directory_store::removal::QueuePolicy;
use crate::directory_store::{AccountStore, AppPasswordStore, DynamicAccount};
use crate::smtp::auth::tests::{fixture_password, hash};
use crate::smtp::session::AcceptedMessage;
use crate::storage::FsSpool;

pub(super) const NAME: &str = "alice";

/// `error: <message>` as the console prints it, colour stripped.
pub(super) fn error(message: &str) -> String {
	format!("error: {message}\n")
}

/// Drive one destructive command through the four answers. `setup` builds
/// a fresh fixture, `run` performs the command with the given `--yes`, and
/// `present` says whether what it destroys is still there.
pub(super) fn gate<S>(
	action: &str,
	question: impl Fn(&S) -> String,
	setup: impl Fn() -> S,
	run: impl Fn(&S, bool) -> ExitCode,
	present: impl Fn(&S) -> bool,
) {
	let fixture = setup();
	let question = question(&fixture);
	assert!(present(&fixture), "{action}: the fixture holds the target");

	let piped = scripted(false, None, "y\n", || run(&fixture, false));
	assert_eq!(piped.value, ExitCode::from(2), "{action}: piped, no --yes");
	assert_eq!(piped.stderr, error(&refused_message(action)));
	assert!(piped.stderr.contains("--yes"), "{}", piped.stderr);
	assert_eq!(piped.unread, 2, "{action}: a piped run reads no answer");
	assert!(present(&fixture), "{action}: the refusal changed something");

	let no = scripted(true, None, "n\n", || run(&fixture, false));
	assert_eq!(no.value, ExitCode::from(2), "{action}: answered n");
	assert_eq!(
		no.stderr,
		format!("{question} {}", error(&cancelled_message(action)))
	);
	assert!(present(&fixture), "{action}: answering n changed something");

	let yes = scripted(true, None, "y\n", || run(&fixture, false));
	assert_eq!(yes.value, ExitCode::SUCCESS, "{action}: answered y");
	assert_eq!(yes.stderr, format!("{question} "));
	assert!(!present(&fixture), "{action}: answering y did not apply");

	let fixture = setup();
	let flag = scripted(false, None, "", || run(&fixture, true));
	assert_eq!(flag.value, ExitCode::SUCCESS, "{action}: --yes");
	assert_eq!(flag.stderr, "", "{action}: --yes asks nothing");
	assert!(!present(&fixture), "{action}: --yes did not apply");
}

/// A data directory and a config file pointing at it, with `extra` TOML
/// appended. The directory is created before the file so `data_dir`
/// canonicalises.
pub(super) fn fixture(extra: &str) -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let dir = tempfile::tempdir().expect("tempdir");
	let mut config = tempfile::NamedTempFile::new().expect("config file");
	std::io::Write::write_all(
		&mut config,
		format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\ndomains = [\"example.org\"]\n{extra}\n",
			dir.path().canonicalize().expect("canonical")
		)
		.as_bytes(),
	)
	.expect("write config");
	(dir, config)
}

pub(super) fn load(path: &Path) -> Config {
	Config::load(path).expect("config loads")
}

pub(super) fn store(config: &Config) -> AccountStore {
	AccountStore::open(
		&config.data_dir,
		config.domains.clone(),
		config.domain_aliases.clone(),
		config.accounts.clone(),
	)
	.expect("open store")
}

/// A fixture holding `alice` as a dynamic account.
pub(super) fn with_alice() -> (tempfile::TempDir, tempfile::NamedTempFile) {
	let (dir, cfg) = fixture("");
	store(&load(cfg.path()))
		.add(DynamicAccount {
			name: NAME.to_string(),
			addresses: vec![format!("{NAME}@example.org")],
			password_hash: hash(fixture_password()),
			scram: None,
			totp_secret: None,
			disabled: false,
			quota_bytes: None,
			allowed_protocols: None,
			..DynamicAccount::default()
		})
		.expect("add alice");
	(dir, cfg)
}

#[test]
fn account_remove_asks_with_what_it_destroys() {
	gate(
		"account-remove",
		|_| {
			"Remove account \"alice\" and its mailbox (0 masked addresses, 0 app passwords), \
			 discarding its queued mail? [y/N]"
				.to_string()
		},
		with_alice,
		|(_, cfg), yes| {
			let config = load(cfg.path());
			accounts::remove(&config, NAME, QueuePolicy::Discard, yes, &mut Vec::new())
		},
		|(_, cfg)| store(&load(cfg.path())).dynamic(NAME).is_some(),
	);
}

#[test]
fn account_remove_refuses_an_unknown_or_static_name_without_asking() {
	let (_dir, cfg) = fixture("[[accounts]]\nname = \"bob\"\naddresses = [\"bob@example.org\"]\n");
	let config = load(cfg.path());
	for name in ["ghost", "bob"] {
		let run = scripted(true, None, "y\n", || {
			accounts::remove(&config, name, QueuePolicy::Drain, false, &mut Vec::new())
		});
		assert_eq!(run.value, ExitCode::from(2), "{name}");
		assert_eq!(run.stderr, "", "{name}: nothing is asked");
		assert_eq!(run.unread, 2, "{name}: no answer is read");
	}
}

fn spooled() -> (tempfile::TempDir, uuid::Uuid) {
	let dir = tempfile::tempdir().expect("tempdir");
	let id = FsSpool::open(dir.path())
		.expect("spool")
		.store(&AcceptedMessage {
			reverse_path: "alice@example.org".to_string(),
			recipients: vec!["bob@remote.example".to_string()],
			data: b"Subject: hello\r\n\r\nbody\r\n".to_vec(),
			require_tls: false,
			mailbox: None,
			tlsrpt_verified: false,
			no_dsn: Vec::new(),
		}, None, &BTreeMap::new())
		.expect("store");
	(dir, id)
}

#[test]
fn queue_remove_asks_with_the_sender_and_recipient_count() {
	gate(
		"queue remove",
		|(_, id)| {
			format!(
				"Remove queued message {id} from alice@example.org to 1 recipients? \
				 It will not be delivered and no bounce is sent. [y/N]"
			)
		},
		spooled,
		|(dir, id), yes| {
			queue::run(
				dir.path(),
				0,
				Some(QueueCli::Remove { id: *id, yes }),
				queue::now_epoch(),
				&mut Vec::new(),
			)
		},
		|(dir, id)| {
			FsSpool::open(dir.path())
				.expect("spool")
				.load_envelope(*id)
				.is_ok()
		},
	);
}

/// An archived entry for `alice` deleted `age` seconds ago.
fn archived(data_dir: &Path, age: u64) {
	let archive = data_dir.join("accounts").join(NAME).join(".archive");
	std::fs::create_dir_all(&archive).expect("mkdir archive");
	let id = uuid::Uuid::new_v4();
	let deleted_at = crate::imap::archive::current_unix_time() - age;
	std::fs::write(
		archive.join(format!("{id}.deleted")),
		format!("{deleted_at}\nINBOX\n"),
	)
	.expect("sidecar");
	std::fs::write(archive.join(format!("{id}.eml")), "Subject: x\r\n\r\nx\r\n").expect("body");
}

fn archive_count(data_dir: &Path) -> usize {
	let root = crate::util::path_component::AccountName::new(NAME)
		.expect("name")
		.root(data_dir)
		.expect("root");
	crate::imap::archive::list(&root).expect("list").len()
}

fn purge(cfg: &Path, older_than_days: Option<u64>, yes: bool) -> ExitCode {
	archive::dispatch(
		archive::Subcommand::Purge {
			config: cfg.to_path_buf(),
			account: NAME.to_string(),
			older_than_days,
			yes,
		},
		&mut Vec::new(),
	)
}

#[test]
fn archive_purge_without_a_selector_says_all() {
	gate(
		"archive purge",
		|_| "Purge all 2 archived entries for \"alice\"? [y/N]".to_string(),
		|| {
			let (dir, cfg) = fixture("[storage]\ndeleted_retention_days = 30");
			archived(dir.path(), 3_600);
			archived(dir.path(), 40 * 86_400);
			(dir, cfg)
		},
		|(_, cfg), yes| purge(cfg.path(), None, yes),
		|(dir, _)| archive_count(dir.path()) == 2,
	);
}

#[test]
fn archive_purge_with_a_threshold_counts_only_what_it_takes() {
	gate(
		"archive purge",
		|_| "Purge 1 archived entries older than 30 days for \"alice\"? [y/N]".to_string(),
		|| {
			let (dir, cfg) = fixture("[storage]\ndeleted_retention_days = 30");
			archived(dir.path(), 3_600);
			archived(dir.path(), 40 * 86_400);
			(dir, cfg)
		},
		|(_, cfg), yes| purge(cfg.path(), Some(30), yes),
		|(dir, _)| archive_count(dir.path()) == 2,
	);
}

#[test]
fn api_key_revoke_asks_with_the_key_scopes() {
	gate(
		"api-key-revoke",
		|_| "Revoke API key \"ci\" (scopes: read)? [y/N]".to_string(),
		|| {
			let (dir, cfg) = fixture("");
			let key = api_keys::NewKey {
				label: "ci".to_string(),
				scopes: vec!["read".to_string()],
				..api_keys::NewKey::default()
			};
			let created = api_keys::create(&load(cfg.path()), key, &mut Vec::new());
			assert_eq!(created, ExitCode::SUCCESS);
			(dir, cfg)
		},
		|(_, cfg), yes| api_keys::revoke(&load(cfg.path()), "ci", yes, &mut Vec::new()),
		|(dir, _)| {
			crate::api::ApiKeyStore::open(dir.path())
				.expect("open")
				.keys()
				.len() == 1
		},
	);
}

#[test]
fn app_password_revoke_asks_naming_label_and_account() {
	gate(
		"app-password-revoke",
		|_| "Revoke app password \"phone\" for \"alice\"? [y/N]".to_string(),
		|| {
			let (dir, cfg) = with_alice();
			let created = app_passwords::create(
				&load(cfg.path()),
				NAME,
				"phone",
				None,
				None,
				None,
				&mut Vec::new(),
			);
			assert_eq!(created, ExitCode::SUCCESS);
			(dir, cfg)
		},
		|(_, cfg), yes| {
			app_passwords::revoke(&load(cfg.path()), NAME, "phone", yes, &mut Vec::new())
		},
		|(dir, _)| {
			AppPasswordStore::open(dir.path())
				.expect("open")
				.for_account(NAME)
				.len() == 1
		},
	);
}

#[test]
fn restore_refuses_a_piped_run_or_a_no_before_reading_the_archive() {
	let (dir, cfg) = fixture("");
	let question = format!(
		"Restore the archive on stdin into {}, replacing what is there? [y/N]",
		dir.path().canonicalize().expect("canonical").display()
	);
	let restore =
		|| crate::cli::dispatch::dispatch_restore(cfg.path().to_path_buf(), false, false, false);
	let piped = scripted(false, None, "y\n", restore);
	assert_eq!(piped.value, ExitCode::from(2));
	assert_eq!(piped.stderr, error(&refused_message("restore")));
	let no = scripted(true, None, "n\n", restore);
	assert_eq!(no.value, ExitCode::from(2));
	assert_eq!(
		no.stderr,
		format!("{question} {}", error(&cancelled_message("restore")))
	);
}

#[test]
fn restore_yes_or_a_y_answer_never_stands_in_for_force() {
	let (dir, cfg) = fixture("");
	let data_dir = dir.path().canonicalize().expect("canonical");
	std::fs::write(data_dir.join("accounts.toml"), "[[accounts]]\n").expect("preset");
	let archive = crate::cli::backup::tar_gz(&[(
		"data/accounts/alice/new/m1.eml".to_string(),
		0o644,
		b"Subject: hi\r\n\r\nbody".to_vec(),
	)])
	.expect("archive");
	let restore =
		|| crate::cli::dispatch::dispatch_restore(cfg.path().to_path_buf(), false, false, true);
	let flag = scripted(false, None, &archive, restore);
	assert_eq!(
		flag.value,
		ExitCode::FAILURE,
		"--yes must not imply --force"
	);
	assert_eq!(flag.unread, 0, "the archive was read");
	let mut typed = b"y\n".to_vec();
	typed.extend_from_slice(&archive);
	let restore =
		|| crate::cli::dispatch::dispatch_restore(cfg.path().to_path_buf(), false, false, false);
	let answered = scripted(true, None, &typed, restore);
	assert_eq!(
		answered.value,
		ExitCode::FAILURE,
		"answering y must not imply --force"
	);
	assert_eq!(
		std::fs::read_to_string(data_dir.join("accounts.toml")).expect("read"),
		"[[accounts]]\n"
	);
	assert!(
		!data_dir.join("accounts/alice/new/m1.eml").exists(),
		"nothing was laid down"
	);
}

#[path = "cli_confirmation_flow_tests_b.rs"]
mod b;
