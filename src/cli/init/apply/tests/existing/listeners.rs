//! When the operator's config on disk already carries a non-empty
//! `listeners` array, `init` must keep those listeners exactly as
//! they are and not overwrite them with the ones `build_config`
//! synthesises from the answers. A re-run with different service
//! toggles must therefore leave the operator's bind addresses (and
//! any kinds init does not write, like `metrics` or `acme`) on disk
//! untouched.

use std::os::unix::fs::PermissionsExt;
use std::path::PathBuf;

use super::*;
use crate::cli::init::answers::{Answers, Mode, Services};
use crate::config::ListenerKind;

/// Write `content` to `path` with mode `0600` so `Config::load`
/// accepts it; the loader refuses files with group/world access and
/// the `existing_operators_listeners` helper piggy-backs on the same
/// gate so a permissive file would fail the helper before the test
/// could inspect it.
pub(super) fn write_0600(path: &PathBuf, content: &str) {
	std::fs::write(path, content).expect("write file");
	let perms = std::fs::Permissions::from_mode(0o600);
	std::fs::set_permissions(path, perms).expect("set permissions 0600");
}

pub(super) fn answers_minimal() -> Answers {
	Answers {
		mode: Mode::Manual,
		hostname: "mail.example.org".to_string(),
		domains: vec!["example.org".to_string()],
		public_ipv4: Some(std::net::Ipv4Addr::new(8, 8, 8, 8)),
		public_ipv6: Some(std::net::Ipv6Addr::new(
			0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888,
		)),
		data_dir: PathBuf::from("/var/lib/epistle"),
		config_path: PathBuf::from("/etc/epistle/mail.toml"),
		dns: None,
		services: Services::default(),
		image: Some("localhost/epistle:dev".to_string()),
		acme: None,
		first_account: None,
		resources: Default::default(),
	}
}

/// A re-run of `init` against a config the operator has curated
/// (one `imap` on a non-default address and port, plus a `metrics`
/// listener that `init` does not write) must keep both listeners
/// exactly as they were and must not insert the `smtp` listener
/// `init` would otherwise write. The byte-level equality on the
/// `[[listeners]]` table is the gate: a regression that drops the
/// `keep_existing_listeners` flag in `apply` lets the merge replace
/// the operator's array with `init`'s, which adds `smtp` and drops
/// `metrics`, and the test goes red on `kind = "metrics"` (gone) and
/// `kind = "smtp"` (added).
#[test]
fn apply_keeps_operator_listeners_when_existing_config_has_them() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let operator_listeners = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[[listeners]]\n\
		kind = \"imap\"\n\
		addr = \"127.0.0.1\"\n\
		port = 1143\n\n\
		[[listeners]]\n\
		kind = \"metrics\"\n\
		addr = \"127.0.0.1\"\n\
		port = 9090\n";
	std::fs::create_dir_all(data_dir.parent().unwrap()).expect("mkdir data");
	write_0600(&config_path, operator_listeners);

	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	// Re-run with imap and submission enabled: a design that
	// unconditionally replaces the operator's listeners would write
	// smtp alongside imap. The kept-listener path keeps the existing
	// array and does not write any of the listeners `init` would
	// normally add.
	answers.services = Services {
		antivirus: None,
		imap: true,
		submission: true,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: false,
		database: false,
		certs: false,
	};

	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply failed when keeping listeners: {:?}",
		outcome.error
	);

	let written = std::fs::read_to_string(&config_path).expect("read config");
	let listeners = crate::config::Config::load(&config_path)
		.expect("config reload")
		.listeners;
	assert_eq!(
		listeners.len(),
		2,
		"operator's two listeners must survive the re-run"
	);
	assert!(
		listeners.iter().any(|l| {
			l.kind == ListenerKind::Imap
				&& l.addr == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
				&& l.port == Some(1143)
		}),
		"the imap listener on 127.0.0.1:1143 must survive byte-for-byte"
	);
	assert!(
		listeners.iter().any(|l| {
			l.kind == ListenerKind::Metrics
				&& l.addr == std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1))
				&& l.port == Some(9090)
		}),
		"the metrics listener on 127.0.0.1:9090 must survive byte-for-byte"
	);
	assert!(
		!listeners.iter().any(|l| l.kind == ListenerKind::Smtp),
		"init must not add an smtp listener when the operator already has listeners"
	);
	assert!(
		!written.contains("kind = \"smtp\""),
		"smtp must not be written into a config the operator already populated; got: {written}"
	);
	assert!(
		written.contains("kind = \"metrics\""),
		"metrics must still be in the file; got: {written}"
	);
	assert!(
		written.contains("addr = \"127.0.0.1\"") && written.contains("port = 1143"),
		"the imap address and port must still be present; got: {written}"
	);
	assert!(
		written.contains("kind = \"metrics\"") && written.contains("port = 9090"),
		"the metrics kind and port must still be present; got: {written}"
	);
}

/// `existing_operators_listeners` reports `Ok(None)` when the
/// existing `listeners` array is empty (the default for a fresh
/// install: `init` writes its own). Keeps the edge documented and
/// confirms the merge in that case still runs normally.
#[test]
fn existing_operators_listeners_is_none_when_array_is_empty() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	// A complete config with an empty listeners array. The
	// `[[listeners]]` table is required to be non-empty by the
	// schema, so `Listener` deserialisation fails; what matters
	// for the helper contract is that the helper does not promote
	// this into a `Some(_)` keep-existing-listeners decision.
	let body = "\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\
		[auth]\n\
		allow_insecure_auth = false\n";
	write_0600(&config_path, body);
	let out = apply_config::existing_operators_listeners(&config_path)
		.expect("read returns Ok(None) for an absent listeners key");
	assert!(
		out.is_none(),
		"no listeners key in the existing config must yield Ok(None); got: {out:?}"
	);
}

/// A re-run against a config whose `[database].password_file`
/// points at a path that no longer exists must still extract the
/// listeners so the apply phase can reconcile the stale
/// password_file away. Before the fix, `existing_operators_listeners`
/// called `Config::load` on the on-disk file; the validator's
/// database check opens the password file and fails on
/// `NotFound`, so the helper returned an error and `init` exited
/// before the reconciliation that would have replaced the stale
/// path. With the fix, the helper returns the listener array
/// verbatim and the merge drops the stale `password_file`
/// because the desired config supplies the fresh one.
#[test]
fn existing_operators_listeners_survives_a_stale_password_file() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_path = dir.path().join("mail.toml");
	let stale = dir.path().join("missing_password_file");
	// A complete config with a non-empty listeners array and a
	// `[database].password_file` pointing at a path that does
	// not exist. The validator refuses to load this file
	// (`ConfigError::Read { kind: "[database] password_file", ... }`),
	// so the previous shape that called `Config::load` here
	// returned an error before returning the listeners.
	let body = format!(
		"\
		hostname = \"mail.example.org\"\n\
		data_dir = \"/var/lib/epistle\"\n\
		domains = [\"example.org\"]\n\n\
		[tls]\n\
		cert_file = \"/var/lib/epistle/keys/cert.pem\"\n\
		key_file = \"/var/lib/epistle/keys/key.pem\"\n\n\
		[database]\n\
		url = \"postgres://epistle@%2Frun%2Fpostgresql/epistle\"\n\
		password_file = \"{}\"\n\n\
		[[listeners]]\n\
		kind = \"imap\"\n\
		addr = \"127.0.0.1\"\n\
		port = 1143\n",
		stale.display()
	);
	write_0600(&config_path, &body);
	let listeners = apply_config::existing_operators_listeners(&config_path)
		.expect("listener discovery must not fail on a stale password_file")
		.expect("a non-empty listeners array must come back as Some(_)");
	assert_eq!(
		listeners.len(),
		1,
		"the kept listener must come back from the helper; got: {listeners:?}"
	);
	assert_eq!(listeners[0].kind, ListenerKind::Imap);

	// Drive the full apply phase against the same config so the
	// reconciliation replaces the stale `password_file` with the
	// one the apply phase writes under the data directory.
	let data_dir = dir.path().join("data");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	answers.services.database = true;
	crate::cli::init::compose::ensure_db_password_with_probe(
		&data_dir,
		&mut Report::default(),
		|_| Ok(false),
	)
	.unwrap();
	let outcome = apply(&answers);
	assert!(
		outcome.error.is_none(),
		"apply must succeed against a stale password_file; got: {:?}",
		outcome.error
	);
	let written = std::fs::read_to_string(&config_path).expect("read merged config");
	assert!(
		!written.contains(&stale.display().to_string()),
		"the stale password_file path must not be in the merged config; got: {written}"
	);
	assert!(
		written.contains("epistle_db_password"),
		"the merged config must point at the freshly written password file; got: {written}"
	);
	assert!(
		data_dir
			.join("secrets")
			.join("epistle_db_password")
			.exists(),
		"the freshly written password file must exist on disk; got: {written}"
	);
}
