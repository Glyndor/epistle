//! `epistle status` reports spool-level security state.
//!
//! Two pieces of spool state an operator cannot
//! otherwise read at a glance: whether `encrypt_at_rest` is on (so the
//! envelope and message body are sealed under the AEAD), and whether every
//! spool file and directory is currently owner-only (loose permissions on a
//! disk that is shared with another account expose the whole envelope to a
//! collateral reader).

use std::path::Path;

use crate::cli::status::report::Level;
use crate::cli::status::spool_area::evaluate;
use crate::config::Config;
use crate::storage::FsSpool;

fn write_config(dir: &Path, body: &str) -> std::path::PathBuf {
	let path = dir.join("mail.toml");
	std::fs::write(&path, body).expect("write config");
	std::fs::set_permissions(&path, std::os::unix::fs::PermissionsExt::from_mode(0o600))
		.expect("chmod config");
	path
}

fn data_dir_config(dir: &Path) -> Config {
	let path = write_config(
		dir,
		&format!(
			"hostname = \"mail.example.org\"\ndata_dir = {:?}\n",
			dir.canonicalize().expect("canon").display().to_string()
		),
	);
	Config::load(&path).expect("parse config")
}

#[test]
fn a_clean_spool_with_encryption_off_is_ok() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = data_dir_config(dir.path());
	let report = evaluate(&config);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(
		report.detail.contains("sealed: no"),
		"detail did not mention sealing: {report:?}"
	);
	assert!(
		report.detail.contains("loose: 0"),
		"detail did not mention loose count: {report:?}"
	);
}

#[test]
fn a_clean_spool_with_encryption_on_reports_sealed_yes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let key = crate::storage::generate_key_base64().expect("keygen");
	std::fs::write(dir.path().join("mail.key"), &key).expect("write key");
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n[storage]\nencrypt_at_rest = true\nencryption_key_file = {:?}\n",
		dir.path()
			.canonicalize()
			.expect("canon")
			.display()
			.to_string(),
		dir.path().join("mail.key").display().to_string()
	);
	let path = write_config(dir.path(), &body);
	let config = Config::load(&path).expect("parse config");

	// Lay down a spool with encryption on.
	let crypto = crate::storage::MessageCrypto::from_config(config.storage.as_ref())
		.expect("crypto from config");
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open spool");
	let _id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@example.org".into()],
				data: b"Subject: hi\r\n\r\nbody\r\n".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&Default::default(),
		)
		.expect("store");

	let report = evaluate(&config);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(
		report.detail.contains("sealed: yes"),
		"detail did not report sealed=yes: {report:?}"
	);
}

#[test]
fn a_loose_file_in_the_spool_warns() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::for_test(&crate::test_fixtures::bytes::<32>());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open");
	let id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@example.org".into()],
				data: b"hi\r\n\r\nbody".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&Default::default(),
		)
		.expect("store");

	// Loosen the envelope and report: status must warn.
	let envelope_path = dir.path().join("spool/new").join(format!("{id}.json"));
	std::fs::set_permissions(
		&envelope_path,
		std::os::unix::fs::PermissionsExt::from_mode(0o644),
	)
	.expect("loosen envelope");

	let key = crate::storage::generate_key_base64().expect("keygen");
	std::fs::write(dir.path().join("mail.key"), &key).expect("write key");
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n[storage]\nencrypt_at_rest = true\nencryption_key_file = {:?}\n",
		dir.path()
			.canonicalize()
			.expect("canon")
			.display()
			.to_string(),
		dir.path().join("mail.key").display().to_string()
	);
	let path = write_config(dir.path(), &body);
	let config = Config::load(&path).expect("parse config");

	let report = evaluate(&config);
	assert_eq!(report.status, Level::Warn, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|item| item.name == "permissions")
		.expect("permissions item");
	assert!(
		item.detail.contains("loose: 1"),
		"detail did not report loose=1: {report:?}"
	);
}

#[test]
fn a_sealed_envelope_after_migration_is_still_sealed_yes() {
	let dir = tempfile::tempdir().expect("tempdir");
	let crypto = crate::storage::MessageCrypto::for_test(&crate::test_fixtures::bytes::<32>());
	let spool = FsSpool::open_with_crypto(dir.path(), crypto).expect("open");
	let _id = spool
		.store(
			&crate::smtp::session::AcceptedMessage {
				reverse_path: "alice@example.org".into(),
				recipients: vec!["bob@example.org".into()],
				data: b"hi\r\n\r\nbody".to_vec(),
				require_tls: false,
				mailbox: None,
				tlsrpt_verified: false,
				sender_verified: false,
				no_dsn: Vec::new(),
			},
			None,
			&Default::default(),
		)
		.expect("store");

	// Re-read a sealed envelope. The status check should still report it
	// as sealed (sealed=yes comes from the configured `encrypt_at_rest`,
	// not from enumerating the spool entries).
	let key = crate::storage::generate_key_base64().expect("keygen");
	std::fs::write(dir.path().join("mail.key"), &key).expect("write key");
	let body = format!(
		"hostname = \"mail.example.org\"\ndata_dir = {:?}\n[storage]\nencrypt_at_rest = true\nencryption_key_file = {:?}\n",
		dir.path()
			.canonicalize()
			.expect("canon")
			.display()
			.to_string(),
		dir.path().join("mail.key").display().to_string()
	);
	let path = write_config(dir.path(), &body);
	let config = Config::load(&path).expect("parse config");

	let report = evaluate(&config);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	let item = report
		.items
		.iter()
		.find(|item| item.name == "encryption")
		.expect("encryption item");
	assert!(item.detail.contains("sealed: yes"), "detail: {report:?}");
}

/// The check only observes: run against a data directory with no spool yet
/// (or by an operator as root), it must not create one.
#[test]
fn the_check_never_creates_the_spool() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = data_dir_config(dir.path());
	let report = evaluate(&config);
	assert_eq!(report.status, Level::Ok, "{report:?}");
	assert!(
		!dir.path().join("spool").exists(),
		"the status check must not create the spool"
	);
}
