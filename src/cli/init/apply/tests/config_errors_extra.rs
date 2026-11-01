//! Additional module regressions.

use super::*;

#[test]
fn apply_writes_a_config_with_a_dns_section() {
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_with_dns_and_extra_services();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	assert!(outcome.error.is_none(), "apply failed: {:?}", outcome.error);
	drop(outcome);
	let rendered = std::fs::read_to_string(&config_path).expect("read config");
	assert!(
		rendered.contains("[dns]"),
		"DNS section must be written into the config: {rendered}"
	);
	assert!(
		rendered.contains("cloudflare"),
		"DNS provider must be in the config: {rendered}"
	);
	assert!(
		rendered.contains("token_file"),
		"DNS token source must be in the config: {rendered}"
	);
	assert!(
		rendered.contains("/run/secrets/cf"),
		"DNS token_file path must be in the config: {rendered}"
	);
}

#[test]
fn apply_rejects_an_existing_config_that_is_unparseable() {
	// A config file already exists at the destination, but the TOML
	// parser cannot make sense of it. The apply phase must surface
	// the read failure rather than silently overwriting the file
	// with bytes the operator did not intend to keep.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::write(&config_path, "this is not = valid TOML\tbroken\n").expect("write");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&config_path, std::fs::Permissions::from_mode(0o600))
			.expect("chmod");
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	let err = outcome.error.expect("apply must surface the parse failure");
	assert!(
		matches!(err, ApplyError::ConfigRead(_, _)),
		"expected ConfigRead, got {}",
		apply_error_name(&err)
	);
	// The unparseable file must still be on disk; the apply phase
	// must not have replaced it with a candidate that never
	// validated.
	let still_there = std::fs::read_to_string(&config_path).expect("read");
	assert!(
		still_there.contains("broken"),
		"unparseable config must survive a failed apply; got: {still_there}"
	);
}

#[test]
fn build_config_includes_the_api_listener_when_services_request_it() {
	let mut answers = answers_minimal();
	answers.services = Services {
		antivirus: None,
		imap: false,
		submission: false,
		pop3: false,
		managesieve: false,
		webdav: false,
		api: true,
		database: false,
	};
	let cert = std::path::PathBuf::from("/var/lib/epistle/keys/cert.pem");
	let key = std::path::PathBuf::from("/var/lib/epistle/keys/key.pem");
	let ed = std::path::PathBuf::from("/var/lib/epistle/keys/s1.pem");
	let mail_addr: std::net::IpAddr = std::net::Ipv6Addr::UNSPECIFIED.into();
	let desired = apply_config::build_config(&answers, mail_addr, Some(&ed), None, &cert, &key)
		.expect("build_config with api");
	assert!(
		desired.listeners.iter().any(|l| l.kind == "api"),
		"api listener must be wired through: {:?}",
		desired.listeners
	);
	let rendered = toml::to_string(&desired).unwrap();
	let config = crate::config::Config::parse_text(&rendered, &answers.config_path).unwrap();
	assert!(config.api.unwrap().token_hash.is_none());
	assert!(!rendered.contains("token_hash"));
	let existing: toml::Value =
		toml::from_str("[api]\ntoken_hash = 'preserve-existing-hash'\n").unwrap();
	let wanted: toml::Value = toml::from_str(&rendered).unwrap();
	let merged = apply_config::reconcile(existing, wanted, false);
	assert_eq!(
		merged["api"]["token_hash"].as_str(),
		Some("preserve-existing-hash")
	);
}

#[cfg(unix)]
#[test]
fn apply_refuses_an_orphan_oauth_public_key() {
	// When oauth_private was deleted but oauth_public was left on
	// disk, the apply phase must NOT mint a fresh unrelated
	// oauth_private: tokens already issued against the surviving
	// oauth_public would silently break. The apply phase surfaces
	// an `OAuthPairIncomplete` error instead, names the missing
	// private key path, and leaves the surviving public key bytes
	// untouched.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome1 = apply(&answers);
	assert!(
		outcome1.error.is_none(),
		"first apply must succeed: {:?}",
		outcome1.error
	);
	drop(outcome1);
	// Delete only the private half so the public half is left over.
	let oauth_private = crate::cli::init::host_secrets::oauth_signing_key(&data_dir);
	let oauth_public = data_dir.join("keys").join("oauth_public.key");
	let public_before = std::fs::read(&oauth_public).expect("read public");
	assert!(
		oauth_private.exists(),
		"first apply must write oauth_private"
	);
	assert!(oauth_public.exists(), "first apply must write oauth_public");
	std::fs::remove_file(&oauth_private).expect("delete oauth_private");

	let outcome2 = apply(&answers);
	let err = outcome2
		.error
		.expect("second apply with orphan oauth_public must refuse");
	let ApplyError::OAuthPairIncomplete(message) = &err else {
		panic!(
			"expected OAuthPairIncomplete, got {}",
			apply_error_name(&err)
		);
	};
	assert!(
		message.contains("oauth_signing.key"),
		"the diagnostic must name the missing private key: {message}"
	);
	assert!(
		!oauth_private.exists(),
		"a fresh private key must NOT have been written"
	);
	let public_after = std::fs::read(&oauth_public).expect("read public");
	// Comparing SPKI byte arrays with `assert_eq!` would Debug-print
	// the full public key on mismatch, dumping it into the CI log.
	// A boolean assertion pins the same invariant without carrying
	// the bytes.
	assert!(
		public_before == public_after,
		"public key bytes must be untouched"
	);
}

#[cfg(unix)]
#[test]
fn apply_fails_when_existing_data_dir_blocks_keys_dir_creation() {
	// data_dir already exists with mode 0500. ensure_data_dir
	// succeeds (it sees the directory), then ensure_keys_dir tries
	// to create data_dir/keys and the mode blocks the write. The
	// apply phase must surface the failure as KeysDir rather than
	// silently creating the keys elsewhere.
	let dir = tempfile::tempdir().expect("tempdir");
	let data_dir = dir.path().join("data");
	let config_path = dir.path().join("mail.toml");
	std::fs::create_dir(&data_dir).expect("mkdir data");
	std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o500))
		.expect("chmod 0500 on data");
	// Canary write: confirms the chmod actually blocks writes
	// (running as root would defeat the test).
	let canary = data_dir.join("canary");
	if std::fs::write(&canary, b"x").is_ok() {
		std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755))
			.expect("restore");
		let _ = std::fs::remove_file(&canary);
		eprintln!(
			"skipping: data_dir mode 0500 did not block writes (running as root or fs ignores mode)"
		);
		return;
	}
	let mut answers = answers_minimal();
	answers.data_dir = data_dir.clone();
	answers.config_path = config_path.clone();
	let outcome = apply(&answers);
	// Restore permissions so the tempdir can be cleaned up.
	let _ = std::fs::set_permissions(&data_dir, std::fs::Permissions::from_mode(0o755));
	let err = outcome
		.error
		.expect("apply must fail when keys dir cannot be created");
	assert!(
		matches!(err, ApplyError::KeysDir(_, _)),
		"expected KeysDir, got {}",
		apply_error_name(&err)
	);
	assert!(
		format!("{err}").contains("keys"),
		"KeysDir display must name the path"
	);
}
