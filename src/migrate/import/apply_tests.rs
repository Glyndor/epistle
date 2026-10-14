use std::path::{Path, PathBuf};

use super::*;
use crate::migrate::mox;

/// An epistle configuration with no domains yet, as `init` leaves one
/// before the first domain is added, plus its data directory.
pub(super) fn epistle(dir: &Path, extra: &str) -> PathBuf {
	let data = dir.join("data");
	std::fs::create_dir_all(&data).expect("data dir");
	let file = dir.join("mail.toml");
	std::fs::write(
		&file,
		format!(
			"hostname = \"mail.new.example\"\ndata_dir = \"{}\"\ndomains = []\n{extra}",
			data.display()
		),
	)
	.expect("config");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600)).expect("chmod");
	}
	file
}

pub(super) fn mox_plan(dir: &Path) -> (Plan, mox::fixture::Written) {
	let source = dir.join("mox");
	std::fs::create_dir_all(&source).expect("mox dir");
	let written = mox::fixture::write(&source);
	(mox::read(&source).expect("plan"), written)
}

/// Every file under `dir`, with its bytes, to prove a run wrote nothing.
pub(super) fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
	let mut out = Vec::new();
	let mut pending = vec![dir.to_path_buf()];
	while let Some(next) = pending.pop() {
		for entry in std::fs::read_dir(&next).expect("list").flatten() {
			let path = entry.path();
			if path.is_dir() {
				pending.push(path);
			} else {
				out.push((path.clone(), std::fs::read(&path).expect("read")));
			}
		}
	}
	out.sort();
	out
}

/// A plan for one domain whose keys can sign it, without the account epistle
/// cannot name.
pub(super) fn single_domain(plan: &mut Plan) {
	plan.domains.retain(|d| d == "example.com");
	plan.keys.retain(|k| k.domain == "example.com");
	for account in &mut plan.accounts {
		account.addresses.retain(|a| a.ends_with("@example.com"));
	}
}

#[test]
fn prepare_writes_nothing() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config = epistle(dir.path(), "");
	let (plan, _) = mox_plan(dir.path());
	let before = snapshot(dir.path());
	let prepared = prepare(&plan, &config, false).expect("prepare");
	assert_eq!(prepared.outcome.domains_added.len(), 2);
	assert_eq!(snapshot(dir.path()), before, "a dry run touches no file");
}

#[test]
fn apply_creates_domains_aliases_keys_and_disabled_accounts() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (mut plan, written) = mox_plan(dir.path());
	single_domain(&mut plan);
	let passwords = dir.path().join("passwords.txt");
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::File(passwords.clone())).expect("apply");
	assert_eq!(outcome.accounts_added, ["alice", "bob"]);

	let config = Config::load(&config_file).expect("load");
	assert_eq!(config.domains, ["example.com"]);
	assert_eq!(config.alias[0].address, "team@example.com");
	assert!(!config.alias[0].hidden);
	let dkim = config.dkim.clone().expect("[dkim]");
	assert_eq!(dkim.selector, "2024a", "the selector Mox published stays");
	assert_eq!(dkim.rsa_selector.as_deref(), Some("2024b"));
	let rsa_file = dkim.rsa_key_file.expect("rsa key file");
	// The server's own signer loads both keys and signs with them.
	let signer = crate::dkim::Signer::load(&dkim.selector, &dkim.key_file)
		.and_then(|signer| signer.with_rsa("2024b", &rsa_file))
		.expect("epistle loads the imported keys");
	let signature = signer
		.sign(
			"example.com",
			b"From: a@example.com\r\nSubject: x\r\n\r\nbody\r\n",
		)
		.expect("sign");
	assert!(
		signature.contains("s=2024a") && signature.contains("s=2024b"),
		"the message is signed with both selectors"
	);
	assert_eq!(
		std::fs::read_to_string(&rsa_file).expect("rsa"),
		written.rsa
	);
	#[cfg(unix)]
	for file in [&dkim.key_file, &rsa_file, &passwords] {
		use std::os::unix::fs::PermissionsExt;
		let mode = std::fs::metadata(file).expect("meta").permissions().mode();
		assert_eq!(mode & 0o777, 0o600, "{}", file.display());
	}

	let store = open_store(&config, &config.domains).expect("store");
	let alice = store.dynamic("alice").expect("alice");
	assert!(alice.disabled, "imported accounts cannot log in yet");
	assert_eq!(alice.display_name.as_deref(), Some("Alice Liddell"));
	assert_eq!(
		store.dynamic("bob").expect("bob").catch_all,
		["example.com"]
	);
	let lines = std::fs::read_to_string(&passwords).expect("passwords");
	let lines: Vec<&str> = lines.lines().collect();
	assert_eq!(lines.len(), 2);
	let (name, secret) = lines[0].split_once('\t').expect("tab");
	assert_eq!(name, "alice");
	assert_eq!(secret.len(), 32);
	assert!(crate::smtp::auth::verify_password(
		&alice.password_hash,
		secret
	));
}

#[test]
fn password_reset_writes_no_password_anywhere() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (mut plan, _) = mox_plan(dir.path());
	single_domain(&mut plan);
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	apply(&plan, prepared, &Passwords::Reset).expect("apply");
	let files: Vec<PathBuf> = snapshot(dir.path()).into_iter().map(|(p, _)| p).collect();
	assert!(
		!files
			.iter()
			.any(|p| p.to_string_lossy().contains("password")),
		"{files:?}"
	);
}

#[test]
fn existing_accounts_and_domains_are_refused_unless_merged() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	std::fs::write(
		&config_file,
		std::fs::read_to_string(&config_file)
			.expect("read")
			.replace("domains = []", "domains = [\"example.com\"]"),
	)
	.expect("write");
	let config = Config::load(&config_file).expect("load");
	let store = open_store(&config, &config.domains).expect("store");
	let existing = DynamicAccount::with_password(
		"alice".into(),
		vec!["alice@example.com".into()],
		crate::test_fixtures::password(),
		&crate::password::Policy::from_config(&config.auth),
		false,
	)
	.expect("account");
	let hash = existing.password_hash.clone();
	store.add(existing).expect("add");
	let (mut plan, _) = mox_plan(dir.path());
	single_domain(&mut plan);

	let before = snapshot(dir.path());
	let refused = prepare(&plan, &config_file, false).err().expect("refused");
	assert!(
		matches!(&refused, ApplyError::Refused(m) if m.contains("account alice") && m.contains("example.com")),
		"{refused}"
	);
	assert_eq!(snapshot(dir.path()), before);

	let prepared = prepare(&plan, &config_file, true).expect("merge");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	assert_eq!(outcome.accounts_kept, ["alice"]);
	assert_eq!(outcome.accounts_added, ["bob"]);
	assert_eq!(outcome.domains_kept, ["example.com"]);
	let store = open_store(&config, &config.domains).expect("store");
	let alice = store.dynamic("alice").expect("alice");
	assert_eq!(
		alice.password_hash, hash,
		"the existing account is untouched"
	);
	assert!(!alice.disabled);
}

#[test]
fn an_account_the_store_refuses_becomes_a_note() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (mut plan, _) = mox_plan(dir.path());
	single_domain(&mut plan);
	// An address in a domain the import does not add: the store refuses it.
	plan.accounts[0]
		.addresses
		.push("alice@elsewhere.example".into());
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	assert_eq!(outcome.accounts_added, ["bob"]);
	assert!(
		outcome
			.notes
			.iter()
			.any(|n| n.starts_with("account alice was not created")),
		"a note names the account the store refused"
	);
}

#[test]
fn no_key_material_in_the_outcome_or_errors() {
	let dir = tempfile::tempdir().expect("tempdir");
	let config_file = epistle(dir.path(), "");
	let (mut plan, written) = mox_plan(dir.path());
	single_domain(&mut plan);
	let prepared = prepare(&plan, &config_file, false).expect("prepare");
	let outcome = apply(&plan, prepared, &Passwords::Reset).expect("apply");
	let shown = format!(
		"{outcome:?}{}",
		serde_json::to_string(&outcome).expect("json")
	);
	let body: String = written
		.rsa
		.lines()
		.filter(|l| !l.starts_with("-----"))
		.collect();
	assert!(!shown.contains(&body[..40]));
	assert!(!shown.contains("PRIVATE KEY"));
}
