//! Tests for account loading, credential reuse, and regeneration.

use super::test_support::{fresh_dir, load_accounts_outcome_for_test, open_store_for_test};
use super::{ACCOUNT_NAME, DEFAULT_PORT_BASE, DOMAIN, prepare};

/// Pin: an empty `accounts.toml` is treated as a present-but-unusable
/// file (the production loader reads the empty string and the TOML parse
/// fails with `StoreError::Invalid`). `prepare` returns `Err`, the error
/// names the data directory, and `mail.toml` is byte-for-byte intact.
#[test]
fn empty_accounts_toml_returns_unusable_error_and_does_not_wipe_mail_toml() {
	let dir = fresh_dir("empty-accounts");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before");
	std::fs::write(&accounts_path, b"").expect("truncate accounts.toml");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an empty accounts.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains(&dir.path().join("data").display().to_string()),
		"error must name the data directory, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: an `accounts.toml` that does not parse (malformed TOML or a
/// non-`DynamicAccount` shape) is treated as an unusable file:
/// `prepare` returns `Err`, the error names the data directory, and
/// `mail.toml` is byte-for-byte intact.
#[test]
fn garbage_accounts_toml_returns_unusable_error_and_does_not_wipe_mail_toml() {
	let dir = fresh_dir("garbage-accounts");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before");
	std::fs::write(&accounts_path, b"this is not TOML at all = ][")
		.expect("write garbage accounts.toml");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a garbage accounts.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains(&dir.path().join("data").display().to_string()),
		"error must name the data directory, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a second `prepare` on a directory that already has a valid pair
/// reuses both files byte-for-byte and does not mint a new password.
/// The byte-for-byte invariant pins the credential pair against the
/// per-run-regenerate regression: any shape that mints a password on
/// every call would fail this test.
#[test]
fn second_prepare_against_a_valid_pair_is_byte_identical() {
	let dir = fresh_dir("reuse-pair");
	let first = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_before =
		std::fs::read_to_string(dir.path().join("mail.toml")).expect("read mail.toml before");
	let accounts_before = std::fs::read_to_string(dir.path().join("data").join("accounts.toml"))
		.expect("read accounts.toml before");

	let second = prepare(dir.path(), DEFAULT_PORT_BASE).expect("second prepare");
	assert!(
		second.password.is_none(),
		"second run must NOT regenerate the credential pair"
	);
	let mail_after =
		std::fs::read_to_string(dir.path().join("mail.toml")).expect("read mail.toml after");
	assert!(
		mail_after == mail_before,
		"mail.toml must be byte-identical on the second run"
	);
	let accounts_after = std::fs::read_to_string(dir.path().join("data").join("accounts.toml"))
		.expect("read accounts.toml after");
	assert!(
		accounts_after == accounts_before,
		"accounts.toml must be byte-identical on the second run"
	);
	// First run minted; second run reused. They are intentionally not equal.
	assert!(first.password.is_some());
}

/// Pin: a truncated `data/masked.json` returns `Err` from `prepare`,
/// the error names the data directory, the underlying store error's
/// text is in the rendered diagnostic, the standard remedy is
/// present, and both credential files are byte-for-byte intact. The
/// diagnostic carries the production `AccountStore::open` loader's text
/// rather than a re-parse of the sidecar: re-parsing would name a
/// different file or substitute a different parser's view of the error.
/// The standard remedy is to remove the whole data directory.
#[test]
fn truncated_masked_json_returns_unusable_error() {
	let dir = fresh_dir("truncated-masked");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let masked_path = dir.path().join("data").join("masked.json");
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before");

	std::fs::write(&masked_path, b"{").expect("truncate masked.json");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a truncated masked.json, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains(&dir.path().join("data").display().to_string()),
		"error must name the data directory, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);
	assert!(
		rendered.contains("invalid account"),
		"error must carry the AccountStore error text, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert!(
		mail_before == mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert!(
		accounts_before == accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a data directory whose `accounts.toml` cannot be stat'ed is
/// `Unusable`, not `Missing`. `prepare` builds `data` itself, so the
/// narrowest setup that makes the accounts path stat fail with an
/// error other than `NotFound` and still reaches the `Missing` /
/// `Unusable` decision is to call `load_accounts_outcome` directly:
/// pass a data-dir path whose parent component is a regular file so
/// the kernel returns `ENOTDIR` on every uid (the same shape
/// `prepare` would see if a hand-rolled `data/` collision block left
/// `<dir>/data` as a regular file under an older harness that had
/// already laid out the directory).
#[test]
fn accounts_path_stat_error_is_unusable_not_missing() {
	let dir = fresh_dir("stat-error");
	let data_dir = dir.path().join("data");
	// Make `data` a regular file. The "data directory" we pass to
	// `load_accounts_outcome` is therefore `<dir>/data/accounts.toml`,
	// whose `data` parent is a regular file; the kernel returns
	// `ENOTDIR` for every uid when stat'ing `accounts.toml`.
	std::fs::write(&data_dir, b"").expect("write regular file at data");
	let outcome = load_accounts_outcome_for_test(&data_dir).expect("load_accounts_outcome");
	match outcome {
		super::config::AccountsOutcome::Unusable(diagnostic) => {
			assert!(
				diagnostic.contains(&data_dir.display().to_string()),
				"unusable diagnostic must name the data directory, got: {diagnostic}"
			);
			assert!(
				diagnostic.contains("Fix it"),
				"unusable diagnostic must carry the standard remedy, got: {diagnostic}"
			);
		}
		other => panic!(
			"accounts path stat error must be Unusable, got {}",
			accounts_outcome_name(&other)
		),
	}
}

/// The variant name of an `AccountsOutcome`, for the assertion
/// message that must not print the full Debug. The `Unusable`
/// variant carries a diagnostic string the operator reads in the
/// log; the panic message has to be a CI log too, and printing the
/// full Debug makes the line wider than the diagnosis needs. The
/// match is exhaustive on purpose: a new variant added to
/// `AccountsOutcome` breaks this file at compile time, so the
/// next caller cannot fall through and print the whole struct.
fn accounts_outcome_name(outcome: &super::config::AccountsOutcome) -> &'static str {
	match outcome {
		super::config::AccountsOutcome::Missing => "Missing",
		super::config::AccountsOutcome::Loaded => "Loaded",
		super::config::AccountsOutcome::Unusable(_) => "Unusable",
	}
}

#[test]
fn missing_mail_toml_with_valid_accounts_regenerates() {
	let dir = fresh_dir("missing-mail-only");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	std::fs::remove_file(&mail_toml).expect("remove mail.toml");

	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare regenerates");
	assert!(
		prepared.password.is_some(),
		"missing mail.toml must trigger regeneration so a fresh password is minted"
	);

	let store = open_store_for_test(&dir.path().join("data")).expect("store opens");
	let accounts: Vec<String> = store
		.handle()
		.current()
		.addresses_for(ACCOUNT_NAME)
		.into_iter()
		.collect();
	assert!(
		accounts.contains(&format!("{ACCOUNT_NAME}@{DOMAIN}")),
		"rewritten accounts.toml must contain the default account {ACCOUNT_NAME}, got addresses {accounts:?}"
	);
}
