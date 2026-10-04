//! Tests for `local/config.rs`: port-base range, loopback binding, and
//! the `hold_outbound` invariant that the TOML loader cannot set.

use std::collections::HashSet;

use super::test_support::{
	LISTENERS_FOR_TEST, fresh_dir, load_accounts_outcome_for_test, load_for_test,
	open_store_for_test,
};
use super::{ACCOUNT_NAME, DEFAULT_PORT_BASE, DOMAIN, LocalError, prepare};

/// Pin: the `mail.toml` written by `prepare` lists six loopback listeners
/// at the expected offsets. The test used to construct an in-memory
/// `Config` directly, bypassing the on-disk `write_mail_toml` /
/// `Config::load` round trip; that meant a TOML-formatting bug in the
/// production write path could pass the unit test while breaking the
/// binary. The test now exercises the same loader the binary uses.
#[test]
fn loopback_every_listener_is_127_and_six_ports_match() {
	for port_base in [DEFAULT_PORT_BASE, 20_000] {
		let dir = fresh_dir(&format!("loopback-{port_base}"));
		prepare(dir.path(), port_base).expect("prepare");
		let config = load_for_test(&dir.path().join("mail.toml")).expect("mail.toml loads");
		assert_eq!(config.listeners.len(), LISTENERS_FOR_TEST.len());
		let mut seen: Vec<(std::net::IpAddr, u16)> = Vec::new();
		for listener in &config.listeners {
			assert!(
				listener.addr.is_loopback(),
				"listener {:?} bound to non-loopback {}",
				listener.kind,
				listener.addr
			);
			seen.push((
				listener.addr,
				listener.port.unwrap_or(listener.kind.default_port()),
			));
		}
		let expected: HashSet<u16> = LISTENERS_FOR_TEST
			.iter()
			.map(|(_, off)| port_base + off)
			.collect();
		let actual: HashSet<u16> = seen.iter().map(|(_, p)| *p).collect();
		assert_eq!(
			actual, expected,
			"the six endpoints must match the contract"
		);
	}
}

/// Pin: `--port-base 65000` is refused naming the first computed port
/// that falls outside `1024..=65535`; the nearest base that keeps the
/// API listener inside the range is accepted.
#[test]
fn port_range_upper_bound_refused_with_named_port_nearest_passes() {
	let upper = prepare(tempfile::tempdir().expect("tempdir").path(), 65000);
	match upper {
		Err(LocalError::PortOutOfRange(port)) => {
			// First offset to fall outside the range: 65000 + 587 = 65587
			// (the submission port). The exact value is what the
			// operator needs to fix the offset.
			assert_eq!(port, 65_587_u32, "first out-of-range port must be 65587");
		}
		other => panic!("expected PortOutOfRange, got {other:?}"),
	}

	// Nearest port-base that passes the upper bound: 57510 keeps the API
	// listener at exactly 65535.
	let upper_dir = tempfile::tempdir().expect("tempdir");
	prepare(upper_dir.path(), 57_510).expect("57510 passes the upper bound");
}

/// Pin: a base that puts the smallest offset under `1024` is refused
/// with the offending port; the nearest base that passes is accepted.
#[test]
fn port_range_lower_bound_refused_with_named_port_nearest_passes() {
	let failing = prepare(tempfile::tempdir().expect("tempdir").path(), 998);
	match failing {
		Err(LocalError::PortOutOfRange(port)) => {
			// 998 + 25 = 1023, the SMTP port. First offset to fall
			// below 1024.
			assert_eq!(port, 1023_u32, "first under-range port must be 1023");
		}
		other => panic!("expected PortOutOfRange, got {other:?}"),
	}

	// 999 keeps +25 at exactly 1024, the inclusive lower bound.
	let passing = prepare(tempfile::tempdir().expect("tempdir").path(), 999);
	assert!(passing.is_ok(), "999 must pass: {passing:?}");
}

/// Pin: the generated `Config` has `hold_outbound == true`; the
/// `start_queue_worker()` decision is `false` for the local config and
/// `true` for an ordinary one; a `mail.toml` carrying
/// `hold_outbound = true` is rejected by `Config::load` as an unknown
/// field (with `#[serde(skip)]` + `deny_unknown_fields`).
#[test]
fn held_outbound_config_is_true_loader_rejects_toml_field_decision_pure() {
	let dir = fresh_dir("held");
	let prepared = prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");
	assert!(
		prepared.config.hold_outbound,
		"local config must hold outbound"
	);
	assert!(
		!prepared.config.start_queue_worker(),
		"local config must NOT start the queue worker"
	);

	// Ordinary config: same struct, default `hold_outbound == false`.
	let ordinary: crate::config::Config =
		toml::from_str("hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n")
			.expect("ordinary config parses");
	assert!(
		ordinary.start_queue_worker(),
		"ordinary config must start the queue worker"
	);
	// Sanity: ordinary has hold_outbound false.
	assert!(!ordinary.hold_outbound);

	// A mail.toml carrying `hold_outbound = true` is rejected as an
	// unknown field (the field is `#[serde(skip)]` so serde never sees
	// it; `deny_unknown_fields` rejects the key).
	let bogus_path = dir.path().join("bogus.toml");
	std::fs::write(
		&bogus_path,
		"hostname = \"mail.local.test\"\ndata_dir = \"/tmp/never-read\"\nhold_outbound = true\n",
	)
	.expect("write bogus");
	#[cfg(unix)]
	{
		use std::os::unix::fs::PermissionsExt;
		let permissions = std::fs::Permissions::from_mode(0o600);
		std::fs::set_permissions(&bogus_path, permissions).expect("chmod 0600");
	}
	let bogus = crate::config::Config::load(&bogus_path);
	assert!(
		matches!(bogus, Err(crate::config::ConfigError::Parse { .. })),
		"hold_outbound in TOML must be rejected as an unknown field, got {bogus:?}"
	);

	// Sanity: the marker directory we just built loads cleanly.
	let reloaded = load_for_test(&dir.path().join("mail.toml")).expect("reloads");
	assert!(
		reloaded.hold_outbound,
		"reload must restore hold_outbound = true"
	);
	assert!(!reloaded.start_queue_worker());
}

/// Pin: the generated `mail.toml` names `<dir>/data` as its `data_dir`,
/// and that path is an existing directory on disk. The previous
/// `write_mail_toml` took the future `mail.toml` path as `dir` and computed
/// `path.join("data")`, which produced `data_dir = "<dir>/mail.toml/data"`,
/// a directory under a regular file. `serve` then asked
/// `FsSpool::open_with_crypto` to create the spool under that path and
/// `create_dir_all` returned `Not a directory (os error 20)`, so the
/// process exited before any listener bound. The test loads the file back
/// through `Config::load` (the same path `serve` walks) and asserts the
/// two halves of the invariant: the path the config names and the
/// filesystem state under it.
#[test]
fn data_dir_is_sibling_of_mail_toml_not_under_it() {
	let dir = fresh_dir("datadir");
	prepare(dir.path(), DEFAULT_PORT_BASE).expect("prepare");

	let config = load_for_test(&dir.path().join("mail.toml")).expect("reloads");
	assert_eq!(
		config.data_dir,
		dir.path().join("data"),
		"data_dir must point at <dir>/data, not at any path under mail.toml"
	);
	assert!(
		dir.path().join("data").is_dir(),
		"<dir>/data must be the existing directory the spool opens under, not a path inside mail.toml"
	);
}

/// Pin: a `mail.toml` that exists but cannot be read is propagated as an
/// error and the credential files stay byte-for-byte intact. The runtime
/// distinguishes four states when it looks at the path: missing,
/// read-failed, parse-failed, loaded. A directory at the path is the
/// only read failure a non-root uid can provoke, and root still cannot
/// read it either: `read_to_string` on a directory fails with `EISDIR`
/// for every uid.
#[cfg(unix)]
#[test]
fn unreadable_mail_toml_propagates_and_does_not_wipe_accounts() {
	let dir = fresh_dir("unreadable-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml");

	// Replace `mail.toml` with a directory. `read_to_string` on a
	// directory fails with `EISDIR` for every uid, so the test is
	// root-safe: no chmod dance that a setuid build would bypass.
	std::fs::remove_file(&mail_toml).expect("remove mail.toml");
	std::fs::create_dir(&mail_toml).expect("create dir at mail.toml");

	let result = prepare(dir.path(), DEFAULT_PORT_BASE);
	let err = match result {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a directory at mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert_eq!(
		accounts_before, accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` whose mode is `0644` propagates as an error and the
/// credential files stay byte-for-byte intact. `Config::load`'s
/// `check_permissions` rejects any file with group/world bits set as
/// `InsecurePermissions`; that variant is an operator-fixable state on
/// an otherwise valid file (the same shape as `Read`), so `prepare`
/// returns the error and does not regenerate the credential pair.
/// Regenerating would silently replace working credentials behind the
/// operator's back, which is the regression this test pins. The mode
/// check is on `st_mode`, not on who runs the test, so the assertion
/// holds as root.
#[cfg(unix)]
#[test]
fn world_readable_mail_toml_propagates_and_does_not_wipe_credentials() {
	use std::os::unix::fs::PermissionsExt;

	let dir = fresh_dir("world-readable-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before");

	// chmod 0644: world-readable. Config::load rejects this as
	// InsecurePermissions because the world-readable bit is set.
	std::fs::set_permissions(&mail_toml, std::fs::Permissions::from_mode(0o644))
		.expect("chmod 0644");

	let result = prepare(dir.path(), DEFAULT_PORT_BASE);
	let err = match result {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for a world-readable mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert_eq!(
		mail_before, mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert_eq!(
		accounts_before, accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

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
	assert_eq!(
		mail_before, mail_after,
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
	assert_eq!(
		mail_before, mail_after,
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
	assert_eq!(
		std::fs::read_to_string(dir.path().join("mail.toml")).expect("read mail.toml after"),
		mail_before,
		"mail.toml must be byte-identical on the second run"
	);
	assert_eq!(
		std::fs::read_to_string(dir.path().join("data").join("accounts.toml"))
			.expect("read accounts.toml after"),
		accounts_before,
		"accounts.toml must be byte-identical on the second run"
	);
	// First run minted; second run reused. They are intentionally not equal.
	assert!(first.password.is_some());
}

/// Pin: a `mail.toml` whose `[api] token_hash` is `${UNSET_VAR}` returns
/// `Err` from `prepare`, the error names `mail.toml`, and both files
/// are byte-for-byte intact. The rule is: the file is on disk, the
/// operator can fix it, do not regenerate.
#[test]
fn unset_env_var_in_token_hash_returns_unusable_error() {
	let dir = fresh_dir("unset-env");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");

	// Mint a surely-unset variable name at run time so the test does
	// not depend on the operator's environment.
	let var_name = format!(
		"EPISTLE_LOCAL_TEST_UNSET_{}",
		std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.expect("clock")
			.as_nanos()
	);
	let original = std::fs::read_to_string(&mail_toml).expect("re-read mail.toml");
	let patched = original.replace("[api]", &format!("[api]\nunset_var = \"${{{var_name}}}\""));
	std::fs::write(&mail_toml, patched).expect("patch mail.toml");

	// Capture "before" snapshots AFTER the patch but BEFORE `prepare`
	// so the byte-for-byte invariant is checked against what the test
	// itself left on disk, not against the file the harness wrote.
	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before prepare");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before prepare");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an unset env var, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains(&var_name),
		"error must name the unset variable, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert_eq!(
		mail_before, mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert_eq!(
		accounts_before, accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
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
	assert_eq!(
		mail_before, mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert_eq!(
		accounts_before, accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` that is not valid TOML returns `Err` from
/// `prepare`, the error names `mail.toml`, the standard remedy text is
/// present, and both files are byte-for-byte intact.
#[test]
fn invalid_toml_mail_toml_returns_unusable_error() {
	let dir = fresh_dir("invalid-toml-mail");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let accounts_path = dir.path().join("data").join("accounts.toml");

	std::fs::write(
		&mail_toml,
		b"hostname = \"mail.local.test\"\nthis is not = ][ valid\n",
	)
	.expect("write invalid TOML");

	let mail_before = std::fs::read(&mail_toml).expect("read mail.toml before prepare");
	let accounts_before = std::fs::read(&accounts_path).expect("read accounts.toml before prepare");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an invalid mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
	);

	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	let accounts_after = std::fs::read(&accounts_path).expect("read accounts.toml after");
	assert_eq!(
		mail_before, mail_after,
		"mail.toml must be byte-for-byte identical when prepare fails"
	);
	assert_eq!(
		accounts_before, accounts_after,
		"accounts.toml must be byte-for-byte identical when prepare fails"
	);
}

/// Pin: a `mail.toml` whose `data_dir` is a relative path is treated
/// as an unusable file: the loader names `data_dir` in the diagnostic
/// (the field the operator has to fix), not a generic
/// "load_local_config called for a non-Loaded outcome" placeholder that
/// hid the underlying `ConfigError::Invalid` message. Built `prepare`
/// always emits an absolute `data_dir`, so the test calls the loader
/// directly with a hand-crafted `mail.toml` carrying `data_dir = "data"`.
#[test]
fn relative_data_dir_loader_returns_diagnostic_that_names_data_dir() {
	let dir = fresh_dir("relative-data-dir");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let original = std::fs::read_to_string(&mail_toml).expect("read mail.toml");
	let patched = original.replace(
		&format!("data_dir = \"{}\"", dir.path().join("data").display()),
		"data_dir = \"data\"",
	);
	std::fs::write(&mail_toml, patched).expect("write relative data_dir");

	let err = load_for_test(&mail_toml).expect_err("relative data_dir is an error");
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);
	assert!(
		rendered.contains("data_dir"),
		"error must name data_dir, got: {rendered}"
	);
	assert!(
		rendered.contains("Fix it"),
		"error must carry the standard remedy, got: {rendered}"
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
		other => panic!("accounts path stat error must be Unusable, got {other:?}"),
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

/// Pin: when `mail.toml` is unusable, `prepare` returns `Err` and
/// neither the certificate nor the DKIM key is regenerated. The
/// evaluation order is: `ensure_dir` -> `write_marker` -> fault point
/// -> evaluate credential pair outcome -> (only on `Missing` or
/// `Loaded`) create the data directory, regenerate cert/key if
/// needed, regenerate dkim if needed, regenerate the credential pair
/// if needed. A `mail.toml` that exists but cannot be used is an
/// operator-fixable error; an error run that regenerated the cert /
/// key / dkim in the meantime would leave the directory in a state a
/// later fix-up run could not recognise (a freshly-regenerated
/// `cert.pem` next to a broken `mail.toml` and a missing `key.pem`).
///
/// The setup exploits the cert/key pairing: a first `prepare` lays
/// out a valid directory, the test corrupts `mail.toml` (invalid
/// TOML) and deletes `key.pem`. If the cert step runs before the
/// credential-pair check, the cert step regenerates the pair (one
/// piece missing -> both regenerated) and `key.pem` reappears. The
/// new ordering returns `Err` first, before the cert step runs.
/// `cert.pem` is byte-identical to the first run because no
/// regeneration happened; `key.pem` is still absent because no
/// regeneration happened; `mail.toml` is still the broken bytes the
/// test wrote, not the original.
#[cfg(unix)]
#[test]
fn invalid_mail_toml_does_not_regenerate_certificate_or_dkim() {
	let dir = fresh_dir("invalid-mail-no-cert-regen");
	let _ = prepare(dir.path(), DEFAULT_PORT_BASE).expect("first prepare");

	let mail_toml = dir.path().join("mail.toml");
	let cert_path = dir.path().join("cert.pem");
	let key_path = dir.path().join("key.pem");
	let dkim_path = dir.path().join("dkim.pem");

	let cert_before = std::fs::read(&cert_path).expect("read cert.pem before");
	let dkim_before = std::fs::read(&dkim_path).expect("read dkim.pem before");

	// Corrupt `mail.toml` with non-empty bytes that are not valid
	// TOML. `Config::load` fails with a parse error and `prepare`
	// must propagate the `Unusable` outcome without touching the
	// cert / key / dkim files.
	std::fs::write(&mail_toml, b"this is not TOML = ][ at all")
		.expect("write invalid TOML to mail.toml");

	// Delete `key.pem` so the cert step would regenerate the pair
	// if the credential-pair check were reordered after it.
	std::fs::remove_file(&key_path).expect("remove key.pem");

	let err = match prepare(dir.path(), DEFAULT_PORT_BASE) {
		Err(error) => error,
		Ok(_) => panic!("prepare must return Err for an invalid mail.toml, got Ok"),
	};
	let rendered = format!("{err}");
	assert!(
		rendered.contains("mail.toml"),
		"error must name mail.toml, got: {rendered}"
	);

	// `key.pem` must still be absent: the cert step never ran, so
	// it was not regenerated. The first prepare left `key.pem` on
	// disk; the test removed it; nothing in the failed `prepare`
	// put it back.
	assert!(
		!key_path.exists(),
		"key.pem must STILL be absent: the credential-pair check ran before the cert step, so the cert step did not run, so the pair was not regenerated"
	);

	// `cert.pem` must be byte-identical to the file the first
	// `prepare` wrote: nothing regenerated it.
	let cert_after = std::fs::read(&cert_path).expect("read cert.pem after");
	assert_eq!(
		cert_before, cert_after,
		"cert.pem must be byte-identical to the first run: the credential-pair check ran before the cert step, so the cert step did not run"
	);

	// `dkim.pem` must be byte-identical for the same reason.
	let dkim_after = std::fs::read(&dkim_path).expect("read dkim.pem after");
	assert_eq!(
		dkim_before, dkim_after,
		"dkim.pem must be byte-identical to the first run: the credential-pair check ran before the dkim step, so the dkim step did not run"
	);

	// The data directory must still be the one the first `prepare`
	// created (its mtime is unchanged), and the broken `mail.toml`
	// must still be the bytes the test wrote.
	let mail_after = std::fs::read(&mail_toml).expect("read mail.toml after");
	assert_eq!(
		mail_after, b"this is not TOML = ][ at all",
		"mail.toml must be the broken bytes the test wrote (the failed prepare must not have rewritten it)"
	);
}
