//! The settings with an enforced floor, through the real loader: a value below
//! its floor is a load error that names the key, and a configuration that is
//! accepted puts its password, hashing and ban settings in force.
//!
//! One test, because accepting a configuration installs process-wide settings
//! and this binary is its own process: the refusals run first, the acceptance
//! last.

use std::io::Write;

use epistle::config::Config;

const BASE: &str = "hostname = \"mail.example.org\"\ndata_dir = \"/var/lib/mail\"\n";

fn load(extra: &str) -> Result<Config, String> {
	let mut file = tempfile::NamedTempFile::new().expect("temp file");
	file.write_all(format!("{BASE}{extra}").as_bytes())
		.expect("write");
	Config::load(file.path()).map_err(|error| error.to_string())
}

fn refused(extra: &str, needle: &str) {
	let error = load(extra).expect_err(extra);
	assert!(
		error.contains(needle),
		"{extra:?} gave {error:?}, wanted {needle:?}"
	);
}

#[test]
fn floors_are_enforced_at_load_and_an_accepted_file_is_put_in_force() {
	// Below a floor, above a ceiling, or inconsistent: a clear error each.
	refused(
		"[auth]\nmin_password_length = 7\n",
		"min_password_length (7) must be at least 8",
	);
	refused(
		"[auth]\nmax_password_length = 63\n",
		"max_password_length (63) must be at least 64",
	);
	refused(
		"[auth]\nargon2_memory_kib = 1000\n",
		"argon2_memory_kib (1000) must be at least 19456",
	);
	refused(
		"[auth]\nargon2_iterations = 1\n",
		"argon2_iterations (1) must be at least 2",
	);
	refused(
		"[auth]\nscram_iterations = 4096\n",
		"scram_iterations (4096) must be at least 600000",
	);
	refused(
		"[bans]\nthreshold = 21\n",
		"[bans] threshold (21) must be between 2 and 20",
	);
	refused(
		"[bans]\nbase_secs = 60\n",
		"[bans] base_secs (60) must be between 300 and 86400",
	);
	refused(
		"[bans]\nbase_secs = 7200\nmax_secs = 3600\n",
		"max_secs (3600) must not be shorter than base_secs (7200)",
	);
	refused(
		"[api.limiter]\nmax_failures = 500\n",
		"[api.limiter] max_failures (500)",
	);
	refused(
		"[api.limiter]\nwindow_secs = 5\n",
		"[api.limiter] window_secs (5)",
	);
	refused(
		"[oauth]\nissuer = \"i\"\naudience = \"a\"\nalgorithm = \"ES256\"\npublic_key = \"K\"\n\
		 signing_key = \"S\"\naccess_token_ttl_secs = 5\n",
		"access_token_ttl_secs` (5) must be between 60 and 86400",
	);
	refused(
		"[auth]\nforbidden_passwords_file = \"/nonexistent/forbidden.txt\"\n",
		"forbidden_passwords_file /nonexistent/forbidden.txt: cannot read it",
	);

	// An accepted file is put in force.
	let dir = tempfile::tempdir().expect("tempdir");
	let list = dir.path().join("forbidden.txt");
	std::fs::write(&list, "# example list\nExample Corp Forbidden\n").expect("write");
	let config = load(&format!(
		"[auth]\nmin_password_length = 8\nmax_password_length = 128\nargon2_memory_kib = 32768\n\
		 argon2_iterations = 3\nscram_iterations = 700000\nforbidden_passwords_file = {:?}\n\
		 [bans]\nthreshold = 3\nmax_secs = 7200\n",
		list.display().to_string()
	))
	.expect("accepted");

	let short = ["q7Zk", "4mX"].join("-");
	assert_eq!(short.len(), 8);
	assert_eq!(
		epistle::password::validate(&short),
		Ok(()),
		"eight characters now pass"
	);
	let long = ["q7Zk", "4mXe"].join("-").repeat(14);
	assert_eq!(long.len(), 126);
	assert_eq!(
		epistle::password::validate(&long),
		Ok(()),
		"126 characters now pass"
	);
	assert_eq!(
		epistle::password::validate(&["example", "corp", "forbidden"].join(" ")),
		Err(epistle::password::Rejection::Forbidden)
	);
	let hash = epistle::smtp::auth::hash_password(&short).expect("hash");
	assert_eq!(hash.split('$').nth(3), Some("m=32768,t=3,p=1"), "{hash}");
	let verifier = epistle::smtp::scram::ScramStored::with_fresh_salt(&short).expect("derive");
	assert_eq!(verifier.iterations, 700_000);
	let policy = config
		.bans
		.policy(epistle::antispam::bans::BanPolicy::default());
	assert_eq!((policy.threshold, policy.max_secs), (3, 7200));
	assert_eq!(policy.threshold_for("account:alice"), 12);
}
