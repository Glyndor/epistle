//! Exit code 3: the command is well formed and its target exists, but a
//! rule of the server refuses the change. Usage errors and unknown names
//! stay 2.

use crate::harness::{add_account, env, epistle};

fn refused(args: &[&str]) -> (Option<i32>, String, String) {
	let output = epistle(args, b"");
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

#[test]
fn a_static_account_is_refused_by_policy() {
	let env =
		env("[[accounts]]\nname = \"postmaster\"\naddresses = [\"postmaster@example.org\"]\n");
	for args in [
		vec![
			"account",
			"--config",
			&env.config,
			"disable",
			"postmaster",
			"--json",
		],
		vec![
			"account",
			"--config",
			&env.config,
			"remove",
			"postmaster",
			"--queue",
			"drain",
			"--yes",
		],
		vec![
			"app-password",
			"--config",
			&env.config,
			"create",
			"postmaster",
			"phone",
		],
	] {
		let (code, stdout, stderr) = refused(&args);
		assert_eq!(code, Some(3), "{args:?}: {stderr}");
		assert_eq!(stdout, "", "{args:?}");
		assert!(stderr.contains("static account"), "{args:?}: {stderr}");
	}
}

#[test]
fn rules_the_server_enforces_are_refused_by_policy() {
	let env = env("masked_addresses_max = 1\n");
	add_account(&env, "bob");
	let cases: [(Vec<&str>, &str); 3] = [
		(
			vec![
				"account",
				"--config",
				&env.config,
				"forward",
				"add",
				"bob",
				"out@example.com",
			],
			"error: account bob forward: set `srs_secret` in the config first; without SRS a forwarded copy fails SPF at the next hop\n",
		),
		(
			vec![
				"api-key",
				"--config",
				&env.config,
				"create",
				"k",
				"--scope",
				"scim",
				"--account",
				"bob",
			],
			"error: account-bound API keys cannot hold the scim scope (scim is administrative)\n",
		),
		(
			vec![
				"masked",
				"--config",
				&env.config,
				"add",
				"bob",
				"--label",
				"two",
			],
			"error: masked-address limit (1) reached for the account\n",
		),
	];
	let first = epistle(
		&[
			"masked",
			"--config",
			&env.config,
			"add",
			"bob",
			"--label",
			"one",
		],
		b"",
	);
	assert!(first.status.success(), "the first mask failed");
	for (args, message) in cases {
		let (code, stdout, stderr) = refused(&args);
		assert_eq!(
			(code, stdout.as_str(), stderr.as_str()),
			(Some(3), "", message),
			"{args:?}"
		);
	}
}

#[test]
fn an_unknown_name_stays_a_usage_error() {
	let env = env("");
	let (code, _, stderr) = refused(&["account", "--config", &env.config, "disable", "nobody"]);
	assert_eq!(
		(code, stderr.as_str()),
		(Some(2), "error: no such account: nobody\n")
	);
}
