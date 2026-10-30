//! Creating something in a disabled domain: a mask is refused, an account
//! or an alias is created with a warning that it cannot work yet.

use crate::harness::{Env, PASSWORD, add_account, env, epistle};

/// `example.net` hosted and switched off, and an account `bob`.
fn setup() -> Env {
	let env = env("");
	for args in [
		vec!["domain", "--config", &env.config, "add", "example.net"],
		vec![
			"domain",
			"--config",
			&env.config,
			"disable",
			"example.net",
			"--yes",
		],
	] {
		assert!(epistle(&args, b"").status.success());
	}
	add_account(&env, "bob");
	env
}

fn run(env: &Env, args: &[&str], stdin: &[u8]) -> (Option<i32>, String, String) {
	let mut full: Vec<&str> = args.to_vec();
	full.extend(["--config", &env.config, "--json"]);
	let output = epistle(&full, stdin);
	(
		output.status.code(),
		String::from_utf8_lossy(&output.stdout).into_owned(),
		String::from_utf8_lossy(&output.stderr).into_owned(),
	)
}

#[test]
fn a_mask_in_a_disabled_domain_is_refused() {
	let env = setup();
	let (code, stdout, stderr) = run(
		&env,
		&[
			"masked",
			"add",
			"bob",
			"--label",
			"shop",
			"--domain",
			"example.net",
		],
		b"",
	);
	assert_eq!((code, stdout.as_str()), (Some(2), ""), "{stderr}");
	assert_eq!(
		stderr.trim_end(),
		"error: example.net is disabled; its mail is rejected until `epistle domain enable example.net`"
	);
	let (code, stdout, _) = run(&env, &["masked", "add", "bob", "--label", "shop"], b"");
	assert_eq!(
		code,
		Some(0),
		"the default domain is bob's own, example.org: {stdout}"
	);
}

#[test]
fn a_mask_defaulting_to_a_disabled_domain_is_refused() {
	let env = env("");
	for args in [
		vec!["domain", "--config", &env.config, "add", "example.net"],
		vec![
			"domain",
			"--config",
			&env.config,
			"disable",
			"example.net",
			"--yes",
		],
	] {
		assert!(epistle(&args, b"").status.success());
	}
	let output = epistle(
		&[
			"account",
			"--config",
			&env.config,
			"add",
			"carol",
			"--address",
			"carol@example.org",
			"--address",
			"carol@example.net",
		],
		PASSWORD,
	);
	assert!(output.status.success());
	// Make the account's first address the disabled one by removing the other.
	assert!(
		epistle(
			&[
				"account",
				"--config",
				&env.config,
				"address",
				"remove",
				"carol",
				"carol@example.org"
			],
			b""
		)
		.status
		.success()
	);
	let (code, stdout, stderr) = run(&env, &["masked", "add", "carol", "--label", "shop"], b"");
	assert_eq!((code, stdout.as_str()), (Some(2), ""), "{stderr}");
	assert!(stderr.contains("example.net is disabled"), "{stderr}");
}

#[test]
fn an_account_address_in_a_disabled_domain_is_created_with_a_warning() {
	let env = setup();
	let (code, stdout, stderr) = run(
		&env,
		&["account", "add", "carol", "--address", "carol@example.net"],
		PASSWORD,
	);
	assert_eq!(code, Some(0), "{stderr}");
	assert_eq!(stdout.lines().count(), 1);
	assert!(
		stderr.contains("carol@example.net is in the disabled domain example.net"),
		"{stderr}"
	);
	let (_, _, quiet) = run(
		&env,
		&["account", "add", "dave", "--address", "dave@example.org"],
		PASSWORD,
	);
	assert!(!quiet.contains("disabled"), "{quiet}");
}

#[test]
fn an_alias_in_a_disabled_domain_is_created_with_a_warning() {
	let env = setup();
	let (code, stdout, stderr) = run(
		&env,
		&["alias", "add", "team@example.net", "bob@example.org"],
		b"",
	);
	assert_eq!(code, Some(0), "{stderr}");
	assert_eq!(stdout.lines().count(), 1);
	assert!(
		stderr.contains("team@example.net is in the disabled domain example.net"),
		"{stderr}"
	);
}
