//! The commands that delete a domain, a domain alias, a masked address or an
//! app password, run from a script: without `--yes` and without a terminal
//! they refuse and change nothing, an object that is not there is a usage
//! error, and what belongs to another account is out of reach.

use serde_json::Value;

use crate::harness::{Env, add_account, env, epistle};
use crate::snapshot::{changes, snapshot};

fn run(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = args.to_vec();
	full.extend_from_slice(&["--config", &env.config]);
	epistle(&full, b"")
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// A command that must succeed.
fn ok(env: &Env, args: &[&str]) -> Value {
	let mut full = args.to_vec();
	full.push("--json");
	let output = run(env, &full);
	assert_eq!(
		output.status.code(),
		Some(0),
		"{args:?}: {}",
		stderr(&output)
	);
	serde_json::from_slice(&output.stdout).unwrap_or(Value::Null)
}

/// `args` refused with exit code 2, nothing on stdout, `needle` on stderr,
/// and the whole directory as it was.
fn refused(env: &Env, args: &[&str], needle: &str) {
	let before = snapshot(env.dir.path());
	let output = run(env, args);
	assert_eq!(
		output.status.code(),
		Some(2),
		"{args:?}: {}",
		stderr(&output)
	);
	assert!(output.stdout.is_empty(), "{args:?}");
	assert!(
		stderr(&output).contains(needle),
		"{args:?}: {}",
		stderr(&output)
	);
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new(),
		"{args:?} changed something"
	);
}

#[test]
fn a_domain_is_removed_only_when_confirmed_and_only_if_it_is_there() {
	let env = env("");
	ok(&env, &["domain", "add", "example.net"]);
	refused(
		&env,
		&["domain", "remove", "example.net"],
		"domain remove was not confirmed",
	);
	refused(
		&env,
		&["domain", "remove", "nowhere.example", "--yes"],
		"domain nowhere.example is not configured",
	);
	let before = snapshot(env.dir.path());
	let dry = run(&env, &["domain", "remove", "example.net", "--dry-run"]);
	assert_eq!(dry.status.code(), Some(0), "{}", stderr(&dry));
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new(),
		"a dry run writes nothing"
	);
	ok(&env, &["domain", "remove", "example.net", "--yes"]);
	refused(
		&env,
		&["domain", "show", "example.net"],
		"domain example.net is not configured",
	);
}

#[test]
fn a_domain_alias_is_removed_only_when_confirmed_and_only_if_it_is_there() {
	let env = env("");
	ok(
		&env,
		&["domain", "alias", "add", "alias.example.net", "example.org"],
	);
	refused(
		&env,
		&["domain", "alias", "remove", "alias.example.net"],
		"domain alias remove was not confirmed",
	);
	refused(
		&env,
		&["domain", "alias", "remove", "other.example.net", "--yes"],
		"domain alias other.example.net is not declared",
	);
	ok(
		&env,
		&["domain", "alias", "remove", "alias.example.net", "--yes"],
	);
	refused(
		&env,
		&["domain", "alias", "remove", "alias.example.net", "--yes"],
		"domain alias alias.example.net is not declared",
	);
}

#[test]
fn an_app_password_is_revoked_only_when_confirmed_and_only_if_it_is_there() {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	ok(&env, &["app-password", "create", "alice", "phone"]);
	refused(
		&env,
		&["app-password", "revoke", "alice", "phone"],
		"app-password-revoke was not confirmed",
	);
	// Another label of the account, and the same label of another account.
	refused(
		&env,
		&["app-password", "revoke", "alice", "tablet", "--yes"],
		"alice/tablet",
	);
	refused(
		&env,
		&["app-password", "revoke", "bob", "phone", "--yes"],
		"bob/phone",
	);
	ok(&env, &["app-password", "revoke", "alice", "phone", "--yes"]);
	refused(
		&env,
		&["app-password", "revoke", "alice", "phone", "--yes"],
		"alice/phone",
	);
}

#[test]
fn a_masked_address_is_removed_only_when_confirmed_and_only_by_its_owner() {
	let env = env("");
	add_account(&env, "alice");
	add_account(&env, "bob");
	let added = ok(&env, &["masked", "add", "alice", "--label", "shop"]);
	let address = added["address"].as_str().expect("address").to_string();
	refused(
		&env,
		&["masked", "remove", "alice", &address],
		"masked remove was not confirmed",
	);
	// Another account naming it does not reach it, with or without --yes.
	let before = snapshot(env.dir.path());
	let stolen = run(&env, &["masked", "remove", "bob", &address, "--yes"]);
	assert_eq!(stolen.status.code(), Some(2), "{}", stderr(&stolen));
	assert_eq!(
		changes(&before, &snapshot(env.dir.path())),
		Vec::<String>::new()
	);
	let listed = run(&env, &["masked", "list", "alice", "--json"]);
	assert!(String::from_utf8_lossy(&listed.stdout).contains(&address));

	ok(&env, &["masked", "remove", "alice", &address, "--yes"]);
	let listed = run(&env, &["masked", "list", "alice", "--json"]);
	assert!(!String::from_utf8_lossy(&listed.stdout).contains(&address));
	let again = run(&env, &["masked", "remove", "alice", &address, "--yes"]);
	assert_eq!(again.status.code(), Some(2), "{}", stderr(&again));
}
