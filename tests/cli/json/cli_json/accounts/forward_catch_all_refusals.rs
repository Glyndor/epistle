//! `epistle account forward` and `account catch-all` against the real binary:
//! what the delivery directory would misroute is refused with exit code 2 and
//! leaves the account as it was. A forward onto the account's own address, a
//! second catch-all for a domain, a catch-all for a domain that is not
//! hosted, and a removal of something that is not on the list.

use serde_json::Value;

use crate::harness::{Env, add_account, env, epistle};

fn account(env: &Env, args: &[&str]) -> std::process::Output {
	let mut full = vec!["account"];
	full.extend_from_slice(args);
	full.extend_from_slice(&["--config", &env.config]);
	epistle(&full, b"")
}

fn stderr(output: &std::process::Output) -> String {
	String::from_utf8_lossy(&output.stderr).into_owned()
}

/// `account show NAME --json` as a value.
fn shown(env: &Env, name: &str) -> Value {
	let output = account(env, &["show", name, "--json"]);
	assert_eq!(output.status.code(), Some(0), "{}", stderr(&output));
	serde_json::from_slice(&output.stdout).expect("JSON")
}

/// `args` refused: exit 2, nothing on stdout, `needle` on stderr, and the
/// views of `alice` and `bob` as they were.
fn refused(env: &Env, args: &[&str], needle: &str) {
	let before = (shown(env, "alice"), shown(env, "bob"));
	let output = account(env, args);
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
	assert_eq!((shown(env, "alice"), shown(env, "bob")), before, "{args:?}");
}

fn two_accounts() -> Env {
	// A forwarded copy needs SRS, or the command refuses before it looks at
	// the address.
	let env = env("srs_secret = \"0123456789abcdef0123456789abcdef\"\n");
	add_account(&env, "alice");
	add_account(&env, "bob");
	env
}

#[test]
fn a_forward_is_checked_before_it_is_added_and_removed_only_when_listed() {
	let env = two_accounts();
	refused(
		&env,
		&["forward", "add", "alice", "not-an-address"],
		"account alice forward:",
	);
	refused(
		&env,
		&["forward", "add", "alice", "alice@example.org"],
		"cannot forward alice to its own address",
	);
	refused(
		&env,
		&["forward", "add", "ghost", "out@remote.example"],
		"no such account: ghost",
	);
	refused(
		&env,
		&["forward", "remove", "alice", "out@remote.example"],
		"is not in alice's forward list",
	);

	let added = account(&env, &["forward", "add", "alice", "Out@Remote.example"]);
	assert_eq!(added.status.code(), Some(0), "{}", stderr(&added));
	assert_eq!(
		shown(&env, "alice")["forward"],
		serde_json::json!(["out@remote.example"])
	);
	refused(
		&env,
		&["forward", "add", "alice", "out@remote.example"],
		"already on the list",
	);
	// The list belongs to the account that holds it.
	refused(
		&env,
		&["forward", "remove", "bob", "out@remote.example"],
		"is not in bob's forward list",
	);
	assert_eq!(
		shown(&env, "alice")["forward"],
		serde_json::json!(["out@remote.example"])
	);

	let removed = account(&env, &["forward", "remove", "alice", "OUT@remote.example"]);
	assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
	assert_eq!(shown(&env, "alice")["forward"], serde_json::json!([]));
}

#[test]
fn a_catch_all_goes_to_one_account_for_a_domain_that_is_hosted() {
	let env = two_accounts();
	refused(
		&env,
		&["catch-all", "add", "alice", "elsewhere.example"],
		"account alice catch-all:",
	);
	refused(
		&env,
		&["catch-all", "add", "ghost", "example.org"],
		"no such account: ghost",
	);
	refused(
		&env,
		&["catch-all", "remove", "alice", "example.org"],
		"account alice catch-all:",
	);

	let added = account(&env, &["catch-all", "add", "alice", "EXAMPLE.org"]);
	assert_eq!(added.status.code(), Some(0), "{}", stderr(&added));
	assert_eq!(
		shown(&env, "alice")["catch_all"],
		serde_json::json!(["example.org"])
	);
	refused(
		&env,
		&["catch-all", "add", "alice", "example.org"],
		"already on the list",
	);
	// A second account does not take the domain from the first.
	refused(
		&env,
		&["catch-all", "add", "bob", "example.org"],
		"already has a catch-all account: alice",
	);
	// Nor can it remove what the first holds.
	refused(
		&env,
		&["catch-all", "remove", "bob", "example.org"],
		"account bob catch-all:",
	);
	assert_eq!(
		shown(&env, "alice")["catch_all"],
		serde_json::json!(["example.org"])
	);

	let removed = account(&env, &["catch-all", "remove", "alice", "example.org"]);
	assert_eq!(removed.status.code(), Some(0), "{}", stderr(&removed));
	assert_eq!(shown(&env, "alice")["catch_all"], serde_json::json!([]));
}
