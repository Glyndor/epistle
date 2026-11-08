//! `epistle account list --aliases`: under each account, the address aliases
//! that deliver to it. Without the flag the output is what it always was.

use serde_json::{Value, json};

use crate::harness::{Env, add_account, env, epistle, json};

/// `team` has members in both accounts and one outside address, `sales`
/// only in bob (and is disabled by `seeded`), `ghost` and `ext` in no
/// account. A domain alias sits beside them and must not show up.
const CONFIG: &str = r#"
[domain_aliases]
"alias.example.org" = "example.org"

[[alias]]
address = "team@example.org"
members = ["bob@example.org", "carol@example.org", "outside@example.net"]

[[alias]]
address = "sales@example.org"
members = ["Bob@Example.org"]
hidden = false

[[alias]]
address = "ghost@example.org"
members = ["nobody@example.net"]

[[alias]]
address = "ext@example.org"
members = ["x@example.net", "y@example.net"]
"#;

fn seeded(config: &str) -> Env {
	let env = env(config);
	add_account(&env, "bob");
	add_account(&env, "carol");
	env
}

fn disable(env: &Env, address: &str) {
	let out = epistle(&["alias", "--config", &env.config, "disable", address], b"");
	assert!(
		out.status.success(),
		"{}",
		String::from_utf8_lossy(&out.stderr)
	);
}

fn text(env: &Env, extra: &[&str]) -> String {
	let mut args = vec!["account", "--config", env.config.as_str(), "list"];
	args.extend_from_slice(extra);
	let out = epistle(&args, b"");
	assert!(
		out.status.success(),
		"{}",
		String::from_utf8_lossy(&out.stderr)
	);
	String::from_utf8(out.stdout).expect("utf8")
}

fn as_json(env: &Env, extra: &[&str]) -> Value {
	let mut args = vec!["account", "--config", env.config.as_str(), "list", "--json"];
	args.extend_from_slice(extra);
	let (code, value) = json(&epistle(&args, b""));
	assert_eq!(code, 0);
	value
}

#[test]
fn without_the_flag_the_output_is_unchanged() {
	let env = seeded(CONFIG);
	assert_eq!(
		text(&env, &[]),
		"bob\tdynamic\tbob@example.org\ncarol\tdynamic\tcarol@example.org\n2 accounts\n"
	);
}

#[test]
fn aliases_hang_under_each_member_account() {
	let env = seeded(CONFIG);
	assert_eq!(
		text(&env, &["--aliases"]),
		"bob\tdynamic\tbob@example.org\n  alias sales@example.org\n  alias team@example.org\n\
		 carol\tdynamic\tcarol@example.org\n  alias team@example.org\n\
		 2 accounts\n\
		 2 aliases deliver to no local account; see them with `epistle alias list`\n"
	);
}

#[test]
fn a_disabled_alias_is_marked_not_hidden() {
	let env = seeded(CONFIG);
	disable(&env, "sales@example.org");
	let shown = text(&env, &["--aliases"]);
	assert!(
		shown.contains("  alias sales@example.org (disabled)\n"),
		"{shown}"
	);
	assert!(shown.contains("  alias team@example.org\n"), "{shown}");
}

#[test]
fn one_alias_without_an_account_is_counted_in_the_singular() {
	let env = seeded(
		"[[alias]]\naddress = \"lost@example.org\"\nmembers = [\"x@example.net\"]\n\
		 [[alias]]\naddress = \"team@example.org\"\nmembers = [\"bob@example.org\"]\n",
	);
	let shown = text(&env, &["--aliases"]);
	assert!(
		shown.ends_with(
			"1 alias delivers to no local account; see them with `epistle alias list`\n"
		),
		"{shown}"
	);
}

#[test]
fn no_summary_when_every_alias_has_an_account() {
	let env =
		seeded("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"bob@example.org\"]\n");
	assert_eq!(
		text(&env, &["--aliases"]),
		"bob\tdynamic\tbob@example.org\n  alias team@example.org\n\
		 carol\tdynamic\tcarol@example.org\n2 accounts\n"
	);
}

#[test]
fn json_without_the_flag_has_no_aliases_key() {
	let env = seeded(CONFIG);
	assert_eq!(
		as_json(&env, &[]),
		json!([
			{ "name": "bob", "source": "dynamic", "display_name": null, "addresses": ["bob@example.org"] },
			{ "name": "carol", "source": "dynamic", "display_name": null, "addresses": ["carol@example.org"] },
		])
	);
}

#[test]
fn json_with_the_flag_adds_aliases_to_each_account() {
	let env = seeded(CONFIG);
	disable(&env, "sales@example.org");
	assert_eq!(
		as_json(&env, &["--aliases"]),
		json!([
			{
				"name": "bob", "source": "dynamic", "display_name": null,
				"addresses": ["bob@example.org"],
				"aliases": [
					{ "address": "sales@example.org", "enabled": false, "hidden": false },
					{ "address": "team@example.org", "enabled": true, "hidden": true },
				],
			},
			{
				"name": "carol", "source": "dynamic", "display_name": null,
				"addresses": ["carol@example.org"],
				"aliases": [{ "address": "team@example.org", "enabled": true, "hidden": true }],
			},
		])
	);
}

#[test]
fn an_account_with_no_alias_gets_an_empty_list() {
	let env =
		seeded("[[alias]]\naddress = \"team@example.org\"\nmembers = [\"bob@example.org\"]\n");
	let value = as_json(&env, &["--aliases"]);
	assert_eq!(value[1]["aliases"], json!([]));
}
