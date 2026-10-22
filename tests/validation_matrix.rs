//! The boundary table of the identity rules, driven through every surface that
//! reaches them.
//!
//! An audit of the validation rules (the work that left `src/util/validation/`
//! in the tree) found that most rules already have exactly one definition, and
//! the ones that did not had it retyped at each call site. This file and
//! `validation_matrix/rules_b.rs` are the premise those conclusions rest on,
//! written as assertions so a rule that drifts between two surfaces turns the
//! build red instead of waiting for the next audit.
//!
//! Every case asserts the *observed* answer rather than the intended one, and a
//! refusal names the row it belongs to. A test that only asked "is it accepted"
//! would pass on a rule that had quietly started refusing everything.
//!
//! The rules here are the ones that decide *who a mail belongs to*: the account
//! name, the address, and the domain. The rules that decide what a name may
//! *look like* are in the other half.

#[path = "validation_matrix/address.rs"]
mod address;
#[path = "validation_matrix/common.rs"]
mod common;
#[path = "validation_matrix/rules_b.rs"]
mod rules_b;

use common::{Row, cell, matrix, store};
use epistle::domain;
use epistle::util::account_rule;
use epistle::util::path_component::AccountName;

#[test]
fn the_account_name_rule_answers_the_same_through_every_path() {
	let paths = ["rule", "rule-stored", "store", "dir-component"];
	// `rule` is the definition reading a name as typed. `rule-stored` is the
	// same definition applied to the stored form, which is what the store
	// applies and the reason a mixed-case `--name` is converted rather than
	// refused (owner decision of 2026-10-12). `store` is the path the CLI, the
	// management API and SCIM all take. `dir-component` is the path-safety
	// rule an external directory row goes through, deliberately wider because
	// SQL and LDAP name accounts `J_Smith`.
	let mut rows = Vec::new();
	for (what, name) in [
		("empty", ""),
		("one character", "a"),
		("plain", "torre"),
		("with a digit", "torre2"),
		("with a hyphen inside", "torre-control"),
		("hyphen at the start", "-torre"),
		("hyphen at the end", "torre-"),
		("capital", "Torre"),
		("capital outside ASCII", "T\u{c6}dRRE"),
		("non-ASCII", "jos\u{e9}"),
		("dot", "torre.control"),
		("space inside", "torre control"),
		("space around", " torre "),
		("NFD of e-acute", "jose\u{0301}"),
		("NFC of e-acute", "jos\u{e9}"),
		("at the maximum length", &"a".repeat(64)),
		("one over the maximum", &"a".repeat(65)),
		("a slash", "torre/control"),
		("NUL", "torre\0control"),
		("CR LF", "torre\r\ncontrol"),
		("a plus", "torre+tag"),
		("a quote", "torre\"control"),
	] {
		let stored_form = epistle::directory_store::account_name(name);
		// The address is built from the stored local part so this table
		// measures the name rule and not the address rule.
		let account = format!("{}@example.org", stored_form.trim());
		let (_, store) = store();
		rows.push(Row {
			what,
			value: name.to_string(),
			accepted: vec![
				account_rule::check(name).is_ok(),
				account_rule::check(&stored_form).is_ok(),
				store
					.validate_for_add(name, std::slice::from_ref(&account))
					.is_ok(),
				AccountName::new(stored_form.trim()).is_ok(),
			],
		});
	}
	for row in &rows {
		assert_eq!(
			row.accepted[1],
			row.accepted[2],
			"the rule on the stored form and the store disagree on {:?}{}",
			row.value,
			matrix(&rows, &paths)
		);
	}
	for (what, expected) in [
		("empty", false),
		("one character", true),
		("plain", true),
		("with a digit", true),
		("with a hyphen inside", true),
		("hyphen at the start", false),
		("hyphen at the end", true),
		("capital", false),
		("capital outside ASCII", false),
		("non-ASCII", false),
		("dot", false),
		("space inside", false),
		("space around", false),
		("NFD of e-acute", false),
		("NFC of e-acute", false),
		("at the maximum length", true),
		("one over the maximum", false),
		("a slash", false),
		("NUL", false),
		("CR LF", false),
		("a plus", false),
		("a quote", false),
	] {
		cell(&rows, &paths, what, 0, expected);
	}
	// The capital row is the one the stored form widens: read as typed the rule
	// refuses a capital, read as stored it is lowercase and accepted.
	let capital = rows.iter().find(|row| row.what == "capital").expect("row");
	assert!(
		!capital.accepted[0] && capital.accepted[1] && capital.accepted[2],
		"a mixed-case name is converted, not refused{}",
		matrix(&rows, &paths)
	);
	// The external directory path stays wider on purpose: a SQL or LDAP row
	// only has to be a directory name.
	for what in ["dot", "capital", "capital outside ASCII", "non-ASCII"] {
		cell(&rows, &paths, what, 3, true);
	}
}

#[test]
fn an_address_gives_an_account_name_by_the_one_derivation() {
	// `init` derives the name of the first account from its address. The dot
	// becomes a hyphen, because the account name doubles as a directory name
	// and the name rule refuses a dot.
	for (local, expected) in [
		("torre", Some("torre")),
		("torre.control", Some("torre-control")),
		("Torre.Control", Some("torre-control")),
		("a.b.c", Some("a-b-c")),
		("jos\u{e9}", None),
		(".torre", None),
		("torre.", None),
		("torre..control", None),
		("torre+tag", None),
		("", None),
	] {
		match (account_rule::derive(local), expected) {
			(Ok(got), Some(want)) => assert_eq!(got, want, "derive({local:?})"),
			(got, want) => assert_eq!(
				got.is_ok(),
				want.is_some(),
				"derive({local:?}) answered {got:?}, this table says {want:?}"
			),
		}
	}
	// Whatever `derive` produces is a name the rule accepts, or the refusal is
	// the derivation's own and the two say the same thing.
	for local in [
		"torre",
		"torre.control",
		"Torre.Control",
		"a.b.c",
		&"a".repeat(account_rule::MAX_LEN),
	] {
		if let Ok(name) = account_rule::derive(local) {
			assert!(
				account_rule::check(&name).is_ok(),
				"derive({local:?}) produced {name:?}, which the rule then refuses"
			);
		}
	}
	// A local part that cannot give a name at its length is refused for the
	// length, not silently cut.
	let too_long = "a".repeat(account_rule::MAX_LEN + 1);
	assert_eq!(
		account_rule::derive(&too_long),
		Err(account_rule::Fault::TooLong(too_long.len())),
		"a derived name over the cap is refused for its length"
	);
}

#[test]
fn a_domain_normalizes_the_same_way_however_it_is_spelled() {
	for (raw, accepted, a_label) in [
		("", false, None),
		("example", false, None),
		("example.org", true, Some("example.org")),
		("EXAMPLE.ORG", true, Some("example.org")),
		("Example.Org", true, Some("example.org")),
		("b\u{fc}cher.example", true, Some("xn--bcher-kva.example")),
		("XN--BCHER-KVA.EXAMPLE", true, Some("xn--bcher-kva.example")),
		("\u{435}xample.org", false, None),
		("example.org.", false, None),
		("exa..mple.org", false, None),
		("example .org", false, None),
		("-example.org", false, None),
		("example-.org", false, None),
		("exam_ple.org", false, None),
	] {
		let got = domain::normalize(raw);
		assert_eq!(
			got.is_ok(),
			accepted,
			"domain {raw:?}: observed {got:?}, this table says {accepted}"
		);
		if let (Some(want), Ok(got)) = (a_label, got) {
			assert_eq!(got, want, "domain {raw:?} did not normalize to its A-label");
		}
	}
	// Two spellings of one domain are one key, whatever the shape check says.
	for (left, right) in [
		("b\u{fc}cher.example", "xn--bcher-kva.example"),
		("EXAMPLE.ORG", "example.org"),
	] {
		assert_eq!(
			domain::normalize(left),
			domain::normalize(right),
			"the two spellings of {left:?} must be one key"
		);
	}
}
