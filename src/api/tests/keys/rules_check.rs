//! The checks that keep the rule table honest: every route declares a
//! rule, and every rule names a test that exists.

use super::rules::{Domain, RULES, registered_routes};
use std::collections::BTreeSet;

#[test]
fn every_route_declares_its_domain_rule() {
	let declared: BTreeSet<String> = RULES.iter().map(|rule| rule.pattern.to_string()).collect();
	assert_eq!(declared.len(), RULES.len(), "a pattern is listed twice");
	let registered = registered_routes();
	let undeclared: Vec<_> = registered.difference(&declared).collect();
	let stale: Vec<_> = declared.difference(&registered).collect();
	assert!(
		undeclared.is_empty(),
		"routes with no rule in RULES (decide how each treats a key confined to some domains): {undeclared:?}"
	);
	assert!(
		stale.is_empty(),
		"rules for routes that no router registers: {stale:?}"
	);
}

#[test]
fn every_rule_names_a_test_that_exists() {
	let mut sources = String::new();
	let mut pending = vec![std::path::PathBuf::from(concat!(
		env!("CARGO_MANIFEST_DIR"),
		"/src/api"
	))];
	while let Some(dir) = pending.pop() {
		for entry in std::fs::read_dir(&dir).expect("read src/api") {
			let path = entry.expect("entry").path();
			if path.is_dir() {
				pending.push(path);
			} else if path.extension().is_some_and(|ext| ext == "rs") {
				sources.push_str(&std::fs::read_to_string(&path).expect("read source"));
			}
		}
	}
	for rule in RULES {
		if rule.domain == Domain::Open {
			continue;
		}
		assert_ne!(rule.covered_by, "-", "{} needs a test", rule.pattern);
		let needle = format!("fn {}(", rule.covered_by);
		assert!(
			sources.contains(&needle),
			"{} is covered by {}, which does not exist",
			rule.pattern,
			rule.covered_by
		);
		assert!(!rule.scope.is_empty());
	}
}
