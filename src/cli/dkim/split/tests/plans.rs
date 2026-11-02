//! Which domain keeps the `[dkim]` key and which move.

use super::harness::Install;
use crate::cli::dkim::split::plan;

#[test]
fn the_first_listed_domain_keeps_the_key_and_the_others_move() {
	let install = Install::new(&["b.example.org", "a.example.org", "c.example.org"], "");
	let plan = plan::build(&install.load())
		.expect("plans")
		.expect("something to split");
	assert_eq!(plan.keeps, "b.example.org");
	assert_eq!(plan.moves, ["a.example.org", "c.example.org"]);
	assert!(!plan.dual_signing);
}

#[test]
fn a_domain_with_a_key_of_its_own_is_neither_kept_nor_moved() {
	let own = format!(
		"[[dkim.domain]]\nname = \"a.example.org\"\nselector = \"o\"\nkey_file = {:?}\n",
		"/k/a.pem"
	);
	let install = Install::new(&["a.example.org", "b.example.org", "c.example.org"], &own);
	let plan = plan::build(&install.load())
		.expect("plans")
		.expect("something to split");
	assert_eq!(plan.keeps, "b.example.org");
	assert_eq!(plan.moves, ["c.example.org"]);
}

#[test]
fn one_domain_on_the_key_leaves_nothing_to_split() {
	let install = Install::new(&["a.example.org"], "");
	assert_eq!(plan::build(&install.load()), Ok(None));
}

#[test]
fn a_rotation_in_progress_refuses() {
	let install = Install::new(&["a.example.org", "b.example.org"], "");
	let state = serde_json::json!({
		"selector": "ed1", "key_file": "dkim-ed1.key", "rotated_at": 1, "previous": null,
		"pending": {
			"selector": "ed2", "key_file": "dkim-ed2.key",
			"domains": ["a.example.org"], "started_at": 2
		}
	});
	std::fs::write(install.data().join("dkim-rotation.json"), state.to_string()).expect("state");
	let reason = plan::build(&install.load()).expect_err("refused");
	assert!(
		reason.contains("rotation to ed2 is in progress"),
		"{reason}"
	);
}
