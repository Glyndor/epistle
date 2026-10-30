//! Tests for the move journal.

use super::super::super::mover::{Pair, Plan};
use super::super::super::table::Block;
use super::{parse, render};

fn plan() -> Plan {
	Plan {
		uid: Some(Pair {
			old: Block {
				start: 100000,
				count: 65536,
			},
			new: Block {
				start: 165536,
				count: 65536,
			},
		}),
		gid: None,
		units: vec!["podman.socket".to_string()],
		containers: vec!["abc123".to_string()],
	}
}

#[test]
fn a_journal_reads_back_as_the_plan_it_was_written_from() {
	let text = render(&plan());
	assert_eq!(
		text,
		"subuid 100000 165536 65536\nunit podman.socket\ncontainer abc123\n"
	);
	assert_eq!(parse(&text), Ok(plan()));
}

#[test]
fn a_damaged_journal_is_refused_rather_than_guessed() {
	for text in [
		"",
		"unit podman.socket\n",
		"subuid 100000 165536\n",
		"subuid 100000 x 65536\n",
		"subuid 100000 165536 0\n",
		"rm -rf /\n",
	] {
		assert!(parse(text).is_err(), "{text:?} must not parse");
	}
}
