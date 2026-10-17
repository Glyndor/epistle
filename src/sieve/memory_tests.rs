//! No reservation in proportion to the input before the budget has been
//! looked at: a script's variable or a message's header of tens of mebibytes
//! must not make the interpreter hold tens of mebibytes more.

use super::alloc_probe::peak_bytes;
use super::ast::Argument;
use super::compare::match_spec;
use super::env::{Env, MAX_VAR_BYTES};

const MIB: usize = 1 << 20;

fn spec(tag: &str) -> super::compare::MatchSpec {
	match_spec(&[Argument::Tag(tag.to_string())])
}

#[test]
fn an_expansion_is_never_built_past_its_limit() {
	let mut env = Env::default();
	env.set("a", &"y".repeat(MAX_VAR_BYTES));
	// 16384 references of 4096 octets would be 64 MiB; the template is 64 KiB.
	let template = "${a}".repeat(16 * 1024);
	let (out, peak) = peak_bytes(|| env.expand(&template));
	assert_eq!(out.len(), template.len());
	assert!(
		peak < MIB,
		"{peak} octets held for a result of {}",
		out.len()
	);
}

#[test]
fn matching_a_long_text_copies_none_of_it() {
	let text = "a".repeat(32 * MIB);
	let mut env = Env::default();
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "*a*", &mut env));
	assert!(matched);
	assert!(peak < MIB, "{peak} octets held to match 32 MiB");
	assert_eq!(env.get("1").map(str::len), Some(0));
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "a*", &mut Env::default()));
	assert!(matched);
	assert!(peak < MIB, "{peak} octets held for the capture of 32 MiB");
}

#[test]
fn a_text_past_the_budget_is_refused_before_it_is_touched() {
	let text = "a".repeat(64 * MIB);
	let mut env = Env::default();
	let (matched, peak) = peak_bytes(|| spec("matches").test(&text, "*a*", &mut env));
	assert!(!matched);
	assert!(env.exhausted(), "the run is abandoned, not told 'no match'");
	assert!(
		peak < 64 * 1024,
		"{peak} octets held for a text it would not read"
	);
}

#[test]
fn the_other_comparisons_copy_none_of_the_text_either() {
	let text = "A".repeat(32 * MIB);
	for (tag, key) in [("contains", "needle"), ("is", "other")] {
		let (_, peak) = peak_bytes(|| spec(tag).test_simple(&text, key));
		assert!(peak < MIB, ":{tag} held {peak} octets for 32 MiB");
	}
	let digits = "1".repeat(32 * MIB);
	let numeric = match_spec(&[
		Argument::Tag("value".to_string()),
		Argument::Str("gt".to_string()),
		Argument::Tag("comparator".to_string()),
		Argument::Str("i;ascii-numeric".to_string()),
	]);
	let (_, peak) = peak_bytes(|| numeric.test_simple(&digits, "5"));
	assert!(
		peak < MIB,
		"a numeric key held {peak} octets for 32 MiB of digits"
	);
}
