//! The set of `:contains` keys must answer as one pass per key does, and cost
//! the run one pass over the text however many keys there are.

use super::super::ast::Argument;
use super::super::compare::match_spec;
use super::super::env::Env;
use super::Keys;

fn spec(tags: &[&str]) -> super::MatchSpec {
	let mut args = vec![Argument::Tag("contains".to_string())];
	if tags.contains(&"octet") {
		args.push(Argument::Tag("comparator".to_string()));
		args.push(Argument::Str("i;octet".to_string()));
	}
	match_spec(&args)
}

fn words(count: usize) -> Vec<String> {
	(0..count).map(|n| format!("word{n}x")).collect()
}

/// Whether the set and the key-by-key test agree about `text`.
fn agree(spec: &super::MatchSpec, keys: &[String], text: &str) -> bool {
	let mut env = Env::default();
	let set = Keys::new(spec, keys, &mut env).any(spec, text, &mut env);
	let each = keys.iter().any(|key| spec.test_simple(text, key));
	assert!(!env.exhausted());
	assert_eq!(set, each, "{keys:?} in {text:?}");
	set
}

#[test]
fn a_key_is_found_wherever_it_is_and_whatever_its_case() {
	let keys = words(500);
	let default = spec(&[]);
	assert!(agree(&default, &keys, "xx WORD499X yy"));
	assert!(agree(&default, &keys, "word0x"));
	assert!(agree(&default, &keys, "wor word7x"));
	assert!(!agree(&default, &keys, "word500x word 12 wor wordx"));
	assert!(!agree(&default, &keys, ""));
	// Octet comparison is exact.
	let octet = spec(&["octet"]);
	assert!(!agree(&octet, &keys, "WORD3X"));
	assert!(agree(&octet, &keys, "a word3x b"));
}

#[test]
fn keys_that_overlap_and_share_prefixes_are_found() {
	let keys: Vec<String> = [
		"she", "he", "hers", "his", "ushers", "aab", "abab", "bab", "ab",
	]
	.iter()
	.map(ToString::to_string)
	.collect();
	let default = spec(&[]);
	for text in [
		"ushers", "xhe", "hi", "aaab", "ababab", "baa", "s", "hershe", "xxxx", "uhhh", "aaa",
	] {
		agree(&default, &keys, text);
	}
}

#[test]
fn an_empty_key_is_in_every_text() {
	let mut keys = words(20);
	keys.push(String::new());
	assert!(agree(&spec(&[]), &keys, ""));
	assert!(agree(&spec(&[]), &keys, "anything"));
}

#[test]
fn random_keys_and_texts_agree_with_one_pass_per_key() {
	// A small alphabet makes overlaps and fallbacks common.
	let mut seed = 0x2545_f491_4f6c_dd1du64;
	let mut next = move |bound: u64| {
		seed ^= seed << 13;
		seed ^= seed >> 7;
		seed ^= seed << 17;
		seed % bound
	};
	let letter = |n: u64| char::from(b"abAB"[n as usize]);
	for round in 0..300 {
		let keys: Vec<String> = (0..8 + next(8))
			.map(|_| (0..1 + next(5)).map(|_| letter(next(4))).collect())
			.collect();
		let text: String = (0..next(60)).map(|_| letter(next(4))).collect();
		for tags in [&[][..], &["octet"][..]] {
			let spec = spec(tags);
			agree(&spec, &keys, &text);
			let _ = round;
		}
	}
}

#[test]
fn a_list_of_keys_is_charged_one_pass_over_the_text() {
	let text = "x".repeat(1 << 20);
	let keys = words(1100);
	let default = spec(&[]);
	let mut env = Env::default();
	let started = env.remaining_work();
	let set = Keys::new(&default, &keys, &mut env);
	assert!(!set.any(&default, &text, &mut env));
	let spent = started - env.remaining_work();
	assert!(!env.exhausted());
	assert!(
		spent < 2 * (1 << 20),
		"{spent} units for 1100 keys over 1 MiB, one pass is 1 MiB"
	);
}

#[test]
fn a_few_keys_are_still_tried_one_by_one() {
	let keys = words(3);
	let default = spec(&[]);
	assert!(agree(&default, &keys, "a word2x b"));
}
