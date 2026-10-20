use super::*;
use serde_json::json;

fn read(text: &str) -> Value {
	parse(text).expect("the subset reads")
}

fn refused(text: &str) -> String {
	parse(text).expect_err("the subset refuses it")
}

#[test]
fn reads_mappings_sequences_and_scalar_types() {
	let doc = read(
		"# a comment\n\
		 a: 1\n\
		 b: -2\n\
		 c: 0.5\n\
		 d: true\n\
		 e: null\n\
		 f: text with spaces\n\
		 g: https://example.org/x\n\
		 list:\n\
		 \x20 - one\n\
		 \x20 - 2\n\
		 \x20 - key: value\n\
		 \x20   other: 3\n\
		 nested:\n\
		 \x20 inner:\n\
		 \x20   leaf: ok\n",
	);
	assert_eq!(
		doc,
		json!({
			"a": 1, "b": -2, "c": 0.5, "d": true, "e": null,
			"f": "text with spaces", "g": "https://example.org/x",
			"list": ["one", 2, {"key": "value", "other": 3}],
			"nested": {"inner": {"leaf": "ok"}},
		})
	);
}

#[test]
fn a_key_without_a_value_is_null_and_keys_are_always_strings() {
	let doc = read("\"200\":\n  description: ok\n404:\nx: 1\n");
	assert_eq!(
		doc,
		json!({"200": {"description": "ok"}, "404": null, "x": 1})
	);
}

#[test]
fn reads_quoted_scalars_and_their_escapes() {
	let doc = read(
		"a: \"quote \\\" slash \\\\ tab \\t nl \\n é \\u00e9\"\nb: 'it''s'\nc: \"#/components/x\"\nd: \"1.0\"\n",
	);
	assert_eq!(doc["a"], "quote \" slash \\ tab \t nl \n é é");
	assert_eq!(doc["b"], "it's");
	assert_eq!(doc["c"], "#/components/x");
	assert_eq!(doc["d"], "1.0");
}

#[test]
fn reads_the_four_block_scalars() {
	let doc = read(
		"lit: |\n  one\n    two\n\n  three\nstrip: |-\n  x\n  y\nfold: >\n  a\n  b\n\n  c\nfoldstrip: >-\n  a\n  b\nlast: end\n",
	);
	assert_eq!(doc["lit"], "one\n  two\n\nthree\n");
	assert_eq!(doc["strip"], "x\ny");
	assert_eq!(doc["fold"], "a b\nc\n");
	assert_eq!(doc["foldstrip"], "a b");
	assert_eq!(doc["last"], "end");
}

#[test]
fn reads_empty_and_scalar_flow_collections() {
	let doc = read("a: []\nb: {}\nc: [x, \"y, z\", 3]\n");
	assert_eq!(doc, json!({"a": [], "b": {}, "c": ["x", "y, z", 3]}));
}

#[test]
fn a_mapping_in_a_sequence_may_carry_a_block_scalar() {
	let doc = read("- name: one\n  text: |\n    first\n    second\n- name: two\n");
	assert_eq!(
		doc,
		json!([{"name": "one", "text": "first\nsecond\n"}, {"name": "two"}])
	);
}

#[test]
fn refuses_what_the_subset_does_not_read() {
	for (text, why) in [
		("a: 1\na: 2\n", "duplicate key"),
		("a: &anchor 1\n", "must be quoted"),
		("a: !!str 1\n", "must be quoted"),
		("a: value # trailing\n", "must be quoted"),
		("a: one: two\n", "must be quoted"),
		("a: yes\n", "YAML 1.1"),
		("a: 1e3\n", "not a plain number"),
		("a: 0x1F\n", "not a plain number"),
		("a: 3.1.0\n", "not a plain number"),
		("a: .5\n", "not a plain number"),
		("a: 007\n", "not a plain number"),
		("a: { b: 1 }\n", "must be quoted"),
		("a:\n- x\n", "sequence item inside a mapping"),
		("a:\n\tb: 1\n", "tabs"),
		("a: \"open\n", "not closed"),
		("a: \"x\" y\n", "after a quoted"),
		("a: [x\n", "close on its line"),
		("- - x\n", "nested sequence"),
		("a: 1\n  b: 2\n", "indentation"),
		("a: |\n", "no content"),
		("a: >\n  x\n    y\n", "more-indented"),
		("a: \"\\x\"\n", "escape"),
	] {
		let message = refused(text);
		assert!(message.contains(why), "{text:?} gave {message:?}");
	}
}

#[test]
fn names_the_line_it_stopped_at() {
	assert!(refused("a: 1\nb: yes\n").starts_with("line 2:"));
	assert!(refused("").contains("empty"));
}

#[test]
fn a_non_ascii_space_in_the_indentation_is_an_error_not_a_panic() {
	for text in [
		"a: |\n  x\n \u{a0}y\n",
		"a:\n\u{a0}b: 1\n",
		"\u{2003}a: 1\n",
	] {
		let message = refused(text);
		assert!(message.contains("only spaces"), "{text:?} gave {message:?}");
	}
}
