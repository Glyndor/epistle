//! Tests for the Sieve parser.

use super::ast::{Argument, Command};
use super::lexer::tokenize;
use super::parser::{ParseError, parse};

fn parse_str(script: &str) -> Result<Vec<Command>, ParseError> {
	let tokens = tokenize(script).expect("lexes");
	parse(&tokens)
}

#[test]
fn rejects_deeply_nested_block_with_nesting_error() {
	// 10 000 nested `if true {` openings without a closing brace.
	// The lexer is happy (no token surprises); the parser must reject
	// with a NestingDepth (or similar) error before overflowing the
	// stack.
	let mut script = String::new();
	for _ in 0..10_000 {
		script.push_str("if true {");
	}
	let err = parse_str(&script).expect_err("deep nesting must be rejected");
	let rendered = format!("{err:?}");
	assert!(
		rendered.contains("NestingDepth") || rendered.contains("nesting"),
		"the error must mention nesting, got: {rendered}"
	);
}

#[test]
#[allow(clippy::single_char_add_str)]
fn modest_nesting_still_parses() {
	// 32 nested `if true {` blocks is well below the limit; the parser
	// must accept it.
	let mut script = String::new();
	for _ in 0..32 {
		script.push_str("if true {");
	}
	for _ in 0..32 {
		script.push_str("}");
	}
	parse_str(&script).expect("32-deep nesting must parse");
}

#[test]
fn parses_require_and_actions() {
	let commands = parse_str("require [\"fileinto\"];\nfileinto \"Junk\";\nkeep;").expect("ok");
	assert_eq!(commands.len(), 3);
	assert_eq!(
		commands[0],
		Command::Action {
			name: "require".into(),
			args: vec![Argument::StrList(vec!["fileinto".into()])],
		}
	);
	assert_eq!(
		commands[1],
		Command::Action {
			name: "fileinto".into(),
			args: vec![Argument::Str("Junk".into())],
		}
	);
	assert_eq!(
		commands[2],
		Command::Action {
			name: "keep".into(),
			args: vec![],
		}
	);
}

#[test]
fn parses_if_with_test_and_block() {
	let commands = parse_str("if header :contains \"Subject\" \"sale\" { discard; }").expect("ok");
	let Command::If(conditional) = &commands[0] else {
		panic!("expected if");
	};
	assert_eq!(conditional.branches.len(), 1);
	let branch = &conditional.branches[0];
	assert_eq!(branch.test.name, "header");
	assert_eq!(
		branch.test.args,
		vec![
			Argument::Tag("contains".into()),
			Argument::Str("Subject".into()),
			Argument::Str("sale".into()),
		]
	);
	assert_eq!(branch.body.len(), 1);
	assert!(conditional.otherwise.is_none());
}

#[test]
fn parses_elsif_and_else() {
	let script = "if size :over 1M { discard; } elsif true { keep; } else { fileinto \"X\"; }";
	let commands = parse_str(script).expect("ok");
	let Command::If(conditional) = &commands[0] else {
		panic!("expected if");
	};
	assert_eq!(conditional.branches.len(), 2);
	assert_eq!(conditional.branches[1].test.name, "true");
	assert!(conditional.otherwise.is_some());
}

#[test]
fn parses_allof_and_not_tests() {
	let script = "if allof (not exists [\"To\"], header :is \"X\" \"y\") { stop; }";
	let commands = parse_str(script).expect("ok");
	let Command::If(conditional) = &commands[0] else {
		panic!("expected if");
	};
	let test = &conditional.branches[0].test;
	assert_eq!(test.name, "allof");
	assert_eq!(test.children.len(), 2);
	assert_eq!(test.children[0].name, "not");
	assert_eq!(test.children[0].children[0].name, "exists");
	assert_eq!(test.children[1].name, "header");
}

#[test]
fn nested_blocks_parse() {
	let script = "if true { if false { keep; } discard; }";
	let commands = parse_str(script).expect("ok");
	let Command::If(outer) = &commands[0] else {
		panic!("expected if");
	};
	assert_eq!(outer.branches[0].body.len(), 2);
	assert!(matches!(outer.branches[0].body[0], Command::If(_)));
}

#[test]
fn missing_semicolon_is_an_error() {
	assert!(matches!(
		parse_str("keep"),
		Err(ParseError::UnexpectedEof | ParseError::Expected(_))
	));
}

#[test]
fn unclosed_block_is_an_error() {
	assert!(parse_str("if true { keep;").is_err());
}

#[test]
fn trailing_garbage_is_rejected() {
	// A bare closing brace with no matching block.
	assert!(parse_str("keep; }").is_err());
}
