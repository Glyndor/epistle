use super::super::wire::Segment;
use super::*;

fn response(text: &[u8]) -> Response {
	Response {
		segments: vec![Segment {
			text: text.to_vec(),
			literal: None,
		}],
	}
}

#[test]
fn atoms_quoted_and_lists() {
	let r = response(br#"* LIST (\Sent \HasNoChildren) "/" "Sent \"Mail\"""#);
	let tokens = tokenize(&r).expect("tokens");
	assert_eq!(
		tokens,
		vec![
			Token::Atom(b"*"),
			Token::Atom(b"LIST"),
			Token::Open,
			Token::Atom(br"\Sent"),
			Token::Atom(br"\HasNoChildren"),
			Token::Close,
			Token::Quoted(b"/".to_vec()),
			Token::Quoted(br#"Sent "Mail""#.to_vec()),
		]
	);
}

#[test]
fn a_literal_replaces_its_marker() {
	let r = Response {
		segments: vec![
			Segment {
				text: b"* 1 FETCH (BODY[] {3}".to_vec(),
				literal: Some(b"abc".to_vec()),
			},
			Segment {
				text: b")".to_vec(),
				literal: None,
			},
		],
	};
	let tokens = tokenize(&r).expect("tokens");
	assert_eq!(tokens[4], Token::Atom(b"BODY[]"));
	assert_eq!(tokens[5], Token::Literal(b"abc", 0));
	assert_eq!(tokens[6], Token::Close);
}

#[test]
fn unbalanced_or_deep_nesting_is_refused() {
	assert_eq!(tokenize(&response(b"* X (a")), Err(TokenError::Nesting));
	assert_eq!(tokenize(&response(b"* X a)")), Err(TokenError::Nesting));
	let deep = format!(
		"* X {}{}",
		"(".repeat(MAX_DEPTH + 1),
		")".repeat(MAX_DEPTH + 1)
	);
	assert_eq!(
		tokenize(&response(deep.as_bytes())),
		Err(TokenError::Nesting)
	);
	let ok = format!("* X {}{}", "(".repeat(MAX_DEPTH), ")".repeat(MAX_DEPTH));
	assert!(tokenize(&response(ok.as_bytes())).is_ok());
}

#[test]
fn an_unterminated_quote_and_control_bytes_are_refused() {
	assert_eq!(
		tokenize(&response(b"* X \"open")),
		Err(TokenError::Unterminated)
	);
	assert_eq!(
		tokenize(&response(b"* X \x01")),
		Err(TokenError::Unexpected(1))
	);
}

#[test]
fn too_many_tokens_are_refused() {
	let many = format!("* X{}", " a".repeat(MAX_TOKENS + 1));
	assert_eq!(
		tokenize(&response(many.as_bytes())),
		Err(TokenError::TooMany)
	);
	let enough = format!("* X{}", " a".repeat(MAX_TOKENS - 2));
	assert!(tokenize(&response(enough.as_bytes())).is_ok());
}
