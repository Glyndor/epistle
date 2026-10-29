	use super::*;

	#[test]
	fn tokenizes_a_simple_rule() {
		let tokens = tokenize("if header :contains \"Subject\" \"sale\" { discard; }").expect("ok");
		assert_eq!(
			tokens,
			vec![
				Token::Identifier("if".into()),
				Token::Identifier("header".into()),
				Token::Tag("contains".into()),
				Token::QuotedString("Subject".into()),
				Token::QuotedString("sale".into()),
				Token::BraceOpen,
				Token::Identifier("discard".into()),
				Token::Semicolon,
				Token::BraceClose,
			]
		);
	}

	#[test]
	fn skips_hash_and_block_comments() {
		let tokens = tokenize("# lead\nkeep; /* mid */ stop;").expect("ok");
		assert_eq!(
			tokens,
			vec![
				Token::Identifier("keep".into()),
				Token::Semicolon,
				Token::Identifier("stop".into()),
				Token::Semicolon,
			]
		);
	}

	#[test]
	fn numbers_apply_quantifiers() {
		assert_eq!(tokenize("1").unwrap(), vec![Token::Number(1)]);
		assert_eq!(tokenize("1K").unwrap(), vec![Token::Number(1024)]);
		assert_eq!(
			tokenize("2M").unwrap(),
			vec![Token::Number(2 * 1024 * 1024)]
		);
		assert_eq!(
			tokenize("3G").unwrap(),
			vec![Token::Number(3 * 1024 * 1024 * 1024)]
		);
	}

	#[test]
	fn quoted_string_resolves_escapes() {
		assert_eq!(
			tokenize(r#""a\"b\\c""#).unwrap(),
			vec![Token::QuotedString("a\"b\\c".into())]
		);
	}

	#[test]
	fn lists_and_punctuation() {
		let tokens = tokenize(r#"["a", "b"]"#).unwrap();
		assert_eq!(
			tokens,
			vec![
				Token::BracketOpen,
				Token::QuotedString("a".into()),
				Token::Comma,
				Token::QuotedString("b".into()),
				Token::BracketClose,
			]
		);
	}

	#[test]
	fn multiline_string_collects_until_dot() {
		let script = "require \"reject\";\nif true { reject text:\nGo away\n..stuffed\n.\n; }";
		let tokens = tokenize(script).expect("ok");
		let multi = tokens
			.iter()
			.find_map(|t| match t {
				Token::MultiLine(s) => Some(s.clone()),
				_ => None,
			})
			.expect("multiline");
		assert_eq!(multi, "Go away\r\n.stuffed");
	}

	#[test]
	fn errors_on_unterminated_string_and_comment() {
		assert_eq!(tokenize("\"oops"), Err(LexError::Unterminated));
		assert_eq!(tokenize("/* oops"), Err(LexError::Unterminated));
	}

	#[test]
	fn errors_on_unexpected_character() {
		assert_eq!(tokenize("@"), Err(LexError::Unexpected('@')));
	}
