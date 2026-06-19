//! Sieve lexer (RFC 5228 §8.1): turn a script into tokens.
//!
//! Handles hash and bracketed comments, whitespace, identifiers, tags
//! (`:name`), numbers with `K`/`M`/`G` quantifiers, quoted strings with
//! backslash escapes, multi-line strings (`text:` … `.`), and the structural
//! punctuation.

/// A lexical token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Token {
	/// A bare identifier such as `if`, `fileinto`, `header`.
	Identifier(String),
	/// A tagged argument such as `:contains`.
	Tag(String),
	/// A number, with any `K`/`M`/`G` quantifier already applied.
	Number(u64),
	/// A quoted string with escapes resolved.
	QuotedString(String),
	/// A multi-line string (`text:` … `.`), dot-unstuffed.
	MultiLine(String),
	BracketOpen,
	BracketClose,
	ParenOpen,
	ParenClose,
	BraceOpen,
	BraceClose,
	Comma,
	Semicolon,
}

/// Why a script could not be tokenized.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LexError {
	/// A `/*` comment or a `"` string was never closed.
	Unterminated,
	/// A number was too large or its quantifier invalid.
	BadNumber,
	/// A character that cannot start any token.
	Unexpected(char),
}

/// Tokenize a Sieve script.
pub fn tokenize(input: &str) -> Result<Vec<Token>, LexError> {
	let chars: Vec<char> = input.chars().collect();
	let mut pos = 0;
	let mut tokens = Vec::new();

	while pos < chars.len() {
		let c = chars[pos];
		match c {
			' ' | '\t' | '\r' | '\n' => pos += 1,
			'#' => {
				// Hash comment to end of line.
				while pos < chars.len() && chars[pos] != '\n' {
					pos += 1;
				}
			}
			'/' if chars.get(pos + 1) == Some(&'*') => {
				pos += 2;
				loop {
					if pos + 1 >= chars.len() {
						return Err(LexError::Unterminated);
					}
					if chars[pos] == '*' && chars[pos + 1] == '/' {
						pos += 2;
						break;
					}
					pos += 1;
				}
			}
			'[' => push(&mut tokens, Token::BracketOpen, &mut pos),
			']' => push(&mut tokens, Token::BracketClose, &mut pos),
			'(' => push(&mut tokens, Token::ParenOpen, &mut pos),
			')' => push(&mut tokens, Token::ParenClose, &mut pos),
			'{' => push(&mut tokens, Token::BraceOpen, &mut pos),
			'}' => push(&mut tokens, Token::BraceClose, &mut pos),
			',' => push(&mut tokens, Token::Comma, &mut pos),
			';' => push(&mut tokens, Token::Semicolon, &mut pos),
			'"' => tokens.push(lex_quoted(&chars, &mut pos)?),
			':' => tokens.push(lex_tag(&chars, &mut pos)),
			c if c.is_ascii_digit() => tokens.push(lex_number(&chars, &mut pos)?),
			c if is_identifier_start(c) => {
				let ident = lex_identifier(&chars, &mut pos);
				// `text:` introduces a multi-line string.
				if ident == "text" && chars.get(pos) == Some(&':') {
					pos += 1;
					tokens.push(lex_multiline(&chars, &mut pos)?);
				} else {
					tokens.push(Token::Identifier(ident));
				}
			}
			other => return Err(LexError::Unexpected(other)),
		}
	}
	Ok(tokens)
}

fn push(tokens: &mut Vec<Token>, token: Token, pos: &mut usize) {
	tokens.push(token);
	*pos += 1;
}

fn is_identifier_start(c: char) -> bool {
	c.is_ascii_alphabetic() || c == '_'
}

fn is_identifier_char(c: char) -> bool {
	c.is_ascii_alphanumeric() || c == '_'
}

fn lex_identifier(chars: &[char], pos: &mut usize) -> String {
	let start = *pos;
	while *pos < chars.len() && is_identifier_char(chars[*pos]) {
		*pos += 1;
	}
	chars[start..*pos].iter().collect()
}

fn lex_tag(chars: &[char], pos: &mut usize) -> Token {
	*pos += 1; // skip ':'
	Token::Tag(lex_identifier(chars, pos))
}

fn lex_number(chars: &[char], pos: &mut usize) -> Result<Token, LexError> {
	let start = *pos;
	while *pos < chars.len() && chars[*pos].is_ascii_digit() {
		*pos += 1;
	}
	let digits: String = chars[start..*pos].iter().collect();
	let mut value: u64 = digits.parse().map_err(|_| LexError::BadNumber)?;
	// Optional quantifier.
	match chars.get(*pos) {
		Some('K' | 'k') => {
			value = value.checked_mul(1024).ok_or(LexError::BadNumber)?;
			*pos += 1;
		}
		Some('M' | 'm') => {
			value = value.checked_mul(1024 * 1024).ok_or(LexError::BadNumber)?;
			*pos += 1;
		}
		Some('G' | 'g') => {
			value = value
				.checked_mul(1024 * 1024 * 1024)
				.ok_or(LexError::BadNumber)?;
			*pos += 1;
		}
		_ => {}
	}
	Ok(Token::Number(value))
}

fn lex_quoted(chars: &[char], pos: &mut usize) -> Result<Token, LexError> {
	*pos += 1; // skip opening quote
	let mut value = String::new();
	while *pos < chars.len() {
		match chars[*pos] {
			'"' => {
				*pos += 1;
				return Ok(Token::QuotedString(value));
			}
			'\\' => {
				// A backslash quotes the next character literally.
				*pos += 1;
				if *pos >= chars.len() {
					return Err(LexError::Unterminated);
				}
				value.push(chars[*pos]);
				*pos += 1;
			}
			other => {
				value.push(other);
				*pos += 1;
			}
		}
	}
	Err(LexError::Unterminated)
}

/// Lex a multi-line string after `text:`: skip to end of line, then collect
/// lines until one containing only `.`, undoing dot-stuffing.
fn lex_multiline(chars: &[char], pos: &mut usize) -> Result<Token, LexError> {
	// Skip an optional hash comment and the rest of the introducing line.
	while *pos < chars.len() && chars[*pos] != '\n' {
		*pos += 1;
	}
	if *pos < chars.len() {
		*pos += 1; // consume the newline
	}

	let mut lines = Vec::new();
	loop {
		let start = *pos;
		while *pos < chars.len() && chars[*pos] != '\n' {
			*pos += 1;
		}
		let mut line: String = chars[start..*pos].iter().collect();
		if line.ends_with('\r') {
			line.pop();
		}
		if *pos < chars.len() {
			*pos += 1; // consume newline
		} else if start == *pos {
			// End of input without a terminating dot.
			return Err(LexError::Unterminated);
		}
		if line == "." {
			break;
		}
		// Undo dot-stuffing: a leading ".." becomes ".".
		if let Some(rest) = line.strip_prefix("..") {
			line = format!(".{rest}");
		}
		lines.push(line);
	}
	Ok(Token::MultiLine(lines.join("\r\n")))
}

#[cfg(test)]
mod tests {
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
}
