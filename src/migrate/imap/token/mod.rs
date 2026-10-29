//! Splitting a server response into IMAP tokens.
//!
//! The tokenizer walks each fragment once, left to right, and yields atoms,
//! quoted strings, literals and parenthesis markers as a flat list. Nesting
//! is tracked as a depth counter capped at [`MAX_DEPTH`] rather than by
//! recursion, so a response full of `(` costs the same as any other.

use super::wire::Response;

/// The deepest parenthesis nesting accepted. The responses the migration
/// reads (LIST, FETCH, NAMESPACE) nest at most four levels.
pub(crate) const MAX_DEPTH: usize = 8;

/// The most tokens one response may produce. A FETCH answer for the items
/// requested has a few dozen; a FLAGS list is capped by the keyword limit.
pub(crate) const MAX_TOKENS: usize = 4096;

/// One token of a response.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Token<'a> {
	/// An atom, a number or `NIL`, as raw bytes.
	Atom(&'a [u8]),
	/// A quoted string, unescaped.
	Quoted(Vec<u8>),
	/// A literal's octets, and the index of the response segment that
	/// carried it, so a caller can take ownership of a large body.
	Literal(&'a [u8], usize),
	/// `(`.
	Open,
	/// `)`.
	Close,
}

impl Token<'_> {
	/// The bytes of a string-like token (atom, quoted or literal).
	pub(crate) fn bytes(&self) -> Option<&[u8]> {
		match self {
			Token::Atom(bytes) | Token::Literal(bytes, _) => Some(bytes),
			Token::Quoted(bytes) => Some(bytes),
			Token::Open | Token::Close => None,
		}
	}

	/// Whether this is the atom `word`, compared without case.
	pub(crate) fn is_atom(&self, word: &str) -> bool {
		matches!(self, Token::Atom(bytes) if bytes.eq_ignore_ascii_case(word.as_bytes()))
	}
}

/// Why a response could not be tokenized.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub(crate) enum TokenError {
	/// A quoted string was not closed on its line.
	#[error("unterminated quoted string")]
	Unterminated,
	/// Parentheses did not balance, or nested deeper than allowed.
	#[error("unbalanced or too deeply nested parentheses")]
	Nesting,
	/// More tokens than [`MAX_TOKENS`].
	#[error("response too long")]
	TooMany,
	/// A byte that cannot start any token.
	#[error("unexpected byte {0:#04x}")]
	Unexpected(u8),
}

/// Tokenize `response`.
pub(crate) fn tokenize(response: &Response) -> Result<Vec<Token<'_>>, TokenError> {
	let mut tokens = Vec::new();
	let mut depth = 0usize;
	for (index, segment) in response.segments.iter().enumerate() {
		let mut text = segment.text.as_slice();
		// The `{N}` that announced the literal is replaced by the literal.
		if let Some(literal) = &segment.literal {
			let start = text.iter().rposition(|&b| b == b'{').unwrap_or(text.len());
			text = &text[..start];
			scan(text, &mut tokens, &mut depth)?;
			tokens.push(Token::Literal(literal, index));
		} else {
			scan(text, &mut tokens, &mut depth)?;
		}
		if tokens.len() > MAX_TOKENS {
			return Err(TokenError::TooMany);
		}
	}
	if depth != 0 {
		return Err(TokenError::Nesting);
	}
	Ok(tokens)
}

/// Scan one fragment's text into `tokens`.
fn scan<'a>(
	text: &'a [u8],
	tokens: &mut Vec<Token<'a>>,
	depth: &mut usize,
) -> Result<(), TokenError> {
	let mut at = 0;
	while at < text.len() {
		if tokens.len() > MAX_TOKENS {
			return Err(TokenError::TooMany);
		}
		match text[at] {
			b' ' => at += 1,
			b'(' => {
				*depth += 1;
				if *depth > MAX_DEPTH {
					return Err(TokenError::Nesting);
				}
				tokens.push(Token::Open);
				at += 1;
			}
			b')' => {
				*depth = depth.checked_sub(1).ok_or(TokenError::Nesting)?;
				tokens.push(Token::Close);
				at += 1;
			}
			b'"' => {
				let (value, next) = quoted(text, at + 1)?;
				tokens.push(Token::Quoted(value));
				at = next;
			}
			byte if byte < 0x20 || byte == 0x7f => return Err(TokenError::Unexpected(byte)),
			_ => {
				let end = text[at..]
					.iter()
					.position(|&b| matches!(b, b' ' | b'(' | b')' | b'"') || b < 0x20)
					.map_or(text.len(), |offset| at + offset);
				tokens.push(Token::Atom(&text[at..end]));
				at = end;
			}
		}
	}
	Ok(())
}

/// The unescaped value of a quoted string starting at `at` (just past the
/// opening quote), and the index just past its closing quote.
fn quoted(text: &[u8], mut at: usize) -> Result<(Vec<u8>, usize), TokenError> {
	let mut value = Vec::new();
	while at < text.len() {
		match text[at] {
			b'"' => return Ok((value, at + 1)),
			b'\\' if at + 1 < text.len() => {
				value.push(text[at + 1]);
				at += 2;
			}
			byte => {
				value.push(byte);
				at += 1;
			}
		}
	}
	Err(TokenError::Unterminated)
}

#[cfg(test)]
mod tests;
