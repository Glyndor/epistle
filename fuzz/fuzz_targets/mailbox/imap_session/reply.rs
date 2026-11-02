//! The framing of what the session writes: lines that end in CRLF and hold no
//! other CR or LF, and literals whose announced size is the size that
//! follows. A reply that breaks either makes the client read the next bytes
//! as something else, which is how one response smuggles another.

/// The response lines of one output, each with its literals cut out, so a
/// line can be read by its first word.
pub fn lines(wire: &[u8]) -> Vec<String> {
	let mut out = Vec::new();
	let mut at = 0;
	let mut current = Vec::new();
	while at < wire.len() {
		let Some(end) = wire[at..].windows(2).position(|w| w == b"\r\n") else {
			panic!(
				"output ends without CRLF: {:?}",
				String::from_utf8_lossy(wire)
			);
		};
		let piece = &wire[at..at + end];
		assert!(
			!piece.iter().any(|b| *b == b'\r' || *b == b'\n'),
			"a bare CR or LF inside a response line: {:?}",
			String::from_utf8_lossy(piece)
		);
		current.extend_from_slice(piece);
		at += end + 2;
		match literal_size(piece) {
			Some(size) => {
				assert!(
					at + size <= wire.len(),
					"a literal announces {size} octets and fewer follow"
				);
				at += size;
				// The line goes on after the literal, up to its own CRLF.
				current.extend_from_slice(b" <literal>");
			}
			None => {
				let line = String::from_utf8_lossy(&std::mem::take(&mut current)).into_owned();
				assert!(balanced(&line), "unbalanced parentheses: {line:?}");
				out.push(line);
			}
		}
	}
	assert!(current.is_empty(), "output ends inside a literal");
	out
}

/// Whether the parentheses of a FETCH, STATUS or METADATA response close,
/// outside quoted strings. A literal that announces more than it carries
/// swallows the `)` after it, and the line still ends in CRLF: this is where
/// that shows. Other responses end in free text, which may hold anything.
fn balanced(line: &str) -> bool {
	let words: Vec<&str> = line.splitn(4, ' ').collect();
	let structured = matches!(words.as_slice(), ["*", "STATUS" | "METADATA", ..])
		|| matches!(words.as_slice(), ["*", _, "FETCH", ..]);
	if !structured {
		return true;
	}
	let (mut depth, mut quoted, mut escaped) = (0i64, false, false);
	for c in line.chars() {
		match (quoted, escaped, c) {
			(true, true, _) => escaped = false,
			(true, false, '\\') => escaped = true,
			(true, false, '"') => quoted = false,
			(false, _, '"') => quoted = true,
			(false, _, '(') => depth += 1,
			(false, _, ')') => {
				depth -= 1;
				if depth < 0 {
					return false;
				}
			}
			_ => {}
		}
	}
	depth == 0 && !quoted
}

/// The size of the literal `{n}` or `~{n}` a line ends with.
fn literal_size(piece: &[u8]) -> Option<usize> {
	let open = piece.iter().rposition(|b| *b == b'{')?;
	let inner = piece.strip_suffix(b"}")?.get(open + 1..)?;
	if inner.is_empty() || !inner.iter().all(u8::is_ascii_digit) {
		return None;
	}
	std::str::from_utf8(inner).ok()?.parse().ok()
}

/// The status of a tagged completion line for `tag`, if `line` is one.
pub fn status<'a>(line: &'a str, tag: &str) -> Option<&'a str> {
	let rest = line.strip_prefix(tag)?.strip_prefix(' ')?;
	let word = rest.split(' ').next()?;
	matches!(word, "OK" | "NO" | "BAD").then_some(word)
}
