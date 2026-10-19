//! Fold at DKIM grammar boundaries, before canonicalizing the signature field.

struct Value {
	text: String,
	column: usize,
}

impl Value {
	fn new() -> Self {
		Self {
			text: String::new(),
			column: "DKIM-Signature:".len(),
		}
	}

	/// `space` separates tags; names and base64 chunks need no separator unless folded.
	fn push(&mut self, token: &str, space: bool) -> Option<()> {
		if self.column + usize::from(space) + token.len() > 78 {
			self.text.push_str("\r\n\t");
			self.column = 1;
		} else if space {
			self.text.push(' ');
			self.column += 1;
		}
		// A domain, selector or field name cannot be split internally.
		if self.column + token.len() > 998 {
			return None;
		}
		self.text.push_str(token);
		self.column += token.len();
		Some(())
	}
}

pub(super) fn unsigned(
	algorithm: &str,
	selector: &str,
	domain: &str,
	names: &str,
	body_hash: &str,
) -> Option<String> {
	let mut value = Value::new();
	for tag in [
		"v=1;",
		&format!("a={algorithm};"),
		"c=relaxed/relaxed;",
		&format!("d={domain};"),
		&format!("s={selector};"),
		"h=",
	] {
		value.push(tag, true)?;
	}
	// RFC 6376 section 3.5 permits FWS beside ':' and after 'h=', not inside names.
	let mut names = names.split(':').peekable();
	while let Some(name) = names.next() {
		let separator = if names.peek().is_some() { ':' } else { ';' };
		value.push(&format!("{name}{separator}"), false)?;
	}
	value.push(&format!("bh={body_hash};"), true)?;
	value.push("b=", true)?;
	Some(value.text)
}

pub(super) fn finish(value: String, signature: &str) -> Option<String> {
	let column = value
		.rsplit_once("\r\n")
		.map_or("DKIM-Signature:".len() + value.len(), |(_, tail)| {
			tail.len()
		});
	let mut value = Value {
		text: value,
		column,
	};
	// FWS anywhere in b= is removed with that value when verifying (section 3.7).
	for chunk in signature.as_bytes().chunks(64) {
		value.push(std::str::from_utf8(chunk).expect("base64 is ASCII"), false)?;
	}
	Some(format!("DKIM-Signature:{}\r\n", value.text))
}
