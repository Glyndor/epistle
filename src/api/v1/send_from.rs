//! The `From` header `/api/v1/send` writes: the sender address with the
//! person's display name in front of it when there is one.

/// `From:` field value for `address`, with `display_name` as the phrase
/// (RFC 5322 section 3.4). An ASCII name is written as a quoted string; any
/// other name as RFC 2047 encoded-words, which is how a phrase carries text
/// outside ASCII. Without a name the bare address is written, as before.
pub(super) fn from_header(display_name: Option<&str>, address: &str) -> String {
	match display_name {
		None => address.to_string(),
		Some(name) if name.is_ascii() => format!("{} <{address}>", quoted(name)),
		Some(name) => format!("{} <{address}>", crate::util::encoded_word::encode(name)),
	}
}

/// An RFC 5322 quoted-string: `"` and `\` are escaped with a backslash.
fn quoted(name: &str) -> String {
	let mut out = String::with_capacity(name.len() + 2);
	out.push('"');
	for c in name.chars() {
		if c == '"' || c == '\\' {
			out.push('\\');
		}
		out.push(c);
	}
	out.push('"');
	out
}
