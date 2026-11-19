//! The display name of a mailbox written as an RFC 5322 phrase, shared by
//! every path that writes an address header (`POST /api/v1/send` and JMAP
//! `Email/set`) so both put the same bytes on the wire for the same name.

/// `name <address>` for `address` with `display_name` as the phrase (RFC 5322
/// section 3.4). A name made of atoms and spaces is written as is; any other
/// ASCII name as a quoted string, where `"` and `\` are escaped with a
/// backslash; a name with text outside ASCII as RFC 2047 encoded-words, which
/// is how a phrase carries it. Without a name the bare address is written.
///
/// The caller has already refused control characters and line breaks: this
/// writes the name it is given and never alters it.
pub fn mailbox(display_name: Option<&str>, address: &str) -> String {
	match display_name {
		None => address.to_string(),
		Some(name) => format!("{} <{address}>", phrase(name)),
	}
}

fn phrase(name: &str) -> String {
	if !name.is_ascii() {
		return crate::util::encoded_word::encode(name);
	}
	let atoms = name
		.bytes()
		.all(|b| b == b' ' || crate::util::validation::is_atext_byte(b));
	if atoms {
		return name.to_string();
	}
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
