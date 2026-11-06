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

/// The domain a `Message-ID` is stamped with: the domain of the sender address, the way
/// SMTP submission does it, so the identifier names the domain that sent the message.
/// Without a readable domain it is `fallback`, the first hosted domain.
pub(super) fn message_id_domain<'a>(address: &'a str, fallback: &'a str) -> &'a str {
	let Some((_, domain)) = address.rsplit_once('@') else {
		return fallback;
	};
	let readable = !domain.is_empty()
		&& domain.len() <= 253
		&& domain
			.bytes()
			.all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'.')
		&& !domain.starts_with('.')
		&& !domain.ends_with('.');
	if readable { domain } else { fallback }
}

#[cfg(test)]
mod tests {
	use super::message_id_domain;

	#[test]
	fn the_identifier_names_the_domain_of_the_sender() {
		assert_eq!(
			message_id_domain(
				"no-reply.sena@mailservice.codicore.com.co",
				"codicore.com.co"
			),
			"mailservice.codicore.com.co"
		);
	}

	#[test]
	fn an_address_without_a_readable_domain_falls_back_to_the_first_hosted_domain() {
		for address in [
			"nobody",
			"a@",
			"a@.example",
			"a@example.",
			"a@exa mple",
			"a@b>c",
			"a@b@c d",
		] {
			assert_eq!(
				message_id_domain(address, "first.test"),
				"first.test",
				"{address:?}"
			);
		}
	}
}
