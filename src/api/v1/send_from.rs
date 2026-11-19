//! The `From` header `/api/v1/send` writes: the sender address with the
//! person's display name in front of it when there is one.

/// `From:` field value for `address`, with `display_name` as the phrase
/// (RFC 5322 section 3.4), written the way every address header is.
pub(super) fn from_header(display_name: Option<&str>, address: &str) -> String {
	crate::compose::mailbox(display_name, address)
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
