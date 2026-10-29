//! The `mailto:` URIs the identification headers carry (RFC 6068), with the
//! address percent-encoded so a character the URI grammar gives a meaning
//! cannot carry that meaning into the field.

/// The characters RFC 6068 leaves alone in a `mailto` address: the unreserved
/// set and the delimiters an address spec may carry. Everything else, `%`
/// and `?` and `&` and `/` included, is percent-encoded.
const MAILTO_TEXT: &percent_encoding::AsciiSet = &percent_encoding::NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~')
	.remove(b'!')
	.remove(b'$')
	.remove(b'\'')
	.remove(b'(')
	.remove(b')')
	.remove(b'*')
	.remove(b'+')
	.remove(b',')
	.remove(b';')
	.remove(b':')
	.remove(b'@');

/// A `mailto:` URI naming `address`, percent-encoded per RFC 6068 so a `?`,
/// an `&` or a `%` in the address cannot read as a query separator.
pub fn uri(address: &str) -> String {
	format!(
		"<mailto:{}>",
		percent_encoding::utf8_percent_encode(address, MAILTO_TEXT)
	)
}

/// The `mailto:` URI a `List-Unsubscribe` carries: `address` with the
/// unsubscribe subject. Nothing on the server answers it.
pub fn unsubscribe(address: &str) -> String {
	format!(
		"<mailto:{}?subject=unsubscribe>",
		percent_encoding::utf8_percent_encode(address, MAILTO_TEXT)
	)
}

#[cfg(test)]
mod tests;
