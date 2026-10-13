//! The TXT values every provider test publishes, so the thirteen providers
//! are held to the same five cases: a short value, an RSA-2048 DKIM key
//! longer than one 255-octet string, a value carrying `"` and `\`, a value
//! the caller already wrapped in quotes, and the publish, list and compare
//! round trip over all of them.

/// A short tagged value that fits in one character-string.
pub(crate) const SHORT: &str = "v=spf1 mx -all";

/// A value with a literal double quote and a literal backslash, untagged so
/// it only ever matches itself. The `&` is there for the XML APIs.
pub(crate) const SPECIAL: &str = r#"verify "a&b" C:\mail\dir"#;

/// SPECIAL in presentation form: the quote and the backslash escaped.
pub(crate) const SPECIAL_PRESENTATION: &str = r#""verify \"a&b\" C:\\mail\\dir""#;

/// The logical value of an RSA-2048 DKIM record: 410 octets, so it needs two
/// character-strings (255 and 155). The key is the shape of a real
/// SubjectPublicKeyInfo in base64, deterministic so failures are readable.
pub(crate) fn dkim_rsa2048() -> String {
	let prefix = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA";
	let mut key = String::from(prefix);
	let alphabet = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
	let mut i = 0usize;
	while key.len() < 384 {
		key.push(char::from(alphabet[(i * 7 + 3) % alphabet.len()]));
		i += 1;
	}
	key.push_str("IDAQAB");
	key.push_str("==");
	let value = format!("v=DKIM1; k=rsa; p={key}");
	assert!(value.len() > 300, "the DKIM fixture must need two strings");
	value
}

/// The DKIM value in presentation form: two quoted strings, one space apart.
pub(crate) fn dkim_rsa2048_presentation() -> String {
	let value = dkim_rsa2048();
	format!("\"{}\" \"{}\"", &value[..255], &value[255..])
}

/// A value the caller wrapped in quotes itself. Every provider must publish
/// the same bytes as for the unquoted value, never `""...""`.
pub(crate) const CALLER_QUOTED: &str = "\"v=DMARC1; p=quarantine; adkim=s\"";

/// CALLER_QUOTED without the caller's quotes.
pub(crate) const CALLER_QUOTED_LOGICAL: &str = "v=DMARC1; p=quarantine; adkim=s";

/// Every fixture paired with its logical value, for round-trip loops.
pub(crate) fn all() -> Vec<(String, String)> {
	vec![
		(SHORT.to_string(), SHORT.to_string()),
		(dkim_rsa2048(), dkim_rsa2048()),
		(SPECIAL.to_string(), SPECIAL.to_string()),
		(CALLER_QUOTED.to_string(), CALLER_QUOTED_LOGICAL.to_string()),
	]
}

/// An untagged TXT that shares a name with epistle's own record, the way
/// an ACME challenge or a site verification token does. Replacing a record
/// of another purpose at that name must leave it alone.
pub(crate) const SIBLING: &str = "token-sibling";

/// A DKIM record about to be rotated out.
pub(crate) const OLD_DKIM: &str = "v=DKIM1; k=rsa; p=OLDKEY";

/// The DKIM record that replaces [`OLD_DKIM`].
pub(crate) const NEW_DKIM: &str = "v=DKIM1; k=rsa; p=NEWKEY";
