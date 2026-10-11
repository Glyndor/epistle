//! Runtime credentials for unit and integration tests.

use ring::rand::{SystemRandom, generate};
use std::sync::LazyLock;

/// Draw fresh bytes directly from the operating system CSPRNG.
pub(crate) fn bytes<const N: usize>() -> [u8; N] {
	generate::<[u8; N]>(&SystemRandom::new())
		.expect("fixture entropy")
		.expose()
}

/// Generate a printable credential suitable for password and token protocols.
pub(crate) fn fresh_secret() -> String {
	use base64::Engine;
	base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(bytes::<32>())
}

/// The account password shared by both sides of a test exchange.
pub(crate) fn password() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}

/// A distinct credential for rejected authentication attempts or a second account.
pub(crate) fn second_password() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}

/// The management API bearer token shared by its test clients and server.
pub(crate) fn api_token() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}

/// A separate API key for tests that also configure a management token.
pub(crate) fn api_key() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}

/// A reproducible salt within a test process, generated anew for every run.
pub(crate) fn salt() -> &'static [u8; 16] {
	static VALUE: LazyLock<[u8; 16]> = LazyLock::new(bytes);
	&VALUE
}

/// A SCRAM server nonce shared with the client proof builder in the same process.
pub(crate) fn nonce() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}

/// A third credential for tests that distinguish two accounts from a rejected password.
pub(crate) fn wrong_password() -> &'static str {
	static VALUE: LazyLock<String> = LazyLock::new(fresh_secret);
	VALUE.as_str()
}
