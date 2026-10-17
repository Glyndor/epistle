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

/// A uniformly distributed value in `0..limit` from the OS CSPRNG. Rejection
/// sampling keeps every value equally likely, so a test that draws characters
/// from a class does not favour the low end of it.
fn below(limit: u32) -> u32 {
	let ceiling = u32::MAX - u32::MAX % limit;
	loop {
		let draw = u32::from_le_bytes(bytes::<4>());
		if draw < ceiling {
			return draw % limit;
		}
	}
}

/// A random printable ASCII character, U+0020 through U+007E.
pub(crate) fn printable_ascii_char() -> char {
	char::from(u8::try_from(0x20 + below(0x5F)).expect("0x20..=0x7E fits in a byte"))
}

/// A random string of exactly `len` printable ASCII characters. The odds of it
/// equalling a common or breached password are nil, so it is acceptable to any
/// policy that only looks at length and character set.
pub(crate) fn printable_ascii(len: usize) -> String {
	(0..len).map(|_| printable_ascii_char()).collect()
}

/// A random character outside ASCII: a Latin-1 supplement letter (two bytes in
/// UTF-8) or an emoji from the Miscellaneous Symbols and Pictographs block
/// (four bytes).
pub(crate) fn non_ascii_char() -> char {
	if below(2) == 0 {
		char::from(u8::try_from(0xC0 + below(0x40)).expect("0xC0..=0xFF fits in a byte"))
	} else {
		char::from_u32(0x1F300 + below(0x100)).expect("the pictograph block holds valid scalars")
	}
}

/// Every ASCII control character: U+0000 through U+001F, and U+007F.
pub(crate) fn control_chars() -> Vec<char> {
	(0..=0x7F_u8)
		.map(char::from)
		.filter(char::is_ascii_control)
		.collect()
}

/// `len` characters of printable ASCII with exactly one `odd` character at a
/// random position, so a check that scans the whole string is exercised at the
/// start, the middle and the end over repeated runs.
pub(crate) fn printable_ascii_with(odd: char, len: usize) -> String {
	assert!(len >= 1, "the odd character needs a slot");
	let before = usize::try_from(below(u32::try_from(len).expect("short test length")))
		.expect("index fits usize");
	let mut text = printable_ascii(before);
	text.push(odd);
	text.push_str(&printable_ascii(len - before - 1));
	text
}

/// A loopback port a test can hand to a server that binds it by itself.
///
/// Binding port 0 and dropping the socket gives the number back to the
/// kernel, and a listener another test opens on port 0 in the meantime can be
/// given the same number: the test then talks to somebody else's server (a TLS
/// listener answered a plain HTTP request with an alert). These ports come
/// from a range below the one the kernel hands out for port 0, each at most
/// once in the process, so the only way to meet one is to be given it here.
pub(crate) fn free_port() -> u16 {
	use std::sync::atomic::{AtomicU16, Ordering};
	/// Below the ephemeral range (`ip_local_port_range` starts at 32768).
	const FIRST: u16 = 20_000;
	const LAST: u16 = 29_999;
	// Where each process starts, so that two test runs at once do not walk the
	// same ports: a few ports of a range of ten thousand, from the process id
	// and the clock.
	static NEXT: LazyLock<AtomicU16> = LazyLock::new(|| {
		let nanos = std::time::SystemTime::now()
			.duration_since(std::time::UNIX_EPOCH)
			.map_or(0, |since| u64::from(since.subsec_nanos()));
		let seed = nanos ^ u64::from(std::process::id()).wrapping_mul(0x9e37_79b9);
		AtomicU16::new(FIRST + u16::try_from(seed % u64::from(LAST - FIRST)).unwrap_or(0))
	});
	for _ in 0..(LAST - FIRST) {
		let port = NEXT.fetch_add(1, Ordering::SeqCst);
		let port = FIRST + (port - FIRST) % (LAST - FIRST);
		if std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port)).is_ok() {
			return port;
		}
	}
	panic!("no free port in the range kept for tests");
}

#[cfg(test)]
mod free_port_tests {
	use super::free_port;

	#[test]
	fn ports_are_unique_free_and_outside_the_range_the_kernel_hands_out() {
		let ports: Vec<u16> = (0..50).map(|_| free_port()).collect();
		let unique: std::collections::HashSet<_> = ports.iter().collect();
		assert_eq!(unique.len(), ports.len());
		assert!(ports.iter().all(|port| (20_000..30_000).contains(port)));
	}
}
