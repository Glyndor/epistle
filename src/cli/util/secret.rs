//! Random credential secrets.

/// Generate a strong random credential secret: 32 bytes from the system CSPRNG,
/// base32-encoded (unpadded, lowercase) for an easy-to-copy ~52-character
/// string. `None` if the CSPRNG cannot produce bytes (fail closed).
pub(in crate::cli) fn generate_secret() -> Option<String> {
	use ring::rand::SecureRandom;
	let mut bytes = [0u8; 32];
	ring::rand::SystemRandom::new().fill(&mut bytes).ok()?;
	// RFC 4648 base32 lowercase, no padding.
	const ALPHABET: &[u8; 32] = b"abcdefghijklmnopqrstuvwxyz234567";
	let mut out = String::with_capacity(52);
	let mut buffer: u32 = 0;
	let mut bits = 0u32;
	for &byte in &bytes {
		buffer = (buffer << 8) | byte as u32;
		bits += 8;
		while bits >= 5 {
			bits -= 5;
			let index = ((buffer >> bits) & 0x1f) as usize;
			out.push(ALPHABET[index] as char);
		}
	}
	if bits > 0 {
		let index = ((buffer << (5 - bits)) & 0x1f) as usize;
		out.push(ALPHABET[index] as char);
	}
	Some(out)
}
