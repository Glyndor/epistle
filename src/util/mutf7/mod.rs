//! Modified UTF-7 (RFC 3501 §5.1.3), the IMAP4rev1 spelling of international
//! mailbox names.
//!
//! Folder directories are named with this encoding, so every name on disk is
//! printable ASCII whatever the client typed. A client that enabled UTF-8
//! (RFC 6855 `UTF8=ACCEPT`, or IMAP4rev2) sees the decoded name; any other
//! client sees and sends the encoded one.

/// The modified base64 alphabet: `,` replaces `/`.
const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+,";

/// Encode a UTF-8 mailbox name. Printable ASCII is kept as is (`&` becomes
/// `&-`); every run of other characters becomes `&<modified base64 of
/// UTF-16BE>-`.
pub fn encode(name: &str) -> String {
	let mut out = String::with_capacity(name.len());
	let mut run: Vec<u16> = Vec::new();
	for c in name.chars() {
		if (' '..='~').contains(&c) {
			flush(&mut out, &mut run);
			if c == '&' {
				out.push_str("&-");
			} else {
				out.push(c);
			}
		} else {
			let mut units = [0u16; 2];
			run.extend_from_slice(c.encode_utf16(&mut units));
		}
	}
	flush(&mut out, &mut run);
	out
}

fn flush(out: &mut String, run: &mut Vec<u16>) {
	if run.is_empty() {
		return;
	}
	let bytes: Vec<u8> = run.iter().flat_map(|unit| unit.to_be_bytes()).collect();
	out.push('&');
	for chunk in bytes.chunks(3) {
		let mut group = [0u8; 3];
		group[..chunk.len()].copy_from_slice(chunk);
		let bits = u32::from(group[0]) << 16 | u32::from(group[1]) << 8 | u32::from(group[2]);
		// One octet needs two characters, two need three, three need four.
		for index in 0..=chunk.len() {
			let sextet = (bits >> (18 - 6 * index)) & 0x3f;
			out.push(char::from(ALPHABET[sextet as usize]));
		}
	}
	out.push('-');
	run.clear();
}

/// Decode a modified UTF-7 name. Returns `None` unless `name` is the
/// canonical encoding of its decoded form: raw 8-bit characters, a bad or
/// unterminated run, non-zero padding bits, an encoded printable ASCII
/// character or two adjacent runs all make it invalid, so every decoded name
/// has exactly one spelling on disk.
pub fn decode(name: &str) -> Option<String> {
	let mut out = String::with_capacity(name.len());
	let mut rest = name;
	while let Some(c) = rest.chars().next() {
		rest = &rest[c.len_utf8()..];
		if c == '&' {
			let (run, after) = rest.split_once('-')?;
			rest = after;
			if run.is_empty() {
				out.push('&');
			} else {
				out.push_str(&decode_run(run)?);
			}
		} else if (' '..='~').contains(&c) {
			out.push(c);
		} else {
			return None;
		}
	}
	(encode(&out) == name).then_some(out)
}

fn decode_run(run: &str) -> Option<String> {
	let mut bytes = Vec::with_capacity(run.len());
	let (mut bits, mut count) = (0u32, 0u32);
	for symbol in run.bytes() {
		let value = ALPHABET.iter().position(|&a| a == symbol)?;
		bits = (bits << 6) | value as u32;
		count += 6;
		if count >= 8 {
			count -= 8;
			bytes.push((bits >> count) as u8);
			bits &= (1 << count) - 1;
		}
	}
	if bytes.len() % 2 != 0 {
		return None;
	}
	let units: Vec<u16> = bytes
		.chunks(2)
		.map(|pair| u16::from_be_bytes([pair[0], pair[1]]))
		.collect();
	String::from_utf16(&units).ok()
}

#[cfg(test)]
mod tests;
