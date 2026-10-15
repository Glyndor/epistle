//! Test inputs for the attachment inspection, built from byte prefixes.
//! Nothing here is, or contains, a working program: an "executable" is the
//! two-byte `MZ` header followed by padding, a "macro" is a directory entry
//! name. That is all the inspection reads, so it is all the tests need.

use base64::Engine as _;

/// A PE header prefix and nothing that runs.
pub fn pe() -> Vec<u8> {
	let mut bytes = b"MZ\x90\x00\x03\x00\x00\x00".to_vec();
	bytes.resize(256, 0);
	bytes
}

/// A PNG signature and an empty header chunk.
pub fn png() -> Vec<u8> {
	let mut bytes = b"\x89PNG\r\n\x1a\n\x00\x00\x00\x0dIHDR".to_vec();
	bytes.resize(64, 0);
	bytes
}

/// A PDF header and a trailer.
pub fn pdf() -> Vec<u8> {
	b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n".to_vec()
}

/// One zip entry: its name and whether it is marked encrypted.
pub struct ZipEntry<'a> {
	pub name: &'a str,
	pub encrypted: bool,
}

/// A stored (uncompressed) zip with one byte per entry, a central
/// directory and an end record.
pub fn zip(entries: &[ZipEntry<'_>]) -> Vec<u8> {
	let mut out = Vec::new();
	let mut central = Vec::new();
	for entry in entries {
		let offset = out.len() as u32;
		let flags: u16 = if entry.encrypted { 1 } else { 0 };
		let name = entry.name.as_bytes();
		out.extend_from_slice(b"PK\x03\x04");
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&flags.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes()); // stored
		out.extend_from_slice(&[0; 8]); // time, date, crc
		out.extend_from_slice(&1u32.to_le_bytes());
		out.extend_from_slice(&1u32.to_le_bytes());
		out.extend_from_slice(&(name.len() as u16).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(name);
		out.push(b'x');
		central.extend_from_slice(b"PK\x01\x02");
		central.extend_from_slice(&20u16.to_le_bytes());
		central.extend_from_slice(&20u16.to_le_bytes());
		central.extend_from_slice(&flags.to_le_bytes());
		central.extend_from_slice(&0u16.to_le_bytes());
		central.extend_from_slice(&[0; 8]);
		central.extend_from_slice(&1u32.to_le_bytes());
		central.extend_from_slice(&1u32.to_le_bytes());
		central.extend_from_slice(&(name.len() as u16).to_le_bytes());
		central.extend_from_slice(&[0; 12]); // extra, comment, disk, attrs
		central.extend_from_slice(&offset.to_le_bytes());
		central.extend_from_slice(name);
	}
	let start = out.len() as u32;
	out.extend_from_slice(&central);
	out.extend_from_slice(b"PK\x05\x06");
	out.extend_from_slice(&[0; 4]);
	out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
	out.extend_from_slice(&(entries.len() as u16).to_le_bytes());
	out.extend_from_slice(&(central.len() as u32).to_le_bytes());
	out.extend_from_slice(&start.to_le_bytes());
	out.extend_from_slice(&0u16.to_le_bytes());
	out
}

/// Plain zip entries from names.
pub fn zip_of(names: &[&str]) -> Vec<u8> {
	let entries: Vec<ZipEntry<'_>> = names
		.iter()
		.map(|name| ZipEntry {
			name,
			encrypted: false,
		})
		.collect();
	zip(&entries)
}

/// An OLE2 header followed by one directory sector whose first entry is
/// named `entry` (UTF-16LE, with the recorded name length).
pub fn ole2(entry: &str) -> Vec<u8> {
	let mut bytes = b"\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1".to_vec();
	bytes.resize(512, 0);
	let mut dir = vec![0u8; 128];
	let name: Vec<u8> = entry.encode_utf16().flat_map(u16::to_le_bytes).collect();
	dir[..name.len()].copy_from_slice(&name);
	let len = (name.len() + 2) as u16;
	dir[64..66].copy_from_slice(&len.to_le_bytes());
	bytes.extend_from_slice(&dir);
	bytes.resize(512 + 512, 0);
	bytes
}

/// One part of a test message.
pub struct Part<'a> {
	/// Raw header lines, without the final blank line.
	pub headers: &'a str,
	/// Content, base64-encoded into the part.
	pub content: &'a [u8],
}

/// An attachment part with a `filename` and a declared type.
pub fn attachment<'a>(headers: &'a str, content: &'a [u8]) -> Part<'a> {
	Part { headers, content }
}

/// A `multipart/mixed` message with a text body and `parts`, each
/// base64-encoded.
pub fn message(parts: &[Part<'_>]) -> Vec<u8> {
	let mut out = String::from(
		"From: a@example.org\r\nTo: b@example.net\r\nSubject: t\r\nMIME-Version: 1.0\r\n\
		 Content-Type: multipart/mixed; boundary=\"outer\"\r\n\r\npreamble\r\n\
		 --outer\r\nContent-Type: text/plain\r\n\r\nhello\r\n",
	);
	for part in parts {
		out.push_str("--outer\r\n");
		out.push_str(part.headers);
		out.push_str("\r\nContent-Transfer-Encoding: base64\r\n\r\n");
		let encoded = base64::engine::general_purpose::STANDARD.encode(part.content);
		for chunk in encoded.as_bytes().chunks(76) {
			out.push_str(std::str::from_utf8(chunk).expect("base64 is ascii"));
			out.push_str("\r\n");
		}
	}
	out.push_str("--outer--\r\n");
	out.into_bytes()
}

/// uuencode `bytes` the way `uuencode(1)` does, with a backquote for zero.
pub fn uu(name: &str, bytes: &[u8]) -> String {
	let char_of = |value: u8| {
		if value == 0 {
			'`'
		} else {
			(value + b' ') as char
		}
	};
	let mut out = format!("begin 644 {name}\n");
	for line in bytes.chunks(45) {
		out.push(char_of(line.len() as u8));
		for group in line.chunks(3) {
			let mut padded = [0u8; 3];
			padded[..group.len()].copy_from_slice(group);
			out.push(char_of(padded[0] >> 2));
			out.push(char_of(((padded[0] & 3) << 4) | (padded[1] >> 4)));
			out.push(char_of(((padded[1] & 15) << 2) | (padded[2] >> 6)));
			out.push(char_of(padded[2] & 63));
		}
		out.push('\n');
	}
	out.push_str("`\nend\n");
	out
}
