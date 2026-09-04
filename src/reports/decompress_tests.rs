use super::*;

fn gzip(bytes: &[u8]) -> Vec<u8> {
	let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::default());
	use std::io::Write;
	enc.write_all(bytes).expect("write");
	enc.finish().expect("finish")
}

#[test]
fn gzip_round_trip() {
	let payload = b"<feedback><report_metadata></report_metadata></feedback>";
	let compressed = gzip(payload);
	let out = inflate_attachment(&compressed, Encoding::Gzip).expect("decompresses");
	assert_eq!(out, payload);
}

#[test]
fn zip_stored_and_deflate_single_entry() {
	use std::io::Write;
	// Build a minimal zip with a single stored (method=0) entry by hand.
	fn build_zip(name: &str, payload: &[u8], method: u16) -> Vec<u8> {
		use flate2::write::DeflateEncoder;
		let compressed = if method == METHOD_DEFLATE {
			let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
			enc.write_all(payload).expect("write");
			enc.finish().expect("finish")
		} else {
			payload.to_vec()
		};
		let crc = crc32(payload);
		let mut out = Vec::new();
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes()); // version needed
		out.extend_from_slice(&0u16.to_le_bytes()); // flags
		out.extend_from_slice(&method.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes()); // mtime
		out.extend_from_slice(&0u16.to_le_bytes()); // mdate
		out.extend_from_slice(&crc.to_le_bytes());
		out.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(name.len() as u16).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes()); // extra len
		out.extend_from_slice(name.as_bytes());
		out.extend_from_slice(&compressed);
		out
	}

	let payload = b"<?xml version=\"1.0\"?><feedback/>";

	// Stored (method 0).
	let stored = build_zip("report.xml", payload, METHOD_STORED);
	let out = inflate_attachment(&stored, Encoding::Zip).expect("stored entry decompresses");
	assert_eq!(out, payload);

	// Deflate (method 8).
	let deflated = build_zip("report.xml", payload, METHOD_DEFLATE);
	let out = inflate_attachment(&deflated, Encoding::Zip).expect("deflate entry decompresses");
	assert_eq!(out, payload);
}

/// A data descriptor (general-purpose bit 3) means the CRC and sizes are
/// not in the local file header; the reader would have to scan for the
/// descriptor marker, which we do not do. Refused.
#[test]
fn a_zip_with_a_data_descriptor_is_refused() {
	fn build_zip_with_data_descriptor(name: &str, payload: &[u8]) -> Vec<u8> {
		let crc = crc32(payload);
		let mut out = Vec::new();
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&0b0000_1000u16.to_le_bytes()); // data descriptor flag
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&crc.to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(name.len() as u16).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(name.as_bytes());
		out.extend_from_slice(payload);
		out
	}

	let payload = b"<feedback/>";
	let zip = build_zip_with_data_descriptor("report.xml", payload);
	let err = inflate_attachment(&zip, Encoding::Zip).expect_err("data descriptor rejected");
	assert!(matches!(err, ReportError::Malformed("data descriptor")), "{err:?}");
}

/// 25 MiB of zeros compressed is a few KiB. The bomb trips on the way out
/// (the decompressed side), not on the way in.
#[test]
fn decompressed_size_over_the_cap_is_too_large() {
	let payload = vec![0u8; 25 * 1024 * 1024];
	let compressed = gzip(&payload);
	// Sanity: the bomb is small on the wire.
	assert!(compressed.len() < 64 * 1024, "{}", compressed.len());
	let err = inflate_attachment(&compressed, Encoding::Gzip).expect_err("bomb tripped");
	assert!(matches!(err, ReportError::TooLarge), "{err:?}");
}

#[test]
fn compressed_size_over_the_cap_is_too_large() {
	// Caller must measure first; if it does not and hands us > MAX_COMPRESSED,
	// we still refuse rather than trust the input.
	let payload = vec![0u8; MAX_COMPRESSED + 1];
	let err = inflate_attachment(&payload, Encoding::Gzip).expect_err("over cap refused");
	assert!(matches!(err, ReportError::TooLarge), "{err:?}");
}

/// A 1-byte payload that is not a valid gzip should fail to decompress
/// (Malformed), not silently produce an empty payload that parses as
/// nothing.
#[test]
fn malformed_gzip_is_rejected() {
	let err = inflate_attachment(b"\x1f\x8b\x00\x00", Encoding::Gzip)
		.expect_err("truncated gzip refused");
	assert!(matches!(err, ReportError::Malformed(_)), "{err:?}");
}

/// A 3-byte prefix that does not match the zip local file header signature.
#[test]
fn non_zip_bytes_are_rejected() {
	let err = inflate_attachment(b"PK\x03\x06", Encoding::Zip).expect_err("bad signature refused");
	assert!(matches!(err, ReportError::Malformed(_)), "{err:?}");
}

/// Built from the polynomial `0xEDB88320` reversed; sufficient for the
/// two archive builders we use in this test module.
fn crc32(bytes: &[u8]) -> u32 {
	let mut table = [0u32; 256];
	for i in 0..256u32 {
		let mut c = i;
		for _ in 0..8 {
			c = if c & 1 != 0 { 0xEDB88320 ^ (c >> 1) } else { c >> 1 };
		}
		table[i as usize] = c;
	}
	let mut crc = 0xFFFF_FFFFu32;
	for &b in bytes {
		crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
	}
	crc ^ 0xFFFF_FFFFu32
}
