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

/// General-purpose bit 3 (data descriptor) means the local file header
/// carries zeros for the sizes; the minimal reader follows the
/// end-of-central-directory pointer back to the central directory to
/// recover them.
#[test]
fn zip_with_data_descriptor_stored_and_deflate() {
	use flate2::write::DeflateEncoder;
	use std::io::Write;
	fn build_zip(name: &str, payload: &[u8], method: u16) -> Vec<u8> {
		let compressed = if method == METHOD_DEFLATE {
			let mut enc = DeflateEncoder::new(Vec::new(), flate2::Compression::default());
			enc.write_all(payload).expect("write");
			enc.finish().expect("finish")
		} else {
			payload.to_vec()
		};
		let crc = crc32(payload);
		// Local file header: sizes are zero, bit 3 set.
		let mut local = Vec::new();
		local.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		local.extend_from_slice(&20u16.to_le_bytes()); // version needed
		local.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		local.extend_from_slice(&method.to_le_bytes());
		local.extend_from_slice(&0u16.to_le_bytes());
		local.extend_from_slice(&0u16.to_le_bytes());
		local.extend_from_slice(&crc.to_le_bytes());
		local.extend_from_slice(&0u32.to_le_bytes()); // compressed size = 0
		local.extend_from_slice(&0u32.to_le_bytes()); // uncompressed size = 0
		local.extend_from_slice(&(name.len() as u16).to_le_bytes());
		local.extend_from_slice(&0u16.to_le_bytes());
		local.extend_from_slice(name.as_bytes());
		local.extend_from_slice(&compressed);
		// Central directory header: real sizes.
		let central_offset = 0usize;
		let mut central = Vec::new();
		central.extend_from_slice(&CENTRAL_DIR_HEADER_SIG);
		central.extend_from_slice(&20u16.to_le_bytes()); // version made by
		central.extend_from_slice(&20u16.to_le_bytes()); // version needed
		central.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		central.extend_from_slice(&method.to_le_bytes());
		central.extend_from_slice(&0u16.to_le_bytes()); // mtime
		central.extend_from_slice(&0u16.to_le_bytes()); // mdate
		central.extend_from_slice(&crc.to_le_bytes());
		central.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
		central.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		central.extend_from_slice(&(name.len() as u16).to_le_bytes());
		central.extend_from_slice(&0u16.to_le_bytes()); // extra len
		central.extend_from_slice(&0u16.to_le_bytes()); // comment len
		central.extend_from_slice(&0u16.to_le_bytes()); // disk start
		central.extend_from_slice(&0u16.to_le_bytes()); // int attrs
		central.extend_from_slice(&0u32.to_le_bytes()); // ext attrs
		central.extend_from_slice(&0u32.to_le_bytes()); // local header offset
		central.extend_from_slice(name.as_bytes());
		// End-of-central-directory record.
		let eocd_offset = local.len() + central.len();
		let mut eocd = Vec::new();
		eocd.extend_from_slice(&EOCD_SIG);
		eocd.extend_from_slice(&0u16.to_le_bytes()); // disk number
		eocd.extend_from_slice(&0u16.to_le_bytes()); // disk with cd
		eocd.extend_from_slice(&1u16.to_le_bytes()); // entries on this disk
		eocd.extend_from_slice(&1u16.to_le_bytes()); // total entries
		eocd.extend_from_slice(&(central.len() as u32).to_le_bytes()); // cd size
		eocd.extend_from_slice(&((central_offset + local.len()) as u32).to_le_bytes()); // cd offset
		eocd.extend_from_slice(&0u16.to_le_bytes()); // comment len
		let _ = eocd_offset;
		let mut out = local;
		out.extend_from_slice(&central);
		out.extend_from_slice(&eocd);
		out
	}

	let payload = b"<feedback/>";
	let stored = build_zip("report.xml", payload, METHOD_STORED);
	let out = inflate_attachment(&stored, Encoding::Zip).expect("stored bit-3");
	assert_eq!(out, payload);
	let deflated = build_zip("report.xml", payload, METHOD_DEFLATE);
	let out = inflate_attachment(&deflated, Encoding::Zip).expect("deflate bit-3");
	assert_eq!(out, payload);
}

/// An archive with a second local file header after the first entry is a
/// multi-entry zip. We refuse on purpose.
#[test]
fn a_second_local_file_header_is_refused() {
	fn build_zip_with_two_entries() -> Vec<u8> {
		let payload = b"<feedback/>";
		let crc = crc32(payload);
		let mut out = Vec::new();
		// First entry (stored, no flags).
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&crc.to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes()); // "a.xml"
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		out.extend_from_slice(payload);
		// Second entry header right after, no data.
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(b"b.xml");
		out
	}
	let zip = build_zip_with_two_entries();
	let err = inflate_attachment(&zip, Encoding::Zip).expect_err("multi-entry refused");
	assert!(
		matches!(err, ReportError::Malformed("zip multi-entry")),
		"{err:?}"
	);
}

/// The end-of-central-directory record is missing from the scan window.
/// A real zip puts the EOCD at the tail of the file, so anything else is
/// hostile: trailing junk pushes the EOCD past the back-scan window.
#[test]
fn eocd_outside_the_scan_window_is_refused() {
	fn build_zip_eocd_outside_window(payload: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes()); // crc
		out.extend_from_slice(&0u32.to_le_bytes()); // compressed = 0
		out.extend_from_slice(&0u32.to_le_bytes()); // uncompressed = 0
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		out.extend_from_slice(payload);
		out.extend_from_slice(&EOCD_SIG);
		out.extend_from_slice(&[0u8; 18]);
		// Trailing junk beyond the EOCD pushes it out of the last-256KiB
		// window the reader scans.
		out.extend(vec![0u8; EOCD_SCAN_WINDOW]);
		out
	}
	let zip = build_zip_eocd_outside_window(b"<feedback/>");
	let err = inflate_attachment(&zip, Encoding::Zip).expect_err("eocd outside window");
	assert!(
		matches!(err, ReportError::Malformed("zip eocd missing")),
		"{err:?}"
	);
}

/// A central directory header whose compressed-size field is larger than
/// the buffer cannot be real; refuse it before the deflate decoder
/// reads past the end.
#[test]
fn central_size_larger_than_the_buffer_is_refused() {
	fn build_zip_oversized_central(payload: &[u8]) -> Vec<u8> {
		let mut out = Vec::new();
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		out.extend_from_slice(payload);
		// Central directory header with a compressed-size field that
		// exceeds both the buffer and MAX_COMPRESSED; the local entry
		// itself is fine.
		out.extend_from_slice(&CENTRAL_DIR_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&(u32::MAX).to_le_bytes()); // compressed size: bomb
		out.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		// EOCD pointing at the central directory above.
		let central_offset = payload.len() + 30 + 5;
		out.extend_from_slice(&EOCD_SIG);
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&1u16.to_le_bytes());
		out.extend_from_slice(&1u16.to_le_bytes());
		out.extend_from_slice(&((out.len() - central_offset - 22) as u32).to_le_bytes());
		out.extend_from_slice(&(central_offset as u32).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out
	}
	let zip = build_zip_oversized_central(b"<feedback/>");
	let err = inflate_attachment(&zip, Encoding::Zip).expect_err("central bomb");
	assert!(
		matches!(err, ReportError::Malformed("zip central size overruns")),
		"{err:?}"
	);
}

/// A central directory header whose compressed-size field is between the
/// buffer length and MAX_COMPRESSED still trips the size cap.
#[test]
fn central_size_above_max_compressed_is_refused() {
	fn build_zip_above_cap() -> Vec<u8> {
		// Local header with bit 3 set, no data payload (we never get to
		// read it; the cap fires first).
		let mut out = Vec::new();
		out.extend_from_slice(&LOCAL_FILE_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		// Fake data block of MAX_COMPRESSED + 1 bytes: above the cap
		// but below the buffer.
		let claimed = (MAX_COMPRESSED as u32) + 1;
		out.extend_from_slice(&vec![0u8; claimed as usize]);
		// Central directory header at the start, sized to claim
		// `claimed` bytes; the real buffer is bigger than the claim so
		// the "central size larger than the buffer" check passes and
		// the "above MAX_COMPRESSED" check fires.
		let central_offset = 0usize;
		out.extend_from_slice(&CENTRAL_DIR_HEADER_SIG);
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&FLAG_DATA_DESCRIPTOR.to_le_bytes());
		out.extend_from_slice(&METHOD_STORED.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&claimed.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&5u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(&0u32.to_le_bytes());
		out.extend_from_slice(b"a.xml");
		let _ = central_offset;
		// EOCD pointing at the central directory.
		out.extend_from_slice(&EOCD_SIG);
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(&1u16.to_le_bytes());
		out.extend_from_slice(&1u16.to_le_bytes());
		out.extend_from_slice(&1u32.to_le_bytes());
		out.extend_from_slice(&((claimed as usize + 30 + 5) as u32).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out
	}
	let zip = build_zip_above_cap();
	let err = inflate_attachment(&zip, Encoding::Zip).expect_err("above MAX_COMPRESSED");
	assert!(matches!(err, ReportError::TooLarge), "{err:?}");
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
			c = if c & 1 != 0 {
				0xEDB88320 ^ (c >> 1)
			} else {
				c >> 1
			};
		}
		table[i as usize] = c;
	}
	let mut crc = 0xFFFF_FFFFu32;
	for &b in bytes {
		crc = table[((crc ^ b as u32) & 0xFF) as usize] ^ (crc >> 8);
	}
	crc ^ 0xFFFF_FFFFu32
}
