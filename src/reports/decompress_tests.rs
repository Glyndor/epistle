use super::*;

#[test]
fn truncated_eocd_tail_is_refused() {
	let mut bytes = vec![0; 30];
	bytes[..4].copy_from_slice(&LOCAL_FILE_HEADER_SIG);
	bytes[6] = FLAG_DATA_DESCRIPTOR as u8;
	bytes.extend_from_slice(&EOCD_SIG);
	let err = inflate_attachment(&bytes, Encoding::Zip).expect_err("truncated EOCD");
	assert!(matches!(err, ReportError::Malformed("zip eocd missing")));
}

#[test]
fn zip_integer_reads_check_truncation_and_extreme_offsets() {
	let bytes = [1, 2, 3, 4];
	assert_eq!(read_u16(&bytes, 2).expect("two bytes remain"), 0x0403);
	assert_eq!(read_u32(&bytes, 0).expect("four bytes remain"), 0x04030201);
	for offset in [3, 4, usize::MAX] {
		assert!(matches!(
			read_u16(&bytes, offset),
			Err(ReportError::Malformed("zip field overruns buffer"))
		));
		assert!(matches!(
			read_u32(&bytes, offset),
			Err(ReportError::Malformed("zip field overruns buffer"))
		));
	}
}

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
	for method in [METHOD_STORED, METHOD_DEFLATE] {
		let bytes = super::tests_single_entry::archive(1, false, method);
		let out = inflate_attachment(&bytes, Encoding::Zip).expect("single entry decompresses");
		assert!(
			out.as_slice() == b"<feedback/>",
			"stored and deflate ZIP must preserve payload"
		);
	}
}

#[test]
fn zip_with_data_descriptor_stored_and_deflate() {
	for method in [METHOD_STORED, METHOD_DEFLATE] {
		let bytes = super::tests_single_entry::archive(1, true, method);
		let out = inflate_attachment(&bytes, Encoding::Zip).expect("streaming entry decompresses");
		assert!(
			out.as_slice() == b"<feedback/>",
			"streaming ZIP must preserve payload"
		);
	}
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
		out.extend_from_slice(&51u32.to_le_bytes());
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

/// Exercise the central-directory cap directly so the outer input cap
/// cannot satisfy this assertion first.
#[test]
fn central_size_above_max_compressed_is_refused() {
	fn build_zip_at_size(claimed: u32) -> Vec<u8> {
		// Leave local sizes zero and declare bit 3 for the central-directory lookup.
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
		// Keep the complete buffer larger than the claimed data size.
		out.extend_from_slice(&vec![0u8; claimed as usize]);
		// Central directory header after the data block, sized to claim
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
		out.extend_from_slice(&51u32.to_le_bytes());
		out.extend_from_slice(&((claimed as usize + 30 + 5) as u32).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out
	}
	let inside = build_zip_at_size(MAX_COMPRESSED as u32);
	assert_eq!(
		read_central_sizes(&inside, 35).expect("central size at cap"),
		(MAX_COMPRESSED, 0)
	);
	let zip = build_zip_at_size(MAX_COMPRESSED as u32 + 1);
	let err = read_central_sizes(&zip, 35).expect_err("central size above MAX_COMPRESSED");
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
