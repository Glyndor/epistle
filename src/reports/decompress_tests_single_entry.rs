use super::*;

pub(super) fn archive(entries: usize, streaming: bool, method: u16) -> Vec<u8> {
	use std::io::Write;
	let payload = b"<feedback/>";
	let compressed = if method == METHOD_DEFLATE {
		let mut encoder =
			flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
		encoder.write_all(payload).expect("encode payload");
		encoder.finish().expect("finish deflate")
	} else {
		payload.to_vec()
	};
	let mut crc = u32::MAX;
	for byte in payload {
		crc ^= u32::from(*byte);
		for _ in 0..8 {
			crc = (crc >> 1) ^ (0xedb88320 & 0u32.wrapping_sub(crc & 1));
		}
	}
	let crc = !crc;
	let flags = if streaming { FLAG_DATA_DESCRIPTOR } else { 0 };
	let mut bytes = Vec::new();
	let mut central = Vec::new();
	for index in 0..entries {
		let offset = bytes.len() as u32;
		let name = format!("{index}.xml");
		let mut local = vec![0; 30];
		local[..4].copy_from_slice(&LOCAL_FILE_HEADER_SIG);
		local[4..6].copy_from_slice(&20u16.to_le_bytes());
		local[6..8].copy_from_slice(&flags.to_le_bytes());
		local[8..10].copy_from_slice(&method.to_le_bytes());
		if !streaming {
			local[14..18].copy_from_slice(&crc.to_le_bytes());
			local[18..22].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
			local[22..26].copy_from_slice(&(payload.len() as u32).to_le_bytes());
		}
		local[26..28].copy_from_slice(&(name.len() as u16).to_le_bytes());
		bytes.extend_from_slice(&local);
		bytes.extend_from_slice(name.as_bytes());
		bytes.extend_from_slice(&compressed);
		if streaming {
			bytes.extend_from_slice(b"PK\x07\x08");
			bytes.extend_from_slice(&crc.to_le_bytes());
			bytes.extend_from_slice(&(compressed.len() as u32).to_le_bytes());
			bytes.extend_from_slice(&(payload.len() as u32).to_le_bytes());
		}
		let mut header = vec![0; 46];
		header[..4].copy_from_slice(&CENTRAL_DIR_HEADER_SIG);
		header[4..6].copy_from_slice(&20u16.to_le_bytes());
		header[6..8].copy_from_slice(&20u16.to_le_bytes());
		header[8..10].copy_from_slice(&flags.to_le_bytes());
		header[10..12].copy_from_slice(&method.to_le_bytes());
		header[16..20].copy_from_slice(&crc.to_le_bytes());
		header[20..24].copy_from_slice(&(compressed.len() as u32).to_le_bytes());
		header[24..28].copy_from_slice(&(payload.len() as u32).to_le_bytes());
		header[28..30].copy_from_slice(&(name.len() as u16).to_le_bytes());
		header[42..46].copy_from_slice(&offset.to_le_bytes());
		central.extend_from_slice(&header);
		central.extend_from_slice(name.as_bytes());
	}
	let central_offset = bytes.len() as u32;
	let mut eocd = vec![0; EOCD_FIXED_LEN];
	eocd[..4].copy_from_slice(&EOCD_SIG);
	eocd[8..10].copy_from_slice(&(entries as u16).to_le_bytes());
	eocd[10..12].copy_from_slice(&(entries as u16).to_le_bytes());
	eocd[12..16].copy_from_slice(&(central.len() as u32).to_le_bytes());
	eocd[16..20].copy_from_slice(&central_offset.to_le_bytes());
	bytes.extend_from_slice(&central);
	bytes.extend_from_slice(&eocd);
	bytes
}

#[test]
fn streaming_zip_with_two_entries_is_refused_by_directory() {
	for method in [METHOD_STORED, METHOD_DEFLATE] {
		let result = inflate_attachment(&archive(2, true, method), Encoding::Zip);
		assert!(
			matches!(result, Err(ReportError::Malformed("zip multi-entry"))),
			"two-entry streaming ZIP must be refused with zip multi-entry"
		);
	}
}

#[test]
fn streaming_zip_with_one_entry_preserves_payload() {
	for method in [METHOD_STORED, METHOD_DEFLATE] {
		let result = inflate_attachment(&archive(1, true, method), Encoding::Zip).ok();
		assert!(
			result.as_deref() == Some(b"<feedback/>"),
			"single-entry streaming ZIP must preserve the complete report payload"
		);
	}
}

#[test]
fn streaming_zip_cannot_hide_second_entry_with_false_counts() {
	let mut bytes = archive(2, true, METHOD_STORED);
	let eocd = bytes.len() - EOCD_FIXED_LEN;
	bytes[eocd + 8..eocd + 12].copy_from_slice(&[1, 0, 1, 0]);
	assert!(
		matches!(
			inflate_attachment(&bytes, Encoding::Zip),
			Err(ReportError::Malformed("zip multi-entry"))
		),
		"extra central directory records must be refused with zip multi-entry"
	);
}
