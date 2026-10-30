//! ZIP directory attacks without filesystem extraction or decompression.

use std::io::Write;

use epistle::antispam::attachments::archive::{MAX_ENTRIES, list_zip};
use epistle::antispam::attachments::rules::{Extensions, Reason};
use epistle::antispam::attachments::{Budget, inspect};

use super::harness::bounded;

fn u16le(out: &mut Vec<u8>, n: u16) {
	out.extend_from_slice(&n.to_le_bytes());
}
fn u32le(out: &mut Vec<u8>, n: u32) {
	out.extend_from_slice(&n.to_le_bytes());
}

/// Consistent local/central metadata; payloads are deliberately opaque.
fn zip(entries: &[(String, Vec<u8>, u32, u16)]) -> Vec<u8> {
	let mut out = Vec::new();
	let mut central = Vec::new();
	for (name, data, expanded, method) in entries {
		let offset = u32::try_from(out.len()).expect("fixture offset");
		let size = u32::try_from(data.len()).expect("fixture size");
		let len = u16::try_from(name.len()).expect("fixture name");
		out.extend_from_slice(b"PK\x03\x04");
		for n in [20, 0, *method, 0, 0] {
			u16le(&mut out, n);
		}
		u32le(&mut out, 0);
		u32le(&mut out, size);
		u32le(&mut out, *expanded);
		u16le(&mut out, len);
		u16le(&mut out, 0);
		out.extend_from_slice(name.as_bytes());
		out.extend_from_slice(data);
		central.extend_from_slice(b"PK\x01\x02");
		for n in [20, 20, 0, *method, 0, 0] {
			u16le(&mut central, n);
		}
		u32le(&mut central, 0);
		u32le(&mut central, size);
		u32le(&mut central, *expanded);
		for n in [len, 0, 0, 0, 0] {
			u16le(&mut central, n);
		}
		u32le(&mut central, 0);
		u32le(&mut central, offset);
		central.extend_from_slice(name.as_bytes());
	}
	let offset = u32::try_from(out.len()).expect("directory offset");
	let size = u32::try_from(central.len()).expect("directory size");
	out.extend(central);
	out.extend_from_slice(b"PK\x05\x06");
	for n in [0, 0, entries.len() as u16, entries.len() as u16] {
		u16le(&mut out, n);
	}
	u32le(&mut out, size);
	u32le(&mut out, offset);
	u16le(&mut out, 0);
	out
}

#[test]
fn zip_bomb_declaring_four_gib_is_listed_without_expansion() {
	bounded(|| {
		let mut deflate =
			flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::best());
		for _ in 0..512 {
			deflate.write_all(&[0; 8192]).expect("compress fixture");
		}
		let payload = deflate.finish().expect("finish fixture");
		assert!(payload.len() < 8192);
		let raw = zip(&[("bomb.bin".into(), payload, u32::MAX, 8)]);
		assert!(raw.len() < 10_000);
		let listing = list_zip(&raw);
		assert_eq!(listing.names, ["bomb.bin"]);
		assert!(!listing.too_many);
		assert!(!listing.unreadable);
		assert!(!listing.ambiguous);
	});
}

#[test]
fn nested_zip_is_not_recursively_extracted() {
	bounded(|| {
		let mut raw = zip(&[("deep.exe".into(), b"MZ".to_vec(), 2, 0)]);
		for _ in 0..1000 {
			let size = raw.len() as u32;
			raw = zip(&[("inner.zip".into(), raw, size, 0)]);
		}
		let listing = list_zip(&raw);
		assert_eq!(listing.names, ["inner.zip"]);
		assert!(!listing.names.iter().any(|name| name == "deep.exe"));
		assert!(!listing.unreadable);
		let mut message = b"Content-Type: application/zip; name=outer.zip\r\n\r\n".to_vec();
		message.extend(raw);
		let report = inspect(&message, &Extensions::default(), Budget::bytes(1 << 20));
		assert_eq!(report.parts.len(), 1);
		assert!(report.reasons().contains(&Reason::NestedArchive));
	});
}

#[test]
fn zip_with_twelve_hundred_names_hits_entry_cap() {
	bounded(|| {
		let entries = (0..1200)
			.map(|n| (format!("{n}.bin"), Vec::new(), 0, 0))
			.collect::<Vec<_>>();
		let listing = list_zip(&zip(&entries));
		assert!(listing.too_many);
		assert_eq!(listing.names.len(), MAX_ENTRIES);
	});
}

#[test]
fn truncated_zip_is_unreadable_instead_of_clean() {
	bounded(|| {
		let raw = zip(&[("a.bin".into(), b"payload".to_vec(), 7, 0)]);
		for cut in [0, 4, 29, raw.len() - 1] {
			let listing = list_zip(&raw[..cut]);
			assert!(listing.unreadable, "cut {cut}: {listing:?}");
			assert!(listing.names.len() <= MAX_ENTRIES);
		}
	});
}
