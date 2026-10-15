//! Zips whose local headers leave the sizes to a data descriptor, the way
//! LibreOffice, Java's `ZipOutputStream`, macOS Finder and every writer
//! that streams its output make them. Read against the central directory
//! they are as simple as any other zip; one that disagrees with it is not.

use std::io::Write as _;

use super::*;
use crate::antispam::attachments::corpus;

/// How the descriptor after each entry is written.
#[derive(Clone, Copy)]
enum Descriptor {
	/// `PK\x07\x08` in front, as most writers do.
	Signed,
	/// No signature: the format allows it and older writers omit it.
	Bare,
}

/// One entry: its name, its content and the compression method.
struct Streamed<'a> {
	name: &'a str,
	content: &'a [u8],
	method: u16,
}

fn deflate(content: &[u8]) -> Vec<u8> {
	let mut encoder =
		flate2::write::DeflateEncoder::new(Vec::new(), flate2::Compression::default());
	encoder.write_all(content).expect("deflate");
	encoder.finish().expect("deflate")
}

/// A zip written front to back: zero crc and sizes in every local header,
/// bit 3 set, the real values in a descriptor after the data and in the
/// central directory. `tamper` may change an entry's stored data.
fn streamed(
	entries: &[Streamed<'_>],
	descriptor: Descriptor,
	tamper: impl Fn(usize, &mut Vec<u8>),
) -> Vec<u8> {
	let mut out = Vec::new();
	let mut central = Vec::new();
	for (index, entry) in entries.iter().enumerate() {
		let mut data = match entry.method {
			0 => entry.content.to_vec(),
			_ => deflate(entry.content),
		};
		let mut crc = flate2::Crc::new();
		crc.update(entry.content);
		let crc = crc.sum();
		tamper(index, &mut data);
		let offset = out.len() as u32;
		let name = entry.name.as_bytes();
		let flags: u16 = 0x0808;
		out.extend_from_slice(b"PK\x03\x04");
		out.extend_from_slice(&20u16.to_le_bytes());
		out.extend_from_slice(&flags.to_le_bytes());
		out.extend_from_slice(&entry.method.to_le_bytes());
		out.extend_from_slice(&[0; 16]); // time, date, crc, sizes
		out.extend_from_slice(&(name.len() as u16).to_le_bytes());
		out.extend_from_slice(&0u16.to_le_bytes());
		out.extend_from_slice(name);
		out.extend_from_slice(&data);
		if let Descriptor::Signed = descriptor {
			out.extend_from_slice(b"PK\x07\x08");
		}
		out.extend_from_slice(&crc.to_le_bytes());
		out.extend_from_slice(&(data.len() as u32).to_le_bytes());
		out.extend_from_slice(&(entry.content.len() as u32).to_le_bytes());
		central.extend_from_slice(b"PK\x01\x02");
		central.extend_from_slice(&20u16.to_le_bytes());
		central.extend_from_slice(&20u16.to_le_bytes());
		central.extend_from_slice(&flags.to_le_bytes());
		central.extend_from_slice(&entry.method.to_le_bytes());
		central.extend_from_slice(&[0; 4]); // time, date
		central.extend_from_slice(&crc.to_le_bytes());
		central.extend_from_slice(&(data.len() as u32).to_le_bytes());
		central.extend_from_slice(&(entry.content.len() as u32).to_le_bytes());
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

fn pdfs() -> Vec<Streamed<'static>> {
	vec![
		Streamed {
			name: "Facturas/",
			content: b"",
			method: 8,
		},
		Streamed {
			name: "Facturas/Factura 1.pdf",
			content: b"%PDF-1.7\n1 0 obj\n<<>>\nendobj\n%%EOF\n",
			method: 8,
		},
		Streamed {
			name: "Facturas/Factura 2.pdf",
			content: b"%PDF-1.7\n2 0 obj\n<<>>\nendobj\n%%EOF\n",
			method: 8,
		},
	]
}

#[test]
fn a_zip_written_with_data_descriptors_is_a_simple_zip() {
	for descriptor in [Descriptor::Signed, Descriptor::Bare] {
		let listing = list_zip(&streamed(&pdfs(), descriptor, |_, _| {}));
		assert_eq!(
			listing.names,
			vec![
				"Facturas/",
				"Facturas/Factura 1.pdf",
				"Facturas/Factura 2.pdf"
			]
		);
		assert!(!listing.ambiguous, "{listing:?}");
		assert!(!listing.unreadable, "{listing:?}");
	}
}

#[test]
fn an_office_document_saved_by_libreoffice_is_clean() {
	let docx = streamed(
		&[
			Streamed {
				name: "_rels/.rels",
				content: b"<?xml version=\"1.0\"?><Relationships/>",
				method: 8,
			},
			Streamed {
				name: "word/document.xml",
				content: b"<?xml version=\"1.0\"?><w:document/>",
				method: 8,
			},
			Streamed {
				name: "[Content_Types].xml",
				content: b"<?xml version=\"1.0\"?><Types/>",
				method: 8,
			},
		],
		Descriptor::Signed,
		|_, _| {},
	);
	let raw = corpus::message(&[corpus::attachment(
		"Content-Type: application/vnd.openxmlformats-officedocument.wordprocessingml.document; name=\"informe.docx\"",
		&docx,
	)]);
	let report = crate::antispam::attachments::inspect(
		&raw,
		&crate::antispam::attachments::rules::Extensions::default(),
		crate::antispam::attachments::Budget::bytes(1 << 20),
	);
	assert_eq!(report.parts.len(), 1);
	assert_eq!(
		report.parts[0].real_type,
		crate::antispam::attachments::sniff::RealType::Ooxml
	);
	assert_eq!(report.reasons(), vec![], "a plain document is not flagged");
}

#[test]
fn a_descriptor_that_disagrees_with_the_directory_is_ambiguous() {
	let mut zip = streamed(&pdfs(), Descriptor::Signed, |_, _| {});
	let descriptor = zip
		.windows(4)
		.rposition(|window| window == b"PK\x07\x08")
		.expect("descriptor");
	zip[descriptor + 8] ^= 0x01;
	assert!(list_zip(&zip).ambiguous);
}

#[test]
fn a_local_header_inside_described_data_is_ambiguous() {
	// A streaming extractor that trusts where the deflate stream ends could
	// find this header; the central directory never names it.
	let zip = streamed(&pdfs(), Descriptor::Signed, |index, data| {
		if index == 1 {
			data.extend_from_slice(b"PK\x03\x04hidden evil.js");
		}
	});
	let listing = list_zip(&zip);
	assert!(listing.ambiguous, "{listing:?}");
	let clean = list_zip(&streamed(&pdfs(), Descriptor::Signed, |_, _| {}));
	assert!(
		!clean.ambiguous,
		"the same zip without the header is simple"
	);
}

#[test]
fn stored_data_behind_a_descriptor_is_ambiguous() {
	// Nothing but a guess tells a streaming extractor where stored data
	// ends; an empty entry is the one case with nothing to guess.
	let stored = [Streamed {
		name: "a.pdf",
		content: b"%PDF-1.7\n%%EOF\n",
		method: 0,
	}];
	assert!(list_zip(&streamed(&stored, Descriptor::Signed, |_, _| {})).ambiguous);
	let empty = [Streamed {
		name: "dir/",
		content: b"",
		method: 0,
	}];
	assert!(!list_zip(&streamed(&empty, Descriptor::Signed, |_, _| {})).ambiguous);
	assert!(list_zip(&streamed(&empty, Descriptor::Bare, |_, _| {})).ambiguous);
}
