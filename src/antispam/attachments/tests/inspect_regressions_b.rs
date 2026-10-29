//! The archive and image evasions of the regression table, kept in their
//! own file so each table stays readable.

use super::*;
use crate::antispam::attachments::tests::corpus;

fn one(headers: &str, content: &[u8]) -> Vec<u8> {
	corpus::message(&[corpus::attachment(headers, content)])
}

fn zip_part(zip: Vec<u8>) -> Vec<u8> {
	one("Content-Type: application/zip; name=a.zip", &zip)
}

fn prefixed(prefix: &[u8], zip: Vec<u8>) -> Vec<u8> {
	let mut out = prefix.to_vec();
	out.extend_from_slice(&zip);
	out
}

#[test]
fn every_known_archive_and_image_evasion_keeps_its_verdict() {
	use Reason::*;
	let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
		(
			"fake end record in the zip comment",
			zip_part(archive::tests::sources::fake_end_record_in_comment()),
			DangerousArchiveEntry,
		),
		(
			"fake end record is ambiguous",
			zip_part(archive::tests::sources::fake_end_record_in_comment()),
			AmbiguousArchive,
		),
		(
			"fake end record before the real directory",
			zip_part(archive::tests::sources::earlier_fake_end_record()),
			DangerousArchiveEntry,
		),
		(
			"directory offset into prefixed data",
			zip_part(archive::tests::sources::offset_into_prefixed_data()),
			AmbiguousArchive,
		),
		(
			"unicode path field",
			zip_part(archive::tests::sources::unicode_path_differs()),
			DangerousArchiveEntry,
		),
		(
			"self-extracting stub in front",
			zip_part(prefixed(&corpus::pe(), corpus::zip_of(&["x.vbs"]))),
			DangerousArchiveEntry,
		),
		(
			"invalid utf-8 that claims utf-8",
			zip_part(corpus::zip_raw(&[corpus::RawEntry {
				name: b"a\xff.exe",
				flags: 0x0800,
				central_extra: Vec::new(),
			}])),
			AmbiguousArchive,
		),
		(
			"entry name longer than the cap",
			zip_part(corpus::zip_raw(&[corpus::RawEntry {
				name: &[b"a".repeat(1100), b".exe".to_vec()].concat(),
				flags: 0,
				central_extra: Vec::new(),
			}])),
			DangerousArchiveEntry,
		),
		(
			"svg with an event handler named as a png",
			one(
				"Content-Type: image/png; name=logo.png",
				b"<svg xmlns='http://www.w3.org/2000/svg' onload='go()'/>",
			),
			ActiveImage,
		),
		(
			"svg with an encoded script url",
			one(
				"Content-Type: image/svg+xml; name=a.svg",
				b"<svg><a href='&#x6a;ava&#9;script:go()'>x</a></svg>",
			),
			ActiveImage,
		),
		(
			"png with a program after IEND",
			one(
				"Content-Type: image/png; name=a.png",
				&image::tests::base::png_then(&image::tests::base::pe_header()),
			),
			AppendedPayload,
		),
		(
			"jpeg with a zip after its end",
			one(
				"Content-Type: image/jpeg; name=a.jpg",
				&image::tests::base::jpeg_then(&corpus::zip_of(&["x.js"])),
			),
			AppendedPayload,
		),
		(
			"gif with an elf after its trailer",
			one(
				"Content-Type: image/gif; name=a.gif",
				&image::tests::base::gif_then(b"\x7fELF\x02"),
			),
			AppendedPayload,
		),
		(
			"webp with a script past its size",
			one(
				"Content-Type: image/webp; name=a.webp",
				&image::tests::base::webp_then(b"#!/bin/sh\n"),
			),
			AppendedPayload,
		),
		(
			"gzip svg with an event handler",
			one(
				"Content-Type: image/svg+xml; name=a.svgz",
				&svg::tests::base::gzip(b"<svg onload='go()'/>"),
			),
			ActiveImage,
		),
		(
			"broken gzip svg",
			one(
				"Content-Type: application/octet-stream; name=a.svgz",
				b"\x1f\x8b\x08 broken",
			),
			ActiveImage,
		),
		(
			"utf-16 svg with a script",
			one(
				"Content-Type: image/png; name=a.png",
				&svg::tests::base::utf16("<svg><script>go()</script></svg>", true, true),
			),
			ActiveImage,
		),
		(
			"svg root after a long comment",
			one(
				"Content-Type: image/png; name=a.png",
				format!("<!--{}--><svg onload='go()'/>", "c".repeat(4000)).as_bytes(),
			),
			ActiveImage,
		),
		(
			"svg with a prefixed script",
			one(
				"Content-Type: image/svg+xml; name=a.svg",
				b"<x:svg xmlns:x='u'><x:script>go()</x:script></x:svg>",
			),
			ActiveImage,
		),
		(
			"svg with entity declarations",
			one(
				"Content-Type: image/svg+xml; name=a.svg",
				b"<!DOCTYPE svg [<!ENTITY a 'x'>]><svg/>",
			),
			ActiveImage,
		),
		(
			"jpeg with a fake end in an APP segment",
			one(
				"Content-Type: image/jpeg; name=a.jpg",
				&[
					&[0xffu8, 0xd8, 0xff, 0xe1, 0x00, 0x06, 0xff, 0xd9, 0x00, 0x00][..],
					&image::tests::base::jpeg_then(&image::tests::base::pe_header())[2..],
				]
				.concat(),
			),
			AppendedPayload,
		),
		(
			"png with a chunk length past the file",
			one("Content-Type: image/png; name=a.png", &{
				let mut png = image::tests::base::png_then(b"");
				png[8..12].copy_from_slice(&0x7fff_ffffu32.to_be_bytes());
				png
			}),
			AmbiguousImage,
		),
		(
			"webp whose size runs past the file",
			one("Content-Type: image/webp; name=a.webp", &{
				let mut webp = image::tests::base::webp_then(b"");
				webp[4..8].copy_from_slice(&4096u32.to_le_bytes());
				webp
			}),
			AmbiguousImage,
		),
		(
			"plain svg attachment",
			one(
				"Content-Type: image/svg+xml; name=logo.svg",
				b"<svg xmlns='http://www.w3.org/2000/svg'><rect/></svg>",
			),
			ActiveImage,
		),
		(
			"svg bytes behind a png claim are a mismatch",
			one(
				"Content-Type: image/png; name=logo.png",
				b"<svg><rect/></svg>",
			),
			TypeMismatch,
		),
		(
			"svg name read through a full-width dot",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?logo=EF=BC=8Esvg?=\"",
				b"x",
			),
			ActiveImage,
		),
		(
			"svg nested inside another xml root",
			one(
				"Content-Type: application/xml; name=doc.xml",
				b"<?xml version='1.0'?><doc><svg/></doc>",
			),
			ActiveImage,
		),
		(
			"utf-16 svg without a byte-order mark",
			one(
				"Content-Type: application/octet-stream; name=a.bin",
				&svg::tests::base::utf16("<svg/>", false, false),
			),
			ActiveImage,
		),
		(
			"svg by declared type only",
			one("Content-Type: image/svg+xml; name=a.bin", b"x"),
			ActiveImage,
		),
	];
	let mut failures = Vec::new();
	for (name, message, expected) in &cases {
		let reasons = inspect(message, &Extensions::default(), Budget::bytes(1 << 20)).reasons();
		if !reasons.contains(expected) {
			failures.push(format!(
				"{name}: expected {} in {reasons:?}",
				expected.code()
			));
		}
	}
	assert!(failures.is_empty(), "{}", failures.join("\n"));
}
