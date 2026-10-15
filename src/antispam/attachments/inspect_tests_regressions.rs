//! Every evasion found so far, in one table: each message must keep the
//! reason it earned, so a later change that weakens a check fails here.

use super::*;
use crate::antispam::attachments::corpus::{self, ZipEntry, attachment};

fn one(headers: &str, content: &[u8]) -> Vec<u8> {
	corpus::message(&[attachment(headers, content)])
}

fn zip_part(zip: Vec<u8>) -> Vec<u8> {
	one("Content-Type: application/zip; name=a.zip", &zip)
}

fn raw(text: &str) -> Vec<u8> {
	text.as_bytes().to_vec()
}

fn many_parts_then(payload: &str) -> Vec<u8> {
	let mut text = String::from("Content-Type: multipart/mixed; boundary=p\r\n\r\n");
	for _ in 0..MAX_PARTS {
		text.push_str("--p\r\nContent-Type: text/plain\r\n\r\nx\r\n");
	}
	text.push_str(payload);
	text.into_bytes()
}

fn nested(levels: usize) -> Vec<u8> {
	let mut text = String::new();
	for level in 0..levels {
		text.push_str(&format!(
			"Content-Type: multipart/mixed; boundary=\"n{level}\"\r\n\r\n--n{level}\r\n"
		));
	}
	text.push_str("Content-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n");
	text.into_bytes()
}

fn prefixed(prefix: &[u8], zip: Vec<u8>) -> Vec<u8> {
	let mut out = prefix.to_vec();
	out.extend_from_slice(&zip);
	out
}

fn central_local_mismatch() -> Vec<u8> {
	let mut zip = corpus::zip_of(&["aaaaa.txt"]);
	zip[36..39].copy_from_slice(b"exe");
	zip
}

fn local_only_entry() -> Vec<u8> {
	let big = corpus::zip_of(&["a.txt", "evil.js"]);
	let small = corpus::zip_of(&["a.txt"]);
	let cut = |zip: &[u8]| {
		zip.windows(4)
			.position(|w| w == b"PK\x01\x02")
			.expect("directory")
	};
	let mut zip = big[..cut(&big)].to_vec();
	zip.extend_from_slice(&small[cut(&small)..]);
	zip
}

fn unknown_method() -> Vec<u8> {
	let mut zip = corpus::zip_of(&["a.txt"]);
	let central = zip
		.windows(4)
		.position(|w| w == b"PK\x01\x02")
		.expect("directory");
	zip[8..10].copy_from_slice(&77u16.to_le_bytes());
	zip[central + 10..central + 12].copy_from_slice(&77u16.to_le_bytes());
	zip
}

fn ole2_encrypted() -> Vec<u8> {
	corpus::ole2("EncryptedPackage")
}

fn uu_text() -> Vec<u8> {
	raw(&format!(
		"Content-Type: text/plain\r\n\r\nhello\r\n{}",
		corpus::uu("run.exe", &corpus::pe())
	))
}

#[test]
fn every_known_evasion_keeps_its_verdict() {
	use Reason::*;
	let pe = corpus::pe();
	let pdf_and_zip = prefixed(&corpus::pdf(), corpus::zip_of(&["x.js"]));
	let cases: Vec<(&str, Vec<u8>, Reason)> = vec![
		(
			"exe renamed as jpg",
			one("Content-Type: image/jpeg; name=a.jpg", &pe),
			ExecutableContent,
		),
		(
			"exe renamed as jpg mismatch",
			one("Content-Type: image/jpeg; name=a.jpg", &pe),
			TypeMismatch,
		),
		(
			"script in zip",
			one(
				"Content-Type: application/zip; name=a.zip",
				&corpus::zip_of(&["x.js"]),
			),
			DangerousArchiveEntry,
		),
		(
			"double extension",
			one(
				"Content-Type: application/pdf; name=\"f.pdf.exe\"",
				b"%PDF-1.4",
			),
			DoubleExtension,
		),
		(
			"trailing dot",
			one(
				"Content-Type: application/octet-stream; name=\"f.exe.\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"trailing space",
			one(
				"Content-Type: application/octet-stream; name=\"f.pdf .exe\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"right-to-left override",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?a=E2=80=AEgpj.exe?=\"",
				b"x",
			),
			BidiName,
		),
		(
			"zero-width inside the extension",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?a.e=E2=80=8Bxe?=\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"full-width dot",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?a=EF=BC=8Eexe?=\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"ideographic full stop",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?a=E3=80=82scr?=\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"full-width letters",
			one(
				"Content-Type: application/octet-stream; name=\"=?utf-8?q?a.=EF=BD=85=EF=BD=98=EF=BD=85?=\"",
				b"x",
			),
			DangerousExtension,
		),
		(
			"NUL in an encoded name",
			one(
				"Content-Type: application/octet-stream\r\nContent-Disposition: attachment; filename*=utf-8''a.exe%00.txt",
				b"x",
			),
			DangerousExtension,
		),
		(
			"NUL in an entry name",
			one(
				"Content-Type: application/zip; name=a.zip",
				&corpus::zip_of(&["a.exe\0.txt"]),
			),
			DangerousArchiveEntry,
		),
		(
			"macro document",
			one(
				"Content-Type: application/zip; name=q.docm",
				&corpus::zip_of(&["[Content_Types].xml", "word/vbaProject.bin"]),
			),
			Macro,
		),
		(
			"macro in OLE2",
			one(
				"Content-Type: application/msword; name=a.doc",
				&corpus::ole2("_VBA_PROJECT"),
			),
			Macro,
		),
		(
			"encrypted Office document",
			one(
				"Content-Type: application/msword; name=a.doc",
				&ole2_encrypted(),
			),
			EncryptedArchive,
		),
		(
			"truncated OLE2",
			one(
				"Content-Type: application/msword; name=a.doc",
				&corpus::ole2("WordDocument")[..700],
			),
			UnreadableArchive,
		),
		(
			"encrypted zip",
			one(
				"Content-Type: application/zip; name=a.zip",
				&corpus::zip(&[ZipEntry {
					name: "a.pdf",
					encrypted: true,
				}]),
			),
			EncryptedArchive,
		),
		(
			"mixed encryption",
			one(
				"Content-Type: application/zip; name=a.zip",
				&corpus::zip(&[
					ZipEntry {
						name: "a.txt",
						encrypted: false,
					},
					ZipEntry {
						name: "b.pdf",
						encrypted: true,
					},
				]),
			),
			AmbiguousArchive,
		),
		(
			"nested archive",
			one(
				"Content-Type: application/zip; name=a.zip",
				&corpus::zip_of(&["inner.7z"]),
			),
			NestedArchive,
		),
		(
			"rar",
			one(
				"Content-Type: application/x-rar; name=a.rar",
				b"Rar!\x1a\x07\x01\x00",
			),
			UnreadableArchive,
		),
		(
			"zip with data in front",
			one(
				"Content-Type: application/octet-stream; name=a.dat",
				&prefixed(b"junk ", corpus::zip_of(&["x.js"])),
			),
			DangerousArchiveEntry,
		),
		(
			"pdf and zip polyglot",
			one("Content-Type: application/pdf; name=a.pdf", &pdf_and_zip),
			DangerousArchiveEntry,
		),
		(
			"central and local names differ",
			one(
				"Content-Type: application/zip; name=a.zip",
				&central_local_mismatch(),
			),
			DangerousArchiveEntry,
		),
		(
			"entry only in local headers",
			one(
				"Content-Type: application/zip; name=a.zip",
				&local_only_entry(),
			),
			DangerousArchiveEntry,
		),
		(
			"unknown compression method",
			one(
				"Content-Type: application/zip; name=a.zip",
				&unknown_method(),
			),
			UnreadableArchive,
		),
		(
			"image the bytes do not confirm",
			one("Content-Type: image/png; name=a.png", b"not a png"),
			TypeMismatch,
		),
		(
			"pdf the bytes do not confirm",
			one("Content-Type: application/pdf; name=a.pdf", b"not a pdf"),
			TypeMismatch,
		),
		(
			"program in a text part",
			raw(
				"Content-Type: text/plain\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAA=\r\n",
			),
			ExecutableContent,
		),
		(
			"uuencoded file in a text body",
			uu_text(),
			ExecutableContent,
		),
		(
			"name and filename disagree",
			one(
				"Content-Type: application/pdf; name=a.exe\r\nContent-Disposition: attachment; filename=a.pdf",
				b"%PDF-1.4",
			),
			DangerousExtension,
		),
		(
			"second Content-Type claims an image",
			raw(
				"Content-Type: text/plain\r\nContent-Type: image/png\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAA=\r\n",
			),
			TypeMismatch,
		),
		(
			"unparsable Content-Type",
			raw("Content-Type: ;;;\r\nContent-Transfer-Encoding: base64\r\n\r\nTVqQAAMAAAA=\r\n"),
			ExecutableContent,
		),
		(
			"repeated Content-Disposition",
			raw(
				"Content-Disposition: inline\r\nContent-Disposition: attachment; filename=a.exe\r\n\r\nMZ\r\n",
			),
			AmbiguousMime,
		),
		(
			"delimiter in other case",
			raw(
				"Content-Type: multipart/mixed; boundary=abc\r\n\r\n--abc\r\nContent-Type: text/plain\r\n\r\nhi\r\n--ABC\r\nContent-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n--abc--\r\n",
			),
			AmbiguousMime,
		),
		(
			"unknown transfer encoding",
			one(
				"Content-Type: application/octet-stream; name=a.bin\r\nContent-Transfer-Encoding: x-gzip64",
				b"x",
			),
			AmbiguousMime,
		),
		(
			"base64 glued after padding",
			raw(
				"Content-Type: application/octet-stream; name=a.bin\r\nContent-Transfer-Encoding: base64\r\n\r\nTVo=\r\nkAA=\r\n",
			),
			AmbiguousMime,
		),
		(
			"invalid quoted-printable escape",
			raw(
				"Content-Type: application/octet-stream; name=a.bin\r\nContent-Transfer-Encoding: quoted-printable\r\n\r\nMZ=ZZ\r\n",
			),
			AmbiguousMime,
		),
		(
			"multipart without a boundary",
			raw("Content-Type: multipart/mixed\r\n\r\nMZ\r\n"),
			AmbiguousMime,
		),
		(
			"payload past the part cap",
			many_parts_then(
				"--p\r\nContent-Type: application/octet-stream; name=a.exe\r\n\r\nMZ\r\n",
			),
			ScanLimit,
		),
		(
			"nesting past the depth cap",
			nested(MAX_DEPTH + 1),
			ScanLimit,
		),
		(
			"encoded message hiding a file",
			one(
				"Content-Type: message/rfc822; name=f.eml",
				&one("Content-Type: application/octet-stream; name=x.exe", b"x"),
			),
			DangerousExtension,
		),
		(
			"fake end record in the zip comment",
			zip_part(archive::tests_sources::fake_end_record_in_comment()),
			DangerousArchiveEntry,
		),
		(
			"fake end record is ambiguous",
			zip_part(archive::tests_sources::fake_end_record_in_comment()),
			AmbiguousArchive,
		),
		(
			"fake end record before the real directory",
			zip_part(archive::tests_sources::earlier_fake_end_record()),
			DangerousArchiveEntry,
		),
		(
			"directory offset into prefixed data",
			zip_part(archive::tests_sources::offset_into_prefixed_data()),
			AmbiguousArchive,
		),
		(
			"unicode path field",
			zip_part(archive::tests_sources::unicode_path_differs()),
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
