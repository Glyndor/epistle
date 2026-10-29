//! The builder's output, read back with the same MIME parser JMAP uses.

use super::*;
use mail_parser::{MessageParser, MimeHeaders, PartType};

fn attachment(kind: &str, data: &[u8], name: Option<&str>) -> Leaf {
	Leaf {
		content_type: kind.to_string(),
		content: Content::Bytes(data.to_vec()),
		disposition: Some(Disposition::Attachment),
		name: name.map(str::to_string),
		content_id: None,
	}
}

fn build(bodies: Bodies) -> Vec<u8> {
	let headers = vec![unstructured("Subject", "s").expect("subject")];
	write(&headers, &bodies.assemble()).expect("write")
}

/// The content type of every part, depth first, as `type/subtype`.
fn shape(raw: &[u8]) -> Vec<String> {
	let message = MessageParser::default().parse(raw).expect("parse");
	message
		.parts
		.iter()
		.map(|part| {
			let ct = part.content_type().expect("content type");
			format!("{}/{}", ct.ctype(), ct.subtype().unwrap_or(""))
		})
		.collect()
}

#[test]
fn text_html_inline_and_attachment_nest_as_mixed_alternative_related() {
	let mut inline = attachment("image/png", b"\x89PNG", Some("logo.png"));
	inline.disposition = Some(Disposition::Inline);
	inline.content_id = Some("logo@x".into());
	let raw = build(Bodies {
		text: Some(Leaf::text("plain", "hi")),
		html: Some(Leaf::text("html", "<img src=\"cid:logo@x\">")),
		inline: vec![inline],
		attachments: vec![attachment("application/pdf", b"%PDF-1", Some("a.pdf"))],
	});
	assert_eq!(
		shape(&raw),
		[
			"multipart/mixed",
			"multipart/alternative",
			"text/plain",
			"multipart/related",
			"text/html",
			"image/png",
			"application/pdf"
		]
	);
	let text = String::from_utf8_lossy(&raw);
	assert!(text.contains("Content-ID: <logo@x>\r\n"), "{text}");
}

#[test]
fn no_body_is_one_empty_text_part_and_lone_inline_parts_are_attached() {
	assert_eq!(shape(&build(Bodies::default())), ["text/plain"]);
	let mut inline = attachment("image/png", b"x", None);
	inline.content_id = Some("c".into());
	let raw = build(Bodies {
		inline: vec![inline],
		..Bodies::default()
	});
	assert_eq!(shape(&raw), ["multipart/mixed", "text/plain", "image/png"]);
}

#[test]
fn text_outside_ascii_and_long_lines_round_trip_through_quoted_printable() {
	let body = format!("Grüße, {}\n= trailing space \nend", "x".repeat(300));
	let raw = build(Bodies {
		text: Some(Leaf::text("plain", &body)),
		..Bodies::default()
	});
	let text = String::from_utf8_lossy(&raw);
	assert!(text.contains("Content-Transfer-Encoding: quoted-printable"));
	assert!(
		text.split("\r\n").all(|line| line.len() <= 76),
		"every encoded line fits in 76 characters"
	);
	let message = MessageParser::default().parse(&raw).expect("parse");
	assert_eq!(
		message.body_text(0).expect("text").as_ref(),
		body.replace('\n', "\r\n")
	);
}

#[test]
fn binary_attachments_round_trip_byte_for_byte() {
	let data: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
	let raw = build(Bodies {
		attachments: vec![attachment("application/octet-stream", &data, Some("b.bin"))],
		..Bodies::default()
	});
	let message = MessageParser::default().parse(&raw).expect("parse");
	let part = message.attachment(0).expect("attachment");
	assert_eq!(part.contents(), data.as_slice());
}

#[test]
fn long_or_non_ascii_file_names_use_rfc_2231_and_read_back() {
	let name = format!("Überweisung {} März.pdf", "lang ".repeat(20));
	let raw = build(Bodies {
		attachments: vec![attachment("application/pdf", b"%PDF", Some(&name))],
		..Bodies::default()
	});
	let text = String::from_utf8_lossy(&raw);
	assert!(text.contains("filename*0*=utf-8''"), "{text}");
	assert!(text.split("\r\n").all(|line| line.len() <= 78), "{text}");
	let message = MessageParser::default().parse(&raw).expect("parse");
	let part = message.attachment(0).expect("attachment");
	assert_eq!(part.attachment_name(), Some(name.as_str()));
}

#[test]
fn an_attached_message_stays_unencoded() {
	let inner = "From: a@x\nSubject: inner é\n\nbody\n".as_bytes();
	let raw = build(Bodies {
		attachments: vec![attachment("message/rfc822", inner, None)],
		..Bodies::default()
	});
	let text = String::from_utf8_lossy(&raw);
	assert!(text.contains("Content-Type: message/rfc822\r\nContent-Transfer-Encoding: 8bit"));
	let message = MessageParser::default().parse(&raw).expect("parse");
	assert!(matches!(message.parts[2].body, PartType::Message(_)));
	let long = format!("Subject: {}\r\n\r\nx", "y".repeat(1000));
	let refused = write(
		&[],
		&Part::Leaf(attachment("message/rfc822", long.as_bytes(), None)),
	);
	assert_eq!(refused.unwrap_err(), ComposeError::LongLine);
}

#[test]
fn line_breaks_and_multipart_leaves_are_refused() {
	assert_eq!(
		unstructured("Subject", "a\r\nBcc: x@y").unwrap_err(),
		ComposeError::HeaderBreak
	);
	assert_eq!(
		structured("In-Reply-To", "<a@b>\nX: y").unwrap_err(),
		ComposeError::HeaderBreak
	);
	assert_eq!(
		address_list("To", &["a@b\r\nBcc: c@d".into()]).unwrap_err(),
		ComposeError::HeaderBreak
	);
	let named = attachment("text/plain", b"x", Some("a\r\nX-Evil: 1"));
	assert_eq!(
		write(&[], &Part::Leaf(named)).unwrap_err(),
		ComposeError::HeaderBreak
	);
	let multipart_leaf = attachment("multipart/mixed", b"x", None);
	assert!(matches!(
		write(&[], &Part::Leaf(multipart_leaf)),
		Err(ComposeError::ContentType(_))
	));
	let mut bad_cid = attachment("image/png", b"x", None);
	bad_cid.content_id = Some("a> <b".into());
	assert_eq!(
		write(&[], &Part::Leaf(bad_cid)).unwrap_err(),
		ComposeError::ContentId
	);
}

#[test]
fn ascii_values_fold_at_78_and_others_become_encoded_words() {
	let long = "word ".repeat(40);
	let line = unstructured("Subject", long.trim_end()).expect("fold");
	assert!(line.split("\r\n").all(|l| l.len() <= 78), "{line}");
	assert_eq!(
		line.replace("\r\n", ""),
		format!("Subject: {}", long.trim_end())
	);
	assert_eq!(
		unstructured("Subject", "Grüße").expect("encode"),
		"Subject: =?UTF-8?B?R3LDvMOfZQ==?=\r\n"
	);
}

#[test]
fn a_missing_content_type_comes_from_the_bytes_then_the_name() {
	assert_eq!(
		content_type_for(Some("x.bin"), b"%PDF-1.7"),
		"application/pdf"
	);
	assert_eq!(content_type_for(Some("photo.JPG"), b"??"), "image/jpeg");
	assert_eq!(
		content_type_for(Some("r.docx"), b"PK\x03\x04"),
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document"
	);
	assert_eq!(
		content_type_for(Some("r.pdf"), b"PK\x03\x04"),
		"application/zip"
	);
	assert_eq!(content_type_for(None, b"??"), "application/octet-stream");
}

#[test]
fn a_folded_address_is_unfolded_and_folded_again_without_a_blank_line() {
	let name = crate::util::encoded_word::encode(&"é".repeat(30));
	assert!(name.contains("\r\n "), "a long name arrives folded");
	let line = address_list("To", &[format!("{name} <jane@example.org>")]).expect("folded");
	assert!(!line.contains("\r\n\r\n"), "{line:?}");
	assert!(
		line.split("\r\n")
			.skip(1)
			.all(|l| l.is_empty() || l.starts_with(' '))
	);
}
