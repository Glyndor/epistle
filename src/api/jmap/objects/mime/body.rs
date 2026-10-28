//! RFC 8621 section 4.1.4 body selection, including nested alternatives.

use mail_parser::Message;
use serde_json::Value;

type Parts<'a> = Vec<&'a Value>;

pub(super) fn lists(tree: &Value) -> (Parts<'_>, Parts<'_>, Parts<'_>) {
	let (mut text, mut html, mut attachments) = (Vec::new(), Vec::new(), Vec::new());
	parse_structure(
		std::slice::from_ref(tree),
		"mixed",
		false,
		Some(&mut text),
		Some(&mut html),
		&mut attachments,
	);
	(text, html, attachments)
}

fn inline_media(media_type: &str) -> bool {
	["image/", "audio/", "video/"]
		.iter()
		.any(|prefix| media_type.starts_with(prefix))
}

fn parse_structure<'a>(
	parts: &'a [Value],
	multipart: &str,
	in_alternative: bool,
	mut text: Option<&mut Parts<'a>>,
	mut html: Option<&mut Parts<'a>>,
	attachments: &mut Parts<'a>,
) {
	let text_length = text.as_ref().map_or(0, |v| v.len());
	let html_length = html.as_ref().map_or(0, |v| v.len());
	for (index, part) in parts.iter().enumerate() {
		let media_type = part["type"].as_str().unwrap_or("");
		let media = inline_media(media_type);
		let inline = part["disposition"] != "attachment"
			&& (media_type == "text/plain" || media_type == "text/html" || media)
			&& (index == 0 || (multipart != "related" && (media || part["name"].is_null())));
		if let Some(subtype) = media_type.strip_prefix("multipart/") {
			parse_structure(
				part["subParts"]
					.as_array()
					.map(Vec::as_slice)
					.unwrap_or_default(),
				subtype,
				in_alternative || subtype == "alternative",
				text.as_deref_mut(),
				html.as_deref_mut(),
				attachments,
			);
		} else if inline {
			if multipart == "alternative" {
				match media_type {
					"text/plain" => {
						if let Some(text) = text.as_mut() {
							text.push(part);
						}
					}
					"text/html" => {
						if let Some(html) = html.as_mut() {
							html.push(part);
						}
					}
					_ => attachments.push(part),
				}
				continue;
			}
			if in_alternative {
				if media_type == "text/plain" {
					html = None;
				}
				if media_type == "text/html" {
					text = None;
				}
			}
			if let Some(text) = text.as_mut() {
				text.push(part);
			}
			if let Some(html) = html.as_mut() {
				html.push(part);
			}
			if (text.is_none() || html.is_none()) && media {
				attachments.push(part);
			}
		} else {
			attachments.push(part);
		}
	}
	if multipart == "alternative"
		&& let (Some(text), Some(html)) = (text, html)
	{
		if text_length == text.len() && html_length != html.len() {
			text.extend_from_slice(&html[html_length..]);
		}
		if html_length == html.len() && text_length != text.len() {
			html.extend_from_slice(&text[text_length..]);
		}
	}
}

pub(super) fn preview(message: &Message<'_>, text: &[&Value]) -> String {
	let content = text
		.iter()
		.filter_map(|part| {
			let index = part["partId"].as_str()?.parse::<usize>().ok()?;
			let text = message.parts.get(index)?.text_contents()?;
			match part["type"].as_str()? {
				"text/html" => Some(mail_parser::decoders::html::html_to_text(text)),
				"text/plain" => Some(text.to_owned()),
				_ => None,
			}
		})
		.collect::<Vec<_>>()
		.join(" ");
	content
		.split_whitespace()
		.collect::<Vec<_>>()
		.join(" ")
		.chars()
		.take(256)
		.collect()
}
