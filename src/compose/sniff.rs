//! The content type of an attachment its sender left out: from the first
//! bytes when they carry a known signature, else from the file name.

/// Signatures at the start of the data, checked first: the bytes are what
/// the receiving client will open, whatever the name says.
const MAGIC: &[(&[u8], &str)] = &[
	(b"%PDF-", "application/pdf"),
	(b"\x89PNG\r\n\x1a\n", "image/png"),
	(b"\xff\xd8\xff", "image/jpeg"),
	(b"GIF87a", "image/gif"),
	(b"GIF89a", "image/gif"),
	(b"PK\x03\x04", "application/zip"),
	(b"\x1f\x8b", "application/gzip"),
	(b"BEGIN:VCALENDAR", "text/calendar"),
];

/// File extensions, lowercase, for data with no known signature.
const EXTENSIONS: &[(&str, &str)] = &[
	("txt", "text/plain"),
	("csv", "text/csv"),
	("htm", "text/html"),
	("html", "text/html"),
	("ics", "text/calendar"),
	("json", "application/json"),
	("xml", "application/xml"),
	("pdf", "application/pdf"),
	("zip", "application/zip"),
	("gz", "application/gzip"),
	("png", "image/png"),
	("jpg", "image/jpeg"),
	("jpeg", "image/jpeg"),
	("gif", "image/gif"),
	("webp", "image/webp"),
	("svg", "image/svg+xml"),
	("eml", "message/rfc822"),
	(
		"docx",
		"application/vnd.openxmlformats-officedocument.wordprocessingml.document",
	),
	(
		"xlsx",
		"application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
	),
];

/// The content type for an attachment named `name` holding `data`;
/// `application/octet-stream` when neither tells.
pub fn content_type_for(name: Option<&str>, data: &[u8]) -> &'static str {
	if let Some((_, kind)) = MAGIC.iter().find(|(magic, _)| data.starts_with(magic)) {
		// A docx or xlsx is a zip; the name says which.
		if *kind == "application/zip"
			&& let Some(by_name) = by_extension(name)
			&& by_name.starts_with("application/vnd.openxmlformats")
		{
			return by_name;
		}
		return kind;
	}
	by_extension(name).unwrap_or("application/octet-stream")
}

fn by_extension(name: Option<&str>) -> Option<&'static str> {
	let (_, extension) = name?.rsplit_once('.')?;
	let extension = extension.to_ascii_lowercase();
	EXTENSIONS
		.iter()
		.find(|(known, _)| *known == extension)
		.map(|(_, kind)| *kind)
}
