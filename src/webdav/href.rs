use percent_encoding::{AsciiSet, NON_ALPHANUMERIC, utf8_percent_encode};
use std::path::Path;

const SEGMENT: &AsciiSet = &NON_ALPHANUMERIC
	.remove(b'-')
	.remove(b'.')
	.remove(b'_')
	.remove(b'~');

pub(super) fn segment(name: &str) -> String {
	utf8_percent_encode(name, SEGMENT).to_string()
}

pub(super) fn canonical(uri_path: &str) -> Option<String> {
	let decoded = percent_encoding::percent_decode_str(uri_path)
		.decode_utf8()
		.ok()?;
	Some(
		decoded
			.split('/')
			.map(segment)
			.collect::<Vec<_>>()
			.join("/"),
	)
}

pub(super) fn resource(root: &Path, disk: &Path) -> Option<String> {
	let relative = disk.strip_prefix(root).ok()?;
	let segments = relative
		.components()
		.map(|part| part.as_os_str().to_str().map(segment))
		.collect::<Option<Vec<_>>>()?;
	Some(format!("/{}", segments.join("/")))
}
