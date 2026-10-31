use super::fetch_envelope::{exact, selected};

const LIMIT: usize = 64;
const EMPTY_ENVELOPE: &str = "(NIL NIL NIL NIL NIL NIL NIL NIL NIL NIL)";

fn multipart(levels: usize) -> (Vec<u8>, Vec<usize>) {
	let mut raw = Vec::new();
	let mut body_offsets = Vec::new();
	for depth in 0..levels {
		raw.extend_from_slice(
			format!("Content-Type: multipart/mixed; boundary=b{depth}\r\n\r\n").as_bytes(),
		);
		body_offsets.push(raw.len());
		raw.extend_from_slice(format!("--b{depth}\r\n").as_bytes());
	}
	raw.extend_from_slice(b"Subject: leaf\r\n\r\nx");
	let mut ends = vec![0; levels];
	for depth in (0..levels).rev() {
		// The parser excludes the CRLF preceding a parent's boundary.
		ends[depth] = raw.len();
		raw.extend_from_slice(format!("\r\n--b{depth}--").as_bytes());
	}
	raw.extend_from_slice(b"\r\n");
	let sizes = (0..levels)
		.map(|depth| {
			let end = if depth == 0 {
				raw.len()
			} else {
				ends[depth - 1]
			};
			end - body_offsets[depth]
		})
		.collect();
	(raw, sizes)
}

fn encapsulated(levels: usize) -> (Vec<u8>, Vec<usize>) {
	let header = b"Content-Type: message/rfc822\r\n\r\n";
	let mut raw = header.repeat(levels);
	raw.extend_from_slice(b"Subject: leaf\r\n\r\nx");
	let sizes = (0..levels)
		.map(|depth| raw.len() - (depth + 1) * header.len())
		.collect();
	(raw, sizes)
}

fn structure(sizes: &[usize], multipart: bool, extensions: bool) -> String {
	let extra = if extensions { " NIL NIL NIL NIL" } else { "" };
	let mut out = format!(
		"(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" {}{extra})",
		sizes[LIMIT]
	);
	for depth in (0..LIMIT).rev() {
		out = if multipart {
			let extra = if extensions {
				format!(" (\"BOUNDARY\" \"b{depth}\") NIL NIL NIL")
			} else {
				String::new()
			};
			format!("({out} \"MIXED\"{extra})")
		} else {
			let envelope = if depth + 1 == LIMIT {
				"NIL"
			} else {
				EMPTY_ENVELOPE
			};
			let lines = (sizes.len() - depth - 1) * 2 + 2;
			format!(
				"(\"MESSAGE\" \"RFC822\" NIL NIL NIL \"7BIT\" {} {envelope} {out} {lines}{extra})",
				sizes[depth]
			)
		};
	}
	out
}

fn check_structure(levels: usize, is_multipart: bool) {
	let (raw, sizes) = if is_multipart {
		multipart(levels)
	} else {
		encapsulated(levels)
	};
	let (_dir, mut session) = selected(&raw);
	for extensions in [false, true] {
		let label = if extensions { "BODYSTRUCTURE" } else { "BODY" };
		let expected = format!(
			"* 1 FETCH ({label} {})\r\nf OK FETCH completed\r\n",
			structure(&sizes, is_multipart, extensions)
		);
		exact(
			&mut session,
			&format!("f FETCH 1 ({label})"),
			expected.as_bytes(),
			"MIME structures must truncate at depth 64 with an exact opaque leaf and NIL nested envelope",
		);
	}
	exact(
		&mut session,
		"f FETCH 1 (ENVELOPE)",
		format!("* 1 FETCH (ENVELOPE {EMPTY_ENVELOPE})\r\nf OK FETCH completed\r\n").as_bytes(),
		"ENVELOPE must return only the outer headers of a deeply nested message",
	);
}

fn check_section(levels: usize, is_multipart: bool) {
	let (raw, _) = if is_multipart {
		multipart(levels)
	} else {
		encapsulated(levels)
	};
	let (_dir, mut session) = selected(&raw);
	let path = vec!["1"; LIMIT + 1].join(".");
	exact(
		&mut session,
		&format!("f FETCH 1 (BODY.PEEK[{path}])"),
		format!("* 1 FETCH (BODY[{path}] {{0}}\r\n)\r\nf OK FETCH completed\r\n").as_bytes(),
		"a section path deeper than 64 must return an exact empty literal",
	);
}

fn small_stack(check: fn(usize, bool), is_multipart: bool) {
	std::thread::Builder::new()
		.stack_size(256 * 1024)
		.spawn(move || {
			// Check truncation first so regressions report the response assertion.
			check(LIMIT + 1, is_multipart);
			check(10_000, is_multipart);
		})
		.unwrap()
		.join()
		.unwrap();
}

#[test]
fn fetch_depth_multipart_structure() {
	small_stack(check_structure, true);
}

#[test]
fn fetch_depth_encapsulated_structure() {
	small_stack(check_structure, false);
}

#[test]
fn fetch_depth_multipart_section() {
	small_stack(check_section, true);
}

#[test]
fn fetch_depth_encapsulated_section() {
	small_stack(check_section, false);
}

fn check_mixed_section(levels: usize, _: bool) {
	let mut raw = Vec::new();
	for depth in 0..levels {
		raw.extend_from_slice(
			format!("Content-Type: message/rfc822\r\n\r\nContent-Type: multipart/mixed; boundary=m{depth}\r\n\r\n--m{depth}\r\n").as_bytes(),
		);
	}
	raw.extend_from_slice(b"Subject: leaf\r\n\r\nx");
	for depth in (0..levels).rev() {
		raw.extend_from_slice(format!("\r\n--m{depth}--").as_bytes());
	}
	let (_dir, mut session) = selected(&raw);
	// One path component can cross both a message root and a multipart edge.
	let path = vec!["1"; LIMIT / 2 + 2].join(".");
	for (request, label, value) in [
		(
			format!("BODY.PEEK[{path}]"),
			format!("BODY[{path}]"),
			"{0}\r\n",
		),
		(
			format!("BODY.PEEK[{path}]<7.3>"),
			format!("BODY[{path}]<7>"),
			"{0}\r\n",
		),
		(
			format!("BINARY.PEEK[{path}]"),
			format!("BINARY[{path}]"),
			"{0}\r\n",
		),
		(
			format!("BINARY.SIZE[{path}]"),
			format!("BINARY.SIZE[{path}]"),
			"0",
		),
	] {
		exact(
			&mut session,
			&format!("f FETCH 1 ({request})"),
			format!("* 1 FETCH ({label} {value})\r\nf OK FETCH completed\r\n").as_bytes(),
			"mixed MIME edges past depth 64 must return exact empty section data",
		);
	}
	let path = vec!["1"; LIMIT / 2 + 1].join(".");
	exact(
		&mut session,
		&format!("f FETCH 1 (BODY.PEEK[{path}.HEADER])"),
		format!("* 1 FETCH (BODY[{path}.HEADER] {{0}}\r\n)\r\nf OK FETCH completed\r\n").as_bytes(),
		"a header suffix must not enter an encapsulated message beyond depth 64",
	);
}

#[test]
fn fetch_depth_mixed_section() {
	small_stack(check_mixed_section, false);
}

#[test]
fn fetch_depth_opaque_extensions() {
	std::thread::Builder::new()
		.stack_size(256 * 1024)
		.spawn(|| {
			let (mut raw, _) = multipart(LIMIT);
			let original = b"Subject: leaf\r\n\r\nx";
			let offset = raw.windows(original.len()).position(|v| v == original).unwrap();
			raw.splice(offset..offset + original.len(), b"Content-MD5: digest\r\nContent-Disposition: attachment; filename=file.bin\r\nContent-Language: en\r\nContent-Location: /file.bin\r\n\r\nx".iter().copied());
			let (_dir, mut session) = selected(&raw);
			for extensions in [false, true] {
				let extra = if extensions {
					" \"digest\" (\"ATTACHMENT\" (\"FILENAME\" \"file.bin\")) \"en\" \"/file.bin\""
				} else {
					""
				};
				let mut expected = format!("(\"APPLICATION\" \"OCTET-STREAM\" NIL NIL NIL \"7BIT\" 1{extra})");
				for depth in (0..LIMIT).rev() {
					let extra = if extensions {
						format!(" (\"BOUNDARY\" \"b{depth}\") NIL NIL NIL")
					} else {
						String::new()
					};
					expected = format!("({expected} \"MIXED\"{extra})");
				}
				let label = if extensions { "BODYSTRUCTURE" } else { "BODY" };
				exact(
					&mut session,
					&format!("f FETCH 1 ({label})"),
					format!("* 1 FETCH ({label} {expected})\r\nf OK FETCH completed\r\n").as_bytes(),
					"opaque cutoff leaves must preserve exact BODYSTRUCTURE extensions",
				);
			}
		})
		.unwrap()
		.join()
		.unwrap();
}
