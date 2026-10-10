//! FETCH section grammar, including nested field lists and byte ranges.

use super::parse::parse_astring;

/// A body section selector.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FetchSection {
	/// One-based MIME part path, empty for the whole message.
	pub path: Vec<u32>,
	/// Content selected within the MIME part.
	pub kind: SectionKind,
	/// Byte offset and maximum number of octets.
	pub partial: Option<(usize, usize)>,
	/// Do not set the Seen flag.
	pub peek: bool,
	/// Decode the content transfer encoding.
	pub binary: bool,
	/// Return the decoded octet count instead of data.
	pub size: bool,
}

/// A section suffix within a MIME part.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SectionKind {
	/// Whole message or part body.
	Entire,
	/// RFC 5322 headers, including the terminating blank line.
	Header,
	/// RFC 5322 body without headers.
	Text,
	/// MIME part headers, including the terminating blank line.
	Mime,
	/// Include or exclude the named header fields.
	Fields {
		/// Header names normalized to ASCII uppercase.
		names: Vec<String>,
		/// Exclude the named fields.
		exclude: bool,
	},
}

impl FetchSection {
	pub(crate) fn label(&self) -> String {
		let mut section = self
			.path
			.iter()
			.map(u32::to_string)
			.collect::<Vec<_>>()
			.join(".");
		let suffix = match &self.kind {
			SectionKind::Entire => String::new(),
			SectionKind::Header => "HEADER".into(),
			SectionKind::Text => "TEXT".into(),
			SectionKind::Mime => "MIME".into(),
			SectionKind::Fields { names, exclude } => format!(
				"HEADER.FIELDS{} ({})",
				if *exclude { ".NOT" } else { "" },
				names.join(" ")
			),
		};
		if !section.is_empty() && !suffix.is_empty() {
			section.push('.');
		}
		section.push_str(&suffix);
		let prefix = if self.size {
			"BINARY.SIZE"
		} else if self.binary {
			"BINARY"
		} else {
			"BODY"
		};
		let mut label = format!("{prefix}[{section}]");
		if let Some((start, _)) = self.partial {
			label.push_str(&format!("<{start}>"));
		}
		label
	}
}

pub(super) fn parse(word: &str) -> Option<FetchSection> {
	let (prefix, rest) = word.split_once('[')?;
	let prefix = prefix.to_ascii_uppercase();
	let (peek, binary, size) = match prefix.as_str() {
		"BODY" => (false, false, false),
		"BODY.PEEK" => (true, false, false),
		"BINARY" => (false, true, false),
		"BINARY.PEEK" => (true, true, false),
		"BINARY.SIZE" => (true, true, true),
		_ => return None,
	};
	let close = rest.rfind(']')?;
	let mut section = rest[..close].trim();
	let tail = &rest[close + 1..];
	let partial = if tail.is_empty() {
		None
	} else {
		if size {
			return None;
		}
		let (start, length) = tail.strip_prefix('<')?.strip_suffix('>')?.split_once('.')?;
		let start = decimal(start)?;
		let length = decimal(length)?;
		if length == 0 {
			return None;
		}
		Some((start, length))
	};
	let mut path = Vec::new();
	while section.as_bytes().first().is_some_and(u8::is_ascii_digit) {
		let end = section.find('.').unwrap_or(section.len());
		let number = decimal(&section[..end])?;
		if number == 0 {
			return None;
		}
		path.push(u32::try_from(number).ok()?);
		section = if end == section.len() {
			""
		} else {
			&section[end + 1..]
		};
		if end < rest[..close].len() && section.is_empty() && rest[..close].ends_with('.') {
			return None;
		}
	}
	let upper = section.to_ascii_uppercase();
	let kind = match upper.as_str() {
		"" => SectionKind::Entire,
		"HEADER" if !binary => SectionKind::Header,
		"TEXT" if !binary => SectionKind::Text,
		"MIME" if !binary && !path.is_empty() => SectionKind::Mime,
		_ if !binary => {
			let (key, fields) = section.split_once(' ')?;
			let exclude = match key.to_ascii_uppercase().as_str() {
				"HEADER.FIELDS" => false,
				"HEADER.FIELDS.NOT" => true,
				_ => return None,
			};
			let mut fields = fields.trim().strip_prefix('(')?.strip_suffix(')')?.trim();
			let mut names = Vec::new();
			while !fields.is_empty() {
				let (name, remaining) = parse_astring(fields)?;
				if name.is_empty() || !name.bytes().all(|b| b.is_ascii_graphic() && b != b':') {
					return None;
				}
				names.push(name.to_ascii_uppercase());
				fields = remaining.trim();
			}
			if names.is_empty() {
				return None;
			}
			SectionKind::Fields { names, exclude }
		}
		_ => return None,
	};
	Some(FetchSection {
		path,
		kind,
		partial,
		peek,
		binary,
		size,
	})
}

fn decimal(text: &str) -> Option<usize> {
	if text.is_empty() || !text.bytes().all(|b| b.is_ascii_digit()) {
		return None;
	}
	text.parse().ok()
}

pub(super) fn tokens(input: &str) -> Option<Vec<&str>> {
	let mut out = Vec::new();
	let mut start = None;
	let mut brackets = 0usize;
	let mut quoted = false;
	let mut escaped = false;
	for (i, ch) in input.char_indices() {
		if ch.is_ascii_whitespace() && brackets == 0 && !quoted {
			if let Some(start) = start.take() {
				out.push(&input[start..i]);
			}
			continue;
		}
		start.get_or_insert(i);
		if escaped {
			escaped = false;
			continue;
		}
		if ch == '\\' && quoted {
			escaped = true;
			continue;
		}
		if ch == '"' {
			quoted = !quoted;
		}
		if !quoted {
			if ch == '[' {
				brackets += 1;
			}
			if ch == ']' {
				brackets = brackets.checked_sub(1)?;
			}
		}
	}
	if brackets != 0 || quoted || escaped {
		return None;
	}
	if let Some(start) = start {
		out.push(&input[start..]);
	}
	Some(out)
}
