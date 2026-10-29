//! The YAML subset `openapi.yaml` is written in, read into JSON.
//!
//! The server embeds the OpenAPI description as YAML, which people read and
//! edit, and serves it as JSON, which clients parse. Pulling in a YAML crate
//! for that one file would add a dependency to the shipped binary, so this
//! reads only what the file uses and refuses everything else with the line
//! it stopped at, instead of guessing:
//!
//! - block mappings and block sequences, indented with spaces;
//! - plain, `"double"` and `'single'` quoted scalars on one line;
//! - the block scalars `|`, `|-`, `>` and `>-`;
//! - the flow forms `[]`, `{}` and `[a, "b"]` (scalars only);
//! - whole-line comments.
//!
//! Anchors, tags, trailing comments, multi-line flow collections, complex
//! keys and a sequence indented the same as its key are not accepted. A plain
//! scalar that YAML 1.1 and 1.2 would read differently (`yes`, `1e3`, `0x1F`)
//! must be quoted, so every YAML parser agrees on the file.

use serde_json::{Map, Number, Value};

/// Read `text` as one YAML document of the subset above.
pub(super) fn parse(text: &str) -> Result<Value, String> {
	let mut parser = Parser {
		lines: text.lines().map(str::to_owned).collect(),
		pos: 0,
	};
	for (at, line) in parser.lines.iter().enumerate() {
		if line
			.chars()
			.take_while(|c| c.is_whitespace())
			.any(|c| c == '\t')
		{
			return Err(format!("line {}: tabs cannot indent a line", at + 1));
		}
		if line
			.chars()
			.take_while(|c| c.is_whitespace())
			.any(|c| c != ' ')
		{
			return Err(format!("line {}: only spaces may indent a line", at + 1));
		}
	}
	let Some((indent, _)) = parser.current() else {
		return Err("the document is empty".into());
	};
	let value = parser.block(indent)?;
	match parser.current() {
		None => Ok(value),
		Some(_) => Err(parser.fail("unexpected content after the document")),
	}
}

struct Parser {
	lines: Vec<String>,
	pos: usize,
}

impl Parser {
	fn fail(&self, message: &str) -> String {
		format!("line {}: {message}", self.pos + 1)
	}

	/// Move to the next line that is not blank or a comment, and give its
	/// indent and trimmed text. `None` at the end of the document.
	fn current(&mut self) -> Option<(usize, String)> {
		while let Some(line) = self.lines.get(self.pos) {
			let content = line.trim_start();
			if content.is_empty() || content.starts_with('#') {
				self.pos += 1;
				continue;
			}
			return Some((line.len() - content.len(), content.trim_end().to_owned()));
		}
		None
	}

	/// The node whose first line sits at `indent`.
	fn block(&mut self, indent: usize) -> Result<Value, String> {
		let Some((found, content)) = self.current() else {
			return Err(self.fail("a value is missing"));
		};
		if found != indent {
			return Err(self.fail("unexpected indentation"));
		}
		if content == "-" || content.starts_with("- ") {
			self.sequence(indent)
		} else {
			self.mapping(indent)
		}
	}

	fn mapping(&mut self, indent: usize) -> Result<Value, String> {
		let mut map = Map::new();
		while let Some((found, content)) = self.current() {
			if found < indent {
				break;
			}
			if found > indent {
				return Err(self.fail("unexpected indentation"));
			}
			if content == "-" || content.starts_with("- ") {
				return Err(self.fail("a sequence item inside a mapping"));
			}
			let (key, rest) = split_key(&content).ok_or_else(|| self.fail("expected `key:`"))?;
			if map.contains_key(&key) {
				return Err(self.fail(&format!("duplicate key `{key}`")));
			}
			let value = self.entry_value(indent, rest.trim())?;
			map.insert(key, value);
		}
		Ok(Value::Object(map))
	}

	/// The value after `key:` on a line at `indent`; `rest` is what follows
	/// the colon on that line.
	fn entry_value(&mut self, indent: usize, rest: &str) -> Result<Value, String> {
		if rest.is_empty() {
			self.pos += 1;
			return match self.current() {
				Some((next, _)) if next > indent => self.block(next),
				_ => Ok(Value::Null),
			};
		}
		if rest.starts_with(['|', '>']) {
			return self.block_scalar(indent, rest);
		}
		let value = inline(rest).map_err(|why| self.fail(&why))?;
		self.pos += 1;
		Ok(value)
	}

	fn sequence(&mut self, indent: usize) -> Result<Value, String> {
		let mut items = Vec::new();
		while let Some((found, content)) = self.current() {
			if found < indent {
				break;
			}
			if found > indent {
				return Err(self.fail("unexpected indentation"));
			}
			if content != "-" && !content.starts_with("- ") {
				break;
			}
			let rest = content.strip_prefix('-').unwrap_or("");
			let gap = rest.len() - rest.trim_start().len();
			let rest = rest.trim_start();
			if rest.is_empty() {
				self.pos += 1;
				match self.current() {
					Some((next, _)) if next > indent => items.push(self.block(next)?),
					_ => return Err(self.fail("an empty sequence item")),
				}
			} else if rest.starts_with("- ") || rest == "-" {
				return Err(self.fail("nested sequence items on one line"));
			} else if split_key(rest).is_some() {
				// `- key: value`: the item is a mapping that starts here, its
				// other keys indented to line up with the first.
				let column = indent + 1 + gap;
				self.lines[self.pos] = format!("{}{rest}", " ".repeat(column));
				items.push(self.mapping(column)?);
			} else {
				items.push(inline(rest).map_err(|why| self.fail(&why))?);
				self.pos += 1;
			}
		}
		Ok(Value::Array(items))
	}

	/// A `|` or `>` scalar whose header is `header` and whose key line has
	/// `indent`.
	fn block_scalar(&mut self, indent: usize, header: &str) -> Result<Value, String> {
		let literal = header.starts_with('|');
		let strip = match &header[1..] {
			"" => false,
			"-" => true,
			_ => return Err(self.fail("only `|`, `|-`, `>` and `>-` are accepted")),
		};
		self.pos += 1;
		let mut body: Vec<String> = Vec::new();
		let mut block_indent = None;
		while let Some(line) = self.lines.get(self.pos) {
			if line.trim().is_empty() {
				body.push(String::new());
				self.pos += 1;
				continue;
			}
			let lead = line.len() - line.trim_start().len();
			if lead <= indent {
				break;
			}
			let cut = *block_indent.get_or_insert(lead);
			if lead < cut {
				return Err(self.fail("a block scalar line is indented less than the first"));
			}
			if !literal && lead > cut {
				return Err(self.fail("a folded scalar cannot have more-indented lines"));
			}
			body.push(line[cut..].trim_end().to_owned());
			self.pos += 1;
		}
		while body.last().is_some_and(String::is_empty) {
			body.pop();
		}
		if body.is_empty() {
			return Err(self.fail("a block scalar has no content"));
		}
		let mut text = if literal {
			body.join("\n")
		} else {
			fold(&body)
		};
		if !strip {
			text.push('\n');
		}
		Ok(Value::String(text))
	}
}

/// Folded text: the lines of a paragraph are joined by a space, paragraphs by
/// a line break.
fn fold(body: &[String]) -> String {
	body.split(|line| line.is_empty())
		.filter(|paragraph| !paragraph.is_empty())
		.map(|paragraph| paragraph.join(" "))
		.collect::<Vec<_>>()
		.join("\n")
}

/// Split `key: rest` (or `key:`); the key may be quoted.
fn split_key(content: &str) -> Option<(String, &str)> {
	if content.starts_with(['"', '\'']) {
		let (key, after) = quoted(content).ok()?;
		let rest = after.strip_prefix(':')?;
		return (rest.is_empty() || rest.starts_with(' ')).then_some((key, rest));
	}
	let at = if let Some(at) = content.find(": ") {
		at
	} else if content.ends_with(':') {
		content.len() - 1
	} else {
		return None;
	};
	let key = &content[..at];
	let plain = !key.is_empty()
		&& !key.starts_with(['[', '{', '&', '*', '!', '|', '>', '%', '@', '`', '#'])
		&& !key.contains(['#', '"', '\'']);
	plain.then(|| (key.to_owned(), &content[at + 1..]))
}

/// Read a quoted scalar from the start of `text`; the rest follows it.
fn quoted(text: &str) -> Result<(String, &str), String> {
	let mut chars = text.char_indices();
	let (_, quote) = chars.next().ok_or("an empty scalar")?;
	let mut out = String::new();
	while let Some((at, c)) = chars.next() {
		if c == quote {
			if quote == '\'' && text[at + 1..].starts_with('\'') {
				out.push('\'');
				chars.next();
				continue;
			}
			return Ok((out, &text[at + 1..]));
		}
		if quote == '"' && c == '\\' {
			out.push(escape(&mut chars)?);
		} else {
			out.push(c);
		}
	}
	Err("a quoted scalar is not closed on its line".into())
}

/// One backslash escape of a double-quoted scalar, JSON's set.
fn escape(chars: &mut std::str::CharIndices<'_>) -> Result<char, String> {
	let (_, c) = chars.next().ok_or("a dangling backslash")?;
	Ok(match c {
		'"' | '\\' | '/' => c,
		'n' => '\n',
		't' => '\t',
		'r' => '\r',
		'u' => {
			let hex: String = chars.by_ref().take(4).map(|(_, digit)| digit).collect();
			u32::from_str_radix(&hex, 16)
				.ok()
				.and_then(char::from_u32)
				.ok_or("a bad \\u escape")?
		}
		other => return Err(format!("the escape \\{other} is not accepted")),
	})
}

/// A value written on the line of its key or sequence dash.
fn inline(text: &str) -> Result<Value, String> {
	if text.starts_with(['"', '\'']) {
		let (value, rest) = quoted(text)?;
		return if rest.trim().is_empty() {
			Ok(Value::String(value))
		} else {
			Err("text after a quoted scalar".into())
		};
	}
	if text == "{}" {
		return Ok(Value::Object(Map::new()));
	}
	if let Some(inner) = text.strip_prefix('[') {
		let inner = inner
			.strip_suffix(']')
			.ok_or("a flow sequence must close on its line")?;
		return flow_items(inner).map(Value::Array);
	}
	plain(text)
}

/// The scalars of a flow sequence body, split at the commas outside quotes.
fn flow_items(inner: &str) -> Result<Vec<Value>, String> {
	let mut items = Vec::new();
	let mut rest = inner.trim();
	while !rest.is_empty() {
		let (item, after) = if rest.starts_with(['"', '\'']) {
			let (value, after) = quoted(rest)?;
			(Value::String(value), after)
		} else {
			let end = rest.find(',').unwrap_or(rest.len());
			(plain(rest[..end].trim())?, &rest[end..])
		};
		items.push(item);
		rest = match after.trim_start().strip_prefix(',') {
			Some(more) => more.trim(),
			None if after.trim().is_empty() => "",
			None => return Err("expected `,` in a flow sequence".into()),
		};
	}
	Ok(items)
}

/// An unquoted scalar: null, a boolean, a number or a string.
fn plain(text: &str) -> Result<Value, String> {
	if text.starts_with(['[', '{', '&', '*', '!', '|', '>', '%', '@', '`', '#']) {
		return Err(format!("`{text}` must be quoted"));
	}
	if text.contains(" #") || text.contains(": ") || text.ends_with(':') {
		return Err(format!("`{text}` must be quoted"));
	}
	match text {
		"null" | "~" => return Ok(Value::Null),
		"true" => return Ok(Value::Bool(true)),
		"false" => return Ok(Value::Bool(false)),
		"y" | "Y" | "n" | "N" | "yes" | "Yes" | "YES" | "no" | "No" | "NO" | "on" | "On" | "ON"
		| "off" | "Off" | "OFF" | "True" | "TRUE" | "False" | "FALSE" | "Null" | "NULL" => {
			return Err(format!("`{text}` reads differently in YAML 1.1: quote it"));
		}
		_ => {}
	}
	if let Some(number) = number(text) {
		return Ok(Value::Number(number));
	}
	if looks_numeric(text) {
		return Err(format!("`{text}` must be quoted: it is not a plain number"));
	}
	Ok(Value::String(text.to_owned()))
}

/// `-?(0|[1-9][0-9]*)` or the same with `.digits`.
fn number(text: &str) -> Option<Number> {
	let digits = text.strip_prefix('-').unwrap_or(text);
	let (whole, fraction) = match digits.split_once('.') {
		Some((whole, fraction)) => (whole, Some(fraction)),
		None => (digits, None),
	};
	let whole_ok = whole == "0"
		|| (!whole.starts_with('0')
			&& !whole.is_empty()
			&& whole.bytes().all(|b| b.is_ascii_digit()));
	let fraction_ok =
		fraction.is_none_or(|f| !f.is_empty() && f.bytes().all(|b| b.is_ascii_digit()));
	if !whole_ok || !fraction_ok {
		return None;
	}
	if fraction.is_some() {
		Number::from_f64(text.parse().ok()?)
	} else {
		text.parse::<i64>().ok().map(Number::from)
	}
}

/// Whether a plain scalar would be a number (or a special float) to some
/// YAML parser, without being one of the forms [`number`] accepts.
fn looks_numeric(text: &str) -> bool {
	let first = text.trim_start_matches(['+', '-']).chars().next();
	first.is_some_and(|c| c.is_ascii_digit() || c == '.')
		&& text.chars().all(|c| {
			c.is_ascii_hexdigit() || matches!(c, '+' | '-' | '.' | '_' | 'x' | 'o' | 'X' | 'O')
		})
}

#[cfg(test)]
mod tests;
