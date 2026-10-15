//! One forward pass over a raw message that hands every leaf MIME part to a
//! visitor, with its declared name and type and its decoded content.
//!
//! The walk never recurses: open multipart boundaries live on a stack that
//! [`Limits::max_depth`] caps, every line is read once, and a line is only
//! compared with the open boundaries when it starts with `--`, so the cost
//! is linear in the message size. Header parsing (RFC 2231 parameters,
//! RFC 2047 encoded words) is mail-parser's, run on one part's header block
//! at a time.

use mail_parser::{MessageParser, MimeHeaders};

/// RFC 2046 section 5.1.1 caps a boundary at 70 characters. A longer one
/// is not a boundary this walk will look for.
const MAX_BOUNDARY_LEN: usize = 70;

/// Largest header block a single part may carry.
pub const MAX_HEADER_BYTES: usize = 64 * 1024;

/// Decoded bytes kept from a part that no longer fits the decode budget:
/// enough for every signature [`super::sniff::sniff`] reads.
const TRUNCATED_PREFIX: usize = super::sniff::SNIFF_WINDOW;

// Test-only count of the bytes the walk examines, so a test can prove the
// cost stays linear on hostile input. Per thread, so parallel tests do not
// see each other.
#[cfg(test)]
thread_local! {
	pub(super) static STEPS: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

#[cfg(test)]
fn step(count: usize) {
	STEPS.with(|steps| steps.set(steps.get() + count as u64));
}

#[cfg(not(test))]
fn step(_count: usize) {}

/// Hard caps on one walk.
#[derive(Clone, Copy, Debug)]
pub struct Limits {
	/// Deepest multipart or `message/rfc822` nesting followed.
	pub max_depth: usize,
	/// Most MIME parts counted, containers included.
	pub max_parts: usize,
	/// Total decoded bytes across every attachment.
	pub max_decoded: usize,
}

/// Why a walk stopped before the end of the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
	/// The nesting went past [`Limits::max_depth`].
	TooDeep,
	/// The message has more parts than [`Limits::max_parts`].
	TooManyParts,
	/// A part's header block is larger than [`MAX_HEADER_BYTES`].
	HeaderTooLarge,
}

/// One leaf part, as the visitor sees it.
#[derive(Debug)]
pub struct Leaf {
	/// The declared file name (`Content-Disposition` `filename`, then
	/// `Content-Type` `name`), decoded.
	pub filename: Option<String>,
	/// The declared `type/subtype`, lower case; `text/plain` when absent.
	pub declared_type: String,
	/// Whether the part is an attachment rather than message text: it has
	/// a name, is marked `attachment`, or is not `text/*`.
	pub attachment: bool,
	/// Nesting depth; the top-level entity is 0.
	pub depth: usize,
	/// The decoded content of an attachment (empty for message text).
	pub content: Vec<u8>,
	/// `content` holds only a prefix because the decode budget ran out.
	pub truncated: bool,
}

/// Walk `raw` and call `visit` for every leaf part. Returns the number of
/// parts seen, or why the walk stopped; leaves visited before a stop have
/// already been handed over.
///
/// A `message/rfc822` part sent base64 or quoted-printable is decoded and
/// walked after the buffer that holds it, from a work list rather than by
/// recursion, so an attachment cannot hide one encoding layer down.
pub fn walk(raw: &[u8], limits: &Limits, mut visit: impl FnMut(Leaf)) -> Result<usize, Stop> {
	let mut shared = Shared {
		parts: 1,
		decoded: 0,
		pending: Vec::new(),
	};
	Walker {
		raw,
		limits,
		stack: Vec::new(),
		shared: &mut shared,
	}
	.run(0, &mut visit)?;
	while let Some((nested, depth)) = shared.pending.pop() {
		Walker {
			raw: &nested,
			limits,
			stack: Vec::new(),
			shared: &mut shared,
		}
		.run(depth, &mut visit)?;
	}
	Ok(shared.parts)
}

/// What every buffer of one walk draws from.
struct Shared {
	parts: usize,
	decoded: usize,
	/// Decoded nested messages still to walk, with their depth.
	pending: Vec<(Vec<u8>, usize)>,
}

/// An open multipart: its delimiter line and the depth of its children.
struct Frame {
	delimiter: Vec<u8>,
	child_depth: usize,
}

/// Where the pass is inside the current entity.
enum State {
	/// Reading a header block that started at `start`.
	Headers { start: usize, depth: usize },
	/// Reading a leaf body that started at `start`.
	Body {
		header: PartHeader,
		start: usize,
		depth: usize,
	},
	/// A preamble or epilogue: nothing to keep until the next delimiter.
	Skip,
}

/// What one header block declares.
struct PartHeader {
	filename: Option<String>,
	declared_type: String,
	attachment: bool,
	encoding: Encoding,
	boundary: Option<Vec<u8>>,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Encoding {
	Identity,
	Base64,
	QuotedPrintable,
}

struct Walker<'a> {
	raw: &'a [u8],
	limits: &'a Limits,
	stack: Vec<Frame>,
	shared: &'a mut Shared,
}

impl Walker<'_> {
	fn run(&mut self, depth: usize, visit: &mut impl FnMut(Leaf)) -> Result<(), Stop> {
		let raw = self.raw;
		let mut state = State::Headers { start: 0, depth };
		let mut pos = 0;
		loop {
			let end = raw[pos..]
				.iter()
				.position(|&byte| byte == b'\n')
				.map_or(raw.len(), |offset| pos + offset);
			step(end - pos + 1);
			let next = (end + 1).min(raw.len());
			let line = trim_cr(&raw[pos..end]);
			if let Some((index, closing)) = self.delimiter(line) {
				self.finish(state, pos, visit)?;
				self.stack.truncate(index + 1);
				state = if closing {
					self.stack.pop();
					State::Skip
				} else {
					self.count_part()?;
					State::Headers {
						start: next,
						depth: self.stack[index].child_depth,
					}
				};
			} else if let State::Headers { start, depth } = state {
				if line.is_empty() {
					state = self.entered(parse_header(&raw[start..pos]), depth, next)?;
				} else if pos - start > MAX_HEADER_BYTES {
					return Err(Stop::HeaderTooLarge);
				}
			}
			if end >= raw.len() {
				return self.finish(state, raw.len(), visit);
			}
			pos = next;
		}
	}

	/// The state after a header block: a multipart opens a frame, an
	/// unencoded `message/rfc822` starts a nested header block, anything
	/// else is a leaf body.
	fn entered(&mut self, header: PartHeader, depth: usize, next: usize) -> Result<State, Stop> {
		if let Some(boundary) = &header.boundary {
			if depth + 1 > self.limits.max_depth {
				return Err(Stop::TooDeep);
			}
			let mut delimiter = b"--".to_vec();
			delimiter.extend_from_slice(boundary);
			self.stack.push(Frame {
				delimiter,
				child_depth: depth + 1,
			});
			return Ok(State::Skip);
		}
		if header.declared_type == "message/rfc822" && header.encoding == Encoding::Identity {
			if depth + 1 > self.limits.max_depth {
				return Err(Stop::TooDeep);
			}
			self.count_part()?;
			return Ok(State::Headers {
				start: next,
				depth: depth + 1,
			});
		}
		Ok(State::Body {
			header,
			start: next,
			depth,
		})
	}

	fn count_part(&mut self) -> Result<(), Stop> {
		self.shared.parts += 1;
		if self.shared.parts > self.limits.max_parts {
			return Err(Stop::TooManyParts);
		}
		Ok(())
	}

	/// The open boundary `line` is a delimiter for, innermost first, and
	/// whether it closes that multipart.
	fn delimiter(&self, line: &[u8]) -> Option<(usize, bool)> {
		if !line.starts_with(b"--") {
			return None;
		}
		for (index, frame) in self.stack.iter().enumerate().rev() {
			step(frame.delimiter.len().min(line.len()));
			let Some(rest) = line.strip_prefix(frame.delimiter.as_slice()) else {
				continue;
			};
			let (closing, rest) = match rest.strip_prefix(b"--") {
				Some(rest) => (true, rest),
				None => (false, rest),
			};
			if rest.iter().all(|&byte| byte == b' ' || byte == b'\t') {
				return Some((index, closing));
			}
		}
		None
	}

	/// Close the current entity at `end`, the start of the line that ended
	/// it, and hand a leaf to `visit`, or queue an encoded nested message.
	fn finish(
		&mut self,
		state: State,
		end: usize,
		visit: &mut impl FnMut(Leaf),
	) -> Result<(), Stop> {
		let (header, start, depth) = match state {
			State::Skip => return Ok(()),
			State::Headers { start, depth } => {
				(parse_header(&self.raw[start..end.max(start)]), end, depth)
			}
			State::Body {
				header,
				start,
				depth,
			} => (header, start, depth),
		};
		// The line break before a delimiter belongs to the delimiter.
		let mut body = &self.raw[start.min(end)..end];
		body = body.strip_suffix(b"\n").unwrap_or(body);
		body = body.strip_suffix(b"\r").unwrap_or(body);
		let (content, truncated) = if header.attachment {
			self.decode(body, header.encoding)
		} else {
			(Vec::new(), false)
		};
		if header.declared_type == "message/rfc822" && !truncated {
			if depth + 1 > self.limits.max_depth {
				return Err(Stop::TooDeep);
			}
			self.count_part()?;
			self.shared.pending.push((content, depth + 1));
			return Ok(());
		}
		visit(Leaf {
			filename: header.filename,
			declared_type: header.declared_type,
			attachment: header.attachment,
			depth,
			content,
			truncated,
		});
		Ok(())
	}

	/// Decode `body` within what is left of the decode budget; past it,
	/// keep only a prefix long enough to identify the content.
	fn decode(&mut self, body: &[u8], encoding: Encoding) -> (Vec<u8>, bool) {
		let remaining = self.limits.max_decoded.saturating_sub(self.shared.decoded);
		let estimate = match encoding {
			Encoding::Base64 => body.len() / 4 * 3 + 3,
			Encoding::Identity | Encoding::QuotedPrintable => body.len(),
		};
		let (input, truncated) = if estimate <= remaining {
			(body, false)
		} else {
			let keep = match encoding {
				Encoding::Base64 => (TRUNCATED_PREFIX / 3 + 1) * 4 * 2,
				Encoding::Identity | Encoding::QuotedPrintable => TRUNCATED_PREFIX * 3,
			};
			(&body[..body.len().min(keep)], true)
		};
		let mut content = match encoding {
			Encoding::Identity => input.to_vec(),
			Encoding::Base64 => decode_base64(input),
			Encoding::QuotedPrintable => {
				mail_parser::decoders::quoted_printable::quoted_printable_decode(input)
					.unwrap_or_else(|| input.to_vec())
			}
		};
		if truncated {
			content.truncate(TRUNCATED_PREFIX);
		}
		self.shared.decoded = self.shared.decoded.saturating_add(content.len());
		(content, truncated)
	}
}

/// Base64 as mail clients read it: characters outside the alphabet are
/// skipped and the data ends at the first `=`, so a sender cannot hide a
/// payload from the scan with stray bytes the recipient's client ignores.
fn decode_base64(input: &[u8]) -> Vec<u8> {
	use base64::Engine as _;
	use base64::engine::{DecodePaddingMode, GeneralPurpose, GeneralPurposeConfig};
	const LENIENT: GeneralPurpose = GeneralPurpose::new(
		&base64::alphabet::STANDARD,
		GeneralPurposeConfig::new()
			.with_decode_allow_trailing_bits(true)
			.with_decode_padding_mode(DecodePaddingMode::Indifferent),
	);
	let mut clean: Vec<u8> = input
		.iter()
		.copied()
		.take_while(|&byte| byte != b'=')
		.filter(|byte| byte.is_ascii_alphanumeric() || *byte == b'+' || *byte == b'/')
		.collect();
	if clean.len() % 4 == 1 {
		clean.pop();
	}
	LENIENT.decode(&clean).unwrap_or_default()
}

/// Parse one header block with mail-parser.
fn parse_header(block: &[u8]) -> PartHeader {
	let mut block = block.to_vec();
	block.extend_from_slice(b"\r\n");
	let parsed = MessageParser::new().parse_headers(&block);
	let content_type = parsed.as_ref().and_then(|message| message.content_type());
	let declared_type = content_type
		.map(|ct| match ct.subtype() {
			Some(subtype) => format!("{}/{}", ct.ctype(), subtype),
			None => ct.ctype().to_string(),
		})
		.map(|value| value.to_ascii_lowercase())
		.unwrap_or_else(|| "text/plain".to_string());
	let disposition = parsed
		.as_ref()
		.and_then(|message| message.content_disposition());
	let filename = disposition
		.and_then(|cd| cd.attribute("filename"))
		.or_else(|| content_type.and_then(|ct| ct.attribute("name")))
		.map(str::to_string)
		.filter(|name| !name.is_empty());
	let boundary = content_type
		.filter(|_| declared_type.starts_with("multipart/"))
		.and_then(|ct| ct.attribute("boundary"))
		.filter(|value| !value.is_empty() && value.len() <= MAX_BOUNDARY_LEN)
		.map(|value| value.as_bytes().to_vec());
	let encoding = match parsed
		.as_ref()
		.and_then(|message| message.content_transfer_encoding())
		.map(str::to_ascii_lowercase)
		.as_deref()
	{
		Some("base64") => Encoding::Base64,
		Some("quoted-printable") => Encoding::QuotedPrintable,
		_ => Encoding::Identity,
	};
	let attachment = filename.is_some()
		|| disposition.is_some_and(|cd| cd.ctype().eq_ignore_ascii_case("attachment"))
		|| !(declared_type.starts_with("text/") || declared_type.starts_with("multipart/"));
	PartHeader {
		filename,
		declared_type,
		attachment,
		encoding,
		boundary,
	}
}

fn trim_cr(line: &[u8]) -> &[u8] {
	line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
#[path = "walk_tests.rs"]
mod tests;
