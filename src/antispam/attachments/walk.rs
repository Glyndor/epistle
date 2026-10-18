//! One forward pass over a raw message that hands every leaf MIME part to a
//! visitor, with its declared names and type and its decoded content.
//!
//! The walk never recurses: open multipart boundaries live on a stack that
//! [`Limits::max_depth`] caps, every line is read once, and a line is only
//! compared with the open boundaries when it starts with `--`, so the cost
//! is linear in the message size. Header blocks are read by
//! [`super::header`], bodies decoded by [`super::decode`].
//!
//! Where a client could read the message differently, the walk takes the
//! reading that shows more content and reports the message as ambiguous;
//! it never settles on the reading that hides a part.

use super::decode;
use super::header::{self, Encoding, PartHeader};

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
	/// Total decoded bytes across every part.
	pub max_decoded: usize,
	/// When the walk gives up, checked every [`DEADLINE_STRIDE`] lines.
	pub deadline: Option<std::time::Instant>,
}

/// Lines between two looks at the clock.
pub const DEADLINE_STRIDE: usize = 1024;

/// Why a walk stopped before the end of the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stop {
	/// The nesting went past [`Limits::max_depth`].
	TooDeep,
	/// The message has more parts than [`Limits::max_parts`].
	TooManyParts,
	/// A part's header block is larger than [`MAX_HEADER_BYTES`].
	HeaderTooLarge,
	/// [`Limits::deadline`] passed.
	OutOfTime,
}

/// One leaf part, as the visitor sees it.
#[derive(Debug)]
pub struct Leaf {
	/// Every candidate file name, in header order (`Content-Disposition`
	/// `filename`, `Content-Type` `name`, each copy of each header).
	pub names: Vec<String>,
	/// The declared `type/subtype`, lower case; `text/plain` when absent.
	pub declared_type: String,
	/// Every declared `type/subtype`, from every copy of the header.
	pub declared_types: Vec<String>,
	/// Whether the part is an attachment rather than message text.
	pub attachment: bool,
	/// Nesting depth; the top-level entity is 0.
	pub depth: usize,
	/// The decoded content (empty for a container nobody decodes, and for a
	/// part [`walk_text`] has no use for).
	pub content: Vec<u8>,
	/// The content decoded under each other transfer encoding the part's
	/// headers declare, which a client may have used instead.
	pub alternates: Vec<Vec<u8>>,
	/// `content` holds only a prefix because the decode budget ran out.
	pub truncated: bool,
	/// Two readers could see this part differently.
	pub ambiguous: bool,
}

impl Leaf {
	/// The name a client most likely shows: the first candidate.
	pub fn filename(&self) -> Option<&str> {
		self.names.first().map(String::as_str)
	}
}

/// How a walk ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Walked {
	/// Parts counted, containers included.
	pub parts: usize,
	/// A delimiter-like line two readers could split on differently.
	pub ambiguous: bool,
	/// Why the walk stopped early; what follows was not seen.
	pub stopped: Option<Stop>,
}

/// Walk `raw` and call `visit` for every leaf part. Leaves visited before
/// a stop have already been handed over.
///
/// A `message/rfc822` part sent base64 or quoted-printable is decoded and
/// walked after the buffer that holds it, from a work list rather than by
/// recursion, so an attachment cannot hide one encoding layer down. A
/// uuencoded file pasted into a text body is handed over as a leaf of its
/// own, since clients show it as an attachment.
pub fn walk(raw: &[u8], limits: &Limits, visit: impl FnMut(Leaf)) -> Walked {
	walk_with(raw, limits, false, visit)
}

/// [`walk`] for a reader of text: a part no client could show as text (a
/// photo, a PDF, an archive) is handed over with no content, and costs nothing
/// of [`Limits::max_decoded`], so attachments cannot use up the budget the
/// text after them needs.
pub fn walk_text(raw: &[u8], limits: &Limits, visit: impl FnMut(Leaf)) -> Walked {
	walk_with(raw, limits, true, visit)
}

fn walk_with(raw: &[u8], limits: &Limits, text_only: bool, mut visit: impl FnMut(Leaf)) -> Walked {
	let mut shared = Shared {
		text_only,
		walked: Walked {
			parts: 1,
			..Walked::default()
		},
		decoded: 0,
		lines: 0,
		pending: Vec::new(),
	};
	let mut result = Walker::new(raw, limits, &mut shared).run(0, &mut visit);
	while result.is_ok()
		&& let Some((nested, depth)) = shared.pending.pop()
	{
		result = Walker::new(&nested, limits, &mut shared).run(depth, &mut visit);
	}
	shared.walked.stopped = result.err();
	shared.walked
}

/// What every buffer of one walk draws from.
struct Shared {
	/// Parts no client could show as text are not decoded.
	text_only: bool,
	walked: Walked,
	decoded: usize,
	lines: usize,
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

struct Walker<'a> {
	raw: &'a [u8],
	limits: &'a Limits,
	stack: Vec<Frame>,
	shared: &'a mut Shared,
}

impl<'a> Walker<'a> {
	fn new(raw: &'a [u8], limits: &'a Limits, shared: &'a mut Shared) -> Self {
		Self {
			raw,
			limits,
			stack: Vec::new(),
			shared,
		}
	}

	fn run(&mut self, depth: usize, visit: &mut impl FnMut(Leaf)) -> Result<(), Stop> {
		let raw = self.raw;
		let mut state = State::Headers { start: 0, depth };
		let mut pos = 0;
		loop {
			if self.shared.lines.is_multiple_of(DEADLINE_STRIDE)
				&& self
					.limits
					.deadline
					.is_some_and(|deadline| std::time::Instant::now() >= deadline)
			{
				return Err(Stop::OutOfTime);
			}
			self.shared.lines += 1;
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
				// Checked before the block is parsed: a header line of
				// megabytes is never read, only counted.
				if pos - start > MAX_HEADER_BYTES {
					return Err(Stop::HeaderTooLarge);
				}
				if line.is_empty() {
					state = self.entered(header::parse(&raw[start..pos]), depth, next)?;
				}
			}
			if end >= raw.len() {
				// A missing closing delimiter still ends the last part here,
				// where clients end it too.
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
			self.shared.walked.ambiguous |= header.ambiguous;
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
			self.shared.walked.ambiguous |= header.ambiguous;
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
		self.shared.walked.parts += 1;
		if self.shared.walked.parts > self.limits.max_parts {
			return Err(Stop::TooManyParts);
		}
		Ok(())
	}

	/// The open boundary `line` is a delimiter for, innermost first, and
	/// whether it closes that multipart. A line that a lenient client could
	/// take for a delimiter (trailing junk, other letter case) is not one
	/// here, and marks the message ambiguous.
	fn delimiter(&mut self, line: &[u8]) -> Option<(usize, bool)> {
		if !line.starts_with(b"--") {
			return None;
		}
		let mut near_miss = false;
		for (index, frame) in self.stack.iter().enumerate().rev() {
			let len = frame.delimiter.len();
			step(len.min(line.len()));
			let Some(head) = line.get(..len) else {
				continue;
			};
			if !head.eq_ignore_ascii_case(&frame.delimiter) {
				continue;
			}
			let rest = &line[len..];
			let (closing, tail) = match rest.strip_prefix(b"--") {
				Some(tail) => (true, tail),
				None => (false, rest),
			};
			if head == frame.delimiter.as_slice()
				&& tail.iter().all(|&byte| byte == b' ' || byte == b'\t')
			{
				return Some((index, closing));
			}
			near_miss = true;
		}
		self.shared.walked.ambiguous |= near_miss;
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
				if end.saturating_sub(start) > MAX_HEADER_BYTES {
					return Err(Stop::HeaderTooLarge);
				}
				(header::parse(&self.raw[start..end.max(start)]), end, depth)
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
		let text = header.declared_type.starts_with("text/") && !header.attachment;
		let wanted =
			(header.attachment || text) && (!self.shared.text_only || header.could_be_text());
		let (content, truncated, garbled) = if wanted {
			self.decode(body, header.encoding)
		} else {
			(Vec::new(), false, false)
		};
		let mut alternates = Vec::new();
		let mut truncated = truncated;
		if wanted {
			for encoding in &header.other_encodings {
				let (other, cut, _) = self.decode(body, *encoding);
				truncated |= cut;
				alternates.push(other);
			}
		}
		if header.declared_type == "message/rfc822" && !truncated {
			if depth + 1 > self.limits.max_depth {
				return Err(Stop::TooDeep);
			}
			self.count_part()?;
			self.shared.walked.ambiguous |= header.ambiguous || garbled;
			self.shared.pending.push((content, depth + 1));
			return Ok(());
		}
		if text {
			let (blocks, capped) = decode::embedded_uuencode(&content);
			truncated |= capped;
			for embedded in blocks {
				self.count_part()?;
				visit(Leaf {
					names: vec![embedded.name],
					declared_type: "application/octet-stream".to_string(),
					declared_types: vec!["application/octet-stream".to_string()],
					attachment: true,
					depth: depth + 1,
					content: embedded.content,
					alternates: Vec::new(),
					truncated,
					ambiguous: false,
				});
			}
		}
		visit(Leaf {
			names: header.names,
			declared_type: header.declared_type,
			declared_types: header.declared_types,
			attachment: header.attachment,
			depth,
			content,
			alternates,
			truncated,
			ambiguous: header.ambiguous || garbled,
		});
		Ok(())
	}

	/// Decode `body` within what is left of the decode budget; past it,
	/// keep only a prefix long enough to identify the content. The third
	/// value says the encoding itself was ambiguous.
	fn decode(&mut self, body: &[u8], encoding: Encoding) -> (Vec<u8>, bool, bool) {
		let remaining = self.limits.max_decoded.saturating_sub(self.shared.decoded);
		let estimate = match encoding {
			Encoding::Base64 | Encoding::Uuencode => body.len() / 4 * 3 + 3,
			Encoding::Identity | Encoding::QuotedPrintable => body.len(),
		};
		let (input, truncated) = if estimate <= remaining {
			(body, false)
		} else {
			let keep = match encoding {
				Encoding::Base64 | Encoding::Uuencode => (TRUNCATED_PREFIX / 3 + 1) * 4 * 2,
				Encoding::Identity | Encoding::QuotedPrintable => TRUNCATED_PREFIX * 3,
			};
			(&body[..body.len().min(keep)], true)
		};
		let (mut content, garbled) = match encoding {
			Encoding::Identity => (input.to_vec(), false),
			Encoding::Base64 => decode::base64(input),
			Encoding::QuotedPrintable => decode::quoted_printable(input),
			Encoding::Uuencode => (decode::uuencode(input), false),
		};
		if truncated {
			content.truncate(TRUNCATED_PREFIX);
		}
		self.shared.decoded = self.shared.decoded.saturating_add(content.len());
		(content, truncated, garbled)
	}
}

fn trim_cr(line: &[u8]) -> &[u8] {
	line.strip_suffix(b"\r").unwrap_or(line)
}

#[cfg(test)]
#[path = "walk_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "walk_tests_differential.rs"]
mod tests_differential;
